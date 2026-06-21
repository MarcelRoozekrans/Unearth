//! Filesystem-aware recovery for exFAT volumes.
//!
//! exFAT is the default filesystem for SD/SDXC cards larger than 32 GB and for
//! most modern cameras, so it is an important complement to [`crate::fat`].
//!
//! ## How exFAT deletion works
//!
//! Directories are made of 32-byte entries grouped into "entry sets". Each
//! entry's first byte is a type code whose high bit (`0x80`) is the **InUse**
//! flag. Deleting a file simply **clears that bit** on every entry of its set;
//! the name, attributes, first cluster, and data length are all left intact.
//! Unlike FAT, no part of the name is lost.
//!
//! exFAT also avoids the per-file FAT chain whenever a file is stored
//! contiguously: the stream-extension entry carries a `NoFatChain` flag plus the
//! first cluster and exact byte length. That makes contiguous deleted files
//! trivially and reliably recoverable — we just read `DataLength` bytes from the
//! first cluster. Fragmented files fall back to following the FAT (when its
//! chain survived the delete).

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// A parsed exFAT volume.
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    bytes_per_sector: u64,
    sectors_per_cluster: u64,
    fat_offset_sectors: u64,
    cluster_heap_offset_sectors: u64,
    cluster_count: u32,
    root_cluster: u32,
    volume_length_sectors: u64,
}

const ENTRY_SIZE: usize = 32;
// Entry type codes with the InUse bit (0x80) masked off.
const TYPE_FILE: u8 = 0x05; // 0x85 File Directory Entry
const TYPE_STREAM: u8 = 0x40; // 0xC0 Stream Extension
const TYPE_NAME: u8 = 0x41; // 0xC1 File Name
const INUSE_BIT: u8 = 0x80;
const ATTR_DIRECTORY: u16 = 0x10;
const FLAG_NO_FAT_CHAIN: u8 = 0x02;
const MAX_DIR_DEPTH: usize = 64;
const MAX_DIR_BYTES: u64 = 64 * 1024 * 1024;

/// Does this sector look like an exFAT volume boot record?
pub fn is_exfat_vbr(s: &[u8]) -> bool {
    s.len() >= 11 && &s[3..11] == b"EXFAT   "
}

impl Volume {
    /// Parse and validate the exFAT boot sector at `offset`.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let mut boot = [0u8; 512];
        if src.read_at(offset, &mut boot)? < 512 {
            bail!("could not read boot sector at offset {offset}");
        }
        if !is_exfat_vbr(&boot) {
            bail!("not an exFAT volume at offset {offset}");
        }

        let fat_offset_sectors =
            u32::from_le_bytes([boot[80], boot[81], boot[82], boot[83]]) as u64;
        let cluster_heap_offset_sectors =
            u32::from_le_bytes([boot[88], boot[89], boot[90], boot[91]]) as u64;
        let cluster_count = u32::from_le_bytes([boot[92], boot[93], boot[94], boot[95]]);
        let root_cluster = u32::from_le_bytes([boot[96], boot[97], boot[98], boot[99]]);
        let volume_length_sectors = u64::from_le_bytes([
            boot[72], boot[73], boot[74], boot[75], boot[76], boot[77], boot[78], boot[79],
        ]);
        let bytes_per_sector_shift = boot[108];
        let sectors_per_cluster_shift = boot[109];

        if !(9..=12).contains(&bytes_per_sector_shift) {
            bail!("implausible exFAT bytes-per-sector shift {bytes_per_sector_shift}");
        }
        // The spec caps a cluster at 32 MiB: bytes-per-sector + sectors-per-
        // cluster shifts must total <= 25. This also bounds per-cluster allocs.
        if bytes_per_sector_shift + sectors_per_cluster_shift > 25 {
            bail!("implausible exFAT cluster size shift {sectors_per_cluster_shift}");
        }

        Ok(Volume {
            offset,
            bytes_per_sector: 1u64 << bytes_per_sector_shift,
            sectors_per_cluster: 1u64 << sectors_per_cluster_shift,
            fat_offset_sectors,
            cluster_heap_offset_sectors,
            cluster_count,
            root_cluster,
            volume_length_sectors,
        })
    }

    fn cluster_bytes(&self) -> u64 {
        self.sectors_per_cluster * self.bytes_per_sector
    }

    fn volume_end(&self) -> u64 {
        self.offset.saturating_add(
            self.volume_length_sectors
                .saturating_mul(self.bytes_per_sector),
        )
    }

    fn max_valid_cluster(&self) -> u32 {
        self.cluster_count.saturating_add(1) // clusters are numbered 2..=cluster_count+1
    }

    /// Absolute byte offset of a data cluster.
    fn cluster_offset(&self, cluster: u32) -> u64 {
        let sector = self.cluster_heap_offset_sectors.saturating_add(
            (cluster as u64)
                .saturating_sub(2)
                .saturating_mul(self.sectors_per_cluster),
        );
        self.offset
            .saturating_add(sector.saturating_mul(self.bytes_per_sector))
    }

    /// Next cluster in the FAT chain, or `None` at end/free/bad/out-of-range.
    fn next_cluster(&self, src: &Source, cluster: u32) -> Result<Option<u32>> {
        let off = self
            .offset
            .saturating_add(
                self.fat_offset_sectors
                    .saturating_mul(self.bytes_per_sector),
            )
            .saturating_add(cluster as u64 * 4);
        let mut b = [0u8; 4];
        if src.read_at(off, &mut b)? < 4 {
            return Ok(None);
        }
        let v = u32::from_le_bytes(b);
        if v < 2 || v > self.max_valid_cluster() || v == 0xFFFF_FFF7 || v == 0xFFFF_FFFF {
            Ok(None)
        } else {
            Ok(Some(v))
        }
    }

    /// Total size of the volume in bytes.
    pub fn size(&self) -> u64 {
        self.volume_length_sectors
            .saturating_mul(self.bytes_per_sector)
    }

    /// Recover all deleted files into `out_dir`.
    pub fn recover_deleted(
        &self,
        src: &Source,
        out_dir: &Path,
        opts: &RecoverOptions,
    ) -> Result<RecoverStats> {
        let mut deleted = Vec::new();
        self.walk(src, &mut deleted)?;

        let mut stats = RecoverStats::default();
        for df in deleted {
            if df.data_length < opts.min_size {
                continue;
            }
            if !self.valid_extent(&df) {
                stats.record_skipped(df.path.clone(), df.data_length);
                continue;
            }
            if opts.dry_run {
                stats.record_recovered(df.path.clone(), df.data_length);
                continue;
            }
            match self.write_file(src, out_dir, &df) {
                Ok(written) if written > 0 || df.data_length == 0 => {
                    stats.record_recovered(df.path.clone(), df.data_length)
                }
                _ => stats.record_skipped(df.path.clone(), df.data_length),
            }
        }
        Ok(stats)
    }

    fn valid_extent(&self, df: &DeletedFile) -> bool {
        if df.data_length == 0 {
            return false; // nothing to recover
        }
        if df.first_cluster < 2 || df.first_cluster > self.max_valid_cluster() {
            return false;
        }
        if df.data_length
            > self
                .volume_length_sectors
                .saturating_mul(self.bytes_per_sector)
        {
            return false;
        }
        // For contiguous files the whole extent must fit inside the volume.
        if df.no_fat_chain {
            let start = self.cluster_offset(df.first_cluster);
            if start.saturating_add(df.data_length) > self.volume_end() {
                return false;
            }
        }
        true
    }

    /// Stream a recovered file to disk, following the FAT chain when present and
    /// falling back to a contiguous read otherwise.
    fn write_file(&self, src: &Source, out_dir: &Path, df: &DeletedFile) -> Result<u64> {
        let target = unique_path(out_dir, &df.path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut out =
            fs::File::create(&target).with_context(|| format!("creating {}", target.display()))?;

        let written = if df.no_fat_chain {
            self.copy_contiguous(src, df.first_cluster, df.data_length, &mut out)?
        } else {
            match self.copy_chain(src, df, &mut out)? {
                w if w >= df.data_length => w,
                // Chain was incomplete (likely freed by the delete); restart as
                // a contiguous read, which is the best remaining guess.
                _ => {
                    out = fs::File::create(&target)?;
                    self.copy_contiguous(src, df.first_cluster, df.data_length, &mut out)?
                }
            }
        };
        out.flush().ok();
        crate::times::apply(&out, df.mtime, df.atime);
        Ok(written)
    }

    fn copy_contiguous(
        &self,
        src: &Source,
        first_cluster: u32,
        len: u64,
        out: &mut fs::File,
    ) -> Result<u64> {
        let mut remaining = len;
        let mut pos = self.cluster_offset(first_cluster);
        // Size the copy buffer to the file, capped at 1 MiB.
        let buf_len = (len as usize).clamp(1, 1024 * 1024);
        let mut buf = vec![0u8; buf_len];
        while remaining > 0 {
            let want = (remaining as usize).min(buf.len());
            let n = src.read_at(pos, &mut buf[..want])?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            remaining -= n as u64;
            pos += n as u64;
        }
        Ok(len - remaining)
    }

    fn copy_chain(&self, src: &Source, df: &DeletedFile, out: &mut fs::File) -> Result<u64> {
        let cb = self.cluster_bytes();
        let mut remaining = df.data_length;
        let mut cluster = df.first_cluster;
        let mut written = 0u64;
        let mut buf = vec![0u8; cb as usize];
        let mut guard = HashSet::new();
        while remaining > 0 {
            if cluster < 2 || cluster > self.max_valid_cluster() || !guard.insert(cluster) {
                break;
            }
            let want = (remaining.min(cb)) as usize;
            let n = src.read_at(self.cluster_offset(cluster), &mut buf[..want])?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            written += n as u64;
            remaining -= n as u64;
            match self.next_cluster(src, cluster)? {
                Some(next) => cluster = next,
                None => break,
            }
        }
        Ok(written)
    }

    /// Walk live directories from the root, collecting deleted files.
    fn walk(&self, src: &Source, out: &mut Vec<DeletedFile>) -> Result<()> {
        let mut visited: HashSet<u32> = HashSet::new();
        // (first cluster, byte length or None, contiguous?, path, depth)
        let mut stack: Vec<(u32, Option<u64>, bool, PathBuf, usize)> =
            vec![(self.root_cluster, None, false, PathBuf::new(), 0)];

        while let Some((cluster, len, contiguous, path, depth)) = stack.pop() {
            if !visited.insert(cluster) {
                continue;
            }
            let bytes = match self.read_directory(src, cluster, len, contiguous) {
                Ok(b) => b,
                Err(_) => continue,
            };
            for item in parse_entry_sets(&bytes) {
                if item.is_dir && !item.deleted {
                    if depth < MAX_DIR_DEPTH
                        && item.first_cluster >= 2
                        && item.first_cluster <= self.max_valid_cluster()
                        && !visited.contains(&item.first_cluster)
                    {
                        let child = path.join(sanitize_component(&item.name));
                        stack.push((
                            item.first_cluster,
                            Some(item.data_length),
                            item.no_fat_chain,
                            child,
                            depth + 1,
                        ));
                    }
                } else if !item.is_dir && item.deleted {
                    out.push(DeletedFile {
                        path: path.join(sanitize_component(&item.name)),
                        first_cluster: item.first_cluster,
                        data_length: item.data_length,
                        no_fat_chain: item.no_fat_chain,
                        mtime: item.mtime,
                        atime: item.atime,
                    });
                }
            }
        }
        Ok(())
    }

    /// Read a directory's raw bytes, contiguously or via the FAT chain.
    fn read_directory(
        &self,
        src: &Source,
        first_cluster: u32,
        len: Option<u64>,
        contiguous: bool,
    ) -> Result<Vec<u8>> {
        let cb = self.cluster_bytes();
        let mut buf = Vec::new();

        if contiguous {
            // Subdirectory with a known contiguous extent.
            let total = len.unwrap_or(cb);
            let mut remaining = total;
            let mut pos = self.cluster_offset(first_cluster);
            while remaining > 0 && (buf.len() as u64) < MAX_DIR_BYTES {
                let want = (remaining.min(cb)) as usize;
                let mut chunk = vec![0u8; want];
                let n = src.read_at(pos, &mut chunk)?;
                chunk.truncate(n);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk);
                remaining -= n as u64;
                pos += n as u64;
            }
            return Ok(buf);
        }

        // Root directory or fragmented subdirectory: follow the FAT chain.
        let mut cluster = first_cluster;
        let mut guard = HashSet::new();
        loop {
            if cluster < 2 || cluster > self.max_valid_cluster() || !guard.insert(cluster) {
                break;
            }
            if buf.len() as u64 + cb > MAX_DIR_BYTES {
                break;
            }
            let mut chunk = vec![0u8; cb as usize];
            let n = src.read_at(self.cluster_offset(cluster), &mut chunk)?;
            chunk.truncate(n);
            buf.extend_from_slice(&chunk);
            if let Some(limit) = len {
                if buf.len() as u64 >= limit {
                    buf.truncate(limit as usize);
                    break;
                }
            }
            match self.next_cluster(src, cluster)? {
                Some(next) => cluster = next,
                None => break,
            }
        }
        Ok(buf)
    }
}

/// A deleted file to recover.
struct DeletedFile {
    path: PathBuf,
    first_cluster: u32,
    data_length: u64,
    no_fat_chain: bool,
    mtime: Option<std::time::SystemTime>,
    atime: Option<std::time::SystemTime>,
}

/// A parsed file/dir entry set.
struct Item {
    name: String,
    deleted: bool,
    is_dir: bool,
    first_cluster: u32,
    data_length: u64,
    no_fat_chain: bool,
    mtime: Option<std::time::SystemTime>,
    atime: Option<std::time::SystemTime>,
}

/// Parse a directory's bytes into file/directory entry sets.
fn parse_entry_sets(bytes: &[u8]) -> Vec<Item> {
    let mut items = Vec::new();
    let total = bytes.len() / ENTRY_SIZE;
    let entry = |i: usize| &bytes[i * ENTRY_SIZE..(i + 1) * ENTRY_SIZE];

    let mut i = 0;
    while i < total {
        let e = entry(i);
        let type_code = e[0] & !INUSE_BIT;

        if type_code != TYPE_FILE {
            i += 1;
            continue;
        }
        let deleted = e[0] & INUSE_BIT == 0;
        let secondary_count = e[1] as usize;
        let attrs = u16::from_le_bytes([e[4], e[5]]);
        let is_dir = attrs & ATTR_DIRECTORY != 0;
        // Timestamps live in the primary File entry (modified at 0x0C, accessed
        // at 0x10), packed in the DOS-style exFAT format.
        let mtime = crate::times::from_exfat(u32::from_le_bytes([e[12], e[13], e[14], e[15]]));
        let atime = crate::times::from_exfat(u32::from_le_bytes([e[16], e[17], e[18], e[19]]));

        // The set is this entry plus `secondary_count` following entries.
        if secondary_count == 0 || i + secondary_count >= total {
            i += 1;
            continue;
        }
        let stream = entry(i + 1);
        if stream[0] & !INUSE_BIT != TYPE_STREAM {
            i += 1;
            continue;
        }
        let flags = stream[1];
        let no_fat_chain = flags & FLAG_NO_FAT_CHAIN != 0;
        let name_length = stream[3] as usize;
        let first_cluster = u32::from_le_bytes([stream[20], stream[21], stream[22], stream[23]]);
        let data_length = u64::from_le_bytes([
            stream[24], stream[25], stream[26], stream[27], stream[28], stream[29], stream[30],
            stream[31],
        ]);

        // Name entries are the remaining secondary entries.
        let mut name_units: Vec<u16> = Vec::with_capacity(name_length);
        for j in 2..=secondary_count {
            let ne = entry(i + j);
            if ne[0] & !INUSE_BIT != TYPE_NAME {
                break;
            }
            for pair in ne[2..ENTRY_SIZE].chunks_exact(2) {
                name_units.push(u16::from_le_bytes([pair[0], pair[1]]));
            }
        }
        name_units.truncate(name_length);
        let name = String::from_utf16_lossy(&name_units);

        if !name.is_empty() {
            items.push(Item {
                name,
                deleted,
                is_dir,
                first_cluster,
                data_length,
                no_fat_chain,
                mtime,
                atime,
            });
        }
        i += 1 + secondary_count;
    }
    items
}

/// Make a single path component safe to write to disk.
fn sanitize_component(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c == '/' || c == '\\' || c == '\0' || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        "_recovered".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Build a non-colliding output path by appending a counter if needed.
fn unique_path(out_dir: &Path, rel: &Path) -> PathBuf {
    let candidate = out_dir.join(rel);
    if !candidate.exists() {
        return candidate;
    }
    let stem = rel
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let ext = rel.extension().map(|e| e.to_string_lossy().to_string());
    let parent = rel.parent().map(|p| p.to_path_buf()).unwrap_or_default();
    for n in 1.. {
        let name = match &ext {
            Some(e) => format!("{stem}_{n}.{e}"),
            None => format!("{stem}_{n}"),
        };
        let candidate = out_dir.join(&parent).join(name);
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!()
}
