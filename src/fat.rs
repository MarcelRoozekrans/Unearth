//! Filesystem-aware recovery for FAT12/FAT16/FAT32 volumes.
//!
//! Unlike carving (see [`crate::carver`]), this reads the filesystem's own
//! directory entries to recover deleted files **with their original names,
//! paths, and sizes**.
//!
//! ## How FAT deletion works
//!
//! When a file is deleted on FAT, two things happen:
//!
//! 1. The first byte of its 32-byte directory entry is overwritten with
//!    `0xE5` (the "deleted" marker). The rest of the entry — including the
//!    starting cluster and file size — usually survives.
//! 2. The file's cluster chain in the FAT is freed (set to 0).
//!
//! Because the chain is gone, we cannot follow it. Instead we assume the file
//! was stored **contiguously** (the common case, especially on freshly written
//! cameras/SD cards) and read `size` bytes starting at the recorded start
//! cluster. This recovers most recently deleted files intact; heavily
//! fragmented files may come back partially corrupt.
//!
//! Long File Names (VFAT) are reconstructed from the LFN entries that precede
//! the short 8.3 entry. Deletion clears only the first byte of each entry, so
//! the name characters themselves survive.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::source::Source;

/// FAT variants, distinguished by cluster count per the Microsoft spec.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FatType {
    Fat12,
    Fat16,
    Fat32,
}

/// A parsed FAT volume and the geometry needed to locate its data.
pub struct Volume {
    /// Byte offset of the volume within the source (0 for a bare volume, or the
    /// partition start when the source is a whole disk image).
    pub offset: u64,
    pub fat_type: FatType,
    bytes_per_sector: u32,
    sectors_per_cluster: u32,
    reserved_sectors: u32,
    total_sectors: u32,
    root_cluster: u32,
    first_data_sector: u32,
    first_root_dir_sector: u32,
    root_dir_sectors: u32,
    count_of_clusters: u32,
}

/// One deleted file we intend to recover, with its reconstructed path.
struct DeletedFile {
    /// Path relative to the volume root (already sanitized component-wise).
    path: PathBuf,
    start_cluster: u32,
    size: u32,
}

/// Outcome of recovering from a single volume.
#[derive(Default)]
pub struct FatStats {
    pub recovered: u64,
    pub bytes_recovered: u64,
    pub skipped: u64,
}

const ENTRY_SIZE: usize = 32;
const ATTR_LFN: u8 = 0x0F;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_VOLUME_ID: u8 = 0x08;
const DELETED_MARKER: u8 = 0xE5;
const MAX_DIR_DEPTH: usize = 64;
/// Cap on bytes read while following a directory's cluster chain, to bound work
/// on a corrupt FAT.
const MAX_DIR_BYTES: u64 = 64 * 1024 * 1024;

/// Detect FAT volumes in `src`: either a bare volume at offset 0, or the FAT
/// partitions listed in an MBR partition table.
pub fn detect_volumes(src: &Source) -> Result<Vec<Volume>> {
    let mut sector0 = [0u8; 512];
    let n = src.read_at(0, &mut sector0)?;
    if n < 512 {
        bail!("source too small to contain a filesystem");
    }

    // A bare FAT volume boot record starts with a jump instruction and carries a
    // sane BPB. Prefer that interpretation when it holds.
    if looks_like_fat_vbr(&sector0) {
        if let Ok(vol) = Volume::parse(src, 0) {
            return Ok(vec![vol]);
        }
    }

    // Otherwise treat sector 0 as an MBR and walk its four partition entries.
    let mut volumes = Vec::new();
    if sector0[510] == 0x55 && sector0[511] == 0xAA {
        for i in 0..4 {
            let base = 446 + i * 16;
            let ptype = sector0[base + 4];
            let lba_start = u32::from_le_bytes([
                sector0[base + 8],
                sector0[base + 9],
                sector0[base + 10],
                sector0[base + 11],
            ]);
            if lba_start == 0 || !is_fat_partition_type(ptype) {
                continue;
            }
            let offset = lba_start as u64 * 512;
            if let Ok(vol) = Volume::parse(src, offset) {
                volumes.push(vol);
            }
        }
    }

    if volumes.is_empty() {
        bail!("no FAT volume found (NTFS/ext/exFAT are not yet supported)");
    }
    Ok(volumes)
}

/// Heuristic: does this sector look like a FAT volume boot record?
fn looks_like_fat_vbr(s: &[u8]) -> bool {
    let jump_ok = s[0] == 0xEB || s[0] == 0xE9;
    let bps = u16::from_le_bytes([s[11], s[12]]);
    let bps_ok = matches!(bps, 512 | 1024 | 2048 | 4096);
    let spc = s[13];
    let spc_ok = spc.is_power_of_two(); // 1,2,4,...,128
    let num_fats = s[16];
    let fats_ok = (1..=2).contains(&num_fats);
    jump_ok && bps_ok && spc_ok && fats_ok
}

fn is_fat_partition_type(t: u8) -> bool {
    matches!(
        t,
        0x01 | 0x04 | 0x06 | 0x0B | 0x0C | 0x0E // FAT12 / FAT16 / FAT32 (LBA) variants
    )
}

impl Volume {
    /// Parse the BPB at `offset` and derive geometry / FAT type.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let mut bpb = [0u8; 512];
        let n = src.read_at(offset, &mut bpb)?;
        if n < 512 {
            bail!("could not read boot sector at offset {offset}");
        }

        let bytes_per_sector = u16::from_le_bytes([bpb[11], bpb[12]]) as u32;
        let sectors_per_cluster = bpb[13] as u32;
        let reserved_sectors = u16::from_le_bytes([bpb[14], bpb[15]]) as u32;
        let num_fats = bpb[16] as u32;
        let root_entry_count = u16::from_le_bytes([bpb[17], bpb[18]]) as u32;
        let total_sectors_16 = u16::from_le_bytes([bpb[19], bpb[20]]) as u32;
        let fat_size_16 = u16::from_le_bytes([bpb[22], bpb[23]]) as u32;
        let total_sectors_32 = u32::from_le_bytes([bpb[32], bpb[33], bpb[34], bpb[35]]);
        let fat_size_32 = u32::from_le_bytes([bpb[36], bpb[37], bpb[38], bpb[39]]);
        let root_cluster = u32::from_le_bytes([bpb[44], bpb[45], bpb[46], bpb[47]]);

        if bytes_per_sector == 0 || sectors_per_cluster == 0 {
            bail!("invalid BPB (zero sector or cluster size) at offset {offset}");
        }

        let fat_size_sectors = if fat_size_16 != 0 {
            fat_size_16
        } else {
            fat_size_32
        };
        let total_sectors = if total_sectors_16 != 0 {
            total_sectors_16
        } else {
            total_sectors_32
        };

        let root_dir_sectors = (root_entry_count * 32).div_ceil(bytes_per_sector);
        let first_data_sector = reserved_sectors + num_fats * fat_size_sectors + root_dir_sectors;
        let first_root_dir_sector = reserved_sectors + num_fats * fat_size_sectors;

        if total_sectors < first_data_sector {
            bail!("invalid BPB (data region before first data sector) at offset {offset}");
        }
        let data_sectors = total_sectors - first_data_sector;
        let count_of_clusters = data_sectors / sectors_per_cluster;

        let fat_type = if count_of_clusters < 4085 {
            FatType::Fat12
        } else if count_of_clusters < 65525 {
            FatType::Fat16
        } else {
            FatType::Fat32
        };

        Ok(Volume {
            offset,
            fat_type,
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            total_sectors,
            root_cluster,
            first_data_sector,
            first_root_dir_sector,
            root_dir_sectors,
            count_of_clusters,
        })
    }

    fn cluster_bytes(&self) -> u64 {
        self.sectors_per_cluster as u64 * self.bytes_per_sector as u64
    }

    /// Absolute byte offset of a data cluster (cluster numbers start at 2).
    fn cluster_offset(&self, cluster: u32) -> u64 {
        let sector =
            self.first_data_sector as u64 + (cluster as u64 - 2) * self.sectors_per_cluster as u64;
        self.offset + sector * self.bytes_per_sector as u64
    }

    fn max_valid_cluster(&self) -> u32 {
        self.count_of_clusters + 1 // clusters are numbered 2..=count+1
    }

    /// Follow the FAT to find the cluster after `cluster`, for *live* chains.
    /// Returns `None` at end-of-chain, on free/bad markers, or out of range.
    fn next_cluster(&self, src: &Source, cluster: u32) -> Result<Option<u32>> {
        let fat_base = self.offset + self.reserved_sectors as u64 * self.bytes_per_sector as u64;
        let (value, eoc) = match self.fat_type {
            FatType::Fat32 => {
                let off = fat_base + cluster as u64 * 4;
                let mut b = [0u8; 4];
                if src.read_at(off, &mut b)? < 4 {
                    return Ok(None);
                }
                let v = u32::from_le_bytes(b) & 0x0FFF_FFFF;
                (v, 0x0FFF_FFF8)
            }
            FatType::Fat16 => {
                let off = fat_base + cluster as u64 * 2;
                let mut b = [0u8; 2];
                if src.read_at(off, &mut b)? < 2 {
                    return Ok(None);
                }
                (u16::from_le_bytes(b) as u32, 0xFFF8)
            }
            FatType::Fat12 => {
                let off = fat_base + (cluster as u64 * 3) / 2;
                let mut b = [0u8; 2];
                if src.read_at(off, &mut b)? < 2 {
                    return Ok(None);
                }
                let raw = u16::from_le_bytes(b);
                let v = if cluster & 1 == 0 {
                    raw & 0x0FFF
                } else {
                    raw >> 4
                };
                (v as u32, 0xFF8)
            }
        };
        if value >= eoc || value < 2 || value > self.max_valid_cluster() {
            Ok(None)
        } else {
            Ok(Some(value))
        }
    }

    /// Recover all deleted files on this volume into `out_dir`.
    pub fn recover_deleted(&self, src: &Source, out_dir: &Path, min_size: u32) -> Result<FatStats> {
        let mut deleted = Vec::new();
        self.walk(src, &mut deleted)?;

        let mut stats = FatStats::default();
        let volume_end = self.offset + self.total_sectors as u64 * self.bytes_per_sector as u64;

        for df in deleted {
            if df.size < min_size {
                continue;
            }
            // Validate before trusting the entry's cluster/size fields.
            if df.size == 0 || df.start_cluster < 2 || df.start_cluster > self.max_valid_cluster() {
                stats.skipped += 1;
                continue;
            }
            let start = self.cluster_offset(df.start_cluster);
            if start + df.size as u64 > volume_end {
                stats.skipped += 1;
                continue;
            }

            match self.write_file(src, out_dir, &df) {
                Ok(written) => {
                    stats.recovered += 1;
                    stats.bytes_recovered += written;
                }
                Err(_) => stats.skipped += 1,
            }
        }
        Ok(stats)
    }

    /// Stream a recovered file to disk under `out_dir`, assuming contiguous data.
    fn write_file(&self, src: &Source, out_dir: &Path, df: &DeletedFile) -> Result<u64> {
        let target = unique_path(out_dir, &df.path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut out =
            fs::File::create(&target).with_context(|| format!("creating {}", target.display()))?;

        let mut remaining = df.size as u64;
        let mut pos = self.cluster_offset(df.start_cluster);
        let mut buf = vec![0u8; 1024 * 1024];
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
        out.flush().ok();
        Ok(df.size as u64 - remaining)
    }

    /// Walk live directories (starting at the root), collecting deleted files
    /// with their reconstructed relative paths.
    fn walk(&self, src: &Source, out: &mut Vec<DeletedFile>) -> Result<()> {
        let mut visited: HashSet<u32> = HashSet::new();
        // Stack of (directory location, path-so-far, depth).
        let mut stack: Vec<(DirLoc, PathBuf, usize)> =
            vec![(self.root_location(), PathBuf::new(), 0)];

        while let Some((loc, path, depth)) = stack.pop() {
            let bytes = match self.read_directory(src, loc, &mut visited) {
                Ok(b) => b,
                Err(_) => continue,
            };
            for entry in parse_entries(&bytes) {
                if entry.is_dir && !entry.deleted {
                    if entry.name == "." || entry.name == ".." {
                        continue;
                    }
                    if depth < MAX_DIR_DEPTH
                        && entry.start_cluster >= 2
                        && entry.start_cluster <= self.max_valid_cluster()
                        && !visited.contains(&entry.start_cluster)
                    {
                        let child = path.join(sanitize_component(&entry.name));
                        stack.push((DirLoc::Cluster(entry.start_cluster), child, depth + 1));
                    }
                } else if !entry.is_dir && entry.deleted {
                    out.push(DeletedFile {
                        path: path.join(sanitize_component(&entry.name)),
                        start_cluster: entry.start_cluster,
                        size: entry.size,
                    });
                }
            }
        }
        Ok(())
    }

    fn root_location(&self) -> DirLoc {
        match self.fat_type {
            FatType::Fat32 => DirLoc::Cluster(self.root_cluster),
            _ => DirLoc::RootRegion,
        }
    }

    /// Read all raw bytes of a directory.
    fn read_directory(
        &self,
        src: &Source,
        loc: DirLoc,
        visited: &mut HashSet<u32>,
    ) -> Result<Vec<u8>> {
        match loc {
            DirLoc::RootRegion => {
                let off =
                    self.offset + self.first_root_dir_sector as u64 * self.bytes_per_sector as u64;
                let len = self.root_dir_sectors as usize * self.bytes_per_sector as usize;
                let mut buf = vec![0u8; len];
                let n = src.read_at(off, &mut buf)?;
                buf.truncate(n);
                Ok(buf)
            }
            DirLoc::Cluster(start) => {
                let mut buf = Vec::new();
                let mut cluster = start;
                let cb = self.cluster_bytes() as usize;
                loop {
                    if cluster < 2 || cluster > self.max_valid_cluster() {
                        break;
                    }
                    if !visited.insert(cluster) {
                        break; // loop guard
                    }
                    if buf.len() as u64 + cb as u64 > MAX_DIR_BYTES {
                        break;
                    }
                    let mut chunk = vec![0u8; cb];
                    let n = src.read_at(self.cluster_offset(cluster), &mut chunk)?;
                    chunk.truncate(n);
                    buf.extend_from_slice(&chunk);
                    match self.next_cluster(src, cluster)? {
                        Some(next) => cluster = next,
                        None => break,
                    }
                }
                Ok(buf)
            }
        }
    }
}

#[derive(Clone, Copy)]
enum DirLoc {
    RootRegion,
    Cluster(u32),
}

/// A directory entry after parsing (short entry, with LFN already merged).
struct ParsedEntry {
    name: String,
    deleted: bool,
    is_dir: bool,
    start_cluster: u32,
    size: u32,
}

/// Parse a directory's raw bytes into entries, merging LFN runs into the
/// following short entry.
fn parse_entries(bytes: &[u8]) -> Vec<ParsedEntry> {
    let mut entries = Vec::new();
    // LFN parts collected in physical order (highest sequence first).
    let mut lfn_parts: Vec<String> = Vec::new();

    for slot in bytes.chunks_exact(ENTRY_SIZE) {
        let first = slot[0];
        if first == 0x00 {
            // Free slot that has never been used; reset any pending LFN run.
            lfn_parts.clear();
            continue;
        }
        let attr = slot[11];

        if attr == ATTR_LFN {
            // LFN entry: collect its 13 name characters even if deleted.
            lfn_parts.push(extract_lfn_chars(slot));
            continue;
        }
        if attr & ATTR_VOLUME_ID != 0 && attr & ATTR_DIRECTORY == 0 {
            // Volume label entry; ignore.
            lfn_parts.clear();
            continue;
        }

        let deleted = first == DELETED_MARKER;
        let name = if !lfn_parts.is_empty() {
            assemble_lfn(&lfn_parts)
        } else {
            short_name(slot, deleted)
        };
        lfn_parts.clear();

        if name.is_empty() {
            continue;
        }

        let is_dir = attr & ATTR_DIRECTORY != 0;
        let hi = u16::from_le_bytes([slot[20], slot[21]]) as u32;
        let lo = u16::from_le_bytes([slot[26], slot[27]]) as u32;
        let start_cluster = (hi << 16) | lo;
        let size = u32::from_le_bytes([slot[28], slot[29], slot[30], slot[31]]);

        entries.push(ParsedEntry {
            name,
            deleted,
            is_dir,
            start_cluster,
            size,
        });
    }
    entries
}

/// Reconstruct the 8.3 short name from a directory slot.
fn short_name(slot: &[u8], deleted: bool) -> String {
    let mut base: Vec<u8> = slot[0..8].to_vec();
    if deleted {
        // The first character was overwritten by the deletion marker; mark it
        // as unknown so the recovered name is still usable.
        base[0] = b'_';
    } else if base[0] == 0x05 {
        // 0x05 stands in for a real leading 0xE5 byte.
        base[0] = 0xE5;
    }
    let name: String = String::from_utf8_lossy(&base).trim_end().to_string();
    let ext: String = String::from_utf8_lossy(&slot[8..11]).trim_end().to_string();
    if ext.is_empty() {
        name
    } else {
        format!("{name}.{ext}")
    }
}

/// Extract the (up to) 13 UTF-16 characters held by a single LFN slot.
fn extract_lfn_chars(slot: &[u8]) -> String {
    let mut units: Vec<u16> = Vec::with_capacity(13);
    let ranges = [1usize..11, 14..26, 28..32];
    for r in ranges {
        for pair in slot[r].chunks_exact(2) {
            units.push(u16::from_le_bytes([pair[0], pair[1]]));
        }
    }
    let mut out = String::new();
    for ch in char::decode_utf16(units) {
        match ch {
            Ok('\u{0000}') => break,    // name terminator
            Ok('\u{FFFF}') => continue, // padding
            Ok(c) => out.push(c),
            Err(_) => continue,
        }
    }
    out
}

/// Assemble LFN parts (collected highest-sequence-first) into the full name.
fn assemble_lfn(parts: &[String]) -> String {
    // Physical order is reverse of logical order, so concatenate back-to-front.
    let mut name = String::new();
    for part in parts.iter().rev() {
        name.push_str(part);
    }
    name.trim_end_matches(['\u{0000}', '\u{FFFF}']).to_string()
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
    for i in 1.. {
        let name = match &ext {
            Some(e) => format!("{stem}_{i}.{e}"),
            None => format!("{stem}_{i}"),
        };
        let candidate = out_dir.join(&parent).join(name);
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!()
}
