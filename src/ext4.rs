//! Filesystem-aware recovery for ext2/ext3/ext4 volumes.
//!
//! ext is the trickiest filesystem to undelete. When a file is removed, ext4
//! clears the inode's link count, stamps a deletion time, and frees it; the
//! directory entry is unlinked by folding its space into the previous entry.
//! The bytes of the removed directory entry — its **name and inode number** —
//! usually remain in the directory block's *slack space*, and the inode (with
//! its **extent tree** or block pointers) often survives until reused.
//!
//! This backend therefore walks the live directory tree, scans the slack inside
//! each directory block for stale entries (the classic `extundelete` /
//! `ext3grep` technique), and for any whose inode is now deleted but still has a
//! readable block map, recovers the file with its original name and path.
//!
//! ## What this cannot do
//!
//! If the inode's extent tree was zeroed on deletion, or the inode has been
//! reused, the file's contents cannot be found from metadata alone — that needs
//! journal (`jbd2`) recovery, which is out of scope. Fall back to `scan`
//! (carving) in that case.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use crate::recover::RecoverStats;
use crate::source::Source;

const SUPERBLOCK_OFFSET: u64 = 1024;
const EXT_MAGIC: u16 = 0xEF53;
const INCOMPAT_FILETYPE: u32 = 0x0002;
const INCOMPAT_64BIT: u32 = 0x0080;
const FLAG_EXTENTS: u32 = 0x0008_0000;
const EXTENT_MAGIC: u16 = 0xF30A;
const MODE_FMT: u16 = 0xF000;
const MODE_DIR: u16 = 0x4000;
const MODE_REG: u16 = 0x8000;
const ROOT_INODE: u32 = 2;
const MAX_DIR_DEPTH: usize = 64;
const MAX_EXTENT_DEPTH: usize = 6;

/// A parsed ext2/3/4 volume.
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    block_size: u64,
    inode_size: u64,
    inodes_per_group: u32,
    filetype_dirents: bool,
    total_blocks: u64,
    /// Block number of each group's inode table.
    inode_tables: Vec<u64>,
}

/// Does the superblock at `vol_offset + 1024` carry the ext magic?
pub fn is_ext_volume(src: &Source, vol_offset: u64) -> bool {
    let mut magic = [0u8; 2];
    if src
        .read_at(vol_offset + SUPERBLOCK_OFFSET + 0x38, &mut magic)
        .unwrap_or(0)
        < 2
    {
        return false;
    }
    u16::from_le_bytes(magic) == EXT_MAGIC
}

impl Volume {
    /// Parse and validate the ext superblock at `offset`.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let mut sb = [0u8; 1024];
        if src.read_at(offset + SUPERBLOCK_OFFSET, &mut sb)? < 1024 {
            bail!("could not read ext superblock at offset {offset}");
        }
        if u16::from_le_bytes([sb[0x38], sb[0x39]]) != EXT_MAGIC {
            bail!("not an ext2/3/4 volume at offset {offset}");
        }

        let inodes_count = u32::from_le_bytes([sb[0], sb[1], sb[2], sb[3]]);
        let blocks_count_lo = u32::from_le_bytes([sb[4], sb[5], sb[6], sb[7]]) as u64;
        let log_block_size = u32::from_le_bytes([sb[0x18], sb[0x19], sb[0x1A], sb[0x1B]]);
        let block_size = 1024u64 << log_block_size;
        let first_data_block = u32::from_le_bytes([sb[0x14], sb[0x15], sb[0x16], sb[0x17]]) as u64;
        let blocks_per_group = u32::from_le_bytes([sb[0x20], sb[0x21], sb[0x22], sb[0x23]]);
        let inodes_per_group = u32::from_le_bytes([sb[0x28], sb[0x29], sb[0x2A], sb[0x2B]]);
        let inode_size = {
            let s = u16::from_le_bytes([sb[0x58], sb[0x59]]) as u64;
            if s == 0 {
                128
            } else {
                s
            }
        };
        let feature_incompat = u32::from_le_bytes([sb[0x60], sb[0x61], sb[0x62], sb[0x63]]);
        let is_64bit = feature_incompat & INCOMPAT_64BIT != 0;
        let desc_size = if is_64bit {
            let d = u16::from_le_bytes([sb[0xFE], sb[0xFF]]) as u64;
            if d < 32 {
                32
            } else {
                d
            }
        } else {
            32
        };
        let blocks_count_hi = if is_64bit {
            u32::from_le_bytes([sb[0x150], sb[0x151], sb[0x152], sb[0x153]]) as u64
        } else {
            0
        };
        let total_blocks = blocks_count_lo | (blocks_count_hi << 32);

        if block_size == 0 || inodes_per_group == 0 || blocks_per_group == 0 {
            bail!("invalid ext superblock geometry");
        }

        let group_count = inodes_count.div_ceil(inodes_per_group) as u64;
        // The group descriptor table follows the superblock block.
        let gdt_block = first_data_block + 1;
        let gdt_start = offset + gdt_block * block_size;

        let mut inode_tables = Vec::with_capacity(group_count as usize);
        for g in 0..group_count {
            let desc_off = gdt_start + g * desc_size;
            let mut d = vec![0u8; desc_size as usize];
            if src.read_at(desc_off, &mut d)? < desc_size as usize {
                break;
            }
            let lo = u32::from_le_bytes([d[8], d[9], d[10], d[11]]) as u64;
            let hi = if desc_size >= 64 && is_64bit {
                u32::from_le_bytes([d[0x28], d[0x29], d[0x2A], d[0x2B]]) as u64
            } else {
                0
            };
            inode_tables.push(lo | (hi << 32));
        }
        if inode_tables.is_empty() {
            bail!("ext volume has no block groups");
        }

        Ok(Volume {
            offset,
            block_size,
            inode_size,
            inodes_per_group,
            filetype_dirents: feature_incompat & INCOMPAT_FILETYPE != 0,
            total_blocks,
            inode_tables,
        })
    }

    fn read_block(&self, src: &Source, block: u64) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; self.block_size as usize];
        let n = src.read_at(self.offset + block * self.block_size, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Read a raw inode by 1-based number.
    fn read_inode(&self, src: &Source, ino: u32) -> Result<Option<Vec<u8>>> {
        if ino == 0 {
            return Ok(None);
        }
        let group = ((ino - 1) / self.inodes_per_group) as usize;
        let index = ((ino - 1) % self.inodes_per_group) as u64;
        let table = match self.inode_tables.get(group) {
            Some(&t) => t,
            None => return Ok(None),
        };
        let off = self.offset + table * self.block_size + index * self.inode_size;
        let mut buf = vec![0u8; self.inode_size as usize];
        if src.read_at(off, &mut buf)? < self.inode_size as usize {
            return Ok(None);
        }
        Ok(Some(buf))
    }

    /// Recover all deleted files into `out_dir`.
    pub fn recover_deleted(
        &self,
        src: &Source,
        out_dir: &Path,
        min_size: u64,
    ) -> Result<RecoverStats> {
        let mut found: BTreeMap<u32, (PathBuf, u64)> = BTreeMap::new();
        self.walk(src, &mut found)?;

        let mut stats = RecoverStats::default();
        for (ino, (rel, size)) in found {
            if size < min_size {
                continue;
            }
            let inode = match self.read_inode(src, ino) {
                Ok(Some(i)) => i,
                _ => {
                    stats.skipped += 1;
                    continue;
                }
            };
            match self.write_file(src, out_dir, &rel, &inode, size) {
                Ok(written) if written > 0 => {
                    stats.recovered += 1;
                    stats.bytes_recovered += written;
                }
                _ => stats.skipped += 1,
            }
        }
        Ok(stats)
    }

    /// Walk live directories from root, collecting deleted regular files keyed
    /// by inode (so multiple stale links don't duplicate).
    fn walk(&self, src: &Source, found: &mut BTreeMap<u32, (PathBuf, u64)>) -> Result<()> {
        let mut visited: HashSet<u32> = HashSet::new();
        let mut stack: Vec<(u32, PathBuf, usize)> = vec![(ROOT_INODE, PathBuf::new(), 0)];

        while let Some((dir_ino, path, depth)) = stack.pop() {
            if !visited.insert(dir_ino) {
                continue;
            }
            let inode = match self.read_inode(src, dir_ino) {
                Ok(Some(i)) => i,
                _ => continue,
            };
            if inode_mode(&inode) & MODE_FMT != MODE_DIR {
                continue;
            }
            // The directory is live, so its block map is intact.
            let data = match self.read_file_data(src, &inode, dir_size(&inode)) {
                Ok(d) => d,
                Err(_) => continue,
            };

            for entry in self.parse_dir_block(&data) {
                if entry.name == "." || entry.name == ".." || entry.ino == 0 {
                    continue;
                }
                let child = match self.read_inode(src, entry.ino) {
                    Ok(Some(i)) => i,
                    _ => continue,
                };
                let mode = inode_mode(&child);
                let deleted = inode_links(&child) == 0 || inode_dtime(&child) != 0;

                if mode & MODE_FMT == MODE_DIR && !deleted {
                    if depth < MAX_DIR_DEPTH {
                        stack.push((
                            entry.ino,
                            path.join(sanitize_component(&entry.name)),
                            depth + 1,
                        ));
                    }
                } else if mode & MODE_FMT == MODE_REG && deleted {
                    let size = reg_size(&child);
                    found
                        .entry(entry.ino)
                        .or_insert_with(|| (path.join(sanitize_component(&entry.name)), size));
                }
            }
        }
        Ok(())
    }

    /// Parse directory entries from a directory's data, including stale entries
    /// hidden in each record's slack space.
    fn parse_dir_block(&self, data: &[u8]) -> Vec<DirEntry> {
        let mut entries = Vec::new();
        // Walk record by record across all directory blocks.
        let block_size = self.block_size as usize;
        let mut base = 0;
        while base < data.len() {
            let block_end = (base + block_size).min(data.len());
            let mut off = base;
            while off + 8 <= block_end {
                let rec_len = u16::from_le_bytes([data[off + 4], data[off + 5]]) as usize;
                if rec_len < 8 || off + rec_len > block_end {
                    break;
                }
                // Live entry at `off`, then scan its slack for stale entries.
                self.read_dirent(data, off, off + rec_len, &mut entries);
                off += rec_len;
            }
            base = block_end;
        }
        entries
    }

    /// Read the entry at `off` and any stale entries packed into [off, limit).
    fn read_dirent(&self, data: &[u8], off: usize, limit: usize, out: &mut Vec<DirEntry>) {
        let mut pos = off;
        let mut first = true;
        while pos + 8 <= limit {
            let ino = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            let name_len = if self.filetype_dirents {
                data[pos + 6] as usize
            } else {
                u16::from_le_bytes([data[pos + 6], data[pos + 7]]) as usize
            };
            let rec_len = u16::from_le_bytes([data[pos + 4], data[pos + 5]]) as usize;

            if ino != 0 && name_len > 0 && pos + 8 + name_len <= limit {
                let name = String::from_utf8_lossy(&data[pos + 8..pos + 8 + name_len]).to_string();
                out.push(DirEntry { ino, name });
            }

            // Advance: for the first (live) entry use rec_len; afterwards step by
            // the real entry size to uncover stale entries in the slack.
            let real = round8(8 + name_len);
            let step = if first {
                round8(8 + name_len).min(rec_len.max(8))
            } else {
                real
            };
            first = false;
            if step == 0 {
                break;
            }
            pos += step;
        }
    }

    /// Read up to `size` bytes of a file's content from its inode block map.
    fn read_file_data(&self, src: &Source, inode: &[u8], size: u64) -> Result<Vec<u8>> {
        if size == 0 || size > self.total_blocks * self.block_size {
            return Ok(Vec::new());
        }
        let num_blocks = size.div_ceil(self.block_size);
        let blocks = self.map_blocks(src, inode, num_blocks)?;

        let mut out = Vec::with_capacity(size as usize);
        for b in blocks {
            if out.len() as u64 >= size {
                break;
            }
            if b == 0 {
                // Sparse hole.
                let take = (size - out.len() as u64).min(self.block_size) as usize;
                out.resize(out.len() + take, 0);
            } else {
                let block = self.read_block(src, b)?;
                out.extend_from_slice(&block);
            }
        }
        out.truncate(size as usize);
        Ok(out)
    }

    /// Map logical blocks 0..num_blocks to physical block numbers (0 = hole).
    fn map_blocks(&self, src: &Source, inode: &[u8], num_blocks: u64) -> Result<Vec<u64>> {
        let flags = inode_flags(inode);
        let i_block = &inode[0x28..0x28 + 60];

        if flags & FLAG_EXTENTS != 0 {
            let mut map: BTreeMap<u32, (u64, u32)> = BTreeMap::new();
            self.collect_extents(src, i_block, &mut map, 0)?;
            let mut out = vec![0u64; num_blocks as usize];
            for (logical, (phys, len)) in map {
                for k in 0..len as u64 {
                    let l = logical as u64 + k;
                    if l < num_blocks {
                        out[l as usize] = phys + k;
                    }
                }
            }
            Ok(out)
        } else {
            self.map_indirect(src, i_block, num_blocks)
        }
    }

    /// Recursively gather extents into `map` (logical block -> (physical, len)).
    fn collect_extents(
        &self,
        src: &Source,
        node: &[u8],
        map: &mut BTreeMap<u32, (u64, u32)>,
        depth_guard: usize,
    ) -> Result<()> {
        if node.len() < 12 || depth_guard > MAX_EXTENT_DEPTH {
            return Ok(());
        }
        if u16::from_le_bytes([node[0], node[1]]) != EXTENT_MAGIC {
            return Ok(());
        }
        let entries = u16::from_le_bytes([node[2], node[3]]) as usize;
        let depth = u16::from_le_bytes([node[6], node[7]]);

        for i in 0..entries {
            let e = match node.get(12 + i * 12..12 + i * 12 + 12) {
                Some(s) => s,
                None => break,
            };
            if depth == 0 {
                let logical = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
                let raw_len = u16::from_le_bytes([e[4], e[5]]);
                let len = if raw_len > 32768 {
                    raw_len - 32768
                } else {
                    raw_len
                };
                let start_hi = u16::from_le_bytes([e[6], e[7]]) as u64;
                let start_lo = u32::from_le_bytes([e[8], e[9], e[10], e[11]]) as u64;
                map.insert(logical, ((start_hi << 32) | start_lo, len as u32));
            } else {
                let leaf_lo = u32::from_le_bytes([e[4], e[5], e[6], e[7]]) as u64;
                let leaf_hi = u16::from_le_bytes([e[8], e[9]]) as u64;
                let child = (leaf_hi << 32) | leaf_lo;
                let block = self.read_block(src, child)?;
                self.collect_extents(src, &block, map, depth_guard + 1)?;
            }
        }
        Ok(())
    }

    /// Map blocks via the classic ext2/3 direct + indirect pointers.
    fn map_indirect(&self, src: &Source, i_block: &[u8], num_blocks: u64) -> Result<Vec<u64>> {
        let mut out = Vec::with_capacity(num_blocks as usize);
        let ptrs_per_block = self.block_size / 4;

        // 12 direct pointers.
        for i in 0..12usize {
            if out.len() as u64 >= num_blocks {
                return Ok(out);
            }
            out.push(u32::from_le_bytes([
                i_block[i * 4],
                i_block[i * 4 + 1],
                i_block[i * 4 + 2],
                i_block[i * 4 + 3],
            ]) as u64);
        }

        let single =
            u32::from_le_bytes([i_block[48], i_block[49], i_block[50], i_block[51]]) as u64;
        let double =
            u32::from_le_bytes([i_block[52], i_block[53], i_block[54], i_block[55]]) as u64;
        let triple =
            u32::from_le_bytes([i_block[56], i_block[57], i_block[58], i_block[59]]) as u64;

        self.read_indirect(src, single, 1, num_blocks, &mut out)?;
        self.read_indirect(src, double, 2, num_blocks, &mut out)?;
        self.read_indirect(src, triple, 3, num_blocks, &mut out)?;
        let _ = ptrs_per_block;
        Ok(out)
    }

    fn read_indirect(
        &self,
        src: &Source,
        block: u64,
        level: u8,
        num_blocks: u64,
        out: &mut Vec<u64>,
    ) -> Result<()> {
        if block == 0 || out.len() as u64 >= num_blocks {
            return Ok(());
        }
        let data = self.read_block(src, block)?;
        let count = data.len() / 4;
        for i in 0..count {
            if out.len() as u64 >= num_blocks {
                break;
            }
            let ptr = u32::from_le_bytes([
                data[i * 4],
                data[i * 4 + 1],
                data[i * 4 + 2],
                data[i * 4 + 3],
            ]) as u64;
            if level == 1 {
                out.push(ptr);
            } else {
                self.read_indirect(src, ptr, level - 1, num_blocks, out)?;
            }
        }
        Ok(())
    }

    fn write_file(
        &self,
        src: &Source,
        out_dir: &Path,
        rel: &Path,
        inode: &[u8],
        size: u64,
    ) -> Result<u64> {
        let data = self.read_file_data(src, inode, size)?;
        if data.is_empty() {
            return Ok(0);
        }
        let target = unique_path(out_dir, rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out = fs::File::create(&target)?;
        out.write_all(&data)?;
        out.flush().ok();
        Ok(data.len() as u64)
    }
}

struct DirEntry {
    ino: u32,
    name: String,
}

fn inode_mode(inode: &[u8]) -> u16 {
    u16::from_le_bytes([inode[0], inode[1]])
}
fn inode_links(inode: &[u8]) -> u16 {
    u16::from_le_bytes([inode[0x1A], inode[0x1B]])
}
fn inode_dtime(inode: &[u8]) -> u32 {
    u32::from_le_bytes([inode[0x14], inode[0x15], inode[0x16], inode[0x17]])
}
fn inode_flags(inode: &[u8]) -> u32 {
    u32::from_le_bytes([inode[0x20], inode[0x21], inode[0x22], inode[0x23]])
}
fn dir_size(inode: &[u8]) -> u64 {
    u32::from_le_bytes([inode[4], inode[5], inode[6], inode[7]]) as u64
}
/// Regular-file size combines the low and high 32-bit halves.
fn reg_size(inode: &[u8]) -> u64 {
    let lo = u32::from_le_bytes([inode[4], inode[5], inode[6], inode[7]]) as u64;
    let hi = u32::from_le_bytes([inode[0x6C], inode[0x6D], inode[0x6E], inode[0x6F]]) as u64;
    lo | (hi << 32)
}

fn round8(n: usize) -> usize {
    n.div_ceil(8) * 8
}

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
