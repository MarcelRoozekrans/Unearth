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
//! ## Journal (jbd2) recovery
//!
//! ext4 usually *zeroes* the inode's extent tree on deletion, leaving the live
//! inode present but unusable. The filesystem journal (inode 8) often still
//! holds an **older copy of that inode-table block** from before the delete,
//! with the extents intact. This backend scans the jbd2 journal, collects the
//! journaled copies of inode-table blocks, and when a deleted file's live inode
//! has no usable block map it recovers the data from the journaled inode.
//!
//! ## What this cannot do
//!
//! If neither the live inode nor any journaled copy has an intact block map (the
//! journal wrapped around, or the inode was reused), the contents cannot be
//! found from metadata alone — fall back to `scan` (carving).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use crate::hash;
use crate::recover::{RecoverOptions, RecoverStats};
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
const DEFAULT_JOURNAL_INODE: u32 = 8;
const MAX_DIR_DEPTH: usize = 64;
const MAX_EXTENT_DEPTH: usize = 6;

// jbd2 journal constants (all on-disk journal fields are big-endian).
const JBD2_MAGIC: u32 = 0xC03B_3998;
const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
const JBD2_FLAG_SAME_UUID: u32 = 0x02;
const JBD2_FLAG_LAST_TAG: u32 = 0x08;
const JBD2_INCOMPAT_64BIT: u32 = 0x02;
const JBD2_INCOMPAT_CSUM_V3: u32 = 0x10;
/// Cap on journal blocks scanned, to bound work on a corrupt journal.
const MAX_JOURNAL_BLOCKS: u64 = 1 << 21;

/// A parsed ext2/3/4 volume.
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    block_size: u64,
    inode_size: u64,
    inodes_per_group: u32,
    filetype_dirents: bool,
    total_blocks: u64,
    /// Inode number of the journal (`s_journal_inum`, usually 8).
    journal_inum: u32,
    /// Block number of each group's inode table.
    inode_tables: Vec<u64>,
    /// Block number of each group's block bitmap.
    block_bitmaps: Vec<u64>,
    /// Blocks per group (`s_blocks_per_group`).
    blocks_per_group: u32,
    /// First data block (`s_first_data_block`: 1 for 1 KiB blocks, else 0).
    first_data_block: u64,
    /// Volume label (`s_volume_name`), empty when unset.
    label: String,
    /// Filesystem UUID (`s_uuid`), `None` when unset.
    uuid: Option<String>,
    /// Whether the filesystem was cleanly unmounted (`s_state` bit 0).
    clean: bool,
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
        // ext block size is 1024 << log_block_size; cap it so a corrupt value
        // cannot overflow the shift or trigger huge allocations (max 64 KiB).
        if log_block_size > 6 {
            bail!("implausible ext block size shift {log_block_size}");
        }
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
        // Inode helpers read fields up to offset 0x70 and the inode must fit in
        // a block; reject sizes outside the spec range.
        if inode_size < 128 || inode_size > block_size {
            bail!("implausible ext inode size {inode_size}");
        }
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

        let journal_inum = {
            let n = u32::from_le_bytes([sb[0xE0], sb[0xE1], sb[0xE2], sb[0xE3]]);
            if n == 0 {
                DEFAULT_JOURNAL_INODE
            } else {
                n
            }
        };

        let group_count = inodes_count.div_ceil(inodes_per_group) as u64;
        // The group descriptor table follows the superblock block.
        let gdt_block = first_data_block + 1;
        let gdt_start = offset + gdt_block * block_size;

        // Reserve conservatively; the loop stops early once reads run past the
        // source, so a corrupt `group_count` can't drive a huge reservation.
        let mut inode_tables = Vec::with_capacity((group_count as usize).min(4096));
        let mut block_bitmaps = Vec::with_capacity((group_count as usize).min(4096));
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

            // Block bitmap: bg_block_bitmap_lo at offset 0, _hi at 0x20 (64-bit).
            let bb_lo = u32::from_le_bytes([d[0], d[1], d[2], d[3]]) as u64;
            let bb_hi = if desc_size >= 64 && is_64bit {
                u32::from_le_bytes([d[0x20], d[0x21], d[0x22], d[0x23]]) as u64
            } else {
                0
            };
            block_bitmaps.push(bb_lo | (bb_hi << 32));
        }
        if inode_tables.is_empty() {
            bail!("ext volume has no block groups");
        }

        // s_volume_name: 16 bytes at superblock offset 0x78, NUL-padded.
        let raw = &sb[0x78..0x88];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let label = String::from_utf8_lossy(&raw[..end]).into_owned();
        // s_uuid: 16 bytes at superblock offset 0x68.
        let uuid = crate::recover::format_uuid(&sb[0x68..0x78]);
        // s_state (u16 at 0x3A): bit 0 (EXT2_VALID_FS) set => cleanly unmounted.
        let clean = u16::from_le_bytes([sb[0x3A], sb[0x3B]]) & 0x0001 != 0;

        Ok(Volume {
            offset,
            block_size,
            inode_size,
            inodes_per_group,
            filetype_dirents: feature_incompat & INCOMPAT_FILETYPE != 0,
            total_blocks,
            journal_inum,
            inode_tables,
            block_bitmaps,
            blocks_per_group,
            first_data_block,
            label,
            uuid,
            clean,
        })
    }

    /// The volume label (`s_volume_name`), empty when unset.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The filesystem UUID (`s_uuid`), or `None` when unset.
    pub fn uuid(&self) -> Option<String> {
        self.uuid.clone()
    }

    /// Whether the filesystem was cleanly unmounted (`s_state` bit 0).
    pub fn is_clean(&self) -> bool {
        self.clean
    }

    fn read_block(&self, src: &Source, block: u64) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.read_block_into(src, block, &mut buf)?;
        Ok(buf)
    }

    /// Read one block into a reusable buffer (sized to the block, truncated to
    /// the bytes actually read). Avoids a fresh allocation per call.
    fn read_block_into(&self, src: &Source, block: u64, buf: &mut Vec<u8>) -> Result<()> {
        buf.resize(self.block_size as usize, 0);
        let at = self
            .offset
            .saturating_add(block.saturating_mul(self.block_size));
        let n = src.read_at(at, buf)?;
        buf.truncate(n);
        Ok(())
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
        let off = self
            .offset
            .saturating_add(table.saturating_mul(self.block_size))
            .saturating_add(index.saturating_mul(self.inode_size));
        let mut buf = vec![0u8; self.inode_size as usize];
        if src.read_at(off, &mut buf)? < self.inode_size as usize {
            return Ok(None);
        }
        Ok(Some(buf))
    }

    /// Total size of the volume in bytes.
    pub fn size(&self) -> u64 {
        self.total_blocks.saturating_mul(self.block_size)
    }

    /// Absolute byte ranges of the volume's **free** blocks, merged where
    /// contiguous, from each block group's block bitmap (a clear bit means the
    /// block is free). Carving these recovers deleted data without re-finding
    /// blocks still allocated to live files.
    pub fn free_extents(&self, src: &Source) -> Result<Vec<(u64, u64)>> {
        if self.blocks_per_group == 0 {
            return Ok(Vec::new());
        }
        let mut out: Vec<(u64, u64)> = Vec::new();
        let mut cur_group = u64::MAX;
        let mut bitmap: Vec<u8> = Vec::new();
        let mut block = self.first_data_block;
        while block < self.total_blocks {
            let rel = block - self.first_data_block;
            let group = rel / self.blocks_per_group as u64;
            if group != cur_group {
                let bmp_block = match self.block_bitmaps.get(group as usize) {
                    Some(&b) => b,
                    None => break,
                };
                bitmap = self.read_block(src, bmp_block)?;
                cur_group = group;
            }
            let bit = (rel % self.blocks_per_group as u64) as usize;
            // A bit past the bitmap we read is treated as allocated (safe).
            let allocated = bitmap
                .get(bit / 8)
                .map(|b| b & (1 << (bit % 8)) != 0)
                .unwrap_or(true);
            if !allocated {
                let start = self.offset + block * self.block_size;
                match out.last_mut() {
                    Some(last) if last.0 + last.1 == start => last.1 += self.block_size,
                    _ => out.push((start, self.block_size)),
                }
            }
            block += 1;
        }
        Ok(out)
    }

    /// Recover all deleted files into `out_dir`.
    pub fn recover_deleted(
        &self,
        src: &Source,
        out_dir: &Path,
        opts: &RecoverOptions,
    ) -> Result<RecoverStats> {
        let mut found: BTreeMap<u32, (PathBuf, u64)> = BTreeMap::new();
        self.walk(src, &mut found)?;

        // Journaled copies of inode-table blocks let us recover files whose live
        // inode had its extent tree zeroed on deletion. Best effort: an empty
        // map just means we rely on the live inode.
        let journal = self.build_journal_map(src).unwrap_or_default();

        let mut stats = RecoverStats::default();
        let volume_bytes = self.total_blocks.saturating_mul(self.block_size);
        for (ino, (rel, _hint)) in found {
            // Prefer the live inode if it still has a usable block map; else fall
            // back to a journaled copy that does.
            let inode = match self.choose_inode(src, &journal, ino) {
                Some(i) => i,
                None => {
                    // Record the size hint so it still shows up as skipped.
                    stats.record_skipped(rel, 0);
                    continue;
                }
            };
            let size = reg_size(&inode);
            if !opts.size_ok(size) {
                continue;
            }
            if !opts.time_ok(crate::times::from_unix(inode_mtime(&inode))) {
                continue;
            }
            if !opts.name_ok(crate::recover::file_name_of(&rel)) {
                continue;
            }
            if size == 0 || size > volume_bytes {
                stats.record_skipped(rel, size);
                continue;
            }
            if opts.dry_run {
                stats.record_recovered(rel, size, None);
                continue;
            }
            match self.write_file(src, out_dir, &rel, &inode, size) {
                Ok((written, digest)) if written > 0 => {
                    stats.record_recovered(rel, size, Some(digest))
                }
                _ => stats.record_skipped(rel, size),
            }
        }
        Ok(stats)
    }

    /// Pick the inode bytes to recover from: the live inode if it still has a
    /// usable block map, otherwise a journaled copy that does.
    fn choose_inode(
        &self,
        src: &Source,
        journal: &HashMap<u64, Vec<Vec<u8>>>,
        ino: u32,
    ) -> Option<Vec<u8>> {
        if let Ok(Some(live)) = self.read_inode(src, ino) {
            if inode_has_blockmap(&live) {
                return Some(live);
            }
        }
        self.journaled_inode(journal, ino)
    }

    /// Look up a journaled copy of inode `ino` whose block map survived.
    fn journaled_inode(&self, journal: &HashMap<u64, Vec<Vec<u8>>>, ino: u32) -> Option<Vec<u8>> {
        if ino == 0 {
            return None;
        }
        let group = ((ino - 1) / self.inodes_per_group) as usize;
        let index = ((ino - 1) % self.inodes_per_group) as u64;
        let table = *self.inode_tables.get(group)?;
        let byte = table
            .saturating_mul(self.block_size)
            .saturating_add(index.saturating_mul(self.inode_size));
        let fs_block = byte / self.block_size;
        let within = (byte % self.block_size) as usize;
        let copies = journal.get(&fs_block)?;
        for copy in copies {
            if within + self.inode_size as usize <= copy.len() {
                let inode = copy[within..within + self.inode_size as usize].to_vec();
                if inode_has_blockmap(&inode) {
                    return Some(inode);
                }
            }
        }
        None
    }

    /// Block ranges (start, count) covering every group's inode table.
    fn inode_table_ranges(&self) -> Vec<(u64, u64)> {
        let blocks_per_table =
            (self.inodes_per_group as u64 * self.inode_size).div_ceil(self.block_size);
        self.inode_tables
            .iter()
            .map(|&start| (start, blocks_per_table))
            .collect()
    }

    /// Scan the jbd2 journal and collect journaled copies of inode-table blocks,
    /// keyed by filesystem block number (a block may have several copies).
    fn build_journal_map(&self, src: &Source) -> Result<HashMap<u64, Vec<Vec<u8>>>> {
        let mut map: HashMap<u64, Vec<Vec<u8>>> = HashMap::new();

        // The journal is itself a file; its live inode must be readable.
        let jinode = match self.read_inode(src, self.journal_inum)? {
            Some(i) if inode_has_blockmap(&i) => i,
            _ => return Ok(map),
        };
        let jsize = reg_size(&jinode);
        if jsize == 0 {
            return Ok(map);
        }
        let n_blocks = jsize.div_ceil(self.block_size);
        let jblocks = self.map_blocks(src, &jinode, n_blocks)?;
        if jblocks.is_empty() {
            return Ok(map);
        }

        // Journal superblock (first journal block), all fields big-endian.
        let sb = self.read_block(src, jblocks[0])?;
        if sb.len() < 0x2C || be32(&sb, 0) != JBD2_MAGIC {
            return Ok(map); // not a jbd2 journal
        }
        let feature_incompat = be32(&sb, 0x28);
        let csum_v3 = feature_incompat & JBD2_INCOMPAT_CSUM_V3 != 0;
        let is_64bit = feature_incompat & JBD2_INCOMPAT_64BIT != 0;
        let maxlen = (be32(&sb, 0x10) as u64).min(n_blocks);
        let first = be32(&sb, 0x14) as u64;

        let ranges = self.inode_table_ranges();
        let interesting = |blk: u64| ranges.iter().any(|&(s, c)| blk >= s && blk < s + c);

        let mut ji = first.max(1);
        let mut steps = 0u64;
        // Reused across the scan; only the descriptor-named data blocks (kept in
        // the map) are allocated fresh.
        let mut block = Vec::new();
        while ji < maxlen && (ji as usize) < jblocks.len() && steps < MAX_JOURNAL_BLOCKS {
            steps += 1;
            self.read_block_into(src, jblocks[ji as usize], &mut block)?;
            if block.len() < 12 || be32(&block, 0) != JBD2_MAGIC {
                ji += 1;
                continue;
            }
            if be32(&block, 4) != JBD2_DESCRIPTOR_BLOCK {
                ji += 1; // commit / revoke / superblock
                continue;
            }
            // Tags name the filesystem blocks of the data blocks that follow.
            let tags = parse_journal_tags(&block, csum_v3, is_64bit);
            for (k, &blocknr) in tags.iter().enumerate() {
                let data_ji = ji + 1 + k as u64;
                if (data_ji as usize) >= jblocks.len() {
                    break;
                }
                if interesting(blocknr) {
                    let content = self.read_block(src, jblocks[data_ji as usize])?;
                    map.entry(blocknr).or_default().push(content);
                }
            }
            ji += 1 + tags.len() as u64;
        }
        Ok(map)
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
        if size == 0 || size > self.total_blocks.saturating_mul(self.block_size) {
            return Ok(Vec::new());
        }
        // A recovered file cannot contain more bytes than the source holds;
        // clamp so a corrupt size can't drive a huge allocation.
        let size = size.min(src.size);
        if size == 0 {
            return Ok(Vec::new());
        }
        let num_blocks = size.div_ceil(self.block_size);
        let blocks = self.map_blocks(src, inode, num_blocks)?;

        let mut out = Vec::with_capacity(size as usize);
        for b in blocks {
            let done = out.len() as u64;
            if done >= size {
                break;
            }
            let take = (size - done).min(self.block_size) as usize;
            let base = out.len();
            // Read straight into the output (sparse holes stay zero-filled).
            out.resize(base + take, 0);
            if b != 0 {
                let at = self
                    .offset
                    .saturating_add(b.saturating_mul(self.block_size));
                let n = src.read_at(at, &mut out[base..])?;
                if n < take {
                    out.truncate(base + n); // short read at end of source
                    break;
                }
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
    ) -> Result<(u64, [u8; 32])> {
        let data = self.read_file_data(src, inode, size)?;
        if data.is_empty() {
            return Ok((0, hash::digest(&data)));
        }
        let target = unique_path(out_dir, rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out = fs::File::create(&target)?;
        out.write_all(&data)?;
        out.flush().ok();
        // Restore timestamps from the inode (Unix seconds).
        let mtime = crate::times::from_unix(inode_mtime(inode));
        let atime = crate::times::from_unix(inode_atime(inode));
        crate::times::apply(&out, mtime, atime);
        Ok((data.len() as u64, hash::digest(&data)))
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
fn inode_atime(inode: &[u8]) -> u32 {
    u32::from_le_bytes([inode[0x08], inode[0x09], inode[0x0A], inode[0x0B]])
}
fn inode_mtime(inode: &[u8]) -> u32 {
    u32::from_le_bytes([inode[0x10], inode[0x11], inode[0x12], inode[0x13]])
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

/// Read a big-endian u32 at `off` (journal fields are big-endian); 0 if short.
fn be32(buf: &[u8], off: usize) -> u32 {
    match buf.get(off..off + 4) {
        Some(b) => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}

/// Does this inode still have a usable block map (extent tree or block
/// pointers)? Deletion on ext4 zeroes the extent tree, leaving the inode
/// present but unusable — in which case a journaled copy may still be intact.
fn inode_has_blockmap(inode: &[u8]) -> bool {
    if inode.len() < 0x28 + 60 {
        return false;
    }
    let i_block = &inode[0x28..0x28 + 60];
    if inode_flags(inode) & FLAG_EXTENTS != 0 {
        u16::from_le_bytes([i_block[0], i_block[1]]) == EXTENT_MAGIC
    } else {
        i_block.iter().any(|&b| b != 0)
    }
}

/// Parse a journal descriptor block's tags into the filesystem block numbers of
/// the data blocks that follow it.
fn parse_journal_tags(block: &[u8], csum_v3: bool, is_64bit: bool) -> Vec<u64> {
    let mut tags = Vec::new();
    let mut pos = 12; // after the 12-byte journal block header
    loop {
        if csum_v3 {
            // journal_block_tag3_t: blocknr, flags, blocknr_high, checksum (BE).
            if pos + 16 > block.len() {
                break;
            }
            let lo = be32(block, pos) as u64;
            let flags = be32(block, pos + 4);
            let hi = be32(block, pos + 8) as u64;
            pos += 16;
            tags.push((hi << 32) | lo);
            if flags & JBD2_FLAG_SAME_UUID == 0 {
                pos += 16; // UUID follows
            }
            if flags & JBD2_FLAG_LAST_TAG != 0 {
                break;
            }
        } else {
            // journal_block_tag_t: blocknr(4), checksum(2), flags(2), [hi(4)].
            if pos + 8 > block.len() {
                break;
            }
            let lo = be32(block, pos) as u64;
            let flags = u16::from_be_bytes([block[pos + 6], block[pos + 7]]) as u32;
            pos += 8;
            let mut blocknr = lo;
            if is_64bit {
                if pos + 4 > block.len() {
                    break;
                }
                blocknr |= (be32(block, pos) as u64) << 32;
                pos += 4;
            }
            tags.push(blocknr);
            if flags & JBD2_FLAG_SAME_UUID == 0 {
                pos += 16;
            }
            if flags & JBD2_FLAG_LAST_TAG != 0 {
                break;
            }
        }
        if pos >= block.len() || tags.len() > 100_000 {
            break;
        }
    }
    tags
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

#[cfg(test)]
mod tests {
    use super::*;

    fn be_u32(v: &mut Vec<u8>, n: u32) {
        v.extend_from_slice(&n.to_be_bytes());
    }
    fn be_u16(v: &mut Vec<u8>, n: u16) {
        v.extend_from_slice(&n.to_be_bytes());
    }

    #[test]
    fn round8_rounds_up() {
        assert_eq!(round8(0), 0);
        assert_eq!(round8(1), 8);
        assert_eq!(round8(8), 8);
        assert_eq!(round8(9), 16);
    }

    #[test]
    fn be32_reads_big_endian() {
        assert_eq!(be32(&[0x00, 0x00, 0x00, 0x06], 0), 6);
        assert_eq!(be32(&[0x12, 0x34], 0), 0); // too short -> 0
    }

    #[test]
    fn blockmap_detection() {
        let mut inode = vec![0u8; 128];
        // EXTENTS flag set but no extent magic => unusable.
        inode[0x20..0x24].copy_from_slice(&FLAG_EXTENTS.to_le_bytes());
        assert!(!inode_has_blockmap(&inode));
        // ...with the extent magic => usable.
        inode[0x28..0x2A].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        assert!(inode_has_blockmap(&inode));

        // Indirect (no extents) with a non-zero block pointer => usable.
        let mut indirect = vec![0u8; 128];
        indirect[0x28] = 1;
        assert!(inode_has_blockmap(&indirect));

        // Fully zeroed => unusable.
        assert!(!inode_has_blockmap(&[0u8; 128]));
    }

    #[test]
    fn journal_tags_basic() {
        let mut b = vec![0u8; 12]; // journal block header
        be_u32(&mut b, 6); // t_blocknr
        be_u16(&mut b, 0); // t_checksum
        be_u16(&mut b, 0x0008); // t_flags = LAST_TAG
        b.extend_from_slice(&[0u8; 16]); // UUID (no SAME_UUID)
        assert_eq!(parse_journal_tags(&b, false, false), vec![6]);
    }

    #[test]
    fn journal_tags_64bit() {
        let mut b = vec![0u8; 12];
        be_u32(&mut b, 6); // blocknr low
        be_u16(&mut b, 0);
        be_u16(&mut b, 0x0008); // LAST_TAG
        be_u32(&mut b, 0); // blocknr high
        b.extend_from_slice(&[0u8; 16]);
        assert_eq!(parse_journal_tags(&b, false, true), vec![6]);
    }

    #[test]
    fn journal_tags_csum_v3() {
        let mut b = vec![0u8; 12];
        be_u32(&mut b, 6); // blocknr
        be_u32(&mut b, 0x0000_0008); // flags = LAST_TAG
        be_u32(&mut b, 0); // blocknr high
        be_u32(&mut b, 0); // checksum
        b.extend_from_slice(&[0u8; 16]); // UUID
        assert_eq!(parse_journal_tags(&b, true, false), vec![6]);
    }

    #[test]
    fn journal_tags_same_uuid_chain() {
        let mut b = vec![0u8; 12];
        // First tag: SAME_UUID set (no trailing UUID), not last.
        be_u32(&mut b, 6);
        be_u16(&mut b, 0);
        be_u16(&mut b, 0x0002); // SAME_UUID
                                // Second tag: LAST_TAG, no SAME_UUID => trailing UUID.
        be_u32(&mut b, 7);
        be_u16(&mut b, 0);
        be_u16(&mut b, 0x0008); // LAST_TAG
        b.extend_from_slice(&[0u8; 16]);
        assert_eq!(parse_journal_tags(&b, false, false), vec![6, 7]);
    }
}
