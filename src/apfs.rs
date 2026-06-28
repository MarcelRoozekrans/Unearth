//! APFS container **detection** and volume enumeration (no metadata undelete).
//!
//! APFS is Apple's modern, copy-on-write filesystem. Unlike HFS+ or ext, a
//! deleted file leaves no stale catalog/inode record to scavenge: the object map
//! and the file-system B-trees are rewritten through checkpoints, and the old
//! objects are reclaimed, so metadata-based undelete is not tractable the way it
//! is for the other backends. This module therefore *recognises* an APFS
//! container and lists the **volumes** inside it (by name) — so `info` /
//! `list_volumes` report it usefully and the user knows to fall back to `scan`
//! (carving) — but recovers nothing itself.
//!
//! Volume enumeration reads the container superblock at the start of the
//! container, resolves its file-system object IDs through the container object
//! map (a B-tree), and reads each volume superblock's name. It is best-effort:
//! it uses the superblock at block 0 (correct for a cleanly unmounted image; a
//! container caught mid-write may need the latest checkpoint superblock), and
//! any parse failure simply yields no names rather than failing detection.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// `nx_magic` ("NXSB") sits 32 bytes into the container superblock, right after
/// the 32-byte `obj_phys_t` object header.
const MAGIC_OFFSET: u64 = 32;
const NX_MAGIC: &[u8; 4] = b"NXSB";
/// `apfs_magic` ("APSB") in a volume superblock, also at offset 32.
const APSB_MAGIC: &[u8; 4] = b"APSB";
/// `obj_phys_t.o_type` low 16 bits for a container superblock.
const OBJECT_TYPE_NX_SUPERBLOCK: u32 = 0x0001;
/// `nx_omap_oid`: physical OID of the container object map.
const NX_OMAP_OID: usize = 160;
/// `nx_max_file_systems`: length of the `nx_fs_oid` array that follows.
const NX_MAX_FILE_SYSTEMS: usize = 180;
/// `nx_fs_oid[0]`: start of the array of volume (file-system) OIDs.
const NX_FS_OID: usize = 184;
/// `apfs_volname`: the volume name (UTF-8, NUL-terminated, 256 bytes).
const APFS_VOLNAME: usize = 704;
/// Spec maximum of volumes in a container (`NX_MAX_FILE_SYSTEMS`).
const MAX_VOLUMES: usize = 100;
/// A B-tree root node ends with a 40-byte `btree_info_phys` trailer.
const BTREE_INFO_LEN: usize = 40;
/// `btree_node_phys_t` fixed fields end (its key/value storage begins here).
const BTN_DATA: usize = 56;

/// A recognised APFS container (volume enumeration only; no metadata undelete).
pub struct Volume {
    /// Byte offset of the container within the source.
    pub offset: u64,
    block_size: u64,
    block_count: u64,
    /// Names of the volumes inside the container, best-effort. Empty when the
    /// object map could not be parsed.
    volume_names: Vec<String>,
}

/// Does the superblock at `vol_offset` carry the APFS container magic?
pub fn is_apfs(src: &Source, vol_offset: u64) -> bool {
    let mut magic = [0u8; 4];
    if src
        .read_at(vol_offset + MAGIC_OFFSET, &mut magic)
        .unwrap_or(0)
        < 4
    {
        return false;
    }
    &magic == NX_MAGIC
}

impl Volume {
    /// Parse the container superblock (`nx_superblock_t`) at `offset`.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let mut sb = [0u8; 48];
        if src.read_at(offset, &mut sb)? < 48 {
            bail!("APFS superblock truncated");
        }
        if &sb[32..36] != NX_MAGIC {
            bail!("not an APFS container");
        }
        // obj_phys_t.o_type (offset 24): the low 16 bits identify the object.
        let o_type = u32::from_le_bytes([sb[24], sb[25], sb[26], sb[27]]);
        if o_type & 0xFFFF != OBJECT_TYPE_NX_SUPERBLOCK {
            bail!("APFS object is not a container superblock");
        }
        let block_size = u32::from_le_bytes([sb[36], sb[37], sb[38], sb[39]]) as u64;
        if !block_size.is_power_of_two() || !(512..=1024 * 1024).contains(&block_size) {
            bail!("implausible APFS block size {block_size}");
        }
        let block_count = u64::from_le_bytes(sb[40..48].try_into().unwrap());
        if block_count == 0 {
            bail!("APFS container reports zero blocks");
        }
        // Best-effort: list the volumes inside the container. Any failure here
        // leaves the list empty without failing detection.
        let volume_names = enumerate_volumes(src, offset, block_size).unwrap_or_default();
        Ok(Volume {
            offset,
            block_size,
            block_count,
            volume_names,
        })
    }

    /// Total size of the container in bytes.
    pub fn size(&self) -> u64 {
        self.block_count.saturating_mul(self.block_size)
    }

    /// The container block (allocation unit) size in bytes.
    pub fn block_size(&self) -> u64 {
        self.block_size
    }

    pub fn fs_label(&self) -> &'static str {
        "APFS"
    }

    /// Names of the volumes contained in this APFS container (empty when the
    /// object map could not be parsed).
    pub fn volume_names(&self) -> &[String] {
        &self.volume_names
    }

    /// APFS metadata undelete is not supported (see the module docs); this
    /// always returns an empty result so a mixed disk's other volumes still
    /// recover. Use `scan` (carving) to recover data from an APFS container.
    pub fn recover_deleted(
        &self,
        _src: &Source,
        _out_dir: &Path,
        _opts: &RecoverOptions,
    ) -> Result<RecoverStats> {
        Ok(RecoverStats::default())
    }
}

/// Resolve and read the name of every volume in the container at `offset`.
fn enumerate_volumes(src: &Source, offset: u64, block_size: u64) -> Option<Vec<String>> {
    let bs = block_size as usize;
    if bs < NX_FS_OID + 8 {
        return None;
    }
    let sb = read_block(src, offset, 0, block_size)?;
    let omap_oid = le64(&sb, NX_OMAP_OID);
    let max_fs = (le32(&sb, NX_MAX_FILE_SYSTEMS) as usize).min(MAX_VOLUMES);
    if omap_oid == 0 || max_fs == 0 {
        return None;
    }
    let fs_oids: Vec<u64> = (0..max_fs)
        .map(|i| le64(&sb, NX_FS_OID + i * 8))
        .filter(|&oid| oid != 0)
        .collect();
    if fs_oids.is_empty() {
        return None;
    }

    // The container object map is a physical object; its B-tree root is too.
    let omap = read_block(src, offset, omap_oid, block_size)?;
    let tree_oid = le64(&omap, 48); // omap_phys_t.om_tree_oid
    if tree_oid == 0 {
        return None;
    }
    let node = read_block(src, offset, tree_oid, block_size)?;
    let oid_to_paddr = parse_omap_leaf(&node, bs)?;

    let mut names = Vec::new();
    for fs in fs_oids {
        if let Some(&paddr) = oid_to_paddr.get(&fs) {
            if let Some(name) = read_volume_name(src, offset, paddr, block_size) {
                names.push(name);
            }
        }
    }
    if names.is_empty() {
        None
    } else {
        Some(names)
    }
}

/// Parse a single-leaf object-map B-tree node into a virtual-OID → physical-block
/// map. Only a leaf root is handled (the common case for the small container
/// object map); a multi-level tree yields `None`.
fn parse_omap_leaf(node: &[u8], node_size: usize) -> Option<HashMap<u64, u64>> {
    if node.len() < BTN_DATA || node.len() < node_size {
        return None;
    }
    let flags = le16(node, 32); // btn_flags
    let level = le16(node, 34); // btn_level (0 == leaf)
    if level != 0 {
        return None;
    }
    let nkeys = le32(node, 36) as usize;
    let toc_off = le16(node, 40) as usize; // btn_table_space.off
    let toc_len = le16(node, 42) as usize; // btn_table_space.len
    let toc_base = BTN_DATA + toc_off;
    let key_base = BTN_DATA + toc_off + toc_len;
    // Values are addressed backward from the end of the value area; in a root
    // node the last 40 bytes are the btree_info trailer.
    let is_root = flags & 0x0001 != 0;
    let val_area_end = if is_root {
        node_size.checked_sub(BTREE_INFO_LEN)?
    } else {
        node_size
    };

    // Fixed-size entries: the TOC is an array of kvoff_t { u16 k; u16 v }.
    let entries = nkeys.min(toc_len / 4).min(MAX_VOLUMES * 4);
    let mut map = HashMap::new();
    for i in 0..entries {
        let e = toc_base + i * 4;
        if e + 4 > node.len() {
            break;
        }
        let k = le16(node, e) as usize;
        let v = le16(node, e + 2) as usize;
        let key_pos = key_base + k;
        if key_pos + 16 > node.len() {
            continue;
        }
        let oid = le64(node, key_pos); // omap_key.ok_oid
        let val_pos = match val_area_end.checked_sub(v) {
            Some(p) => p,
            None => continue,
        };
        if val_pos + 16 > node.len() {
            continue;
        }
        let paddr = le64(node, val_pos + 8); // omap_val.ov_paddr
        map.insert(oid, paddr);
    }
    if map.is_empty() {
        None
    } else {
        Some(map)
    }
}

/// Read a volume superblock at physical block `paddr` and return its name.
fn read_volume_name(src: &Source, offset: u64, paddr: u64, block_size: u64) -> Option<String> {
    let byte = offset.checked_add(paddr.checked_mul(block_size)?)?;
    let mut buf = vec![0u8; APFS_VOLNAME + 256];
    if src.read_at(byte, &mut buf).ok()? < APFS_VOLNAME + 256 {
        return None;
    }
    if &buf[32..36] != APSB_MAGIC {
        return None;
    }
    let raw = &buf[APFS_VOLNAME..APFS_VOLNAME + 256];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&raw[..end]).into_owned())
}

/// Read one container block (`oid` is a physical block address relative to the
/// container start at `offset`).
fn read_block(src: &Source, offset: u64, oid: u64, block_size: u64) -> Option<Vec<u8>> {
    let byte = offset.checked_add(oid.checked_mul(block_size)?)?;
    let mut buf = vec![0u8; block_size as usize];
    if src.read_at(byte, &mut buf).ok()? < buf.len() {
        return None;
    }
    Some(buf)
}

fn le16(b: &[u8], o: usize) -> u16 {
    match b.get(o..o + 2) {
        Some(s) => u16::from_le_bytes([s[0], s[1]]),
        None => 0,
    }
}
fn le32(b: &[u8], o: usize) -> u32 {
    match b.get(o..o + 4) {
        Some(s) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
        None => 0,
    }
}
fn le64(b: &[u8], o: usize) -> u64 {
    match b.get(o..o + 8) {
        Some(s) => u64::from_le_bytes(s.try_into().unwrap()),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn superblock(block_size: u32, block_count: u64) -> Vec<u8> {
        let mut v = vec![0u8; 4096];
        v[24..28].copy_from_slice(&OBJECT_TYPE_NX_SUPERBLOCK.to_le_bytes()); // o_type
        v[32..36].copy_from_slice(NX_MAGIC);
        v[36..40].copy_from_slice(&block_size.to_le_bytes());
        v[40..48].copy_from_slice(&block_count.to_le_bytes());
        v
    }

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("c.img");
        std::fs::write(&p, bytes).unwrap();
        let src = Source::open(&p).unwrap();
        (tmp, src)
    }

    #[test]
    fn detects_and_sizes_a_container() {
        let (_t, src) = source_of(&superblock(4096, 8));
        assert!(is_apfs(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "APFS");
        assert_eq!(v.size(), 4096 * 8);
    }

    #[test]
    fn rejects_bad_magic_type_and_geometry() {
        // No magic.
        let (_t, src) = source_of(&vec![0u8; 4096]);
        assert!(!is_apfs(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());

        // Magic present but wrong object type.
        let mut sb = superblock(4096, 8);
        sb[24..28].copy_from_slice(&0x0002u32.to_le_bytes());
        let (_t, src) = source_of(&sb);
        assert!(Volume::parse(&src, 0).is_err());

        // Magic present but a non-power-of-two block size.
        let (_t, src) = source_of(&superblock(5000, 8));
        assert!(Volume::parse(&src, 0).is_err());
    }
}
