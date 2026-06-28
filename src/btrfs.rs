//! Btrfs **detection**, label, and subvolume enumeration (no metadata undelete).
//!
//! Btrfs is a copy-on-write filesystem: like APFS, a deleted file's metadata is
//! not left in place to be scavenged — the B-trees are rewritten and old nodes
//! are eventually reclaimed — so metadata-based undelete is not tractable the
//! way it is for FAT/exFAT/NTFS/ext/HFS+. This module *recognises* a Btrfs
//! volume, reports its geometry and filesystem **label**, and lists its
//! **subvolumes** by name (so `info` / `list_volumes` surface them and the user
//! knows to fall back to `scan`), but it recovers nothing itself.
//!
//! Subvolume enumeration walks two B-trees, translating logical to physical
//! addresses through the chunk map: it bootstraps the map from the superblock's
//! system-chunk array, reads the **chunk tree** to complete it, then reads the
//! **root tree** and collects the names from its `ROOT_REF` items. It handles
//! single-device, single-leaf trees (the common small-filesystem case) and is
//! strictly best-effort — any unexpected structure simply yields no subvolumes
//! without failing detection. It is validated against a synthetic fixture
//! rather than a live `mkfs.btrfs` image, so confirm against a real volume
//! before relying on it for an unusual layout (multi-device, multi-level trees).

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// The primary Btrfs superblock sits 64 KiB into the volume.
const SUPERBLOCK_OFFSET: u64 = 0x1_0000;
/// `btrfs_super_block.magic` ("_BHRfS_M") at offset 64 in the superblock.
const MAGIC_OFFSET: usize = 64;
const BTRFS_MAGIC: &[u8; 8] = b"_BHRfS_M";
/// `total_bytes` (u64) field offset within the superblock.
/// `fsid` (16 bytes) at offset 0x20: the filesystem UUID.
const FSID: usize = 0x20;
const TOTAL_BYTES: usize = 112;
/// `sectorsize` (u32) field offset.
const SECTORSIZE: usize = 144;
/// `nodesize` (u32) field offset.
const NODESIZE: usize = 148;
/// `label[256]` field offset.
const LABEL: usize = 299;
const LABEL_LEN: usize = 256;
/// `root` (u64): logical address of the root tree.
const ROOT_LOGICAL: usize = 80;
/// `chunk_root` (u64): logical address of the chunk tree.
const CHUNK_ROOT_LOGICAL: usize = 88;
/// `sys_chunk_array_size` (u32).
const SYS_CHUNK_ARRAY_SIZE: usize = 160;
/// `sys_chunk_array` (the bootstrap chunk map embedded in the superblock).
const SYS_CHUNK_ARRAY: usize = 811;
/// The whole superblock is 4 KiB; read it all so the system-chunk array is in.
const SUPERBLOCK_LEN: usize = 4096;

/// `btrfs_header` length (precedes a node's keys/items).
const HEADER_LEN: usize = 101;
/// `btrfs_item` length in a leaf node (key + data offset/size).
const ITEM_LEN: usize = 25;
/// `btrfs_disk_key` length (objectid u64, type u8, offset u64).
const DISK_KEY_LEN: usize = 17;
/// Key types we care about.
const CHUNK_ITEM_KEY: u8 = 228;
const ROOT_REF_KEY: u8 = 156;
/// Defensive caps.
const MAX_CHUNKS: usize = 4096;
const MAX_SUBVOLUMES: usize = 4096;

/// A recognised Btrfs volume (label/geometry/subvolume reporting; no undelete).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    total_bytes: u64,
    sectorsize: u32,
    nodesize: u32,
    label: String,
    /// Filesystem UUID (`fsid`), `None` when unset.
    uuid: Option<String>,
    /// Names of the subvolumes, best-effort. Empty when the trees could not be
    /// walked.
    subvolumes: Vec<String>,
}

/// Does the superblock 64 KiB into `vol_offset` carry the Btrfs magic?
pub fn is_btrfs(src: &Source, vol_offset: u64) -> bool {
    let mut magic = [0u8; 8];
    let at = vol_offset + SUPERBLOCK_OFFSET + MAGIC_OFFSET as u64;
    if src.read_at(at, &mut magic).unwrap_or(0) < 8 {
        return false;
    }
    &magic == BTRFS_MAGIC
}

impl Volume {
    /// Parse the Btrfs superblock at `offset` (the superblock itself is 64 KiB
    /// further in).
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let mut sb = vec![0u8; SUPERBLOCK_LEN];
        if src.read_at(offset + SUPERBLOCK_OFFSET, &mut sb)? < SUPERBLOCK_LEN {
            bail!("Btrfs superblock truncated");
        }
        if &sb[MAGIC_OFFSET..MAGIC_OFFSET + 8] != BTRFS_MAGIC {
            bail!("not a Btrfs volume");
        }
        let total_bytes = le64(&sb, TOTAL_BYTES);
        if total_bytes == 0 {
            bail!("Btrfs volume reports zero total bytes");
        }
        let sectorsize = le32(&sb, SECTORSIZE);
        let nodesize = le32(&sb, NODESIZE);
        // Guard against a coincidental magic in random data: the geometry must
        // be sane powers of two.
        if !sectorsize.is_power_of_two() || !(512..=65536).contains(&sectorsize) {
            bail!("implausible Btrfs sector size {sectorsize}");
        }
        if !nodesize.is_power_of_two() || !(512..=262144).contains(&nodesize) {
            bail!("implausible Btrfs node size {nodesize}");
        }

        let raw = &sb[LABEL..LABEL + LABEL_LEN];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let label = String::from_utf8_lossy(&raw[..end]).into_owned();
        let uuid = crate::recover::format_uuid(&sb[FSID..FSID + 16]);

        // Best-effort: list the subvolumes. Any failure leaves it empty without
        // failing detection.
        let subvolumes =
            enumerate_subvolumes(src, offset, &sb, nodesize as usize).unwrap_or_default();

        Ok(Volume {
            offset,
            total_bytes,
            sectorsize,
            nodesize,
            label,
            uuid,
            subvolumes,
        })
    }

    /// Names of the subvolumes in this filesystem (empty when the trees could
    /// not be walked).
    pub fn subvolumes(&self) -> &[String] {
        &self.subvolumes
    }

    /// Total size of the volume in bytes.
    pub fn size(&self) -> u64 {
        self.total_bytes
    }

    pub fn fs_label(&self) -> &'static str {
        "Btrfs"
    }

    /// The user-set filesystem label, or an empty string if none is set.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The filesystem UUID (`fsid`), or `None` when unset.
    pub fn uuid(&self) -> Option<String> {
        self.uuid.clone()
    }

    /// Sector and node sizes, for reporting.
    pub fn geometry(&self) -> (u32, u32) {
        (self.sectorsize, self.nodesize)
    }

    /// Btrfs metadata undelete is not supported (copy-on-write reclaims old
    /// tree nodes); always returns an empty result so a mixed disk's other
    /// volumes still recover. Use `scan` (carving) for a Btrfs volume.
    pub fn recover_deleted(
        &self,
        _src: &Source,
        _out_dir: &Path,
        _opts: &RecoverOptions,
    ) -> Result<RecoverStats> {
        Ok(RecoverStats::default())
    }
}

/// One chunk-map entry: a logical range and where it lives physically (the
/// first stripe's device offset; single-device volumes have just the one).
struct Chunk {
    logical: u64,
    length: u64,
    physical: u64,
}

/// Walk the chunk tree and root tree to list subvolume names. Best-effort:
/// returns `None` on any structure it cannot follow (multi-level trees, missing
/// chunks), and the caller treats that as "no subvolumes".
fn enumerate_subvolumes(
    src: &Source,
    offset: u64,
    sb: &[u8],
    nodesize: usize,
) -> Option<Vec<String>> {
    let root_logical = le64(sb, ROOT_LOGICAL);
    let chunk_root_logical = le64(sb, CHUNK_ROOT_LOGICAL);
    let sys_size = le32(sb, SYS_CHUNK_ARRAY_SIZE) as usize;

    // 1. Bootstrap the chunk map from the superblock's system-chunk array.
    let mut map: Vec<Chunk> = Vec::new();
    parse_chunk_array(sb, SYS_CHUNK_ARRAY, sys_size, &mut map);
    if map.is_empty() {
        return None;
    }

    // 2. Read the chunk tree to complete the map (its node is mapped by the
    //    bootstrap chunks).
    let chunk_node = read_logical(src, offset, &map, chunk_root_logical, nodesize)?;
    for_each_leaf_item(&chunk_node, |objectid, ktype, key_off, data| {
        let _ = objectid;
        if ktype == CHUNK_ITEM_KEY && map.len() < MAX_CHUNKS {
            parse_chunk(data, key_off, &mut map);
        }
    })?;

    // 3. Read the root tree and collect the ROOT_REF names.
    let root_node = read_logical(src, offset, &map, root_logical, nodesize)?;
    let mut names = Vec::new();
    for_each_leaf_item(&root_node, |_objectid, ktype, _off, data| {
        if ktype == ROOT_REF_KEY && names.len() < MAX_SUBVOLUMES {
            if let Some(name) = root_ref_name(data) {
                names.push(name);
            }
        }
    })?;
    if names.is_empty() {
        None
    } else {
        Some(names)
    }
}

/// Parse a sequence of (disk_key, btrfs_chunk) pairs (the system-chunk array, or
/// any run of chunk items) into `map`.
fn parse_chunk_array(buf: &[u8], start: usize, size: usize, map: &mut Vec<Chunk>) {
    let end = (start + size).min(buf.len());
    let mut p = start;
    while p + DISK_KEY_LEN <= end && map.len() < MAX_CHUNKS {
        let ktype = *buf.get(p + 8).unwrap_or(&0);
        let logical = le64(buf, p + 9); // disk_key.offset
        let chunk = p + DISK_KEY_LEN;
        if ktype != CHUNK_ITEM_KEY || chunk + 48 > end {
            break;
        }
        let num_stripes = le16(buf, chunk + 44) as usize;
        let consumed = 48 + num_stripes * 32;
        if num_stripes == 0 || chunk + consumed > end {
            break;
        }
        parse_chunk(&buf[chunk..chunk + consumed], logical, map);
        p = chunk + consumed;
    }
}

/// Parse one `btrfs_chunk` (mapping `logical`) and append it to `map`.
fn parse_chunk(chunk: &[u8], logical: u64, map: &mut Vec<Chunk>) {
    if chunk.len() < 56 + 8 {
        return;
    }
    let length = le64(chunk, 0);
    let num_stripes = le16(chunk, 44) as usize;
    if num_stripes == 0 || length == 0 {
        return;
    }
    // First stripe: devid @48, offset @56.
    let physical = le64(chunk, 56);
    if map.len() < MAX_CHUNKS {
        map.push(Chunk {
            logical,
            length,
            physical,
        });
    }
}

/// Read `len` bytes at a logical address, translating through the chunk map.
fn read_logical(
    src: &Source,
    offset: u64,
    map: &[Chunk],
    logical: u64,
    len: usize,
) -> Option<Vec<u8>> {
    let c = map
        .iter()
        .find(|c| logical >= c.logical && logical < c.logical + c.length)?;
    let physical = c.physical.checked_add(logical - c.logical)?;
    let byte = offset.checked_add(physical)?;
    let mut buf = vec![0u8; len];
    if src.read_at(byte, &mut buf).ok()? < len {
        return None;
    }
    Some(buf)
}

/// Invoke `f(objectid, type, key_offset, data)` for each item in a **leaf**
/// node (level 0). Returns `None` for a non-leaf node or a malformed header.
fn for_each_leaf_item(node: &[u8], mut f: impl FnMut(u64, u8, u64, &[u8])) -> Option<()> {
    if node.len() < HEADER_LEN {
        return None;
    }
    let nritems = le32(node, 96) as usize;
    let level = node[100];
    if level != 0 {
        return None; // only single-leaf trees are handled
    }
    let data_area = node.len() - HEADER_LEN;
    if nritems > data_area / ITEM_LEN {
        return None; // implausible item count
    }
    for i in 0..nritems {
        let item = HEADER_LEN + i * ITEM_LEN;
        let objectid = le64(node, item);
        let ktype = node[item + 8];
        let key_off = le64(node, item + 9);
        let data_off = le32(node, item + 17) as usize;
        let data_size = le32(node, item + 21) as usize;
        let start = HEADER_LEN + data_off;
        let endpos = start.checked_add(data_size)?;
        if endpos > node.len() {
            continue;
        }
        f(objectid, ktype, key_off, &node[start..endpos]);
    }
    Some(())
}

/// Decode a `btrfs_root_ref` item's name (`dirid` u64, `sequence` u64,
/// `name_len` u16, then the name bytes).
fn root_ref_name(data: &[u8]) -> Option<String> {
    if data.len() < 18 {
        return None;
    }
    let name_len = le16(data, 16) as usize;
    let name = data.get(18..18 + name_len)?;
    if name.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(name).into_owned())
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

    fn superblock(label: &str, total: u64) -> Vec<u8> {
        // Enough bytes for the superblock at 64 KiB.
        let mut v = vec![0u8; SUPERBLOCK_OFFSET as usize + SUPERBLOCK_LEN];
        let sb = SUPERBLOCK_OFFSET as usize;
        v[sb + MAGIC_OFFSET..sb + MAGIC_OFFSET + 8].copy_from_slice(BTRFS_MAGIC);
        v[sb + TOTAL_BYTES..sb + TOTAL_BYTES + 8].copy_from_slice(&total.to_le_bytes());
        v[sb + SECTORSIZE..sb + SECTORSIZE + 4].copy_from_slice(&4096u32.to_le_bytes());
        v[sb + NODESIZE..sb + NODESIZE + 4].copy_from_slice(&16384u32.to_le_bytes());
        v[sb + FSID..sb + FSID + 16].copy_from_slice(&[0x33; 16]);
        let lb = label.as_bytes();
        v[sb + LABEL..sb + LABEL + lb.len()].copy_from_slice(lb);
        v
    }

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("b.img");
        std::fs::write(&p, bytes).unwrap();
        let src = Source::open(&p).unwrap();
        (tmp, src)
    }

    #[test]
    fn detects_and_reads_label_and_geometry() {
        let (_t, src) = source_of(&superblock("backups", 1 << 30));
        assert!(is_btrfs(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "Btrfs");
        assert_eq!(v.size(), 1 << 30);
        assert_eq!(v.label(), "backups");
        assert_eq!(v.geometry(), (4096, 16384));
        assert_eq!(v.uuid().unwrap(), "33333333-3333-3333-3333-333333333333");
    }

    #[test]
    fn an_unlabeled_volume_has_an_empty_label() {
        let (_t, src) = source_of(&superblock("", 1 << 20));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.label(), "");
    }

    #[test]
    fn rejects_bad_magic_and_geometry() {
        let (_t, src) = source_of(&vec![0u8; SUPERBLOCK_OFFSET as usize + SUPERBLOCK_LEN]);
        assert!(!is_btrfs(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());

        // Magic present but an implausible (non-power-of-two) sector size.
        let mut sb = superblock("x", 1 << 20);
        sb[SUPERBLOCK_OFFSET as usize + SECTORSIZE..SUPERBLOCK_OFFSET as usize + SECTORSIZE + 4]
            .copy_from_slice(&5000u32.to_le_bytes());
        let (_t, src) = source_of(&sb);
        assert!(Volume::parse(&src, 0).is_err());
    }
}
