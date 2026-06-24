//! Btrfs **detection** and filesystem-label reporting (no metadata undelete).
//!
//! Btrfs is a copy-on-write filesystem: like APFS, a deleted file's metadata is
//! not left in place to be scavenged — the B-trees are rewritten and old nodes
//! are eventually reclaimed — so metadata-based undelete is not tractable the
//! way it is for FAT/exFAT/NTFS/ext/HFS+. This module *recognises* a Btrfs
//! volume and reports its geometry and filesystem **label** (so `info` /
//! `list_volumes` surface it and the user knows to fall back to `scan`), but it
//! recovers nothing itself.
//!
//! Enumerating the **subvolumes** inside a Btrfs filesystem additionally
//! requires walking the chunk tree (to map logical to physical addresses) and
//! the root tree, which is left for a later step.

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
const TOTAL_BYTES: usize = 112;
/// `sectorsize` (u32) field offset.
const SECTORSIZE: usize = 144;
/// `nodesize` (u32) field offset.
const NODESIZE: usize = 148;
/// `label[256]` field offset.
const LABEL: usize = 299;
const LABEL_LEN: usize = 256;
/// Bytes of the superblock we read (through the label field).
const SUPERBLOCK_LEN: usize = LABEL + LABEL_LEN;

/// A recognised Btrfs volume (label/geometry reporting only; no undelete).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    total_bytes: u64,
    sectorsize: u32,
    nodesize: u32,
    label: String,
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

        Ok(Volume {
            offset,
            total_bytes,
            sectorsize,
            nodesize,
            label,
        })
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
