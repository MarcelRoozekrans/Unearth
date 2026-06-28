//! Old HFS (HFS Standard) **detection** — no metadata undelete.
//!
//! HFS (the "Mac OS Standard" filesystem, 1985–1998) predates HFS+ and is found
//! on old Mac floppies, disks, and CDs. Its catalog is a different on-disk B-tree
//! from HFS+, and the format is long obsolete, so this module only *recognises*
//! an HFS volume — reporting its size and name so `info` / `list_volumes` show it
//! instead of leaving it unrecognised — and leaves recovery to `scan` (carving).
//!
//! An HFS volume opens with a Master Directory Block (`BD`) 1024 bytes in. When
//! that MDB instead *wraps* an embedded HFS+ volume (`drEmbedSigWord` == `H+`),
//! [`crate::hfsplus`] follows it to the HFS+ volume, so this module deliberately
//! claims only a **pure** HFS volume (no HFS+ embed).

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// The Master Directory Block sits 1024 bytes into the volume.
const MDB_OFFSET: u64 = 1024;
/// `drSigWord` ("BD") at MDB offset 0.
const SIG_HFS: u16 = 0x4244;
/// `drEmbedSigWord` ("H+") at MDB offset 0x7C marks an HFS+ wrapper.
const SIG_HFSPLUS: u16 = 0x482B;
/// `drNmAlBlks` (u16) at offset 0x12, `drAlBlkSiz` (u32) at 0x14, `drAlBlSt`
/// (u16) at 0x1C, `drVN` (Pascal string) at 0x24. We read this much of the MDB.
const HEADER_LEN: usize = 0x80;

/// A recognised old HFS volume (detection only; no metadata undelete).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
    label: String,
}

/// Does a pure HFS volume (an MDB with the `BD` signature and **no** embedded
/// HFS+ volume) sit at `vol_offset`?
pub fn is_hfs(src: &Source, vol_offset: u64) -> bool {
    let mut mdb = [0u8; HEADER_LEN];
    if src.read_at(vol_offset + MDB_OFFSET, &mut mdb).unwrap_or(0) < HEADER_LEN {
        return false;
    }
    u16::from_be_bytes([mdb[0], mdb[1]]) == SIG_HFS
        // An embedded HFS+ volume is handled by `crate::hfsplus`, not here.
        && u16::from_be_bytes([mdb[0x7C], mdb[0x7D]]) != SIG_HFSPLUS
}

impl Volume {
    /// Parse the HFS Master Directory Block at `offset`, failing if it is not one
    /// (or is an HFS+ wrapper).
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let mut mdb = [0u8; HEADER_LEN];
        if src.read_at(offset + MDB_OFFSET, &mut mdb)? < HEADER_LEN {
            bail!("HFS master directory block truncated");
        }
        if u16::from_be_bytes([mdb[0], mdb[1]]) != SIG_HFS {
            bail!("not an HFS volume");
        }
        if u16::from_be_bytes([mdb[0x7C], mdb[0x7D]]) == SIG_HFSPLUS {
            bail!("HFS+ wrapper, not a pure HFS volume");
        }
        let num_blocks = u16::from_be_bytes([mdb[0x12], mdb[0x13]]) as u64;
        let block_size = u32::from_be_bytes([mdb[0x14], mdb[0x15], mdb[0x16], mdb[0x17]]) as u64;
        let first_block = u16::from_be_bytes([mdb[0x1C], mdb[0x1D]]) as u64;
        if num_blocks == 0 || block_size == 0 {
            bail!("implausible HFS geometry");
        }
        // Volume size: the allocation blocks plus the reserved area before them.
        let size = first_block
            .saturating_mul(512)
            .saturating_add(num_blocks.saturating_mul(block_size));
        // drVN: a Pascal string (length byte then Mac Roman bytes) at offset 0x24.
        let len = (mdb[0x24] as usize).min(27);
        let label = String::from_utf8_lossy(&mdb[0x25..0x25 + len]).into_owned();
        Ok(Volume {
            offset,
            size,
            label,
        })
    }

    /// Total size of the volume in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Short filesystem label.
    pub fn fs_label(&self) -> &'static str {
        "HFS"
    }

    /// The volume name (`drVN`), or an empty string when unset.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// HFS metadata undelete is not supported (see the module docs); always
    /// returns an empty result so a mixed disk's other volumes still recover.
    /// Use `scan` (carving) to recover data from an HFS volume.
    pub fn recover_deleted(
        &self,
        _src: &Source,
        _out_dir: &Path,
        _opts: &RecoverOptions,
    ) -> Result<RecoverStats> {
        Ok(RecoverStats::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal HFS Master Directory Block volume.
    fn hfs_volume(num_blocks: u16, block_size: u32, first_block: u16, name: &str) -> Vec<u8> {
        let mut v = vec![0u8; 4096];
        let mdb = MDB_OFFSET as usize;
        v[mdb..mdb + 2].copy_from_slice(&SIG_HFS.to_be_bytes());
        v[mdb + 0x12..mdb + 0x14].copy_from_slice(&num_blocks.to_be_bytes());
        v[mdb + 0x14..mdb + 0x18].copy_from_slice(&block_size.to_be_bytes());
        v[mdb + 0x1C..mdb + 0x1E].copy_from_slice(&first_block.to_be_bytes());
        v[mdb + 0x24] = name.len() as u8;
        v[mdb + 0x25..mdb + 0x25 + name.len()].copy_from_slice(name.as_bytes());
        v
    }

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("hfs.img");
        std::fs::write(&p, bytes).unwrap();
        (tmp, Source::open(&p).unwrap())
    }

    #[test]
    fn detects_size_and_name() {
        let (_t, src) = source_of(&hfs_volume(100, 512, 4, "Mac HD"));
        assert!(is_hfs(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "HFS");
        assert_eq!(v.label(), "Mac HD");
        assert_eq!(v.size(), 4 * 512 + 100 * 512);
    }

    #[test]
    fn ignores_an_hfsplus_wrapper() {
        // A BD block that embeds HFS+ belongs to crate::hfsplus, not here.
        let mut v = hfs_volume(100, 512, 4, "Wrapper");
        let mdb = MDB_OFFSET as usize;
        v[mdb + 0x7C..mdb + 0x7E].copy_from_slice(&SIG_HFSPLUS.to_be_bytes());
        let (_t, src) = source_of(&v);
        assert!(!is_hfs(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());
    }

    #[test]
    fn rejects_non_hfs() {
        let (_t, src) = source_of(&vec![0u8; 4096]);
        assert!(!is_hfs(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());
    }
}
