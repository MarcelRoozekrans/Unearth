//! APFS container **detection** (recognition only).
//!
//! APFS is Apple's modern, copy-on-write filesystem. Unlike HFS+ or ext, a
//! deleted file leaves no stale catalog/inode record to scavenge: the object map
//! and the file-system B-trees are rewritten through checkpoints, and the old
//! objects are reclaimed, so metadata-based undelete is not tractable the way it
//! is for the other backends. This module therefore only *recognises* an APFS
//! container — so `info`/`list_volumes` report it correctly and the user knows to
//! fall back to `scan` (carving) — and recovers nothing itself.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// `nx_magic` ("NXSB") sits 32 bytes into the container superblock, right after
/// the 32-byte `obj_phys_t` object header.
const MAGIC_OFFSET: u64 = 32;
const NX_MAGIC: &[u8; 4] = b"NXSB";
/// `obj_phys_t.o_type` low 16 bits for a container superblock.
const OBJECT_TYPE_NX_SUPERBLOCK: u32 = 0x0001;

/// A recognised (but not recoverable) APFS container.
pub struct Volume {
    /// Byte offset of the container within the source.
    pub offset: u64,
    block_size: u64,
    block_count: u64,
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
        Ok(Volume {
            offset,
            block_size,
            block_count,
        })
    }

    /// Total size of the container in bytes.
    pub fn size(&self) -> u64 {
        self.block_count.saturating_mul(self.block_size)
    }

    pub fn fs_label(&self) -> &'static str {
        "APFS"
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
