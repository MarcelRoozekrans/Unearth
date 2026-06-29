//! UFS / UFS2 (BSD Fast File System) **detection** — no metadata undelete.
//!
//! UFS (the Berkeley Fast File System) is the traditional filesystem of the BSDs
//! and Solaris, and the ancestor of much of Unix filesystem design. Its on-disk
//! layout (cylinder groups, fragmented blocks) is unlike the filesystems already
//! handled here, so this module only *recognises* a UFS volume — reporting its
//! version, size, and block size so `info` / `list_volumes` show it instead of
//! leaving it unrecognised — and leaves recovery to `scan` (carving).
//!
//! The superblock lives at a fixed offset (8 KiB for UFS1, 64 KiB for UFS2) and
//! carries its magic at offset 0x55C. UFS ran on both big- and little-endian
//! hardware; the byte order is taken from the magic. The early geometry fields
//! (`fs_bsize`, `fs_fsize`, `fs_old_size`) are the original FFS layout, unchanged
//! across both versions.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// Candidate superblock locations: UFS1 at 8 KiB, UFS2 at 64 KiB.
const SB_OFFSETS: [u64; 2] = [8192, 65536];
/// `fs_magic` sits 0x55C into the superblock.
const MAGIC_OFFSET: usize = 0x55C;
const UFS1_MAGIC: u32 = 0x0001_1954;
const UFS2_MAGIC: u32 = 0x1954_0119;
/// Early `struct fs` geometry fields (stable across UFS1/UFS2).
const OLD_SIZE_OFFSET: usize = 0x24; // u32: size in fragments (UFS1)
const BSIZE_OFFSET: usize = 0x30; // u32: block size in bytes
const FSIZE_OFFSET: usize = 0x34; // u32: fragment size in bytes
/// We read this much of the superblock to cover the magic at 0x55C.
const HEADER_LEN: usize = MAGIC_OFFSET + 4;

/// A recognised UFS volume (detection only; no metadata undelete).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
    block_size: u64,
    /// Whether this is UFS2 (`true`) or the original UFS1 (`false`).
    is_ufs2: bool,
}

/// The superblock offset, byte order, and version of a UFS volume at
/// `vol_offset`, or `None` if there is no UFS superblock. `true` = big-endian.
fn probe(src: &Source, vol_offset: u64) -> Option<(u64, bool, bool)> {
    for &sb in &SB_OFFSETS {
        let at = vol_offset.checked_add(sb)?;
        let mut m = [0u8; 4];
        if src.read_at(at + MAGIC_OFFSET as u64, &mut m).unwrap_or(0) < 4 {
            continue;
        }
        for big in [false, true] {
            let magic = if big {
                u32::from_be_bytes(m)
            } else {
                u32::from_le_bytes(m)
            };
            if magic == UFS1_MAGIC {
                return Some((at, big, false));
            }
            if magic == UFS2_MAGIC {
                return Some((at, big, true));
            }
        }
    }
    None
}

/// Does a UFS superblock sit at `vol_offset`?
pub fn is_ufs(src: &Source, vol_offset: u64) -> bool {
    probe(src, vol_offset).is_some()
}

impl Volume {
    /// Parse the UFS superblock at `offset`, failing if there is none.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let Some((sb, big, is_ufs2)) = probe(src, offset) else {
            bail!("not a UFS volume");
        };
        let mut hdr = [0u8; HEADER_LEN];
        if src.read_at(sb, &mut hdr)? < HEADER_LEN {
            bail!("UFS superblock truncated");
        }
        let rd32 = |o: usize| {
            let a = hdr[o..o + 4].try_into().unwrap();
            if big {
                u32::from_be_bytes(a)
            } else {
                u32::from_le_bytes(a)
            }
        };
        let block_size = rd32(BSIZE_OFFSET) as u64;
        let frag_size = rd32(FSIZE_OFFSET) as u64;
        // A real UFS block size is a power of two in this range; checking it
        // rejects a coincidental match of the 4-byte magic.
        if !block_size.is_power_of_two() || !(512..=65536).contains(&block_size) {
            bail!("implausible UFS geometry");
        }
        // UFS1 records the size in fragments here; UFS2 moved it to a 64-bit field
        // and leaves this zero, so fall back to the source span.
        let frags = rd32(OLD_SIZE_OFFSET) as u64;
        let fallback = src.size.saturating_sub(offset);
        let size = frags
            .checked_mul(frag_size)
            .filter(|&b| b > 0 && b <= fallback.max(frag_size.max(1)))
            .unwrap_or(fallback);
        Ok(Volume {
            offset,
            size,
            block_size,
            is_ufs2,
        })
    }

    /// Total size of the volume in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Block size in bytes.
    pub fn block_size(&self) -> u64 {
        self.block_size
    }

    /// Short filesystem label.
    pub fn fs_label(&self) -> &'static str {
        if self.is_ufs2 {
            "UFS2"
        } else {
            "UFS"
        }
    }

    /// UFS metadata undelete is not supported (see the module docs); always
    /// returns an empty result so a mixed disk's other volumes still recover.
    /// Use `scan` (carving) to recover data from a UFS volume.
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

    /// Build a UFS volume of `total` bytes with a superblock at `sb`.
    fn ufs_image(
        sb: u64,
        magic: u32,
        bsize: u32,
        fsize: u32,
        old_size: u32,
        big: bool,
        total: usize,
    ) -> Vec<u8> {
        let mut v = vec![0u8; total];
        let s = sb as usize;
        let w32 = |v: &mut [u8], o: usize, x: u32| {
            let b = if big {
                x.to_be_bytes()
            } else {
                x.to_le_bytes()
            };
            v[o..o + 4].copy_from_slice(&b);
        };
        w32(&mut v, s + MAGIC_OFFSET, magic);
        w32(&mut v, s + BSIZE_OFFSET, bsize);
        w32(&mut v, s + FSIZE_OFFSET, fsize);
        w32(&mut v, s + OLD_SIZE_OFFSET, old_size);
        v
    }

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("ufs.img");
        std::fs::write(&p, bytes).unwrap();
        (tmp, Source::open(&p).unwrap())
    }

    #[test]
    fn detects_ufs1_with_size_and_block_size() {
        // UFS1 at 8 KiB: 1000 fragments of 2 KiB = ~2 MiB.
        let (_t, src) = source_of(&ufs_image(
            8192,
            UFS1_MAGIC,
            16384,
            2048,
            1000,
            false,
            4 * 1024 * 1024,
        ));
        assert!(is_ufs(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "UFS");
        assert_eq!(v.block_size(), 16384);
        assert_eq!(v.size(), 1000 * 2048);
    }

    #[test]
    fn detects_big_endian_ufs2_falling_back_to_span() {
        // UFS2 at 64 KiB, big-endian, old_size 0 → size falls back to the span.
        let total = 256 * 1024;
        let (_t, src) = source_of(&ufs_image(65536, UFS2_MAGIC, 32768, 4096, 0, true, total));
        assert!(is_ufs(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "UFS2");
        assert_eq!(v.block_size(), 32768);
        assert_eq!(v.size(), total as u64);
    }

    #[test]
    fn rejects_non_ufs() {
        let (_t, src) = source_of(&vec![0u8; 128 * 1024]);
        assert!(!is_ufs(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());
    }
}
