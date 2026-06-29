//! OCFS2 **detection** — no metadata undelete.
//!
//! OCFS2 (the Oracle Cluster File System 2) is a shared-disk cluster filesystem
//! for Linux, like [`crate::gfs2`]: several nodes mount the same block device at
//! once and coordinate through a cluster stack. Its metadata is cluster-managed
//! rather than single-host, so this module only *recognises* an OCFS2 volume —
//! reporting its size, label, and UUID so `info` / `list_volumes` show it instead
//! of leaving it unrecognised — and leaves recovery to `scan` (carving).
//!
//! The "superblock" is really a system inode (an `ocfs2_dinode` whose signature
//! is `OCFSV2`) stored at block #2 of the volume. The block size isn't known in
//! advance, so the inode is probed at `2 × block_size` for each supported block
//! size (512 B … 4 KiB). Field offsets follow `ocfs2_fs.h` / `libblkid`.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{format_uuid, RecoverOptions, RecoverStats};
use crate::source::Source;

/// `i_signature` ("OCFSV2") at offset 0 of the superblock inode.
const SIGNATURE: &[u8; 6] = b"OCFSV2";
/// Supported block sizes; the superblock inode lives at `2 × block_size`.
const BLOCK_SIZES: [u64; 4] = [512, 1024, 2048, 4096];
/// Byte offsets within the `ocfs2_dinode` (little-endian throughout).
const I_CLUSTERS_OFFSET: usize = 0x14; // u32: total clusters (on the superblock inode)
/// The `id2.i_super` (`ocfs2_super_block`) union begins 0xC0 into the inode.
const SUPER_OFFSET: usize = 0xC0;
const CLUSTERSIZE_BITS_OFFSET: usize = SUPER_OFFSET + 0x3C; // u32
const LABEL_OFFSET: usize = SUPER_OFFSET + 0x50; // 64 bytes, NUL-padded
const UUID_OFFSET: usize = SUPER_OFFSET + 0x90; // 16 bytes
/// We read this much of the inode to cover every field above.
const HEADER_LEN: usize = UUID_OFFSET + 16;

/// A recognised OCFS2 volume (detection only; no metadata undelete).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
    /// Volume label (`s_label`), empty when unset.
    label: String,
    /// Filesystem UUID (`s_uuid`), `None` when unset.
    uuid: Option<String>,
}

/// The byte offset of the OCFS2 superblock inode within `vol_offset`, or `None`
/// if there is no OCFS2 signature at any supported block size.
fn sb_offset(src: &Source, vol_offset: u64) -> Option<u64> {
    for &bs in &BLOCK_SIZES {
        let at = vol_offset.checked_add(bs * 2)?;
        let mut sig = [0u8; 6];
        if src.read_at(at, &mut sig).unwrap_or(0) < 6 {
            continue;
        }
        if &sig == SIGNATURE {
            return Some(at);
        }
    }
    None
}

/// Does an OCFS2 superblock inode sit at `vol_offset`?
pub fn is_ocfs2(src: &Source, vol_offset: u64) -> bool {
    sb_offset(src, vol_offset).is_some()
}

impl Volume {
    /// Parse the OCFS2 superblock inode at `offset`, failing if there is none.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let Some(sb) = sb_offset(src, offset) else {
            bail!("not an OCFS2 volume");
        };
        let mut hdr = [0u8; HEADER_LEN];
        if src.read_at(sb, &mut hdr)? < HEADER_LEN {
            bail!("OCFS2 superblock truncated");
        }
        let clusters = u32::from_le_bytes(
            hdr[I_CLUSTERS_OFFSET..I_CLUSTERS_OFFSET + 4]
                .try_into()
                .unwrap(),
        ) as u64;
        let bits = u32::from_le_bytes(
            hdr[CLUSTERSIZE_BITS_OFFSET..CLUSTERSIZE_BITS_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        // A sane cluster size keeps the shift in range and guards the signature.
        if !(9..=30).contains(&bits) || clusters == 0 {
            bail!("implausible OCFS2 geometry");
        }
        let fallback = src.size.saturating_sub(offset);
        let size = clusters
            .checked_shl(bits)
            .filter(|&b| b > 0 && b <= fallback.max(1u64 << bits))
            .unwrap_or(fallback);
        let uuid = format_uuid(&hdr[UUID_OFFSET..UUID_OFFSET + 16]);
        let raw = &hdr[LABEL_OFFSET..LABEL_OFFSET + 64];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let label = String::from_utf8_lossy(&raw[..end]).into_owned();
        Ok(Volume {
            offset,
            size,
            label,
            uuid,
        })
    }

    /// Total size of the volume in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Short filesystem label.
    pub fn fs_label(&self) -> &'static str {
        "OCFS2"
    }

    /// The volume label (`s_label`), or an empty string when unset.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The filesystem UUID (`s_uuid`), or `None` when unset.
    pub fn uuid(&self) -> Option<String> {
        self.uuid.clone()
    }

    /// OCFS2 metadata undelete is not supported (see the module docs); always
    /// returns an empty result so a mixed disk's other volumes still recover.
    /// Use `scan` (carving) to recover data from an OCFS2 volume.
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

    /// Build an OCFS2 volume of `total` bytes whose superblock inode sits at
    /// `2 × block_size`.
    fn ocfs2_image(
        block_size: u64,
        clusters: u32,
        clustersize_bits: u32,
        label: &str,
        uuid: &[u8; 16],
        total: usize,
    ) -> Vec<u8> {
        let mut v = vec![0u8; total];
        let sb = (block_size * 2) as usize;
        v[sb..sb + 6].copy_from_slice(SIGNATURE);
        v[sb + I_CLUSTERS_OFFSET..sb + I_CLUSTERS_OFFSET + 4]
            .copy_from_slice(&clusters.to_le_bytes());
        v[sb + CLUSTERSIZE_BITS_OFFSET..sb + CLUSTERSIZE_BITS_OFFSET + 4]
            .copy_from_slice(&clustersize_bits.to_le_bytes());
        let lb = label.as_bytes();
        v[sb + LABEL_OFFSET..sb + LABEL_OFFSET + lb.len()].copy_from_slice(lb);
        v[sb + UUID_OFFSET..sb + UUID_OFFSET + 16].copy_from_slice(uuid);
        v
    }

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("ocfs2.img");
        std::fs::write(&p, bytes).unwrap();
        (tmp, Source::open(&p).unwrap())
    }

    #[test]
    fn detects_size_label_and_uuid() {
        let uuid = [
            0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7,
            0xe8, 0xf9,
        ];
        // 4 KiB blocks → inode at 8 KiB; 64 clusters of 4 KiB = 256 KiB.
        let (_t, src) = source_of(&ocfs2_image(4096, 64, 12, "cluster-fs", &uuid, 512 * 1024));
        assert!(is_ocfs2(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "OCFS2");
        assert_eq!(v.size(), 64 * 4096);
        assert_eq!(v.label(), "cluster-fs");
        assert_eq!(
            v.uuid().as_deref(),
            Some("0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9")
        );
    }

    #[test]
    fn detects_with_512_byte_blocks() {
        // 512 B blocks → inode at 1 KiB.
        let (_t, src) = source_of(&ocfs2_image(512, 16, 12, "", &[0u8; 16], 256 * 1024));
        assert!(is_ocfs2(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.size(), 16 * 4096);
        assert_eq!(v.uuid(), None);
        assert_eq!(v.label(), "");
    }

    #[test]
    fn rejects_non_ocfs2_and_implausible_geometry() {
        let (_t, src) = source_of(&vec![0u8; 64 * 1024]);
        assert!(!is_ocfs2(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());

        // The signature with an out-of-range cluster shift is rejected.
        let (_t, src) = source_of(&ocfs2_image(4096, 64, 40, "x", &[0u8; 16], 64 * 1024));
        assert!(Volume::parse(&src, 0).is_err());
    }
}
