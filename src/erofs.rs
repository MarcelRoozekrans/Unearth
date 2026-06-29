//! EROFS (Enhanced Read-Only File System) **detection** — no metadata undelete.
//!
//! EROFS is a modern compressed read-only Linux filesystem, used for Android
//! system/vendor images (Android 11+) and ChromeOS. Being read-only it has no
//! "deleted files" to scavenge, so this module only *recognises* an EROFS volume
//! — reporting its size, label, UUID, and build time so `info` / `list_volumes`
//! show it instead of leaving it unrecognised — and leaves extraction to `scan`
//! (carving) of the compressed contents.
//!
//! The superblock sits at a fixed 1 KiB into the volume and opens with the magic
//! `0xE0F5E1E2`. Field offsets follow the kernel's `erofs_super_block`.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{format_uuid, RecoverOptions, RecoverStats};
use crate::source::Source;

/// The superblock sits 1 KiB into the volume.
const SB_OFFSET: u64 = 1024;
/// `magic` (little-endian u32) at superblock offset 0.
const MAGIC: u32 = 0xE0F5_E1E2;
/// Byte offsets within `erofs_super_block`.
const BLKSZBITS_OFFSET: usize = 0x0C; // u8: block size = 1 << this
const BUILD_TIME_OFFSET: usize = 0x18; // u64: build time, Unix seconds
const BLOCKS_OFFSET: usize = 0x24; // u32: total blocks
const UUID_OFFSET: usize = 0x30; // 16 bytes
const VOLUME_NAME_OFFSET: usize = 0x40; // 16 bytes, NUL-padded
/// We read this much of the superblock to cover every field above.
const HEADER_LEN: usize = VOLUME_NAME_OFFSET + 16;

/// A recognised EROFS volume (detection only; no metadata undelete).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
    block_size: u64,
    /// Filesystem label (`volume_name`), empty when unset.
    label: String,
    /// Filesystem UUID, `None` when unset.
    uuid: Option<String>,
    /// Build time as Unix seconds, `None` when unset.
    created: Option<u64>,
}

/// Does an EROFS superblock sit at `vol_offset`?
pub fn is_erofs(src: &Source, vol_offset: u64) -> bool {
    let Some(at) = vol_offset.checked_add(SB_OFFSET) else {
        return false;
    };
    let mut m = [0u8; 4];
    src.read_at(at, &mut m).unwrap_or(0) >= 4 && u32::from_le_bytes(m) == MAGIC
}

impl Volume {
    /// Parse the EROFS superblock at `offset`, failing if there is none.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let at = offset
            .checked_add(SB_OFFSET)
            .ok_or_else(|| anyhow::anyhow!("offset overflow"))?;
        let mut hdr = [0u8; HEADER_LEN];
        if src.read_at(at, &mut hdr)? < HEADER_LEN {
            bail!("EROFS superblock truncated");
        }
        if u32::from_le_bytes(hdr[0..4].try_into().unwrap()) != MAGIC {
            bail!("not an EROFS volume");
        }
        let blkszbits = hdr[BLKSZBITS_OFFSET];
        // A sane block-size shift (512 B … 64 KiB) also guards the 4-byte magic.
        if !(9..=16).contains(&blkszbits) {
            bail!("implausible EROFS geometry");
        }
        let block_size = 1u64 << blkszbits;
        let blocks =
            u32::from_le_bytes(hdr[BLOCKS_OFFSET..BLOCKS_OFFSET + 4].try_into().unwrap()) as u64;
        let fallback = src.size.saturating_sub(offset);
        let size = blocks
            .checked_mul(block_size)
            .filter(|&b| b > 0 && b <= fallback.max(block_size))
            .unwrap_or(fallback);
        let uuid = format_uuid(&hdr[UUID_OFFSET..UUID_OFFSET + 16]);
        let raw = &hdr[VOLUME_NAME_OFFSET..VOLUME_NAME_OFFSET + 16];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let label = String::from_utf8_lossy(&raw[..end]).into_owned();
        let bt = u64::from_le_bytes(
            hdr[BUILD_TIME_OFFSET..BUILD_TIME_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        let created = (bt != 0).then_some(bt);
        Ok(Volume {
            offset,
            size,
            block_size,
            label,
            uuid,
            created,
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
        "EROFS"
    }

    /// The filesystem label (`volume_name`), or an empty string when unset.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The filesystem UUID, or `None` when unset.
    pub fn uuid(&self) -> Option<String> {
        self.uuid.clone()
    }

    /// Build time as Unix seconds, `None` when unset.
    pub fn created_time(&self) -> Option<u64> {
        self.created
    }

    /// EROFS is read-only, so there are no deleted files to undelete; always
    /// returns an empty result so a mixed disk's other volumes still recover.
    /// Use `scan` (carving) to recover data from an EROFS volume.
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

    /// Build an EROFS volume of `total` bytes with a superblock at 1 KiB.
    fn erofs_image(
        blkszbits: u8,
        blocks: u32,
        uuid: &[u8; 16],
        label: &str,
        build_time: u64,
        total: usize,
    ) -> Vec<u8> {
        let mut v = vec![0u8; total];
        let sb = SB_OFFSET as usize;
        v[sb..sb + 4].copy_from_slice(&MAGIC.to_le_bytes());
        v[sb + BLKSZBITS_OFFSET] = blkszbits;
        v[sb + BUILD_TIME_OFFSET..sb + BUILD_TIME_OFFSET + 8]
            .copy_from_slice(&build_time.to_le_bytes());
        v[sb + BLOCKS_OFFSET..sb + BLOCKS_OFFSET + 4].copy_from_slice(&blocks.to_le_bytes());
        v[sb + UUID_OFFSET..sb + UUID_OFFSET + 16].copy_from_slice(uuid);
        let lb = label.as_bytes();
        v[sb + VOLUME_NAME_OFFSET..sb + VOLUME_NAME_OFFSET + lb.len()].copy_from_slice(lb);
        v
    }

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("erofs.img");
        std::fs::write(&p, bytes).unwrap();
        (tmp, Source::open(&p).unwrap())
    }

    #[test]
    fn detects_size_label_uuid_and_build_time() {
        let uuid = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0,
        ];
        // 4 KiB blocks (blkszbits 12), 64 blocks = 256 KiB.
        let (_t, src) = source_of(&erofs_image(
            12,
            64,
            &uuid,
            "system",
            1_600_000_000,
            512 * 1024,
        ));
        assert!(is_erofs(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "EROFS");
        assert_eq!(v.block_size(), 4096);
        assert_eq!(v.size(), 64 * 4096);
        assert_eq!(v.label(), "system");
        assert_eq!(v.created_time(), Some(1_600_000_000));
        assert_eq!(
            v.uuid().as_deref(),
            Some("12345678-9abc-def0-1234-56789abcdef0")
        );
    }

    #[test]
    fn rejects_non_erofs_and_bad_block_size() {
        let (_t, src) = source_of(&vec![0u8; 64 * 1024]);
        assert!(!is_erofs(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());

        // The magic with an out-of-range block-size shift is rejected.
        let (_t, src) = source_of(&erofs_image(40, 64, &[0u8; 16], "", 0, 64 * 1024));
        assert!(Volume::parse(&src, 0).is_err());
    }
}
