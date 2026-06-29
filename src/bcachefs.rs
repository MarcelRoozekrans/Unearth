//! bcachefs **detection** — no metadata undelete.
//!
//! bcachefs is a modern copy-on-write Linux filesystem (merged into the mainline
//! kernel in 6.7) with built-in multi-device, tiering, and checksumming. Like the
//! other copy-on-write filesystems here it leaves no stale metadata to scavenge,
//! so this module only *recognises* a bcachefs volume — reporting its label and
//! UUID so `info` / `list_volumes` show it instead of leaving it unrecognised —
//! and leaves recovery to `scan` (carving).
//!
//! The superblock sits 4 KiB into the volume and opens with a 16-byte magic. The
//! header prefix is stable across format versions; field offsets follow
//! `bcachefs_format.h` / `libblkid`. Total size spans member devices (not a
//! single superblock field), so the source span is reported.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{format_uuid, RecoverOptions, RecoverStats};
use crate::source::Source;

/// The superblock sits 4 KiB into the volume (`BCH_SB_SECTOR` = 8 × 512).
const SB_OFFSET: u64 = 4096;
/// `bch_sb.magic` — the 16-byte `BCACHE_MAGIC` constant.
const MAGIC: [u8; 16] = [
    0xc6, 0x85, 0x73, 0xf6, 0x4e, 0x1a, 0x45, 0xca, 0x82, 0x65, 0xf5, 0x7f, 0x48, 0xb1, 0x36, 0x29,
];
/// Byte offsets within `bch_sb`.
const MAGIC_OFFSET: usize = 0x18; // 16 bytes
const USER_UUID_OFFSET: usize = 0x38; // 16 bytes: the external (reported) UUID
const LABEL_OFFSET: usize = 0x48; // 32 bytes, NUL-padded
/// We read this much of the superblock to cover every field above.
const HEADER_LEN: usize = LABEL_OFFSET + 32;

/// A recognised bcachefs volume (detection only; no metadata undelete).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
    /// Filesystem label (`bch_sb.label`), empty when unset.
    label: String,
    /// External filesystem UUID (`bch_sb.user_uuid`), `None` when unset.
    uuid: Option<String>,
}

/// Does a bcachefs superblock sit at `vol_offset`?
pub fn is_bcachefs(src: &Source, vol_offset: u64) -> bool {
    let Some(at) = vol_offset.checked_add(SB_OFFSET + MAGIC_OFFSET as u64) else {
        return false;
    };
    let mut magic = [0u8; 16];
    src.read_at(at, &mut magic).unwrap_or(0) >= 16 && magic == MAGIC
}

impl Volume {
    /// Parse the bcachefs superblock at `offset`, failing if there is none.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let at = offset
            .checked_add(SB_OFFSET)
            .ok_or_else(|| anyhow::anyhow!("offset overflow"))?;
        let mut hdr = [0u8; HEADER_LEN];
        if src.read_at(at, &mut hdr)? < HEADER_LEN {
            bail!("bcachefs superblock truncated");
        }
        if hdr[MAGIC_OFFSET..MAGIC_OFFSET + 16] != MAGIC {
            bail!("not a bcachefs volume");
        }
        // Total size spans member devices; report the source span.
        let size = src.size.saturating_sub(offset);
        let uuid = format_uuid(&hdr[USER_UUID_OFFSET..USER_UUID_OFFSET + 16]);
        let raw = &hdr[LABEL_OFFSET..LABEL_OFFSET + 32];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let label = String::from_utf8_lossy(&raw[..end]).into_owned();
        Ok(Volume {
            offset,
            size,
            label,
            uuid,
        })
    }

    /// Total size of the volume in bytes (the source span; see the module docs).
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Short filesystem label.
    pub fn fs_label(&self) -> &'static str {
        "bcachefs"
    }

    /// The filesystem label (`bch_sb.label`), or an empty string when unset.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The external filesystem UUID (`bch_sb.user_uuid`), or `None` when unset.
    pub fn uuid(&self) -> Option<String> {
        self.uuid.clone()
    }

    /// bcachefs metadata undelete is not supported (see the module docs); always
    /// returns an empty result so a mixed disk's other volumes still recover.
    /// Use `scan` (carving) to recover data from a bcachefs volume.
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

    /// Build a bcachefs volume of `total` bytes with a superblock at 4 KiB.
    fn bcachefs_image(uuid: &[u8; 16], label: &str, total: usize) -> Vec<u8> {
        let mut v = vec![0u8; total];
        let sb = SB_OFFSET as usize;
        v[sb + MAGIC_OFFSET..sb + MAGIC_OFFSET + 16].copy_from_slice(&MAGIC);
        v[sb + USER_UUID_OFFSET..sb + USER_UUID_OFFSET + 16].copy_from_slice(uuid);
        let lb = label.as_bytes();
        v[sb + LABEL_OFFSET..sb + LABEL_OFFSET + lb.len()].copy_from_slice(lb);
        v
    }

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("bcachefs.img");
        std::fs::write(&p, bytes).unwrap();
        (tmp, Source::open(&p).unwrap())
    }

    #[test]
    fn detects_label_and_uuid() {
        let uuid = [
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xaa, 0xbb,
        ];
        let (_t, src) = source_of(&bcachefs_image(&uuid, "pool", 256 * 1024));
        assert!(is_bcachefs(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "bcachefs");
        assert_eq!(v.size(), 256 * 1024);
        assert_eq!(v.label(), "pool");
        assert_eq!(
            v.uuid().as_deref(),
            Some("deadbeef-0011-2233-4455-66778899aabb")
        );
    }

    #[test]
    fn missing_uuid_and_label_report_as_absent() {
        let (_t, src) = source_of(&bcachefs_image(&[0u8; 16], "", 256 * 1024));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.uuid(), None);
        assert_eq!(v.label(), "");
    }

    #[test]
    fn rejects_non_bcachefs() {
        let (_t, src) = source_of(&vec![0u8; 64 * 1024]);
        assert!(!is_bcachefs(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());
    }
}
