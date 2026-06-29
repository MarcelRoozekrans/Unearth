//! NILFS2 **detection** — no metadata undelete.
//!
//! NILFS2 (the New Implementation of a Log-structured File System) is a Linux
//! filesystem with continuous snapshotting. Its log-structured, checkpoint-based
//! design — like the other copy-on-write filesystems here — leaves no stale
//! metadata to scavenge, so this module only *recognises* a NILFS2 volume —
//! reporting its size, label, and UUID so `info` / `list_volumes` show it
//! instead of leaving it unrecognised — and leaves recovery to `scan` (carving).
//!
//! The primary superblock sits at a fixed 1 KiB into the volume and carries the
//! magic `0x3434` plus a major revision of 2. Field offsets and the
//! size/label/UUID interpretation follow what `libblkid` reads.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{format_uuid, RecoverOptions, RecoverStats};
use crate::source::Source;

/// The primary superblock sits 1 KiB into the volume.
const SB_OFFSET: u64 = 1024;
/// `s_magic` (u16) at superblock offset 0x06.
const MAGIC: u16 = 0x3434;
/// NILFS2's major revision (`s_rev_level`), checked to guard the 2-byte magic.
const CURRENT_REV: u32 = 2;
/// Byte offsets within the superblock (matching `libblkid`'s `nilfs_super_block`).
const REV_LEVEL_OFFSET: usize = 0x00; // u32
const MAGIC_OFFSET: usize = 0x06; // u16
const LOG_BLOCK_SIZE_OFFSET: usize = 0x14; // u32: block size = 1024 << this
const DEV_SIZE_OFFSET: usize = 0x20; // u64: block device size in bytes
const FREE_BLOCKS_OFFSET: usize = 0x50; // u64: free blocks count
const CTIME_OFFSET: usize = 0x58; // u64: s_ctime (creation, Unix seconds)
const WTIME_OFFSET: usize = 0x68; // u64: s_wtime (last write, Unix seconds)
const STATE_OFFSET: usize = 0x74; // u16: s_state (valid / error bits)
/// `s_state` bits: the filesystem is valid, and not flagged with errors.
const STATE_VALID_FS: u16 = 0x0001;
const STATE_ERROR_FS: u16 = 0x0002;
const UUID_OFFSET: usize = 0x98; // 16 bytes
const VOLUME_NAME_OFFSET: usize = 0xA8; // 80 bytes, NUL-padded
/// We read this much of the superblock to cover every field above.
const HEADER_LEN: usize = VOLUME_NAME_OFFSET + 80;

/// A recognised NILFS2 volume (detection only; no metadata undelete).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
    /// Block size in bytes.
    block_size: u64,
    /// Free (unallocated) bytes (`s_free_blocks_count` × block size).
    free_bytes: u64,
    /// Whether the volume is marked valid and free of errors (`s_state`).
    clean: bool,
    /// Creation time (`s_ctime`) as Unix seconds, `None` when unset.
    created: Option<u64>,
    /// Last-write time (`s_wtime`) as Unix seconds, `None` when unset.
    written: Option<u64>,
    /// Filesystem label (`s_volume_name`), empty when unset.
    label: String,
    /// Filesystem UUID (`s_uuid`), `None` when unset.
    uuid: Option<String>,
}

/// Does a NILFS2 superblock sit at `vol_offset`?
pub fn is_nilfs2(src: &Source, vol_offset: u64) -> bool {
    let Some(at) = vol_offset.checked_add(SB_OFFSET) else {
        return false;
    };
    let mut buf = [0u8; 8];
    if src.read_at(at, &mut buf).unwrap_or(0) < 8 {
        return false;
    }
    let rev = u32::from_le_bytes(
        buf[REV_LEVEL_OFFSET..REV_LEVEL_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    let magic = u16::from_le_bytes(buf[MAGIC_OFFSET..MAGIC_OFFSET + 2].try_into().unwrap());
    // The magic is only 2 bytes, so also require the current major revision to
    // avoid matching stray `0x3434` bytes.
    magic == MAGIC && rev == CURRENT_REV
}

impl Volume {
    /// Parse the NILFS2 superblock at `offset`, failing if there is none.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let at = offset
            .checked_add(SB_OFFSET)
            .ok_or_else(|| anyhow::anyhow!("offset overflow"))?;
        let mut hdr = [0u8; HEADER_LEN];
        if src.read_at(at, &mut hdr)? < HEADER_LEN {
            bail!("NILFS2 superblock truncated");
        }
        let rev = u32::from_le_bytes(
            hdr[REV_LEVEL_OFFSET..REV_LEVEL_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        let magic = u16::from_le_bytes(hdr[MAGIC_OFFSET..MAGIC_OFFSET + 2].try_into().unwrap());
        if magic != MAGIC || rev != CURRENT_REV {
            bail!("not a NILFS2 volume");
        }
        let dev_size = u64::from_le_bytes(
            hdr[DEV_SIZE_OFFSET..DEV_SIZE_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        // `s_dev_size` is the device size in bytes; fall back to the source span
        // when it is zero or exceeds what the source can hold.
        let fallback = src.size.saturating_sub(offset);
        let size = if dev_size > 0 && dev_size <= fallback.max(SB_OFFSET) {
            dev_size
        } else {
            fallback
        };
        let log_bs = u32::from_le_bytes(
            hdr[LOG_BLOCK_SIZE_OFFSET..LOG_BLOCK_SIZE_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        // Block size = 1024 << s_log_block_size; clamp the shift defensively.
        let block_size = 1024u64 << (log_bs & 0x1F);
        let free_blocks = u64::from_le_bytes(
            hdr[FREE_BLOCKS_OFFSET..FREE_BLOCKS_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        let state = u16::from_le_bytes(hdr[STATE_OFFSET..STATE_OFFSET + 2].try_into().unwrap());
        let clean = state & STATE_VALID_FS != 0 && state & STATE_ERROR_FS == 0;
        let read_time = |off: usize| {
            let t = u64::from_le_bytes(hdr[off..off + 8].try_into().unwrap());
            (t != 0).then_some(t)
        };
        let created = read_time(CTIME_OFFSET);
        let written = read_time(WTIME_OFFSET);
        let uuid = format_uuid(&hdr[UUID_OFFSET..UUID_OFFSET + 16]);
        let raw = &hdr[VOLUME_NAME_OFFSET..VOLUME_NAME_OFFSET + 80];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let label = String::from_utf8_lossy(&raw[..end]).into_owned();
        Ok(Volume {
            offset,
            size,
            block_size,
            free_bytes: free_blocks.saturating_mul(block_size),
            clean,
            created,
            written,
            label,
            uuid,
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

    /// Free (unallocated) bytes in the volume.
    pub fn free_bytes(&self) -> u64 {
        self.free_bytes
    }

    /// Whether the volume is marked valid and free of errors.
    pub fn is_clean(&self) -> bool {
        self.clean
    }

    /// Creation time as Unix seconds, `None` when unset.
    pub fn created_time(&self) -> Option<u64> {
        self.created
    }

    /// Last-write time as Unix seconds, `None` when unset.
    pub fn written_time(&self) -> Option<u64> {
        self.written
    }

    /// Short filesystem label.
    pub fn fs_label(&self) -> &'static str {
        "NILFS2"
    }

    /// The filesystem label (`s_volume_name`), or an empty string when unset.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The filesystem UUID (`s_uuid`), or `None` when unset.
    pub fn uuid(&self) -> Option<String> {
        self.uuid.clone()
    }

    /// NILFS2 metadata undelete is not supported (see the module docs); always
    /// returns an empty result so a mixed disk's other volumes still recover.
    /// Use `scan` (carving) to recover data from a NILFS2 volume.
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

    /// Build a NILFS2 volume of `total` bytes with a superblock at 1 KiB.
    fn nilfs2_image(dev_size: u64, uuid: &[u8; 16], label: &str, total: usize) -> Vec<u8> {
        let mut v = vec![0u8; total];
        let sb = SB_OFFSET as usize;
        v[sb + REV_LEVEL_OFFSET..sb + REV_LEVEL_OFFSET + 4]
            .copy_from_slice(&CURRENT_REV.to_le_bytes());
        v[sb + MAGIC_OFFSET..sb + MAGIC_OFFSET + 2].copy_from_slice(&MAGIC.to_le_bytes());
        v[sb + DEV_SIZE_OFFSET..sb + DEV_SIZE_OFFSET + 8].copy_from_slice(&dev_size.to_le_bytes());
        // 50 free blocks of 1 KiB (the default block size in this builder).
        v[sb + FREE_BLOCKS_OFFSET..sb + FREE_BLOCKS_OFFSET + 8]
            .copy_from_slice(&50u64.to_le_bytes());
        // Valid filesystem, no errors.
        v[sb + STATE_OFFSET..sb + STATE_OFFSET + 2].copy_from_slice(&STATE_VALID_FS.to_le_bytes());
        v[sb + CTIME_OFFSET..sb + CTIME_OFFSET + 8]
            .copy_from_slice(&1_600_000_000u64.to_le_bytes());
        v[sb + WTIME_OFFSET..sb + WTIME_OFFSET + 8]
            .copy_from_slice(&1_600_000_500u64.to_le_bytes());
        v[sb + UUID_OFFSET..sb + UUID_OFFSET + 16].copy_from_slice(uuid);
        let lb = label.as_bytes();
        v[sb + VOLUME_NAME_OFFSET..sb + VOLUME_NAME_OFFSET + lb.len()].copy_from_slice(lb);
        v
    }

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("nilfs2.img");
        std::fs::write(&p, bytes).unwrap();
        (tmp, Source::open(&p).unwrap())
    }

    #[test]
    fn detects_size_label_and_uuid() {
        let uuid = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00,
        ];
        let (_t, src) = source_of(&nilfs2_image(192 * 1024, &uuid, "snaps", 256 * 1024));
        assert!(is_nilfs2(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "NILFS2");
        assert_eq!(v.size(), 192 * 1024);
        assert_eq!(v.free_bytes(), 50 * 1024);
        assert!(v.is_clean());
        assert_eq!(v.created_time(), Some(1_600_000_000));
        assert_eq!(v.written_time(), Some(1_600_000_500));
        assert_eq!(v.label(), "snaps");
        assert_eq!(
            v.uuid().as_deref(),
            Some("11223344-5566-7788-99aa-bbccddeeff00")
        );
    }

    #[test]
    fn missing_uuid_and_label_report_as_absent() {
        let (_t, src) = source_of(&nilfs2_image(64 * 1024, &[0u8; 16], "", 256 * 1024));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.size(), 64 * 1024);
        assert_eq!(v.uuid(), None);
        assert_eq!(v.label(), "");
    }

    #[test]
    fn wrong_revision_is_not_nilfs2() {
        // The 0x3434 magic with the wrong major revision must be rejected.
        let mut v = nilfs2_image(64 * 1024, &[0u8; 16], "", 256 * 1024);
        let sb = SB_OFFSET as usize;
        v[sb + REV_LEVEL_OFFSET..sb + REV_LEVEL_OFFSET + 4].copy_from_slice(&1u32.to_le_bytes());
        let (_t, src) = source_of(&v);
        assert!(!is_nilfs2(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());
    }

    #[test]
    fn rejects_non_nilfs2_and_falls_back_on_bad_size() {
        let (_t, src) = source_of(&vec![0u8; 64 * 1024]);
        assert!(!is_nilfs2(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());

        // A device size larger than the source falls back to the span.
        let (_t, src) = source_of(&nilfs2_image(u64::MAX, &[0u8; 16], "", 64 * 1024));
        assert_eq!(Volume::parse(&src, 0).unwrap().size(), 64 * 1024);
    }
}
