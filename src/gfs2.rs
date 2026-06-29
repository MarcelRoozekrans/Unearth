//! GFS2 / GFS **detection** — no metadata undelete.
//!
//! GFS2 (the Global File System 2) is Red Hat's shared-disk cluster filesystem,
//! where several nodes mount the same block device at once. Its metadata is a
//! cluster-coordinated structure unlike a single-host filesystem, and a member
//! device is meaningful only as part of the cluster, so this module only
//! *recognises* a GFS2 (or the older GFS) volume — reporting its lock table and
//! UUID so `info` / `list_volumes` show it instead of leaving it unrecognised —
//! and leaves recovery to `scan` (carving).
//!
//! The superblock sits at a fixed 64 KiB into the volume and opens with a
//! metadata header carrying the big-endian magic `0x01161970` and block type 1
//! (`GFS2_METATYPE_SB`). The `sb_fs_format` field distinguishes GFS2 (1801) from
//! the original GFS (1309). The superblock records no total size (that is derived
//! from the resource groups), so the source span is reported instead.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{format_uuid, RecoverOptions, RecoverStats};
use crate::source::Source;

/// The superblock sits 64 KiB into the volume.
const SB_OFFSET: u64 = 65536;
/// `mh_magic` (big-endian u32) at offset 0 of the metadata header.
const MAGIC: u32 = 0x0116_1970;
/// `mh_type` value for a superblock (`GFS2_METATYPE_SB`).
const METATYPE_SB: u32 = 1;
/// `sb_fs_format` values: GFS2 vs the original GFS.
const FORMAT_GFS2: u32 = 1801;
const FORMAT_GFS1: u32 = 1309;
/// Byte offsets within the superblock (big-endian throughout).
const MAGIC_OFFSET: usize = 0x00; // u32
const TYPE_OFFSET: usize = 0x04; // u32
const FS_FORMAT_OFFSET: usize = 0x18; // u32
const LOCKTABLE_OFFSET: usize = 0xA0; // 64 bytes, NUL-padded
const UUID_OFFSET: usize = 0x100; // 16 bytes
/// We read this much of the superblock to cover every field above.
const HEADER_LEN: usize = UUID_OFFSET + 16;

/// A recognised GFS2/GFS volume (detection only; no metadata undelete).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
    /// Whether this is GFS2 (`true`) or the original GFS (`false`).
    is_gfs2: bool,
    /// Lock table name (`sb_locktable`, e.g. `cluster:fs`), empty when unset.
    label: String,
    /// Filesystem UUID (`sb_uuid`), `None` when unset.
    uuid: Option<String>,
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b[..4].try_into().unwrap())
}

/// Does a GFS2/GFS superblock sit at `vol_offset`?
pub fn is_gfs2(src: &Source, vol_offset: u64) -> bool {
    let Some(at) = vol_offset.checked_add(SB_OFFSET) else {
        return false;
    };
    let mut buf = [0u8; FS_FORMAT_OFFSET + 4];
    if src.read_at(at, &mut buf).unwrap_or(0) < buf.len() {
        return false;
    }
    let fmt = be32(&buf[FS_FORMAT_OFFSET..]);
    be32(&buf[MAGIC_OFFSET..]) == MAGIC
        && be32(&buf[TYPE_OFFSET..]) == METATYPE_SB
        // Require a known filesystem format to guard against a stray metadata
        // header (the magic and type also appear on other GFS2 metadata blocks).
        && (fmt == FORMAT_GFS2 || fmt == FORMAT_GFS1)
}

impl Volume {
    /// Parse the GFS2/GFS superblock at `offset`, failing if there is none.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let at = offset
            .checked_add(SB_OFFSET)
            .ok_or_else(|| anyhow::anyhow!("offset overflow"))?;
        let mut hdr = [0u8; HEADER_LEN];
        if src.read_at(at, &mut hdr)? < HEADER_LEN {
            bail!("GFS2 superblock truncated");
        }
        let fmt = be32(&hdr[FS_FORMAT_OFFSET..]);
        if be32(&hdr[MAGIC_OFFSET..]) != MAGIC
            || be32(&hdr[TYPE_OFFSET..]) != METATYPE_SB
            || (fmt != FORMAT_GFS2 && fmt != FORMAT_GFS1)
        {
            bail!("not a GFS2 volume");
        }
        // The superblock records no total size; report the source span.
        let size = src.size.saturating_sub(offset);
        let raw = &hdr[LOCKTABLE_OFFSET..LOCKTABLE_OFFSET + 64];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let label = String::from_utf8_lossy(&raw[..end]).into_owned();
        // The original GFS predates the on-disk UUID; only GFS2 carries one.
        let uuid = if fmt == FORMAT_GFS2 {
            format_uuid(&hdr[UUID_OFFSET..UUID_OFFSET + 16])
        } else {
            None
        };
        Ok(Volume {
            offset,
            size,
            is_gfs2: fmt == FORMAT_GFS2,
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
        if self.is_gfs2 {
            "GFS2"
        } else {
            "GFS"
        }
    }

    /// The lock table name (`sb_locktable`), or an empty string when unset.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The filesystem UUID (`sb_uuid`), or `None` when unset (or on GFS).
    pub fn uuid(&self) -> Option<String> {
        self.uuid.clone()
    }

    /// GFS2 metadata undelete is not supported (see the module docs); always
    /// returns an empty result so a mixed disk's other volumes still recover.
    /// Use `scan` (carving) to recover data from a GFS2 volume.
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

    /// Build a GFS2/GFS volume of `total` bytes with a superblock at 64 KiB.
    fn gfs2_image(fs_format: u32, locktable: &str, uuid: &[u8; 16], total: usize) -> Vec<u8> {
        let mut v = vec![0u8; total];
        let sb = SB_OFFSET as usize;
        v[sb + MAGIC_OFFSET..sb + MAGIC_OFFSET + 4].copy_from_slice(&MAGIC.to_be_bytes());
        v[sb + TYPE_OFFSET..sb + TYPE_OFFSET + 4].copy_from_slice(&METATYPE_SB.to_be_bytes());
        v[sb + FS_FORMAT_OFFSET..sb + FS_FORMAT_OFFSET + 4]
            .copy_from_slice(&fs_format.to_be_bytes());
        let lb = locktable.as_bytes();
        v[sb + LOCKTABLE_OFFSET..sb + LOCKTABLE_OFFSET + lb.len()].copy_from_slice(lb);
        v[sb + UUID_OFFSET..sb + UUID_OFFSET + 16].copy_from_slice(uuid);
        v
    }

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("gfs2.img");
        std::fs::write(&p, bytes).unwrap();
        (tmp, Source::open(&p).unwrap())
    }

    #[test]
    fn detects_gfs2_with_locktable_and_uuid() {
        let uuid = [
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
            0x67, 0x89,
        ];
        let (_t, src) = source_of(&gfs2_image(FORMAT_GFS2, "alpha:data", &uuid, 256 * 1024));
        assert!(is_gfs2(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "GFS2");
        assert_eq!(v.size(), 256 * 1024);
        assert_eq!(v.label(), "alpha:data");
        assert_eq!(
            v.uuid().as_deref(),
            Some("abcdef01-2345-6789-abcd-ef0123456789")
        );
    }

    #[test]
    fn detects_original_gfs_without_uuid() {
        let (_t, src) = source_of(&gfs2_image(FORMAT_GFS1, "old:vol", &[0xff; 16], 256 * 1024));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "GFS");
        assert_eq!(v.label(), "old:vol");
        // GFS predates the on-disk UUID, so none is reported even if bytes are set.
        assert_eq!(v.uuid(), None);
    }

    #[test]
    fn rejects_wrong_format_and_non_gfs2() {
        // The magic and type with an unknown format is rejected.
        let (_t, src) = source_of(&gfs2_image(42, "x", &[0u8; 16], 128 * 1024));
        assert!(!is_gfs2(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());

        let (_t, src) = source_of(&vec![0u8; 128 * 1024]);
        assert!(!is_gfs2(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());
    }
}
