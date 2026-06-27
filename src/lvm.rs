//! LVM2 physical-volume **detection** (no metadata undelete).
//!
//! LVM is the Linux Logical Volume Manager: a partition is initialised as a
//! *physical volume* (PV), one or more PVs form a *volume group*, and the group
//! is carved into *logical volumes* (LVs) that hold the actual filesystems. A
//! disk that uses LVM therefore has partitions whose contents are not a
//! filesystem but an LVM PV — without this, such a partition shows up as
//! unrecognised.
//!
//! This module *recognises* an LVM2 PV from its on-disk label (`LABELONE` plus
//! the `LVM2 001` type marker in the first sectors) and reports the PV's size, so
//! `info` / `list_volumes` surface it and the user knows to recover with `scan`
//! (carving) — a whole-source `scan` / `--scan` finds the filesystems inside the
//! logical volumes at their physical offsets. It does not map the LVs itself.
//!
//! The label is found by scanning the first four 512-byte sectors for the
//! `LABELONE` id; the label header then points to the PV header, which records
//! the device size.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// LVM scans the first four sectors of a device for the label.
const LABEL_SCAN_SECTORS: u64 = 4;
const SECTOR: u64 = 512;
/// `label_header.id` — present at the start of the label sector.
const LABEL_ID: &[u8; 8] = b"LABELONE";
/// `label_header.type` at offset 24 — the format type marker.
const LABEL_TYPE_OFFSET: usize = 24;
const LABEL_TYPE: &[u8; 8] = b"LVM2 001";
/// `label_header.offset_xl` (u32) at offset 20: byte offset from the label to the
/// PV header.
const LABEL_OFFSET_XL: usize = 20;
/// `pv_header.device_size_xl` (u64) at offset 32: the PV size in bytes.
const PV_DEVICE_SIZE_OFFSET: u64 = 32;

/// A recognised LVM2 physical volume (detection only; no metadata undelete).
pub struct Volume {
    /// Byte offset of the PV within the source.
    pub offset: u64,
    size: u64,
}

/// Find the LVM label within the first four sectors at `vol_offset`, returning
/// the sector's byte offset and the 512-byte label sector.
fn find_label(src: &Source, vol_offset: u64) -> Option<(u64, [u8; 512])> {
    for s in 0..LABEL_SCAN_SECTORS {
        let pos = vol_offset.checked_add(s.checked_mul(SECTOR)?)?;
        let mut sec = [0u8; 512];
        if src.read_at(pos, &mut sec).unwrap_or(0) < 512 {
            break;
        }
        if &sec[0..8] == LABEL_ID && &sec[LABEL_TYPE_OFFSET..LABEL_TYPE_OFFSET + 8] == LABEL_TYPE {
            return Some((pos, sec));
        }
    }
    None
}

/// Does an LVM2 PV label sit in the first sectors at `vol_offset`?
pub fn is_lvm(src: &Source, vol_offset: u64) -> bool {
    find_label(src, vol_offset).is_some()
}

impl Volume {
    /// Parse the LVM2 PV at `offset`, failing if there is no label.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let Some((label_byte, label)) = find_label(src, offset) else {
            bail!("not an LVM2 physical volume");
        };
        // The label header points to the PV header, which carries the size.
        let offset_xl = u32::from_le_bytes(
            label[LABEL_OFFSET_XL..LABEL_OFFSET_XL + 4]
                .try_into()
                .unwrap(),
        ) as u64;
        let fallback = src.size.saturating_sub(offset);
        let size = read_device_size(src, label_byte, offset_xl)
            .filter(|&sz| sz > 0 && sz <= fallback.max(SECTOR))
            .unwrap_or(fallback);
        Ok(Volume { offset, size })
    }

    /// Total size of the physical volume in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Short filesystem label.
    pub fn fs_label(&self) -> &'static str {
        "LVM2 PV"
    }

    /// LVM PV recovery is not supported (the logical volumes are not mapped); this
    /// always returns an empty result so a mixed disk's other volumes still
    /// recover. Use `scan` (carving) to recover data from inside an LVM volume.
    pub fn recover_deleted(
        &self,
        _src: &Source,
        _out_dir: &Path,
        _opts: &RecoverOptions,
    ) -> Result<RecoverStats> {
        Ok(RecoverStats::default())
    }
}

/// Read `pv_header.device_size` (a u64 at offset 32 of the PV header, which is
/// `offset_xl` bytes past the label), or `None` if it can't be read.
fn read_device_size(src: &Source, label_byte: u64, offset_xl: u64) -> Option<u64> {
    let pv = label_byte.checked_add(offset_xl)?;
    let pos = pv.checked_add(PV_DEVICE_SIZE_OFFSET)?;
    let mut buf = [0u8; 8];
    if src.read_at(pos, &mut buf).ok()? < 8 {
        return None;
    }
    Some(u64::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a source whose label sits in `label_sector`, with the PV header
    /// (and its `device_size`) `offset_xl` bytes past the label.
    fn pv_image(label_sector: u64, offset_xl: u32, device_size: u64, total: usize) -> Vec<u8> {
        let mut v = vec![0u8; total];
        let lb = (label_sector * SECTOR) as usize;
        v[lb..lb + 8].copy_from_slice(LABEL_ID);
        v[lb + LABEL_OFFSET_XL..lb + LABEL_OFFSET_XL + 4].copy_from_slice(&offset_xl.to_le_bytes());
        v[lb + LABEL_TYPE_OFFSET..lb + LABEL_TYPE_OFFSET + 8].copy_from_slice(LABEL_TYPE);
        let ds = lb + offset_xl as usize + PV_DEVICE_SIZE_OFFSET as usize;
        v[ds..ds + 8].copy_from_slice(&device_size.to_le_bytes());
        v
    }

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("pv.img");
        std::fs::write(&p, bytes).unwrap();
        let src = Source::open(&p).unwrap();
        (tmp, src)
    }

    #[test]
    fn detects_and_sizes_a_pv() {
        // Label in sector 1 (the usual place), PV header 32 bytes later.
        let (_t, src) = source_of(&pv_image(1, 32, 9000, 16 * 1024));
        assert!(is_lvm(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "LVM2 PV");
        assert_eq!(v.size(), 9000);
    }

    #[test]
    fn rejects_non_lvm_and_falls_back_on_bad_size() {
        // No label anywhere.
        let (_t, src) = source_of(&vec![0u8; 4 * 1024]);
        assert!(!is_lvm(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());

        // A label with an implausible device_size falls back to the source span.
        let (_t, src) = source_of(&pv_image(1, 32, u64::MAX, 8 * 1024));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.size(), 8 * 1024);
    }

    #[test]
    fn finds_label_in_sector_zero() {
        let (_t, src) = source_of(&pv_image(0, 32, 4096, 16 * 1024));
        assert!(is_lvm(&src, 0));
        assert_eq!(Volume::parse(&src, 0).unwrap().size(), 4096);
    }
}
