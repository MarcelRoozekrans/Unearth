//! Linux MD (software RAID) member **detection** — no metadata undelete.
//!
//! `mdadm` builds a software RAID array from member devices (partitions or whole
//! disks); each member carries an MD superblock describing the array. A member
//! device is not itself a filesystem — the real filesystem lives on the
//! *assembled* array — so without this a RAID member shows up as unrecognised.
//!
//! This module *recognises* an MD member from its version-1 superblock and
//! reports the array's UUID, name, RAID level, and the member's data size, so
//! `info` / `list_volumes` surface it and the user knows to assemble the array
//! (`mdadm --assemble`) before recovering from it. It does not assemble the array
//! or map the data itself.
//!
//! Only the version-1 superblock is read. Its location depends on the sub-version
//! (`mdadm` writes 1.2 by default): **1.1** places it at the start of the device,
//! **1.2** at 4 KiB in. The rarer **1.0** (near the end of the device) is not
//! detected, since its position depends on the exact device size.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// `mdp_superblock_1.magic` (little-endian u32) at offset 0 of the superblock.
const MD_MAGIC: u32 = 0xA92B_4EFC;
/// Byte offsets within the version-1 superblock.
const MAJOR_VERSION_OFFSET: usize = 4;
const SET_UUID_OFFSET: usize = 0x10; // 16 bytes
const SET_NAME_OFFSET: usize = 0x20; // 32 bytes, NUL-padded
const LEVEL_OFFSET: usize = 0x48; // i32
const SIZE_OFFSET: usize = 0x50; // u64, used component size in 512-byte sectors
/// We read this many bytes of the superblock to cover every field above.
const HEADER_LEN: usize = SIZE_OFFSET + 8;
/// Candidate superblock locations: 1.1 at the device start, 1.2 at 4 KiB.
const SB_OFFSETS: [u64; 2] = [0, 4096];
const SECTOR: u64 = 512;

/// A recognised Linux MD/RAID member (detection only; no metadata undelete).
pub struct Volume {
    /// Byte offset of the member within the source.
    pub offset: u64,
    size: u64,
    /// Array UUID (`set_uuid`), `None` when unset.
    uuid: Option<String>,
    /// Array name (`set_name`), empty when unset.
    name: String,
    /// RAID level (`level`): 0/1/4/5/6/10, or -1 for linear.
    level: i32,
}

/// The superblock offset (0 for 1.1, 4096 for 1.2) carrying the MD magic at
/// `vol_offset`, or `None` if there is no version-1 MD superblock.
fn sb_offset(src: &Source, vol_offset: u64) -> Option<u64> {
    for &sb in &SB_OFFSETS {
        let at = vol_offset.checked_add(sb)?;
        let mut buf = [0u8; 8];
        if src.read_at(at, &mut buf).unwrap_or(0) < 8 {
            continue;
        }
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let major = u32::from_le_bytes(
            buf[MAJOR_VERSION_OFFSET..MAJOR_VERSION_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        if magic == MD_MAGIC && major == 1 {
            return Some(at);
        }
    }
    None
}

/// Does a version-1 MD superblock sit at `vol_offset`?
pub fn is_mdraid(src: &Source, vol_offset: u64) -> bool {
    sb_offset(src, vol_offset).is_some()
}

/// Format an MD `set_uuid` the way `mdadm` shows it: four colon-separated groups
/// of eight hex digits. `None` when all-zero.
fn format_md_uuid(raw: &[u8]) -> Option<String> {
    if raw.len() < 16 || raw.iter().all(|&b| b == 0) {
        return None;
    }
    let group = |g: usize| {
        let o = g * 4;
        format!(
            "{:02x}{:02x}{:02x}{:02x}",
            raw[o],
            raw[o + 1],
            raw[o + 2],
            raw[o + 3]
        )
    };
    Some(format!(
        "{}:{}:{}:{}",
        group(0),
        group(1),
        group(2),
        group(3)
    ))
}

impl Volume {
    /// Parse the MD superblock at `offset`, failing if there is none.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let Some(sb) = sb_offset(src, offset) else {
            bail!("not a Linux MD/RAID member");
        };
        let mut hdr = [0u8; HEADER_LEN];
        if src.read_at(sb, &mut hdr)? < HEADER_LEN {
            bail!("MD superblock truncated");
        }
        let uuid = format_md_uuid(&hdr[SET_UUID_OFFSET..SET_UUID_OFFSET + 16]);
        let raw = &hdr[SET_NAME_OFFSET..SET_NAME_OFFSET + 32];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let name = String::from_utf8_lossy(&raw[..end]).into_owned();
        let level = i32::from_le_bytes(hdr[LEVEL_OFFSET..LEVEL_OFFSET + 4].try_into().unwrap());
        let sectors = u64::from_le_bytes(hdr[SIZE_OFFSET..SIZE_OFFSET + 8].try_into().unwrap());
        // `size` is the used component size in 512-byte sectors; fall back to the
        // source span when it is zero or implausibly large.
        let fallback = src.size.saturating_sub(offset);
        let size = sectors
            .checked_mul(SECTOR)
            .filter(|&b| b > 0 && b <= fallback.max(SECTOR))
            .unwrap_or(fallback);
        Ok(Volume {
            offset,
            size,
            uuid,
            name,
            level,
        })
    }

    /// Total size of the member's data area in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// A label including the RAID level, e.g. `"Linux RAID5"` or
    /// `"Linux RAID (linear)"`.
    pub fn fs_label(&self) -> String {
        match self.level {
            0 | 1 | 4 | 5 | 6 | 10 => format!("Linux RAID{}", self.level),
            -1 => "Linux RAID (linear)".to_string(),
            _ => "Linux RAID".to_string(),
        }
    }

    /// The array name (`set_name`), or an empty string when unset.
    pub fn label(&self) -> &str {
        &self.name
    }

    /// The array UUID (`set_uuid`) in `mdadm` form, or `None` when unset.
    pub fn uuid(&self) -> Option<String> {
        self.uuid.clone()
    }

    /// MD member recovery is not supported (the array is not assembled); this
    /// always returns an empty result so a mixed disk's other volumes still
    /// recover. Assemble the array with `mdadm` first, then recover from it.
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

    /// Build a device of `total` bytes carrying a version-1 MD superblock at
    /// `sb` with the given fields.
    fn md_image(
        sb: usize,
        uuid: &[u8; 16],
        name: &str,
        level: i32,
        size_sectors: u64,
        total: usize,
    ) -> Vec<u8> {
        let mut v = vec![0u8; total];
        v[sb..sb + 4].copy_from_slice(&MD_MAGIC.to_le_bytes());
        v[sb + MAJOR_VERSION_OFFSET..sb + MAJOR_VERSION_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        v[sb + SET_UUID_OFFSET..sb + SET_UUID_OFFSET + 16].copy_from_slice(uuid);
        let nb = name.as_bytes();
        v[sb + SET_NAME_OFFSET..sb + SET_NAME_OFFSET + nb.len()].copy_from_slice(nb);
        v[sb + LEVEL_OFFSET..sb + LEVEL_OFFSET + 4].copy_from_slice(&level.to_le_bytes());
        v[sb + SIZE_OFFSET..sb + SIZE_OFFSET + 8].copy_from_slice(&size_sectors.to_le_bytes());
        v
    }

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("md.img");
        std::fs::write(&p, bytes).unwrap();
        let src = Source::open(&p).unwrap();
        (tmp, src)
    }

    #[test]
    fn detects_a_v1_2_member() {
        // 1.2 superblock at 4 KiB.
        let uuid = [
            0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e,
            0x8f, 0x90,
        ];
        let (_t, src) = source_of(&md_image(4096, &uuid, "nas:0", 5, 200, 256 * 1024));
        assert!(is_mdraid(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "Linux RAID5");
        assert_eq!(v.size(), 200 * 512);
        assert_eq!(v.label(), "nas:0");
        assert_eq!(
            v.uuid().as_deref(),
            Some("a1b2c3d4:e5f60718:293a4b5c:6d7e8f90")
        );
    }

    #[test]
    fn detects_a_v1_1_member_at_offset_zero() {
        let (_t, src) = source_of(&md_image(0, &[0u8; 16], "", 1, 100, 64 * 1024));
        assert!(is_mdraid(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "Linux RAID1");
        // All-zero UUID and empty name are reported as absent.
        assert_eq!(v.uuid(), None);
        assert_eq!(v.label(), "");
    }

    #[test]
    fn linear_and_unknown_levels() {
        let (_t, src) = source_of(&md_image(0, &[1u8; 16], "", -1, 10, 8 * 1024));
        assert_eq!(
            Volume::parse(&src, 0).unwrap().fs_label(),
            "Linux RAID (linear)"
        );
    }

    #[test]
    fn rejects_non_md_and_falls_back_on_bad_size() {
        let (_t, src) = source_of(&vec![0u8; 8 * 1024]);
        assert!(!is_mdraid(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());

        // An implausible component size falls back to the source span.
        let (_t, src) = source_of(&md_image(0, &[2u8; 16], "x", 5, u64::MAX / 256, 8 * 1024));
        assert_eq!(Volume::parse(&src, 0).unwrap().size(), 8 * 1024);
    }
}
