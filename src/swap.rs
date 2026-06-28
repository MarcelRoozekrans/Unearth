//! Linux swap area **detection** — no recoverable files.
//!
//! A swap partition is not a filesystem and holds no files to recover, but it is
//! recognised so `info` / `list_volumes` can label it (rather than show it as an
//! unrecognised volume) and report its size, UUID, and label straight from the
//! swap header. A disk imaged for recovery almost always carries a swap
//! partition, and identifying it — by its `UUID=`, the value `/etc/fstab` uses —
//! helps confirm which disk an image came from and rules the area out as a place
//! to look for lost files.
//!
//! Detection targets the version-2 layout written by `mkswap` (every swap area
//! created since Linux 2.2). The first page of the area is a `union swap_header`:
//! a 1 KiB `bootbits` reserved region, then `version`, `last_page`, `nr_badpages`,
//! a 16-byte UUID, and a 16-byte label, with the ASCII magic `"SWAPSPACE2"`
//! written at the very end of the page (`page_size - 10`). The magic's position
//! reveals the page size the area was created with (commonly 4 KiB). The older
//! version-1 format (`"SWAP-SPACE"`, which lacks the UUID/`last_page` fields) and
//! hibernation images (`"S1SUSPEND"` / `"S2SUSPEND"`) are not reported here.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// `version` (little-endian u32) at offset 1024 of the swap header. The on-disk
/// value is `1` for a version-2 (`"SWAPSPACE2"`) area.
const VERSION_OFFSET: u64 = 1024;
/// `last_page` (little-endian u32) at offset 1028: index of the last page of the
/// swap area.
const LAST_PAGE_OFFSET: u64 = 1028;
/// `sws_uuid[16]` at offset 1036: the swap area's UUID.
const UUID_OFFSET: usize = 1036;
/// `sws_volume[16]` at offset 1052: the swap area's label, NUL-padded.
const LABEL_OFFSET: usize = 1052;
const LABEL_LEN: usize = 16;
/// We read this many bytes of the header to cover every field above.
const HEADER_LEN: usize = LABEL_OFFSET + LABEL_LEN;
/// The version-2 magic, written at `page_size - 10`.
const MAGIC: &[u8; 10] = b"SWAPSPACE2";
/// Page sizes a swap area may have been created with; the magic sits at
/// `page_size - 10` for one of these (4 KiB is by far the most common).
const PAGE_SIZES: [u64; 4] = [4096, 8192, 16384, 65536];

/// A recognised Linux swap area (detection only; holds no recoverable files).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
    /// Page size the area was created with (the magic's position gives it).
    page_size: u64,
    label: String,
    uuid: Option<String>,
}

/// The page size whose `page_size - 10` slot holds the version-2 swap magic, or
/// `None` if `vol_offset` is not a version-2 swap area.
fn swap_page_size(src: &Source, vol_offset: u64) -> Option<u64> {
    for &ps in &PAGE_SIZES {
        let mut magic = [0u8; 10];
        if src.read_at(vol_offset + ps - 10, &mut magic).unwrap_or(0) < 10 {
            continue;
        }
        if &magic == MAGIC {
            return Some(ps);
        }
    }
    None
}

/// Does `vol_offset` carry a Linux version-2 swap header?
pub fn is_swap(src: &Source, vol_offset: u64) -> bool {
    swap_page_size(src, vol_offset).is_some()
}

impl Volume {
    /// Parse the swap header at `offset`, failing if it is not a version-2 area.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let page_size = match swap_page_size(src, offset) {
            Some(ps) => ps,
            None => bail!("not a Linux swap area"),
        };
        let mut hdr = [0u8; HEADER_LEN];
        if src.read_at(offset, &mut hdr)? < HEADER_LEN {
            bail!("swap header truncated");
        }
        // The header `version` field is 1 for a "SWAPSPACE2" area; require it so a
        // page-aligned coincidental magic does not produce a bogus volume.
        let version = u32::from_le_bytes(
            hdr[VERSION_OFFSET as usize..VERSION_OFFSET as usize + 4]
                .try_into()
                .unwrap(),
        );
        if version != 1 {
            bail!("unsupported swap version {version}");
        }
        let last_page = u32::from_le_bytes(
            hdr[LAST_PAGE_OFFSET as usize..LAST_PAGE_OFFSET as usize + 4]
                .try_into()
                .unwrap(),
        ) as u64;
        if last_page == 0 {
            bail!("swap area reports zero pages");
        }
        // The area spans pages 0..=last_page inclusive (page 0 is this header).
        let size = last_page
            .saturating_add(1)
            .saturating_mul(page_size)
            .min(src.size.saturating_sub(offset).max(page_size));

        let raw = &hdr[LABEL_OFFSET..LABEL_OFFSET + LABEL_LEN];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(LABEL_LEN);
        let label = String::from_utf8_lossy(&raw[..end]).into_owned();
        let uuid = crate::recover::format_uuid(&hdr[UUID_OFFSET..UUID_OFFSET + 16]);

        Ok(Volume {
            offset,
            size,
            page_size,
            label,
            uuid,
        })
    }

    /// Total size of the swap area in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Short label for the area.
    pub fn fs_label(&self) -> &'static str {
        "Linux swap"
    }

    /// The swap label (`sws_volume`), or an empty string when unset.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The swap area's UUID (the `UUID=` value `/etc/fstab` uses), or `None`.
    pub fn uuid(&self) -> Option<String> {
        self.uuid.clone()
    }

    /// The page size the area was created with, in bytes.
    pub fn page_size(&self) -> u64 {
        self.page_size
    }

    /// A swap area holds no files; recovery always yields an empty result so a
    /// mixed disk's other volumes still recover.
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

    /// Build a minimal version-2 swap area with the given page size and fields.
    fn swap_area(page_size: u64, last_page: u32, uuid: &[u8; 16], label: &str) -> Vec<u8> {
        let total = (last_page as u64 + 1) * page_size;
        let mut v = vec![0u8; total as usize];
        v[VERSION_OFFSET as usize..VERSION_OFFSET as usize + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        v[LAST_PAGE_OFFSET as usize..LAST_PAGE_OFFSET as usize + 4]
            .copy_from_slice(&last_page.to_le_bytes());
        v[UUID_OFFSET..UUID_OFFSET + 16].copy_from_slice(uuid);
        let lbytes = label.as_bytes();
        v[LABEL_OFFSET..LABEL_OFFSET + lbytes.len()].copy_from_slice(lbytes);
        v[(page_size - 10) as usize..page_size as usize].copy_from_slice(MAGIC);
        v
    }

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("v.img");
        std::fs::write(&p, bytes).unwrap();
        let src = Source::open(&p).unwrap();
        (tmp, src)
    }

    #[test]
    fn detects_size_uuid_and_label() {
        let uuid = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let (_t, src) = source_of(&swap_area(4096, 9, &uuid, "swap0"));
        assert!(is_swap(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "Linux swap");
        assert_eq!(v.size(), 10 * 4096);
        assert_eq!(v.page_size(), 4096);
        assert_eq!(v.label(), "swap0");
        assert_eq!(
            v.uuid().as_deref(),
            Some("12345678-9abc-def0-1122-334455667788")
        );
    }

    #[test]
    fn detects_a_larger_page_size() {
        let (_t, src) = source_of(&swap_area(65536, 3, &[0u8; 16], ""));
        assert!(is_swap(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.page_size(), 65536);
        assert_eq!(v.size(), 4 * 65536);
        // An all-zero UUID and an empty label are reported as absent.
        assert_eq!(v.uuid(), None);
        assert_eq!(v.label(), "");
    }

    #[test]
    fn rejects_non_swap_data() {
        let (_t, src) = source_of(&vec![0u8; 8192]);
        assert!(!is_swap(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());
    }

    #[test]
    fn rejects_wrong_version() {
        // Magic present but the header version field is not 1.
        let mut a = swap_area(4096, 9, &[0u8; 16], "");
        a[VERSION_OFFSET as usize..VERSION_OFFSET as usize + 4]
            .copy_from_slice(&7u32.to_le_bytes());
        let (_t, src) = source_of(&a);
        // The magic still matches, but parsing rejects the unknown version.
        assert!(is_swap(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());
    }
}
