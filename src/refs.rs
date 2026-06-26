//! ReFS (Resilient File System) **detection** — no metadata undelete.
//!
//! ReFS is Microsoft's copy-on-write filesystem (Windows Server, and Storage
//! Spaces / Dev Drive on Windows clients). Like APFS and Btrfs it rewrites its
//! metadata B+ trees through a checkpoint/copy-on-write scheme rather than
//! editing records in place, so a deleted file leaves no stale directory entry
//! to scavenge and metadata-based undelete is not tractable the way it is for
//! FAT/exFAT/NTFS/ext/HFS+. The on-disk format is also undocumented by
//! Microsoft. This module therefore *recognises* a ReFS volume and reports its
//! geometry — so `info` / `list_volumes` surface it and the user knows to fall
//! back to `scan` (carving) — but it recovers nothing itself.
//!
//! Detection reads the volume boot record at the start of the volume: a ReFS
//! VBR carries the file-system signature `"ReFS"` at offset 3 and the structure
//! identifier `"FSRS"` at offset 0x10. The boot record also records the sector
//! count, bytes per sector, and sectors per cluster, from which the volume size
//! is derived.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// `"ReFS"` file-system signature at offset 3 of the boot sector.
const FS_SIGNATURE_OFFSET: usize = 3;
const FS_SIGNATURE: &[u8; 4] = b"ReFS";
/// `"FSRS"` structure identifier at offset 0x10.
const FSRS_OFFSET: usize = 0x10;
const FSRS_SIGNATURE: &[u8; 4] = b"FSRS";
/// Number of sectors in the volume (u64) at offset 0x18.
const NUM_SECTORS_OFFSET: usize = 0x18;
/// Bytes per sector (u32) at offset 0x20.
const BYTES_PER_SECTOR_OFFSET: usize = 0x20;
/// Sectors per cluster (u32) at offset 0x24.
const SECTORS_PER_CLUSTER_OFFSET: usize = 0x24;
/// Major / minor format version (u8 each) at offsets 0x28 / 0x29.
const VERSION_MAJOR_OFFSET: usize = 0x28;
const VERSION_MINOR_OFFSET: usize = 0x29;
/// We read this many bytes of the boot record to cover every field above.
const HEADER_LEN: usize = 0x2A;

/// A recognised ReFS volume (detection only; no metadata undelete).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
    bytes_per_sector: u32,
    sectors_per_cluster: u32,
    version_major: u8,
    version_minor: u8,
}

/// Does the boot record at `offset` carry the ReFS signatures (`"ReFS"` at
/// offset 3 and `"FSRS"` at offset 0x10)?
pub fn is_refs(src: &Source, offset: u64) -> bool {
    let mut head = [0u8; FSRS_OFFSET + 4];
    if src.read_at(offset, &mut head).unwrap_or(0) < head.len() {
        return false;
    }
    &head[FS_SIGNATURE_OFFSET..FS_SIGNATURE_OFFSET + 4] == FS_SIGNATURE
        && &head[FSRS_OFFSET..FSRS_OFFSET + 4] == FSRS_SIGNATURE
}

impl Volume {
    /// Parse the ReFS boot record at `offset`, failing if it is not one.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let mut hdr = [0u8; HEADER_LEN];
        if src.read_at(offset, &mut hdr)? < HEADER_LEN {
            bail!("ReFS boot record truncated");
        }
        if &hdr[FS_SIGNATURE_OFFSET..FS_SIGNATURE_OFFSET + 4] != FS_SIGNATURE
            || &hdr[FSRS_OFFSET..FSRS_OFFSET + 4] != FSRS_SIGNATURE
        {
            bail!("not a ReFS volume");
        }
        let num_sectors = u64::from_le_bytes(
            hdr[NUM_SECTORS_OFFSET..NUM_SECTORS_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        let bytes_per_sector = u32::from_le_bytes(
            hdr[BYTES_PER_SECTOR_OFFSET..BYTES_PER_SECTOR_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        let sectors_per_cluster = u32::from_le_bytes(
            hdr[SECTORS_PER_CLUSTER_OFFSET..SECTORS_PER_CLUSTER_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        // Derive the volume size from the geometry, but fall back to the source
        // span if the boot record's fields are implausible (the format is
        // undocumented, so be conservative rather than report a wrong size).
        let size = match bytes_per_sector {
            bps if (512..=65536).contains(&bps) && bps.is_power_of_two() && num_sectors > 0 => {
                num_sectors
                    .checked_mul(bps as u64)
                    .unwrap_or_else(|| src.size.saturating_sub(offset))
            }
            _ => src.size.saturating_sub(offset),
        };
        Ok(Volume {
            offset,
            size,
            bytes_per_sector,
            sectors_per_cluster,
            version_major: hdr[VERSION_MAJOR_OFFSET],
            version_minor: hdr[VERSION_MINOR_OFFSET],
        })
    }

    /// Total size of the volume in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Short filesystem label.
    pub fn fs_label(&self) -> &'static str {
        "ReFS"
    }

    /// Cluster size in bytes (bytes per sector × sectors per cluster), or `None`
    /// when the boot record's geometry is implausible.
    pub fn cluster_size(&self) -> Option<u64> {
        let bps = self.bytes_per_sector as u64;
        let spc = self.sectors_per_cluster as u64;
        if bps == 0 || spc == 0 {
            return None;
        }
        bps.checked_mul(spc)
    }

    /// The on-disk format version as `(major, minor)` (e.g. `(1, 2)` or
    /// `(3, 14)`), or `None` when the boot record does not record one.
    pub fn version(&self) -> Option<(u8, u8)> {
        if self.version_major == 0 {
            None
        } else {
            Some((self.version_major, self.version_minor))
        }
    }

    /// ReFS metadata undelete is not supported (see the module docs); this
    /// always returns an empty result so a mixed disk's other volumes still
    /// recover. Use `scan` (carving) to recover data from a ReFS volume.
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

    /// Build a minimal ReFS boot record with the given geometry and version.
    fn boot_record(
        num_sectors: u64,
        bytes_per_sector: u32,
        sectors_per_cluster: u32,
        version: (u8, u8),
    ) -> Vec<u8> {
        let mut v = vec![0u8; 512];
        v[FS_SIGNATURE_OFFSET..FS_SIGNATURE_OFFSET + 4].copy_from_slice(FS_SIGNATURE);
        v[FSRS_OFFSET..FSRS_OFFSET + 4].copy_from_slice(FSRS_SIGNATURE);
        v[NUM_SECTORS_OFFSET..NUM_SECTORS_OFFSET + 8].copy_from_slice(&num_sectors.to_le_bytes());
        v[BYTES_PER_SECTOR_OFFSET..BYTES_PER_SECTOR_OFFSET + 4]
            .copy_from_slice(&bytes_per_sector.to_le_bytes());
        v[SECTORS_PER_CLUSTER_OFFSET..SECTORS_PER_CLUSTER_OFFSET + 4]
            .copy_from_slice(&sectors_per_cluster.to_le_bytes());
        v[VERSION_MAJOR_OFFSET] = version.0;
        v[VERSION_MINOR_OFFSET] = version.1;
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
    fn detects_sizes_and_versions_a_volume() {
        let (_t, src) = source_of(&boot_record(2048, 512, 8, (3, 14)));
        assert!(is_refs(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "ReFS");
        assert_eq!(v.size(), 2048 * 512);
        assert_eq!(v.cluster_size(), Some(512 * 8));
        assert_eq!(v.version(), Some((3, 14)));
    }

    #[test]
    fn rejects_non_refs_data() {
        // No signatures.
        let (_t, src) = source_of(&vec![0u8; 512]);
        assert!(!is_refs(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());

        // "ReFS" present but the "FSRS" identifier missing.
        let mut b = boot_record(2048, 512, 8, (3, 14));
        b[FSRS_OFFSET..FSRS_OFFSET + 4].copy_from_slice(b"XXXX");
        let (_t, src) = source_of(&b);
        assert!(!is_refs(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());
    }

    #[test]
    fn falls_back_to_source_span_for_implausible_geometry() {
        // A non-power-of-two sector size: size falls back to the source length.
        let mut b = boot_record(2048, 1000, 8, (1, 2));
        b.resize(4096, 0); // make the source larger than the geometry claims
        let (_t, src) = source_of(&b);
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.size(), 4096);
        assert_eq!(v.cluster_size(), Some(1000 * 8)); // geometry still reported
    }
}
