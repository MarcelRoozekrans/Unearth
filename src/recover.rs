//! Unified entry point for filesystem-aware undelete.
//!
//! Detects the filesystem of each volume in a source and dispatches to the
//! appropriate recovery backend ([`crate::fat`], [`crate::exfat`],
//! [`crate::ntfs`], or [`crate::ext4`]), so the `undelete` command can treat
//! every supported filesystem the same way.

use std::path::Path;

use anyhow::{bail, Result};

use crate::source::Source;
use crate::{exfat, ext4, fat, ntfs};

/// Outcome of recovering deleted files from one volume.
#[derive(Default)]
pub struct RecoverStats {
    pub recovered: u64,
    pub bytes_recovered: u64,
    /// Entries that looked deleted but failed validation (bad cluster/size).
    pub skipped: u64,
}

/// A detected, recoverable volume of a known filesystem type.
pub enum Volume {
    Fat(fat::Volume),
    Exfat(exfat::Volume),
    Ntfs(ntfs::Volume),
    Ext(ext4::Volume),
}

impl Volume {
    /// Byte offset of the volume within the source.
    pub fn offset(&self) -> u64 {
        match self {
            Volume::Fat(v) => v.offset,
            Volume::Exfat(v) => v.offset,
            Volume::Ntfs(v) => v.offset,
            Volume::Ext(v) => v.offset,
        }
    }

    /// Short human-readable filesystem label, e.g. `"FAT16"` or `"exFAT"`.
    pub fn fs_label(&self) -> String {
        match self {
            Volume::Fat(v) => format!("{:?}", v.fat_type),
            Volume::Exfat(_) => "exFAT".to_string(),
            Volume::Ntfs(_) => "NTFS".to_string(),
            Volume::Ext(_) => "ext2/3/4".to_string(),
        }
    }

    /// Recover all deleted files from this volume into `out_dir`.
    pub fn recover_deleted(
        &self,
        src: &Source,
        out_dir: &Path,
        min_size: u64,
    ) -> Result<RecoverStats> {
        match self {
            Volume::Fat(v) => v.recover_deleted(src, out_dir, min_size as u32),
            Volume::Exfat(v) => v.recover_deleted(src, out_dir, min_size),
            Volume::Ntfs(v) => v.recover_deleted(src, out_dir, min_size),
            Volume::Ext(v) => v.recover_deleted(src, out_dir, min_size),
        }
    }
}

/// Detect every FAT/exFAT volume in `src`: a bare volume at offset 0, or the
/// volumes referenced by an MBR partition table.
pub fn detect(src: &Source) -> Result<Vec<Volume>> {
    let mut sector0 = [0u8; 512];
    if src.read_at(0, &mut sector0)? < 512 {
        bail!("source too small to contain a filesystem");
    }

    // Bare volume: prefer an exact filesystem signature in sector 0.
    if exfat::is_exfat_vbr(&sector0) {
        if let Ok(v) = exfat::Volume::parse(src, 0) {
            return Ok(vec![Volume::Exfat(v)]);
        }
    }
    if ntfs::is_ntfs_vbr(&sector0) {
        if let Ok(v) = ntfs::Volume::parse(src, 0) {
            return Ok(vec![Volume::Ntfs(v)]);
        }
    }
    if ext4::is_ext_volume(src, 0) {
        if let Ok(v) = ext4::Volume::parse(src, 0) {
            return Ok(vec![Volume::Ext(v)]);
        }
    }
    if fat::looks_like_fat_vbr(&sector0) {
        if let Ok(v) = fat::Volume::parse(src, 0) {
            return Ok(vec![Volume::Fat(v)]);
        }
    }

    // Otherwise walk an MBR partition table.
    let mut volumes = Vec::new();
    if sector0[510] == 0x55 && sector0[511] == 0xAA {
        for i in 0..4 {
            let base = 446 + i * 16;
            let ptype = sector0[base + 4];
            let lba_start = u32::from_le_bytes([
                sector0[base + 8],
                sector0[base + 9],
                sector0[base + 10],
                sector0[base + 11],
            ]);
            if lba_start == 0 {
                continue;
            }
            let offset = lba_start as u64 * 512;

            // Type 0x07 covers both exFAT and NTFS; the signature check inside
            // each parser decides which (or neither).
            if ptype == 0x07 {
                if let Ok(v) = exfat::Volume::parse(src, offset) {
                    volumes.push(Volume::Exfat(v));
                } else if let Ok(v) = ntfs::Volume::parse(src, offset) {
                    volumes.push(Volume::Ntfs(v));
                }
            } else if ptype == 0x83 {
                // Linux native: ext2/3/4.
                if let Ok(v) = ext4::Volume::parse(src, offset) {
                    volumes.push(Volume::Ext(v));
                }
            } else if fat::is_fat_partition_type(ptype) {
                if let Ok(v) = fat::Volume::parse(src, offset) {
                    volumes.push(Volume::Fat(v));
                }
            } else {
                // Unknown type: try each, signature checks decide.
                if let Ok(v) = exfat::Volume::parse(src, offset) {
                    volumes.push(Volume::Exfat(v));
                } else if let Ok(v) = ntfs::Volume::parse(src, offset) {
                    volumes.push(Volume::Ntfs(v));
                } else if ext4::is_ext_volume(src, offset) {
                    if let Ok(v) = ext4::Volume::parse(src, offset) {
                        volumes.push(Volume::Ext(v));
                    }
                } else if let Ok(v) = fat::Volume::parse(src, offset) {
                    volumes.push(Volume::Fat(v));
                }
            }
        }
    }

    if volumes.is_empty() {
        bail!("no FAT, exFAT, NTFS, or ext2/3/4 volume found");
    }
    Ok(volumes)
}

/// Parse a single volume at an explicit byte offset, trying each backend.
pub fn parse_at(src: &Source, offset: u64) -> Result<Volume> {
    if let Ok(v) = exfat::Volume::parse(src, offset) {
        return Ok(Volume::Exfat(v));
    }
    if let Ok(v) = ntfs::Volume::parse(src, offset) {
        return Ok(Volume::Ntfs(v));
    }
    if ext4::is_ext_volume(src, offset) {
        if let Ok(v) = ext4::Volume::parse(src, offset) {
            return Ok(Volume::Ext(v));
        }
    }
    let v = fat::Volume::parse(src, offset)?;
    Ok(Volume::Fat(v))
}
