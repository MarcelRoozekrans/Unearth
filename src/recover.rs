//! Unified entry point for filesystem-aware undelete.
//!
//! Detects the filesystem of each volume in a source and dispatches to the
//! appropriate recovery backend ([`crate::fat`], [`crate::exfat`],
//! [`crate::ntfs`], [`crate::ext4`], or [`crate::hfsplus`]), so the `undelete`
//! command can treat every supported filesystem the same way. APFS containers
//! ([`crate::apfs`]) are recognised for reporting but not recovered from
//! metadata — carving (`scan`) is the fallback there.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use crate::source::Source;
use crate::{apfs, exfat, ext4, fat, hfsplus, ntfs};

/// Options controlling a recovery run.
#[derive(Clone, Copy, Default)]
pub struct RecoverOptions {
    /// Ignore deleted files smaller than this many bytes.
    pub min_size: u64,
    /// Report what would be recovered without writing any files.
    pub dry_run: bool,
}

/// One file the recovery considered, for reporting.
pub struct RecoveredFile {
    /// Path relative to the volume root.
    pub path: PathBuf,
    pub size: u64,
    /// Whether the data was successfully recovered (false = skipped/corrupt).
    pub recovered: bool,
    /// SHA-256 of the recovered bytes, when they were written. `None` for
    /// skipped files and for dry runs (where nothing is read or written).
    pub sha256: Option<[u8; 32]>,
}

/// Outcome of recovering deleted files from one volume.
#[derive(Default)]
pub struct RecoverStats {
    pub recovered: u64,
    pub bytes_recovered: u64,
    /// Entries that looked deleted but failed validation (bad cluster/size).
    pub skipped: u64,
    /// Per-file records (populated for the recovery report).
    pub files: Vec<RecoveredFile>,
}

impl RecoverStats {
    /// Record a successfully recovered file. `sha256` is the digest of the
    /// written bytes, or `None` for a dry run.
    pub fn record_recovered(&mut self, path: PathBuf, size: u64, sha256: Option<[u8; 32]>) {
        self.recovered += 1;
        self.bytes_recovered += size;
        self.files.push(RecoveredFile {
            path,
            size,
            recovered: true,
            sha256,
        });
    }

    /// Record a deleted entry that could not be recovered.
    pub fn record_skipped(&mut self, path: PathBuf, size: u64) {
        self.skipped += 1;
        self.files.push(RecoveredFile {
            path,
            size,
            recovered: false,
            sha256: None,
        });
    }
}

/// A detected, recoverable volume of a known filesystem type.
pub enum Volume {
    Fat(fat::Volume),
    Exfat(exfat::Volume),
    Ntfs(ntfs::Volume),
    Ext(ext4::Volume),
    Hfs(hfsplus::Volume),
    Apfs(apfs::Volume),
}

impl Volume {
    /// Byte offset of the volume within the source.
    pub fn offset(&self) -> u64 {
        match self {
            Volume::Fat(v) => v.offset,
            Volume::Exfat(v) => v.offset,
            Volume::Ntfs(v) => v.offset,
            Volume::Ext(v) => v.offset,
            Volume::Hfs(v) => v.offset,
            Volume::Apfs(v) => v.offset,
        }
    }

    /// Total size of the volume in bytes.
    pub fn size(&self) -> u64 {
        match self {
            Volume::Fat(v) => v.size(),
            Volume::Exfat(v) => v.size(),
            Volume::Ntfs(v) => v.size(),
            Volume::Ext(v) => v.size(),
            Volume::Hfs(v) => v.size(),
            Volume::Apfs(v) => v.size(),
        }
    }

    /// Short human-readable filesystem label, e.g. `"FAT16"` or `"exFAT"`.
    pub fn fs_label(&self) -> String {
        match self {
            Volume::Fat(v) => format!("{:?}", v.fat_type),
            Volume::Exfat(_) => "exFAT".to_string(),
            Volume::Ntfs(_) => "NTFS".to_string(),
            Volume::Ext(_) => "ext2/3/4".to_string(),
            Volume::Hfs(v) => v.fs_label().to_string(),
            Volume::Apfs(v) => v.fs_label().to_string(),
        }
    }

    /// Absolute byte ranges of the volume's free (unallocated) space, if this
    /// backend can compute it. Carving only these ranges recovers deleted
    /// content without re-finding files that are still allocated. Returns
    /// `None` for filesystems whose allocation map is not yet parsed.
    pub fn free_extents(&self, src: &Source) -> Option<Vec<(u64, u64)>> {
        match self {
            Volume::Fat(v) => v.free_extents(src).ok(),
            Volume::Exfat(v) => v.free_extents(src).ok(),
            Volume::Ext(v) => v.free_extents(src).ok(),
            _ => None,
        }
    }

    /// Recover all deleted files from this volume into `out_dir`.
    pub fn recover_deleted(
        &self,
        src: &Source,
        out_dir: &Path,
        opts: &RecoverOptions,
    ) -> Result<RecoverStats> {
        match self {
            Volume::Fat(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Exfat(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Ntfs(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Ext(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Hfs(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Apfs(v) => v.recover_deleted(src, out_dir, opts),
        }
    }
}

/// Detect every supported volume in `src`: a bare volume at offset 0, or the
/// volumes referenced by a GPT or legacy MBR partition table.
pub fn detect(src: &Source) -> Result<Vec<Volume>> {
    let mut sector0 = [0u8; 512];
    if src.read_at(0, &mut sector0)? < 512 {
        bail!("source too small to contain a filesystem");
    }

    // 1. A bare filesystem placed directly at offset 0 (no partition table).
    if let Some(v) = try_parse_volume(src, 0)? {
        return Ok(vec![v]);
    }

    // 2. A GUID Partition Table (GPT).
    let gpt = detect_gpt(src)?;
    if !gpt.is_empty() {
        return Ok(gpt);
    }

    // 3. A legacy MBR partition table.
    let mut volumes = Vec::new();
    if sector0[510] == 0x55 && sector0[511] == 0xAA {
        for i in 0..4 {
            let base = 446 + i * 16;
            let lba_start = u32::from_le_bytes([
                sector0[base + 8],
                sector0[base + 9],
                sector0[base + 10],
                sector0[base + 11],
            ]);
            if lba_start == 0 {
                continue;
            }
            if let Some(v) = try_parse_volume(src, lba_start as u64 * 512)? {
                volumes.push(v);
            }
        }
    }

    if volumes.is_empty() {
        bail!("no FAT, exFAT, NTFS, ext2/3/4, HFS+, or APFS volume found");
    }
    Ok(volumes)
}

/// Try to recognise a supported filesystem at `offset`, by signature. Returns
/// `None` if nothing matches (e.g. an empty or unsupported partition).
fn try_parse_volume(src: &Source, offset: u64) -> Result<Option<Volume>> {
    let mut boot = [0u8; 512];
    if src.read_at(offset, &mut boot)? < 512 {
        return Ok(None);
    }
    if exfat::is_exfat_vbr(&boot) {
        if let Ok(v) = exfat::Volume::parse(src, offset) {
            return Ok(Some(Volume::Exfat(v)));
        }
    }
    if ntfs::is_ntfs_vbr(&boot) {
        if let Ok(v) = ntfs::Volume::parse(src, offset) {
            return Ok(Some(Volume::Ntfs(v)));
        }
    }
    if ext4::is_ext_volume(src, offset) {
        if let Ok(v) = ext4::Volume::parse(src, offset) {
            return Ok(Some(Volume::Ext(v)));
        }
    }
    if hfsplus::is_hfsplus(src, offset) {
        if let Ok(v) = hfsplus::Volume::parse(src, offset) {
            return Ok(Some(Volume::Hfs(v)));
        }
    }
    if apfs::is_apfs(src, offset) {
        if let Ok(v) = apfs::Volume::parse(src, offset) {
            return Ok(Some(Volume::Apfs(v)));
        }
    }
    if fat::looks_like_fat_vbr(&boot) {
        if let Ok(v) = fat::Volume::parse(src, offset) {
            return Ok(Some(Volume::Fat(v)));
        }
    }
    Ok(None)
}

/// Detect volumes via a GPT, supporting 512- and 4096-byte logical sectors.
/// Returns an empty vec when the source is not GPT-partitioned.
fn detect_gpt(src: &Source) -> Result<Vec<Volume>> {
    for sector_size in [512u64, 4096] {
        let mut hdr = [0u8; 92];
        if src.read_at(sector_size, &mut hdr)? < 92 {
            continue;
        }
        if &hdr[0..8] != b"EFI PART" {
            continue;
        }
        let entry_lba = u64::from_le_bytes(hdr[72..80].try_into().unwrap());
        let num_entries = u32::from_le_bytes(hdr[80..84].try_into().unwrap()) as u64;
        let entry_size = u32::from_le_bytes(hdr[84..88].try_into().unwrap()) as u64;
        if !(128..=4096).contains(&entry_size) {
            continue;
        }
        let num_entries = num_entries.min(1024); // guard against corruption
        let array_start = match entry_lba.checked_mul(sector_size) {
            Some(v) => v,
            None => continue,
        };

        let mut volumes = Vec::new();
        let mut entry = vec![0u8; entry_size as usize];
        for i in 0..num_entries {
            let off = array_start + i * entry_size;
            if src.read_at(off, &mut entry)? < entry_size as usize {
                break;
            }
            // An all-zero type GUID marks an unused entry.
            if entry[0..16].iter().all(|&b| b == 0) {
                continue;
            }
            let start_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap());
            if start_lba == 0 {
                continue;
            }
            if let Some(v) = try_parse_volume(src, start_lba * sector_size)? {
                volumes.push(v);
            }
        }
        return Ok(volumes);
    }
    Ok(vec![])
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
    if hfsplus::is_hfsplus(src, offset) {
        if let Ok(v) = hfsplus::Volume::parse(src, offset) {
            return Ok(Volume::Hfs(v));
        }
    }
    if apfs::is_apfs(src, offset) {
        if let Ok(v) = apfs::Volume::parse(src, offset) {
            return Ok(Volume::Apfs(v));
        }
    }
    let v = fat::Volume::parse(src, offset)?;
    Ok(Volume::Fat(v))
}
