//! Detection of ISO 9660 volumes (data CD/DVD discs and `.iso` images).
//!
//! ISO 9660 is the classic optical-disc filesystem. Its directory structure is
//! not parsed here, so `filerecovery` does not extract files from it directly —
//! but recognising and naming it (with its size and volume label) is useful: a
//! user who images a data CD/DVD or opens an `.iso` gets a clear answer ("this
//! is ISO 9660 — carve it") instead of a bare "no supported volumes" message.
//! Recovery is a no-op; carving (`scan`) is the fallback.
//!
//! Detection reads the **Volume Descriptor Set** at sector 16 (byte offset
//! 32768): a series of 2048-byte descriptors each `{ type: u8, id: "CD001",
//! version: u8, ... }`. The **Primary Volume Descriptor** (type 1) carries the
//! volume identifier (label) and the volume size (block count × block size, as
//! both-endian fields). A UDF disc with an ISO bridge is detected as UDF first
//! (it has the additional `NSR` descriptor), so this only claims pure ISO 9660.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// The Volume Descriptor Set begins at sector 16 with 2048-byte sectors.
const VDS_OFFSET: u64 = 16 * 2048;
const VD_SIZE: u64 = 2048;
const PRIMARY: u8 = 1;
const TERMINATOR: u8 = 255;

/// A recognised ISO 9660 volume (not recovered from metadata; carving is the
/// fallback).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
    label: String,
}

/// Recognise an ISO 9660 volume at `offset` by finding its Primary Volume
/// Descriptor. Returns `None` when no `CD001` Primary descriptor is present.
pub fn detect(src: &Source, offset: u64) -> Option<Volume> {
    let base = offset.checked_add(VDS_OFFSET)?;
    for i in 0..16u64 {
        let pos = base.checked_add(i * VD_SIZE)?;
        let mut d = [0u8; 256];
        if src.read_at(pos, &mut d).ok()? < d.len() {
            break;
        }
        if &d[1..6] != b"CD001" {
            break; // not a volume descriptor: the set has ended
        }
        match d[0] {
            PRIMARY => return Some(parse_primary(offset, src, &d)),
            TERMINATOR => break,
            _ => {} // boot record / supplementary: keep scanning for the primary
        }
    }
    None
}

/// Build a [`Volume`] from a Primary Volume Descriptor's bytes.
fn parse_primary(offset: u64, src: &Source, pvd: &[u8]) -> Volume {
    // Volume Space Size (block count) is a both-endian u32 at offset 80; the
    // little-endian half is first. Logical Block Size is a both-endian u16 at
    // offset 128. Total size = block count × block size.
    let blocks = u32::from_le_bytes([pvd[80], pvd[81], pvd[82], pvd[83]]) as u64;
    let block_size = u16::from_le_bytes([pvd[128], pvd[129]]) as u64;
    let computed = blocks.checked_mul(block_size).unwrap_or(0);
    // Fall back to the remaining source if the header values are implausible.
    let size = if computed == 0 {
        src.size.saturating_sub(offset)
    } else {
        computed
    };
    // Volume Identifier: 32 d-characters at offset 40, space/NUL padded.
    let raw = &pvd[40..72];
    let end = raw
        .iter()
        .rposition(|&b| b != b' ' && b != 0)
        .map_or(0, |p| p + 1);
    let label = String::from_utf8_lossy(&raw[..end]).trim().to_string();
    Volume {
        offset,
        size,
        label,
    }
}

impl Volume {
    /// Parse an ISO 9660 volume at `offset`, failing if it is not one.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        match detect(src, offset) {
            Some(v) => Ok(v),
            None => bail!("not a recognised ISO 9660 volume"),
        }
    }

    /// Size of the volume in bytes (block count × block size from the PVD).
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Filesystem label.
    pub fn fs_label(&self) -> &'static str {
        "ISO 9660"
    }

    /// The volume identifier from the Primary Volume Descriptor (may be empty).
    pub fn label(&self) -> &str {
        &self.label
    }

    /// ISO 9660 directory metadata is not parsed, so files are not extracted
    /// from it here; always returns an empty result so a mixed disk's other
    /// volumes still recover. Carve the volume (`scan`) to recover its contents.
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

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("i.img");
        std::fs::write(&p, bytes).unwrap();
        (tmp, Source::open(&p).unwrap())
    }

    /// Write a volume descriptor of `vtype` (with the `CD001` identifier) at
    /// sector `16 + index`, returning a mutable view for further field writes.
    fn put_descriptor(v: &mut [u8], index: u64, vtype: u8) -> usize {
        let off = (VDS_OFFSET + index * VD_SIZE) as usize;
        v[off] = vtype;
        v[off + 1..off + 6].copy_from_slice(b"CD001");
        v[off + 6] = 1;
        off
    }

    #[test]
    fn detects_primary_with_size_and_label() {
        let mut v = vec![0u8; (VDS_OFFSET + 4 * VD_SIZE) as usize];
        let off = put_descriptor(&mut v, 0, PRIMARY);
        // 100 blocks of 2048 bytes = 204800.
        v[off + 80..off + 84].copy_from_slice(&100u32.to_le_bytes());
        v[off + 128..off + 130].copy_from_slice(&2048u16.to_le_bytes());
        v[off + 40..off + 40 + 11].copy_from_slice(b"UBUNTU_2204");

        let (_t, src) = source_of(&v);
        let vol = detect(&src, 0).unwrap();
        assert_eq!(vol.fs_label(), "ISO 9660");
        assert_eq!(vol.size(), 100 * 2048);
        assert_eq!(vol.label(), "UBUNTU_2204");
    }

    #[test]
    fn finds_the_primary_after_a_boot_record() {
        let mut v = vec![0u8; (VDS_OFFSET + 4 * VD_SIZE) as usize];
        put_descriptor(&mut v, 0, 0); // boot record (type 0)
        let off = put_descriptor(&mut v, 1, PRIMARY);
        v[off + 80..off + 84].copy_from_slice(&10u32.to_le_bytes());
        v[off + 128..off + 130].copy_from_slice(&2048u16.to_le_bytes());
        let (_t, src) = source_of(&v);
        assert_eq!(detect(&src, 0).unwrap().size(), 10 * 2048);
    }

    #[test]
    fn rejects_non_iso_data() {
        let (_t, src) = source_of(&vec![0u8; (VDS_OFFSET + 4 * VD_SIZE) as usize]);
        assert!(detect(&src, 0).is_none());
        assert!(Volume::parse(&src, 0).is_err());
    }
}
