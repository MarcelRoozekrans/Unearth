//! Detection of UDF (Universal Disk Format) volumes.
//!
//! UDF (ECMA-167 / ISO 13346) is the filesystem of optical media (DVDs,
//! Blu-ray) and is also used on many large USB drives and camcorder cards. Its
//! copy-on-write-ish, descriptor-based metadata is not parsed here, so
//! `filerecovery` does not recover deleted files from UDF directly — but
//! recognising and naming it is useful: a user who images a UDF disc gets a
//! clear answer ("this is UDF — carve it") instead of a bare "no supported
//! volumes" message. Recovery is a no-op; carving (`scan`) is the fallback.
//!
//! Detection uses the **Volume Recognition Sequence**: starting at sector 16
//! (byte offset 32768), UDF places a series of 2048-byte Volume Structure
//! Descriptors, each `{ type: u8, id: [u8; 5], version: u8, ... }`. A UDF volume
//! is identified by an `NSR02`/`NSR03` descriptor (optionally preceded by a
//! `BEA01` beginning marker and an ISO-9660 `CD001` bridge descriptor).

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// The Volume Recognition Sequence begins at sector 16 with 2048-byte sectors.
const VRS_OFFSET: u64 = 16 * 2048;
const VSD_SIZE: u64 = 2048;

/// A recognised UDF volume (not recovered from metadata; carving is the fallback).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
}

/// Recognise a UDF volume at `offset` via its Volume Recognition Sequence.
/// Returns `None` when no `NSR02`/`NSR03` descriptor is present.
pub fn detect(src: &Source, offset: u64) -> Option<Volume> {
    let base = offset.checked_add(VRS_OFFSET)?;
    let mut is_udf = false;
    // Walk the descriptor sequence; stop at the terminator, at a non-VRS
    // descriptor, or after a generous bound.
    for i in 0..16u64 {
        let pos = base.checked_add(i * VSD_SIZE)?;
        let mut d = [0u8; 8];
        if src.read_at(pos, &mut d).ok()? < 8 {
            break;
        }
        match &d[1..6] {
            b"NSR02" | b"NSR03" => {
                is_udf = true; // the definitive UDF marker
            }
            // Other valid Volume Structure Descriptors: keep scanning.
            b"BEA01" | b"BOOT2" | b"CD001" | b"CDW02" => {}
            b"TEA01" => break, // terminating descriptor ends the sequence
            _ => break,        // not a recognition descriptor: sequence ended
        }
    }
    if !is_udf {
        return None;
    }
    let size = src.size.saturating_sub(offset);
    Some(Volume { offset, size })
}

impl Volume {
    /// Parse a UDF volume at `offset`, failing if it is not one.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        match detect(src, offset) {
            Some(v) => Ok(v),
            None => bail!("not a recognised UDF volume"),
        }
    }

    /// Size of the volume in bytes (from its offset to the end of the source).
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Filesystem label.
    pub fn fs_label(&self) -> &'static str {
        "UDF"
    }

    /// UDF metadata is not parsed, so deleted files are not recovered from it;
    /// always returns an empty result so a mixed disk's other volumes still
    /// recover. Carve the volume (`scan`) to recover its contents.
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
        let p = tmp.path().join("u.img");
        std::fs::write(&p, bytes).unwrap();
        (tmp, Source::open(&p).unwrap())
    }

    /// Write a Volume Structure Descriptor with standard identifier `id` at
    /// sector `16 + index` of `v`.
    fn put_vsd(v: &mut [u8], index: u64, id: &[u8; 5]) {
        let off = (VRS_OFFSET + index * VSD_SIZE) as usize;
        v[off + 1..off + 6].copy_from_slice(id);
    }

    #[test]
    fn detects_udf_via_the_recognition_sequence() {
        // 16 sectors of reserved area + a BEA01/NSR03/TEA01 sequence.
        let mut v = vec![0u8; (VRS_OFFSET + 8 * VSD_SIZE) as usize];
        put_vsd(&mut v, 0, b"BEA01");
        put_vsd(&mut v, 1, b"NSR03");
        put_vsd(&mut v, 2, b"TEA01");
        let (_t, src) = source_of(&v);
        let vol = detect(&src, 0).unwrap();
        assert_eq!(vol.fs_label(), "UDF");
        assert_eq!(vol.size(), v.len() as u64);
    }

    #[test]
    fn detects_udf_behind_an_iso9660_bridge() {
        // A CD001 (ISO-9660 bridge) descriptor before the UDF markers.
        let mut v = vec![0u8; (VRS_OFFSET + 8 * VSD_SIZE) as usize];
        put_vsd(&mut v, 0, b"CD001");
        put_vsd(&mut v, 1, b"BEA01");
        put_vsd(&mut v, 2, b"NSR02");
        put_vsd(&mut v, 3, b"TEA01");
        let (_t, src) = source_of(&v);
        assert_eq!(detect(&src, 0).unwrap().fs_label(), "UDF");
    }

    #[test]
    fn rejects_plain_and_iso_only_data() {
        // All zeros: no recognition sequence.
        let (_t, src) = source_of(&vec![0u8; (VRS_OFFSET + 8 * VSD_SIZE) as usize]);
        assert!(detect(&src, 0).is_none());

        // An ISO-9660 disc with no UDF NSR descriptor is not UDF.
        let mut v = vec![0u8; (VRS_OFFSET + 8 * VSD_SIZE) as usize];
        put_vsd(&mut v, 0, b"CD001");
        put_vsd(&mut v, 1, b"TEA01");
        let (_t, src) = source_of(&v);
        assert!(detect(&src, 0).is_none());
    }
}
