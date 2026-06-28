//! Detection of full-disk-encryption containers (LUKS and BitLocker).
//!
//! These volumes hold no readable filesystem until they are unlocked with the
//! correct key, so `filerecovery` cannot recover from them directly. Detecting
//! and naming them is still useful: a user who points the tool at an encrypted
//! disk gets a clear answer ("this is LUKS / BitLocker — unlock it first with
//! `cryptsetup` / Windows, then image the mapped device") instead of a bare
//! "no supported volumes" message. Recovery is a no-op here; carving the raw
//! container only yields ciphertext.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// LUKS magic (`"LUKS\xBA\xBE"`) at the start of the header.
const LUKS_MAGIC: &[u8; 6] = b"LUKS\xba\xbe";
/// BitLocker volumes carry the OEM ID `"-FVE-FS-"` at offset 3 of the boot
/// sector (where a plain NTFS/FAT volume carries its own OEM string).
const FVE_OEM: &[u8; 8] = b"-FVE-FS-";
/// `uuid[40]` — an ASCII, NUL-terminated UUID at offset 0xA8 of both the LUKS1
/// and LUKS2 on-disk headers.
const LUKS_UUID_OFFSET: usize = 0xA8;
/// `label[48]` — an ASCII, NUL-terminated label at offset 24 of the LUKS2 header
/// (LUKS1 has the cipher name there instead, so it is read only for LUKS2).
const LUKS2_LABEL_OFFSET: usize = 24;
/// Read enough of the header to cover the UUID (ends at 0xD0).
const HEADER_LEN: usize = LUKS_UUID_OFFSET + 40;

/// A recognised encrypted container (not recoverable without the key).
pub struct Volume {
    /// Byte offset of the container within the source.
    pub offset: u64,
    kind: &'static str,
    size: u64,
    /// LUKS UUID, when present. `None` for BitLocker or a truncated header.
    uuid: Option<String>,
    /// LUKS2 label, empty when unset or not LUKS2.
    label: String,
}

/// Extract a NUL-terminated ASCII field, trimmed; `None` when empty.
fn ascii_field(raw: &[u8]) -> Option<String> {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let s = String::from_utf8_lossy(&raw[..end]).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Recognise a LUKS or BitLocker container at `offset`. Returns `None` when the
/// bytes match neither.
pub fn detect(src: &Source, offset: u64) -> Option<Volume> {
    let mut hdr = [0u8; HEADER_LEN];
    let n = src.read_at(offset, &mut hdr).ok()?;
    if n < 16 {
        return None;
    }
    let kind = if &hdr[0..6] == LUKS_MAGIC {
        // LUKS version is a big-endian u16 at offset 6.
        match u16::from_be_bytes([hdr[6], hdr[7]]) {
            1 => "LUKS1",
            2 => "LUKS2",
            _ => "LUKS",
        }
    } else if &hdr[3..11] == FVE_OEM {
        "BitLocker"
    } else {
        return None;
    };
    let is_luks = kind.starts_with("LUKS");
    let uuid = if is_luks && n >= HEADER_LEN {
        ascii_field(&hdr[LUKS_UUID_OFFSET..LUKS_UUID_OFFSET + 40])
    } else {
        None
    };
    let label = if kind == "LUKS2" && n >= LUKS2_LABEL_OFFSET + 48 {
        ascii_field(&hdr[LUKS2_LABEL_OFFSET..LUKS2_LABEL_OFFSET + 48]).unwrap_or_default()
    } else {
        String::new()
    };
    // The ciphertext fills the container from here to the end of the source
    // (for a bare device or a partition that the encryption fills).
    let size = src.size.saturating_sub(offset);
    Some(Volume {
        offset,
        kind,
        size,
        uuid,
        label,
    })
}

impl Volume {
    /// Parse an encrypted container at `offset`, failing if it is not one.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        match detect(src, offset) {
            Some(v) => Ok(v),
            None => bail!("not a recognised encrypted container"),
        }
    }

    /// Size of the encrypted container in bytes (from its offset to the end of
    /// the source).
    pub fn size(&self) -> u64 {
        self.size
    }

    /// `"LUKS1"`, `"LUKS2"`, or `"BitLocker"`.
    pub fn fs_label(&self) -> &'static str {
        self.kind
    }

    /// The LUKS UUID (the value `cryptsetup luksUUID` / `blkid` show), or `None`
    /// for BitLocker.
    pub fn uuid(&self) -> Option<String> {
        self.uuid.clone()
    }

    /// The LUKS2 label, or an empty string when unset / not LUKS2.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Recovery is not possible without the decryption key; always returns an
    /// empty result so a mixed disk's other volumes still recover. Unlock the
    /// container first (`cryptsetup open`, or Windows for BitLocker), then image
    /// and recover from the mapped plaintext device.
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
        let p = tmp.path().join("e.img");
        std::fs::write(&p, bytes).unwrap();
        (tmp, Source::open(&p).unwrap())
    }

    #[test]
    fn detects_luks1_and_luks2() {
        let uuid = "cafe1234-5678-90ab-cdef-001122334455";
        let mut v = vec![0u8; 4096];
        v[0..6].copy_from_slice(LUKS_MAGIC);
        v[6..8].copy_from_slice(&1u16.to_be_bytes());
        v[LUKS_UUID_OFFSET..LUKS_UUID_OFFSET + uuid.len()].copy_from_slice(uuid.as_bytes());
        let (_t, src) = source_of(&v);
        let vol = detect(&src, 0).unwrap();
        assert_eq!(vol.fs_label(), "LUKS1");
        assert_eq!(vol.uuid().as_deref(), Some(uuid));
        assert_eq!(vol.label(), ""); // LUKS1 has no label field

        v[6..8].copy_from_slice(&2u16.to_be_bytes());
        v[LUKS2_LABEL_OFFSET..LUKS2_LABEL_OFFSET + 7].copy_from_slice(b"backups");
        let (_t, src) = source_of(&v);
        let vol = detect(&src, 0).unwrap();
        assert_eq!(vol.fs_label(), "LUKS2");
        assert_eq!(vol.size(), 4096);
        assert_eq!(vol.uuid().as_deref(), Some(uuid));
        assert_eq!(vol.label(), "backups");
    }

    #[test]
    fn bitlocker_has_no_uuid() {
        let mut v = vec![0u8; 4096];
        v[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        v[3..11].copy_from_slice(FVE_OEM);
        let (_t, src) = source_of(&v);
        let vol = detect(&src, 0).unwrap();
        assert_eq!(vol.fs_label(), "BitLocker");
        assert_eq!(vol.uuid(), None);
    }

    #[test]
    fn detects_bitlocker() {
        let mut v = vec![0u8; 4096];
        v[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]); // a boot-sector jump
        v[3..11].copy_from_slice(FVE_OEM);
        let (_t, src) = source_of(&v);
        assert_eq!(detect(&src, 0).unwrap().fs_label(), "BitLocker");
    }

    #[test]
    fn rejects_plain_data() {
        let (_t, src) = source_of(&vec![0u8; 4096]);
        assert!(detect(&src, 0).is_none());
        assert!(Volume::parse(&src, 0).is_err());
    }
}
