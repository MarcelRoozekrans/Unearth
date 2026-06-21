//! Lightweight structural validation of carved files.
//!
//! Signature carving matches only a handful of magic bytes, so a magic that
//! occurs by coincidence inside unrelated data produces a bogus "file". These
//! validators inspect a recovered file's header for the fixed structural fields
//! the format guarantees and reject candidates that cannot be real.
//!
//! They are deliberately **conservative**: a check returns [`Validity::Invalid`]
//! only on a definite structural violation, and returns [`Validity::Unknown`]
//! (which the carver accepts) whenever there is not enough data or no validator
//! exists for the type. The goal is to drop obvious garbage without ever
//! discarding a genuine file.

use crate::signatures::Signature;

/// Verdict for a carved file's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    /// The header matches the format's fixed structure.
    Valid,
    /// The header violates the format; the magic match is almost certainly
    /// coincidental.
    Invalid,
    /// Not enough information to decide. Treated as acceptable.
    Unknown,
}

impl Validity {
    /// Whether the carver should keep a file with this verdict. Only a definite
    /// [`Validity::Invalid`] is rejected.
    pub fn accept(self) -> bool {
        !matches!(self, Validity::Invalid)
    }
}

/// Number of leading bytes the validators need to inspect. The carver reads at
/// most this many bytes of each candidate before deciding.
pub const HEADER_LEN: usize = 64;

/// Validate the leading bytes of a carved file of type `sig`.
///
/// `data` holds up to [`HEADER_LEN`] bytes from the start of the candidate file
/// (fewer if the file is shorter).
pub fn validate(sig: &Signature, data: &[u8]) -> Validity {
    match sig.ext {
        "jpg" => jpeg(data),
        "png" => png(data),
        "gif" => gif(data),
        "bmp" => bmp(data),
        "sqlite" => sqlite(data),
        // No structural check for the remaining types; their length strategy
        // (footer search, atom walk, etc.) already rejects most spurious hits.
        _ => Validity::Unknown,
    }
}

/// JPEG: the SOI magic `FF D8 FF` is immediately followed by a marker code. A
/// real stream's first marker is an APPn/DQT/DHT/COM/SOFn — never padding
/// (`0xFF`), a stuffed zero (`0x00`), or another SOI/EOI.
fn jpeg(d: &[u8]) -> Validity {
    if d.len() < 4 {
        return Validity::Unknown;
    }
    let marker = d[3];
    if (0xC0..=0xFE).contains(&marker) && marker != 0xD8 && marker != 0xD9 {
        Validity::Valid
    } else {
        Validity::Invalid
    }
}

/// PNG: the 8-byte signature must be followed by an `IHDR` chunk — a length of
/// exactly 13, the `IHDR` type, then non-zero width and height (big-endian).
fn png(d: &[u8]) -> Validity {
    if d.len() < 24 {
        return Validity::Unknown;
    }
    if u32::from_be_bytes([d[8], d[9], d[10], d[11]]) != 13 || &d[12..16] != b"IHDR" {
        return Validity::Invalid;
    }
    let w = u32::from_be_bytes([d[16], d[17], d[18], d[19]]);
    let h = u32::from_be_bytes([d[20], d[21], d[22], d[23]]);
    if w == 0 || h == 0 {
        return Validity::Invalid;
    }
    Validity::Valid
}

/// GIF: after the 6-byte `GIF87a`/`GIF89a` header comes the logical screen
/// descriptor, whose canvas width and height (little-endian) are non-zero.
fn gif(d: &[u8]) -> Validity {
    if d.len() < 10 {
        return Validity::Unknown;
    }
    let w = u16::from_le_bytes([d[6], d[7]]);
    let h = u16::from_le_bytes([d[8], d[9]]);
    if w == 0 || h == 0 {
        return Validity::Invalid;
    }
    Validity::Valid
}

/// BMP: past the 14-byte file header sits the DIB header, whose first field is
/// its own size — one of a small set of standard values.
fn bmp(d: &[u8]) -> Validity {
    if d.len() < 18 {
        return Validity::Unknown;
    }
    // BITMAPCOREHEADER(12), BITMAPINFOHEADER(40), V2(52), V3(56), V4(108), V5(124).
    const KNOWN: [u32; 6] = [12, 40, 52, 56, 108, 124];
    let dib = u32::from_le_bytes([d[14], d[15], d[16], d[17]]);
    if KNOWN.contains(&dib) {
        Validity::Valid
    } else {
        Validity::Invalid
    }
}

/// SQLite: the database header has several bytes fixed by the file format —
/// the read/write format versions are 1 or 2, and the payload fractions are the
/// constants 64/32/32. A coincidental "SQLite format 3\0" almost never has all
/// of these right.
fn sqlite(d: &[u8]) -> Validity {
    if d.len() < 24 {
        return Validity::Unknown;
    }
    let write_ver = d[18];
    let read_ver = d[19];
    if !(1..=2).contains(&write_ver) || !(1..=2).contains(&read_ver) {
        return Validity::Invalid;
    }
    if d[21] != 64 || d[22] != 32 || d[23] != 32 {
        return Validity::Invalid;
    }
    Validity::Valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::{select, Signature};

    fn sig(ext: &str) -> &'static Signature {
        let all = select(&[]).unwrap();
        all.into_iter().find(|s| s.ext == ext).unwrap()
    }

    #[test]
    fn jpeg_marker_check() {
        assert_eq!(
            validate(sig("jpg"), &[0xFF, 0xD8, 0xFF, 0xE0]),
            Validity::Valid
        );
        assert_eq!(
            validate(sig("jpg"), &[0xFF, 0xD8, 0xFF, 0xDB]),
            Validity::Valid
        );
        // 0x00, padding 0xFF, and a stray SOI/EOI are all bogus first markers.
        assert_eq!(
            validate(sig("jpg"), &[0xFF, 0xD8, 0xFF, 0x00]),
            Validity::Invalid
        );
        assert_eq!(
            validate(sig("jpg"), &[0xFF, 0xD8, 0xFF, 0xFF]),
            Validity::Invalid
        );
        assert_eq!(
            validate(sig("jpg"), &[0xFF, 0xD8, 0xFF, 0xD9]),
            Validity::Invalid
        );
        // Too short to judge => accepted.
        assert_eq!(validate(sig("jpg"), &[0xFF, 0xD8]), Validity::Unknown);
    }

    #[test]
    fn png_ihdr_check() {
        let mut good = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        good.extend_from_slice(&13u32.to_be_bytes());
        good.extend_from_slice(b"IHDR");
        good.extend_from_slice(&64u32.to_be_bytes()); // width
        good.extend_from_slice(&64u32.to_be_bytes()); // height
        assert_eq!(validate(sig("png"), &good), Validity::Valid);

        // Random bytes where IHDR should be => rejected.
        let mut bad = good.clone();
        bad[12..16].copy_from_slice(b"junk");
        assert_eq!(validate(sig("png"), &bad), Validity::Invalid);

        // Zero dimensions => rejected.
        let mut zero = good.clone();
        zero[16..20].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(validate(sig("png"), &zero), Validity::Invalid);
    }

    #[test]
    fn bmp_dib_size_check() {
        let mut v = vec![b'B', b'M'];
        v.extend_from_slice(&100u32.to_le_bytes()); // file size
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved
        v.extend_from_slice(&54u32.to_le_bytes()); // pixel offset
        v.extend_from_slice(&40u32.to_le_bytes()); // DIB header size
        assert_eq!(validate(sig("bmp"), &v), Validity::Valid);

        let mut bad = v.clone();
        bad[14..18].copy_from_slice(&999u32.to_le_bytes());
        assert_eq!(validate(sig("bmp"), &bad), Validity::Invalid);
    }

    #[test]
    fn sqlite_fixed_fields_check() {
        let mut v = vec![0u8; 24];
        v[0..16].copy_from_slice(b"SQLite format 3\0");
        v[18] = 1;
        v[19] = 1;
        v[21] = 64;
        v[22] = 32;
        v[23] = 32;
        assert_eq!(validate(sig("sqlite"), &v), Validity::Valid);

        // All-zero fixed fields (a coincidental magic) => rejected.
        let mut bad = v.clone();
        bad[21] = 0;
        assert_eq!(validate(sig("sqlite"), &bad), Validity::Invalid);
    }

    #[test]
    fn unknown_types_accepted() {
        assert_eq!(validate(sig("pdf"), b"%PDF-1.7 garbage"), Validity::Unknown);
        assert_eq!(
            validate(sig("zip"), &[0x50, 0x4B, 0x03, 0x04]),
            Validity::Unknown
        );
    }
}
