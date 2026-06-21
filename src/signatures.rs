//! Known file-type signatures and the strategy used to find where each
//! recovered file ends.
//!
//! Carving works by locating a *header* (a magic byte sequence) on the raw
//! device, then determining the file's length with one of a few strategies:
//!
//! * [`Extent::Footer`] — scan forward for a trailing marker (JPEG, PNG, ...).
//! * [`Extent::HeaderSizeLe32`] — read a little-endian u32 size field from the
//!   header itself (BMP).
//! * [`Extent::Mp4Atoms`] — walk the ISO base-media box/atom structure (MP4,
//!   MOV, M4A, ...).
//!
//! Adding a new file type is just a matter of appending a [`Signature`] to
//! [`SIGNATURES`].

/// How to determine the length of a carved file once its header is found.
#[derive(Clone, Copy, Debug)]
pub enum Extent {
    /// Search forward for `marker`; the file ends `trailing` bytes after the
    /// end of the marker.
    Footer {
        marker: &'static [u8],
        trailing: u64,
    },
    /// The total file size is stored as a little-endian u32 at `offset` bytes
    /// into the file (relative to the file start).
    HeaderSizeLe32 { offset: usize },
    /// Parse the ISO base-media (MP4/QuickTime) box structure to sum atoms.
    Mp4Atoms,
}

/// A recoverable file type.
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    /// Human-readable name, e.g. `"JPEG image"`.
    pub name: &'static str,
    /// Output file extension (without the dot), e.g. `"jpg"`.
    pub ext: &'static str,
    /// Magic bytes that identify the type.
    pub magic: &'static [u8],
    /// Where the magic appears relative to the start of the file. This is `0`
    /// for most formats but `4` for MP4/MOV where the `ftyp` marker follows a
    /// 4-byte box-size field.
    pub magic_offset: u64,
    /// Strategy used to compute the file length.
    pub extent: Extent,
    /// Hard cap on carved size; protects against runaway files when an end
    /// marker is missing or corrupt.
    pub max_size: u64,
}

const KB: u64 = 1024;
const MB: u64 = 1024 * KB;
const GB: u64 = 1024 * MB;

/// The built-in signature table.
pub static SIGNATURES: &[Signature] = &[
    Signature {
        name: "JPEG image",
        ext: "jpg",
        magic: &[0xFF, 0xD8, 0xFF],
        magic_offset: 0,
        extent: Extent::Footer {
            marker: &[0xFF, 0xD9],
            trailing: 0,
        },
        max_size: 50 * MB,
    },
    Signature {
        name: "PNG image",
        ext: "png",
        magic: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        magic_offset: 0,
        extent: Extent::Footer {
            // IEND chunk: length(0) + "IEND" + CRC
            marker: &[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82],
            trailing: 0,
        },
        max_size: 100 * MB,
    },
    Signature {
        name: "GIF image (89a)",
        ext: "gif",
        magic: b"GIF89a",
        magic_offset: 0,
        extent: Extent::Footer {
            marker: &[0x00, 0x3B],
            trailing: 0,
        },
        max_size: 30 * MB,
    },
    Signature {
        name: "GIF image (87a)",
        ext: "gif",
        magic: b"GIF87a",
        magic_offset: 0,
        extent: Extent::Footer {
            marker: &[0x00, 0x3B],
            trailing: 0,
        },
        max_size: 30 * MB,
    },
    Signature {
        name: "BMP image",
        ext: "bmp",
        magic: b"BM",
        magic_offset: 0,
        // Total file size is a LE u32 at offset 2.
        extent: Extent::HeaderSizeLe32 { offset: 2 },
        max_size: 100 * MB,
    },
    Signature {
        name: "PDF document",
        ext: "pdf",
        magic: b"%PDF",
        magic_offset: 0,
        extent: Extent::Footer {
            marker: b"%%EOF",
            trailing: 2, // allow a trailing CR/LF
        },
        max_size: 500 * MB,
    },
    Signature {
        name: "ZIP archive (also DOCX/XLSX/PPTX/ODT/JAR/APK)",
        ext: "zip",
        magic: &[0x50, 0x4B, 0x03, 0x04],
        magic_offset: 0,
        extent: Extent::Footer {
            // End of central directory record.
            marker: &[0x50, 0x4B, 0x05, 0x06],
            trailing: 18, // minimal EOCD is 22 bytes (4 marker + 18); ignores any comment
        },
        max_size: 2 * GB,
    },
    Signature {
        name: "MP4/MOV/M4A media",
        ext: "mp4",
        magic: b"ftyp",
        magic_offset: 4, // preceded by a 4-byte box size
        extent: Extent::Mp4Atoms,
        max_size: 4 * GB,
    },
];

/// Look up signatures relevant to a single source byte, keyed by the first
/// byte of their magic *as it appears on disk*. The on-disk first byte is the
/// first byte of `magic` (because `magic_offset` shifts the file start
/// backward, not the magic position).
pub struct SignatureIndex {
    /// For each possible leading byte, the signatures whose magic starts with
    /// it. Most slots are empty, keeping per-byte work tiny.
    by_first_byte: [Vec<&'static Signature>; 256],
    /// Largest number of bytes we must look ahead to confirm any magic.
    pub max_magic_len: usize,
}

impl SignatureIndex {
    pub fn build(active: &[&'static Signature]) -> Self {
        // `Vec` is not `Copy`, so build the array element by element.
        let by_first_byte: [Vec<&'static Signature>; 256] = std::array::from_fn(|_| Vec::new());
        let mut idx = SignatureIndex {
            by_first_byte,
            max_magic_len: 0,
        };
        for sig in active {
            let first = sig.magic[0] as usize;
            idx.by_first_byte[first].push(sig);
            idx.max_magic_len = idx.max_magic_len.max(sig.magic.len());
        }
        idx
    }

    /// Return the signature whose magic matches the bytes starting at `window`,
    /// if any. `window` must begin at the on-disk position of a candidate magic.
    pub fn match_at(&self, window: &[u8]) -> Option<&'static Signature> {
        let first = *window.first()? as usize;
        for sig in &self.by_first_byte[first] {
            if window.len() >= sig.magic.len() && &window[..sig.magic.len()] == sig.magic {
                return Some(sig);
            }
        }
        None
    }
}

/// Resolve user-requested type names (extensions or `"all"`) to signatures.
///
/// Returns an error listing the offending name if one is unknown.
pub fn select(types: &[String]) -> anyhow::Result<Vec<&'static Signature>> {
    if types.is_empty() || types.iter().any(|t| t.eq_ignore_ascii_case("all")) {
        return Ok(SIGNATURES.iter().collect());
    }
    let mut selected = Vec::new();
    for t in types {
        let matches: Vec<&'static Signature> = SIGNATURES
            .iter()
            .filter(|s| s.ext.eq_ignore_ascii_case(t))
            .collect();
        if matches.is_empty() {
            let known: Vec<&str> = SIGNATURES.iter().map(|s| s.ext).collect();
            anyhow::bail!("unknown file type '{t}'. Known types: {}", known.join(", "));
        }
        selected.extend(matches);
    }
    Ok(selected)
}
