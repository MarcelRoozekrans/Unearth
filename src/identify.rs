//! Content-based file-type identification.
//!
//! Recovered files — especially carved ones — may have a generic or wrong
//! extension. This matches a file's leading bytes against the same signature
//! table and structural validators the carver uses, so an unknown blob can be
//! identified by content. It is deterministic (no model), and reuses
//! [`crate::signatures`] and [`crate::validate`].

use crate::signatures::SIGNATURES;
use crate::validate::{self, Validity};

/// A detected file type.
pub struct Detected {
    /// File-type extension, e.g. `"jpg"`.
    pub ext: &'static str,
    /// Human-readable type name.
    pub name: &'static str,
    /// True when a structural validator confirmed the header (not just the
    /// magic). False means the type has no validator, so it was matched by
    /// magic (and any secondary tag) alone.
    pub validated: bool,
}

/// Identify the type of a file from its leading bytes, or `None` if no known
/// signature matches. Tries signatures in table order (most specific first) and
/// skips any whose structural validator rejects the header outright.
pub fn identify(head: &[u8]) -> Option<Detected> {
    for sig in SIGNATURES {
        let off = sig.magic_offset as usize;
        let end = off + sig.magic.len();
        if head.len() < end || &head[off..end] != sig.magic {
            continue;
        }
        if let Some((soff, tag)) = sig.secondary {
            let start = off + soff;
            if head.len() < start + tag.len() || &head[start..start + tag.len()] != tag {
                continue;
            }
        }
        // Validators read from the start of the file (offset 0).
        let validity = validate::validate(sig, head);
        if validity == Validity::Invalid {
            continue; // magic matched but the header is structurally wrong
        }
        // A ZIP may actually be a DOCX/EPUB/APK/…; refine it from its content so
        // identify matches what the carver names the file.
        let (ext, name) = if sig.ext == "zip" {
            crate::signatures::classify_zip(head).unwrap_or((sig.ext, sig.name))
        } else {
            (sig.ext, sig.name)
        };
        return Some(Detected {
            ext,
            name,
            validated: validity == Validity::Valid,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_validated_types() {
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0, 0];
        let d = identify(&jpeg).unwrap();
        assert_eq!(d.ext, "jpg");
        assert!(d.validated, "jpeg has a validator");
    }

    #[test]
    fn identifies_magic_only_types() {
        // ZIP has no structural validator; matched by magic, validated = false.
        let zip = [0x50, 0x4B, 0x03, 0x04, 0, 0];
        let d = identify(&zip).unwrap();
        assert_eq!(d.ext, "zip");
        assert!(!d.validated);
    }

    #[test]
    fn refines_a_zip_into_its_subtype() {
        // A ZIP carrying the DOCX marker member is identified as docx, not zip.
        let mut docx = vec![0x50, 0x4B, 0x03, 0x04];
        docx.extend_from_slice(b"word/document.xml");
        let d = identify(&docx).unwrap();
        assert_eq!(d.ext, "docx");
        // A ZIP with no marker stays a plain zip.
        let zip = [0x50, 0x4B, 0x03, 0x04, b'x', b'y'];
        assert_eq!(identify(&zip).unwrap().ext, "zip");
    }

    #[test]
    fn rejects_bad_header_for_validated_type() {
        // JPEG magic but an impossible first marker (0x00) => not identified as jpg.
        let fake = [0xFF, 0xD8, 0xFF, 0x00, 0, 0];
        assert!(identify(&fake).is_none());
    }

    #[test]
    fn secondary_tag_picks_the_right_riff() {
        let wav = b"RIFF\0\0\0\0WAVE";
        assert_eq!(identify(wav).unwrap().ext, "wav");
        let webp = b"RIFF\0\0\0\0WEBP";
        assert_eq!(identify(webp).unwrap().ext, "webp");
    }

    #[test]
    fn unknown_bytes_are_unidentified() {
        assert!(identify(b"not a known file").is_none());
        assert!(identify(b"").is_none());
    }
}
