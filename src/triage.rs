//! Triage a directory of recovered files into a compact summary: how many of
//! each type, the largest files, content duplicates, and empties.
//!
//! This is deterministic (no model needed); it gives an AI agent — or a person
//! — the shape of a recovery run to reason over without reading every file. It
//! streams each file through SHA-256 so duplicate detection bounds memory.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::hash::Sha256;

/// Per-extension tally.
#[derive(Default, Clone, Copy)]
pub struct TypeStat {
    pub count: u64,
    pub bytes: u64,
}

/// A file whose detected content type doesn't match its extension — a sign of a
/// renamed/disguised file (or a recovery mislabel).
pub struct Mismatch {
    /// Path relative to the triaged directory.
    pub path: String,
    /// The file's extension (lower-cased), e.g. `jpg`.
    pub claimed: String,
    /// The type detected from the content, e.g. `exe`.
    pub detected: String,
}

/// A file whose extension names a type with a known magic signature, but whose
/// content matches no signature at all — a truncated or corrupted header (or a
/// mislabel of an unidentifiable blob).
pub struct Corrupt {
    /// Path relative to the triaged directory.
    pub path: String,
    /// The file's extension (lower-cased), e.g. `jpg`.
    pub claimed: String,
}

/// The result of triaging a directory.
#[derive(Default)]
pub struct Summary {
    pub total_files: u64,
    pub total_bytes: u64,
    /// Count and total bytes per lower-cased extension (`""` = no extension).
    pub by_type: BTreeMap<String, TypeStat>,
    /// The largest files as `(relative path, size)`, biggest first.
    pub largest: Vec<(String, u64)>,
    /// Files of zero length.
    pub empty_files: u64,
    /// Number of content groups (by SHA-256) with more than one file.
    pub duplicate_sets: u64,
    /// Bytes that are redundant copies (sum over groups of size × (count − 1)).
    pub duplicate_bytes: u64,
    /// Files whose content type doesn't match their extension.
    pub mismatches: Vec<Mismatch>,
    /// Files whose extension names a known type but whose content matches no
    /// signature — likely truncated or corrupted.
    pub corrupt: Vec<Corrupt>,
}

impl Summary {
    /// Roll the per-extension tallies up into per-category tallies (`image`,
    /// `audio`, …; unknown extensions fall under `other`). Categories with no
    /// files are omitted. The keys are sorted for stable output.
    pub fn by_category(&self) -> BTreeMap<&'static str, TypeStat> {
        let mut out: BTreeMap<&'static str, TypeStat> = BTreeMap::new();
        for (ext, st) in &self.by_type {
            let cat = crate::signatures::category_of(ext).as_str();
            let entry = out.entry(cat).or_default();
            entry.count += st.count;
            entry.bytes = entry.bytes.saturating_add(st.bytes);
        }
        out
    }
}

/// Walk `dir` recursively and summarize the files under it. `top_n` bounds the
/// `largest` list.
pub fn summarize(dir: &Path, top_n: usize) -> Result<Summary> {
    let mut files = Vec::new();
    collect(dir, &mut files)?;

    let mut summary = Summary::default();
    // digest -> (count, size) for duplicate detection.
    let mut by_digest: BTreeMap<[u8; 32], (u64, u64)> = BTreeMap::new();
    let mut sized: Vec<(String, u64)> = Vec::new();

    for path in &files {
        let (size, digest, head) = hash_file(path)?;
        summary.total_files += 1;
        summary.total_bytes = summary.total_bytes.saturating_add(size);
        if size == 0 {
            summary.empty_files += 1;
        }

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .unwrap_or_default();

        let rel = path
            .strip_prefix(dir)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned();

        // Compare the file's content with the type its extension claims: flag a
        // type mismatch (content is a different known type) or a corrupt file
        // (extension names a signatured type but the content matches nothing).
        // Empty files are reported separately, so skip the content check there.
        if !head.is_empty() {
            match classify_content(&ext, &head) {
                Content::Mismatch(detected) => summary.mismatches.push(Mismatch {
                    path: rel.clone(),
                    claimed: ext.clone(),
                    detected,
                }),
                Content::Corrupt => summary.corrupt.push(Corrupt {
                    path: rel.clone(),
                    claimed: ext.clone(),
                }),
                Content::Ok => {}
            }
        }

        let stat = summary.by_type.entry(ext).or_default();
        stat.count += 1;
        stat.bytes = stat.bytes.saturating_add(size);

        let entry = by_digest.entry(digest).or_insert((0, size));
        entry.0 += 1;

        sized.push((rel, size));
    }

    for (count, size) in by_digest.values() {
        if *count > 1 {
            summary.duplicate_sets += 1;
            summary.duplicate_bytes = summary
                .duplicate_bytes
                .saturating_add(size.saturating_mul(count - 1));
        }
    }

    sized.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    sized.truncate(top_n);
    summary.largest = sized;

    Ok(summary)
}

/// Collect every file (not directory) under `dir`, recursively.
fn collect(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

/// Stream a file through SHA-256, returning its size, digest, and a copy of the
/// leading bytes (the first chunk, up to 64 KiB) for content identification.
fn hash_file(path: &Path) -> Result<(u64, [u8; 32], Vec<u8>)> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut size = 0u64;
    let mut head = Vec::new();
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if head.is_empty() {
            head.extend_from_slice(&buf[..n]); // the first chunk is enough
        }
        size += n as u64;
        hasher.update(&buf[..n]);
    }
    Ok((size, hasher.finalize(), head))
}

/// How a file's content compares with the type its extension claims.
enum Content {
    /// Not a verifiable type, or the content matches the extension — no issue.
    Ok,
    /// Content identifies as a *different* known type (the detected extension).
    Mismatch(String),
    /// The extension names a type with a known magic signature, but the content
    /// matches no signature — a truncated/corrupted header (or a mislabel).
    Corrupt,
}

/// Classify a file by comparing its leading bytes with the type its extension
/// claims. Common aliases (`jpeg`→`jpg`, `mov`→`mp4`, …) are normalised first.
/// Extensions we don't recognise are never flagged, so generic blobs and
/// unknown formats produce no noise. A *mismatch* (different known type) is
/// reported for any recognised category; a *corrupt* verdict is reserved for
/// extensions with a direct magic signature, so unidentifiable-but-plausible
/// container subtypes (`docx`, `msg`, …) aren't called corrupt.
fn classify_content(claimed_ext: &str, head: &[u8]) -> Content {
    use crate::signatures::{category_of, has_signature, Category};
    let canon = canonical_ext(claimed_ext);
    let known = category_of(canon) != Category::Other;
    let signatured = has_signature(canon);
    if !known && !signatured {
        return Content::Ok; // not a type we can verify from content
    }
    match crate::identify::identify(head) {
        Some(d) if d.ext == canon => Content::Ok,
        Some(d) if known => Content::Mismatch(d.ext.to_string()),
        Some(_) => Content::Ok,
        None if signatured => Content::Corrupt,
        None => Content::Ok,
    }
}

/// Normalise common extension aliases to the canonical signature extension, so
/// `photo.jpeg` or `clip.mov` aren't flagged against `jpg` / `mp4`.
fn canonical_ext(ext: &str) -> &str {
    match ext {
        "jpeg" | "jpe" | "jfif" => "jpg",
        "tiff" => "tif",
        "mov" | "m4v" | "m4a" | "m4b" | "qt" => "mp4",
        "aif" => "aiff",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_types_sizes_and_duplicates() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        std::fs::write(dir.join("a.jpg"), vec![1u8; 100]).unwrap();
        std::fs::write(dir.join("b.jpg"), vec![2u8; 300]).unwrap();
        std::fs::write(dir.join("c.png"), vec![3u8; 50]).unwrap();
        std::fs::write(dir.join("empty.bin"), b"").unwrap();
        // A nested duplicate of a.jpg (same content).
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/dup.jpg"), vec![1u8; 100]).unwrap();

        let sum = summarize(dir, 3).unwrap();
        assert_eq!(sum.total_files, 5);
        assert_eq!(sum.total_bytes, 100 + 300 + 50 + 100); // plus one empty file
        assert_eq!(sum.empty_files, 1);

        let jpg = sum.by_type.get("jpg").unwrap();
        assert_eq!(jpg.count, 3); // a, b, dup
        assert_eq!(jpg.bytes, 500);
        assert_eq!(sum.by_type.get("png").unwrap().count, 1);

        // The jpg and png tallies roll up under the "image" category; the empty
        // .bin is an unknown type and lands in "other".
        let by_cat = sum.by_category();
        let image = by_cat.get("image").unwrap();
        assert_eq!(image.count, 4); // 3 jpg + 1 png
        assert_eq!(image.bytes, 550);
        assert_eq!(by_cat.get("other").unwrap().count, 1); // empty.bin

        // a.jpg and sub/dup.jpg share content => one duplicate set, 100 wasted.
        assert_eq!(sum.duplicate_sets, 1);
        assert_eq!(sum.duplicate_bytes, 100);

        // Largest first, capped at 3.
        assert_eq!(sum.largest.len(), 3);
        assert_eq!(sum.largest[0].1, 300);
    }

    #[test]
    fn empty_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let sum = summarize(tmp.path(), 10).unwrap();
        assert_eq!(sum.total_files, 0);
        assert_eq!(sum.duplicate_sets, 0);
        assert!(sum.largest.is_empty());
    }

    /// A minimal valid JPEG (SOI + APP0 marker + EOI) that `identify` confirms.
    fn jpeg() -> Vec<u8> {
        vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0xFF, 0xD9]
    }

    #[test]
    fn flags_content_extension_mismatches() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        std::fs::write(dir.join("real.jpg"), jpeg()).unwrap(); // matches
        std::fs::write(dir.join("photo.jpeg"), jpeg()).unwrap(); // alias, matches
        std::fs::write(dir.join("disguised.png"), jpeg()).unwrap(); // JPEG named .png
        std::fs::write(dir.join("notes.txt"), b"just text").unwrap(); // unknown content
        std::fs::write(dir.join("blob.bin"), jpeg()).unwrap(); // unknown extension

        let sum = summarize(dir, 10).unwrap();
        // Only the JPEG-named-.png is a mismatch: .jpg/.jpeg match, .txt content
        // isn't identifiable, and .bin isn't a known extension.
        assert_eq!(sum.mismatches.len(), 1, "exactly one mismatch");
        let m = &sum.mismatches[0];
        assert_eq!(m.path, "disguised.png");
        assert_eq!(m.claimed, "png");
        assert_eq!(m.detected, "jpg");
        // None of these is corrupt: every file is either a clean match, an
        // unidentifiable .txt, or an unknown .bin extension.
        assert!(sum.corrupt.is_empty(), "no corrupt files");
    }

    #[test]
    fn flags_corrupt_or_truncated_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        std::fs::write(dir.join("good.jpg"), jpeg()).unwrap(); // valid JPEG
                                                               // A .jpg whose content has no JPEG (or any) magic — truncated/corrupt.
        std::fs::write(
            dir.join("broken.jpg"),
            b"Hello, this is plain text not a JPEG.",
        )
        .unwrap();
        // A signatured-type extension is required to call something corrupt:
        // .txt and .bin have no magic, so an unidentifiable body is left alone.
        std::fs::write(dir.join("notes.txt"), b"just some notes").unwrap();
        std::fs::write(dir.join("blob.bin"), b"\x01\x02\x03\x04").unwrap();

        let sum = summarize(dir, 10).unwrap();
        assert_eq!(sum.corrupt.len(), 1, "only broken.jpg is corrupt");
        let c = &sum.corrupt[0];
        assert_eq!(c.path, "broken.jpg");
        assert_eq!(c.claimed, "jpg");
        // The good JPEG is neither corrupt nor a mismatch.
        assert!(sum.mismatches.is_empty(), "no mismatches");
    }
}
