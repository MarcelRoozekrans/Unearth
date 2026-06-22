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
        let (size, digest) = hash_file(path)?;
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
        let stat = summary.by_type.entry(ext).or_default();
        stat.count += 1;
        stat.bytes = stat.bytes.saturating_add(size);

        let entry = by_digest.entry(digest).or_insert((0, size));
        entry.0 += 1;

        let rel = path
            .strip_prefix(dir)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned();
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

/// Stream a file through SHA-256, returning its size and digest.
fn hash_file(path: &Path) -> Result<(u64, [u8; 32])> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        hasher.update(&buf[..n]);
    }
    Ok((size, hasher.finalize()))
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
}
