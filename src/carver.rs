//! The carving engine: scan the source for headers and reconstruct files.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::signatures::{Extent, Signature, SignatureIndex};
use crate::source::Source;

/// How much of the source we read per scan iteration.
const SCAN_CHUNK: usize = 8 * 1024 * 1024; // 8 MiB
/// Window used when streaming a recovered file to disk.
const COPY_CHUNK: usize = 4 * 1024 * 1024; // 4 MiB

/// Tunable knobs for a carving run.
pub struct CarveOptions {
    /// Directory recovered files are written into (created if missing).
    pub output_dir: PathBuf,
    /// First byte offset to scan.
    pub start: u64,
    /// Exclusive end offset; `None` means scan to the end of the device.
    pub end: Option<u64>,
    /// Ignore carved files smaller than this many bytes.
    pub min_size: u64,
    /// Stop after recovering this many files (`None` = no limit).
    pub max_files: Option<u64>,
    /// Find files even when nested inside another carved file (e.g. a JPEG
    /// thumbnail inside a JPEG). Off by default to avoid duplicates.
    pub allow_nested: bool,
    /// Report progress to stderr.
    pub progress: bool,
}

/// Outcome of a carving run.
#[derive(Default)]
pub struct CarveStats {
    pub bytes_scanned: u64,
    pub files_recovered: u64,
    pub bytes_recovered: u64,
    /// Recovered-file count per extension.
    pub per_type: std::collections::BTreeMap<&'static str, u64>,
}

/// Scan `source` for the `active` signatures and write recovered files.
pub fn carve(
    source: &Source,
    active: &[&'static Signature],
    opts: &CarveOptions,
    progress: &dyn ProgressSink,
) -> Result<CarveStats> {
    fs::create_dir_all(&opts.output_dir)
        .with_context(|| format!("creating output dir {}", opts.output_dir.display()))?;

    let index = SignatureIndex::build(active);
    let max_magic_offset = active.iter().map(|s| s.magic_offset).max().unwrap_or(0);
    // Carry over enough bytes so a magic straddling a chunk boundary is still
    // matched, and so we can subtract magic_offset to find the file start.
    let overlap = index.max_lookahead + max_magic_offset as usize;

    let scan_end = opts.end.unwrap_or(source.size).min(source.size);
    let scan_start = opts.start.min(scan_end);

    let mut stats = CarveStats::default();
    let mut buf = vec![0u8; SCAN_CHUNK + overlap];
    let mut abs = scan_start;
    // Detected file starts below this offset are skipped (already inside a
    // recovered file). Disabled when `allow_nested` is set.
    let mut skip_until = 0u64;
    // Scratch buffers reused across files to avoid per-file allocations.
    let mut footer_buf: Vec<u8> = Vec::new();
    let mut copy_buf: Vec<u8> = Vec::new();

    progress.begin(scan_end - scan_start);

    while abs < scan_end {
        let want = ((scan_end - abs) as usize).min(SCAN_CHUNK + overlap);
        let n = source.read_at(abs, &mut buf[..want])?;
        if n == 0 {
            break;
        }

        // Only scan positions whose full magic could fit within what we read.
        // The tail `overlap` region is re-read at the start of the next chunk.
        let scan_limit = if n == want && abs + (n as u64) < scan_end {
            n.saturating_sub(overlap)
        } else {
            n // final chunk: scan everything we have
        };

        let mut i = 0usize;
        while i < scan_limit {
            let magic_abs = abs + i as u64;
            if let Some(sig) = index.match_at(&buf[i..n]) {
                let file_start = magic_abs.wrapping_sub(sig.magic_offset);
                // `file_start` underflows past the device start only if magic
                // appears in the first few bytes; guard against that.
                let valid_start = magic_abs >= sig.magic_offset;

                if valid_start && (opts.allow_nested || file_start >= skip_until) {
                    if let Some(len) =
                        file_length(source, sig, file_start, scan_end, &mut footer_buf)?
                    {
                        if len >= opts.min_size {
                            write_file(
                                source,
                                sig,
                                file_start,
                                len,
                                opts,
                                &mut stats,
                                &mut copy_buf,
                            )?;
                            if !opts.allow_nested {
                                skip_until = file_start + len;
                            }
                            if let Some(max) = opts.max_files {
                                if stats.files_recovered >= max {
                                    progress.finish(stats.bytes_scanned);
                                    return Ok(stats);
                                }
                            }
                        }
                    }
                }
            }
            i += 1;
        }

        // Advance, leaving the overlap to be re-read (unless this was the tail).
        let advance = if scan_limit == n { n } else { scan_limit };
        abs += advance as u64;
        stats.bytes_scanned = abs - scan_start;
        progress.update(stats.bytes_scanned);
    }

    progress.finish(stats.bytes_scanned);
    Ok(stats)
}

/// Compute the length of the file of type `sig` starting at `file_start`,
/// or `None` if it cannot be reconstructed.
fn file_length(
    source: &Source,
    sig: &Signature,
    file_start: u64,
    scan_end: u64,
    footer_buf: &mut Vec<u8>,
) -> Result<Option<u64>> {
    let limit = (file_start + sig.max_size).min(scan_end);
    match sig.extent {
        Extent::Footer { marker, trailing } => Ok(find_footer(
            source, file_start, marker, trailing, limit, footer_buf,
        )?),
        Extent::HeaderSizeLe32 { offset } => {
            let mut hdr = [0u8; 4];
            let need = offset + 4;
            let mut tmp = vec![0u8; need];
            let n = source.read_at(file_start, &mut tmp)?;
            if n < need {
                return Ok(None);
            }
            hdr.copy_from_slice(&tmp[offset..offset + 4]);
            let size = u32::from_le_bytes(hdr) as u64;
            if size == 0 || file_start + size > limit {
                return Ok(None);
            }
            Ok(Some(size))
        }
        Extent::RiffSize => {
            let mut tmp = [0u8; 8];
            if source.read_at(file_start, &mut tmp)? < 8 {
                return Ok(None);
            }
            let chunk = u32::from_le_bytes([tmp[4], tmp[5], tmp[6], tmp[7]]) as u64;
            let size = chunk + 8;
            if chunk == 0 || file_start + size > limit {
                return Ok(None);
            }
            Ok(Some(size))
        }
        Extent::Sqlite => {
            let mut hdr = [0u8; 32];
            if source.read_at(file_start, &mut hdr)? < 32 {
                return Ok(None);
            }
            // page_size: big-endian u16 at offset 16; the value 1 means 65536.
            let raw = u16::from_be_bytes([hdr[16], hdr[17]]) as u64;
            let page_size = if raw == 1 { 65536 } else { raw };
            let page_count = u32::from_be_bytes([hdr[28], hdr[29], hdr[30], hdr[31]]) as u64;
            let size = page_size.checked_mul(page_count).unwrap_or(0);
            if size == 0 || file_start + size > limit {
                return Ok(None);
            }
            Ok(Some(size))
        }
        Extent::SevenZip => {
            let mut hdr = [0u8; 32];
            if source.read_at(file_start, &mut hdr)? < 32 {
                return Ok(None);
            }
            let next_off = u64::from_le_bytes(hdr[12..20].try_into().unwrap());
            let next_size = u64::from_le_bytes(hdr[20..28].try_into().unwrap());
            let size = 32u64
                .checked_add(next_off)
                .and_then(|s| s.checked_add(next_size))
                .unwrap_or(0);
            if size <= 32 || file_start + size > limit {
                return Ok(None);
            }
            Ok(Some(size))
        }
        Extent::Mp4Atoms => Ok(mp4_length(source, file_start, limit)?),
    }
}

/// Search forward from `file_start` for `marker`, returning the file length
/// (marker end + `trailing`, clamped to `limit`).
fn find_footer(
    source: &Source,
    file_start: u64,
    marker: &[u8],
    trailing: u64,
    limit: u64,
    buf: &mut Vec<u8>,
) -> Result<Option<u64>> {
    let window = 1024 * 1024usize;
    let overlap = marker.len().saturating_sub(1);
    // Size the (reused) scratch buffer to the search region, capped at the
    // window. Reusing it across files avoids a per-header allocation.
    let cap = (window + overlap)
        .min((limit - file_start) as usize)
        .max(marker.len());
    if buf.len() < cap {
        buf.resize(cap, 0);
    }

    // Start the search just past the header so a magic that is itself a prefix
    // of the marker cannot match at offset 0.
    let mut pos = file_start;
    loop {
        if pos >= limit {
            return Ok(None);
        }
        let want = ((limit - pos) as usize).min(window + overlap);
        let n = source.read_at(pos, &mut buf[..want])?;
        if n == 0 {
            return Ok(None);
        }
        if let Some(idx) = find_subsequence(&buf[..n], marker) {
            let marker_end = pos + idx as u64 + marker.len() as u64;
            let file_end = (marker_end + trailing).min(limit);
            return Ok(Some(file_end - file_start));
        }
        if n < want {
            return Ok(None); // reached the end without a footer
        }
        // Keep `overlap` bytes so a marker spanning the boundary is caught.
        pos += (n - overlap) as u64;
    }
}

/// Walk the ISO base-media box structure to find the total media length.
fn mp4_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let mut pos = file_start;
    let mut hdr = [0u8; 16];
    let mut saw_ftyp = false;

    loop {
        if pos + 8 > limit {
            break;
        }
        let n = source.read_at(pos, &mut hdr)?;
        if n < 8 {
            break;
        }
        let size32 = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as u64;
        let box_type = &hdr[4..8];

        // Box types are four printable ASCII characters; anything else means
        // we have walked off the end of the media into unrelated data.
        if !box_type.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
            break;
        }
        if box_type == b"ftyp" {
            saw_ftyp = true;
        }

        let box_size = match size32 {
            1 => {
                // 64-bit "largesize" follows the 8-byte box header.
                if n < 16 {
                    break;
                }
                u64::from_be_bytes([
                    hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
                ])
            }
            0 => limit - pos, // box extends to end of file
            other => other,
        };

        if box_size < 8 {
            break; // malformed; stop here
        }
        pos = pos.saturating_add(box_size);
        if pos >= limit {
            pos = limit;
            break;
        }
    }

    let len = pos - file_start;
    if saw_ftyp && len >= 8 {
        Ok(Some(len))
    } else {
        Ok(None)
    }
}

/// Stream `len` bytes from the source at `file_start` into a new output file.
fn write_file(
    source: &Source,
    sig: &Signature,
    file_start: u64,
    len: u64,
    opts: &CarveOptions,
    stats: &mut CarveStats,
    buf: &mut Vec<u8>,
) -> Result<()> {
    let name = format!(
        "{:08}_{:#016x}.{}",
        stats.files_recovered, file_start, sig.ext
    );
    let path: PathBuf = opts.output_dir.join(name);
    let mut out =
        fs::File::create(&path).with_context(|| format!("creating {}", path.display()))?;

    let mut remaining = len;
    let mut pos = file_start;
    // Reused copy buffer, grown to the file size but capped at COPY_CHUNK.
    let buf_len = (len as usize).clamp(1, COPY_CHUNK);
    if buf.len() < buf_len {
        buf.resize(buf_len, 0);
    }
    while remaining > 0 {
        let want = (remaining as usize).min(buf_len);
        let n = source.read_at(pos, &mut buf[..want])?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])
            .with_context(|| format!("writing {}", path.display()))?;
        remaining -= n as u64;
        pos += n as u64;
    }
    out.flush().ok();

    let written = len - remaining;
    stats.files_recovered += 1;
    stats.bytes_recovered += written;
    *stats.per_type.entry(sig.ext).or_insert(0) += 1;
    Ok(())
}

/// Naive substring search. Fine here: the haystack window is ~1 MiB and the
/// needle is a handful of bytes, so this is not a bottleneck.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Sink for progress reporting so the engine stays decoupled from the UI.
pub trait ProgressSink {
    fn begin(&self, _total: u64) {}
    fn update(&self, _scanned: u64) {}
    fn finish(&self, _scanned: u64) {}
}

/// A no-op progress sink.
pub struct NoProgress;
impl ProgressSink for NoProgress {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_subsequence() {
        assert_eq!(find_subsequence(b"hello world", b"wor"), Some(6));
        assert_eq!(find_subsequence(b"hello", b"xyz"), None);
        assert_eq!(find_subsequence(b"abc", b""), None);
    }
}
