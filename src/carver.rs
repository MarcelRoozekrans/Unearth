//! The carving engine: scan the source for headers and reconstruct files.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};

use std::collections::HashSet;

use crate::hash::Sha256;
use crate::signatures::{Extent, Signature, SignatureIndex};
use crate::source::Source;
use crate::validate::{self, HEADER_LEN};

/// How much of the source we read per scan iteration.
const SCAN_CHUNK: usize = 8 * 1024 * 1024; // 8 MiB
/// Persist the scan checkpoint at least this often, so an interrupted scan of a
/// large drive loses little progress.
const CHECKPOINT_INTERVAL: u64 = 256 * 1024 * 1024; // 256 MiB
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
    /// Reject candidates whose header fails a structural check, cutting the
    /// false positives that coincidental magic bytes produce. On by default.
    pub validate: bool,
    /// Skip writing a file whose content (by SHA-256) was already recovered in
    /// this run. Off by default.
    pub dedup: bool,
    /// Report progress to stderr.
    pub progress: bool,
    /// Optional checkpoint file. When set, the scan position and recovered-file
    /// tally are written here periodically so an interrupted scan can `resume`.
    pub checkpoint: Option<PathBuf>,
    /// Resume from the checkpoint file if it exists: continue from the saved
    /// position with the prior run's tally (and dedup set). Requires the same
    /// output directory and options as the original run.
    pub resume: bool,
    /// Group recovered files into a per-type subdirectory of the output
    /// directory (e.g. `jpg/`, `png/`) instead of a single flat directory.
    pub organize: bool,
}

/// One carved file, recorded for the recovery report.
pub struct CarvedFile {
    /// Output file name within the output directory.
    pub name: String,
    /// File-type extension, e.g. `"jpg"`.
    pub ext: &'static str,
    /// Byte offset of the file's start within the source.
    pub offset: u64,
    /// Number of bytes written.
    pub size: u64,
    /// SHA-256 of the written bytes.
    pub sha256: [u8; 32],
}

/// Outcome of a carving run.
#[derive(Default)]
pub struct CarveStats {
    pub bytes_scanned: u64,
    pub files_recovered: u64,
    pub bytes_recovered: u64,
    /// Candidates dropped because their header failed structural validation.
    pub rejected: u64,
    /// Files dropped by `--dedup` because identical content was already written.
    pub duplicates: u64,
    /// Recovered-file count per extension.
    pub per_type: std::collections::BTreeMap<&'static str, u64>,
    /// Per-file records, populated for the recovery report.
    pub files: Vec<CarvedFile>,
}

/// Scan `source` for the `active` signatures and write recovered files.
pub fn carve(
    source: &Source,
    active: &[&'static Signature],
    opts: &CarveOptions,
    progress: &dyn ProgressSink,
) -> Result<CarveStats> {
    carve_seeded(source, active, opts, progress, HashSet::new())
}

/// Like [`carve`], but pre-seed the `--dedup` set with content digests already
/// recovered elsewhere (e.g. by `undelete`), so carving only writes files whose
/// content is new. Has no effect unless [`CarveOptions::dedup`] is set.
pub fn carve_seeded(
    source: &Source,
    active: &[&'static Signature],
    opts: &CarveOptions,
    progress: &dyn ProgressSink,
    seed: HashSet<[u8; 32]>,
) -> Result<CarveStats> {
    fs::create_dir_all(&opts.output_dir)
        .with_context(|| format!("creating output dir {}", opts.output_dir.display()))?;

    let index = SignatureIndex::build(active);
    let max_magic_offset = active.iter().map(|s| s.magic_offset).max().unwrap_or(0);
    // Carry over enough bytes so a magic straddling a chunk boundary is still
    // matched, and so we can subtract magic_offset to find the file start.
    let overlap = index.max_lookahead + max_magic_offset as usize;

    let scan_end = opts.end.unwrap_or(source.size).min(source.size);
    let base_start = opts.start.min(scan_end);

    let mut stats = CarveStats::default();
    let mut buf = vec![0u8; SCAN_CHUNK + overlap];
    // Detected file starts below this offset are skipped (already inside a
    // recovered file). Disabled when `allow_nested` is set.
    let mut skip_until = 0u64;
    // Scratch buffers reused across files to avoid per-file allocations.
    let mut footer_buf: Vec<u8> = Vec::new();
    let mut copy_buf: Vec<u8> = Vec::new();
    // Content digests of files already written, for `--dedup` (pre-seeded with
    // any digests the caller already recovered by other means).
    let mut seen: HashSet<[u8; 32]> = seed;

    // Resume from a checkpoint if asked and one exists: continue from the saved
    // position with the prior run's tally, dedup set, and skip boundary. A
    // corrupt checkpoint is treated as "start over" (always safe).
    let mut scan_start = base_start;
    let resume_path = opts
        .checkpoint
        .as_ref()
        .filter(|p| opts.resume && p.exists());
    if let Some(path) = resume_path {
        if let Some(saved) = read_checkpoint(path) {
            scan_start = saved.pos.clamp(base_start, scan_end);
            skip_until = saved.skip_until;
            seen.extend(saved.seen);
            stats = saved.stats;
        }
    }

    let mut abs = scan_start;
    let mut last_checkpoint = abs;
    progress.begin(scan_end - base_start);
    progress.update(abs - base_start);

    while abs < scan_end {
        if progress.cancelled() {
            break; // stop early; `stats` holds what was recovered so far
        }
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
                            if opts.validate && !passes_validation(source, sig, file_start, len)? {
                                stats.rejected += 1;
                            } else {
                                write_file(
                                    source,
                                    sig,
                                    file_start,
                                    len,
                                    opts,
                                    &mut stats,
                                    &mut copy_buf,
                                    &mut seen,
                                )?;
                                // A duplicate still occupies this region, so skip
                                // past it just like a written file.
                                if !opts.allow_nested {
                                    skip_until = file_start + len;
                                }
                                if let Some(max) = opts.max_files {
                                    if stats.files_recovered >= max {
                                        progress.finish(stats.bytes_scanned);
                                        if let Some(path) = &opts.checkpoint {
                                            write_checkpoint(
                                                path, abs, scan_end, skip_until, &stats, &seen,
                                                opts.dedup,
                                            )?;
                                        }
                                        return Ok(stats);
                                    }
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
        stats.bytes_scanned = abs - base_start;
        progress.update(stats.bytes_scanned);

        // Checkpoint periodically so an interrupted scan loses little progress.
        if let Some(path) = &opts.checkpoint {
            if abs - last_checkpoint >= CHECKPOINT_INTERVAL {
                write_checkpoint(path, abs, scan_end, skip_until, &stats, &seen, opts.dedup)?;
                last_checkpoint = abs;
            }
        }
    }

    progress.finish(stats.bytes_scanned);
    // Persist a final checkpoint (covers completion and cancellation). On a
    // completed scan `pos == scan_end`, so a later resume is a no-op.
    if let Some(path) = &opts.checkpoint {
        write_checkpoint(path, abs, scan_end, skip_until, &stats, &seen, opts.dedup)?;
    }
    Ok(stats)
}

/// State restored from a scan checkpoint.
struct LoadedCheckpoint {
    pos: u64,
    skip_until: u64,
    seen: HashSet<[u8; 32]>,
    stats: CarveStats,
}

/// Write the scan checkpoint atomically (temp file + rename) so a crash never
/// leaves a half-written checkpoint. Records the scan position, the skip
/// boundary, the running tally, the dedup digests (when deduping), and the
/// per-file manifest rows so a resumed run's `--report` stays complete.
fn write_checkpoint(
    path: &std::path::Path,
    pos: u64,
    end: u64,
    skip_until: u64,
    stats: &CarveStats,
    seen: &HashSet<[u8; 32]>,
    dedup: bool,
) -> Result<()> {
    let mut s = String::from("# filerecovery scan checkpoint v1\n");
    s.push_str(&format!("pos {pos}\n"));
    s.push_str(&format!("end {end}\n"));
    s.push_str(&format!("skip_until {skip_until}\n"));
    s.push_str(&format!("files {}\n", stats.files_recovered));
    s.push_str(&format!("bytes {}\n", stats.bytes_recovered));
    s.push_str(&format!("rejected {}\n", stats.rejected));
    s.push_str(&format!("duplicates {}\n", stats.duplicates));
    if dedup {
        for h in seen {
            s.push_str(&format!("seen {}\n", crate::hash::to_hex(h)));
        }
    }
    for f in &stats.files {
        s.push_str(&format!(
            "file {} {} {} {} {}\n",
            f.ext,
            f.offset,
            f.size,
            crate::hash::to_hex(&f.sha256),
            f.name
        ));
    }

    let tmp = path.with_extension("checkpoint.tmp");
    fs::write(&tmp, s).with_context(|| format!("writing checkpoint {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("installing checkpoint {}", path.display()))?;
    Ok(())
}

/// Read a scan checkpoint leniently: unparseable lines are skipped (so a
/// truncated file degrades gracefully). Returns `None` only if the file cannot
/// be read at all, in which case the caller starts a fresh scan.
fn read_checkpoint(path: &std::path::Path) -> Option<LoadedCheckpoint> {
    let text = fs::read_to_string(path).ok()?;
    let mut pos = 0u64;
    let mut skip_until = 0u64;
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut stats = CarveStats::default();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.splitn(6, ' ');
        match it.next() {
            Some("pos") => pos = it.next().and_then(|v| v.parse().ok()).unwrap_or(pos),
            Some("skip_until") => {
                skip_until = it.next().and_then(|v| v.parse().ok()).unwrap_or(skip_until)
            }
            Some("files") => {
                stats.files_recovered = it.next().and_then(|v| v.parse().ok()).unwrap_or(0)
            }
            Some("bytes") => {
                stats.bytes_recovered = it.next().and_then(|v| v.parse().ok()).unwrap_or(0)
            }
            Some("rejected") => {
                stats.rejected = it.next().and_then(|v| v.parse().ok()).unwrap_or(0)
            }
            Some("duplicates") => {
                stats.duplicates = it.next().and_then(|v| v.parse().ok()).unwrap_or(0)
            }
            Some("seen") => {
                if let Some(h) = it.next().and_then(parse_hex32) {
                    seen.insert(h);
                }
            }
            Some("file") => {
                if let (Some(ext), Some(offset), Some(size), Some(sha), Some(name)) = (
                    it.next().and_then(intern_ext),
                    it.next().and_then(|v| v.parse::<u64>().ok()),
                    it.next().and_then(|v| v.parse::<u64>().ok()),
                    it.next().and_then(parse_hex32),
                    it.next(),
                ) {
                    *stats.per_type.entry(ext).or_insert(0) += 1;
                    stats.files.push(CarvedFile {
                        name: name.to_string(),
                        ext,
                        offset,
                        size,
                        sha256: sha,
                    });
                }
            }
            _ => {}
        }
    }
    Some(LoadedCheckpoint {
        pos,
        skip_until,
        seen,
        stats,
    })
}

/// Resolve an extension string back to the `&'static str` from the signature
/// table, so a restored [`CarvedFile`] keeps the same lifetime as a fresh one.
fn intern_ext(s: &str) -> Option<&'static str> {
    crate::signatures::SIGNATURES
        .iter()
        .map(|sig| sig.ext)
        .find(|e| *e == s)
}

/// Parse 64 hex characters into a 32-byte digest.
fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
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
        Extent::HeaderSizeBe32 { offset } => {
            let need = offset + 4;
            let mut tmp = vec![0u8; need];
            if source.read_at(file_start, &mut tmp)? < need {
                return Ok(None);
            }
            let hdr: [u8; 4] = tmp[offset..offset + 4].try_into().unwrap();
            let size = u32::from_be_bytes(hdr) as u64;
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
        Extent::FormSize => {
            let mut tmp = [0u8; 8];
            if source.read_at(file_start, &mut tmp)? < 8 {
                return Ok(None);
            }
            let chunk = u32::from_be_bytes([tmp[4], tmp[5], tmp[6], tmp[7]]) as u64;
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
        Extent::Elf => Ok(elf_length(source, file_start, limit)?),
        Extent::Pe => Ok(pe_length(source, file_start, limit)?),
        Extent::Tiff => Ok(tiff_length(source, file_start, limit)?),
        Extent::Ebml => Ok(ebml_length(source, file_start, limit)?),
        Extent::Ogg => Ok(ogg_length(source, file_start, limit)?),
        Extent::Asf => Ok(asf_length(source, file_start, limit)?),
        Extent::Wasm => Ok(wasm_length(source, file_start, limit)?),
        Extent::IcoCur => Ok(icocur_length(source, file_start, limit)?),
        Extent::Sfnt => Ok(sfnt_length(source, file_start, limit)?),
        Extent::Midi => Ok(midi_length(source, file_start, limit)?),
        Extent::Flv => Ok(flv_length(source, file_start, limit)?),
        Extent::Pcap => Ok(pcap_length(source, file_start, limit)?),
        Extent::Pcapng => Ok(pcapng_length(source, file_start, limit)?),
        Extent::Ttc => Ok(ttc_length(source, file_start, limit)?),
        Extent::Rar => Ok(rar_length(source, file_start, limit)?),
        Extent::Zstd => Ok(zstd_length(source, file_start, limit)?),
        Extent::Lz4 => Ok(lz4_length(source, file_start, limit)?),
        Extent::Psd => Ok(psd_length(source, file_start, limit)?),
    }
}

/// Walk a Flash Video tag chain. After the 9-byte header (which records its own
/// size and must be 9), each tag is an 11-byte header — a 1-byte type and a
/// 24-bit big-endian data size — followed by the data and a 4-byte
/// previous-tag-size field. The file ends after the last valid tag.
fn flv_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    const MAX_TAGS: u64 = 1 << 24;
    let avail = limit - file_start;
    let mut hdr = [0u8; 9];
    if source.read_at(file_start, &mut hdr)? < 9 {
        return Ok(None);
    }
    let data_offset = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) as u64;
    if &hdr[0..3] != b"FLV" || data_offset != 9 {
        return Ok(None);
    }

    // The header is followed by PreviousTagSize0 (always 0).
    let mut pos = 9u64;
    let mut tag = [0u8; 11];
    let mut tags = 0u64;
    loop {
        // 4-byte previous-tag-size precedes each tag (the first must be zero).
        if pos + 4 > avail {
            break;
        }
        let mut prev = [0u8; 4];
        source.read_at(file_start + pos, &mut prev)?;
        if tags == 0 && prev != [0, 0, 0, 0] {
            return Ok(None);
        }
        pos += 4;

        if pos + 11 > avail || tags >= MAX_TAGS {
            break;
        }
        if source.read_at(file_start + pos, &mut tag)? < 11 {
            break;
        }
        // Tag types: 8 audio, 9 video, 18 script data.
        if !matches!(tag[0], 8 | 9 | 18) {
            break;
        }
        let data_size = u32::from_be_bytes([0, tag[1], tag[2], tag[3]]) as u64;
        let next = pos.saturating_add(11).saturating_add(data_size);
        if next > avail {
            break;
        }
        pos = next;
        tags += 1;
    }

    if tags == 0 || file_start + pos > limit {
        return Ok(None);
    }
    Ok(Some(pos))
}

/// Defensive cap on the number of RAR blocks walked.
const MAX_RAR_BLOCKS: u64 = 1 << 24;

/// RAR archive length. The 6-byte `Rar!\x1A\x07` signature is shared by v4 and
/// v5; the next byte selects the layout (`0x00` => v4, `0x01 0x00` => v5). Each
/// format is a chain of blocks ending in an end-of-archive marker block.
fn rar_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let mut sig = [0u8; 8];
    let n = source.read_at(file_start, &mut sig)?;
    if n < 7 || &sig[0..6] != b"Rar!\x1a\x07" {
        return Ok(None);
    }
    match sig[6] {
        0x00 => rar4_length(source, file_start, limit),
        0x01 if n >= 8 && sig[7] == 0x00 => rar5_length(source, file_start, limit),
        _ => Ok(None),
    }
}

/// RAR v4: a 7-byte marker block then a chain of blocks. Each block header is
/// `HEAD_CRC(2) HEAD_TYPE(1) HEAD_FLAGS(2) HEAD_SIZE(2)`, with an extra
/// `ADD_SIZE(4)` when `HEAD_FLAGS & 0x8000` is set. The block spans
/// `HEAD_SIZE + ADD_SIZE`; the terminator block has type `0x7B`.
fn rar4_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let mut pos = 7u64; // past the marker
    for _ in 0..MAX_RAR_BLOCKS {
        let mut hdr = [0u8; 11];
        let got = source.read_at(file_start + pos, &mut hdr)?;
        if got < 7 {
            return Ok(None);
        }
        let htype = hdr[2];
        let flags = u16::from_le_bytes([hdr[3], hdr[4]]);
        let head_size = u16::from_le_bytes([hdr[5], hdr[6]]) as u64;
        if head_size < 7 {
            return Ok(None);
        }
        let add_size = if flags & 0x8000 != 0 {
            if got < 11 {
                return Ok(None);
            }
            u32::from_le_bytes([hdr[7], hdr[8], hdr[9], hdr[10]]) as u64
        } else {
            0
        };
        let block_len = match head_size.checked_add(add_size) {
            Some(b) if b > 0 => b,
            _ => return Ok(None),
        };
        pos = match pos.checked_add(block_len) {
            Some(p) => p,
            None => return Ok(None),
        };
        if file_start + pos > limit {
            return Ok(None);
        }
        if htype == 0x7B {
            return Ok(Some(pos)); // end-of-archive block consumed
        }
    }
    Ok(None)
}

/// RAR v5: an 8-byte signature then a chain of blocks. Each block is
/// `CRC32(4)`, a vint `header_size`, the header (that many bytes), then an
/// optional data area. The header begins `vint type, vint flags`, with a vint
/// `extra_area_size` when `flags & 1` and a vint `data_size` when `flags & 2`;
/// the block spans `4 + len(header_size) + header_size + data_size`. The
/// terminator block has type `5`.
fn rar5_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let mut pos = 8u64; // past the signature
    for _ in 0..MAX_RAR_BLOCKS {
        let crc_end = pos + 4;
        let (header_size, hs_len) = match read_vint(source, file_start + crc_end)? {
            Some(x) => x,
            None => return Ok(None),
        };
        let header_start = crc_end + hs_len;
        let (htype, t_len) = match read_vint(source, file_start + header_start)? {
            Some(x) => x,
            None => return Ok(None),
        };
        let (flags, f_len) = match read_vint(source, file_start + header_start + t_len)? {
            Some(x) => x,
            None => return Ok(None),
        };
        let mut cursor = header_start + t_len + f_len;
        if flags & 0x0001 != 0 {
            // extra_area_size vint (its bytes live inside header_size).
            match read_vint(source, file_start + cursor)? {
                Some((_, e_len)) => cursor += e_len,
                None => return Ok(None),
            }
        }
        let data_size = if flags & 0x0002 != 0 {
            match read_vint(source, file_start + cursor)? {
                Some((ds, _)) => ds,
                None => return Ok(None),
            }
        } else {
            0
        };
        let block_len = 4u64
            .checked_add(hs_len)
            .and_then(|b| b.checked_add(header_size))
            .and_then(|b| b.checked_add(data_size));
        let block_len = match block_len {
            Some(b) if b > 0 => b,
            _ => return Ok(None),
        };
        pos = match pos.checked_add(block_len) {
            Some(p) => p,
            None => return Ok(None),
        };
        if file_start + pos > limit {
            return Ok(None);
        }
        if htype == 5 {
            return Ok(Some(pos)); // end-of-archive block consumed
        }
    }
    Ok(None)
}

/// Zstandard frame length. Parse the frame header to find where the data blocks
/// begin and whether a content checksum trails the frame, then walk the blocks
/// (each a 3-byte header: bit 0 = last block, bits 1-2 = type, bits 3-23 = size)
/// to the final block.
fn zstd_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    const MAX_ZSTD_BLOCKS: u64 = 1 << 24;
    let mut head = [0u8; 5];
    if source.read_at(file_start, &mut head)? < 5 {
        return Ok(None);
    }
    if head[0..4] != [0x28, 0xB5, 0x2F, 0xFD] {
        return Ok(None);
    }
    // Frame_Header_Descriptor: the header's variable parts are sized by it.
    let fhd = head[4];
    let fcs_flag = fhd >> 6;
    let single_segment = (fhd >> 5) & 1;
    let checksum = (fhd >> 2) & 1;
    let dict_id_flag = fhd & 0x03;
    let window_size = if single_segment == 1 { 0 } else { 1 };
    let dict_size = match dict_id_flag {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    let fcs_size = match fcs_flag {
        0 => single_segment as u64, // 1 byte only when single-segment, else 0
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let mut pos = 4 + 1 + window_size + dict_size + fcs_size;

    // Walk the data blocks to the last one.
    for _ in 0..MAX_ZSTD_BLOCKS {
        let mut bh = [0u8; 3];
        if source.read_at(file_start + pos, &mut bh)? < 3 {
            return Ok(None);
        }
        let raw = bh[0] as u32 | (bh[1] as u32) << 8 | (bh[2] as u32) << 16;
        let last = raw & 1;
        let block_type = (raw >> 1) & 0x3;
        let block_size = (raw >> 3) as u64;
        if block_type == 3 {
            return Ok(None); // reserved block type
        }
        // RLE blocks carry a single byte; raw/compressed carry block_size bytes.
        let content = if block_type == 1 { 1 } else { block_size };
        pos = match pos.checked_add(3).and_then(|p| p.checked_add(content)) {
            Some(p) => p,
            None => return Ok(None),
        };
        if file_start + pos > limit {
            return Ok(None);
        }
        if last == 1 {
            break;
        }
    }

    if checksum == 1 {
        pos = match pos.checked_add(4) {
            Some(p) => p,
            None => return Ok(None),
        };
        if file_start + pos > limit {
            return Ok(None);
        }
    }
    Ok(Some(pos))
}

/// LZ4 frame length. Parse the frame descriptor (whose FLG byte sizes the
/// optional content-size and dictionary-id fields and flags per-block and
/// content checksums), then walk the data blocks — each a 4-byte little-endian
/// size (high bit = uncompressed) — to the zero-sized end mark.
fn lz4_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    const MAX_LZ4_BLOCKS: u64 = 1 << 24;
    let mut head = [0u8; 5];
    if source.read_at(file_start, &mut head)? < 5 {
        return Ok(None);
    }
    if head[0..4] != [0x04, 0x22, 0x4D, 0x18] {
        return Ok(None);
    }
    let flg = head[4];
    // FLG: bit 4 block-checksum, bit 3 content-size, bit 2 content-checksum,
    // bit 0 dictionary-id. The version bits (7-6) must be 01.
    if flg >> 6 != 0b01 {
        return Ok(None);
    }
    let block_checksum = (flg >> 4) & 1;
    let content_size = (flg >> 3) & 1;
    let content_checksum = (flg >> 2) & 1;
    let dict_id = flg & 1;
    // Frame descriptor: magic(4) + FLG(1) + BD(1) + [content size 8] +
    // [dict id 4] + header checksum(1).
    let mut pos = 4 + 1 + 1 + (content_size as u64) * 8 + (dict_id as u64) * 4 + 1;

    for _ in 0..MAX_LZ4_BLOCKS {
        let mut sz = [0u8; 4];
        if source.read_at(file_start + pos, &mut sz)? < 4 {
            return Ok(None);
        }
        let raw = u32::from_le_bytes(sz);
        pos = match pos.checked_add(4) {
            Some(p) => p,
            None => return Ok(None),
        };
        if raw == 0 {
            break; // EndMark
        }
        let data_size = (raw & 0x7FFF_FFFF) as u64;
        pos = match pos
            .checked_add(data_size)
            .and_then(|p| p.checked_add((block_checksum as u64) * 4))
        {
            Some(p) => p,
            None => return Ok(None),
        };
        if file_start + pos > limit {
            return Ok(None);
        }
    }

    if content_checksum == 1 {
        pos = match pos.checked_add(4) {
            Some(p) => p,
            None => return Ok(None),
        };
    }
    if file_start + pos > limit {
        return Ok(None);
    }
    Ok(Some(pos))
}

/// Advance past one of a PSD's length-prefixed sections: a big-endian length
/// field of `field_size` bytes (4 for PSD, 8 for PSB) followed by that many
/// bytes. Returns the offset just past the section, or `None` if it runs past
/// the limit or the source ends.
fn psd_section(
    source: &Source,
    file_start: u64,
    pos: u64,
    field_size: usize,
    limit: u64,
) -> Result<Option<u64>> {
    let mut buf = [0u8; 8];
    if source.read_at(file_start + pos, &mut buf[..field_size])? < field_size {
        return Ok(None);
    }
    let len = if field_size == 8 {
        u64::from_be_bytes(buf)
    } else {
        u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64
    };
    let next = pos.saturating_add(field_size as u64).saturating_add(len);
    if file_start.saturating_add(next) > limit {
        return Ok(None);
    }
    Ok(Some(next))
}

/// Photoshop document (PSD/PSB) length. After the 26-byte header come three
/// length-prefixed sections, then the image data: raw (size from the geometry)
/// or PackBits RLE (a per-scanline byte-count table whose entries sum to the
/// compressed size).
fn psd_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let mut hdr = [0u8; 26];
    if source.read_at(file_start, &mut hdr)? < 26 || &hdr[0..4] != b"8BPS" {
        return Ok(None);
    }
    let version = u16::from_be_bytes([hdr[4], hdr[5]]); // 1 = PSD, 2 = PSB
    if version != 1 && version != 2 {
        return Ok(None);
    }
    let channels = u16::from_be_bytes([hdr[12], hdr[13]]) as u64;
    let height = u32::from_be_bytes([hdr[14], hdr[15], hdr[16], hdr[17]]) as u64;
    let width = u32::from_be_bytes([hdr[18], hdr[19], hdr[20], hdr[21]]) as u64;
    let depth = u16::from_be_bytes([hdr[22], hdr[23]]) as u64;
    if channels == 0 || channels > 56 || width == 0 || height == 0 {
        return Ok(None);
    }
    if !matches!(depth, 1 | 8 | 16 | 32) {
        return Ok(None);
    }

    // Colour-mode data, image resources, and layer & mask info. The layer length
    // field is a u64 in PSB (version 2), a u32 in PSD.
    let layer_field = if version == 2 { 8 } else { 4 };
    let mut pos = 26u64;
    for field in [4usize, 4, layer_field] {
        pos = match psd_section(source, file_start, pos, field, limit)? {
            Some(p) => p,
            None => return Ok(None),
        };
    }

    // Image data: a 2-byte compression method, then the pixel data.
    let mut comp = [0u8; 2];
    if source.read_at(file_start + pos, &mut comp)? < 2 {
        return Ok(None);
    }
    pos += 2;
    let rows = height.saturating_mul(channels);
    match u16::from_be_bytes(comp) {
        0 => {
            // Raw: each scanline is width * (depth bytes), 1-bit packed to bytes.
            let row_bytes = if depth == 1 {
                width.div_ceil(8)
            } else {
                width.saturating_mul(depth / 8)
            };
            pos = pos.saturating_add(row_bytes.saturating_mul(rows));
        }
        1 => {
            // PackBits RLE: a byte-count per scanline (u16 PSD / u32 PSB), then
            // the compressed rows whose lengths are exactly those counts.
            let count_size: u64 = if version == 2 { 4 } else { 2 };
            let counts_bytes = rows.saturating_mul(count_size);
            if counts_bytes > 64 * 1024 * 1024 {
                return Ok(None); // implausible scanline-count table
            }
            let mut counts = vec![0u8; counts_bytes as usize];
            if (source.read_at(file_start + pos, &mut counts)? as u64) < counts_bytes {
                return Ok(None);
            }
            let mut sum = 0u64;
            for i in 0..rows as usize {
                let c = if count_size == 4 {
                    let o = i * 4;
                    u32::from_be_bytes([counts[o], counts[o + 1], counts[o + 2], counts[o + 3]])
                        as u64
                } else {
                    let o = i * 2;
                    u16::from_be_bytes([counts[o], counts[o + 1]]) as u64
                };
                sum = sum.saturating_add(c);
            }
            pos = pos.saturating_add(counts_bytes).saturating_add(sum);
        }
        _ => return Ok(None), // zip-compressed image data: length not derivable here
    }

    if pos == 0 || file_start.saturating_add(pos) > limit {
        return Ok(None);
    }
    Ok(Some(pos))
}

/// Read a RAR5 variable-length integer (base-128, low group first, high bit =
/// continue) at `pos`. Returns the value and the number of bytes it occupied.
fn read_vint(source: &Source, pos: u64) -> Result<Option<(u64, u64)>> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for i in 0..10u64 {
        let mut b = [0u8; 1];
        if source.read_at(pos + i, &mut b)? < 1 {
            return Ok(None);
        }
        value |= ((b[0] & 0x7F) as u64) << shift;
        if b[0] & 0x80 == 0 {
            return Ok(Some((value, i + 1)));
        }
        shift += 7;
        if shift >= 64 {
            return Ok(None);
        }
    }
    Ok(None)
}

/// Walk a libpcap capture: a 24-byte global header (the magic gives the byte
/// order and microsecond/nanosecond flavour) then packet records, each a
/// 16-byte header whose captured length is bounded by the snap length. The file
/// ends at the first byte that is not a plausible record.
fn pcap_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    const MAX_RECORDS: u64 = 1 << 28;
    let avail = limit - file_start;
    let mut hdr = [0u8; 24];
    if source.read_at(file_start, &mut hdr)? < 24 {
        return Ok(None);
    }
    // Determine byte order from the magic; reject anything else.
    let be = match hdr[0..4] {
        [0xA1, 0xB2, 0xC3, 0xD4] | [0xA1, 0xB2, 0x3C, 0x4D] => true,
        [0xD4, 0xC3, 0xB2, 0xA1] | [0x4D, 0x3C, 0xB2, 0xA1] => false,
        _ => return Ok(None),
    };
    let rd32 = |b: &[u8]| -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if be {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    };
    // snaplen bounds each record's captured length; clamp it so a corrupt
    // header cannot wave through arbitrary garbage.
    let snaplen = (rd32(&hdr[16..20]) as u64).clamp(1, 256 * 1024);

    let mut pos = 24u64;
    let mut recs = 0u64;
    let mut rh = [0u8; 16];
    while recs < MAX_RECORDS {
        if pos + 16 > avail {
            break;
        }
        if source.read_at(file_start + pos, &mut rh)? < 16 {
            break;
        }
        let incl_len = rd32(&rh[8..12]) as u64;
        let orig_len = rd32(&rh[12..16]) as u64;
        // A real record captures at least one byte, no more than was on the wire
        // or the snap length, and the timestamp's microseconds field is bounded.
        if incl_len == 0 || incl_len > snaplen || incl_len > orig_len {
            break;
        }
        let next = pos.saturating_add(16).saturating_add(incl_len);
        if next > avail {
            break;
        }
        pos = next;
        recs += 1;
    }

    if recs == 0 || file_start + pos > limit {
        return Ok(None);
    }
    Ok(Some(pos))
}

/// Walk a pcapng capture: a chain of blocks, each `type(4), total_length(4),
/// body, total_length(4)`. The byte order comes from the first Section Header
/// Block's byte-order magic. The file ends at the first malformed block.
fn pcapng_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    const MAX_BLOCKS: u64 = 1 << 24;
    const SHB_TYPE: [u8; 4] = [0x0A, 0x0D, 0x0D, 0x0A];
    const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;
    let avail = limit - file_start;

    // The first block must be a Section Header Block; its byte-order magic at
    // offset 8 tells us the endianness of every length field.
    let mut shb = [0u8; 12];
    if source.read_at(file_start, &mut shb)? < 12 || shb[0..4] != SHB_TYPE {
        return Ok(None);
    }
    let be = if u32::from_be_bytes([shb[8], shb[9], shb[10], shb[11]]) == BYTE_ORDER_MAGIC {
        true
    } else if u32::from_le_bytes([shb[8], shb[9], shb[10], shb[11]]) == BYTE_ORDER_MAGIC {
        false
    } else {
        return Ok(None);
    };
    let rd32 = |b: &[u8]| -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if be {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    };

    let mut pos = 0u64;
    let mut blocks = 0u64;
    let mut head = [0u8; 8];
    while blocks < MAX_BLOCKS {
        if pos + 12 > avail {
            break;
        }
        if source.read_at(file_start + pos, &mut head)? < 8 {
            break;
        }
        let total = rd32(&head[4..8]) as u64;
        // Every block is a multiple of 4 bytes and at least the 12-byte frame.
        if total < 12 || total % 4 != 0 {
            break;
        }
        let next = pos.saturating_add(total);
        if next > avail {
            break;
        }
        // The trailing total-length must match the leading one.
        let mut tail = [0u8; 4];
        source.read_at(file_start + next - 4, &mut tail)?;
        if rd32(&tail) as u64 != total {
            break;
        }
        pos = next;
        blocks += 1;
    }

    // The first block (the SHB) is required; without a second block the file is
    // just a header, which is still a valid (if empty) capture.
    if blocks == 0 || file_start + pos > limit {
        return Ok(None);
    }
    Ok(Some(pos))
}

/// Walk one SFNT table directory at `dir_rel` bytes into the font/collection
/// file: a 12-byte header (whose `numTables` u16 at offset 4 gives the table
/// count) followed by 16-byte records of `tag, checksum, offset, length` (all
/// big-endian). Returns the furthest `offset + length` (padded to 4 bytes) — a
/// file-relative end, since table offsets are measured from the file start.
fn sfnt_tables_end(
    source: &Source,
    file_start: u64,
    dir_rel: u64,
    avail: u64,
) -> Result<Option<u64>> {
    if dir_rel + 12 > avail {
        return Ok(None);
    }
    let mut hdr = [0u8; 12];
    if source.read_at(file_start + dir_rel, &mut hdr)? < 12 {
        return Ok(None);
    }
    let num_tables = u16::from_be_bytes([hdr[4], hdr[5]]) as u64;
    if num_tables == 0 || num_tables > 4096 {
        return Ok(None);
    }
    let dir_end = dir_rel + 12 + num_tables * 16;
    if dir_end > avail {
        return Ok(None);
    }

    let mut max_end = dir_end;
    let mut entry = [0u8; 16];
    for i in 0..num_tables {
        if source.read_at(file_start + dir_rel + 12 + i * 16, &mut entry)? < 16 {
            return Ok(None);
        }
        let off = u32::from_be_bytes([entry[8], entry[9], entry[10], entry[11]]) as u64;
        let len = u32::from_be_bytes([entry[12], entry[13], entry[14], entry[15]]) as u64;
        // Each table must sit within the file and after at least a header.
        if off < 12 {
            return Ok(None);
        }
        let padded = off.saturating_add(len).saturating_add(3) & !3;
        if padded > avail {
            return Ok(None);
        }
        max_end = max_end.max(padded);
    }
    Ok(Some(max_end))
}

/// A standalone SFNT font is a single table directory at the file start.
fn sfnt_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    sfnt_tables_end(source, file_start, 0, limit - file_start)
}

/// Walk a TrueType Collection (`ttcf`): a header with a `numFonts` u32 at offset
/// 8 and then that many u32 offsets to each member font's table directory. The
/// file ends at the furthest table end across all member fonts.
fn ttc_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let avail = limit - file_start;
    let mut hdr = [0u8; 12];
    if source.read_at(file_start, &mut hdr)? < 12 || &hdr[0..4] != b"ttcf" {
        return Ok(None);
    }
    let num_fonts = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]) as u64;
    if num_fonts == 0 || num_fonts > 1024 {
        return Ok(None);
    }
    let offsets_end = 12 + num_fonts * 4;
    if offsets_end > avail {
        return Ok(None);
    }

    let mut max_end = offsets_end;
    let mut off4 = [0u8; 4];
    for i in 0..num_fonts {
        if source.read_at(file_start + 12 + i * 4, &mut off4)? < 4 {
            return Ok(None);
        }
        let font_off = u32::from_be_bytes(off4) as u64;
        // Member directories sit after the offset table.
        if font_off < offsets_end || font_off >= avail {
            return Ok(None);
        }
        match sfnt_tables_end(source, file_start, font_off, avail)? {
            Some(end) => max_end = max_end.max(end),
            None => return Ok(None),
        }
    }
    Ok(Some(max_end))
}

/// Walk a Standard MIDI file: an `MThd` header chunk (whose big-endian u32
/// length must be 6) followed by `MTrk` track chunks, each a 4-byte tag and a
/// big-endian u32 length. The file ends after the last track chunk.
fn midi_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    const MAX_TRACKS: u64 = 1 << 20;
    let avail = limit - file_start;
    let mut hdr = [0u8; 8];
    if source.read_at(file_start, &mut hdr)? < 8 {
        return Ok(None);
    }
    if &hdr[0..4] != b"MThd" || u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) != 6 {
        return Ok(None);
    }

    let mut pos = 14u64; // 8-byte chunk header + 6-byte MThd body
    if pos > avail {
        return Ok(None);
    }
    let mut tracks = 0u64;
    while tracks < MAX_TRACKS {
        if pos + 8 > avail {
            break;
        }
        let mut chunk = [0u8; 8];
        if source.read_at(file_start + pos, &mut chunk)? < 8 || &chunk[0..4] != b"MTrk" {
            break;
        }
        let len = u32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]) as u64;
        let next = pos.saturating_add(8).saturating_add(len);
        if next > avail {
            break;
        }
        pos = next;
        tracks += 1;
    }

    if tracks == 0 || file_start + pos > limit {
        return Ok(None);
    }
    Ok(Some(pos))
}

/// Compute an ICO/CUR file's length from its image directory: each 16-byte entry
/// gives an image's byte size and its offset, and the file ends at the furthest
/// `offset + size`. The weak 4-byte magic is gated by requiring a plausible
/// directory whose images all sit after it.
fn icocur_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let avail = limit - file_start;
    let mut hdr = [0u8; 6];
    if source.read_at(file_start, &mut hdr)? < 6 {
        return Ok(None);
    }
    // reserved must be 0 and type must be icon (1) or cursor (2).
    if hdr[0] != 0 || hdr[1] != 0 || !matches!(u16::from_le_bytes([hdr[2], hdr[3]]), 1 | 2) {
        return Ok(None);
    }
    let count = u16::from_le_bytes([hdr[4], hdr[5]]) as u64;
    if count == 0 || count > 1024 {
        return Ok(None);
    }
    let dir_end = 6 + count * 16;
    if dir_end > avail {
        return Ok(None);
    }

    let mut max_end = dir_end;
    let mut entry = [0u8; 16];
    for i in 0..count {
        if source.read_at(file_start + 6 + i * 16, &mut entry)? < 16 {
            return Ok(None);
        }
        let size = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]) as u64;
        let off = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]) as u64;
        // Image data must be non-empty and sit past the directory.
        if size == 0 || off < dir_end {
            return Ok(None);
        }
        max_end = max_end.max(off.saturating_add(size));
    }

    if file_start + max_end > limit {
        return Ok(None);
    }
    Ok(Some(max_end))
}

/// Read an unsigned LEB128 integer at `off`. Returns `(value, byte_len)`, or
/// `None` if it runs past `avail` or exceeds the 5-byte limit for a 32-bit
/// value (WebAssembly section sizes are `u32`).
fn wasm_leb(source: &Source, base: u64, avail: u64, off: u64) -> Result<Option<(u64, u32)>> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let mut len = 0u32;
    loop {
        if off + len as u64 >= avail {
            return Ok(None);
        }
        let mut b = [0u8; 1];
        if source.read_at(base + off + len as u64, &mut b)? < 1 {
            return Ok(None);
        }
        value |= ((b[0] & 0x7F) as u64) << shift;
        len += 1;
        if b[0] & 0x80 == 0 {
            return Ok(Some((value, len)));
        }
        shift += 7;
        if len >= 5 {
            return Ok(None); // a u32 LEB128 is at most 5 bytes
        }
    }
}

/// Walk a WebAssembly module's sections. After the 8-byte header each section is
/// a 1-byte id, an unsigned LEB128 size, then that many content bytes; the file
/// ends at the first byte that is no longer a valid section.
fn wasm_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    const MAX_SECTIONS: u64 = 1 << 16;
    let avail = limit - file_start;
    let mut hdr = [0u8; 8];
    if source.read_at(file_start, &mut hdr)? < 8 {
        return Ok(None);
    }
    // "\0asm" magic and version 1.
    if hdr[0..4] != [0x00, 0x61, 0x73, 0x6D]
        || u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) != 1
    {
        return Ok(None);
    }

    let mut pos = 8u64;
    let mut sections = 0u64;
    while sections < MAX_SECTIONS {
        if pos >= avail {
            break;
        }
        let mut id = [0u8; 1];
        if source.read_at(file_start + pos, &mut id)? < 1 || id[0] > 12 {
            break; // 0..=12 are the defined section ids; anything else ends it
        }
        let (size, leblen) = match wasm_leb(source, file_start, avail, pos + 1)? {
            Some(v) => v,
            None => break,
        };
        if size == 0 {
            break; // every real section carries at least one content byte
        }
        let next = pos
            .saturating_add(1)
            .saturating_add(leblen as u64)
            .saturating_add(size);
        if next > avail {
            break;
        }
        pos = next;
        sections += 1;
    }

    if sections == 0 || pos <= 8 || file_start + pos > limit {
        return Ok(None);
    }
    Ok(Some(pos))
}

/// The 16-byte GUIDs of the ASF top-level objects, used both to confirm the
/// container and to know where it ends (the walk stops at the first GUID that is
/// not one of these).
const ASF_GUIDS: [[u8; 16]; 6] = [
    // Header Object (75B22630-668E-11CF-A6D9-00AA0062CE6C)
    [
        0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE,
        0x6C,
    ],
    // Data Object (75B22636-668E-11CF-A6D9-00AA0062CE6C)
    [
        0x36, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE,
        0x6C,
    ],
    // Simple Index Object (33000890-E5B1-11CF-89F4-00A0C90349CB)
    [
        0x90, 0x08, 0x00, 0x33, 0xB1, 0xE5, 0xCF, 0x11, 0x89, 0xF4, 0x00, 0xA0, 0xC9, 0x03, 0x49,
        0xCB,
    ],
    // Index Object (D6E229D3-35DA-11D1-9034-00A0C90349BE)
    [
        0xD3, 0x29, 0xE2, 0xD6, 0xDA, 0x35, 0xD1, 0x11, 0x90, 0x34, 0x00, 0xA0, 0xC9, 0x03, 0x49,
        0xBE,
    ],
    // Media Object Index Object (FEB103F8-12AD-4C64-840F-2A1D2F7AD48C)
    [
        0xF8, 0x03, 0xB1, 0xFE, 0xAD, 0x12, 0x64, 0x4C, 0x84, 0x0F, 0x2A, 0x1D, 0x2F, 0x7A, 0xD4,
        0x8C,
    ],
    // Timecode Index Object (3CB73FD0-0C4A-4803-953D-EDF7B6228F0C)
    [
        0xD0, 0x3F, 0xB7, 0x3C, 0x4A, 0x0C, 0x03, 0x48, 0x95, 0x3D, 0xED, 0xF7, 0xB6, 0x22, 0x8F,
        0x0C,
    ],
];

/// Walk the top-level ASF objects (WMV/WMA). Each object is a 16-byte GUID plus
/// a 64-bit little-endian size that covers the whole object; the file ends at
/// the first position that is not a recognised top-level object.
fn asf_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    const MAX_OBJECTS: u64 = 4096;
    let avail = limit - file_start;
    let mut pos = 0u64;
    let mut count = 0u64;

    while count < MAX_OBJECTS {
        if pos + 24 > avail {
            break;
        }
        let mut hdr = [0u8; 24];
        if source.read_at(file_start + pos, &mut hdr)? < 24 {
            break;
        }
        if !ASF_GUIDS.iter().any(|g| g == &hdr[0..16]) {
            break; // unknown object => end of this container
        }
        let size = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
        if size < 24 {
            break; // an object includes its own 24-byte header
        }
        let next = pos.saturating_add(size);
        if next > avail {
            break;
        }
        pos = next;
        count += 1;
    }

    if count == 0 || pos == 0 || file_start + pos > limit {
        return Ok(None);
    }
    Ok(Some(pos))
}

/// Walk the chain of Ogg pages starting at `file_start`. Each `OggS` page is
/// sized by its 27-byte header plus the lacing values in its segment table; the
/// bitstream ends at the first position that is no longer a valid page.
fn ogg_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    const MAX_PAGES: u64 = 1 << 24;
    let avail = limit - file_start;
    let mut pos = 0u64;
    let mut pages = 0u64;

    while pages < MAX_PAGES {
        if pos + 27 > avail {
            break;
        }
        let mut hdr = [0u8; 27];
        if source.read_at(file_start + pos, &mut hdr)? < 27 {
            break;
        }
        // Each page begins with "OggS" and stream-structure version 0.
        if &hdr[0..4] != b"OggS" || hdr[4] != 0 {
            break;
        }
        let nsegs = hdr[26] as u64;
        if pos + 27 + nsegs > avail {
            break;
        }
        let mut seg = [0u8; 255];
        if nsegs > 0
            && source.read_at(file_start + pos + 27, &mut seg[..nsegs as usize])? < nsegs as usize
        {
            break;
        }
        let data: u64 = seg[..nsegs as usize].iter().map(|&b| b as u64).sum();
        let page_len = 27 + nsegs + data;
        if pos + page_len > avail {
            break;
        }
        pos += page_len;
        pages += 1;
    }

    if pages == 0 || pos == 0 || file_start + pos > limit {
        return Ok(None);
    }
    Ok(Some(pos))
}

/// Read an EBML variable-length integer at `off` (relative to `base`). Returns
/// `(value, byte_len, is_unknown)` with the leading length-marker bit removed
/// from the value; `is_unknown` marks the all-ones "unknown size" encoding.
fn ebml_vint(source: &Source, base: u64, avail: u64, off: u64) -> Result<Option<(u64, u32, bool)>> {
    if off >= avail {
        return Ok(None);
    }
    let mut first = [0u8; 1];
    if source.read_at(base + off, &mut first)? < 1 {
        return Ok(None);
    }
    let first = first[0];
    if first == 0 {
        return Ok(None); // lengths beyond 8 bytes are unsupported here
    }
    let len = first.leading_zeros() + 1; // 1..=8
    if off + len as u64 > avail {
        return Ok(None);
    }
    let marker = 1u8 << (8 - len);
    let mut value = (first & (marker - 1)) as u64;
    let extra = (len - 1) as usize;
    if extra > 0 {
        let mut buf = [0u8; 7];
        if source.read_at(base + off + 1, &mut buf[..extra])? < extra {
            return Ok(None);
        }
        for &b in &buf[..extra] {
            value = (value << 8) | b as u64;
        }
    }
    let data_bits = 7 * len;
    let unknown = if data_bits >= 64 {
        value == u64::MAX
    } else {
        value == (1u64 << data_bits) - 1
    };
    Ok(Some((value, len, unknown)))
}

/// Length of an EBML element ID at `off`, derived from its first byte.
fn ebml_id_len(source: &Source, base: u64, avail: u64, off: u64) -> Result<Option<u32>> {
    if off >= avail {
        return Ok(None);
    }
    let mut first = [0u8; 1];
    if source.read_at(base + off, &mut first)? < 1 || first[0] == 0 {
        return Ok(None);
    }
    let len = first[0].leading_zeros() + 1;
    if off + len as u64 > avail {
        return Ok(None);
    }
    Ok(Some(len))
}

/// Compute the length of a Matroska/WebM (EBML) file: skip the EBML header
/// element, then take the Segment's declared size, or sum its top-level
/// children when the Segment size is encoded as "unknown".
fn ebml_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    const EBML_HEADER_ID: [u8; 4] = [0x1A, 0x45, 0xDF, 0xA3];
    const SEGMENT_ID: [u8; 4] = [0x18, 0x53, 0x80, 0x67];
    let avail = limit - file_start;

    let mut id = [0u8; 4];
    if source.read_at(file_start, &mut id)? < 4 || id != EBML_HEADER_ID {
        return Ok(None);
    }
    // EBML header element: 4-byte ID then a size VINT and that many data bytes.
    let (hsize, hlen, hunknown) = match ebml_vint(source, file_start, avail, 4)? {
        Some(v) => v,
        None => return Ok(None),
    };
    if hunknown {
        return Ok(None);
    }
    let seg_pos = (4u64 + hlen as u64).saturating_add(hsize);

    // The next top-level element must be the Segment.
    let mut seg = [0u8; 4];
    if seg_pos + 4 > avail
        || source.read_at(file_start + seg_pos, &mut seg)? < 4
        || seg != SEGMENT_ID
    {
        return Ok(None);
    }
    let (ssize, slen, sunknown) = match ebml_vint(source, file_start, avail, seg_pos + 4)? {
        Some(v) => v,
        None => return Ok(None),
    };
    let seg_data_start = seg_pos + 4 + slen as u64;

    let total = if !sunknown {
        seg_data_start.saturating_add(ssize)
    } else {
        // Unknown segment size: sum top-level children that declare a size.
        let mut p = seg_data_start;
        let mut advanced = false;
        loop {
            if p >= avail {
                break;
            }
            let idlen = match ebml_id_len(source, file_start, avail, p)? {
                Some(l) => l,
                None => break,
            };
            let (csize, clen, cunknown) =
                match ebml_vint(source, file_start, avail, p + idlen as u64)? {
                    Some(v) => v,
                    None => break,
                };
            if cunknown {
                break; // can't bound a child of unknown size
            }
            let next = p
                .saturating_add(idlen as u64)
                .saturating_add(clen as u64)
                .saturating_add(csize);
            if next > avail {
                break;
            }
            p = next;
            advanced = true;
        }
        if !advanced {
            return Ok(None);
        }
        p
    };

    if total <= seg_data_start || file_start + total > limit {
        return Ok(None);
    }
    Ok(Some(total))
}

/// Positioned, endian-aware reader for the TIFF walk. All offsets are relative
/// to the file start and bounds-checked against `avail`. `big` selects BigTIFF
/// (8-byte offsets and counts) over classic TIFF (4-byte).
struct TiffReader<'a> {
    src: &'a Source,
    base: u64,
    le: bool,
    big: bool,
    avail: u64,
}

impl TiffReader<'_> {
    fn u16(&self, off: u64) -> Result<Option<u16>> {
        if off.saturating_add(2) > self.avail {
            return Ok(None);
        }
        let mut b = [0u8; 2];
        if self.src.read_at(self.base + off, &mut b)? < 2 {
            return Ok(None);
        }
        Ok(Some(if self.le {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        }))
    }

    fn u32(&self, off: u64) -> Result<Option<u32>> {
        if off.saturating_add(4) > self.avail {
            return Ok(None);
        }
        let mut b = [0u8; 4];
        if self.src.read_at(self.base + off, &mut b)? < 4 {
            return Ok(None);
        }
        Ok(Some(if self.le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        }))
    }

    fn u64(&self, off: u64) -> Result<Option<u64>> {
        if off.saturating_add(8) > self.avail {
            return Ok(None);
        }
        let mut b = [0u8; 8];
        if self.src.read_at(self.base + off, &mut b)? < 8 {
            return Ok(None);
        }
        Ok(Some(if self.le {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        }))
    }

    /// Read an offset-sized field: 8 bytes for BigTIFF, 4 for classic TIFF.
    fn ptr(&self, off: u64) -> Result<Option<u64>> {
        if self.big {
            self.u64(off)
        } else {
            Ok(self.u32(off)?.map(|v| v as u64))
        }
    }

    /// Byte offset of the value/offset field within a 12- (classic) or 20-byte
    /// (BigTIFF) IFD entry.
    fn value_field(&self, entry: u64) -> u64 {
        entry + if self.big { 12 } else { 8 }
    }

    /// Read up to `cap` integer values of an IFD entry. Values live inline when
    /// they fit in the value field (4 bytes classic, 8 bytes BigTIFF), otherwise
    /// at the offset stored there. Only integer types used for offsets and byte
    /// counts (1/2/4/8-byte) are read.
    fn entry_array(&self, entry: u64, typ: u16, count: u64, cap: u64) -> Result<Vec<u64>> {
        let sz = tiff_type_size(typ);
        if !(sz == 1 || sz == 2 || sz == 4 || sz == 8) || count == 0 {
            return Ok(Vec::new());
        }
        let n = count.min(cap);
        let total = n.saturating_mul(sz);
        let val_field = self.value_field(entry);
        let inline_cap = if self.big { 8 } else { 4 };
        let base = if count.saturating_mul(sz) <= inline_cap {
            val_field
        } else {
            match self.ptr(val_field)? {
                Some(o) => o,
                None => return Ok(Vec::new()),
            }
        };
        if base.saturating_add(total) > self.avail {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; total as usize];
        let got = self.src.read_at(self.base + base, &mut buf)?;
        let usable = (got as u64 / sz).min(n);
        let mut out = Vec::with_capacity(usable as usize);
        for j in 0..usable as usize {
            let o = j * sz as usize;
            let v = match sz {
                1 => buf[o] as u64,
                2 => {
                    let b = [buf[o], buf[o + 1]];
                    if self.le {
                        u16::from_le_bytes(b) as u64
                    } else {
                        u16::from_be_bytes(b) as u64
                    }
                }
                4 => {
                    let b = [buf[o], buf[o + 1], buf[o + 2], buf[o + 3]];
                    if self.le {
                        u32::from_le_bytes(b) as u64
                    } else {
                        u32::from_be_bytes(b) as u64
                    }
                }
                _ => {
                    let b: [u8; 8] = buf[o..o + 8].try_into().unwrap();
                    if self.le {
                        u64::from_le_bytes(b)
                    } else {
                        u64::from_be_bytes(b)
                    }
                }
            };
            out.push(v);
        }
        Ok(out)
    }
}

/// Byte size of a TIFF field type (0 for unknown/unsupported types).
fn tiff_type_size(typ: u16) -> u64 {
    match typ {
        1 | 2 | 6 | 7 => 1,   // BYTE, ASCII, SBYTE, UNDEFINED
        3 | 8 => 2,           // SHORT, SSHORT
        4 | 9 | 11 | 13 => 4, // LONG, SLONG, FLOAT, IFD
        5 | 10 | 12 => 8,     // RATIONAL, SRATIONAL, DOUBLE
        16..=18 => 8,         // LONG8, SLONG8, IFD8 (BigTIFF)
        _ => 0,
    }
}

/// Walk a TIFF's IFD chain (plus sub-IFDs) and return the furthest byte the
/// file references, which is its length. Returns `None` for a non-TIFF or a
/// coincidental magic with no usable IFD.
fn tiff_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    const MAX_IFDS: usize = 4096;
    const MAX_SUBIFDS: u64 = 64;
    const MAX_STRIPS: u64 = 1 << 20;
    let avail = limit - file_start;

    let mut hdr = [0u8; 8];
    if source.read_at(file_start, &mut hdr)? < 8 {
        return Ok(None);
    }
    let le = match &hdr[0..2] {
        b"II" => true,
        b"MM" => false,
        _ => return Ok(None),
    };
    // Detect classic TIFF (magic 42) vs BigTIFF (magic 43). They differ in
    // offset width, IFD-count width, and entry size.
    let magic = if le {
        u16::from_le_bytes([hdr[2], hdr[3]])
    } else {
        u16::from_be_bytes([hdr[2], hdr[3]])
    };
    let big = match magic {
        42 => false,
        43 => true,
        _ => return Ok(None),
    };
    let t = TiffReader {
        src: source,
        base: file_start,
        le,
        big,
        avail,
    };
    // BigTIFF: bytes 4-5 are the offset byte-size (8) and 6-7 are reserved (0).
    if big && (t.u16(4)?.unwrap_or(0) != 8 || t.u16(6)?.unwrap_or(1) != 0) {
        return Ok(None);
    }
    // Per-format layout constants: count-field width, entry size, offset width,
    // and the location of the first IFD offset.
    let (cnt_size, entry_size, ptr_size, header_end) = if big {
        (8u64, 20u64, 8u64, 16u64)
    } else {
        (2u64, 12u64, 4u64, 8u64)
    };
    let first = match if big {
        t.u64(8)?
    } else {
        t.u32(4)?.map(|v| v as u64)
    } {
        Some(v) => v,
        None => return Ok(None),
    };

    let mut max_end = header_end; // the header
    let mut visited = std::collections::HashSet::new();
    let mut queue = vec![first];
    let mut processed = 0usize;
    let mut budget: u32 = 1 << 20; // total entries scanned, bounds adversarial input

    while let Some(ifd) = queue.pop() {
        if ifd < header_end || !visited.insert(ifd) || processed >= MAX_IFDS {
            continue;
        }
        let count = match if big {
            t.u64(ifd)?
        } else {
            t.u16(ifd)?.map(|c| c as u64)
        } {
            Some(c) => c,
            None => continue,
        };
        processed += 1;
        // Extend by the IFD's own span, but only if it plausibly fits (a bogus
        // count must not inflate the result past the device).
        let span = ifd
            .saturating_add(cnt_size)
            .saturating_add(count.saturating_mul(entry_size))
            .saturating_add(ptr_size);
        if span <= avail {
            max_end = max_end.max(span);
        }

        // Strip/tile offset+bytecount pairs, captured then resolved together.
        let mut strip_off = None;
        let mut strip_cnt = None;
        let mut tile_off = None;
        let mut tile_cnt = None;

        for i in 0..count {
            if budget == 0 {
                break;
            }
            budget -= 1;
            let e = ifd + cnt_size + i * entry_size;
            let tag = match t.u16(e)? {
                Some(v) => v,
                None => break,
            };
            let typ = t.u16(e + 2)?.unwrap_or(0);
            let cnt = match if big {
                t.u64(e + 4)?
            } else {
                t.u32(e + 4)?.map(|v| v as u64)
            } {
                Some(v) => v,
                None => break,
            };
            let total = cnt.saturating_mul(tiff_type_size(typ));
            // Field data stored out-of-line extends the file.
            if total > ptr_size {
                if let Some(off) = t.ptr(t.value_field(e))? {
                    max_end = max_end.max(off.saturating_add(total));
                }
            }
            match tag {
                273 => strip_off = Some((typ, cnt, e)), // StripOffsets
                279 => strip_cnt = Some((typ, cnt, e)), // StripByteCounts
                324 => tile_off = Some((typ, cnt, e)),  // TileOffsets
                325 => tile_cnt = Some((typ, cnt, e)),  // TileByteCounts
                330 => {
                    // SubIFDs: an array of offsets to further IFDs.
                    for off in t.entry_array(e, typ, cnt, MAX_SUBIFDS)? {
                        queue.push(off);
                    }
                }
                34665 | 34853 => {
                    // Exif / GPS IFD pointer (a single offset).
                    if let Some(off) = t.entry_array(e, typ, cnt, 1)?.first() {
                        queue.push(*off);
                    }
                }
                _ => {}
            }
        }

        max_end = max_end.max(strip_tile_end(&t, strip_off, strip_cnt, MAX_STRIPS)?);
        max_end = max_end.max(strip_tile_end(&t, tile_off, tile_cnt, MAX_STRIPS)?);

        if let Some(next) = t.ptr(ifd + cnt_size + count.saturating_mul(entry_size))? {
            if next != 0 {
                queue.push(next);
            }
        }
    }

    if processed == 0 || max_end <= header_end || file_start + max_end > limit {
        return Ok(None);
    }
    Ok(Some(max_end))
}

/// Resolve a paired (offsets, byte-counts) set of strip or tile entries to the
/// furthest `offset[i] + bytecount[i]`.
fn strip_tile_end(
    t: &TiffReader,
    offsets: Option<(u16, u64, u64)>,
    counts: Option<(u16, u64, u64)>,
    cap: u64,
) -> Result<u64> {
    let (ot, oc, oe) = match offsets {
        Some(v) => v,
        None => return Ok(0),
    };
    let (ct, cc, ce) = match counts {
        Some(v) => v,
        None => return Ok(0),
    };
    let offs = t.entry_array(oe, ot, oc, cap)?;
    let lens = t.entry_array(ce, ct, cc, cap)?;
    let mut end = 0u64;
    for (o, l) in offs.iter().zip(lens.iter()) {
        end = end.max(o.saturating_add(*l));
    }
    Ok(end)
}

/// Compute a PE (Windows EXE/DLL) file's length. The MZ magic is only two
/// bytes, so the real gate here is finding the `PE\0\0` header via `e_lfanew`
/// and a sane section table; a coincidental "MZ" returns `None` and is skipped.
fn pe_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let avail = limit - file_start;
    let mut dos = [0u8; 64];
    if source.read_at(file_start, &mut dos)? < 64 || &dos[0..2] != b"MZ" {
        return Ok(None);
    }
    let e_lfanew = u32::from_le_bytes([dos[0x3C], dos[0x3D], dos[0x3E], dos[0x3F]]) as u64;
    // The PE header must lie past the DOS header and within the file.
    if e_lfanew < 64 || e_lfanew.saturating_add(24) > avail {
        return Ok(None);
    }

    // PE signature + 20-byte COFF file header.
    let mut coff = [0u8; 24];
    if source.read_at(file_start + e_lfanew, &mut coff)? < 24 || &coff[0..4] != b"PE\0\0" {
        return Ok(None);
    }
    let num_sections = u16::from_le_bytes([coff[6], coff[7]]) as u64;
    let opt_size = u16::from_le_bytes([coff[20], coff[21]]) as u64;
    if num_sections == 0 || num_sections > 96 {
        return Ok(None); // 96 is the PE-spec maximum
    }

    let opt_off = file_start + e_lfanew + 24;
    let sec_table_off = opt_off + opt_size;
    // The file spans at least its headers.
    let mut end = sec_table_off
        .saturating_add(num_sections.saturating_mul(40))
        .saturating_sub(file_start);

    let mut sh = [0u8; 40];
    for i in 0..num_sections {
        if source.read_at(sec_table_off + i * 40, &mut sh)? < 40 {
            break;
        }
        let size_raw = u32::from_le_bytes([sh[16], sh[17], sh[18], sh[19]]) as u64;
        let ptr_raw = u32::from_le_bytes([sh[20], sh[21], sh[22], sh[23]]) as u64;
        if ptr_raw != 0 {
            end = end.max(ptr_raw.saturating_add(size_raw));
        }
    }

    // The certificate (Authenticode) table, if present, is appended past the
    // sections; its directory entry holds a *file offset* (not an RVA) + size.
    if let Some(cert_end) = pe_cert_end(source, opt_off, opt_size)? {
        end = end.max(cert_end);
    }

    if end == 0 || file_start + end > limit {
        return Ok(None);
    }
    Ok(Some(end))
}

/// Read the PE optional header's certificate-table directory entry and return
/// `offset + size` if it points to an overlay, else `None`.
fn pe_cert_end(source: &Source, opt_off: u64, opt_size: u64) -> Result<Option<u64>> {
    if opt_size < 4 {
        return Ok(None);
    }
    let mut magic = [0u8; 2];
    if source.read_at(opt_off, &mut magic)? < 2 {
        return Ok(None);
    }
    // Data-directory base and NumberOfRvaAndSizes offset differ by PE flavour.
    let (numrva_off, dir_off) = match u16::from_le_bytes(magic) {
        0x10B => (92u64, 96u64),   // PE32
        0x20B => (108u64, 112u64), // PE32+
        _ => return Ok(None),
    };
    // The security directory is index 4, so the optional header must hold at
    // least five directory entries (8 bytes each).
    if opt_size < dir_off + 5 * 8 {
        return Ok(None);
    }
    let mut nb = [0u8; 4];
    if source.read_at(opt_off + numrva_off, &mut nb)? < 4 || u32::from_le_bytes(nb) <= 4 {
        return Ok(None);
    }
    let mut cert = [0u8; 8];
    if source.read_at(opt_off + dir_off + 4 * 8, &mut cert)? < 8 {
        return Ok(None);
    }
    let cert_off = u32::from_le_bytes([cert[0], cert[1], cert[2], cert[3]]) as u64;
    let cert_size = u32::from_le_bytes([cert[4], cert[5], cert[6], cert[7]]) as u64;
    if cert_off == 0 {
        return Ok(None);
    }
    Ok(Some(cert_off.saturating_add(cert_size)))
}

/// Compute an ELF file's length from its section-header table, which normally
/// sits at the end of the file. Handles 32/64-bit and either byte order.
fn elf_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let mut hdr = [0u8; 64];
    if source.read_at(file_start, &mut hdr)? < 52 {
        return Ok(None); // smaller than even a 32-bit ELF header
    }
    let is_64 = match hdr[4] {
        1 => false,
        2 => true,
        _ => return Ok(None),
    };
    let le = match hdr[5] {
        1 => true,
        2 => false,
        _ => return Ok(None),
    };
    let u16f = |b: &[u8]| {
        if le {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        }
    };
    let u32f = |b: &[u8]| {
        if le {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        }
    };
    let u64f = |b: &[u8]| {
        if le {
            u64::from_le_bytes(b[..8].try_into().unwrap())
        } else {
            u64::from_be_bytes(b[..8].try_into().unwrap())
        }
    };

    // Section-header-table offset, entry size, and entry count.
    let (sh_off, sh_entsize, sh_num) = if is_64 {
        (
            u64f(&hdr[0x28..0x30]),
            u16f(&hdr[0x3A..0x3C]) as u64,
            u16f(&hdr[0x3C..0x3E]) as u64,
        )
    } else {
        (
            u32f(&hdr[0x20..0x24]) as u64,
            u16f(&hdr[0x2E..0x30]) as u64,
            u16f(&hdr[0x30..0x32]) as u64,
        )
    };

    if sh_off == 0 || sh_num == 0 || sh_entsize == 0 {
        return Ok(None); // stripped of section headers; size not determinable here
    }
    let size = sh_off.saturating_add(sh_num.saturating_mul(sh_entsize));
    if size == 0 || file_start + size > limit {
        return Ok(None);
    }
    Ok(Some(size))
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
        if n < want || pos + n as u64 >= limit {
            // Reached the end of the search region without a footer. (The final
            // read was already searched above, so nothing was missed.) This also
            // guarantees forward progress: the advance below can be zero when the
            // tail read is `<= overlap` bytes, which would otherwise loop forever.
            return Ok(None);
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

/// Read the candidate's header and ask the type's validator whether it looks
/// like a real file. A short read (file smaller than the header window) just
/// means the validator sees fewer bytes and tends to abstain.
fn passes_validation(source: &Source, sig: &Signature, file_start: u64, len: u64) -> Result<bool> {
    let mut hdr = [0u8; HEADER_LEN];
    let take = (len as usize).min(HEADER_LEN);
    let n = source.read_at(file_start, &mut hdr[..take])?;
    Ok(validate::validate(sig, &hdr[..n]).accept())
}

/// Stream `len` bytes from the source at `file_start` into a new output file,
/// hashing as we go. With `--dedup` set, a file whose content was already
/// written this run is removed again and counted as a duplicate.
#[allow(clippy::too_many_arguments)]
fn write_file(
    source: &Source,
    sig: &Signature,
    file_start: u64,
    len: u64,
    opts: &CarveOptions,
    stats: &mut CarveStats,
    buf: &mut Vec<u8>,
    seen: &mut HashSet<[u8; 32]>,
) -> Result<()> {
    let base = format!(
        "{:08}_{:#016x}.{}",
        stats.files_recovered, file_start, sig.ext
    );
    // With `--organize`, group files into a per-type subdirectory; the manifest
    // name keeps the `<ext>/` prefix so `verify` still resolves it.
    let (name, path): (String, PathBuf) = if opts.organize {
        (
            format!("{}/{}", sig.ext, base),
            opts.output_dir.join(sig.ext).join(&base),
        )
    } else {
        (base.clone(), opts.output_dir.join(&base))
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut out =
        fs::File::create(&path).with_context(|| format!("creating {}", path.display()))?;

    let mut remaining = len;
    let mut pos = file_start;
    let mut hasher = Sha256::new();
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
        hasher.update(&buf[..n]);
        remaining -= n as u64;
        pos += n as u64;
    }
    out.flush().ok();

    let digest = hasher.finalize();
    if opts.dedup && !seen.insert(digest) {
        // Identical content already recovered; discard this copy.
        drop(out);
        fs::remove_file(&path).ok();
        stats.duplicates += 1;
        return Ok(());
    }

    let written = len - remaining;
    stats.files_recovered += 1;
    stats.bytes_recovered += written;
    *stats.per_type.entry(sig.ext).or_insert(0) += 1;
    stats.files.push(CarvedFile {
        name,
        ext: sig.ext,
        offset: file_start,
        size: written,
        sha256: digest,
    });
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
    /// Whether the caller has requested cancellation. The scan loop checks this
    /// once per chunk and stops early, returning what it has recovered so far.
    fn cancelled(&self) -> bool {
        false
    }
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
