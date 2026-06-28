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
    /// Ignore carved files larger than this many bytes (`None` = no cap). This
    /// gates the *computed* file length, on top of each type's built-in
    /// `max_size` runaway guard, so a run can skip large files entirely.
    pub max_size: Option<u64>,
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
    /// Preview only: find recoverable files and tally them (counts, sizes,
    /// per-type, and the manifest records) without writing any output. Useful
    /// for sizing up a device before committing disk space to a real recovery.
    pub dry_run: bool,
    /// Only accept candidates whose start offset is a multiple of this many
    /// bytes (1 = every offset). Files inside a filesystem begin on cluster
    /// (sector-multiple) boundaries, so a sector alignment like 512 discards
    /// the coincidental mid-sector magic matches that produce false positives.
    pub align: u64,
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
    /// Recognised files skipped because they exceeded the `--max-size` cap.
    pub skipped_large: u64,
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
    if !opts.dry_run {
        fs::create_dir_all(&opts.output_dir)
            .with_context(|| format!("creating output dir {}", opts.output_dir.display()))?;
    }

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
                // Optional sector/cluster alignment: real files inside a
                // filesystem start on a cluster boundary, so an unaligned start
                // is almost always a coincidental magic match.
                let aligned = opts.align <= 1 || file_start % opts.align == 0;

                if valid_start && aligned && (opts.allow_nested || file_start >= skip_until) {
                    if let Some(len) =
                        file_length(source, sig, file_start, scan_end, &mut footer_buf)?
                    {
                        if len >= opts.min_size {
                            if opts.max_size.is_some_and(|max| len > max) {
                                // Recognised but over the run's size cap: skip past
                                // it without writing, so its interior isn't
                                // rescanned for nested magics.
                                stats.skipped_large += 1;
                                if !opts.allow_nested {
                                    skip_until = file_start + len;
                                }
                            } else if opts.validate
                                && !passes_validation(source, sig, file_start, len)?
                            {
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
        Extent::Wmf => Ok(wmf_length(source, file_start, limit)?),
        Extent::Djvu => Ok(djvu_length(source, file_start, limit)?),
        Extent::Evtx => Ok(evtx_length(source, file_start, limit)?),
        Extent::Rtf => Ok(rtf_length(source, file_start, limit)?),
        Extent::Mp3 => Ok(mp3_length(source, file_start, limit)?),
        Extent::MachO => Ok(macho_length(source, file_start, limit)?),
        Extent::Regf => Ok(regf_length(source, file_start, limit)?),
        Extent::Aac => Ok(aac_length(source, file_start, limit)?),
        Extent::Dex => Ok(dex_length(source, file_start, limit)?),
        Extent::Icc => Ok(icc_length(source, file_start, limit)?),
        Extent::Ar => Ok(ar_length(source, file_start, limit)?),
        Extent::Shp => Ok(shp_length(source, file_start, limit)?),
        Extent::Blend => Ok(blend_length(source, file_start, limit)?),
        Extent::Nes => Ok(nes_length(source, file_start, limit)?),
        Extent::Mp3Raw => Ok(mp3_raw_length(source, file_start, limit)?),
        Extent::Jpeg => Ok(jpeg_length(source, file_start, limit)?),
        Extent::Zip => Ok(zip_length(source, file_start, limit)?),
        Extent::Gif => Ok(gif_length(source, file_start, limit)?),
        Extent::Wim => Ok(wim_length(source, file_start, limit)?),
        Extent::Swf => Ok(swf_length(source, file_start, limit)?),
        Extent::Cfbf => Ok(cfbf_length(source, file_start, limit)?),
        Extent::Pst => Ok(pst_length(source, file_start, limit)?),
        Extent::Tar => Ok(tar_length(source, file_start, limit)?),
        Extent::Cpio => Ok(cpio_length(source, file_start, limit)?),
        Extent::Squashfs => Ok(squashfs_length(source, file_start, limit)?),
        Extent::Mpegts => Ok(mpegts_length(source, file_start, limit)?),
    }
}

/// Uncompressed Flash movie (`FWS`) length. The 8-byte header is `FWS`, a 1-byte
/// version, then the total file length as a little-endian u32 at offset 4. The
/// version must be non-zero and the length at least the header size, which
/// rejects a coincidental `FWS` magic.
fn swf_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let mut h = [0u8; 8];
    if source.read_at(file_start, &mut h)? < 8 || &h[0..3] != b"FWS" {
        return Ok(None);
    }
    if h[3] == 0 {
        return Ok(None); // version 0 does not exist
    }
    let size = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as u64;
    if size < 8 || file_start.saturating_add(size) > limit {
        return Ok(None);
    }
    Ok(Some(size))
}

/// Windows Imaging Format (WIM) length. The 208-byte header carries a resource
/// header — an 8-byte (56-bit size + 8-bit flags) field plus an 8-byte offset —
/// for the offset/lookup table (at 0x30), XML data (0x48), boot metadata (0x60),
/// and integrity table (0x7C). The file ends at the furthest `offset + size` of
/// these; one of them (normally the integrity table or XML data) is the last
/// structure in the file, and every file-data resource lies before it. The
/// header size field (0xD0 at offset 8) is checked to reject a coincidental
/// magic.
fn wim_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let mut h = [0u8; 148]; // through the end of the integrity resource header
    if source.read_at(file_start, &mut h)? < 148 || &h[0..8] != b"MSWIM\x00\x00\x00" {
        return Ok(None);
    }
    // The header records its own size; the WIM v1 header is 208 (0xD0) bytes.
    let cb_size = u32::from_le_bytes([h[8], h[9], h[10], h[11]]);
    if cb_size != 0xD0 {
        return Ok(None);
    }
    // Each resource header: 8 bytes of (56-bit size | 8-bit flags) then an
    // 8-byte offset. Return the resource's furthest extent, or None when absent.
    let extent_of = |off: usize| -> u64 {
        let raw = u64::from_le_bytes(h[off..off + 8].try_into().unwrap());
        let size = raw & 0x00FF_FFFF_FFFF_FFFF;
        let offset = u64::from_le_bytes(h[off + 8..off + 16].try_into().unwrap());
        if offset == 0 {
            0
        } else {
            offset.saturating_add(size)
        }
    };

    let mut end = u64::from(cb_size); // at least the header
    for off in [0x30, 0x48, 0x60, 0x7C] {
        end = end.max(extent_of(off));
    }
    if end <= u64::from(cb_size) {
        return Ok(None); // no resources -> not a usable WIM
    }
    if file_start.saturating_add(end) > limit {
        return Ok(None);
    }
    Ok(Some(end))
}

/// GIF length. Walk the block stream — the 13-byte header/logical-screen
/// descriptor (and an optional global colour table), then image (`0x2C`) and
/// extension (`0x21`) blocks (each ending in a chain of length-prefixed
/// sub-blocks) — to the trailer byte (`0x3B`), which ends the file. Walking the
/// structure avoids stopping at a `00 3B` byte pair that occurs by chance inside
/// the LZW-compressed image data.
fn gif_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let avail = limit.saturating_sub(file_start);
    let mut hdr = [0u8; 13];
    if source.read_at(file_start, &mut hdr)? < 13 || &hdr[0..3] != b"GIF" {
        return Ok(None);
    }
    // Colour-table size encoded in a packed byte: present iff bit 7 is set, with
    // 3 * 2^(n+1) bytes where n is the low three bits.
    let color_table = |packed: u8| -> u64 {
        if packed & 0x80 != 0 {
            3 * (1u64 << ((packed & 0x07) + 1))
        } else {
            0
        }
    };

    let mut pos = 13u64 + color_table(hdr[10]); // global colour table
    loop {
        if pos >= avail {
            return Ok(None);
        }
        let mut b = [0u8; 1];
        if source.read_at(file_start + pos, &mut b)? < 1 {
            return Ok(None);
        }
        pos += 1;
        match b[0] {
            0x3B => return Ok(Some(pos)), // trailer: the file ends here
            0x2C => {
                // Image descriptor: 9 bytes, then an optional local colour table.
                let mut d = [0u8; 9];
                if pos + 9 > avail || source.read_at(file_start + pos, &mut d)? < 9 {
                    return Ok(None);
                }
                pos += 9 + color_table(d[8]);
                // LZW minimum-code-size byte, then the image data sub-blocks.
                if pos >= avail {
                    return Ok(None);
                }
                pos += 1;
                pos = match gif_skip_subblocks(source, file_start, pos, avail)? {
                    Some(p) => p,
                    None => return Ok(None),
                };
            }
            0x21 => {
                // Extension: a 1-byte label, then its sub-block chain.
                if pos >= avail {
                    return Ok(None);
                }
                pos += 1;
                pos = match gif_skip_subblocks(source, file_start, pos, avail)? {
                    Some(p) => p,
                    None => return Ok(None),
                };
            }
            _ => return Ok(None), // not a valid block introducer
        }
    }
}

/// Advance past a GIF sub-block chain: a sequence of (1-byte length, that many
/// bytes) runs ending in a zero-length block terminator. Returns the position
/// just past the terminator.
fn gif_skip_subblocks(
    source: &Source,
    file_start: u64,
    mut pos: u64,
    avail: u64,
) -> Result<Option<u64>> {
    loop {
        if pos >= avail {
            return Ok(None);
        }
        let mut len = [0u8; 1];
        if source.read_at(file_start + pos, &mut len)? < 1 {
            return Ok(None);
        }
        pos += 1;
        if len[0] == 0 {
            return Ok(Some(pos)); // block terminator
        }
        pos += len[0] as u64;
        if pos > avail {
            return Ok(None);
        }
    }
}

/// ZIP length. Locate the End-of-Central-Directory record (`PK\x05\x06`) and end
/// the file after it plus its declared comment. The EOCD records the central
/// directory's size and offset; the record whose geometry matches this archive
/// (`file_start + cd_offset + cd_size == eocd_pos`) is the archive's own — this
/// skips the EOCD of a ZIP nested *inside* the archive, which a first-match
/// search would wrongly stop at, and rejects a coincidental marker. A ZIP64
/// archive (whose 32-bit geometry fields are `0xFFFFFFFF` sentinels) can't be
/// validated this way, so the last such candidate is used as a best effort.
fn zip_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    const EOCD: &[u8] = &[0x50, 0x4B, 0x05, 0x06];
    let window = 1024 * 1024usize;
    let overlap = EOCD.len() - 1;
    let mut buf = vec![0u8; window + overlap];
    let mut pos = file_start;
    let mut zip64_best: Option<u64> = None; // fallback end offset for ZIP64
    loop {
        if pos >= limit {
            break;
        }
        let want = ((limit - pos) as usize).min(window + overlap);
        let n = source.read_at(pos, &mut buf[..want])?;
        if n == 0 {
            break;
        }
        let mut from = 0usize;
        while let Some(rel) = find_subsequence(&buf[from..n], EOCD) {
            let idx = from + rel;
            let eocd_abs = pos + idx as u64;
            let mut e = [0u8; 22];
            if source.read_at(eocd_abs, &mut e)? >= 22 {
                let cd_size = u32::from_le_bytes([e[12], e[13], e[14], e[15]]) as u64;
                let cd_off = u32::from_le_bytes([e[16], e[17], e[18], e[19]]) as u64;
                let comment_len = u16::from_le_bytes([e[20], e[21]]) as u64;
                let end = eocd_abs + 22 + comment_len;
                let is_zip64 = cd_size == 0xFFFF_FFFF || cd_off == 0xFFFF_FFFF;
                if end <= limit {
                    if !is_zip64 && file_start + cd_off + cd_size == eocd_abs {
                        // This EOCD describes the archive that starts at file_start.
                        return Ok(Some(end - file_start));
                    }
                    if is_zip64 {
                        zip64_best = Some(end - file_start);
                    }
                }
            }
            from = idx + EOCD.len();
        }
        if n < want || pos + n as u64 >= limit {
            break;
        }
        pos += (n - overlap) as u64;
    }
    Ok(zip64_best)
}

/// JPEG length. Scan for the End-of-Image marker (`FF D9`), tracking nested
/// Start-of-Image markers (`FF D8`) so an embedded thumbnail's EOI does not end
/// the carve early; the file ends at the EOI that closes the outer image. Within
/// JPEG entropy-coded data an `FF` is always stuffed (`FF 00`) or a restart
/// marker (`FF D0`–`FF D7`), so `FF D8`/`FF D9` only ever mark real image
/// boundaries.
fn jpeg_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let mut soi = [0u8; 3];
    if source.read_at(file_start, &mut soi)? < 3 || soi[0] != 0xFF || soi[1] != 0xD8 {
        return Ok(None);
    }
    const WINDOW: usize = 1 << 20;
    const OVERLAP: usize = 1; // a marker is two bytes, so carry one byte over
    let mut buf = vec![0u8; WINDOW + OVERLAP];
    let mut pos = file_start + 2; // start scanning just past the outer SOI
    let mut depth: u32 = 0; // nested SOI/EOI pairs currently open
    loop {
        if pos >= limit {
            return Ok(None);
        }
        let want = ((limit - pos) as usize).min(WINDOW + OVERLAP);
        let n = source.read_at(pos, &mut buf[..want])?;
        if n == 0 {
            return Ok(None);
        }
        let mut i = 0;
        while i + 1 < n {
            if buf[i] != 0xFF {
                i += 1;
                continue;
            }
            match buf[i + 1] {
                0xD8 => {
                    depth += 1;
                    i += 2;
                }
                0xD9 => {
                    if depth == 0 {
                        return Ok(Some((pos - file_start) + i as u64 + 2));
                    }
                    depth -= 1;
                    i += 2;
                }
                _ => i += 1,
            }
        }
        if pos + n as u64 >= limit {
            // Scanned to the end of the source without a closing EOI.
            return Ok(None);
        }
        // Re-examine the final (unpaired) byte at the head of the next window.
        pos += (n - OVERLAP) as u64;
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

/// RTF document length. The whole document is a single `{ ... }` group; the
/// file ends where the opening brace's match closes. A backslash escapes the
/// next byte (`\{`, `\}`, `\\`), so those do not affect the brace depth.
fn rtf_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    const CHUNK: usize = 1 << 16;
    let avail = limit.saturating_sub(file_start);
    let mut buf = vec![0u8; CHUNK];
    let mut pos = 0u64;
    let mut depth: i64 = 0;
    let mut after_backslash = false;
    while pos < avail {
        let want = (avail - pos).min(CHUNK as u64) as usize;
        let n = source.read_at(file_start + pos, &mut buf[..want])?;
        if n == 0 {
            break;
        }
        for (k, &b) in buf[..n].iter().enumerate() {
            if after_backslash {
                after_backslash = false;
            } else if b == b'\\' {
                after_backslash = true;
            } else if b == b'{' {
                depth += 1;
            } else if b == b'}' {
                depth -= 1;
                if depth == 0 {
                    return Ok(Some(pos + k as u64 + 1));
                }
                if depth < 0 {
                    return Ok(None);
                }
            }
        }
        pos += n as u64;
    }
    Ok(None)
}

/// Decode the length in bytes of a single MPEG audio frame from its 4-byte
/// header, or `None` if the header is not a valid MPEG-1/2/2.5 Layer I/II/III
/// frame sync. The four bytes are:
/// `FF Ex` (11-bit sync) then version/layer/CRC, bitrate/sample-rate/padding.
fn frame_length(hdr: &[u8; 4]) -> Option<u64> {
    // Bitrate tables (kbps), indexed by [layer_idx][bitrate_index].
    // layer_idx: 0 = Layer I, 1 = Layer II, 2 = Layer III.
    const BITRATE_V1: [[u32; 16]; 3] = [
        [
            0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0,
        ],
        [
            0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0,
        ],
        [
            0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0,
        ],
    ];
    // MPEG 2 / 2.5: Layer II and Layer III share a column.
    const BITRATE_V2: [[u32; 16]; 3] = [
        [
            0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0,
        ],
        [
            0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0,
        ],
        [
            0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0,
        ],
    ];
    // Sample rate (Hz), indexed by [version][sample_rate_index].
    // version field: 0 = MPEG 2.5, 2 = MPEG 2, 3 = MPEG 1 (1 is reserved).
    const SAMPLERATE: [[u32; 3]; 4] = [
        [11025, 12000, 8000],  // MPEG 2.5
        [0, 0, 0],             // reserved
        [22050, 24000, 16000], // MPEG 2
        [44100, 48000, 32000], // MPEG 1
    ];

    if hdr[0] != 0xFF || (hdr[1] & 0xE0) != 0xE0 {
        return None;
    }
    let version = (hdr[1] >> 3) & 0x03; // 0=2.5, 1=reserved, 2=v2, 3=v1
    if version == 1 {
        return None;
    }
    let layer_field = (hdr[1] >> 1) & 0x03; // 0=reserved, 1=III, 2=II, 3=I
    if layer_field == 0 {
        return None;
    }
    let br_idx = ((hdr[2] >> 4) & 0x0F) as usize;
    if br_idx == 0 || br_idx == 15 {
        return None; // free-format and "bad" are unsupported
    }
    let sr_idx = ((hdr[2] >> 2) & 0x03) as usize;
    if sr_idx == 3 {
        return None;
    }
    let pad = ((hdr[2] >> 1) & 0x01) as u64;

    let layer_idx = (3 - layer_field) as usize; // I->0, II->1, III->2
    let bitrate = if version == 3 {
        BITRATE_V1[layer_idx][br_idx]
    } else {
        BITRATE_V2[layer_idx][br_idx]
    } as u64
        * 1000;
    let samplerate = SAMPLERATE[version as usize][sr_idx] as u64;
    if bitrate == 0 || samplerate == 0 {
        return None;
    }

    // Frame length in bytes per layer.
    let len = match layer_field {
        3 => (12 * bitrate / samplerate + pad) * 4, // Layer I
        2 => 144 * bitrate / samplerate + pad,      // Layer II
        1 => {
            let coef = if version == 3 { 144 } else { 72 }; // Layer III
            coef * bitrate / samplerate + pad
        }
        _ => return None,
    };
    if len < 4 {
        return None;
    }
    Some(len)
}

/// MP3 length. Anchored on an ID3v2 tag (`ID3`), the audio is sized by walking
/// the MPEG frames. The ID3v2 header at offset 0 carries a synchsafe 28-bit
/// size (bytes 6..10) plus a 10-byte footer when flag 0x10 is set; the audio
/// begins right after. Each frame's length comes from [`frame_length`]; the
/// walk stops at the first non-frame byte, picking up a trailing 128-byte
/// ID3v1 (`TAG`) tag when present. At least three valid frames are required so
/// the 3-byte `ID3` magic cannot trigger a false carve.
fn mp3_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let avail = limit.saturating_sub(file_start);
    let mut id3 = [0u8; 10];
    if source.read_at(file_start, &mut id3)? < 10 || &id3[0..3] != b"ID3" {
        return Ok(None);
    }
    // Synchsafe size: 4 bytes, 7 bits each, big-endian.
    if id3[6] & 0x80 != 0 || id3[7] & 0x80 != 0 || id3[8] & 0x80 != 0 || id3[9] & 0x80 != 0 {
        return Ok(None);
    }
    let tag_size = ((id3[6] as u64) << 21)
        | ((id3[7] as u64) << 14)
        | ((id3[8] as u64) << 7)
        | (id3[9] as u64);
    let footer = if id3[5] & 0x10 != 0 { 10 } else { 0 };
    let audio_start = 10u64.saturating_add(tag_size).saturating_add(footer);
    if audio_start >= avail {
        return Ok(None);
    }

    let (pos, frames) = walk_mp3_frames(source, file_start, audio_start, avail)?;
    // The tag is a strong anchor, so a few frames suffice to confirm it.
    if frames < 3 || pos > avail {
        return Ok(None);
    }
    Ok(Some(pos))
}

/// MP3 length when anchored directly on an MPEG frame sync (no ID3v2 tag), for
/// the many MP3s that carry only an ID3v1 trailer or no tag at all. The frame
/// sync is just 11 bits, so a longer run of consecutive valid frames is required
/// than for the tag-anchored case, to avoid a false carve in arbitrary data.
fn mp3_raw_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let avail = limit.saturating_sub(file_start);
    let (pos, frames) = walk_mp3_frames(source, file_start, 0, avail)?;
    const MIN_FRAMES: u64 = 8;
    if frames < MIN_FRAMES || pos > avail {
        return Ok(None);
    }
    Ok(Some(pos))
}

/// Walk MPEG audio frames starting at `audio_start` (relative to `file_start`),
/// using [`frame_length`] for each frame, until a non-frame byte or the bounds.
/// A trailing ID3v1 (`TAG`) tag is included. Returns the end offset (relative to
/// `file_start`) and the number of frames walked.
fn walk_mp3_frames(
    source: &Source,
    file_start: u64,
    audio_start: u64,
    avail: u64,
) -> Result<(u64, u64)> {
    let mut pos = audio_start;
    let mut frames = 0u64;
    loop {
        let mut hdr = [0u8; 4];
        let n = source.read_at(file_start + pos, &mut hdr)?;
        if n < 4 {
            break;
        }
        if &hdr[0..3] == b"TAG" {
            // ID3v1 trailer.
            pos = pos.saturating_add(128);
            break;
        }
        match frame_length(&hdr) {
            Some(len) => {
                let next = pos.saturating_add(len);
                if next > avail {
                    break;
                }
                pos = next;
                frames += 1;
            }
            None => break,
        }
    }
    Ok((pos, frames))
}

/// Windows Event Log (EVTX) length. A 4096-byte `ElfFile` header records the
/// number of 64 KiB chunks at offset 0x2A, so the file ends at
/// `4096 + chunks * 65536`. The header block size (0x1000) and header size
/// (0x80) are checked to reject a coincidental magic.
fn evtx_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let mut h = [0u8; 48];
    if source.read_at(file_start, &mut h)? < 48 || &h[0..8] != b"ElfFile\x00" {
        return Ok(None);
    }
    let header_size = u32::from_le_bytes([h[0x20], h[0x21], h[0x22], h[0x23]]);
    let header_block_size = u16::from_le_bytes([h[0x28], h[0x29]]);
    if header_size != 0x80 || header_block_size != 0x1000 {
        return Ok(None);
    }
    let chunks = u16::from_le_bytes([h[0x2A], h[0x2B]]) as u64;
    if chunks == 0 {
        return Ok(None);
    }
    let total = 4096 + chunks.saturating_mul(65536);
    if file_start.saturating_add(total) > limit {
        return Ok(None);
    }
    Ok(Some(total))
}

/// DjVu document length. The file is an IFF `FORM` wrapped in a 4-byte `AT&T`
/// prefix: `"AT&T" "FORM" <be32 length> <form-type> ...`. The big-endian length
/// at offset 8 covers everything after it, so the file ends at `12 + length`.
/// The form type must be a known DjVu chunk to reject a coincidental magic.
fn djvu_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let mut h = [0u8; 16];
    if source.read_at(file_start, &mut h)? < 16 || &h[0..8] != b"AT&TFORM" {
        return Ok(None);
    }
    let form_type = &h[12..16];
    if !matches!(form_type, b"DJVU" | b"DJVM" | b"DJVI") {
        return Ok(None);
    }
    let length = u32::from_be_bytes([h[8], h[9], h[10], h[11]]) as u64;
    let total = length.saturating_add(12);
    if length < 4 || file_start.saturating_add(total) > limit {
        return Ok(None);
    }
    Ok(Some(total))
}

/// Windows Metafile (WMF) length. A 22-byte placeable header (Aldus, magic
/// `D7 CD C6 9A`) may precede the standard `METAHEADER`, whose `mtSize` field is
/// the metafile size in 16-bit words. The file ends at `[placeable] + mtSize*2`.
fn wmf_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let mut h = [0u8; 32];
    let n = source.read_at(file_start, &mut h)?;
    if n < 6 {
        return Ok(None);
    }
    let le16 = |b: &[u8], o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
    let le32 = |b: &[u8], o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as u64;

    // Placeable (APM) header: 22 bytes, then a standard METAHEADER at offset 22
    // whose mtSize (u32, words) sits at offset 22 + 6 = 28.
    if h[0..4] == [0xD7, 0xCD, 0xC6, 0x9A] {
        if n < 32 {
            return Ok(None);
        }
        let mt_size = le32(&h, 28);
        if mt_size < 9 {
            return Ok(None); // mtSize counts the 9-word header at minimum
        }
        let total = 22 + mt_size.saturating_mul(2);
        if file_start.saturating_add(total) > limit {
            return Ok(None);
        }
        return Ok(Some(total));
    }

    // Standard METAHEADER: mtType (1 or 2), mtHeaderSize == 9 words,
    // mtVersion (0x0100 or 0x0300), mtSize (u32, words) at offset 6.
    if n < 10 {
        return Ok(None);
    }
    let mt_type = le16(&h, 0);
    let header_words = le16(&h, 2);
    let version = le16(&h, 4);
    if !matches!(mt_type, 1 | 2) || header_words != 9 || !matches!(version, 0x0100 | 0x0300) {
        return Ok(None);
    }
    let mt_size = le32(&h, 6);
    if mt_size < 9 {
        return Ok(None);
    }
    let total = mt_size.saturating_mul(2);
    if file_start.saturating_add(total) > limit {
        return Ok(None);
    }
    Ok(Some(total))
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

/// Mach-O (thin) length. Read the header to find the load-command region, then
/// walk the commands taking the furthest extent of every segment
/// (`fileoff + filesize`) and link-edit table (symbol/string tables and
/// `dataoff + datasize` blobs such as the code signature). Handles 32/64-bit
/// and either byte order; fat/universal binaries are not handled here.
fn macho_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let mut magic = [0u8; 4];
    if source.read_at(file_start, &mut magic)? < 4 {
        return Ok(None);
    }
    let (is_64, le) = match magic {
        [0xCF, 0xFA, 0xED, 0xFE] => (true, true),
        [0xCE, 0xFA, 0xED, 0xFE] => (false, true),
        [0xFE, 0xED, 0xFA, 0xCF] => (true, false),
        [0xFE, 0xED, 0xFA, 0xCE] => (false, false),
        _ => return Ok(None),
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

    // mach_header(_64): magic, cputype, cpusubtype, filetype, ncmds,
    // sizeofcmds, flags, (reserved on 64-bit). ncmds@16, sizeofcmds@20.
    let header_size: u64 = if is_64 { 32 } else { 28 };
    let mut hdr = [0u8; 32];
    if source.read_at(file_start, &mut hdr[..header_size as usize])? < header_size as usize {
        return Ok(None);
    }
    let ncmds = u32f(&hdr[16..20]) as u64;
    let sizeofcmds = u32f(&hdr[20..24]) as u64;
    if ncmds == 0 || sizeofcmds == 0 {
        return Ok(None);
    }
    // Sanity bound on the load-command region so a coincidental magic can't make
    // us read megabytes of junk.
    if sizeofcmds > 16 * 1024 * 1024 || ncmds > 1_000_000 {
        return Ok(None);
    }
    let cmds_end = header_size.saturating_add(sizeofcmds);
    if file_start.saturating_add(cmds_end) > limit {
        return Ok(None);
    }

    let mut cmds = vec![0u8; sizeofcmds as usize];
    if source.read_at(file_start + header_size, &mut cmds)? < cmds.len() {
        return Ok(None);
    }

    // Load-command identifiers (low bits; LC_REQ_DYLD high bit ignored here).
    const LC_SEGMENT: u32 = 0x1;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_SYMTAB: u32 = 0x2;
    // Commands whose payload is a linkedit_data_command (cmd, cmdsize, dataoff,
    // datasize): code signature, function starts, data-in-code, chained fixups,
    // exports trie, etc. The code signature in particular ends most binaries.
    const LINKEDIT_DATA: &[u32] = &[
        0x1D,               // LC_CODE_SIGNATURE
        0x1E,               // LC_SEGMENT_SPLIT_INFO
        0x26,               // LC_FUNCTION_STARTS
        0x29,               // LC_DATA_IN_CODE
        0x2B,               // LC_DYLIB_CODE_SIGN_DRS
        0x2E,               // LC_LINKER_OPTIMIZATION_HINT
        0x33 | 0x8000_0000, // LC_DYLD_EXPORTS_TRIE (REQ_DYLD)
        0x34 | 0x8000_0000, // LC_DYLD_CHAINED_FIXUPS (REQ_DYLD)
    ];

    let mut end = cmds_end;
    let mut off = 0usize;
    for _ in 0..ncmds {
        if off + 8 > cmds.len() {
            break;
        }
        let cmd = u32f(&cmds[off..off + 4]);
        let cmdsize = u32f(&cmds[off + 4..off + 8]) as usize;
        // cmdsize must be 4-byte aligned and advance the cursor.
        if cmdsize < 8 || cmdsize % 4 != 0 || off + cmdsize > cmds.len() {
            return Ok(None);
        }
        let body = &cmds[off..off + cmdsize];
        match cmd {
            LC_SEGMENT => {
                // segment_command: ... fileoff@32, filesize@36 (u32).
                if cmdsize >= 56 {
                    let fileoff = u32f(&body[32..36]) as u64;
                    let filesize = u32f(&body[36..40]) as u64;
                    end = end.max(fileoff.saturating_add(filesize));
                }
            }
            LC_SEGMENT_64 => {
                // segment_command_64: ... fileoff@40, filesize@48 (u64).
                if cmdsize >= 72 {
                    let fileoff = u64f(&body[40..48]);
                    let filesize = u64f(&body[48..56]);
                    end = end.max(fileoff.saturating_add(filesize));
                }
            }
            LC_SYMTAB => {
                // symtab_command: symoff@8, nsyms@12, stroff@16, strsize@20.
                if cmdsize >= 24 {
                    let symoff = u32f(&body[8..12]) as u64;
                    let nsyms = u32f(&body[12..16]) as u64;
                    let stroff = u32f(&body[16..20]) as u64;
                    let strsize = u32f(&body[20..24]) as u64;
                    let symsize = if is_64 { 16 } else { 12 };
                    end = end.max(symoff.saturating_add(nsyms.saturating_mul(symsize)));
                    end = end.max(stroff.saturating_add(strsize));
                }
            }
            c if LINKEDIT_DATA.contains(&c) && cmdsize >= 16 => {
                // linkedit_data_command: dataoff@8, datasize@12.
                let dataoff = u32f(&body[8..12]) as u64;
                let datasize = u32f(&body[12..16]) as u64;
                end = end.max(dataoff.saturating_add(datasize));
            }
            _ => {}
        }
        off += cmdsize;
    }

    if end == 0 || file_start.saturating_add(end) > limit {
        return Ok(None);
    }
    Ok(Some(end))
}

/// Windows registry hive (`regf`) length. The 4096-byte base block records the
/// total size of the hive-bins data area (a little-endian u32 at offset 0x28),
/// so the file ends at `4096 + hive_bins_data_size`. The major version (1), the
/// file type (0 = primary hive), and the 4096-alignment of the data size are
/// checked to reject a coincidental `regf` magic.
fn regf_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    const BASE_BLOCK: u64 = 4096;
    let mut h = [0u8; 48];
    if source.read_at(file_start, &mut h)? < 48 || &h[0..4] != b"regf" {
        return Ok(None);
    }
    let major = u32::from_le_bytes([h[0x14], h[0x15], h[0x16], h[0x17]]);
    let file_type = u32::from_le_bytes([h[0x1C], h[0x1D], h[0x1E], h[0x1F]]);
    let hbins_size = u32::from_le_bytes([h[0x28], h[0x29], h[0x2A], h[0x2B]]) as u64;
    // A primary hive has major version 1 and file type 0; the hive-bins data is
    // made of 4096-byte bins, so its total size is a non-zero multiple of 4096.
    if major != 1 || file_type != 0 || hbins_size == 0 || hbins_size % BASE_BLOCK != 0 {
        return Ok(None);
    }
    let total = BASE_BLOCK.saturating_add(hbins_size);
    if file_start.saturating_add(total) > limit {
        return Ok(None);
    }
    Ok(Some(total))
}

/// ADTS AAC length. Each frame begins with a 7-byte header (9 with CRC) whose
/// bytes 3..6 carry a 13-bit frame length (header included), so the stream is
/// walked frame to frame to its end. Each header is validated — sync word
/// 0xFFF, layer bits 00, a sample-rate index in range (0..=12) and consistent
/// across the stream — and at least four consecutive valid frames are required,
/// so the short sync word cannot trigger a false carve.
fn aac_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    const MIN_FRAMES: u64 = 4;
    let avail = limit.saturating_sub(file_start);
    let mut pos = 0u64;
    let mut frames = 0u64;
    let mut ref_sr: Option<u8> = None;
    loop {
        let mut hdr = [0u8; 7];
        if source.read_at(file_start + pos, &mut hdr)? < 7 {
            break;
        }
        // Sync word 0xFFF and layer bits (byte1 bits 2..1) == 00.
        if hdr[0] != 0xFF || (hdr[1] & 0xF6) != 0xF0 {
            break;
        }
        let sr_idx = (hdr[2] >> 2) & 0x0F;
        if sr_idx > 12 {
            break;
        }
        match ref_sr {
            Some(r) if r != sr_idx => break,
            _ => ref_sr = Some(sr_idx),
        }
        let frame_len =
            (((hdr[3] & 0x03) as u64) << 11) | ((hdr[4] as u64) << 3) | ((hdr[5] as u64) >> 5);
        if frame_len < 7 {
            break;
        }
        let next = pos.saturating_add(frame_len);
        if next > avail {
            break;
        }
        pos = next;
        frames += 1;
    }
    if frames < MIN_FRAMES {
        return Ok(None);
    }
    Ok(Some(pos))
}

/// MPEG transport stream (.ts) length. A TS is a run of fixed 188-byte packets,
/// each starting with the sync byte `0x47`; the packets are walked to the first
/// boundary without the sync byte, so the file ends at the last whole packet.
/// Sync bytes are read in chunks to avoid a syscall per packet. The signature
/// already required the sync at offsets 0 and 188, and `MIN_PACKETS` consecutive
/// packets are required here, so the single-byte sync cannot trigger a false
/// carve. Only the 188-byte form is carved (see [`Extent::Mpegts`]).
fn mpegts_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    const PACKET: u64 = 188;
    const MIN_PACKETS: u64 = 8;
    let avail = limit.saturating_sub(file_start);
    let mut buf = vec![0u8; 64 * 1024];
    let mut pos = 0u64;
    let mut packets = 0u64;
    'walk: loop {
        if pos + PACKET > avail {
            break;
        }
        let want = ((avail - pos).min(buf.len() as u64)) as usize;
        let n = source.read_at(file_start + pos, &mut buf[..want])?;
        let mut off = 0usize;
        // Scan whole packets within what we read.
        while off + PACKET as usize <= n {
            if buf[off] != 0x47 {
                break 'walk;
            }
            off += PACKET as usize;
            pos += PACKET;
            packets += 1;
        }
        // No full packet fit in this read (truncated tail): stop.
        if off == 0 {
            break;
        }
    }
    if packets < MIN_PACKETS {
        return Ok(None);
    }
    Ok(Some(packets * PACKET))
}

/// Android Dalvik executable (DEX) length. The header stores the total file
/// size as a little-endian u32 at offset 0x20, so the file ends there. The
/// header size (0x70 at offset 0x24) and endian tag (0x12345678 at offset 0x28)
/// are checked to reject a coincidental `dex\n` magic.
fn dex_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let mut h = [0u8; 0x2C];
    if source.read_at(file_start, &mut h)? < 0x2C || &h[0..4] != b"dex\n" {
        return Ok(None);
    }
    let file_size = u32::from_le_bytes([h[0x20], h[0x21], h[0x22], h[0x23]]) as u64;
    let header_size = u32::from_le_bytes([h[0x24], h[0x25], h[0x26], h[0x27]]);
    let endian_tag = u32::from_le_bytes([h[0x28], h[0x29], h[0x2A], h[0x2B]]);
    // header_size is fixed at 0x70; the standard (little-endian) DEX endian tag
    // is 0x12345678.
    if header_size != 0x70 || endian_tag != 0x1234_5678 {
        return Ok(None);
    }
    if file_size < 0x70 || file_start.saturating_add(file_size) > limit {
        return Ok(None);
    }
    Ok(Some(file_size))
}

/// ICC colour profile length. The 128-byte profile header opens with the total
/// profile size as a big-endian u32 at offset 0 (the `acsp` file signature sits
/// at offset 36). The size must be at least the 128-byte header and a multiple
/// of 4 (profiles are padded to a 4-byte boundary), which rejects a coincidental
/// `acsp` match.
fn icc_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let mut h = [0u8; 4];
    if source.read_at(file_start, &mut h)? < 4 {
        return Ok(None);
    }
    let size = u32::from_be_bytes(h) as u64;
    if size < 128 || size % 4 != 0 {
        return Ok(None);
    }
    if file_start.saturating_add(size) > limit {
        return Ok(None);
    }
    Ok(Some(size))
}

/// Unix `ar` archive length. After the 8-byte `!<arch>\n` global header, walk
/// the member chain: each member has a 60-byte header ending in the `` `\n ``
/// sentinel (at offset 58) and carrying its data size as a decimal field at
/// offset 48; member data is padded to an even length. The walk stops at the
/// first header without the sentinel — that is the end of the archive — so the
/// length is exact. At least one valid member is required to reject a stray
/// magic.
fn ar_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    const GLOBAL: u64 = 8;
    let avail = limit.saturating_sub(file_start);
    let mut g = [0u8; 8];
    if source.read_at(file_start, &mut g)? < 8 || &g != b"!<arch>\n" {
        return Ok(None);
    }
    let mut pos = GLOBAL;
    let mut members = 0u64;
    loop {
        if pos.saturating_add(60) > avail {
            break;
        }
        let mut hdr = [0u8; 60];
        if source.read_at(file_start + pos, &mut hdr)? < 60 {
            break;
        }
        // Every member header ends with the "`\n" sentinel; its absence marks
        // the end of the archive (or a coincidental magic).
        if &hdr[58..60] != b"`\n" {
            break;
        }
        // Data size: a decimal value, left-justified and space-padded to 10.
        let size = match std::str::from_utf8(&hdr[48..58])
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
        {
            Some(s) => s,
            None => break,
        };
        let padded = size.saturating_add(size & 1); // data padded to even length
        let next = pos.saturating_add(60).saturating_add(padded);
        if next > avail {
            break;
        }
        pos = next;
        members += 1;
    }
    if members == 0 {
        return Ok(None);
    }
    Ok(Some(pos))
}

/// `tar` archive length. Each member is a 512-byte header (its data size an octal
/// field at offset 124) followed by data padded up to a multiple of 512; the
/// archive ends with two all-zero blocks. Walk the member chain from one `ustar`
/// header to the next — validating each header's checksum — and end at the zero
/// terminator, so a coincidental `ustar` does not over- or under-read.
fn tar_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    const BLOCK: u64 = 512;
    const MAX_MEMBERS: u64 = 1_000_000;
    let avail = limit.saturating_sub(file_start);
    let mut pos = 0u64;
    let mut members = 0u64;
    let mut block = [0u8; BLOCK as usize];
    loop {
        if pos.saturating_add(BLOCK) > avail {
            break;
        }
        if source.read_at(file_start + pos, &mut block)? < BLOCK as usize {
            break;
        }
        // Two consecutive zero blocks mark end-of-archive.
        if block.iter().all(|&b| b == 0) {
            // Include both terminator blocks when they fit (a valid tar EOF),
            // else just the one we have.
            let end = if pos.saturating_add(2 * BLOCK) <= avail {
                pos + 2 * BLOCK
            } else {
                pos + BLOCK
            };
            return Ok(if members == 0 { None } else { Some(end) });
        }
        // A non-terminator block must be a valid ustar header.
        if &block[257..262] != b"ustar" || !tar_checksum_ok(&block) {
            break;
        }
        let size = match parse_tar_numeric(&block[124..136]) {
            Some(s) => s,
            None => break,
        };
        // Header block + the member data padded up to a multiple of 512.
        let data_blocks = size.div_ceil(BLOCK);
        let next = pos
            .saturating_add(BLOCK)
            .saturating_add(data_blocks.saturating_mul(BLOCK));
        if next > avail || members >= MAX_MEMBERS {
            break;
        }
        pos = next;
        members += 1;
    }
    // No zero terminator (a truncated archive): return the bytes up to the last
    // complete member so the recovered data is still a usable prefix.
    if members == 0 {
        Ok(None)
    } else {
        Ok(Some(pos))
    }
}

/// Verify a tar header's checksum: the unsigned sum of all 512 header bytes, with
/// the 8-byte checksum field (offset 148) taken as ASCII spaces, equals the octal
/// value stored in that field.
fn tar_checksum_ok(block: &[u8; 512]) -> bool {
    let Some(stored) = parse_tar_numeric(&block[148..156]) else {
        return false;
    };
    let sum: u64 = block
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                0x20
            } else {
                b as u64
            }
        })
        .sum();
    sum == stored
}

/// Parse a tar numeric field: octal ASCII (space/NUL padded), or GNU base-256
/// when the field's top bit is set. An all-padding field is `0`.
fn parse_tar_numeric(field: &[u8]) -> Option<u64> {
    if field.is_empty() {
        return None;
    }
    // GNU base-256: high bit of the first byte set; the rest is a big-endian
    // integer (the low 8 bytes are enough for any realistic size).
    if field[0] & 0x80 != 0 {
        let mut v: u64 = 0;
        for &b in field.iter().skip(field.len().saturating_sub(8)) {
            v = (v << 8) | b as u64;
        }
        return Some(v);
    }
    // Octal ASCII: drop NULs, trim spaces, read octal digits.
    let digits: Vec<u8> = field.iter().copied().filter(|&b| b != 0).collect();
    let text = std::str::from_utf8(&digits).ok()?.trim();
    if text.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(text, 8).ok()
}

/// `cpio` archive (newc) length. Each entry is a 110-byte ASCII header (8-hex-
/// digit fields, including `filesize` and `namesize`) followed by the
/// NUL-terminated name and the file data, each padded so the next entry begins on
/// a 4-byte boundary. Walk the entry chain to the `TRAILER!!!` entry; its (padded)
/// end is the end of the archive.
fn cpio_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    const HDR: u64 = 110;
    const MAX_ENTRIES: u64 = 5_000_000;
    let avail = limit.saturating_sub(file_start);
    let mut pos = 0u64;
    let mut entries = 0u64;
    let mut hdr = [0u8; HDR as usize];
    loop {
        if pos.saturating_add(HDR) > avail {
            break;
        }
        if source.read_at(file_start + pos, &mut hdr)? < HDR as usize {
            break;
        }
        // Header magic: "070701" (newc) or "070702" (newc + CRC).
        if &hdr[0..5] != b"07070" || (hdr[5] != b'1' && hdr[5] != b'2') {
            break;
        }
        // Fields are 8 hex digits each after the 6-byte magic: filesize is
        // field 6 (offset 54), namesize field 11 (offset 94).
        let (Some(filesize), Some(namesize)) =
            (parse_cpio_hex(&hdr[54..62]), parse_cpio_hex(&hdr[94..102]))
        else {
            break;
        };
        // The name includes a trailing NUL; bound it so a corrupt field can't
        // make us read absurd amounts.
        if namesize == 0 || namesize > 8192 {
            break;
        }
        let name_pos = pos.saturating_add(HDR);
        if name_pos.saturating_add(namesize) > avail {
            break;
        }
        let mut name = vec![0u8; namesize as usize];
        if source.read_at(file_start + name_pos, &mut name)? < namesize as usize {
            break;
        }
        // The name and data are each padded so the next field starts on a 4-byte
        // boundary, measured from the start of the entry's header.
        let after_name = round_up4(HDR.saturating_add(namesize));
        // The "TRAILER!!!" entry (name, no data) marks end-of-archive.
        let trimmed = name.strip_suffix(&[0]).unwrap_or(&name);
        if trimmed == b"TRAILER!!!" {
            let end = pos.saturating_add(after_name).min(avail);
            return Ok(if entries == 0 { None } else { Some(end) });
        }
        let next = pos
            .saturating_add(after_name)
            .saturating_add(round_up4(filesize));
        if next > avail || entries >= MAX_ENTRIES {
            break;
        }
        pos = next;
        entries += 1;
    }
    Ok(None)
}

/// Round up to a multiple of 4 (cpio newc pads names and data to 4 bytes).
fn round_up4(n: u64) -> u64 {
    (n.saturating_add(3) / 4) * 4
}

/// SquashFS image length. The version-4 superblock stores `bytes_used` (the exact
/// image size) as a little-endian u64 at offset 40. The major version must be 4
/// and the block size must be a power of two equal to `1 << block_log` (a
/// consistency check that rejects a coincidental `hsqs`).
fn squashfs_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let mut sb = [0u8; 48];
    if source.read_at(file_start, &mut sb)? < 48 {
        return Ok(None);
    }
    let block_size = u32::from_le_bytes(sb[12..16].try_into().unwrap());
    let block_log = u16::from_le_bytes(sb[22..24].try_into().unwrap());
    let s_major = u16::from_le_bytes(sb[28..30].try_into().unwrap());
    let bytes_used = u64::from_le_bytes(sb[40..48].try_into().unwrap());
    // Only the 4.0 superblock layout is parsed here.
    if s_major != 4 {
        return Ok(None);
    }
    // block_size is 4 KiB..1 MiB and must equal 1 << block_log.
    if !(12..=20).contains(&block_log) || block_size != 1u32 << block_log {
        return Ok(None);
    }
    // bytes_used must cover at least the superblock and fit in the region.
    if bytes_used < 96 || file_start.saturating_add(bytes_used) > limit {
        return Ok(None);
    }
    Ok(Some(bytes_used))
}

/// Parse an 8-character ASCII hex field from a cpio header.
fn parse_cpio_hex(field: &[u8]) -> Option<u64> {
    u64::from_str_radix(std::str::from_utf8(field).ok()?, 16).ok()
}

/// ESRI Shapefile (`.shp`/`.shx`) length. The 100-byte header stores the total
/// file length as a big-endian u32 at offset 24, counted in 16-bit words, so the
/// file ends at `length * 2`. The file code (9994 at offset 0) and version
/// (1000, little-endian, at offset 28) are checked to reject a coincidental
/// magic, and the length must cover at least the header.
fn shp_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let mut h = [0u8; 32];
    if source.read_at(file_start, &mut h)? < 32 {
        return Ok(None);
    }
    let file_code = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
    let version = u32::from_le_bytes([h[28], h[29], h[30], h[31]]);
    if file_code != 9994 || version != 1000 {
        return Ok(None);
    }
    let length_words = u32::from_be_bytes([h[24], h[25], h[26], h[27]]) as u64;
    let size = length_words.saturating_mul(2);
    if size < 100 || file_start.saturating_add(size) > limit {
        return Ok(None);
    }
    Ok(Some(size))
}

/// Blender (`.blend`) length. A 12-byte header (`BLENDER`, a pointer-size flag
/// `_` (4) or `-` (8), an endianness flag `v` (little) or `V` (big), and a
/// 3-byte version) is followed by a chain of file blocks. Each block header is
/// a 4-byte code, a 4-byte data size, an old pointer (4 or 8 bytes), and two
/// 4-byte fields, followed by `size` bytes of data. The chain is walked to the
/// terminating `ENDB` block, which gives an exact end.
fn blend_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let avail = limit.saturating_sub(file_start);
    let mut head = [0u8; 12];
    if source.read_at(file_start, &mut head)? < 12 || &head[0..7] != b"BLENDER" {
        return Ok(None);
    }
    let ptr_size: u64 = match head[7] {
        b'_' => 4,
        b'-' => 8,
        _ => return Ok(None),
    };
    let le = match head[8] {
        b'v' => true,
        b'V' => false,
        _ => return Ok(None),
    };
    let block_hdr = 16 + ptr_size; // code(4) + size(4) + ptr + sdna(4) + count(4)

    let mut pos = 12u64;
    loop {
        if pos.saturating_add(block_hdr) > avail {
            break;
        }
        let mut hdr = [0u8; 24]; // max block header (64-bit pointer)
        if source.read_at(file_start + pos, &mut hdr[..block_hdr as usize])? < block_hdr as usize {
            break;
        }
        let size = if le {
            u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]])
        } else {
            u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]])
        } as u64;
        if &hdr[0..4] == b"ENDB" {
            // The terminating block ends the file (its data size is normally 0).
            let end = pos.saturating_add(block_hdr).saturating_add(size);
            if end > avail {
                break;
            }
            return Ok(Some(end));
        }
        let next = pos.saturating_add(block_hdr).saturating_add(size);
        if next > avail {
            break;
        }
        pos = next;
    }
    Ok(None) // no ENDB terminator found within bounds
}

/// Compound File Binary Format (OLE2) length. Reads the header for the sector
/// size and the FAT (located via the DIFAT — the first 109 FAT-sector pointers
/// live in the header, the rest follow a DIFAT-sector chain), then walks the
/// FAT to find the highest sector index that is not marked free. The file is
/// that many sectors plus the leading header sector, so it ends at
/// `(max_used_sector + 2) * sector_size`.
fn cfbf_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    const FREESECT: u32 = 0xFFFF_FFFF;
    const ENDOFCHAIN: u32 = 0xFFFF_FFFE;

    let mut hdr = [0u8; 512];
    if source.read_at(file_start, &mut hdr)? < 512 {
        return Ok(None);
    }
    if hdr[0..8] != [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] {
        return Ok(None);
    }
    // Little-endian byte-order mark; CFBF is always little-endian in practice.
    if hdr[28] != 0xFE || hdr[29] != 0xFF {
        return Ok(None);
    }
    let sector_size: u64 = match u16::from_le_bytes([hdr[30], hdr[31]]) {
        9 => 512,
        12 => 4096,
        _ => return Ok(None),
    };
    let entries_per_sector = (sector_size / 4) as usize;
    let num_fat_sectors = u32::from_le_bytes([hdr[44], hdr[45], hdr[46], hdr[47]]) as u64;
    if num_fat_sectors == 0 {
        return Ok(None);
    }
    // A corrupt header could claim more FAT sectors than could fit in the carve
    // window; reject it rather than reading wildly.
    let max_sectors = (limit.saturating_sub(file_start) / sector_size) + 2;
    if num_fat_sectors > max_sectors {
        return Ok(None);
    }

    // Collect the FAT sector numbers: the first 109 from the header DIFAT array
    // (offset 76), then any further ones via the DIFAT-sector chain.
    let mut fat_sectors: Vec<u32> = Vec::new();
    for i in 0..109usize {
        let off = 76 + i * 4;
        let s = u32::from_le_bytes([hdr[off], hdr[off + 1], hdr[off + 2], hdr[off + 3]]);
        if s != FREESECT && s != ENDOFCHAIN {
            fat_sectors.push(s);
        }
    }
    let num_difat_sectors = u32::from_le_bytes([hdr[72], hdr[73], hdr[74], hdr[75]]) as u64;
    let mut difat = u32::from_le_bytes([hdr[68], hdr[69], hdr[70], hdr[71]]);
    let mut difat_seen = 0u64;
    let mut sec = vec![0u8; sector_size as usize];
    while difat != FREESECT && difat != ENDOFCHAIN && difat_seen < num_difat_sectors {
        let sec_off = file_start + (difat as u64 + 1) * sector_size;
        if source.read_at(sec_off, &mut sec)? < sector_size as usize {
            return Ok(None);
        }
        // All but the last entry are FAT-sector pointers; the last points to the
        // next DIFAT sector.
        for i in 0..entries_per_sector - 1 {
            let s = u32::from_le_bytes(sec[i * 4..i * 4 + 4].try_into().unwrap());
            if s != FREESECT && s != ENDOFCHAIN {
                fat_sectors.push(s);
            }
        }
        let last = (entries_per_sector - 1) * 4;
        difat = u32::from_le_bytes(sec[last..last + 4].try_into().unwrap());
        difat_seen += 1;
    }
    // The DIFAT must yield exactly the declared number of FAT sectors, or the
    // structure is inconsistent and a computed size can't be trusted.
    if fat_sectors.len() as u64 != num_fat_sectors {
        return Ok(None);
    }

    // Walk the FAT, tracking the highest sector index that is in use (any entry
    // other than FREESECT marks its sector as allocated).
    let mut max_used: i64 = -1;
    for (fi, &fat_sec) in fat_sectors.iter().enumerate() {
        let sec_off = file_start + (fat_sec as u64 + 1) * sector_size;
        if source.read_at(sec_off, &mut sec)? < sector_size as usize {
            return Ok(None);
        }
        for i in 0..entries_per_sector {
            let v = u32::from_le_bytes(sec[i * 4..i * 4 + 4].try_into().unwrap());
            if v != FREESECT {
                max_used = max_used.max((fi * entries_per_sector + i) as i64);
            }
        }
    }
    if max_used < 0 {
        return Ok(None);
    }
    let size = (max_used as u64 + 2) * sector_size;
    if file_start + size > limit {
        return Ok(None);
    }
    Ok(Some(size))
}

/// Outlook data file (PST/OST) length. The NDB header records the file's own
/// end offset (`ibFileEof`) — a little-endian u64 at offset 0xB8 in the Unicode
/// format (`wVer` >= 23), which is the exact on-disk size. The ANSI format
/// (`wVer` 14/15) places a 32-bit `ibFileEof` elsewhere and is not carved.
fn pst_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let mut hdr = [0u8; 0xC0];
    if source.read_at(file_start, &mut hdr)? < hdr.len() {
        return Ok(None);
    }
    // "!BDN" magic and the "SM" client signature (also checked at match time).
    if &hdr[0..4] != b"!BDN" || &hdr[8..10] != b"SM" {
        return Ok(None);
    }
    let ver = u16::from_le_bytes([hdr[10], hdr[11]]);
    if ver < 23 {
        return Ok(None); // ANSI format: ibFileEof layout differs; not supported
    }
    let size = u64::from_le_bytes(hdr[0xB8..0xC0].try_into().unwrap());
    // A valid file is at least the header; reject a corrupt or overlong size.
    if size < hdr.len() as u64 || file_start + size > limit {
        return Ok(None);
    }
    Ok(Some(size))
}

/// iNES / NES 2.0 ROM length. The 16-byte header records the PRG ROM size at
/// byte 4 (in 16 KiB units) and the CHR ROM size at byte 5 (in 8 KiB units),
/// plus an optional 512-byte trainer (flag bit 2 of byte 6), so the file ends at
/// `16 + trainer + prg * 16384 + chr * 8192`. NES 2.0 (byte 7 bits 2..3 == 2)
/// extends each count with the nibbles of byte 9; the exponent bank form (high
/// nibble 0xF) and an indeterminate miscellaneous-ROM area are rejected.
fn nes_length(source: &Source, file_start: u64, limit: u64) -> Result<Option<u64>> {
    let mut h = [0u8; 16];
    if source.read_at(file_start, &mut h)? < 16 || &h[0..4] != b"NES\x1a" {
        return Ok(None);
    }
    let trainer = if h[6] & 0x04 != 0 { 512 } else { 0 };
    let is_nes2 = (h[7] & 0x0C) == 0x08;
    let (prg_count, chr_count) = if is_nes2 {
        // Miscellaneous ROM area (byte 14, low two bits) has no header-encoded
        // size, so its presence makes the length indeterminate.
        if h[14] & 0x03 != 0 {
            return Ok(None);
        }
        let prg_hi = (h[9] & 0x0F) as u64;
        let chr_hi = ((h[9] >> 4) & 0x0F) as u64;
        if prg_hi == 0x0F || chr_hi == 0x0F {
            return Ok(None); // exponent bank form (rare); size not computed here
        }
        ((prg_hi << 8) | h[4] as u64, (chr_hi << 8) | h[5] as u64)
    } else {
        (h[4] as u64, h[5] as u64)
    };
    if prg_count == 0 {
        return Ok(None); // a ROM must have program data
    }
    let total = 16 + trainer + prg_count.saturating_mul(16384) + chr_count.saturating_mul(8192);
    if file_start.saturating_add(total) > limit {
        return Ok(None);
    }
    Ok(Some(total))
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

/// The extension to write a carved file under. Normally the signature's own
/// extension, but a ZIP is inspected for the marker entries of the common
/// ZIP-based formats so a recovered Office/OpenDocument/e-book/Java/Android file
/// gets a usable name (`.docx`, `.xlsx`, …) instead of a generic `.zip`.
fn effective_ext(
    source: &Source,
    sig: &Signature,
    file_start: u64,
    len: u64,
) -> Result<&'static str> {
    if sig.ext != "zip" && sig.ext != "ole" {
        return Ok(sig.ext);
    }
    // The marker entry / directory-stream names live near the start; a 64 KiB
    // window comfortably covers both ZIP and CFBF.
    let want = len.min(64 * 1024) as usize;
    let mut head = vec![0u8; want];
    let n = source.read_at(file_start, &mut head)?;
    head.truncate(n);
    if sig.ext == "ole" {
        return Ok(crate::signatures::classify_cfbf(&head)
            .map(|(ext, _)| ext)
            .unwrap_or("ole"));
    }
    Ok(crate::signatures::classify_zip(&head)
        .map(|(ext, _)| ext)
        .unwrap_or("zip"))
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
    // Refine the extension from content where useful (e.g. a ZIP that is really
    // a .docx), so the recovered file gets a directly-usable name.
    let ext = effective_ext(source, sig, file_start, len)?;
    let base = format!("{:08}_{:#016x}.{}", stats.files_recovered, file_start, ext);
    // With `--organize`, group files into a per-type subdirectory; the manifest
    // name keeps the `<ext>/` prefix so `verify` still resolves it.
    let (name, path): (String, PathBuf) = if opts.organize {
        (
            format!("{}/{}", ext, base),
            opts.output_dir.join(ext).join(&base),
        )
    } else {
        (base.clone(), opts.output_dir.join(&base))
    };
    // In dry-run mode nothing is written; the bytes are still read and hashed so
    // the tally, manifest, and dedup behave exactly as a real run would.
    let mut out = if opts.dry_run {
        None
    } else {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        Some(fs::File::create(&path).with_context(|| format!("creating {}", path.display()))?)
    };

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
        if let Some(out) = out.as_mut() {
            out.write_all(&buf[..n])
                .with_context(|| format!("writing {}", path.display()))?;
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
        pos += n as u64;
    }
    if let Some(out) = out.as_mut() {
        out.flush().ok();
    }

    let digest = hasher.finalize();
    if opts.dedup && !seen.insert(digest) {
        // Identical content already recovered; discard this copy.
        drop(out);
        if !opts.dry_run {
            fs::remove_file(&path).ok();
        }
        stats.duplicates += 1;
        return Ok(());
    }

    let written = len - remaining;
    stats.files_recovered += 1;
    stats.bytes_recovered += written;
    *stats.per_type.entry(ext).or_insert(0) += 1;
    stats.files.push(CarvedFile {
        name,
        ext,
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
