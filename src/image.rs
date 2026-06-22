//! Robust, read-only disk imaging.
//!
//! The safest way to recover a failing drive is to copy it once, then work on
//! the copy — every later scan reads the image instead of stressing the dying
//! hardware again. This module does that copy:
//!
//! - **read-only** source access (same guarantee as the rest of the tool),
//! - **bad-sector tolerance**: a block that fails to read is retried at sector
//!   granularity; sectors that still fail are left as holes and recorded, so one
//!   unreadable spot does not abort the whole image,
//! - **sparse output**: runs of zero bytes are skipped, so an image of a
//!   mostly-empty drive stays small on a filesystem that supports holes.

use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::carver::ProgressSink;
use crate::source::Source;

/// How much we attempt to read (and write) per iteration.
const IMAGE_CHUNK: usize = 4 * 1024 * 1024; // 4 MiB
/// Granularity at which a sparse run is detected and left as a hole. Small
/// enough to catch holes that do not align to the read chunk, large enough that
/// the zero check and the per-write overhead stay cheap.
const SPARSE_BLOCK: usize = 64 * 1024; // 64 KiB
/// Default bad-sector retry granularity.
pub const DEFAULT_SECTOR: u64 = 512;

/// Tunable knobs for an imaging run.
pub struct ImageOptions {
    /// Image file to create (overwritten if it exists).
    pub output: PathBuf,
    /// First source byte offset to copy.
    pub start: u64,
    /// Exclusive end offset; `None` means copy to the end of the device.
    pub end: Option<u64>,
    /// Skip runs of zero bytes, leaving holes in the output (a sparse image).
    pub sparse: bool,
    /// Granularity to fall back to when a larger read fails.
    pub sector_size: u64,
}

impl Default for ImageOptions {
    fn default() -> Self {
        ImageOptions {
            output: PathBuf::new(),
            start: 0,
            end: None,
            sparse: true,
            sector_size: DEFAULT_SECTOR,
        }
    }
}

/// A contiguous span of the source that could not be read.
pub struct BadRegion {
    /// Source offset where the unreadable span starts.
    pub offset: u64,
    /// Length of the unreadable span, in bytes.
    pub len: u64,
}

/// Outcome of an imaging run.
#[derive(Default)]
pub struct ImageStats {
    /// Total bytes in the copied range.
    pub bytes_total: u64,
    /// Bytes successfully read from the source and written to the image.
    pub bytes_copied: u64,
    /// Bytes left as holes because their sectors were unreadable.
    pub bytes_zeroed: u64,
    /// Bytes skipped as zero runs (only when `sparse`).
    pub bytes_sparse: u64,
    /// Unreadable spans, merged where contiguous.
    pub bad_regions: Vec<BadRegion>,
    /// Whether the run stopped early because cancellation was requested.
    pub cancelled: bool,
}

/// A positioned byte source. Abstracted so the bad-sector path can be tested
/// with an injected fault; [`Source`] is the production implementation.
pub trait BlockSource {
    fn size(&self) -> u64;
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize>;
}

impl BlockSource for Source {
    fn size(&self) -> u64 {
        self.size
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        Source::read_at(self, offset, buf).map_err(|e| std::io::Error::other(e.to_string()))
    }
}

/// Copy `src` to `opts.output`, tolerating unreadable sectors.
pub fn image<S: BlockSource>(
    src: &S,
    opts: &ImageOptions,
    progress: &dyn ProgressSink,
) -> Result<ImageStats> {
    let sector = opts.sector_size.max(1);
    let end = opts.end.unwrap_or(src.size()).min(src.size());
    let start = opts.start.min(end);
    let total = end - start;

    if let Some(parent) = opts.output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating image dir {}", parent.display()))?;
        }
    }
    let mut out = File::create(&opts.output)
        .with_context(|| format!("creating image {}", opts.output.display()))?;
    // Size the file up front so skipped (sparse) and unreadable regions become
    // real holes that read back as zero.
    out.set_len(total)
        .with_context(|| format!("sizing image {}", opts.output.display()))?;

    let mut stats = ImageStats {
        bytes_total: total,
        ..Default::default()
    };
    // Bad sectors collected in source order, merged into `bad_regions` at the end.
    let mut bad: Vec<(u64, u64)> = Vec::new();
    let mut buf = vec![0u8; IMAGE_CHUNK];

    progress.begin(total);
    let mut abs = start;
    while abs < end {
        if progress.cancelled() {
            stats.cancelled = true;
            break;
        }
        let want = ((end - abs) as usize).min(IMAGE_CHUNK);
        match src.read_at(abs, &mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => {
                write_region(&mut out, abs - start, &buf[..n], opts.sparse, &mut stats)?;
                abs += n as u64;
            }
            Err(_) => {
                // The block read failed; recover the good sectors around the
                // bad one by retrying at sector granularity.
                let block_end = abs + want as u64;
                let mut pos = abs;
                while pos < block_end {
                    let len = sector.min(block_end - pos) as usize;
                    match src.read_at(pos, &mut buf[..len]) {
                        Ok(n) if n > 0 => {
                            write_region(
                                &mut out,
                                pos - start,
                                &buf[..n],
                                opts.sparse,
                                &mut stats,
                            )?;
                            pos += n as u64;
                        }
                        _ => {
                            // Unreadable: leave a hole and record it.
                            bad.push((pos, len as u64));
                            stats.bytes_zeroed += len as u64;
                            pos += len as u64;
                        }
                    }
                }
                abs = block_end;
            }
        }
        progress.update(abs - start);
    }
    out.flush().context("flushing image")?;
    progress.finish(abs - start);

    stats.bad_regions = merge_regions(&bad);
    Ok(stats)
}

/// Write one good span to the image at `out_off`. In sparse mode the span is
/// examined in [`SPARSE_BLOCK`] sub-blocks and any all-zero sub-block is left as
/// a hole, so holes that do not align to the read chunk are still found.
fn write_region(
    out: &mut File,
    out_off: u64,
    data: &[u8],
    sparse: bool,
    stats: &mut ImageStats,
) -> Result<()> {
    if !sparse {
        out.seek(SeekFrom::Start(out_off))
            .context("seeking image")?;
        out.write_all(data).context("writing image")?;
        stats.bytes_copied += data.len() as u64;
        return Ok(());
    }
    for (i, block) in data.chunks(SPARSE_BLOCK).enumerate() {
        if block.iter().all(|&b| b == 0) {
            stats.bytes_sparse += block.len() as u64;
            continue;
        }
        out.seek(SeekFrom::Start(out_off + (i * SPARSE_BLOCK) as u64))
            .context("seeking image")?;
        out.write_all(block).context("writing image")?;
        stats.bytes_copied += block.len() as u64;
    }
    Ok(())
}

/// Merge sectors that touch into single regions (they arrive in source order).
fn merge_regions(sectors: &[(u64, u64)]) -> Vec<BadRegion> {
    let mut out: Vec<BadRegion> = Vec::new();
    for &(off, len) in sectors {
        match out.last_mut() {
            Some(prev) if prev.offset + prev.len == off => prev.len += len,
            _ => out.push(BadRegion { offset: off, len }),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::carver::NoProgress;

    /// An in-memory source that can be told to fail reads over a byte range, so
    /// the bad-sector path is exercised without real failing hardware.
    struct FaultySource {
        data: Vec<u8>,
        bad: std::ops::Range<u64>,
    }

    impl BlockSource for FaultySource {
        fn size(&self) -> u64 {
            self.data.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let len = buf.len() as u64;
            // Any overlap with the bad range fails the whole read, just like a
            // kernel EIO covering a request that spans an unreadable sector.
            if offset < self.bad.end && offset + len > self.bad.start {
                return Err(std::io::Error::other("EIO"));
            }
            let start = offset as usize;
            let n = (buf.len()).min(self.data.len().saturating_sub(start));
            buf[..n].copy_from_slice(&self.data[start..start + n]);
            Ok(n)
        }
    }

    fn read_back(path: &std::path::Path) -> Vec<u8> {
        std::fs::read(path).unwrap()
    }

    #[test]
    fn images_a_file_byte_for_byte() {
        let tmp = tempfile::tempdir().unwrap();
        let src_path = tmp.path().join("src.bin");
        let out = tmp.path().join("out.img");
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&src_path, &data).unwrap();

        let source = Source::open(&src_path).unwrap();
        let opts = ImageOptions {
            output: out.clone(),
            sparse: false,
            ..Default::default()
        };
        let stats = image(&source, &opts, &NoProgress).unwrap();

        assert_eq!(stats.bytes_total, data.len() as u64);
        assert_eq!(stats.bytes_copied, data.len() as u64);
        assert!(stats.bad_regions.is_empty());
        assert_eq!(read_back(&out), data);
    }

    #[test]
    fn sparse_skips_zero_runs_but_preserves_content() {
        let tmp = tempfile::tempdir().unwrap();
        let src_path = tmp.path().join("src.bin");
        let out = tmp.path().join("out.img");
        let mut data = vec![0xABu8; 1000];
        data.extend(std::iter::repeat(0u8).take(5 * 1024 * 1024)); // a big hole
        data.extend(std::iter::repeat(0xCDu8).take(1000));
        std::fs::write(&src_path, &data).unwrap();

        let source = Source::open(&src_path).unwrap();
        let opts = ImageOptions {
            output: out.clone(),
            sparse: true,
            ..Default::default()
        };
        let stats = image(&source, &opts, &NoProgress).unwrap();

        assert!(stats.bytes_sparse > 0, "a zero run should be skipped");
        assert_eq!(stats.bytes_total, data.len() as u64);
        // Content is identical regardless of how it was stored.
        assert_eq!(read_back(&out), data);
    }

    #[test]
    fn copies_only_the_requested_range() {
        let tmp = tempfile::tempdir().unwrap();
        let src_path = tmp.path().join("src.bin");
        let out = tmp.path().join("out.img");
        let data: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
        std::fs::write(&src_path, &data).unwrap();

        let source = Source::open(&src_path).unwrap();
        let opts = ImageOptions {
            output: out.clone(),
            start: 1000,
            end: Some(2000),
            sparse: false,
            ..Default::default()
        };
        let stats = image(&source, &opts, &NoProgress).unwrap();

        assert_eq!(stats.bytes_total, 1000);
        assert_eq!(read_back(&out), data[1000..2000]);
    }

    #[test]
    fn bad_sectors_are_zero_filled_and_recorded() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out.img");
        // 4096 bytes of 0xEE, with one unreadable 512-byte sector at offset 1024.
        let data = vec![0xEEu8; 4096];
        let source = FaultySource {
            data: data.clone(),
            bad: 1024..1536,
        };
        let opts = ImageOptions {
            output: out.clone(),
            sparse: false,
            sector_size: 512,
            ..Default::default()
        };
        let stats = image(&source, &opts, &NoProgress).unwrap();

        assert_eq!(stats.bytes_zeroed, 512);
        assert_eq!(stats.bad_regions.len(), 1);
        assert_eq!(stats.bad_regions[0].offset, 1024);
        assert_eq!(stats.bad_regions[0].len, 512);

        let got = read_back(&out);
        assert_eq!(got.len(), 4096);
        // Good sectors copied; the bad sector reads back as a zero-filled hole.
        assert_eq!(&got[..1024], &data[..1024]);
        assert!(got[1024..1536].iter().all(|&b| b == 0));
        assert_eq!(&got[1536..], &data[1536..]);
    }

    #[test]
    fn contiguous_bad_sectors_merge_into_one_region() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out.img");
        let source = FaultySource {
            data: vec![0x11u8; 8192],
            // Spans three 512-byte sectors (1024..2560).
            bad: 1100..2400,
        };
        let opts = ImageOptions {
            output: out,
            sparse: false,
            sector_size: 512,
            ..Default::default()
        };
        let stats = image(&source, &opts, &NoProgress).unwrap();

        assert_eq!(stats.bad_regions.len(), 1, "adjacent bad sectors merge");
        assert_eq!(stats.bad_regions[0].offset, 1024);
        assert_eq!(stats.bad_regions[0].len, 1536); // three sectors
        assert_eq!(stats.bytes_zeroed, 1536);
    }
}
