//! Command-line interface definition.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use clap_complete::Shell;

/// Recover deleted files from SD cards, hard drives, and disk images by
/// signature-based file carving.
#[derive(Parser)]
#[command(name = "filerecovery", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Carve files from a device or image by signature (filesystem-agnostic).
    ///
    /// Works even after a format or partition loss, but cannot restore
    /// original filenames.
    Scan(ScanArgs),
    /// Recover deleted files from a FAT, exFAT, NTFS, ext, or HFS+ filesystem,
    /// keeping their original names, paths, and sizes.
    ///
    /// More accurate than carving when the filesystem metadata is intact (e.g.
    /// a file was just deleted), but requires a readable FAT12/16/32, exFAT,
    /// NTFS, ext2/3/4, or HFS+/HFSX volume.
    Undelete(UndeleteArgs),
    /// Recover everything in one pass: filesystem-aware undelete, then carving
    /// for whatever the filesystem metadata could not restore.
    ///
    /// Writes named files (with paths) under `<OUTPUT>/named/` and carved files
    /// under `<OUTPUT>/carved/`. Carving is content-deduplicated against the
    /// undelete results, so `carved/` only holds data not already recovered by
    /// name.
    Recover(RecoverArgs),
    /// Show the partition / filesystem layout detected in a source.
    Info(InfoArgs),
    /// Copy a device or image to an image file, read-only and bad-sector
    /// tolerant.
    ///
    /// Best practice for a failing drive: image it once, then run `scan` /
    /// `undelete` against the image so later passes never touch the dying
    /// hardware. Unreadable sectors are left as holes and reported, and zero
    /// runs are skipped to keep the image sparse.
    Image(ImageArgs),
    /// Re-hash recovered files against a manifest to confirm their integrity.
    ///
    /// Reads a report written by `scan --report` or `undelete --report` and
    /// checks each recovered file's SHA-256 still matches, turning the manifest
    /// into an auditable integrity record.
    Verify(VerifyArgs),
    /// Summarize a directory of recovered files: counts per type, the largest
    /// files, content duplicates, and empty files.
    Triage(TriageArgs),
    /// Identify a file's type from its contents, independent of its extension.
    Identify(IdentifyArgs),
    /// List the file types this build can recover.
    ListTypes,
    /// Run as a Model Context Protocol (MCP) server on stdin/stdout, exposing
    /// recovery as tools an AI agent can call.
    Mcp,
    /// Print a shell completion script (bash, zsh, fish, powershell, elvish).
    ///
    /// Example: `filerecovery completions bash > /etc/bash_completion.d/filerecovery`.
    Completions(CompletionsArgs),
}

#[derive(Parser)]
pub struct TriageArgs {
    /// Directory of recovered files to summarize.
    #[arg(value_name = "DIR")]
    pub dir: PathBuf,

    /// How many of the largest files to list.
    #[arg(long, value_name = "N", default_value_t = 10)]
    pub top: usize,

    /// Emit the summary as JSON on stdout instead of a table.
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser)]
pub struct IdentifyArgs {
    /// File to identify.
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Emit the result as JSON on stdout instead of a line of text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser)]
pub struct CompletionsArgs {
    /// Shell to generate a completion script for.
    #[arg(value_name = "SHELL")]
    pub shell: Shell,
}

#[derive(Parser)]
pub struct VerifyArgs {
    /// Manifest to verify: a `.json` or `.csv` report (format chosen by
    /// extension).
    #[arg(value_name = "MANIFEST")]
    pub manifest: PathBuf,

    /// Directory the recovered files live in. The `name`/`path` in each manifest
    /// row is resolved relative to this.
    #[arg(short, long, value_name = "DIR", default_value = ".")]
    pub base: PathBuf,
}

#[derive(Parser)]
pub struct ImageArgs {
    /// Source to copy: a disk image file or a block device
    /// (e.g. /dev/sdb, /dev/mmcblk0). Opened read-only.
    #[arg(value_name = "SOURCE")]
    pub source: PathBuf,

    /// Image file to create (overwritten if it exists).
    #[arg(value_name = "OUTPUT")]
    pub output: PathBuf,

    /// Start copying at this byte offset.
    #[arg(long, value_name = "BYTES", default_value_t = 0)]
    pub start: u64,

    /// Stop copying at this byte offset (exclusive).
    #[arg(long, value_name = "BYTES")]
    pub end: Option<u64>,

    /// Write every byte, including zero runs, instead of leaving holes. Use this
    /// when the destination filesystem does not support sparse files.
    #[arg(long)]
    pub no_sparse: bool,

    /// Bad-sector retry granularity: when a larger read fails, fall back to
    /// reads of this size to salvage the good sectors around the bad one.
    #[arg(long, value_name = "BYTES", default_value_t = 512)]
    pub sector_size: u64,

    /// Checkpoint/map file recording progress and unreadable regions, so an
    /// interrupted copy can be resumed. Defaults to `<OUTPUT>.map` when
    /// `--resume` is used.
    #[arg(long, value_name = "FILE")]
    pub map: Option<PathBuf>,

    /// Resume a previous run from its map file (skips the bytes already copied).
    /// Use the same SOURCE, OUTPUT, and --start/--end as the original run.
    #[arg(long)]
    pub resume: bool,

    /// After the main copy, re-read unreadable regions this many extra times.
    /// A failing drive sometimes returns data on a later attempt, so retrying
    /// can salvage sectors the first pass had to zero-fill.
    #[arg(long = "retry-bad", value_name = "PASSES", default_value_t = 0)]
    pub retry_bad: u32,

    /// Write a run summary (bytes copied/zeroed/sparse, bad regions) to this
    /// path. `.json` for JSON, otherwise plain text.
    #[arg(long, value_name = "FILE")]
    pub summary: Option<PathBuf>,

    /// Suppress the progress bar.
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(Parser)]
pub struct RecoverArgs {
    /// Source to read: a disk image file or a block device. Opened read-only.
    #[arg(value_name = "SOURCE")]
    pub source: PathBuf,

    /// Directory to write recovered files into (created if needed). Named files
    /// go under `named/`, carved files under `carved/`.
    #[arg(short, long, value_name = "DIR", default_value = "recovered")]
    pub output: PathBuf,

    /// Byte offset of the volume for the undelete pass (default: auto-detect).
    #[arg(long, value_name = "BYTES")]
    pub offset: Option<u64>,

    /// Restrict the carving pass to these file types (extensions). Repeatable.
    #[arg(short, long = "type", value_name = "EXT")]
    pub types: Vec<String>,

    /// Ignore files smaller than this many bytes (both passes).
    #[arg(long, value_name = "BYTES", default_value_t = 0)]
    pub min_size: u64,

    /// Group carved files into per-type subdirectories under `carved/`.
    #[arg(long)]
    pub organize: bool,

    /// Carve only the volume's unallocated (free) space, skipping data that is
    /// still allocated to live files. Recovers deleted content with much less
    /// noise. Falls back to carving the whole source if the filesystem's
    /// free-space map cannot be read (currently supported for FAT).
    #[arg(long)]
    pub unallocated: bool,

    /// Write a combined manifest of every recovered file (named and carved) to
    /// this path. `.json` for JSON, otherwise CSV. Verifiable with
    /// `filerecovery verify <FILE> --base <OUTPUT>`.
    #[arg(long, value_name = "FILE")]
    pub report: Option<PathBuf>,

    /// Write a run summary (source, options, counts, timing) to this path.
    /// `.json` for JSON, otherwise plain text.
    #[arg(long, value_name = "FILE")]
    pub summary: Option<PathBuf>,

    /// Suppress the progress bar.
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(Parser)]
pub struct InfoArgs {
    /// Source to inspect: a disk image file or a block device. Opened read-only.
    #[arg(value_name = "SOURCE")]
    pub source: PathBuf,

    /// Also count recoverable deleted files in each volume (runs a dry scan).
    #[arg(long)]
    pub deleted: bool,

    /// Emit the detected layout as JSON on stdout instead of a table.
    #[arg(long)]
    pub json: bool,

    /// Scan the whole source for filesystem signatures, not just the partition
    /// table — finds **lost or orphaned partitions** whose table entry is gone
    /// or corrupt. Reports each volume's offset, type, and size so it can be
    /// targeted with `undelete --offset` or `scan --start`. May take a while on
    /// a large device.
    #[arg(long)]
    pub scan: bool,

    /// Alignment (in bytes) at which `--scan` probes for a volume; partitions
    /// are conventionally 1 MiB-aligned. Smaller finds more but is slower.
    #[arg(long, value_name = "BYTES", default_value_t = 1024 * 1024)]
    pub scan_step: u64,
}

#[derive(Parser)]
pub struct UndeleteArgs {
    /// Source to read: a disk image file or a block device
    /// (e.g. /dev/sdb, /dev/mmcblk0). Opened read-only.
    #[arg(value_name = "SOURCE")]
    pub source: PathBuf,

    /// Directory to write recovered files into (created if needed).
    #[arg(short, long, value_name = "DIR", default_value = "recovered")]
    pub output: PathBuf,

    /// Byte offset of the volume within the source. By default the source is
    /// auto-detected (bare volume, or a GPT or MBR partition table).
    #[arg(long, value_name = "BYTES")]
    pub offset: Option<u64>,

    /// Ignore deleted files smaller than this many bytes.
    #[arg(long, value_name = "BYTES", default_value_t = 0)]
    pub min_size: u64,

    /// List what would be recovered without writing any files.
    #[arg(long)]
    pub dry_run: bool,

    /// Write a report of recovered files to this path. The format is chosen by
    /// extension: `.json` for JSON, otherwise CSV.
    #[arg(long, value_name = "FILE")]
    pub report: Option<PathBuf>,

    /// Write a run summary (source, options, counts, timing) to this path.
    /// `.json` for JSON, otherwise plain text.
    #[arg(long, value_name = "FILE")]
    pub summary: Option<PathBuf>,
}

#[derive(Parser)]
pub struct ScanArgs {
    /// Source to read: a disk image file or a block device
    /// (e.g. /dev/sdb, /dev/mmcblk0). Opened read-only.
    #[arg(value_name = "SOURCE")]
    pub source: PathBuf,

    /// Directory to write recovered files into (created if needed).
    #[arg(short, long, value_name = "DIR", default_value = "recovered")]
    pub output: PathBuf,

    /// Restrict recovery to these file types (extensions). Repeatable.
    /// Omit, or use "all", to recover every known type.
    #[arg(short, long = "type", value_name = "EXT")]
    pub types: Vec<String>,

    /// Start scanning at this byte offset.
    #[arg(long, value_name = "BYTES", default_value_t = 0)]
    pub start: u64,

    /// Stop scanning at this byte offset (exclusive).
    #[arg(long, value_name = "BYTES")]
    pub end: Option<u64>,

    /// Ignore carved files smaller than this many bytes.
    #[arg(long, value_name = "BYTES", default_value_t = 0)]
    pub min_size: u64,

    /// Stop after recovering this many files.
    #[arg(long, value_name = "N")]
    pub max_files: Option<u64>,

    /// Also recover files nested inside other files (e.g. embedded thumbnails).
    /// May produce duplicates.
    #[arg(long)]
    pub allow_nested: bool,

    /// Disable structural validation of carved files. By default a candidate
    /// whose header fails a format check is dropped to cut false positives;
    /// pass this to keep every signature match.
    #[arg(long)]
    pub no_validate: bool,

    /// Skip files whose content (SHA-256) was already recovered in this run, so
    /// identical copies are written only once.
    #[arg(long)]
    pub dedup: bool,

    /// Group recovered files into a per-type subdirectory of the output
    /// directory (e.g. `recovered/jpg/`, `recovered/png/`) instead of one flat
    /// directory.
    #[arg(long)]
    pub organize: bool,

    /// Write a manifest of carved files to this path. The format is chosen by
    /// extension: `.json` for JSON, otherwise CSV.
    #[arg(long, value_name = "FILE")]
    pub report: Option<PathBuf>,

    /// Write a run summary (source, options, counts, timing) to this path.
    /// `.json` for JSON, otherwise plain text.
    #[arg(long, value_name = "FILE")]
    pub summary: Option<PathBuf>,

    /// Checkpoint scan progress to this file so an interrupted scan can be
    /// resumed. Defaults to `<OUTPUT>.checkpoint` when `--resume` is used.
    #[arg(long, value_name = "FILE")]
    pub checkpoint: Option<PathBuf>,

    /// Resume a previous scan from its checkpoint (continues from where it
    /// stopped). Use the same SOURCE, OUTPUT, and options as the original run.
    #[arg(long)]
    pub resume: bool,

    /// Carve only the volume's unallocated (free) space, skipping clusters
    /// still in use by live files — less noise and a faster scan. Requires a
    /// filesystem whose free-space map can be read (FAT, exFAT, ext, NTFS,
    /// HFS+); otherwise the whole source is carved. Not combinable with
    /// --resume.
    #[arg(long)]
    pub unallocated: bool,

    /// Suppress the progress bar.
    #[arg(short, long)]
    pub quiet: bool,
}
