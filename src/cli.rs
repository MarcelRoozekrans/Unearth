//! Command-line interface definition.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

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
    /// Recover deleted files from a FAT or exFAT filesystem, keeping their
    /// original names, paths, and sizes.
    ///
    /// More accurate than carving when the filesystem metadata is intact (e.g.
    /// a file was just deleted), but requires a readable FAT12/16/32 or exFAT
    /// volume.
    Undelete(UndeleteArgs),
    /// Show the partition / filesystem layout detected in a source.
    Info(InfoArgs),
    /// List the file types this build can recover.
    ListTypes,
}

#[derive(Parser)]
pub struct InfoArgs {
    /// Source to inspect: a disk image file or a block device. Opened read-only.
    #[arg(value_name = "SOURCE")]
    pub source: PathBuf,

    /// Also count recoverable deleted files in each volume (runs a dry scan).
    #[arg(long)]
    pub deleted: bool,
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

    /// Suppress the progress bar.
    #[arg(short, long)]
    pub quiet: bool,
}
