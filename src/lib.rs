//! `filerecovery` — recover deleted files from SD cards, hard drives, and disk
//! images.
//!
//! Two complementary strategies are provided:
//!
//! * [`fat`] / [`exfat`] / [`ntfs`] / [`ext4`] / [`hfsplus`] — **filesystem-aware**
//!   recovery for FAT12/16/32, exFAT, NTFS, ext2/3/4, and HFS+/HFSX. Reads the
//!   directory/MFT/inode/catalog metadata that survives deletion to restore
//!   files with their original names, paths, and sizes. Use this when the
//!   filesystem metadata is still intact (e.g. a file was just deleted). The
//!   [`recover`] module auto-detects which one applies.
//! * [`carver`] — **filesystem-agnostic** signature carving. Scans the raw
//!   bytes of a device for known file signatures and reconstructs each file's
//!   extent. Recovers data even after a quick format or partition-table loss,
//!   at the cost of not restoring original filenames.
//!
//! Both read the source strictly read-only (see [`source::Source`]).
//!
//! # Example (carving)
//!
//! ```no_run
//! use std::path::PathBuf;
//! use filerecovery::{carver, signatures, source::Source};
//!
//! let src = Source::open(std::path::Path::new("disk.img")).unwrap();
//! let sigs = signatures::select(&["jpg".to_string()]).unwrap();
//! let opts = carver::CarveOptions {
//!     output_dir: PathBuf::from("recovered"),
//!     start: 0,
//!     end: None,
//!     min_size: 0,
//!     max_size: None,
//!     max_files: None,
//!     allow_nested: false,
//!     validate: true,
//!     dedup: false,
//!     progress: false,
//!     checkpoint: None,
//!     resume: false,
//!     organize: false,
//!     dry_run: false,
//!     align: 1,
//! };
//! let stats = carver::carve(&src, &sigs, &opts, &carver::NoProgress).unwrap();
//! println!("recovered {} files", stats.files_recovered);
//! ```

pub mod apfs;
pub mod btrfs;
pub mod carver;
pub mod encrypted;
pub mod exfat;
pub mod ext4;
pub mod f2fs;
pub mod fat;
pub mod hash;
pub mod hfs;
pub mod hfsplus;
pub mod identify;
pub mod image;
pub mod iso9660;
pub mod jfs;
pub mod job;
pub mod json;
pub mod lvm;
pub mod manifest;
pub mod mcp;
pub mod mdraid;
pub mod ntfs;
pub mod partition;
pub mod recover;
pub mod refs;
pub mod reiserfs;
pub mod signatures;
pub mod source;
pub mod swap;
pub mod times;
pub mod triage;
pub mod udf;
pub mod validate;
pub mod xfs;
