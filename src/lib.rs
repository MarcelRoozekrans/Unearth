//! `filerecovery` — recover deleted files from SD cards, hard drives, and disk
//! images.
//!
//! Two complementary strategies are provided:
//!
//! * [`fat`] / [`exfat`] / [`ntfs`] / [`ext4`] — **filesystem-aware** recovery
//!   for FAT12/16/32, exFAT, NTFS, and ext2/3/4. Reads the directory/MFT/inode
//!   metadata that survives deletion to restore files with their original names,
//!   paths, and sizes. Use this when the filesystem metadata is still intact
//!   (e.g. a file was just deleted). The [`recover`] module auto-detects which
//!   one applies.
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
//!     max_files: None,
//!     allow_nested: false,
//!     validate: true,
//!     dedup: false,
//!     progress: false,
//! };
//! let stats = carver::carve(&src, &sigs, &opts, &carver::NoProgress).unwrap();
//! println!("recovered {} files", stats.files_recovered);
//! ```

pub mod carver;
pub mod exfat;
pub mod ext4;
pub mod fat;
pub mod hash;
pub mod identify;
pub mod json;
pub mod manifest;
pub mod mcp;
pub mod ntfs;
pub mod recover;
pub mod signatures;
pub mod source;
pub mod times;
pub mod triage;
pub mod validate;
