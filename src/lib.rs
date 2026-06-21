//! `filerecovery` — recover deleted files from SD cards, hard drives, and disk
//! images using signature-based file carving.
//!
//! The library is filesystem-agnostic: instead of parsing FAT/NTFS/ext
//! directory structures, it scans the raw bytes of a device for known file
//! signatures and reconstructs each file's extent. This recovers data even
//! after a quick format or partition-table loss, at the cost of not restoring
//! original filenames.
//!
//! # Example
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
//!     progress: false,
//! };
//! let stats = carver::carve(&src, &sigs, &opts, &carver::NoProgress).unwrap();
//! println!("recovered {} files", stats.files_recovered);
//! ```

pub mod carver;
pub mod signatures;
pub mod source;
