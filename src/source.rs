//! Read-only access to the device or image we are recovering from.
//!
//! The source is **never** written to. We open it read-only and only ever
//! issue positioned reads, so running the tool against a live device cannot
//! modify it.

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::path::Path;

use anyhow::{Context, Result};

/// A read-only handle to a block device or disk image.
pub struct Source {
    file: File,
    /// Total readable size in bytes.
    pub size: u64,
}

impl Source {
    /// Open `path` read-only and determine its size.
    ///
    /// Works for both regular image files and block devices. Block devices
    /// report a length of `0` through `metadata()`, so we fall back to seeking
    /// to the end to discover the real size.
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .open(path)
            .with_context(|| format!("opening source {} (read-only)", path.display()))?;

        let meta_len = file.metadata().map(|m| m.len()).unwrap_or(0);
        let size = if meta_len > 0 {
            meta_len
        } else {
            // Block devices: discover size by seeking to the end.
            file.seek(SeekFrom::End(0))
                .with_context(|| format!("determining size of {}", path.display()))?
        };

        if size == 0 {
            anyhow::bail!(
                "{} reports a size of 0 bytes; nothing to scan",
                path.display()
            );
        }

        Ok(Source { file, size })
    }

    /// Read up to `buf.len()` bytes starting at absolute `offset`.
    ///
    /// Returns the number of bytes actually read, which may be short at the end
    /// of the device. Uses positioned reads so it does not disturb (or depend
    /// on) the file's seek cursor.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            let mut total = 0;
            while total < buf.len() {
                match self.file.read_at(&mut buf[total..], offset + total as u64) {
                    Ok(0) => break,
                    Ok(n) => total += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e).context("reading from source"),
                }
            }
            Ok(total)
        }
        #[cfg(not(unix))]
        {
            use std::io::Read;
            // Fall back to seek + read on non-unix platforms. This needs &mut,
            // so clone a handle to keep `read_at` taking &self.
            let mut f = self.file.try_clone().context("cloning source handle")?;
            f.seek(SeekFrom::Start(offset)).context("seeking source")?;
            let mut total = 0;
            while total < buf.len() {
                match f.read(&mut buf[total..]) {
                    Ok(0) => break,
                    Ok(n) => total += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e).context("reading from source"),
                }
            }
            Ok(total)
        }
    }
}
