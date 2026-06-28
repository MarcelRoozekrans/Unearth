//! F2FS (Flash-Friendly File System) **detection**, geometry, and label.
//!
//! F2FS is the log-structured filesystem designed for NAND flash; it is the
//! internal-storage filesystem on most Android phones and is used on many SD
//! cards and embedded devices. Being log-structured and copy-on-write, a deleted
//! file's metadata is not left in place to be scavenged the way it is for
//! FAT/exFAT/NTFS/ext/HFS+, so metadata-based undelete is not tractable here.
//! This module therefore *recognises* an F2FS volume and reports its size and
//! **label** (so `info` / `list_volumes` surface it and the user knows to fall
//! back to `scan`), but recovers nothing itself.
//!
//! Detection reads the superblock, which begins 1024 bytes into the volume: a
//! 32-bit little-endian magic `0xF2F52010`, the log2 block size and block count
//! (from which the volume size is derived), and a UTF-16LE volume label. All
//! fields are little-endian.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// The F2FS superblock begins 1024 bytes into the volume.
const SB_OFFSET: u64 = 1024;
/// `magic` (little-endian u32) at offset 0 of the superblock.
const MAGIC: u32 = 0xF2F5_2010;
/// `log_blocksize` (u32) at offset 0x10: block size = `1 << log_blocksize`.
const LOG_BLOCKSIZE_OFFSET: usize = 0x10;
/// `block_count` (u64) at offset 0x24: total blocks, in units of the block size.
const BLOCK_COUNT_OFFSET: usize = 0x24;
/// `uuid` (16 bytes) at offset 0x6C: the filesystem UUID.
const UUID_OFFSET: usize = 0x6C;
/// `volume_name[512]` (UTF-16LE, NUL-terminated) at offset 0x7C.
const VOLUME_NAME_OFFSET: usize = 0x7C;
/// How many UTF-16 code units of the label to read (plenty for any real label).
const VOLUME_NAME_UNITS: usize = 128;
/// Bytes of the superblock we read: through the start of the label field.
const SB_READ: usize = VOLUME_NAME_OFFSET + VOLUME_NAME_UNITS * 2;

/// A recognised F2FS volume (detection only; no metadata undelete).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
    block_size: u32,
    label: String,
    uuid: Option<String>,
}

/// Does the superblock at `vol_offset` carry the F2FS magic (`0xF2F52010`)?
pub fn is_f2fs(src: &Source, vol_offset: u64) -> bool {
    let Some(pos) = vol_offset.checked_add(SB_OFFSET) else {
        return false;
    };
    let mut magic = [0u8; 4];
    if src.read_at(pos, &mut magic).unwrap_or(0) < 4 {
        return false;
    }
    u32::from_le_bytes(magic) == MAGIC
}

impl Volume {
    /// Parse the F2FS superblock at `offset`, failing if it is not one.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let pos = offset
            .checked_add(SB_OFFSET)
            .ok_or_else(|| anyhow::anyhow!("offset overflow"))?;
        let mut sb = [0u8; SB_READ];
        if src.read_at(pos, &mut sb)? < SB_READ {
            bail!("F2FS superblock truncated");
        }
        if u32::from_le_bytes(sb[0..4].try_into().unwrap()) != MAGIC {
            bail!("not an F2FS volume");
        }
        let log_blocksize = u32::from_le_bytes(
            sb[LOG_BLOCKSIZE_OFFSET..LOG_BLOCKSIZE_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        // Sane block sizes are 512 B .. 64 KiB (log2 9..=16); F2FS itself uses
        // 4 KiB. Reject anything outside that so junk isn't read as a volume.
        if !(9..=16).contains(&log_blocksize) {
            bail!("implausible F2FS log block size {log_blocksize}");
        }
        let block_size = 1u32 << log_blocksize;
        let block_count = u64::from_le_bytes(
            sb[BLOCK_COUNT_OFFSET..BLOCK_COUNT_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        if block_count == 0 {
            bail!("F2FS reports zero blocks");
        }
        let size = block_count
            .checked_mul(block_size as u64)
            .unwrap_or_else(|| src.size.saturating_sub(offset));
        let label =
            decode_label(&sb[VOLUME_NAME_OFFSET..VOLUME_NAME_OFFSET + VOLUME_NAME_UNITS * 2]);
        let uuid = crate::recover::format_uuid(&sb[UUID_OFFSET..UUID_OFFSET + 16]);
        Ok(Volume {
            offset,
            size,
            block_size,
            label,
            uuid,
        })
    }

    /// Total size of the volume in bytes (block count × block size).
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Short filesystem label.
    pub fn fs_label(&self) -> &'static str {
        "F2FS"
    }

    /// The user-set volume label, or an empty string when none.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// F2FS block size in bytes.
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// The filesystem UUID, or `None` when unset.
    pub fn uuid(&self) -> Option<String> {
        self.uuid.clone()
    }

    /// F2FS metadata undelete is not supported (see the module docs); this always
    /// returns an empty result so a mixed disk's other volumes still recover.
    /// Use `scan` (carving) to recover data from an F2FS volume.
    pub fn recover_deleted(
        &self,
        _src: &Source,
        _out_dir: &Path,
        _opts: &RecoverOptions,
    ) -> Result<RecoverStats> {
        Ok(RecoverStats::default())
    }
}

/// Decode a UTF-16LE, NUL-terminated label from `bytes`.
fn decode_label(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal F2FS volume (superblock at byte 1024) with the given
    /// log2 block size, block count, and label.
    fn volume(log_blocksize: u32, block_count: u64, label: &str) -> Vec<u8> {
        let mut v = vec![0u8; SB_OFFSET as usize + SB_READ];
        let sb = SB_OFFSET as usize;
        v[sb..sb + 4].copy_from_slice(&MAGIC.to_le_bytes());
        v[sb + LOG_BLOCKSIZE_OFFSET..sb + LOG_BLOCKSIZE_OFFSET + 4]
            .copy_from_slice(&log_blocksize.to_le_bytes());
        v[sb + BLOCK_COUNT_OFFSET..sb + BLOCK_COUNT_OFFSET + 8]
            .copy_from_slice(&block_count.to_le_bytes());
        v[sb + UUID_OFFSET..sb + UUID_OFFSET + 16].copy_from_slice(&[0x22; 16]);
        for (i, u) in label.encode_utf16().enumerate() {
            let o = sb + VOLUME_NAME_OFFSET + i * 2;
            v[o..o + 2].copy_from_slice(&u.to_le_bytes());
        }
        v
    }

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("v.img");
        std::fs::write(&p, bytes).unwrap();
        let src = Source::open(&p).unwrap();
        (tmp, src)
    }

    #[test]
    fn detects_sizes_and_labels_a_volume() {
        // log_blocksize 12 => 4096-byte blocks; 2560 blocks => 10 MiB.
        let (_t, src) = source_of(&volume(12, 2560, "userdata"));
        assert!(is_f2fs(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "F2FS");
        assert_eq!(v.block_size(), 4096);
        assert_eq!(v.size(), 4096 * 2560);
        assert_eq!(v.label(), "userdata");
        assert_eq!(v.uuid().unwrap(), "22222222-2222-2222-2222-222222222222");
    }

    #[test]
    fn rejects_bad_magic_and_geometry() {
        // No magic.
        let (_t, src) = source_of(&vec![0u8; SB_OFFSET as usize + SB_READ]);
        assert!(!is_f2fs(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());

        // Magic present but an out-of-range log block size.
        let (_t, src) = source_of(&volume(30, 2560, ""));
        assert!(Volume::parse(&src, 0).is_err());

        // Magic present but zero blocks.
        let (_t, src) = source_of(&volume(12, 0, ""));
        assert!(Volume::parse(&src, 0).is_err());
    }

    #[test]
    fn empty_label_is_blank() {
        let (_t, src) = source_of(&volume(12, 100, ""));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.label(), "");
        assert_eq!(v.size(), 4096 * 100);
    }
}
