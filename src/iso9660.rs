//! ISO 9660 volume detection and file extraction (data CD/DVD discs and `.iso`
//! images).
//!
//! ISO 9660 is the classic optical-disc filesystem. Unlike UDF, its directory
//! structure is simple and read-only, so `filerecovery` both recognises it (in
//! `info`/`list_volumes`, with size and label) *and* extracts its files with
//! their original names and folder paths — which is far better than carving,
//! which loses both. Extraction walks the directory tree from the Primary Volume
//! Descriptor, or from the **Joliet** Supplementary Volume Descriptor when one
//! is present, so the long, Unicode (UCS-2) filenames that Windows-authored
//! discs use are recovered intact. (Rock Ridge long names are not yet decoded,
//! falling back to the short ISO 9660 identifier.)
//!
//! Detection reads the **Volume Descriptor Set** at sector 16 (byte offset
//! 32768): a series of 2048-byte descriptors each `{ type: u8, id: "CD001",
//! version: u8, ... }`. The **Primary Volume Descriptor** (type 1) carries the
//! volume identifier (label), the volume size (block count × block size), and
//! the root directory record. A UDF disc with an ISO bridge is detected as UDF
//! first (it has the additional `NSR` descriptor), so this only claims pure
//! ISO 9660.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::hash::HashingWriter;
use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// The Volume Descriptor Set begins at sector 16 with 2048-byte sectors.
const VDS_OFFSET: u64 = 16 * 2048;
const VD_SIZE: u64 = 2048;
const PRIMARY: u8 = 1;
const SUPPLEMENTARY: u8 = 2;
const TERMINATOR: u8 = 255;
/// Bound the directory walk against malformed or hostile images.
const MAX_DEPTH: usize = 64;
const MAX_ENTRIES: u64 = 5_000_000;
/// Largest single directory extent we will read into memory.
const MAX_DIR_BYTES: u64 = 32 * 1024 * 1024;

/// A recognised ISO 9660 volume.
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
    label: String,
    block_size: u64,
    root_lba: u64,
    root_len: u64,
    /// Directory names are UCS-2 (Joliet) rather than short ISO 9660 identifiers.
    joliet: bool,
}

/// Recognise an ISO 9660 volume at `offset` by finding its Primary Volume
/// Descriptor. Returns `None` when no `CD001` Primary descriptor is present.
pub fn detect(src: &Source, offset: u64) -> Option<Volume> {
    let base = offset.checked_add(VDS_OFFSET)?;
    let mut primary: Option<Volume> = None;
    let mut joliet_root: Option<(u64, u64)> = None;
    for i in 0..16u64 {
        let pos = base.checked_add(i * VD_SIZE)?;
        let mut d = [0u8; 256];
        if src.read_at(pos, &mut d).ok()? < d.len() {
            break;
        }
        if &d[1..6] != b"CD001" {
            break; // not a volume descriptor: the set has ended
        }
        match d[0] {
            PRIMARY => primary = Some(parse_primary(offset, src, &d)),
            SUPPLEMENTARY if is_joliet(&d) => joliet_root = Some(root_record(&d)),
            TERMINATOR => break,
            _ => {} // boot record / non-Joliet supplementary: keep scanning
        }
    }
    let mut vol = primary?;
    // Prefer the Joliet directory tree: its names are the full Unicode names.
    if let Some((lba, len)) = joliet_root {
        vol.root_lba = lba;
        vol.root_len = len;
        vol.joliet = true;
    }
    Some(vol)
}

/// Whether a Supplementary Volume Descriptor declares Joliet via its escape
/// sequences field (offset 88): `%/@`, `%/C`, or `%/E` for UCS-2 levels 1–3.
fn is_joliet(svd: &[u8]) -> bool {
    matches!(&svd[88..91], b"%/@" | b"%/C" | b"%/E")
}

/// Extent LBA and data length of the root Directory Record embedded at offset
/// 156 of a (primary or supplementary) volume descriptor.
fn root_record(vd: &[u8]) -> (u64, u64) {
    let r = &vd[156..];
    let lba = u32::from_le_bytes([r[2], r[3], r[4], r[5]]) as u64;
    let len = u32::from_le_bytes([r[10], r[11], r[12], r[13]]) as u64;
    (lba, len)
}

/// Build a [`Volume`] from a Primary Volume Descriptor's bytes.
fn parse_primary(offset: u64, src: &Source, pvd: &[u8]) -> Volume {
    // Volume Space Size (block count) is a both-endian u32 at offset 80; the
    // little-endian half is first. Logical Block Size is a both-endian u16 at
    // offset 128. Total size = block count × block size.
    let blocks = u32::from_le_bytes([pvd[80], pvd[81], pvd[82], pvd[83]]) as u64;
    let block_size = u16::from_le_bytes([pvd[128], pvd[129]]) as u64;
    let computed = blocks.checked_mul(block_size).unwrap_or(0);
    let size = if computed == 0 {
        src.size.saturating_sub(offset)
    } else {
        computed
    };
    // Volume Identifier: 32 d-characters at offset 40, space/NUL padded.
    let raw = &pvd[40..72];
    let end = raw
        .iter()
        .rposition(|&b| b != b' ' && b != 0)
        .map_or(0, |p| p + 1);
    let label = String::from_utf8_lossy(&raw[..end]).trim().to_string();
    let (root_lba, root_len) = root_record(pvd);
    Volume {
        offset,
        size,
        label,
        block_size,
        root_lba,
        root_len,
        joliet: false,
    }
}

impl Volume {
    /// Parse an ISO 9660 volume at `offset`, failing if it is not one.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        match detect(src, offset) {
            Some(v) => Ok(v),
            None => bail!("not a recognised ISO 9660 volume"),
        }
    }

    /// Size of the volume in bytes (block count × block size from the PVD).
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Filesystem label.
    pub fn fs_label(&self) -> &'static str {
        "ISO 9660"
    }

    /// The volume identifier from the Primary Volume Descriptor (may be empty).
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Extract every file from the volume into `out_dir`, preserving names and
    /// folder paths by walking the directory tree from the root record. (ISO
    /// 9660 is read-only, so "recover" here means extract the live files; the
    /// method name matches the other backends for a uniform dispatch.)
    pub fn recover_deleted(
        &self,
        src: &Source,
        out_dir: &Path,
        opts: &RecoverOptions,
    ) -> Result<RecoverStats> {
        let mut stats = RecoverStats::default();
        // A sane block size is required to translate LBAs to byte offsets.
        if !(512..=65536).contains(&self.block_size) || self.root_len == 0 {
            return Ok(stats);
        }
        let vol_end = self.offset.saturating_add(self.size).min(src.size);

        let mut visited: HashSet<u64> = HashSet::new();
        let mut entries = 0u64;
        // Stack of directories to walk: (extent LBA, byte length, relative path,
        // depth).
        let mut stack: Vec<(u64, u64, PathBuf, usize)> =
            vec![(self.root_lba, self.root_len, PathBuf::new(), 0)];

        while let Some((lba, len, rel, depth)) = stack.pop() {
            if !visited.insert(lba) || entries >= MAX_ENTRIES {
                continue; // already walked, or run-away guard tripped
            }
            let Some(dir) = self.read_extent(src, lba, len, vol_end) else {
                continue; // extent out of bounds or unreadable
            };

            let mut pos = 0usize;
            while pos < dir.len() {
                let rec_len = dir[pos] as usize;
                if rec_len == 0 {
                    // Records do not span sectors; a zero length is padding to
                    // the next logical block.
                    let next = (pos / self.block_size as usize + 1) * self.block_size as usize;
                    pos = next;
                    continue;
                }
                if pos + rec_len > dir.len() || rec_len < 33 {
                    break;
                }
                entries += 1;
                let rec = &dir[pos..pos + rec_len];
                pos += rec_len;

                let name_len = rec[32] as usize;
                if 33 + name_len > rec.len() {
                    continue;
                }
                let name_bytes = &rec[33..33 + name_len];
                // The "." and ".." entries use single bytes 0x00 and 0x01.
                if name_len == 1 && (name_bytes[0] == 0 || name_bytes[0] == 1) {
                    continue;
                }
                let child_lba = u32::from_le_bytes([rec[2], rec[3], rec[4], rec[5]]) as u64;
                let child_len = u32::from_le_bytes([rec[10], rec[11], rec[12], rec[13]]) as u64;
                let is_dir = rec[25] & 0x02 != 0;
                let name = decode_name(name_bytes, is_dir, self.joliet);
                let child_rel = rel.join(&name);

                if is_dir {
                    if depth + 1 < MAX_DEPTH {
                        stack.push((child_lba, child_len, child_rel, depth + 1));
                    }
                    continue;
                }
                self.recover_file(
                    src, out_dir, child_lba, child_len, child_rel, vol_end, opts, &mut stats,
                );
            }
        }
        Ok(stats)
    }

    /// Read a directory extent (`lba`/`len`) into memory, or `None` if it falls
    /// outside the volume or is implausibly large.
    fn read_extent(&self, src: &Source, lba: u64, len: u64, vol_end: u64) -> Option<Vec<u8>> {
        if len == 0 || len > MAX_DIR_BYTES {
            return None;
        }
        let start = self.offset.checked_add(lba.checked_mul(self.block_size)?)?;
        if start < self.offset || start.checked_add(len)? > vol_end {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        let n = src.read_at(start, &mut buf).ok()?;
        buf.truncate(n);
        Some(buf)
    }

    /// Extract one file, recording it in `stats` (or counting it for a dry run).
    #[allow(clippy::too_many_arguments)]
    fn recover_file(
        &self,
        src: &Source,
        out_dir: &Path,
        lba: u64,
        len: u64,
        rel: PathBuf,
        vol_end: u64,
        opts: &RecoverOptions,
        stats: &mut RecoverStats,
    ) {
        if !opts.size_ok(len) {
            return;
        }
        // Validate the data extent before trusting it.
        let start = match self.offset.checked_add(lba.saturating_mul(self.block_size)) {
            Some(s) if s >= self.offset && s.saturating_add(len) <= vol_end => s,
            _ => {
                stats.record_skipped(rel, len);
                return;
            }
        };
        if opts.dry_run {
            stats.record_recovered(rel, len, None);
            return;
        }
        match write_file(src, out_dir, &rel, start, len) {
            Ok(digest) => stats.record_recovered(rel, len, Some(digest)),
            Err(_) => stats.record_skipped(rel, len),
        }
    }
}

/// Decode a directory-record file identifier: UCS-2 big-endian for Joliet, else
/// ASCII d-characters. Strips the `;version` suffix and a single trailing `.`
/// from files, and sanitises the result into a safe path component.
fn decode_name(bytes: &[u8], is_dir: bool, joliet: bool) -> String {
    let mut s = if joliet {
        // Joliet names are UCS-2 (UTF-16) big-endian.
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).to_string()
    };
    if !is_dir {
        if let Some(semi) = s.find(';') {
            s.truncate(semi);
        }
        if s.ends_with('.') {
            s.pop();
        }
    }
    sanitize_component(&s)
}

/// Stream `len` bytes at `start` into `out_dir/rel`, returning the SHA-256 of the
/// written bytes.
fn write_file(src: &Source, out_dir: &Path, rel: &Path, start: u64, len: u64) -> Result<[u8; 32]> {
    let target = unique_path(out_dir, rel);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let file =
        fs::File::create(&target).with_context(|| format!("creating {}", target.display()))?;
    let mut out = HashingWriter::new(file);

    let mut remaining = len;
    let mut pos = start;
    let buf_len = (len as usize).clamp(1, 1024 * 1024);
    let mut buf = vec![0u8; buf_len];
    while remaining > 0 {
        let want = (remaining as usize).min(buf.len());
        let n = src.read_at(pos, &mut buf[..want])?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])?;
        remaining -= n as u64;
        pos += n as u64;
    }
    out.flush().ok();
    let (_, digest) = out.into_parts();
    Ok(digest)
}

/// Map a name to a safe single path component (no separators or control chars).
fn sanitize_component(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c == '/' || c == '\\' || c == '\0' || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        "_recovered".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Build a non-colliding output path by appending a counter if needed.
fn unique_path(out_dir: &Path, rel: &Path) -> PathBuf {
    let candidate = out_dir.join(rel);
    if !candidate.exists() {
        return candidate;
    }
    let stem = rel
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let ext = rel.extension().map(|e| e.to_string_lossy().to_string());
    let parent = rel.parent().map(|p| p.to_path_buf()).unwrap_or_default();
    for i in 1.. {
        let name = match &ext {
            Some(e) => format!("{stem}_{i}.{e}"),
            None => format!("{stem}_{i}"),
        };
        let candidate = out_dir.join(&parent).join(name);
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("i.img");
        std::fs::write(&p, bytes).unwrap();
        (tmp, Source::open(&p).unwrap())
    }

    /// Write a volume descriptor of `vtype` (with the `CD001` identifier) at
    /// sector `16 + index`, returning its byte offset for further field writes.
    fn put_descriptor(v: &mut [u8], index: u64, vtype: u8) -> usize {
        let off = (VDS_OFFSET + index * VD_SIZE) as usize;
        v[off] = vtype;
        v[off + 1..off + 6].copy_from_slice(b"CD001");
        v[off + 6] = 1;
        off
    }

    /// Write a directory record at `buf[at..]` and return its length.
    fn put_record(
        buf: &mut [u8],
        at: usize,
        lba: u32,
        len: u32,
        is_dir: bool,
        name: &[u8],
    ) -> usize {
        let rec_len = 33 + name.len() + (name.len() % 2 == 0) as usize; // padded to even
        buf[at] = rec_len as u8;
        buf[at + 2..at + 6].copy_from_slice(&lba.to_le_bytes());
        buf[at + 10..at + 14].copy_from_slice(&len.to_le_bytes());
        buf[at + 25] = if is_dir { 0x02 } else { 0 };
        buf[at + 32] = name.len() as u8;
        buf[at + 33..at + 33 + name.len()].copy_from_slice(name);
        rec_len
    }

    #[test]
    fn detects_primary_with_size_and_label() {
        let mut v = vec![0u8; (VDS_OFFSET + 4 * VD_SIZE) as usize];
        let off = put_descriptor(&mut v, 0, PRIMARY);
        v[off + 80..off + 84].copy_from_slice(&100u32.to_le_bytes());
        v[off + 128..off + 130].copy_from_slice(&2048u16.to_le_bytes());
        v[off + 40..off + 40 + 11].copy_from_slice(b"UBUNTU_2204");

        let (_t, src) = source_of(&v);
        let vol = detect(&src, 0).unwrap();
        assert_eq!(vol.fs_label(), "ISO 9660");
        assert_eq!(vol.size(), 100 * 2048);
        assert_eq!(vol.label(), "UBUNTU_2204");
    }

    #[test]
    fn rejects_non_iso_data() {
        let (_t, src) = source_of(&vec![0u8; (VDS_OFFSET + 4 * VD_SIZE) as usize]);
        assert!(detect(&src, 0).is_none());
        assert!(Volume::parse(&src, 0).is_err());
    }

    #[test]
    fn extracts_files_with_names_and_paths() {
        const BS: usize = 2048;
        // Layout: sector 16 = PVD; sector 18 = root dir; sector 19 = subdir;
        // sector 20 = HELLO.TXT data; sector 21 = NOTE.TXT data.
        let total = 22 * BS;
        let mut v = vec![0u8; total];

        let payload_hello = b"hello iso";
        let payload_note = b"a note in a subdir";
        v[20 * BS..20 * BS + payload_hello.len()].copy_from_slice(payload_hello);
        v[21 * BS..21 * BS + payload_note.len()].copy_from_slice(payload_note);

        // Root directory (sector 18): ".", "..", HELLO.TXT;1, SUB (dir).
        let root = 18 * BS;
        let mut p = root;
        p += put_record(&mut v, p, 18, BS as u32, true, &[0x00]);
        p += put_record(&mut v, p, 18, BS as u32, true, &[0x01]);
        p += put_record(
            &mut v,
            p,
            20,
            payload_hello.len() as u32,
            false,
            b"HELLO.TXT;1",
        );
        let _ = put_record(&mut v, p, 19, BS as u32, true, b"SUB");

        // Subdirectory (sector 19): ".", "..", NOTE.TXT;1.
        let sub = 19 * BS;
        let mut q = sub;
        q += put_record(&mut v, q, 19, BS as u32, true, &[0x00]);
        q += put_record(&mut v, q, 18, BS as u32, true, &[0x01]);
        let _ = put_record(
            &mut v,
            q,
            21,
            payload_note.len() as u32,
            false,
            b"NOTE.TXT;1",
        );

        // PVD (sector 16): block size, volume size, and the root record at +156.
        let off = put_descriptor(&mut v, 0, PRIMARY);
        v[off + 80..off + 84].copy_from_slice(&22u32.to_le_bytes());
        v[off + 128..off + 130].copy_from_slice(&(BS as u16).to_le_bytes());
        // Root directory record embedded in the PVD: extent = sector 18.
        put_record(&mut v, off + 156, 18, BS as u32, true, &[0x00]);

        let (tmp, src) = source_of(&v);
        let vol = detect(&src, 0).unwrap();
        let out = tmp.path().join("out");
        let stats = vol
            .recover_deleted(&src, &out, &RecoverOptions::default())
            .unwrap();

        assert_eq!(stats.recovered, 2, "two files extracted");
        assert_eq!(std::fs::read(out.join("HELLO.TXT")).unwrap(), payload_hello);
        assert_eq!(
            std::fs::read(out.join("SUB").join("NOTE.TXT")).unwrap(),
            payload_note,
            "file recovered under its subdirectory path"
        );
    }

    /// Encode a string as UCS-2 big-endian, as Joliet stores names.
    fn ucs2_be(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
    }

    #[test]
    fn joliet_long_names_are_preferred() {
        const BS: usize = 2048;
        // sector 16 = PVD, 17 = Joliet SVD, 18 = primary root, 19 = Joliet root,
        // 20 = file data.
        let total = 22 * BS;
        let mut v = vec![0u8; total];
        let payload = b"joliet payload";
        v[20 * BS..20 * BS + payload.len()].copy_from_slice(payload);

        // Primary root (sector 18): the short 8.3 name.
        let mut p = 18 * BS;
        p += put_record(&mut v, p, 18, BS as u32, true, &[0x00]);
        p += put_record(&mut v, p, 18, BS as u32, true, &[0x01]);
        let _ = put_record(
            &mut v,
            p,
            20,
            payload.len() as u32,
            false,
            b"MYPHOT~1.JPG;1",
        );

        // Joliet root (sector 19): the full Unicode name (UCS-2 BE).
        let mut q = 19 * BS;
        q += put_record(&mut v, q, 19, BS as u32, true, &[0x00]);
        q += put_record(&mut v, q, 18, BS as u32, true, &[0x01]);
        let jname = ucs2_be("My Photo.jpg;1");
        let _ = put_record(&mut v, q, 20, payload.len() as u32, false, &jname);

        // PVD (sector 16): root at sector 18.
        let off = put_descriptor(&mut v, 0, PRIMARY);
        v[off + 80..off + 84].copy_from_slice(&22u32.to_le_bytes());
        v[off + 128..off + 130].copy_from_slice(&(BS as u16).to_le_bytes());
        put_record(&mut v, off + 156, 18, BS as u32, true, &[0x00]);

        // Joliet SVD (sector 17): escape sequence "%/E" and root at sector 19.
        let soff = put_descriptor(&mut v, 1, SUPPLEMENTARY);
        v[soff + 88..soff + 91].copy_from_slice(b"%/E");
        v[soff + 128..soff + 130].copy_from_slice(&(BS as u16).to_le_bytes());
        put_record(&mut v, soff + 156, 19, BS as u32, true, &[0x00]);

        let (tmp, src) = source_of(&v);
        let vol = detect(&src, 0).unwrap();
        let out = tmp.path().join("out");
        let stats = vol
            .recover_deleted(&src, &out, &RecoverOptions::default())
            .unwrap();

        assert_eq!(stats.recovered, 1);
        // The Joliet long name is used, not the short MYPHOT~1.JPG.
        assert_eq!(std::fs::read(out.join("My Photo.jpg")).unwrap(), payload);
    }
}
