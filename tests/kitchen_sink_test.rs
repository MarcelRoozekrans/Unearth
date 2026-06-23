//! End-to-end "kitchen sink" regression test over the whole pipeline.
//!
//! One synthetic image embeds a representative file for **every carve extent
//! strategy** (footer, header-size, RIFF, SQLite, 7z, MP4 atoms, ELF, PE, TIFF,
//! EBML, Ogg). It is carved in a single pass with validation and content
//! deduplication on, and each recovered file is checked byte-for-byte and by
//! SHA-256. A second pass builds a multi-volume GPT disk and recovers deleted
//! files from two filesystems at once. This guards the interactions between
//! features (signature ordering, skip-past, validation, dedup, the manifest)
//! that the per-format tests do not exercise together.

mod common;

use std::collections::BTreeMap;
use std::io::Write;

use filerecovery::carver::{self, CarveOptions, NoProgress};
use filerecovery::recover::{self, RecoverOptions};
use filerecovery::signatures;
use filerecovery::source::Source;

/// Deterministic filler that never contains `0xFF` or two bytes that form a
/// footer/magic, so payloads can't carry stray signatures of their own.
fn filler(seed: u64, n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i as u64 + seed) % 251) as u8).collect()
}

fn jpeg(p: &[u8]) -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
    v.extend_from_slice(p);
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

fn png(p: &[u8]) -> Vec<u8> {
    let mut v = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    v.extend_from_slice(&13u32.to_be_bytes());
    v.extend_from_slice(b"IHDR");
    v.extend_from_slice(&64u32.to_be_bytes());
    v.extend_from_slice(&64u32.to_be_bytes());
    v.extend_from_slice(&[8, 6, 0, 0, 0, 0, 0, 0, 0]); // bit depth etc + CRC
    v.extend_from_slice(p);
    v.extend_from_slice(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]);
    v
}

fn gif(p: &[u8]) -> Vec<u8> {
    let mut v = b"GIF89a".to_vec();
    v.extend_from_slice(&64u16.to_le_bytes()); // width
    v.extend_from_slice(&64u16.to_le_bytes()); // height
    v.extend_from_slice(&[0, 0, 0]); // packed, background, aspect
    v.extend_from_slice(p);
    v.extend_from_slice(&[0x00, 0x3B]);
    v
}

fn bmp(p: &[u8]) -> Vec<u8> {
    let total = (54 + p.len()) as u32;
    let mut v = vec![b'B', b'M'];
    v.extend_from_slice(&total.to_le_bytes()); // size at offset 2
    v.extend_from_slice(&0u32.to_le_bytes()); // reserved
    v.extend_from_slice(&54u32.to_le_bytes()); // pixel offset
    v.extend_from_slice(&40u32.to_le_bytes()); // DIB header size
    v.extend_from_slice(&64i32.to_le_bytes()); // width
    v.extend_from_slice(&64i32.to_le_bytes()); // height
    v.extend_from_slice(&1u16.to_le_bytes()); // planes
    v.extend_from_slice(&24u16.to_le_bytes()); // bpp
    v.extend_from_slice(&[0u8; 24]);
    v.extend_from_slice(p);
    v
}

fn pdf(p: &[u8]) -> Vec<u8> {
    let mut v = b"%PDF-1.7\n".to_vec();
    v.extend_from_slice(p);
    v.extend_from_slice(b"%%EOF\r\n"); // marker + 2 trailing bytes
    v
}

fn zip(p: &[u8]) -> Vec<u8> {
    let mut v = vec![0x50, 0x4B, 0x03, 0x04];
    v.extend_from_slice(p);
    v.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]); // EOCD
    v.extend_from_slice(&[0u8; 18]); // minimal EOCD remainder
    v
}

fn wav(p: &[u8]) -> Vec<u8> {
    let mut v = b"RIFF".to_vec();
    v.extend_from_slice(&((4 + p.len()) as u32).to_le_bytes()); // "WAVE" + payload
    v.extend_from_slice(b"WAVE");
    v.extend_from_slice(p);
    v
}

fn sqlite(page_size: u16, page_count: u32) -> Vec<u8> {
    let mut v = vec![0u8; page_size as usize * page_count as usize];
    v[0..16].copy_from_slice(b"SQLite format 3\0");
    v[16..18].copy_from_slice(&page_size.to_be_bytes());
    v[18] = 1;
    v[19] = 1;
    v[21] = 64;
    v[22] = 32;
    v[23] = 32;
    v[28..32].copy_from_slice(&page_count.to_be_bytes());
    for (i, b) in v.iter_mut().enumerate().skip(100) {
        *b = (i % 251) as u8;
    }
    v
}

fn sevenz(next_off: u64, next_size: u64) -> Vec<u8> {
    let mut v = vec![0u8; 32 + next_off as usize + next_size as usize];
    v[0..6].copy_from_slice(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);
    v[12..20].copy_from_slice(&next_off.to_le_bytes());
    v[20..28].copy_from_slice(&next_size.to_le_bytes());
    for (i, b) in v.iter_mut().enumerate().skip(32) {
        *b = (i % 241) as u8;
    }
    v
}

fn heic(p: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&16u32.to_be_bytes());
    v.extend_from_slice(b"ftyp");
    v.extend_from_slice(b"heic");
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(&((8 + p.len()) as u32).to_be_bytes());
    v.extend_from_slice(b"mdat");
    v.extend_from_slice(p);
    v
}

fn elf(shnum: u16) -> Vec<u8> {
    let size = 64 + shnum as usize * 64;
    let mut v = vec![0u8; size];
    v[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    v[4] = 2;
    v[5] = 1;
    v[6] = 1;
    v[0x28..0x30].copy_from_slice(&64u64.to_le_bytes()); // e_shoff
    v[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    v[0x3C..0x3E].copy_from_slice(&shnum.to_le_bytes()); // e_shnum
    for (i, b) in v.iter_mut().enumerate().skip(64) {
        *b = (i % 251) as u8;
    }
    v
}

fn pe() -> Vec<u8> {
    let opt_size = 112usize;
    let headers = 64 + 4 + 20 + opt_size + 2 * 40;
    let s0_ptr = headers;
    let total = s0_ptr + 200 + 100;
    let mut v = vec![0u8; total];
    v[0..2].copy_from_slice(b"MZ");
    v[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
    v[64..68].copy_from_slice(b"PE\0\0");
    v[70..72].copy_from_slice(&2u16.to_le_bytes()); // NumberOfSections
    v[84..86].copy_from_slice(&(opt_size as u16).to_le_bytes());
    v[88..90].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+
    let sec = 64 + 4 + 20 + opt_size;
    v[sec + 16..sec + 20].copy_from_slice(&200u32.to_le_bytes());
    v[sec + 20..sec + 24].copy_from_slice(&(s0_ptr as u32).to_le_bytes());
    v[sec + 56..sec + 60].copy_from_slice(&100u32.to_le_bytes());
    v[sec + 60..sec + 64].copy_from_slice(&((s0_ptr + 200) as u32).to_le_bytes());
    for (i, b) in v.iter_mut().enumerate().skip(s0_ptr) {
        *b = (i % 251) as u8;
    }
    v
}

fn tiff(image: &[u8]) -> Vec<u8> {
    let n: u16 = 4;
    let ifd = 8usize;
    let strip = ifd + 2 + n as usize * 12 + 4;
    let total = strip + image.len();
    let mut v = vec![0u8; total];
    v[0..2].copy_from_slice(b"II");
    v[2..4].copy_from_slice(&42u16.to_le_bytes());
    v[4..8].copy_from_slice(&(ifd as u32).to_le_bytes());
    v[ifd..ifd + 2].copy_from_slice(&n.to_le_bytes());
    let mut e = |idx: usize, tag: u16, typ: u16, c: u32, val: u32| {
        let o = ifd + 2 + idx * 12;
        v[o..o + 2].copy_from_slice(&tag.to_le_bytes());
        v[o + 2..o + 4].copy_from_slice(&typ.to_le_bytes());
        v[o + 4..o + 8].copy_from_slice(&c.to_le_bytes());
        v[o + 8..o + 12].copy_from_slice(&val.to_le_bytes());
    };
    e(0, 256, 4, 1, 64);
    e(1, 257, 4, 1, image.len() as u32 / 64);
    e(2, 273, 4, 1, strip as u32);
    e(3, 279, 4, 1, image.len() as u32);
    v[strip..strip + image.len()].copy_from_slice(image);
    v
}

fn ebml_vint(value: u64, len: u32) -> Vec<u8> {
    let mut b = vec![0u8; len as usize];
    for i in 0..len as usize {
        b[len as usize - 1 - i] = (value >> (8 * i)) as u8;
    }
    b[0] |= 1u8 << (8 - len);
    b
}

fn mkv(p: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0x1A, 0x45, 0xDF, 0xA3]);
    v.extend_from_slice(&ebml_vint(0, 1));
    v.extend_from_slice(&[0x18, 0x53, 0x80, 0x67]);
    v.extend_from_slice(&ebml_vint(p.len() as u64, 8));
    v.extend_from_slice(p);
    v
}

fn ogg(p: &[u8]) -> Vec<u8> {
    let mut segs = Vec::new();
    let mut rem = p.len();
    loop {
        if rem >= 255 {
            segs.push(255u8);
            rem -= 255;
        } else {
            segs.push(rem as u8);
            break;
        }
    }
    let mut v = Vec::new();
    v.extend_from_slice(b"OggS");
    v.push(0);
    v.push(0x02);
    v.extend_from_slice(&0u64.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.push(segs.len() as u8);
    v.extend_from_slice(&segs);
    v.extend_from_slice(p);
    v
}

#[test]
fn carves_every_extent_strategy_in_one_pass() {
    // One representative file per extent strategy.
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("jpg", jpeg(&filler(1, 3000))),  // Footer
        ("png", png(&filler(2, 2500))),   // Footer
        ("gif", gif(&filler(3, 1800))),   // Footer
        ("pdf", pdf(&filler(4, 2200))),   // Footer
        ("zip", zip(&filler(5, 2600))),   // Footer
        ("bmp", bmp(&filler(6, 2000))),   // HeaderSizeLe32
        ("wav", wav(&filler(7, 2400))),   // RiffSize
        ("sqlite", sqlite(512, 8)),       // Sqlite
        ("7z", sevenz(120, 60)),          // SevenZip
        ("heic", heic(&filler(8, 2700))), // Mp4Atoms
        ("elf", elf(3)),                  // Elf
        ("exe", pe()),                    // Pe
        ("tif", tiff(&filler(9, 3200))),  // Tiff
        ("mkv", mkv(&filler(10, 4096))),  // Ebml
        ("ogg", ogg(&filler(11, 3500))),  // Ogg
    ];

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    // Lay the files out with zero-filled gaps (which cleanly terminate every
    // length strategy) and a duplicate of the JPEG to exercise --dedup.
    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&vec![0u8; 1024]).unwrap();
    for (_, bytes) in &files {
        img.write_all(bytes).unwrap();
        img.write_all(&vec![0u8; 1024]).unwrap();
    }
    img.write_all(&files[0].1).unwrap(); // duplicate JPEG content
    img.write_all(&vec![0u8; 1024]).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&[]).unwrap();
    let opts = CarveOptions {
        output_dir: out_dir.clone(),
        start: 0,
        end: None,
        min_size: 0,
        max_files: None,
        allow_nested: false,
        validate: true,
        dedup: true,
        progress: false,
        checkpoint: None,
        resume: false,
    };
    let stats = carver::carve(&source, &sigs, &opts, &NoProgress).unwrap();

    // The duplicate JPEG is deduped away, so exactly one file per type remains.
    assert_eq!(
        stats.files_recovered as usize,
        files.len(),
        "one file per type"
    );
    assert_eq!(stats.duplicates, 1, "the repeated JPEG is skipped");
    assert_eq!(stats.rejected, 0, "no valid file rejected by validation");

    // Per-type counts: every extension exactly once.
    let mut expected: BTreeMap<&str, u64> = BTreeMap::new();
    for (ext, _) in &files {
        *expected.entry(ext).or_default() += 1;
    }
    for (ext, want) in &expected {
        assert_eq!(stats.per_type.get(*ext), Some(want), "count for {ext}");
    }

    // Recovered bytes match the originals.
    let mut recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    recovered.sort();
    let mut originals: Vec<Vec<u8>> = files.iter().map(|(_, b)| b.clone()).collect();
    originals.sort();
    assert_eq!(recovered, originals, "carved bytes match originals");

    // Every manifest digest matches the SHA-256 of an original file.
    let mut digests: std::collections::HashSet<String> = files
        .iter()
        .map(|(_, b)| filerecovery::hash::to_hex(&filerecovery::hash::digest(b)))
        .collect();
    for f in &stats.files {
        let hex = filerecovery::hash::to_hex(&f.sha256);
        assert!(
            digests.remove(&hex),
            "manifest digest {hex} not an original"
        );
    }
    assert!(digests.is_empty(), "every original is in the manifest");
}

#[test]
fn undeletes_two_filesystems_on_one_gpt_disk() {
    // A GPT disk carrying an ext volume and a FAT32 volume, each with a deleted
    // file, recovered together in one detect+recover pass.
    let ext_payload = b"deleted from the ext volume".to_vec();
    let ext_vol = common::ext_volume("notes.txt", &ext_payload);

    let fat_payload: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
    let fat_vol = common::fat32_volume(b"CLIP    ", b"AVI", &fat_payload);

    // Place both volumes on a 512-byte-sector GPT disk.
    let sector = 512usize;
    let ext_lba = 64usize;
    let fat_lba = ext_lba + ext_vol.len().div_ceil(sector) + 64;
    let mut disk = common::gpt_disk(&ext_vol, sector, ext_lba);
    // Extend the disk and drop the FAT volume in, then register a 2nd GPT entry.
    let fat_off = fat_lba * sector;
    if disk.len() < fat_off + fat_vol.len() {
        disk.resize(fat_off + fat_vol.len(), 0);
    }
    disk[fat_off..fat_off + fat_vol.len()].copy_from_slice(&fat_vol);
    let e = 2 * sector + 128; // second partition entry
    disk[e..e + 16].copy_from_slice(&[0x22; 16]); // non-zero type GUID
    disk[e + 32..e + 40].copy_from_slice(&(fat_lba as u64).to_le_bytes());

    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out = tmp.path().join("out");
    std::fs::write(&img, &disk).unwrap();

    let source = Source::open(&img).unwrap();
    let volumes = recover::detect(&source).unwrap();
    assert_eq!(volumes.len(), 2, "GPT exposes both volumes");

    let mut total = 0u64;
    for (i, vol) in volumes.iter().enumerate() {
        let stats = vol
            .recover_deleted(
                &source,
                &out.join(format!("v{i}")),
                &RecoverOptions::default(),
            )
            .unwrap();
        total += stats.recovered;
    }
    assert_eq!(total, 2, "one deleted file recovered from each filesystem");

    // Both files come back with their original contents.
    let found: Vec<Vec<u8>> = walkdir(&out);
    assert!(found.contains(&ext_payload), "ext file recovered");
    assert!(found.contains(&fat_payload), "fat file recovered");
}

/// Read the contents of every file under `dir`, recursively.
fn walkdir(dir: &std::path::Path) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walkdir(&p));
            } else if let Ok(data) = std::fs::read(&p) {
                out.push(data);
            }
        }
    }
    out
}
