//! Carving test for Compound File Binary Format (OLE2) containers — legacy
//! `.doc`/`.xls`/`.ppt`. A minimal but valid CFBF is built byte-exactly
//! (512-byte header + a one-sector FAT + a one-sector directory), embedded in a
//! synthetic image, and recovered byte-for-byte. Its directory names a
//! `WordDocument` stream, so it is refined from the generic `ole` to `doc`.

use std::io::Write;

use filerecovery::carver::{self, CarveOptions, NoProgress};
use filerecovery::signatures;
use filerecovery::source::Source;

const FREE: u32 = 0xFFFF_FFFF;
const EOC: u32 = 0xFFFF_FFFE;
const FATSECT: u32 = 0xFFFF_FFFD;

fn filler(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn put_u16(v: &mut [u8], off: usize, x: u16) {
    v[off..off + 2].copy_from_slice(&x.to_le_bytes());
}
fn put_u32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}
fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// A 1536-byte v3 CFBF: header + one FAT sector + one directory sector. The FAT
/// marks sector 0 (itself) and sector 1 (the directory) as used, so the file is
/// `(1 + 2) * 512 = 1536` bytes. `stream_name`, if given, is written as a
/// directory entry so `classify_cfbf` can refine the type.
fn make_cfbf(stream_name: Option<&str>) -> Vec<u8> {
    let sector = 512usize;
    let mut v = vec![0u8; 512 + sector * 2];

    // --- Header ---
    v[0..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    put_u16(&mut v, 24, 0x003E); // minor version
    put_u16(&mut v, 26, 0x0003); // major version (v3 -> 512-byte sectors)
    v[28] = 0xFE;
    v[29] = 0xFF; // little-endian byte-order mark
    put_u16(&mut v, 30, 9); // sector shift -> 512
    put_u16(&mut v, 32, 6); // mini sector shift
    put_u32(&mut v, 44, 1); // number of FAT sectors
    put_u32(&mut v, 48, 1); // first directory sector
    put_u32(&mut v, 56, 4096); // mini-stream cutoff
    put_u32(&mut v, 60, EOC); // first mini-FAT sector
    put_u32(&mut v, 64, 0); // number of mini-FAT sectors
    put_u32(&mut v, 68, EOC); // first DIFAT sector
    put_u32(&mut v, 72, 0); // number of DIFAT sectors
    put_u32(&mut v, 76, 0); // DIFAT[0] -> FAT in sector 0
    for i in 1..109 {
        put_u32(&mut v, 76 + i * 4, FREE);
    }

    // --- Sector 0: the FAT (128 entries) ---
    let fat = 512;
    put_u32(&mut v, fat, FATSECT); // sector 0 is the FAT itself
    put_u32(&mut v, fat + 4, EOC); // sector 1 (directory) is a one-sector chain
    for i in 2..128 {
        put_u32(&mut v, fat + i * 4, FREE);
    }

    // --- Sector 1: the directory (128-byte entries) ---
    let dir = 1024;
    let root = utf16le("Root Entry");
    v[dir..dir + root.len()].copy_from_slice(&root);
    put_u16(&mut v, dir + 64, (root.len() + 2) as u16);
    v[dir + 66] = 5; // root storage
    if let Some(name) = stream_name {
        let e1 = dir + 128;
        let n = utf16le(name);
        v[e1..e1 + n.len()].copy_from_slice(&n);
        put_u16(&mut v, e1 + 64, (n.len() + 2) as u16);
        v[e1 + 66] = 2; // stream
    }
    v
}

fn carve_one(data: &[u8]) -> (carver::CarveStats, Vec<Vec<u8>>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 700)).unwrap();
    img.write_all(data).unwrap();
    img.write_all(&filler(11, 700)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["ole".to_string()]).unwrap();
    let opts = CarveOptions {
        output_dir: out_dir.clone(),
        start: 0,
        end: None,
        min_size: 0,
        max_size: None,
        max_files: None,
        allow_nested: false,
        validate: true,
        dedup: false,
        progress: false,
        checkpoint: None,
        resume: false,
        organize: false,
        dry_run: false,
    };
    let stats = carver::carve(&source, &sigs, &opts, &NoProgress).unwrap();
    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    (stats, recovered, tmp)
}

#[test]
fn recovers_a_compound_file_sized_from_the_fat() {
    let cfbf = make_cfbf(Some("WordDocument"));
    assert_eq!(cfbf.len(), 1536, "test fixture is 3 sectors");

    let (stats, recovered, _tmp) = carve_one(&cfbf);
    assert_eq!(stats.files_recovered, 1, "one compound file");
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0], cfbf,
        "recovered bytes must match the original, sized from the FAT"
    );
    // The WordDocument stream refines the generic `ole` to `doc`.
    assert_eq!(stats.per_type.get("doc"), Some(&1));
}

#[test]
fn an_unclassified_compound_file_stays_ole() {
    // No marker stream -> classification can't refine it, so it stays `.ole`.
    let cfbf = make_cfbf(None);
    let (stats, recovered, _tmp) = carve_one(&cfbf);
    assert_eq!(stats.files_recovered, 1);
    assert_eq!(recovered[0], cfbf);
    assert_eq!(stats.per_type.get("ole"), Some(&1));
}
