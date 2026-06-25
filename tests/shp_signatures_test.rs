//! Carving test for ESRI Shapefiles (`.shp`). A shapefile is built byte-exactly
//! (a 100-byte header recording the file code, total length in 16-bit words, and
//! version, plus record data), embedded in a synthetic image, and recovered
//! byte-for-byte.

use std::io::Write;

use filerecovery::carver::{self, CarveOptions, NoProgress};
use filerecovery::signatures;
use filerecovery::source::Source;

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

/// A shapefile of `total` bytes (must be even and >= 100): a 100-byte header
/// (file code 9994 big-endian, total length in 16-bit words at offset 24,
/// version 1000 little-endian at offset 28) followed by record data.
fn make_shp(total: usize) -> Vec<u8> {
    assert!(total >= 100 && total % 2 == 0);
    let mut v = filler(3, total);
    v[0..4].copy_from_slice(&9994u32.to_be_bytes()); // file code
    v[4..24].copy_from_slice(&[0u8; 20]); // five unused ints
    v[24..28].copy_from_slice(&((total / 2) as u32).to_be_bytes()); // length in words
    v[28..32].copy_from_slice(&1000u32.to_le_bytes()); // version
    v[32..36].copy_from_slice(&5u32.to_le_bytes()); // shape type (polygon)
    v
}

#[test]
fn recovers_a_shapefile() {
    let shp = make_shp(128);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 700)).unwrap();
    img.write_all(&shp).unwrap();
    img.write_all(&filler(11, 700)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["shp".to_string()]).unwrap();
    let opts = CarveOptions {
        output_dir: out_dir.clone(),
        start: 0,
        end: None,
        min_size: 0,
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
    assert_eq!(stats.files_recovered, 1, "one shapefile");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], shp, "recovered bytes must match the original");
    assert_eq!(stats.per_type.get("shp"), Some(&1));
}
