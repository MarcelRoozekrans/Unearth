//! Carving test for uncompressed Flash movies (`.swf`, `FWS`). A movie is built
//! byte-exactly (an 8-byte header recording the total length, plus a body),
//! embedded in a synthetic image, and recovered byte-for-byte.

use std::io::Write;

use unearth::carver::{self, CarveOptions, NoProgress};
use unearth::signatures;
use unearth::source::Source;

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

/// An uncompressed SWF of `total` bytes: `FWS`, version 6, total length (LE u32
/// at offset 4), then body.
fn make_swf(total: usize) -> Vec<u8> {
    let mut v = vec![b'F', b'W', b'S', 6];
    v.extend_from_slice(&(total as u32).to_le_bytes());
    v.extend_from_slice(&filler(1, total - 8));
    v
}

#[test]
fn recovers_an_uncompressed_swf() {
    let swf = make_swf(256);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 500)).unwrap();
    img.write_all(&swf).unwrap();
    img.write_all(&filler(11, 500)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["swf".to_string()]).unwrap();
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
        align: 1,
    };
    let stats = carver::carve(&source, &sigs, &opts, &NoProgress).unwrap();
    assert_eq!(stats.files_recovered, 1, "one swf movie");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], swf, "recovered bytes must match the original");
    assert_eq!(stats.per_type.get("swf"), Some(&1));
}
