//! Carving test for ICC colour profiles. A profile is built byte-exactly (a
//! 128-byte header opening with the total size and carrying the `acsp` file
//! signature at offset 36, plus a body), embedded in a synthetic image, and
//! recovered byte-for-byte.

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

/// An ICC profile of `size` bytes (must be >= 128 and a multiple of 4): a
/// 128-byte header whose first u32 (big-endian) is the total size and whose
/// offset-36 signature is `acsp`, followed by filler.
fn make_icc(size: usize) -> Vec<u8> {
    assert!(size >= 128 && size % 4 == 0);
    let mut v = filler(3, size);
    v[0..4].copy_from_slice(&(size as u32).to_be_bytes()); // profile size (BE)
    v[36..40].copy_from_slice(b"acsp"); // profile file signature
    v
}

#[test]
fn recovers_an_icc_profile() {
    let icc = make_icc(256);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 700)).unwrap();
    img.write_all(&icc).unwrap();
    img.write_all(&filler(11, 700)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["icc".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "one icc profile");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], icc, "recovered bytes must match the original");
    assert_eq!(stats.per_type.get("icc"), Some(&1));
}
