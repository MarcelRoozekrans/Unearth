//! Carving test for Android Dalvik executables (DEX). A `.dex` file is built
//! byte-exactly (a 0x70-byte header recording the total file size, header size,
//! and endian tag, plus a body), embedded in a synthetic image, and recovered
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

/// A DEX file: an 0x70-byte header (magic `dex\n035\0`, checksum, signature,
/// file size, header size 0x70, endian tag 0x12345678) followed by `body`
/// bytes.
fn make_dex(body: usize) -> Vec<u8> {
    let total = 0x70 + body;
    let mut v = vec![0u8; 0x70];
    v[0..8].copy_from_slice(b"dex\n035\0"); // magic + version
    v[0x08..0x0C].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // checksum
    v[0x0C..0x20].copy_from_slice(&filler(7, 20)); // SHA-1 signature
    v[0x20..0x24].copy_from_slice(&(total as u32).to_le_bytes()); // file size
    v[0x24..0x28].copy_from_slice(&0x70u32.to_le_bytes()); // header size
    v[0x28..0x2C].copy_from_slice(&0x1234_5678u32.to_le_bytes()); // endian tag
    v.extend_from_slice(&filler(1, body));
    assert_eq!(v.len(), total);
    v
}

#[test]
fn recovers_a_dex_file() {
    let dex = make_dex(128);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 700)).unwrap();
    img.write_all(&dex).unwrap();
    img.write_all(&filler(11, 700)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["dex".to_string()]).unwrap();
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
    };
    let stats = carver::carve(&source, &sigs, &opts, &NoProgress).unwrap();
    assert_eq!(stats.files_recovered, 1, "one dex file");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], dex, "recovered bytes must match the original");
    assert_eq!(stats.per_type.get("dex"), Some(&1));
}
