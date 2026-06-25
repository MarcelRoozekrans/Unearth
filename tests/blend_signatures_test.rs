//! Carving test for Blender files (`.blend`). A file is built byte-exactly (a
//! 12-byte header + a data block + a terminating `ENDB` block), embedded in a
//! synthetic image, and recovered byte-for-byte.

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

/// One 64-bit little-endian file block: code (4) + size (4) + old pointer (8) +
/// SDNA index (4) + count (4), followed by `data`.
fn block(code: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(code);
    v.extend_from_slice(&(data.len() as u32).to_le_bytes()); // data size
    v.extend_from_slice(&[0u8; 8]); // old memory pointer
    v.extend_from_slice(&0u32.to_le_bytes()); // SDNA index
    v.extend_from_slice(&1u32.to_le_bytes()); // count
    v.extend_from_slice(data);
    v
}

/// A 64-bit little-endian `.blend` (version 3.03): header + one data block + the
/// terminating ENDB block.
fn make_blend() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"BLENDER-v303"); // magic + 64-bit ptr + little-endian
    v.extend_from_slice(&block(b"REND", &filler(5, 8)));
    v.extend_from_slice(&block(b"ENDB", &[]));
    v
}

#[test]
fn recovers_a_blend_file() {
    let blend = make_blend();

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 700)).unwrap();
    img.write_all(&blend).unwrap();
    img.write_all(&filler(11, 700)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["blend".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "one blend file");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0], blend,
        "recovered bytes must match the original"
    );
    assert_eq!(stats.per_type.get("blend"), Some(&1));
}
