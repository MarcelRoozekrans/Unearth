//! Carving test for glTF binary (.glb) 3D models. A glB is built byte-exactly
//! (12-byte header + JSON and BIN chunks) with the total length recorded at
//! offset 8, embedded in a synthetic image, and recovered byte-for-byte.

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

/// A glB with a JSON chunk and a BIN chunk (both 4-byte-aligned), with the
/// total length filled into the header at offset 8.
fn make_glb(json: &[u8], bin: &[u8]) -> Vec<u8> {
    assert!(json.len() % 4 == 0 && bin.len() % 4 == 0);
    let mut v = Vec::new();
    v.extend_from_slice(b"glTF");
    v.extend_from_slice(&2u32.to_le_bytes()); // version
    v.extend_from_slice(&0u32.to_le_bytes()); // total length (filled below)

    v.extend_from_slice(&(json.len() as u32).to_le_bytes());
    v.extend_from_slice(b"JSON");
    v.extend_from_slice(json);

    v.extend_from_slice(&(bin.len() as u32).to_le_bytes());
    v.extend_from_slice(b"BIN\0");
    v.extend_from_slice(bin);

    let total = v.len() as u32;
    v[8..12].copy_from_slice(&total.to_le_bytes());
    v
}

#[test]
fn recovers_a_glb_model() {
    // JSON chunk padded with spaces to a 4-byte boundary (16 bytes).
    let glb = make_glb(br#"{"asset":{}}    "#, &filler(1, 2048));

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 600)).unwrap();
    img.write_all(&glb).unwrap();
    img.write_all(&filler(11, 600)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["glb".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "one glb model");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], glb, "recovered bytes must match the original");
    assert_eq!(stats.per_type.get("glb"), Some(&1));
}
