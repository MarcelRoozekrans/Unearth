//! Carving test for Windows Imaging Format (WIM). A WIM is built byte-exactly
//! (a 208-byte header with resource headers for the lookup table, XML data, and
//! integrity table, plus the resource bodies), embedded in a synthetic image,
//! and recovered byte-for-byte.

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

/// Write a resource header (8-byte size/flags + 8-byte offset) at `off`.
fn put_reshdr(v: &mut [u8], off: usize, size: u64, offset: u64) {
    v[off..off + 8].copy_from_slice(&size.to_le_bytes()); // flags byte = 0
    v[off + 8..off + 16].copy_from_slice(&offset.to_le_bytes());
}

/// A WIM whose last structure (integrity table) ends the file at offset 308.
fn make_wim() -> Vec<u8> {
    let total = 308usize;
    let mut v = vec![0u8; total];
    v[0..8].copy_from_slice(b"MSWIM\x00\x00\x00");
    v[8..12].copy_from_slice(&208u32.to_le_bytes()); // cbSize
    put_reshdr(&mut v, 0x30, 50, 208); // offset/lookup table -> ends at 258
    put_reshdr(&mut v, 0x48, 30, 258); // XML data            -> ends at 288
                                       // boot metadata (0x60) left absent (zero)
    put_reshdr(&mut v, 0x7C, 20, 288); // integrity table     -> ends at 308
    let body = filler(1, total - 208);
    v[208..].copy_from_slice(&body);
    v
}

#[test]
fn recovers_a_wim_image() {
    let wim = make_wim();

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 700)).unwrap();
    img.write_all(&wim).unwrap();
    img.write_all(&filler(11, 700)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["wim".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "one wim image");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], wim, "recovered bytes must match the original");
    assert_eq!(stats.per_type.get("wim"), Some(&1));
}
