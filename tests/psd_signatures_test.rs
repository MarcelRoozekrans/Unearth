//! Carving test for Photoshop documents (PSD). Files are built byte-exactly per
//! the PSD format (header + three length-prefixed sections + image data, both
//! raw and PackBits-RLE), embedded in a synthetic image, and recovered
//! byte-for-byte.

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

/// A 26-byte PSD header (version 1) for `channels` × `width` × `height` at
/// `depth` bits, RGB colour mode.
fn psd_header(channels: u16, height: u32, width: u32, depth: u16) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(b"8BPS");
    h.extend_from_slice(&1u16.to_be_bytes()); // version (PSD)
    h.extend_from_slice(&[0u8; 6]); // reserved
    h.extend_from_slice(&channels.to_be_bytes());
    h.extend_from_slice(&height.to_be_bytes());
    h.extend_from_slice(&width.to_be_bytes());
    h.extend_from_slice(&depth.to_be_bytes());
    h.extend_from_slice(&3u16.to_be_bytes()); // colour mode = RGB
    h
}

/// A raw (uncompressed) PSD: header + three empty sections + compression 0 +
/// width*height*channels*(depth/8) pixel bytes.
fn psd_raw() -> Vec<u8> {
    let (channels, height, width, depth) = (3u16, 4u32, 5u32, 8u16);
    let mut v = psd_header(channels, height, width, depth);
    v.extend_from_slice(&0u32.to_be_bytes()); // colour-mode data length
    v.extend_from_slice(&0u32.to_be_bytes()); // image-resources length
    v.extend_from_slice(&0u32.to_be_bytes()); // layer & mask info length
    v.extend_from_slice(&0u16.to_be_bytes()); // compression = raw
    let pixels = (width * height * channels as u32 * (depth as u32 / 8)) as usize;
    v.extend_from_slice(&filler(1, pixels));
    v
}

/// A PackBits-RLE PSD: header + empty sections + compression 1 + a per-scanline
/// u16 byte-count table + that many compressed bytes.
fn psd_rle() -> Vec<u8> {
    let (channels, height, width, depth) = (3u16, 4u32, 5u32, 8u16);
    let rows = (height * channels as u32) as usize;
    let per_row = 7u16; // arbitrary compressed byte count per scanline
    let mut v = psd_header(channels, height, width, depth);
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes()); // compression = RLE
    for _ in 0..rows {
        v.extend_from_slice(&per_row.to_be_bytes()); // scanline byte counts
    }
    v.extend_from_slice(&filler(2, rows * per_row as usize)); // compressed rows
    v
}

#[test]
fn recovers_psd_raw_and_rle() {
    let raw = psd_raw();
    let rle = psd_rle();

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 400)).unwrap();
    img.write_all(&raw).unwrap();
    img.write_all(&filler(11, 300)).unwrap();
    img.write_all(&rle).unwrap();
    img.write_all(&filler(12, 400)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["psd".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 2, "raw and RLE PSD");

    let mut recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    recovered.sort();
    let mut originals = vec![raw, rle];
    originals.sort();
    assert_eq!(recovered, originals, "recovered bytes must match originals");
    assert_eq!(stats.per_type.get("psd"), Some(&2));
}
