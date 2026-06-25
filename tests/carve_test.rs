//! Integration test: build a synthetic disk image with embedded files and
//! verify the carver recovers them byte-for-byte.

use std::io::Write;
use std::path::PathBuf;

use filerecovery::carver::{self, CarveOptions, NoProgress};
use filerecovery::signatures;
use filerecovery::source::Source;

/// Deterministic pseudo-random filler so the image looks like real noisy media.
fn filler(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn make_jpeg(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
    v.extend_from_slice(payload);
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

fn make_png(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    // IHDR chunk: length(13) + "IHDR" + 13-byte header + CRC (validators only
    // check the length, type, and dimensions, so a dummy CRC is fine here).
    v.extend_from_slice(&13u32.to_be_bytes());
    v.extend_from_slice(b"IHDR");
    v.extend_from_slice(&64u32.to_be_bytes()); // width
    v.extend_from_slice(&64u32.to_be_bytes()); // height
    v.extend_from_slice(&[8, 6, 0, 0, 0]); // bit depth, colour type, etc.
    v.extend_from_slice(&[0, 0, 0, 0]); // CRC placeholder
    v.extend_from_slice(payload);
    v.extend_from_slice(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]);
    v
}

fn make_bmp(payload: &[u8]) -> Vec<u8> {
    // 14-byte BITMAPFILEHEADER + 40-byte BITMAPINFOHEADER + payload. The total
    // size is a LE u32 at offset 2 (the carver's extent strategy).
    let dib = 40u32;
    let pixel_off = 14 + dib;
    let total = pixel_off + payload.len() as u32;
    let mut v = vec![b'B', b'M'];
    v.extend_from_slice(&total.to_le_bytes()); // file size (offset 2)
    v.extend_from_slice(&0u32.to_le_bytes()); // reserved
    v.extend_from_slice(&pixel_off.to_le_bytes()); // pixel-array offset
    v.extend_from_slice(&dib.to_le_bytes()); // DIB header size (offset 14)
    v.extend_from_slice(&64i32.to_le_bytes()); // width
    v.extend_from_slice(&64i32.to_le_bytes()); // height
    v.extend_from_slice(&1u16.to_le_bytes()); // planes
    v.extend_from_slice(&24u16.to_le_bytes()); // bits per pixel
    v.extend_from_slice(&[0u8; 24]); // rest of BITMAPINFOHEADER
    v.extend_from_slice(payload);
    v
}

#[test]
fn recovers_embedded_files() {
    let tmp = tempfile::tempdir().unwrap();
    let img_path: PathBuf = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let jpeg = make_jpeg(&filler(1, 5000));
    let png = make_png(&filler(2, 8000));
    let bmp = make_bmp(&filler(3, 3000));

    // Lay the files out between regions of random "free space".
    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 4096)).unwrap();
    img.write_all(&jpeg).unwrap();
    img.write_all(&filler(11, 1234)).unwrap();
    img.write_all(&png).unwrap();
    img.write_all(&filler(12, 777)).unwrap();
    img.write_all(&bmp).unwrap();
    img.write_all(&filler(13, 4096)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&[]).unwrap(); // all types
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
    assert_eq!(stats.files_recovered, 3, "should recover jpeg, png, bmp");

    // Collect recovered files and match them against originals by content.
    let mut recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    recovered.sort();

    let mut originals = vec![jpeg, png, bmp];
    originals.sort();

    assert_eq!(recovered, originals, "recovered bytes must match originals");
}

#[test]
fn type_filter_limits_recovery() {
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let jpeg = make_jpeg(&filler(1, 1000));
    let png = make_png(&filler(2, 1000));

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 512)).unwrap();
    img.write_all(&jpeg).unwrap();
    img.write_all(&filler(11, 512)).unwrap();
    img.write_all(&png).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["png".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1);
    assert_eq!(stats.per_type.get("png"), Some(&1));
}

#[test]
fn unknown_type_is_rejected() {
    let err = signatures::select(&["xyz".to_string()]).unwrap_err();
    assert!(err.to_string().contains("unknown file type"));
}

#[test]
fn footer_search_terminates_without_a_footer() {
    // Regression: a footer-type magic (JPEG) followed by data with no `FF D9`
    // footer used to spin `find_footer` forever once the search reached the end
    // of the buffer (the tail read advanced position by zero). It must instead
    // terminate and recover nothing.
    let tmp = tempfile::tempdir().unwrap();
    let img: PathBuf = tmp.path().join("disk.img");
    let out = tmp.path().join("out");

    let mut data = vec![0xFF, 0xD8, 0xFF, 0xE0]; // JPEG SOI, no EOI anywhere
    data.extend(std::iter::repeat(0x00).take(5000));
    std::fs::write(&img, &data).unwrap();

    let source = Source::open(&img).unwrap();
    let sigs = signatures::select(&["jpg".to_string()]).unwrap();
    let opts = CarveOptions {
        output_dir: out,
        start: 0,
        end: None,
        min_size: 0,
        max_files: None,
        allow_nested: false,
        validate: false,
        dedup: false,
        progress: false,
        checkpoint: None,
        resume: false,
        organize: false,
        dry_run: false,
    };
    let stats = carver::carve(&source, &sigs, &opts, &NoProgress).unwrap();
    assert_eq!(stats.files_recovered, 0, "no footer => nothing recovered");
}
