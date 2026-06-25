//! Carving tests for IFF "FORM" audio (AIFF / AIFF-C) and Apple ICNS icons.
//! Each is embedded with a header-derived length into a synthetic image and
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

/// "FORM" + big-endian size + form type + payload (EA-IFF-85 container).
fn make_form(form: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut v = b"FORM".to_vec();
    let chunk = (4 + data.len()) as u32; // form type + payload
    v.extend_from_slice(&chunk.to_be_bytes());
    v.extend_from_slice(form);
    v.extend_from_slice(data);
    v
}

/// "icns" + big-endian total length + payload.
fn make_icns(payload: &[u8]) -> Vec<u8> {
    let mut v = b"icns".to_vec();
    let total = (8 + payload.len()) as u32;
    v.extend_from_slice(&total.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

#[test]
fn recovers_iff_form_and_icns() {
    let aiff = make_form(b"AIFF", &filler(1, 2000));
    let aifc = make_form(b"AIFC", &filler(2, 1700));
    let icns = make_icns(&filler(3, 1200));

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 800)).unwrap();
    img.write_all(&aiff).unwrap();
    img.write_all(&filler(11, 300)).unwrap();
    img.write_all(&aifc).unwrap();
    img.write_all(&filler(12, 300)).unwrap();
    img.write_all(&icns).unwrap();
    img.write_all(&filler(13, 800)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&[]).unwrap();
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
    assert_eq!(stats.files_recovered, 3, "aiff, aifc, icns");

    let mut recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    recovered.sort();

    let mut originals = vec![aiff, aifc, icns];
    originals.sort();

    assert_eq!(recovered, originals, "recovered bytes must match originals");

    for ext in ["aiff", "aifc", "icns"] {
        assert_eq!(stats.per_type.get(ext), Some(&1), "missing {ext}");
    }
}
