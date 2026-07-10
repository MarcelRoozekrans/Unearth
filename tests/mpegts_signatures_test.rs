//! Carving test for MPEG transport streams. A run of fixed 188-byte packets
//! (each beginning with the `0x47` sync byte) is built, embedded in a synthetic
//! image, and recovered byte-for-byte.

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

/// One 188-byte TS packet: the `0x47` sync byte then arbitrary payload.
fn packet(seed: u64) -> Vec<u8> {
    let mut v = vec![0x47u8];
    v.extend_from_slice(&filler(seed, 187));
    v
}

fn make_ts(packets: u64) -> Vec<u8> {
    let mut v = Vec::new();
    for i in 0..packets {
        v.extend_from_slice(&packet(i + 1));
    }
    v
}

#[test]
fn recovers_an_mpegts_stream() {
    let ts = make_ts(12);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 700)).unwrap();
    img.write_all(&ts).unwrap();
    // The byte at the packet boundary after the stream must not be 0x47, so the
    // walk ends exactly at the last whole packet.
    img.write_all(&[0x00]).unwrap();
    img.write_all(&filler(11, 700)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["ts".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "one transport stream");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], ts, "recovered bytes must match the original");
    assert_eq!(stats.per_type.get("ts"), Some(&1));
}
