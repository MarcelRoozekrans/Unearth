//! Carving test for MP3s anchored on a frame sync (no ID3v2 tag). A stream of
//! byte-exact CBR MPEG-1 Layer III frames (with only an ID3v1 `TAG` trailer) is
//! built, embedded in a synthetic image, and recovered byte-for-byte.

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

/// One MPEG-1 Layer III frame, 128 kbps @ 44100 Hz, no padding (header
/// `FF FB 90 00`). Length = 144 * 128000 / 44100 = 417 bytes.
fn frame(seed: u64) -> Vec<u8> {
    const LEN: usize = 144 * 128000 / 44100; // 417
    let mut v = vec![0xFF, 0xFB, 0x90, 0x00];
    v.extend_from_slice(&filler(seed, LEN - 4));
    v
}

/// A tagless MP3: `frames` audio frames followed by a 128-byte ID3v1 `TAG`.
fn make_mp3(frames: u64) -> Vec<u8> {
    let mut v = Vec::new();
    for i in 0..frames {
        v.extend_from_slice(&frame(i + 1));
    }
    let mut tag = vec![0u8; 128];
    tag[0..3].copy_from_slice(b"TAG");
    v.extend_from_slice(&tag);
    v
}

#[test]
fn recovers_a_tagless_mp3() {
    // 10 frames -> comfortably above the raw-anchor minimum of 8.
    let mp3 = make_mp3(10);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 700)).unwrap();
    img.write_all(&mp3).unwrap();
    img.write_all(&filler(11, 700)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["mp3".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "one tagless mp3");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], mp3, "recovered bytes must match the original");
    assert_eq!(stats.per_type.get("mp3"), Some(&1));
}
