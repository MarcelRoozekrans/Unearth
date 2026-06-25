//! Carving test for ADTS AAC audio. A stream of byte-exact ADTS frames (each a
//! 7-byte header carrying its own 13-bit frame length plus payload) is built,
//! embedded in a synthetic image, and recovered byte-for-byte.

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

/// One ADTS frame of total length `len` (header + payload). MPEG-4, AAC-LC, no
/// CRC, 44100 Hz (sample-rate index 4), stereo.
fn frame(len: u64, seed: u64) -> Vec<u8> {
    assert!((7..(1 << 13)).contains(&len));
    let mut h = [0u8; 7];
    h[0] = 0xFF; // sync
    h[1] = 0xF1; // sync low, MPEG-4, layer 00, no CRC
                 // profile = AAC-LC (1), sr_idx = 4, channel cfg = 2 (stereo)
    h[2] = (1 << 6) | (4 << 2); // 0x50
    h[3] = (2 << 6) | (((len >> 11) & 0x03) as u8); // chan low + frame len hi
    h[4] = ((len >> 3) & 0xFF) as u8; // frame len mid
    h[5] = (((len & 0x07) << 5) as u8) | 0x1F; // frame len lo + buffer fullness hi
    h[6] = 0xFC; // buffer fullness lo + (frames-1 = 0)
    let mut v = h.to_vec();
    v.extend_from_slice(&filler(seed, (len - 7) as usize));
    v
}

fn make_aac(frames: u64, frame_len: u64) -> Vec<u8> {
    let mut v = Vec::new();
    for i in 0..frames {
        v.extend_from_slice(&frame(frame_len, i + 1));
    }
    v
}

#[test]
fn recovers_an_aac_stream() {
    let aac = make_aac(5, 200);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 700)).unwrap();
    img.write_all(&aac).unwrap();
    img.write_all(&filler(11, 700)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["aac".to_string()]).unwrap();
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
    };
    let stats = carver::carve(&source, &sigs, &opts, &NoProgress).unwrap();
    assert_eq!(stats.files_recovered, 1, "one aac stream");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], aac, "recovered bytes must match the original");
    assert_eq!(stats.per_type.get("aac"), Some(&1));
}
