//! Carving test for LZ4 frames. Frames are built byte-exactly per the LZ4 frame
//! format (descriptor + data blocks + end mark + optional checksums), embedded
//! in a synthetic image, and recovered byte-for-byte by walking the block chain.

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

/// An LZ4 frame with the given FLG byte (we use no content size / no dict id),
/// two uncompressed data blocks, the end mark, and a content checksum iff FLG
/// bit 2 is set. Block checksums are included iff FLG bit 4 is set.
fn lz4_frame(flg: u8, b1: &[u8], b2: &[u8]) -> Vec<u8> {
    let block_checksum = (flg >> 4) & 1 == 1;
    let content_checksum = (flg >> 2) & 1 == 1;

    let mut v = vec![0x04, 0x22, 0x4D, 0x18]; // magic
    v.push(flg); // FLG
    v.push(0x70); // BD (block max size; value irrelevant to carving)
    v.push(0x00); // header checksum (not validated by the carver)

    for b in [b1, b2] {
        // Uncompressed block: high bit set in the 4-byte size.
        let size = (b.len() as u32) | 0x8000_0000;
        v.extend_from_slice(&size.to_le_bytes());
        v.extend_from_slice(b);
        if block_checksum {
            v.extend_from_slice(&[0, 0, 0, 0]);
        }
    }
    v.extend_from_slice(&0u32.to_le_bytes()); // EndMark
    if content_checksum {
        v.extend_from_slice(&[0, 0, 0, 0]);
    }
    v
}

#[test]
fn recovers_lz4_frames() {
    // Plain frame; one with block + content checksums (FLG bits 4 and 2).
    let plain = lz4_frame(0x40, &filler(1, 1500), &filler(2, 900));
    let summed = lz4_frame(0x54, &filler(3, 600), &filler(4, 400));

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 500)).unwrap();
    img.write_all(&plain).unwrap();
    img.write_all(&filler(11, 300)).unwrap();
    img.write_all(&summed).unwrap();
    img.write_all(&filler(12, 500)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["lz4".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 2, "two lz4 frames");

    let mut recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    recovered.sort();
    let mut originals = vec![plain, summed];
    originals.sort();
    assert_eq!(recovered, originals, "recovered bytes must match originals");
    assert_eq!(stats.per_type.get("lz4"), Some(&2));
}
