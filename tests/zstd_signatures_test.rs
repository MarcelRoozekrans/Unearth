//! Carving test for Zstandard (.zst) frames. Frames are built byte-exactly per
//! RFC 8878 (header + data blocks + optional content checksum), embedded in a
//! synthetic image, and recovered byte-for-byte by walking the block chain.

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

/// One block header (3 bytes LE): bit 0 = last, bits 1-2 = type, bits 3-23 = size.
fn block_header(last: bool, btype: u32, size: u32) -> [u8; 3] {
    let raw = (last as u32) | (btype << 1) | (size << 3);
    [raw as u8, (raw >> 8) as u8, (raw >> 16) as u8]
}

/// A Zstandard frame with a Frame_Header_Descriptor of `fhd` (we use no
/// dictionary / no frame-content-size, window descriptor present), one
/// non-last raw block then a last raw block, and a content checksum iff the
/// descriptor sets bit 2.
fn zstd_frame(fhd: u8, raw1: &[u8], raw2: &[u8]) -> Vec<u8> {
    let mut v = vec![0x28, 0xB5, 0x2F, 0xFD]; // magic
    v.push(fhd); // Frame_Header_Descriptor
    v.push(0x00); // Window_Descriptor (single-segment flag is clear in fhd)

    v.extend_from_slice(&block_header(false, 0, raw1.len() as u32)); // raw, not last
    v.extend_from_slice(raw1);
    v.extend_from_slice(&block_header(true, 0, raw2.len() as u32)); // raw, last
    v.extend_from_slice(raw2);

    if fhd & 0x04 != 0 {
        v.extend_from_slice(&[0, 0, 0, 0]); // 4-byte content checksum
    }
    v
}

#[test]
fn recovers_zstandard_frames() {
    // One frame without a checksum, one with (fhd bit 2 set).
    let plain = zstd_frame(0x00, &filler(1, 1200), &filler(2, 800));
    let checksummed = zstd_frame(0x04, &filler(3, 500), &filler(4, 300));

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 600)).unwrap();
    img.write_all(&plain).unwrap();
    img.write_all(&filler(11, 300)).unwrap();
    img.write_all(&checksummed).unwrap();
    img.write_all(&filler(12, 600)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["zst".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 2, "two zstd frames");

    let mut recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    recovered.sort();
    let mut originals = vec![plain, checksummed];
    originals.sort();
    assert_eq!(recovered, originals, "recovered bytes must match originals");
    assert_eq!(stats.per_type.get("zst"), Some(&2));
}
