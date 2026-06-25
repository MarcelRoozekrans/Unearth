//! Carving test for Windows Metafiles (WMF), both the placeable (Aldus) variant
//! and the plain METAHEADER variant. Each is built byte-exactly with a known
//! `mtSize`, embedded in a synthetic image, and recovered byte-for-byte.

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

/// A standard METAHEADER (18 bytes) declaring `mt_size` total words.
fn metaheader(mt_type: u16, mt_size: u32) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&mt_type.to_le_bytes()); // mtType
    h.extend_from_slice(&9u16.to_le_bytes()); // mtHeaderSize (words)
    h.extend_from_slice(&0x0300u16.to_le_bytes()); // mtVersion
    h.extend_from_slice(&mt_size.to_le_bytes()); // mtSize (words)
    h.extend_from_slice(&0u16.to_le_bytes()); // mtNoObjects
    h.extend_from_slice(&3u32.to_le_bytes()); // mtMaxRecord
    h.extend_from_slice(&0u16.to_le_bytes()); // mtNoParameters
    debug_assert_eq!(h.len(), 18);
    h
}

/// The metafile body after the header: a single 3-word end-of-metafile record.
fn eof_record() -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&3u32.to_le_bytes()); // record size (words)
    r.extend_from_slice(&0u16.to_le_bytes()); // function = 0 (EOF)
    r
}

/// A plain WMF: METAHEADER (9 words) + EOF record (3 words) => mtSize = 12.
fn wmf_standard() -> Vec<u8> {
    let mut v = metaheader(1, 12);
    v.extend_from_slice(&eof_record());
    v
}

/// A placeable WMF: 22-byte APM header + the same 12-word metafile.
fn wmf_placeable() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0xD7, 0xCD, 0xC6, 0x9A]); // key
    v.extend_from_slice(&0u16.to_le_bytes()); // hWmf
    v.extend_from_slice(&[0u8; 8]); // bounding box
    v.extend_from_slice(&96u16.to_le_bytes()); // inch
    v.extend_from_slice(&0u32.to_le_bytes()); // reserved
    v.extend_from_slice(&0u16.to_le_bytes()); // checksum
    debug_assert_eq!(v.len(), 22);
    v.extend_from_slice(&metaheader(1, 12));
    v.extend_from_slice(&eof_record());
    v
}

#[test]
fn recovers_placeable_and_standard_wmf() {
    let placeable = wmf_placeable();
    let standard = wmf_standard();

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 500)).unwrap();
    img.write_all(&placeable).unwrap();
    img.write_all(&filler(11, 300)).unwrap();
    img.write_all(&standard).unwrap();
    img.write_all(&filler(12, 500)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["wmf".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 2, "placeable and standard WMF");

    let mut recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    recovered.sort();
    let mut originals = vec![placeable, standard];
    originals.sort();
    assert_eq!(recovered, originals, "recovered bytes must match originals");
    assert_eq!(stats.per_type.get("wmf"), Some(&2));
}
