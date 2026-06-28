//! Carving test for the ISO-BMFF brand variants that get their own extension:
//! QuickTime (`qt  ` → .mov), M4A (`M4A ` → .m4a), and M4V (`M4V ` → .m4v).

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

/// An ISO base-media file: an `ftyp` box with the given 4-byte major brand,
/// then an `mdat` box holding `payload`.
fn make_bmff(brand: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&16u32.to_be_bytes()); // ftyp box size
    v.extend_from_slice(b"ftyp");
    v.extend_from_slice(brand); // major brand at offset 8
    v.extend_from_slice(&0u32.to_be_bytes()); // minor version
    let mdat = (8 + payload.len()) as u32;
    v.extend_from_slice(&mdat.to_be_bytes());
    v.extend_from_slice(b"mdat");
    v.extend_from_slice(payload);
    v
}

#[test]
fn brands_get_their_own_extensions() {
    let mov = make_bmff(b"qt  ", &filler(1, 2000));
    let m4a = make_bmff(b"M4A ", &filler(2, 1500));
    let m4v = make_bmff(b"M4V ", &filler(3, 1800));

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 600)).unwrap();
    img.write_all(&mov).unwrap();
    img.write_all(&filler(11, 600)).unwrap();
    img.write_all(&m4a).unwrap();
    img.write_all(&filler(12, 600)).unwrap();
    img.write_all(&m4v).unwrap();
    img.write_all(&filler(13, 600)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs =
        signatures::select(&["mov".to_string(), "m4a".to_string(), "m4v".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 3, "one of each brand");
    assert_eq!(stats.per_type.get("mov"), Some(&1));
    assert_eq!(stats.per_type.get("m4a"), Some(&1));
    assert_eq!(stats.per_type.get("m4v"), Some(&1));
}
