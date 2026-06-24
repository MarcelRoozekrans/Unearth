//! Carving test for Windows registry hives (`regf`). A hive is built
//! byte-exactly (a 4096-byte base block recording the hive-bins data size,
//! followed by that many bytes of hive-bins data), embedded in a synthetic
//! image, and recovered byte-for-byte.

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

/// A registry hive: a 4096-byte base block (magic, version 1.x, primary file
/// type, root cell offset, hive-bins data size) followed by `bins` 4096-byte
/// hive bins.
fn make_regf(bins: u32) -> Vec<u8> {
    let hbins_size = bins * 4096;
    let mut v = vec![0u8; 4096];
    v[0..4].copy_from_slice(b"regf");
    v[4..8].copy_from_slice(&1u32.to_le_bytes()); // primary sequence number
    v[8..12].copy_from_slice(&1u32.to_le_bytes()); // secondary sequence number
    v[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // major version
    v[0x18..0x1C].copy_from_slice(&5u32.to_le_bytes()); // minor version
    v[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes()); // file type = primary
    v[0x20..0x24].copy_from_slice(&1u32.to_le_bytes()); // file format = direct
    v[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes()); // root cell offset
    v[0x28..0x2C].copy_from_slice(&hbins_size.to_le_bytes()); // hive-bins data size
    v[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes()); // clustering factor
    for b in 0..bins {
        v.extend_from_slice(&filler(b as u64 + 1, 4096));
    }
    v
}

#[test]
fn recovers_a_registry_hive() {
    let regf = make_regf(2);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 700)).unwrap();
    img.write_all(&regf).unwrap();
    img.write_all(&filler(11, 700)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["regf".to_string()]).unwrap();
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
    };
    let stats = carver::carve(&source, &sigs, &opts, &NoProgress).unwrap();
    assert_eq!(stats.files_recovered, 1, "one registry hive");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0], regf,
        "recovered bytes must match the original"
    );
    assert_eq!(stats.per_type.get("regf"), Some(&1));
}
