//! Carving test for Microsoft Program Database (PDB) files. A minimal MSF 7.0
//! superblock declaring `block_size × num_blocks` is built, embedded in a
//! synthetic image, and recovered byte-for-byte.

use std::io::Write;

use unearth::carver::{self, CarveOptions, NoProgress};
use unearth::signatures;
use unearth::source::Source;

const MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";

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

/// A PDB of `block_size × num_blocks` bytes with a valid MSF 7.0 superblock.
fn pdb(block_size: u32, num_blocks: u32) -> Vec<u8> {
    let total = block_size as usize * num_blocks as usize;
    let mut v = vec![0u8; total];
    v[0..32].copy_from_slice(MAGIC);
    v[0x20..0x24].copy_from_slice(&block_size.to_le_bytes());
    v[0x28..0x2C].copy_from_slice(&num_blocks.to_le_bytes());
    // Some arbitrary content in the remaining blocks.
    let body = filler(7, total - 0x2C);
    v[0x2C..].copy_from_slice(&body);
    v
}

#[test]
fn recovers_a_pdb() {
    let p = pdb(512, 6); // 3072 bytes

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 700)).unwrap();
    img.write_all(&p).unwrap();
    img.write_all(&filler(11, 700)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["pdb".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "one PDB");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], p, "recovered bytes must match the original");
    assert_eq!(stats.per_type.get("pdb"), Some(&1));
}
