//! Carving test for SquashFS images (`hsqs`). A synthetic version-4 superblock
//! with a `bytes_used` size is embedded in an image and recovered byte-for-byte;
//! a superblock with an inconsistent block size / version is rejected.

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

/// A minimal SquashFS v4 image of `total` bytes: a superblock recording the
/// block size / `block_log` and `bytes_used = total`, padded with filler.
fn squashfs_image(block_log: u16, s_major: u16, total: usize) -> Vec<u8> {
    let len = total.max(96);
    let mut v = vec![0u8; len];
    v[0..4].copy_from_slice(b"hsqs"); // s_magic
    v[12..16].copy_from_slice(&(1u32 << block_log).to_le_bytes()); // block_size
    v[22..24].copy_from_slice(&block_log.to_le_bytes()); // block_log
    v[28..30].copy_from_slice(&s_major.to_le_bytes()); // s_major
    v[40..48].copy_from_slice(&(len as u64).to_le_bytes()); // bytes_used
                                                            // Fill the body after the superblock with recognisable filler.
    let body = filler(99, v.len() - 96);
    v[96..].copy_from_slice(&body);
    v
}

fn opts(out_dir: std::path::PathBuf) -> CarveOptions {
    CarveOptions {
        output_dir: out_dir,
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
    }
}

#[test]
fn recovers_a_squashfs_image() {
    let image = squashfs_image(17, 4, 5000); // 128 KiB blocks, v4, 5000 bytes

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 800)).unwrap();
    img.write_all(&image).unwrap();
    img.write_all(&filler(11, 400)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["squashfs".to_string()]).unwrap();
    let stats = carver::carve(&source, &sigs, &opts(out_dir.clone()), &NoProgress).unwrap();

    assert_eq!(stats.files_recovered, 1, "one squashfs image");
    assert_eq!(stats.per_type.get("squashfs"), Some(&1));
    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], image, "carved bytes match bytes_used exactly");
}

#[test]
fn rejects_inconsistent_superblock() {
    // hsqs magic but block_size doesn't match block_log: not a real superblock.
    let mut image = squashfs_image(17, 4, 5000);
    image[12..16].copy_from_slice(&4096u32.to_le_bytes()); // block_size != 1<<17

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");
    std::fs::write(&img_path, &image).unwrap();

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["squashfs".to_string()]).unwrap();
    let stats = carver::carve(&source, &sigs, &opts(out_dir), &NoProgress).unwrap();
    assert_eq!(stats.files_recovered, 0, "inconsistent superblock rejected");
}
