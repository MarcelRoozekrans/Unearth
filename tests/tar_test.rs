//! Carving test for POSIX/GNU `tar` archives. A byte-exact ustar archive (two
//! members plus the two-zero-block terminator) is embedded in a synthetic image
//! and recovered by walking the 512-byte member chain; a header with a bad
//! checksum is rejected.

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

/// A 512-byte ustar header for `name`/`size` with a correct checksum.
fn tar_header(name: &str, size: usize) -> [u8; 512] {
    let mut h = [0u8; 512];
    let nb = name.as_bytes();
    h[..nb.len()].copy_from_slice(nb);
    h[100..108].copy_from_slice(b"0000644\0"); // mode
    h[108..116].copy_from_slice(b"0000000\0"); // uid
    h[116..124].copy_from_slice(b"0000000\0"); // gid
    h[124..136].copy_from_slice(format!("{size:011o} ").as_bytes()); // size (octal)
    h[136..148].copy_from_slice(b"00000000000 "); // mtime
    h[156] = b'0'; // typeflag: regular file
    h[257..263].copy_from_slice(b"ustar\0"); // magic
    h[263..265].copy_from_slice(b"00"); // version
                                        // Checksum: sum of all bytes with the field taken as spaces.
    for b in &mut h[148..156] {
        *b = b' ';
    }
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

/// Build a tar archive from `(name, data)` members, ending with two zero blocks.
fn tar_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut v = Vec::new();
    for (name, data) in members {
        v.extend_from_slice(&tar_header(name, data.len()));
        v.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        v.extend(std::iter::repeat(0u8).take(pad));
    }
    v.extend(std::iter::repeat(0u8).take(1024)); // end-of-archive marker
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
fn recovers_a_tar_archive() {
    let archive = tar_archive(&[
        ("hello.txt", &filler(1, 1000)), // spans two data blocks
        ("notes/readme", &filler(2, 100)),
    ]);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 700)).unwrap();
    img.write_all(&archive).unwrap();
    img.write_all(&filler(11, 500)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["tar".to_string()]).unwrap();
    let stats = carver::carve(&source, &sigs, &opts(out_dir.clone()), &NoProgress).unwrap();

    assert_eq!(stats.files_recovered, 1, "one tar archive");
    assert_eq!(stats.per_type.get("tar"), Some(&1));
    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0], archive,
        "carved bytes match the archive exactly"
    );
}

#[test]
fn rejects_a_bad_checksum_header() {
    // A block with the ustar magic at offset 257 but a corrupt checksum is not a
    // real tar header and must not be carved.
    let mut block = filler(7, 512);
    block[257..263].copy_from_slice(b"ustar\0");
    block[148..156].copy_from_slice(b"999999\0 "); // wrong checksum

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");
    std::fs::write(&img_path, &block).unwrap();

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["tar".to_string()]).unwrap();
    let stats = carver::carve(&source, &sigs, &opts(out_dir), &NoProgress).unwrap();
    assert_eq!(stats.files_recovered, 0, "bad-checksum header rejected");
}
