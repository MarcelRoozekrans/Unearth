//! Carving test for `cpio` archives in the "new ASCII" (newc) format used by
//! Linux initramfs images and RPM payloads. A byte-exact archive (one file plus
//! the `TRAILER!!!` entry) is embedded in a synthetic image and recovered by
//! walking the entry chain; a header with non-hex fields is rejected.

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

/// A newc cpio entry: 110-byte header (8-hex-digit fields), then the
/// NUL-terminated name and the data, each padded to a 4-byte boundary.
fn cpio_entry(name: &str, data: &[u8]) -> Vec<u8> {
    let namesize = name.len() + 1; // includes the trailing NUL
    let mut v = Vec::new();
    v.extend_from_slice(b"070701");
    // 13 fields; only filesize (index 6) and namesize (index 11) need real values.
    let fields = [
        1u64,              // ino
        0o100644,          // mode
        0,                 // uid
        0,                 // gid
        1,                 // nlink
        0,                 // mtime
        data.len() as u64, // filesize
        0,                 // devmajor
        0,                 // devminor
        0,                 // rdevmajor
        0,                 // rdevminor
        namesize as u64,   // namesize
        0,                 // check
    ];
    for f in fields {
        v.extend_from_slice(format!("{f:08X}").as_bytes());
    }
    assert_eq!(v.len(), 110);
    v.extend_from_slice(name.as_bytes());
    v.push(0);
    while v.len() % 4 != 0 {
        v.push(0); // pad name to a 4-byte boundary
    }
    v.extend_from_slice(data);
    while v.len() % 4 != 0 {
        v.push(0); // pad data to a 4-byte boundary
    }
    v
}

/// A full newc archive: the given entries followed by the TRAILER!!! entry.
fn cpio_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut v = Vec::new();
    for (name, data) in entries {
        v.extend_from_slice(&cpio_entry(name, data));
    }
    v.extend_from_slice(&cpio_entry("TRAILER!!!", &[]));
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
fn recovers_a_cpio_archive() {
    let archive = cpio_archive(&[
        ("etc/hostname", &filler(1, 30)),
        ("bin/init", &filler(2, 513)), // not a multiple of 4
    ]);
    // Sanity: the trailer's padded end is the archive end.
    assert_eq!(archive.len() % 4, 0);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 600)).unwrap();
    img.write_all(&archive).unwrap();
    img.write_all(&filler(11, 400)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["cpio".to_string()]).unwrap();
    let stats = carver::carve(&source, &sigs, &opts(out_dir.clone()), &NoProgress).unwrap();

    assert_eq!(stats.files_recovered, 1, "one cpio archive");
    assert_eq!(stats.per_type.get("cpio"), Some(&1));
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
fn rejects_non_hex_header() {
    // The newc magic followed by non-hex header fields is not a real cpio entry.
    let mut block = b"070701".to_vec();
    block.extend_from_slice(&filler(7, 200)); // garbage (non-hex) fields

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");
    std::fs::write(&img_path, &block).unwrap();

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["cpio".to_string()]).unwrap();
    let stats = carver::carve(&source, &sigs, &opts(out_dir), &NoProgress).unwrap();
    assert_eq!(stats.files_recovered, 0, "non-hex header rejected");
}
