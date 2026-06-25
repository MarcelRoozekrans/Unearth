//! Carving test for Unix `ar` archives (`.a` static libraries, `.deb`
//! packages). An archive is built byte-exactly (global header + two members,
//! each a 60-byte header with the `` `\n `` sentinel and an even-padded body),
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

/// A 60-byte `ar` member header for a member named `name` with `size` bytes of
/// data. All fields are space-padded; the header ends with `` `\n ``.
fn ar_header(name: &str, size: usize) -> [u8; 60] {
    let mut h = [b' '; 60];
    let put = |h: &mut [u8; 60], off: usize, s: &str| {
        h[off..off + s.len()].copy_from_slice(s.as_bytes());
    };
    put(&mut h, 0, name); // file name (16)
    put(&mut h, 16, "0"); // mtime (12)
    put(&mut h, 28, "0"); // uid (6)
    put(&mut h, 34, "0"); // gid (6)
    put(&mut h, 40, "100644"); // mode (8)
    put(&mut h, 48, &size.to_string()); // data size (10)
    h[58] = b'`';
    h[59] = b'\n';
    h
}

/// Append a member (header + data + even padding) to `v`.
fn push_member(v: &mut Vec<u8>, name: &str, data: &[u8]) {
    v.extend_from_slice(&ar_header(name, data.len()));
    v.extend_from_slice(data);
    if data.len() % 2 == 1 {
        v.push(b'\n'); // pad odd-length data to an even boundary
    }
}

fn make_ar() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"!<arch>\n");
    push_member(&mut v, "hello.txt", b"hello"); // odd length -> padded
    push_member(&mut v, "data.bin", b"abcd"); // even length
    v
}

#[test]
fn recovers_an_ar_archive() {
    let ar = make_ar();

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 700)).unwrap();
    img.write_all(&ar).unwrap();
    img.write_all(&filler(11, 700)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["ar".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "one ar archive");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], ar, "recovered bytes must match the original");
    assert_eq!(stats.per_type.get("ar"), Some(&1));
}
