//! Carving test for Outlook data files (PST/OST). A synthetic Unicode NDB
//! header is built with its `ibFileEof` set to the total size; the carver reads
//! that field to size the file and recovers it byte-for-byte. An ANSI-version
//! header (whose `ibFileEof` layout differs) is rejected rather than mis-sized.

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

/// A `total`-byte Outlook data file: an NDB header (magic `!BDN`, client `SM`,
/// version `ver`, and `ibFileEof` at 0xB8) followed by filler to `total`.
fn make_pst(total: usize, ver: u16) -> Vec<u8> {
    let mut v = filler(7, total);
    v[0..4].copy_from_slice(b"!BDN");
    v[8..10].copy_from_slice(b"SM");
    v[10..12].copy_from_slice(&ver.to_le_bytes());
    v[0xB8..0xC0].copy_from_slice(&(total as u64).to_le_bytes());
    v
}

fn carve_pst(data: &[u8]) -> (carver::CarveStats, Vec<Vec<u8>>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 600)).unwrap();
    img.write_all(data).unwrap();
    img.write_all(&filler(11, 600)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["pst".to_string()]).unwrap();
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
    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    (stats, recovered, tmp)
}

#[test]
fn recovers_a_unicode_pst_sized_from_ibfileeof() {
    let pst = make_pst(4096, 23); // wVer 23 = Unicode
    let (stats, recovered, _tmp) = carve_pst(&pst);
    assert_eq!(stats.files_recovered, 1, "one PST recovered");
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0], pst,
        "recovered bytes match, sized from ibFileEof"
    );
    assert_eq!(stats.per_type.get("pst"), Some(&1));
}

#[test]
fn rejects_an_ansi_pst() {
    // wVer 15 = ANSI: ibFileEof layout differs, so the carver declines.
    let pst = make_pst(4096, 15);
    let (stats, _recovered, _tmp) = carve_pst(&pst);
    assert_eq!(stats.files_recovered, 0, "ANSI PST is not carved");
}
