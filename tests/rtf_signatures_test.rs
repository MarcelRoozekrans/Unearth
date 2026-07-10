//! Carving test for Rich Text Format (RTF) documents. An RTF is one big
//! `{ ... }` group; the carver matches the outer braces (honouring `\{`, `\}`,
//! `\\` escapes) to find the end. Built byte-exactly, embedded, and recovered.

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

#[test]
fn recovers_an_rtf_document() {
    // Nested groups plus escaped braces (\{ and \}) that must NOT change depth.
    let rtf: &[u8] = br#"{\rtf1\ansi{\fonttbl{\f0 Times;}}\f0 hi \{x\} bye}"#;

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 500)).unwrap();
    img.write_all(rtf).unwrap();
    // Trailing braces in following noise must not be attributed to the RTF.
    img.write_all(b"}}} trailing").unwrap();
    img.write_all(&filler(11, 500)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["rtf".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "one rtf document");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], rtf, "recovered bytes must match the original");
    assert_eq!(stats.per_type.get("rtf"), Some(&1));
}
