//! Test for `CarveOptions::dry_run`: the carver tallies what it would recover
//! (counts, sizes, per-type, manifest records) without writing any files.

use std::io::Write;

use filerecovery::carver::{self, CarveOptions, NoProgress};
use filerecovery::signatures;
use filerecovery::source::Source;

/// A minimal BMP whose total size (200) is recorded in the header at offset 2.
fn bmp(total: usize) -> Vec<u8> {
    let mut v = vec![0u8; total];
    v[0..2].copy_from_slice(b"BM");
    v[2..6].copy_from_slice(&(total as u32).to_le_bytes());
    v
}

fn opts(out_dir: std::path::PathBuf, dry_run: bool) -> CarveOptions {
    CarveOptions {
        output_dir: out_dir,
        start: 0,
        end: None,
        min_size: 0,
        max_files: None,
        allow_nested: false,
        validate: false,
        dedup: false,
        progress: false,
        checkpoint: None,
        resume: false,
        organize: false,
        dry_run,
    }
}

#[test]
fn dry_run_tallies_without_writing() {
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let file = bmp(200);
    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&[0u8; 300]).unwrap();
    img.write_all(&file).unwrap();
    img.write_all(&[0u8; 300]).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["bmp".to_string()]).unwrap();

    // Dry run: the file is found and tallied, but nothing is written.
    let stats = carver::carve(&source, &sigs, &opts(out_dir.clone(), true), &NoProgress).unwrap();
    assert_eq!(stats.files_recovered, 1, "the file is tallied");
    assert_eq!(stats.bytes_recovered, 200);
    assert_eq!(stats.per_type.get("bmp"), Some(&1));
    assert_eq!(stats.files.len(), 1, "the manifest record is produced");
    assert!(
        !out_dir.exists() || std::fs::read_dir(&out_dir).unwrap().next().is_none(),
        "dry run must not write any files"
    );

    // A real run with the same inputs writes the file.
    let stats = carver::carve(&source, &sigs, &opts(out_dir.clone(), false), &NoProgress).unwrap();
    assert_eq!(stats.files_recovered, 1);
    let written: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(written.len(), 1);
    assert_eq!(written[0], file, "the real run writes the carved bytes");
}
