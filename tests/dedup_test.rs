//! Integration test for content-based deduplication: two byte-identical JPEGs
//! planted at different offsets are carved once with `--dedup`, twice without.

use std::io::Write;

use filerecovery::carver::{self, CarveOptions, NoProgress};
use filerecovery::signatures;
use filerecovery::source::Source;

/// Filler that never contains `0xFF`, so it plants no stray JPEG framing.
fn filler(seed: u64, n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i as u64 + seed) % 251) as u8).collect()
}

fn jpeg(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
    v.extend_from_slice(payload);
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

fn carve(img: &[u8], dedup: bool) -> (carver::CarveStats, usize) {
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");
    let mut f = std::fs::File::create(&img_path).unwrap();
    f.write_all(img).unwrap();
    f.flush().unwrap();
    drop(f);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["jpg".to_string()]).unwrap();
    let opts = CarveOptions {
        output_dir: out_dir.clone(),
        start: 0,
        end: None,
        min_size: 0,
        max_files: None,
        allow_nested: false,
        validate: true,
        dedup,
        progress: false,
    };
    let stats = carver::carve(&source, &sigs, &opts, &NoProgress).unwrap();
    let written = std::fs::read_dir(&out_dir).unwrap().count();
    (stats, written)
}

#[test]
fn dedup_writes_identical_content_once() {
    let same = jpeg(&filler(1, 4000));
    let other = jpeg(&filler(2, 4000));

    // Two identical JPEGs plus a distinct one, separated by noise.
    let mut img = filler(10, 500);
    img.extend_from_slice(&same);
    img.extend_from_slice(&filler(11, 500));
    img.extend_from_slice(&same);
    img.extend_from_slice(&filler(12, 500));
    img.extend_from_slice(&other);

    // Without dedup all three matches are written.
    let (stats, written) = carve(&img, false);
    assert_eq!(stats.files_recovered, 3);
    assert_eq!(stats.duplicates, 0);
    assert_eq!(written, 3);

    // With dedup the repeated content is written only once.
    let (stats, written) = carve(&img, true);
    assert_eq!(stats.files_recovered, 2, "two distinct files");
    assert_eq!(stats.duplicates, 1, "one identical copy skipped");
    assert_eq!(written, 2, "only two files on disk");
}
