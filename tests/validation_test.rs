//! Integration tests for the carver's structural-validation gate: a magic that
//! occurs by coincidence (with a footer to bound it) is dropped by default but
//! kept when validation is disabled.

use std::io::Write;

use filerecovery::carver::{self, CarveOptions, NoProgress};
use filerecovery::signatures;
use filerecovery::source::Source;

/// Deterministic filler that never contains the byte `0xFF`, so it can hold no
/// stray JPEG magic (`FF D8 FF`) or footer (`FF D9`) of its own. That keeps the
/// recovered-file counts depending only on the planted candidates.
fn filler(seed: u64, n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i as u64 + seed) % 251) as u8).collect()
}

/// A bogus "JPEG": valid SOI/footer framing but an impossible first marker
/// (0x00), so the JPEG validator rejects it.
fn fake_jpeg(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8, 0xFF, 0x00];
    v.extend_from_slice(payload);
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

/// A real-looking JPEG (APP0 marker) the validator accepts.
fn real_jpeg(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
    v.extend_from_slice(payload);
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

fn carve(img: &[u8], validate: bool) -> carver::CarveStats {
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
        output_dir: out_dir,
        start: 0,
        end: None,
        min_size: 0,
        max_size: None,
        max_files: None,
        allow_nested: false,
        validate,
        dedup: false,
        progress: false,
        checkpoint: None,
        resume: false,
        organize: false,
        dry_run: false,
        align: 1,
    };
    carver::carve(&source, &sigs, &opts, &NoProgress).unwrap()
}

#[test]
fn validation_drops_bogus_match_but_keeps_real_one() {
    let mut img = filler(10, 500);
    img.extend_from_slice(&fake_jpeg(&filler(1, 2000)));
    img.extend_from_slice(&filler(11, 500));
    img.extend_from_slice(&real_jpeg(&filler(2, 2000)));

    // With validation (the default) only the real JPEG survives.
    let stats = carve(&img, true);
    assert_eq!(stats.files_recovered, 1, "only the real JPEG is kept");
    assert_eq!(stats.rejected, 1, "the bogus match is rejected");

    // With validation disabled both signature matches are carved.
    let stats = carve(&img, false);
    assert_eq!(stats.files_recovered, 2, "both matches kept");
    assert_eq!(stats.rejected, 0);
}
