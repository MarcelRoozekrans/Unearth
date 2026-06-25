//! `--max-size` skips carved files larger than the cap, counting them in
//! `skipped_large` instead of writing them. Two PNGs of different sizes are
//! embedded; a cap between them keeps only the smaller one.

use std::io::Write;

use filerecovery::carver::{self, CarveOptions, NoProgress};
use filerecovery::signatures;
use filerecovery::source::Source;

/// A minimal but structurally valid PNG: signature, an IHDR chunk, and the IEND
/// trailer, padded with `extra` zero bytes of (ignored) image data so the carved
/// length can be made larger or smaller.
fn make_png(extra: usize) -> Vec<u8> {
    let mut v = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    // IHDR: length(13) + "IHDR" + 13 bytes + CRC(4).
    v.extend_from_slice(&13u32.to_be_bytes());
    v.extend_from_slice(b"IHDR");
    v.extend_from_slice(&1u32.to_be_bytes()); // width
    v.extend_from_slice(&1u32.to_be_bytes()); // height
    v.extend_from_slice(&[8, 2, 0, 0, 0]); // bit depth, colour type, etc.
    v.extend_from_slice(&[0, 0, 0, 0]); // CRC (not validated by the carver)
                                        // An IDAT chunk carrying `extra` payload bytes, to control the size.
    v.extend_from_slice(&(extra as u32).to_be_bytes());
    v.extend_from_slice(b"IDAT");
    v.extend(std::iter::repeat(0u8).take(extra));
    v.extend_from_slice(&[0, 0, 0, 0]); // CRC
                                        // IEND trailer.
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(b"IEND");
    v.extend_from_slice(&[0xAE, 0x42, 0x60, 0x82]);
    v
}

fn carve_with_max(max_size: Option<u64>, files: &[&[u8]]) -> carver::CarveStats {
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    for (i, f) in files.iter().enumerate() {
        img.write_all(&vec![0u8; 256]).unwrap(); // separator padding
        img.write_all(f).unwrap();
        let _ = i;
    }
    img.write_all(&vec![0u8; 256]).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["png".to_string()]).unwrap();
    let opts = CarveOptions {
        output_dir: out_dir,
        start: 0,
        end: None,
        min_size: 0,
        max_size,
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
    carver::carve(&source, &sigs, &opts, &NoProgress).unwrap()
}

#[test]
fn max_size_skips_files_over_the_cap() {
    let small = make_png(64);
    let large = make_png(8192);
    assert!(large.len() as u64 > small.len() as u64);

    // No cap: both recovered.
    let both = carve_with_max(None, &[&small, &large]);
    assert_eq!(both.files_recovered, 2);
    assert_eq!(both.skipped_large, 0);

    // Cap between the two sizes: only the small one is written; the large one is
    // counted as skipped, not recovered.
    let cap = (small.len() as u64 + large.len() as u64) / 2;
    let capped = carve_with_max(Some(cap), &[&small, &large]);
    assert_eq!(capped.files_recovered, 1, "only the small PNG fits the cap");
    assert_eq!(capped.skipped_large, 1, "the large PNG is skipped");
}
