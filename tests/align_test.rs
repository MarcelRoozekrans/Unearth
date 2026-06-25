//! `--align` restricts carving to candidates whose start offset is a multiple
//! of the given alignment. Two valid PNGs are placed at a sector-aligned and a
//! non-aligned offset; with `align = 512` only the aligned one is recovered,
//! with `align = 1` both are.

use filerecovery::carver::{self, CarveOptions, NoProgress};
use filerecovery::signatures;
use filerecovery::source::Source;

/// A minimal but valid PNG (signature + IHDR + IEND).
fn png() -> Vec<u8> {
    let mut v = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    v.extend_from_slice(&13u32.to_be_bytes());
    v.extend_from_slice(b"IHDR");
    v.extend_from_slice(&1u32.to_be_bytes()); // width
    v.extend_from_slice(&1u32.to_be_bytes()); // height
    v.extend_from_slice(&[8, 2, 0, 0, 0]); // depth, colour type, etc.
    v.extend_from_slice(&[0, 0, 0, 0]); // CRC (carver doesn't check it)
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(b"IEND");
    v.extend_from_slice(&[0xAE, 0x42, 0x60, 0x82]);
    v
}

/// Build an image with each `(offset, bytes)` placed at that absolute offset,
/// carve it for PNGs at the given alignment, and return the recovered count.
fn carve_aligned(align: u64, placements: &[(usize, Vec<u8>)]) -> u64 {
    let size = placements
        .iter()
        .map(|(off, b)| off + b.len())
        .max()
        .unwrap_or(0)
        + 512;
    let mut img = vec![0u8; size];
    for (off, bytes) in placements {
        img[*off..*off + bytes.len()].copy_from_slice(bytes);
    }

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    std::fs::write(&img_path, &img).unwrap();
    let out_dir = tmp.path().join("out");

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["png".to_string()]).unwrap();
    let opts = CarveOptions {
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
        align,
    };
    carver::carve(&source, &sigs, &opts, &NoProgress)
        .unwrap()
        .files_recovered
}

#[test]
fn alignment_keeps_only_sector_aligned_candidates() {
    // One PNG at a 512-aligned offset, one at an offset that is not a multiple.
    let placements = vec![(512usize, png()), (2000usize, png())];
    assert_ne!(2000 % 512, 0, "second offset is deliberately unaligned");

    // No alignment: both are found.
    assert_eq!(carve_aligned(1, &placements), 2, "align=1 finds both");

    // 512-byte alignment: only the aligned PNG survives.
    assert_eq!(
        carve_aligned(512, &placements),
        1,
        "align=512 drops the unaligned PNG"
    );
}
