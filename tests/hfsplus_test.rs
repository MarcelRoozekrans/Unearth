//! HFS+ undelete: recover a deleted file from a catalog leaf node's free space.

mod common;

use filerecovery::recover::{self, RecoverOptions};
use filerecovery::source::Source;

fn write_img(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    std::fs::write(&img, bytes).unwrap();
    (tmp, img)
}

#[test]
fn detects_and_recovers_a_deleted_file() {
    let payload = b"the quick brown fox jumps over the lazy dog";
    let (tmp, img) = write_img(&common::hfsplus_volume("notes.txt", payload));
    let src = Source::open(&img).unwrap();

    let vols = recover::detect(&src).unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].fs_label(), "HFS+");

    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();

    assert_eq!(stats.recovered, 1);
    assert_eq!(stats.bytes_recovered, payload.len() as u64);
    assert_eq!(std::fs::read(out.join("notes.txt")).unwrap(), payload);
}

#[test]
fn recovers_a_multi_block_file_byte_for_byte() {
    // Larger than one 512-byte allocation block, so the extent spans blocks.
    let payload: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
    let (tmp, img) = write_img(&common::hfsplus_volume("data.bin", &payload));
    let src = Source::open(&img).unwrap();

    let vols = recover::detect(&src).unwrap();
    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();

    assert_eq!(stats.recovered, 1);
    assert_eq!(std::fs::read(out.join("data.bin")).unwrap(), payload);
}

#[test]
fn dry_run_reports_without_writing() {
    let (tmp, img) = write_img(&common::hfsplus_volume("secret.dat", b"hello hfs+"));
    let src = Source::open(&img).unwrap();
    let vols = recover::detect(&src).unwrap();

    let out = tmp.path().join("out");
    let opts = RecoverOptions {
        min_size: 0,
        dry_run: true,
    };
    let stats = vols[0].recover_deleted(&src, &out, &opts).unwrap();

    assert_eq!(stats.recovered, 1);
    assert!(!out.exists(), "dry run must not write files");
}

#[test]
fn unicode_name_is_preserved() {
    let (tmp, img) = write_img(&common::hfsplus_volume("café — not.txt", b"unicode body"));
    let src = Source::open(&img).unwrap();
    let vols = recover::detect(&src).unwrap();

    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 1);
    // The ':' separator is the only character HFS+ forbids; the rest survive.
    assert_eq!(
        std::fs::read(out.join("café — not.txt")).unwrap(),
        b"unicode body"
    );
}
