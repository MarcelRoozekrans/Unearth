//! ISO 9660 (data CD/DVD discs and `.iso` images) is recognised by
//! `detect`/`info` — with its size and volume label — and its files are
//! extracted with their names and folder paths (see the unit tests in
//! `src/iso9660.rs` for the directory-walk extraction itself).

use std::process::Command;

use filerecovery::recover::{self, RecoverOptions};
use filerecovery::source::Source;

const VDS_OFFSET: usize = 16 * 2048;
const VD_SIZE: usize = 2048;

/// A minimal ISO 9660 image: a Primary Volume Descriptor at sector 16 with a
/// volume size (block count × block size) and a volume label. No directory tree,
/// so there are no files to extract.
fn iso_image(blocks: u32, label: &str) -> Vec<u8> {
    let mut v = vec![0u8; VDS_OFFSET + 4 * VD_SIZE];
    let off = VDS_OFFSET; // sector 16
    v[off] = 1; // Primary Volume Descriptor
    v[off + 1..off + 6].copy_from_slice(b"CD001");
    v[off + 6] = 1;
    v[off + 40..off + 40 + label.len()].copy_from_slice(label.as_bytes());
    v[off + 80..off + 84].copy_from_slice(&blocks.to_le_bytes());
    v[off + 128..off + 130].copy_from_slice(&2048u16.to_le_bytes());
    // Volume creation date/time at offset 813: 2021-01-01 12:00:00, GMT.
    v[off + 813..off + 829].copy_from_slice(b"2021010112000000");
    v
}

#[test]
fn detect_reports_iso9660_with_size_and_label() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disc.iso");
    std::fs::write(&img, iso_image(50, "MY_DISC")).unwrap();
    let src = Source::open(&img).unwrap();

    let vols = recover::detect(&src).unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].fs_label(), "ISO 9660");
    assert_eq!(vols[0].size(), 50 * 2048);
    assert_eq!(vols[0].volume_label().as_deref(), Some("MY_DISC"));
    // 2021-01-01 12:00:00 UTC = 18628 days + 12 h.
    assert_eq!(vols[0].created_time(), Some(18628 * 86400 + 12 * 3600));

    // This image has no root directory tree, so there is nothing to extract.
    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 0);
}

#[test]
fn info_cli_lists_an_iso9660_volume() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disc.iso");
    std::fs::write(&img, iso_image(50, "MY_DISC")).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_filerecovery"))
        .args(["info", img.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ISO 9660"), "stdout: {stdout}");
    assert!(stdout.contains("MY_DISC"), "stdout: {stdout}");
}
