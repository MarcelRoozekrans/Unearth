//! `info` reports each volume's free (unallocated) space, computed from the
//! filesystem's allocation map via `recover::Volume::free_extents`.

mod common;

use filerecovery::recover;
use filerecovery::source::Source;
use std::process::Command;

fn source_of(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf, Source) {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("vol.img");
    std::fs::write(&p, bytes).unwrap();
    let src = Source::open(&p).unwrap();
    (tmp, p, src)
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_filerecovery")
}

#[test]
fn fat_volume_reports_some_free_space() {
    let img = common::fat32_volume(b"PHOTO   ", b"JPG", b"x");
    let (_t, _p, src) = source_of(&img);
    let vol = &recover::detect(&src).unwrap()[0];
    let extents = vol
        .free_extents(&src)
        .expect("FAT exposes an allocation map");
    let free: u64 = extents.iter().map(|(_, len)| len).sum();
    // A nearly-empty volume has free space, and it cannot exceed the volume.
    assert!(free > 0, "expected non-zero free space");
    assert!(free <= vol.size(), "free space cannot exceed the volume");
}

#[test]
fn info_text_output_includes_a_free_line() {
    let img = common::fat32_volume(b"PHOTO   ", b"JPG", b"x");
    let (_t, p, _src) = source_of(&img);
    let out = Command::new(bin())
        .args(["info", p.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("free:"), "stdout: {stdout}");
    assert!(stdout.contains("unallocated"), "stdout: {stdout}");
}

#[test]
fn info_json_output_includes_numeric_free_bytes() {
    let img = common::fat32_volume(b"PHOTO   ", b"JPG", b"x");
    let (_t, p, _src) = source_of(&img);
    let out = Command::new(bin())
        .args(["info", "--json", p.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"free_bytes\":"), "stdout: {stdout}");
    // The value is a number, not the `null` fallback, for FAT.
    assert!(
        !stdout.contains("\"free_bytes\": null"),
        "FAT should report a numeric free_bytes, got: {stdout}"
    );
}
