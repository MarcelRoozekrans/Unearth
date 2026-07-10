//! LUKS and BitLocker containers are recognised by `detect`/`info` (so the user
//! is told the disk is encrypted), but nothing is recovered from them — they
//! must be unlocked with the key first.

use std::process::Command;

use unearth::recover::{self, RecoverOptions};
use unearth::source::Source;

fn luks_image(version: u16) -> Vec<u8> {
    let mut v = vec![0u8; 1 << 20];
    v[0..6].copy_from_slice(b"LUKS\xba\xbe");
    v[6..8].copy_from_slice(&version.to_be_bytes());
    v
}

fn bitlocker_image() -> Vec<u8> {
    let mut v = vec![0u8; 1 << 20];
    v[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]); // boot-sector jump
    v[3..11].copy_from_slice(b"-FVE-FS-"); // BitLocker OEM ID
    v[510] = 0x55;
    v[511] = 0xAA;
    v
}

#[test]
fn detects_luks_and_recovers_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("luks.img");
    std::fs::write(&img, luks_image(2)).unwrap();
    let src = Source::open(&img).unwrap();

    let vols = recover::detect(&src).unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].fs_label(), "LUKS2");
    assert_eq!(vols[0].size(), 1 << 20);

    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 0);
}

#[test]
fn detects_bitlocker() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("bl.img");
    std::fs::write(&img, bitlocker_image()).unwrap();
    let src = Source::open(&img).unwrap();

    let vols = recover::detect(&src).unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].fs_label(), "BitLocker");
}

#[test]
fn info_cli_reports_an_encrypted_volume() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("luks.img");
    std::fs::write(&img, luks_image(1)).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_unearth"))
        .args(["info", img.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("LUKS1"), "stdout: {stdout}");
}
