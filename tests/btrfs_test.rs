//! Btrfs is recognised by `detect`/`info` (with its label and size), but it is
//! not recovered from metadata — `undelete` finds nothing and carving is the
//! fallback (copy-on-write reclaims old tree nodes).

use std::process::Command;

use filerecovery::recover::{self, RecoverOptions};
use filerecovery::source::Source;

const SB_OFFSET: usize = 0x1_0000; // primary superblock at 64 KiB
const MAGIC: usize = 64;
const TOTAL_BYTES: usize = 112;
const SECTORSIZE: usize = 144;
const NODESIZE: usize = 148;
const LABEL: usize = 299;

/// A minimal Btrfs volume: just enough of the superblock for detection.
fn btrfs_volume(label: &str, total_bytes: u64) -> Vec<u8> {
    let mut v = vec![0u8; SB_OFFSET + 4096];
    let sb = SB_OFFSET;
    v[sb + MAGIC..sb + MAGIC + 8].copy_from_slice(b"_BHRfS_M");
    v[sb + TOTAL_BYTES..sb + TOTAL_BYTES + 8].copy_from_slice(&total_bytes.to_le_bytes());
    v[sb + SECTORSIZE..sb + SECTORSIZE + 4].copy_from_slice(&4096u32.to_le_bytes());
    v[sb + NODESIZE..sb + NODESIZE + 4].copy_from_slice(&16384u32.to_le_bytes());
    let lb = label.as_bytes();
    v[sb + LABEL..sb + LABEL + lb.len()].copy_from_slice(lb);
    v
}

#[test]
fn detect_reports_btrfs_with_label_but_recovers_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("b.img");
    std::fs::write(&img, btrfs_volume("photos", 1 << 30)).unwrap();
    let src = Source::open(&img).unwrap();

    let vols = recover::detect(&src).unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].fs_label(), "Btrfs");
    assert_eq!(vols[0].size(), 1 << 30);
    assert_eq!(vols[0].volume_label().as_deref(), Some("photos"));

    // Recognised, but metadata undelete yields nothing.
    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 0);
}

#[test]
fn info_cli_shows_the_btrfs_label() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("b.img");
    std::fs::write(&img, btrfs_volume("backups", 1 << 30)).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_filerecovery"))
        .args(["info", img.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Btrfs"), "stdout: {stdout}");
    assert!(stdout.contains("backups"), "stdout: {stdout}");
}
