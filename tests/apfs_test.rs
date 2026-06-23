//! APFS is recognised by `detect`/`info` (and surfaced to the user), but it is
//! not recovered from metadata — `undelete` finds nothing and carving is the
//! fallback.

use std::process::Command;

use filerecovery::recover::{self, RecoverOptions};
use filerecovery::source::Source;

/// A minimal APFS container superblock (`nx_superblock_t`).
fn apfs_container(block_size: u32, block_count: u64) -> Vec<u8> {
    let total = block_size as usize * block_count as usize;
    let mut v = vec![0u8; total.max(4096)];
    v[24..28].copy_from_slice(&0x0001u32.to_le_bytes()); // o_type = NX_SUPERBLOCK
    v[32..36].copy_from_slice(b"NXSB"); // nx_magic
    v[36..40].copy_from_slice(&block_size.to_le_bytes());
    v[40..48].copy_from_slice(&block_count.to_le_bytes());
    v
}

#[test]
fn detect_reports_apfs_but_recovers_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("c.img");
    std::fs::write(&img, apfs_container(4096, 8)).unwrap();
    let src = Source::open(&img).unwrap();

    let vols = recover::detect(&src).unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].fs_label(), "APFS");
    assert_eq!(vols[0].size(), 4096 * 8);

    // Recognised, but metadata undelete yields nothing (no error, no files).
    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 0);
}

#[test]
fn info_cli_lists_an_apfs_volume() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("c.img");
    std::fs::write(&img, apfs_container(4096, 8)).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_filerecovery"))
        .args(["info", img.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("APFS"), "stdout: {stdout}");
}
