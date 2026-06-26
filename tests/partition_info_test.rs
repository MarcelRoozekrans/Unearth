//! `info` reports the partition table (scheme + each entry's type/name/range),
//! even for partitions whose filesystem isn't recovered.

use std::process::Command;

/// An MBR disk with two partition-table entries (no real filesystems inside).
fn mbr_disk() -> Vec<u8> {
    let mut disk = vec![0u8; 8192];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    // Partition 0: Linux (0x83) at LBA 2048, 100 sectors.
    let e = 446;
    disk[e + 4] = 0x83;
    disk[e + 8..e + 12].copy_from_slice(&2048u32.to_le_bytes());
    disk[e + 12..e + 16].copy_from_slice(&100u32.to_le_bytes());
    // Partition 1: NTFS/exFAT (0x07) at LBA 4096, 200 sectors.
    let e = 446 + 16;
    disk[e + 4] = 0x07;
    disk[e + 8..e + 12].copy_from_slice(&4096u32.to_le_bytes());
    disk[e + 12..e + 16].copy_from_slice(&200u32.to_le_bytes());
    disk
}

fn run(args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_filerecovery"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

#[test]
fn info_text_shows_the_partition_table() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    std::fs::write(&img, mbr_disk()).unwrap();

    let (ok, stdout) = run(&["info", img.to_str().unwrap()]);
    assert!(ok);
    assert!(stdout.contains("Partition table: MBR"), "stdout: {stdout}");
    assert!(stdout.contains("Linux"), "stdout: {stdout}");
    assert!(stdout.contains("NTFS / exFAT"), "stdout: {stdout}");
}

#[test]
fn info_json_includes_partitions() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    std::fs::write(&img, mbr_disk()).unwrap();

    let (ok, stdout) = run(&["info", "--json", img.to_str().unwrap()]);
    assert!(ok);
    assert!(
        stdout.contains("\"partition_scheme\": \"mbr\""),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("\"type\": \"Linux\""), "stdout: {stdout}");
    assert!(
        stdout.contains("\"start\": 1048576"),
        "partition 0 starts at 2048*512: {stdout}"
    );
}
