//! Lost-partition scanning: when the partition table is gone or corrupt, a
//! whole-source signature scan still locates the filesystems on the disk.

mod common;

use unearth::recover;
use unearth::source::Source;

const MIB: usize = 1024 * 1024;

#[test]
fn scan_finds_a_volume_with_no_partition_table() {
    // An ext volume placed at 1 MiB, with garbage (no MBR/GPT) before it, so
    // ordinary detection finds nothing but a signature scan locates it.
    let ext = common::ext_volume("notes.txt", b"hello world");
    let mut img = vec![0xA5u8; MIB + ext.len()];
    img[MIB..MIB + ext.len()].copy_from_slice(&ext);
    // Make sure offset 0 is not accidentally a valid volume.
    img[510] = 0;
    img[511] = 0;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("nopart.img");
    std::fs::write(&path, &img).unwrap();
    let src = Source::open(&path).unwrap();

    // Ordinary detection sees nothing.
    assert!(recover::detect(&src).is_err());

    // The signature scan finds the ext volume at 1 MiB.
    let found = recover::scan_lost_volumes(&src, MIB as u64, |_| {}).unwrap();
    assert_eq!(found.len(), 1, "should find the orphaned ext volume");
    assert_eq!(found[0].offset(), MIB as u64);
    assert_eq!(found[0].fs_label(), "ext2/3/4");
}

#[test]
fn undelete_scan_recovers_from_a_lost_partition() {
    // A deleted file in an ext volume at 1 MiB, no partition table; `undelete
    // --scan` should locate the volume and recover the file.
    let ext = common::ext_volume("notes.txt", b"hello world");
    let mut img = vec![0xA5u8; MIB + ext.len()];
    img[MIB..MIB + ext.len()].copy_from_slice(&ext);
    img[510] = 0;
    img[511] = 0;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("nopart.img");
    let out = tmp.path().join("out");
    std::fs::write(&path, &img).unwrap();

    let result = std::process::Command::new(env!("CARGO_BIN_EXE_unearth"))
        .args([
            "undelete",
            path.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--scan",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        std::fs::read(out.join("notes.txt")).unwrap(),
        b"hello world"
    );
}

#[test]
fn info_scan_cli_reports_a_lost_partition() {
    let ext = common::ext_volume("notes.txt", b"hello world");
    let mut img = vec![0xA5u8; MIB + ext.len()];
    img[MIB..MIB + ext.len()].copy_from_slice(&ext);
    img[510] = 0;
    img[511] = 0;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("nopart.img");
    std::fs::write(&path, &img).unwrap();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_unearth"))
        .args(["info", path.to_str().unwrap(), "--scan", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"scan\""), "stdout: {stdout}");
    assert!(stdout.contains("ext2/3/4"), "stdout: {stdout}");
    assert!(
        stdout.contains(&format!("\"offset\": {}", MIB)),
        "stdout: {stdout}"
    );
}
