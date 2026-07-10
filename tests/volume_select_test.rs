//! `--volume <N>` selects a single detected volume (by its `info` index) for the
//! undelete pass, instead of processing every volume.

mod common;

use std::process::Command;

/// A disk with an MBR pointing at two ext volumes (at LBA 64 and 200), each
/// holding one deleted file with a distinct name.
fn two_volume_disk() -> Vec<u8> {
    let v0 = common::ext_volume("alpha.txt", b"first volume payload");
    let v1 = common::ext_volume("beta.txt", b"second volume payload");
    let (lba0, lba1) = (64usize, 200usize);
    let mut disk = vec![0u8; (lba1 + 128) * 512];
    disk[lba0 * 512..lba0 * 512 + v0.len()].copy_from_slice(&v0);
    disk[lba1 * 512..lba1 * 512 + v1.len()].copy_from_slice(&v1);

    // MBR signature and two Linux (0x83) partition entries.
    disk[510] = 0x55;
    disk[511] = 0xAA;
    for (i, lba) in [lba0, lba1].iter().enumerate() {
        let p = 446 + i * 16;
        disk[p + 4] = 0x83;
        disk[p + 8..p + 12].copy_from_slice(&(*lba as u32).to_le_bytes());
    }
    disk
}

/// Whether any file named `name` exists anywhere under `dir`.
fn contains_file(dir: &std::path::Path, name: &str) -> bool {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.file_name().and_then(|s| s.to_str()) == Some(name) {
                return true;
            }
        }
    }
    false
}

#[test]
fn volume_index_selects_one_volume() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    std::fs::write(&img, two_volume_disk()).unwrap();
    let out = tmp.path().join("out");

    let status = Command::new(env!("CARGO_BIN_EXE_unearth"))
        .args([
            "undelete",
            img.to_str().unwrap(),
            "--volume",
            "1",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());

    assert!(contains_file(&out, "beta.txt"), "volume 1's file recovered");
    assert!(
        !contains_file(&out, "alpha.txt"),
        "volume 0's file must not be recovered"
    );
}

#[test]
fn out_of_range_volume_is_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    std::fs::write(&img, two_volume_disk()).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_unearth"))
        .args([
            "undelete",
            img.to_str().unwrap(),
            "--volume",
            "9",
            "-o",
            tmp.path().join("out").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "index 9 is out of range");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("out of range"), "stderr: {stderr}");
}
