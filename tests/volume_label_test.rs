//! Volume labels are read from each filesystem and surfaced via
//! `recover::Volume::volume_label()` (and thus `info` / `list_volumes`).

mod common;

use filerecovery::source::Source;
use filerecovery::{ext4, fat, recover};

fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("vol.img");
    std::fs::write(&p, bytes).unwrap();
    (tmp, Source::open(&p).unwrap())
}

#[test]
fn ext_volume_label_is_read_from_the_superblock() {
    // s_volume_name lives at superblock offset 0x78 (superblock starts at 1024).
    let mut img = common::ext_volume("notes.txt", b"hi");
    let off = 1024 + 0x78;
    let name = b"MYEXTDISK";
    img[off..off + name.len()].copy_from_slice(name);

    let (_t, src) = source_of(&img);
    assert_eq!(ext4::Volume::parse(&src, 0).unwrap().label(), "MYEXTDISK");
    assert_eq!(
        recover::detect(&src).unwrap()[0].volume_label().as_deref(),
        Some("MYEXTDISK")
    );
}

#[test]
fn fat32_volume_label_is_read_from_the_boot_sector() {
    // BS_VolLab is 11 bytes at offset 71 on FAT32, space-padded.
    let mut img = common::fat32_volume(b"PHOTO   ", b"JPG", b"x");
    img[71..82].copy_from_slice(b"MY FAT32   ");

    let (_t, src) = source_of(&img);
    assert_eq!(fat::Volume::parse(&src, 0).unwrap().label(), "MY FAT32");
    assert_eq!(
        recover::detect(&src).unwrap()[0].volume_label().as_deref(),
        Some("MY FAT32")
    );
}

#[test]
fn unlabeled_fat_reports_no_label() {
    // The "NO NAME" placeholder is treated as no label.
    let mut img = common::fat32_volume(b"PHOTO   ", b"JPG", b"x");
    img[71..82].copy_from_slice(b"NO NAME    ");
    let (_t, src) = source_of(&img);
    assert_eq!(fat::Volume::parse(&src, 0).unwrap().label(), "");
    assert_eq!(recover::detect(&src).unwrap()[0].volume_label(), None);
}
