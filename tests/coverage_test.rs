//! Extra coverage for less-common code paths: FAT32 (cluster-chained root
//! directory) and GPT with 4096-byte logical sectors.

mod common;

use filerecovery::recover::{self, RecoverOptions};
use filerecovery::source::Source;

fn recover_one(disk: &[u8], expected_name: &str, expected: &[u8], expected_fs: &str) {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out = tmp.path().join("out");
    std::fs::write(&img, disk).unwrap();

    let source = Source::open(&img).unwrap();
    let volumes = recover::detect(&source).unwrap();
    assert_eq!(volumes.len(), 1, "exactly one volume expected");
    assert_eq!(volumes[0].fs_label(), expected_fs);

    let stats = volumes[0]
        .recover_deleted(&source, &out, &RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 1, "should recover one file");
    assert_eq!(std::fs::read(out.join(expected_name)).unwrap(), expected);
}

#[test]
fn fat32_cluster_chained_root() {
    let payload: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
    let disk = common::fat32_volume(b"MOVIE   ", b"AVI", &payload);
    // The short name's first byte is lost to the deletion marker => '_'.
    recover_one(&disk, "_OVIE.AVI", &payload, "Fat32");
}

#[test]
fn gpt_with_4k_logical_sectors() {
    let payload = b"recovered from a 4K-sector GPT disk";
    let vol = common::ext_volume("big_sector.bin", payload);
    let disk = common::gpt_disk(&vol, 4096, 4); // 4 KiB sectors, partition at LBA 4
    recover_one(&disk, "big_sector.bin", payload, "ext2/3/4");
}

#[test]
fn gpt_with_512_sectors_still_works() {
    let payload = b"classic 512-byte sector GPT";
    let vol = common::ext_volume("classic.bin", payload);
    let disk = common::gpt_disk(&vol, 512, 34);
    recover_one(&disk, "classic.bin", payload, "ext2/3/4");
}
