//! Apple Partition Map detection: a volume inside an APM partition is found by
//! `recover::detect`, and the partition table reports the APM scheme.

mod common;

use unearth::partition::{self, Scheme};
use unearth::recover;
use unearth::source::Source;

const BS: usize = 512;

#[test]
fn detect_finds_a_volume_in_an_apm_partition() {
    // An ext volume placed at block 64; an APM map (one entry) points at it.
    let ext = common::ext_volume("notes.txt", b"hello apm");
    let part_block = 64usize;
    let part_blocks = ext.len().div_ceil(BS);
    let mut img = vec![0u8; part_block * BS + ext.len()];
    img[part_block * BS..part_block * BS + ext.len()].copy_from_slice(&ext);

    // Partition map entry at block 1: "PM" sig, one map block, start/size.
    let e = BS;
    img[e..e + 2].copy_from_slice(b"PM");
    img[e + 4..e + 8].copy_from_slice(&1u32.to_be_bytes()); // pmMapBlkCnt
    img[e + 8..e + 12].copy_from_slice(&(part_block as u32).to_be_bytes());
    img[e + 12..e + 16].copy_from_slice(&(part_blocks as u32).to_be_bytes());
    img[e + 48..e + 48 + 9].copy_from_slice(b"Apple_HFS"); // pmPartType (informational)

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("mac.img");
    std::fs::write(&path, &img).unwrap();
    let src = Source::open(&path).unwrap();

    // The partition table reports the APM scheme and the entry.
    let table = partition::read(&src);
    assert_eq!(table.scheme, Scheme::Apm);
    assert_eq!(table.partitions.len(), 1);
    assert_eq!(table.partitions[0].start, (part_block * BS) as u64);

    // And the volume inside the partition is detected and recoverable.
    let vols = recover::detect(&src).unwrap();
    assert_eq!(
        vols.len(),
        1,
        "the ext volume in the APM partition is found"
    );
    assert_eq!(vols[0].fs_label(), "ext2/3/4");
    assert_eq!(vols[0].offset(), (part_block * BS) as u64);
}
