//! Linux MD/RAID member detection through the unified `recover::detect` path:
//! a RAID member partition is recognised with its level, UUID, and name.

use unearth::recover;
use unearth::source::Source;

const SECTOR: usize = 512;
const MD_MAGIC: u32 = 0xA92B_4EFC;

/// A device carrying a version-1.2 MD superblock (at 4 KiB) with the given fields.
fn md_member(uuid: &[u8; 16], name: &str, level: i32, size_sectors: u64) -> Vec<u8> {
    let mut v = vec![0u8; 256 * 1024];
    let sb = 4096;
    v[sb..sb + 4].copy_from_slice(&MD_MAGIC.to_le_bytes());
    v[sb + 4..sb + 8].copy_from_slice(&1u32.to_le_bytes()); // major version
    v[sb + 0x10..sb + 0x20].copy_from_slice(uuid); // set_uuid
    let nb = name.as_bytes();
    v[sb + 0x20..sb + 0x20 + nb.len()].copy_from_slice(nb); // set_name
    v[sb + 0x48..sb + 0x4C].copy_from_slice(&level.to_le_bytes()); // level
    v[sb + 0x50..sb + 0x58].copy_from_slice(&size_sectors.to_le_bytes()); // size
    v
}

/// Wrap `payload` in a single-partition MBR starting at LBA 1.
fn mbr_with_partition(payload: &[u8]) -> Vec<u8> {
    let mut img = vec![0u8; SECTOR + payload.len()];
    img[SECTOR..SECTOR + payload.len()].copy_from_slice(payload);
    let e = 446;
    img[e + 4] = 0xFD; // type 0xFD = Linux RAID autodetect (informational)
    img[e + 8..e + 12].copy_from_slice(&1u32.to_le_bytes()); // start LBA
    img[e + 12..e + 16].copy_from_slice(&((payload.len() / SECTOR) as u32).to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;
    img
}

#[test]
fn detect_reports_a_raid_member() {
    let uuid = [
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f,
        0x90,
    ];
    let img = mbr_with_partition(&md_member(&uuid, "nas:0", 6, 256));

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("md.img");
    std::fs::write(&path, &img).unwrap();
    let src = Source::open(&path).unwrap();

    let vols = recover::detect(&src).unwrap();
    assert_eq!(vols.len(), 1, "should find one RAID member");
    let v = &vols[0];
    assert_eq!(v.fs_label(), "Linux RAID6");
    assert_eq!(v.offset(), SECTOR as u64);
    assert_eq!(v.size(), 256 * 512);
    assert_eq!(v.volume_label().as_deref(), Some("nas:0"));
    assert_eq!(
        v.volume_uuid().as_deref(),
        Some("a1b2c3d4:e5f60718:293a4b5c:6d7e8f90")
    );
}
