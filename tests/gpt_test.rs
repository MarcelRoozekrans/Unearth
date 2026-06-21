//! Verify GPT partition tables are auto-detected: build a disk with a protective
//! MBR, a GPT header + entry array, and an ext4 volume inside one partition,
//! then confirm `recover::detect` finds and recovers from it.

use filerecovery::recover;
use filerecovery::source::Source;

const SS: usize = 512; // logical sector size

// ext4 geometry (block size 1024), built as a standalone volume image.
const BS: usize = 1024;
const INODE_SIZE: usize = 128;
const ITAB: usize = 5;
const ROOT: usize = 9;
const DATA: usize = 11;
const EXT_BLOCKS: usize = 32;

fn ino_off(i: u32) -> usize {
    ITAB * BS + (i as usize - 1) * INODE_SIZE
}

fn winode(v: &mut [u8], i: u32, mode: u16, links: u16, dtime: u32, size: u32, block: u32) {
    let mut n = [0u8; INODE_SIZE];
    n[0..2].copy_from_slice(&mode.to_le_bytes());
    n[4..8].copy_from_slice(&size.to_le_bytes());
    n[0x14..0x18].copy_from_slice(&dtime.to_le_bytes());
    n[0x1A..0x1C].copy_from_slice(&links.to_le_bytes());
    n[0x20..0x24].copy_from_slice(&0x0008_0000u32.to_le_bytes());
    let ib = 0x28;
    n[ib..ib + 2].copy_from_slice(&0xF30Au16.to_le_bytes());
    n[ib + 2..ib + 4].copy_from_slice(&1u16.to_le_bytes());
    n[ib + 4..ib + 6].copy_from_slice(&4u16.to_le_bytes());
    n[ib + 16..ib + 18].copy_from_slice(&1u16.to_le_bytes());
    n[ib + 20..ib + 24].copy_from_slice(&block.to_le_bytes());
    let o = ino_off(i);
    v[o..o + INODE_SIZE].copy_from_slice(&n);
}

fn wd(v: &mut [u8], block: usize, off: usize, ino: u32, rec_len: u16, name: &str, ft: u8) {
    let p = block * BS + off;
    v[p..p + 4].copy_from_slice(&ino.to_le_bytes());
    v[p + 4..p + 6].copy_from_slice(&rec_len.to_le_bytes());
    v[p + 6] = name.len() as u8;
    v[p + 7] = ft;
    v[p + 8..p + 8 + name.len()].copy_from_slice(name.as_bytes());
}

/// Build a standalone ext4 volume image containing one deleted file.
fn build_ext_volume(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; EXT_BLOCKS * BS];
    let sb = 1024;
    v[sb..sb + 4].copy_from_slice(&32u32.to_le_bytes());
    v[sb + 4..sb + 8].copy_from_slice(&(EXT_BLOCKS as u32).to_le_bytes());
    v[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes());
    v[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes());
    v[sb + 0x28..sb + 0x2C].copy_from_slice(&32u32.to_le_bytes());
    v[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    v[sb + 0x58..sb + 0x5A].copy_from_slice(&(INODE_SIZE as u16).to_le_bytes());
    v[sb + 0x60..sb + 0x64].copy_from_slice(&0x0002u32.to_le_bytes());
    v[2 * BS + 8..2 * BS + 12].copy_from_slice(&(ITAB as u32).to_le_bytes());

    winode(&mut v, 2, 0x41ED, 3, 0, BS as u32, ROOT as u32);
    winode(
        &mut v,
        11,
        0x81A4,
        0,
        12345,
        payload.len() as u32,
        DATA as u32,
    );
    v[DATA * BS..DATA * BS + payload.len()].copy_from_slice(payload);
    wd(&mut v, ROOT, 0, 2, 12, ".", 2);
    wd(&mut v, ROOT, 12, 2, (BS - 12) as u16, "..", 2);
    wd(&mut v, ROOT, 28, 11, 24, "gpt_recovered.bin", 1);
    v
}

#[test]
fn detects_and_recovers_from_gpt() {
    let part_lba = 34usize; // partition starts at LBA 34 (typical)
    let part_offset = part_lba * SS;
    let ext = build_ext_volume(b"recovered from a GPT partition");

    let mut disk = vec![0u8; part_offset + ext.len()];

    // Protective MBR signature (not required for detection, but realistic).
    disk[510] = 0x55;
    disk[511] = 0xAA;

    // GPT header at LBA 1.
    let h = SS;
    disk[h..h + 8].copy_from_slice(b"EFI PART");
    disk[h + 72..h + 80].copy_from_slice(&2u64.to_le_bytes()); // entry array at LBA 2
    disk[h + 80..h + 84].copy_from_slice(&4u32.to_le_bytes()); // 4 entries
    disk[h + 84..h + 88].copy_from_slice(&128u32.to_le_bytes()); // 128 bytes/entry

    // One partition entry at LBA 2.
    let e = 2 * SS;
    disk[e..e + 16].copy_from_slice(&[0x11; 16]); // non-zero type GUID
    disk[e + 32..e + 40].copy_from_slice(&(part_lba as u64).to_le_bytes()); // starting LBA

    // The ext4 volume itself.
    disk[part_offset..part_offset + ext.len()].copy_from_slice(&ext);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    std::fs::write(&img_path, &disk).unwrap();
    let out_dir = tmp.path().join("out");

    let source = Source::open(&img_path).unwrap();
    let volumes = recover::detect(&source).unwrap();
    assert_eq!(volumes.len(), 1, "GPT partition should be detected");
    assert_eq!(volumes[0].fs_label(), "ext2/3/4");
    assert_eq!(volumes[0].offset(), part_offset as u64);

    let stats = volumes[0]
        .recover_deleted(&source, &out_dir, &recover::RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 1);
    assert_eq!(
        std::fs::read(out_dir.join("gpt_recovered.bin")).unwrap(),
        b"recovered from a GPT partition"
    );
}
