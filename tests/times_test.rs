//! Verify that recovered files keep their original modification time.
//! Uses a minimal ext4 volume (Unix-second timestamps convert exactly).

use std::time::{Duration, UNIX_EPOCH};

use filerecovery::ext4;
use filerecovery::source::Source;

const BS: usize = 1024;
const INODE_SIZE: usize = 128;
const INODES_PER_GROUP: u32 = 32;
const TOTAL_BLOCKS: usize = 32;
const INODE_TABLE_BLOCK: usize = 5;
const ROOT_DIR_BLOCK: usize = 9;
const DATA_BLOCK: usize = 11;

const KNOWN_MTIME: u32 = 1_600_000_000; // 2020-09-13 UTC

fn inode_offset(ino: u32) -> usize {
    INODE_TABLE_BLOCK * BS + (ino as usize - 1) * INODE_SIZE
}

#[allow(clippy::too_many_arguments)]
fn write_inode(
    img: &mut [u8],
    ino: u32,
    mode: u16,
    links: u16,
    dtime: u32,
    mtime: u32,
    size: u32,
    block: u32,
) {
    let o = inode_offset(ino);
    let mut n = [0u8; INODE_SIZE];
    n[0..2].copy_from_slice(&mode.to_le_bytes());
    n[4..8].copy_from_slice(&size.to_le_bytes());
    n[0x08..0x0C].copy_from_slice(&mtime.to_le_bytes()); // atime (reuse mtime)
    n[0x10..0x14].copy_from_slice(&mtime.to_le_bytes()); // mtime
    n[0x14..0x18].copy_from_slice(&dtime.to_le_bytes());
    n[0x1A..0x1C].copy_from_slice(&links.to_le_bytes());
    n[0x20..0x24].copy_from_slice(&0x0008_0000u32.to_le_bytes()); // EXTENTS_FL
    let ib = 0x28;
    n[ib..ib + 2].copy_from_slice(&0xF30Au16.to_le_bytes());
    n[ib + 2..ib + 4].copy_from_slice(&1u16.to_le_bytes());
    n[ib + 4..ib + 6].copy_from_slice(&4u16.to_le_bytes());
    let ext = ib + 12;
    n[ext + 4..ext + 6].copy_from_slice(&1u16.to_le_bytes());
    n[ext + 8..ext + 12].copy_from_slice(&block.to_le_bytes());
    img[o..o + INODE_SIZE].copy_from_slice(&n);
}

fn write_dirent(
    img: &mut [u8],
    block: usize,
    off: usize,
    ino: u32,
    rec_len: u16,
    name: &str,
    ft: u8,
) {
    let p = block * BS + off;
    img[p..p + 4].copy_from_slice(&ino.to_le_bytes());
    img[p + 4..p + 6].copy_from_slice(&rec_len.to_le_bytes());
    img[p + 6] = name.len() as u8;
    img[p + 7] = ft;
    img[p + 8..p + 8 + name.len()].copy_from_slice(name.as_bytes());
}

#[test]
fn restores_modification_time() {
    let mut img = vec![0u8; TOTAL_BLOCKS * BS];
    let sb = 1024;
    img[sb..sb + 4].copy_from_slice(&32u32.to_le_bytes());
    img[sb + 4..sb + 8].copy_from_slice(&(TOTAL_BLOCKS as u32).to_le_bytes());
    img[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes());
    img[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes());
    img[sb + 0x28..sb + 0x2C].copy_from_slice(&INODES_PER_GROUP.to_le_bytes());
    img[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    img[sb + 0x58..sb + 0x5A].copy_from_slice(&(INODE_SIZE as u16).to_le_bytes());
    img[sb + 0x60..sb + 0x64].copy_from_slice(&0x0002u32.to_le_bytes());
    img[2 * BS + 8..2 * BS + 12].copy_from_slice(&(INODE_TABLE_BLOCK as u32).to_le_bytes());

    // Root dir (live) and a deleted file with a known mtime.
    write_inode(
        &mut img,
        2,
        0x41ED,
        3,
        0,
        0,
        BS as u32,
        ROOT_DIR_BLOCK as u32,
    );
    let payload = b"data with a known timestamp";
    write_inode(
        &mut img,
        11,
        0x81A4,
        0,
        12345,
        KNOWN_MTIME,
        payload.len() as u32,
        DATA_BLOCK as u32,
    );
    img[DATA_BLOCK * BS..DATA_BLOCK * BS + payload.len()].copy_from_slice(payload);

    write_dirent(&mut img, ROOT_DIR_BLOCK, 0, 2, 12, ".", 2);
    write_dirent(&mut img, ROOT_DIR_BLOCK, 12, 2, (BS - 12) as u16, "..", 2);
    write_dirent(&mut img, ROOT_DIR_BLOCK, 28, 11, 24, "dated.bin", 1); // stale (after "..")

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    std::fs::write(&img_path, &img).unwrap();
    let out_dir = tmp.path().join("out");

    let source = Source::open(&img_path).unwrap();
    let vol = ext4::Volume::parse(&source, 0).unwrap();
    let stats = vol
        .recover_deleted(
            &source,
            &out_dir,
            &filerecovery::recover::RecoverOptions::default(),
        )
        .unwrap();
    assert_eq!(stats.recovered, 1);

    let meta = std::fs::metadata(out_dir.join("dated.bin")).unwrap();
    let modified = meta.modified().unwrap();
    let expected = UNIX_EPOCH + Duration::from_secs(KNOWN_MTIME as u64);
    assert_eq!(modified, expected, "recovered file should keep its mtime");
}
