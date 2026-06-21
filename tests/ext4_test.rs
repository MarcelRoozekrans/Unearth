//! Integration test: build a minimal ext4-style volume by hand (superblock,
//! one block group, inode table with extent-based inodes, and directory blocks
//! containing stale/deleted entries in their slack), then verify recovery
//! restores names, paths, and contents.

use filerecovery::ext4;
use filerecovery::recover;
use filerecovery::source::Source;

const BS: usize = 1024; // block size
const INODE_SIZE: usize = 128;
const INODES_PER_GROUP: u32 = 32;
const TOTAL_BLOCKS: usize = 32;

// Block layout.
const GDT_BLOCK: usize = 2;
const INODE_TABLE_BLOCK: usize = 5;
const ROOT_DIR_BLOCK: usize = 9;
const LOGS_DIR_BLOCK: usize = 10;
const PHOTO_BLOCK: usize = 11;
const APPLOG_BLOCK: usize = 12;

fn inode_offset(ino: u32) -> usize {
    INODE_TABLE_BLOCK * BS + (ino as usize - 1) * INODE_SIZE
}

fn write_superblock(img: &mut [u8]) {
    let sb = 1024; // superblock starts at byte 1024
    img[sb..sb + 4].copy_from_slice(&32u32.to_le_bytes()); // inodes_count
    img[sb + 4..sb + 8].copy_from_slice(&(TOTAL_BLOCKS as u32).to_le_bytes()); // blocks_count_lo
    img[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes()); // first_data_block
    img[sb + 0x18..sb + 0x1C].copy_from_slice(&0u32.to_le_bytes()); // log_block_size => 1024
    img[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes()); // blocks_per_group
    img[sb + 0x28..sb + 0x2C].copy_from_slice(&INODES_PER_GROUP.to_le_bytes()); // inodes_per_group
    img[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes()); // magic
    img[sb + 0x58..sb + 0x5A].copy_from_slice(&(INODE_SIZE as u16).to_le_bytes()); // inode_size
    img[sb + 0x60..sb + 0x64].copy_from_slice(&0x0002u32.to_le_bytes()); // incompat: FILETYPE
}

fn write_gdt(img: &mut [u8]) {
    let d = GDT_BLOCK * BS;
    img[d + 8..d + 12].copy_from_slice(&(INODE_TABLE_BLOCK as u32).to_le_bytes());
    // inode table
}

/// Build a 128-byte inode using a single extent that maps logical block 0 to
/// the given physical block.
fn write_inode(img: &mut [u8], ino: u32, mode: u16, links: u16, dtime: u32, size: u32, block: u32) {
    let o = inode_offset(ino);
    let mut n = [0u8; INODE_SIZE];
    n[0..2].copy_from_slice(&mode.to_le_bytes());
    n[4..8].copy_from_slice(&size.to_le_bytes());
    n[0x14..0x18].copy_from_slice(&dtime.to_le_bytes());
    n[0x1A..0x1C].copy_from_slice(&links.to_le_bytes());
    n[0x20..0x24].copy_from_slice(&0x0008_0000u32.to_le_bytes()); // EXTENTS_FL

    // Extent header + one leaf extent in i_block (offset 0x28).
    let ib = 0x28;
    n[ib..ib + 2].copy_from_slice(&0xF30Au16.to_le_bytes()); // magic
    n[ib + 2..ib + 4].copy_from_slice(&1u16.to_le_bytes()); // entries
    n[ib + 4..ib + 6].copy_from_slice(&4u16.to_le_bytes()); // max
    n[ib + 6..ib + 8].copy_from_slice(&0u16.to_le_bytes()); // depth (leaf)
    let ext = ib + 12;
    n[ext..ext + 4].copy_from_slice(&0u32.to_le_bytes()); // logical block 0
    n[ext + 4..ext + 6].copy_from_slice(&1u16.to_le_bytes()); // length 1
    n[ext + 6..ext + 8].copy_from_slice(&0u16.to_le_bytes()); // start hi
    n[ext + 8..ext + 12].copy_from_slice(&block.to_le_bytes()); // start lo

    img[o..o + INODE_SIZE].copy_from_slice(&n);
}

/// Write a directory entry (with FILETYPE) into `block` at `off`.
fn write_dirent(
    img: &mut [u8],
    block: usize,
    off: usize,
    ino: u32,
    rec_len: u16,
    name: &str,
    ftype: u8,
) {
    let p = block * BS + off;
    img[p..p + 4].copy_from_slice(&ino.to_le_bytes());
    img[p + 4..p + 6].copy_from_slice(&rec_len.to_le_bytes());
    img[p + 6] = name.len() as u8;
    img[p + 7] = ftype;
    img[p + 8..p + 8 + name.len()].copy_from_slice(name.as_bytes());
}

#[test]
fn recovers_deleted_ext4_files() {
    let mut img = vec![0u8; TOTAL_BLOCKS * BS];
    write_superblock(&mut img);
    write_gdt(&mut img);

    // Inodes.
    write_inode(&mut img, 2, 0x41ED, 3, 0, BS as u32, ROOT_DIR_BLOCK as u32); // root dir
    write_inode(&mut img, 13, 0x41ED, 2, 0, BS as u32, LOGS_DIR_BLOCK as u32); // logs dir (live)
    write_inode(&mut img, 12, 0x81A4, 1, 0, 0, 0); // readme (live regular, unused)

    let photo: Vec<u8> = (0..600u32).map(|i| (i % 251) as u8).collect();
    write_inode(
        &mut img,
        11,
        0x81A4,
        0,
        12345,
        photo.len() as u32,
        PHOTO_BLOCK as u32,
    ); // deleted
    img[PHOTO_BLOCK * BS..PHOTO_BLOCK * BS + photo.len()].copy_from_slice(&photo);

    let applog = b"deleted log line one\ndeleted log line two\n";
    write_inode(
        &mut img,
        14,
        0x81A4,
        0,
        12345,
        applog.len() as u32,
        APPLOG_BLOCK as u32,
    ); // deleted
    img[APPLOG_BLOCK * BS..APPLOG_BLOCK * BS + applog.len()].copy_from_slice(applog);

    // Root directory: ".", "..", live "logs", and (hidden in logs's slack) a
    // stale entry for the deleted "photo.raw".
    write_dirent(&mut img, ROOT_DIR_BLOCK, 0, 2, 12, ".", 2);
    write_dirent(&mut img, ROOT_DIR_BLOCK, 12, 2, 12, "..", 2);
    write_dirent(
        &mut img,
        ROOT_DIR_BLOCK,
        24,
        13,
        (BS - 24) as u16,
        "logs",
        2,
    );
    write_dirent(&mut img, ROOT_DIR_BLOCK, 40, 11, 24, "photo.raw", 1); // stale (deleted)

    // logs directory: ".", "..", live "readme", and a stale "app.log".
    write_dirent(&mut img, LOGS_DIR_BLOCK, 0, 13, 12, ".", 2);
    write_dirent(&mut img, LOGS_DIR_BLOCK, 12, 2, 12, "..", 2);
    write_dirent(
        &mut img,
        LOGS_DIR_BLOCK,
        24,
        12,
        (BS - 24) as u16,
        "readme",
        1,
    );
    write_dirent(&mut img, LOGS_DIR_BLOCK, 40, 14, 16, "app.log", 1); // stale (deleted)

    // Write the image and run recovery.
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    std::fs::write(&img_path, &img).unwrap();
    let out_dir = tmp.path().join("out");

    let source = Source::open(&img_path).unwrap();

    let volumes = recover::detect(&source).unwrap();
    assert_eq!(volumes.len(), 1);
    assert_eq!(volumes[0].fs_label(), "ext2/3/4");

    let vol = ext4::Volume::parse(&source, 0).unwrap();
    let stats = vol.recover_deleted(&source, &out_dir, 0).unwrap();
    assert_eq!(stats.recovered, 2, "photo.raw and logs/app.log");

    assert_eq!(std::fs::read(out_dir.join("photo.raw")).unwrap(), photo);
    assert_eq!(
        std::fs::read(out_dir.join("logs").join("app.log")).unwrap(),
        applog
    );
}
