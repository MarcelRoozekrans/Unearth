//! Verify ext4 journal (jbd2) recovery: a deleted file whose **live** inode has
//! its extent tree zeroed is recovered from an older copy of the inode-table
//! block preserved in the journal.

use filerecovery::ext4;
use filerecovery::recover::RecoverOptions;
use filerecovery::source::Source;

const BS: usize = 1024;
const INODE_SIZE: usize = 128;
const INODES_PER_GROUP: u32 = 32;
const TOTAL_BLOCKS: usize = 64;

const ITAB: usize = 5; // inode table starts at block 5 (blocks 5..9)
const ROOT_DIR: usize = 9;
const JOURNAL_START: usize = 16; // journal occupies blocks 16..24
const DATA_BLOCK: usize = 30; // the deleted file's data
const INODE_TABLE_BLOCK_OF_11: u64 = 6; // fs block holding inode 11

fn inode_offset(ino: u32) -> usize {
    ITAB * BS + (ino as usize - 1) * INODE_SIZE
}

/// Build a 128-byte inode. With `block = Some((start, len))` it gets a single
/// extent mapping `len` blocks from `start`; with `None` the block map is left
/// zeroed (as after deletion).
fn inode(
    mode: u16,
    links: u16,
    dtime: u32,
    size: u32,
    block: Option<(u32, u16)>,
) -> [u8; INODE_SIZE] {
    let mut n = [0u8; INODE_SIZE];
    n[0..2].copy_from_slice(&mode.to_le_bytes());
    n[4..8].copy_from_slice(&size.to_le_bytes());
    n[0x14..0x18].copy_from_slice(&dtime.to_le_bytes());
    n[0x1A..0x1C].copy_from_slice(&links.to_le_bytes());
    n[0x20..0x24].copy_from_slice(&0x0008_0000u32.to_le_bytes()); // EXTENTS_FL
    if let Some((start, len)) = block {
        let ib = 0x28;
        n[ib..ib + 2].copy_from_slice(&0xF30Au16.to_le_bytes());
        n[ib + 2..ib + 4].copy_from_slice(&1u16.to_le_bytes()); // entries
        n[ib + 4..ib + 6].copy_from_slice(&4u16.to_le_bytes()); // max
        n[ib + 16..ib + 18].copy_from_slice(&len.to_le_bytes()); // extent length
        n[ib + 20..ib + 24].copy_from_slice(&start.to_le_bytes()); // start lo
    }
    n
}

fn put_inode(img: &mut [u8], ino: u32, bytes: &[u8; INODE_SIZE]) {
    let o = inode_offset(ino);
    img[o..o + INODE_SIZE].copy_from_slice(bytes);
}

fn wd(img: &mut [u8], block: usize, off: usize, ino: u32, rec_len: u16, name: &str, ft: u8) {
    let p = block * BS + off;
    img[p..p + 4].copy_from_slice(&ino.to_le_bytes());
    img[p + 4..p + 6].copy_from_slice(&rec_len.to_le_bytes());
    img[p + 6] = name.len() as u8;
    img[p + 7] = ft;
    img[p + 8..p + 8 + name.len()].copy_from_slice(name.as_bytes());
}

fn be32(img: &mut [u8], at: usize, v: u32) {
    img[at..at + 4].copy_from_slice(&v.to_be_bytes());
}

#[test]
fn recovers_via_journal_when_live_inode_zeroed() {
    let mut img = vec![0u8; TOTAL_BLOCKS * BS];

    // Superblock.
    let sb = 1024;
    img[sb..sb + 4].copy_from_slice(&32u32.to_le_bytes()); // inodes_count
    img[sb + 4..sb + 8].copy_from_slice(&(TOTAL_BLOCKS as u32).to_le_bytes());
    img[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes()); // first_data_block
    img[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes()); // blocks_per_group
    img[sb + 0x28..sb + 0x2C].copy_from_slice(&INODES_PER_GROUP.to_le_bytes());
    img[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes()); // magic
    img[sb + 0x58..sb + 0x5A].copy_from_slice(&(INODE_SIZE as u16).to_le_bytes());
    img[sb + 0x60..sb + 0x64].copy_from_slice(&0x0002u32.to_le_bytes()); // FILETYPE
    img[sb + 0xE0..sb + 0xE4].copy_from_slice(&8u32.to_le_bytes()); // s_journal_inum

    // Group descriptor: inode table at block 5.
    img[2 * BS + 8..2 * BS + 12].copy_from_slice(&(ITAB as u32).to_le_bytes());

    let payload: Vec<u8> = (0..500u32).map(|i| (i % 251) as u8).collect();

    // Inodes (live table):
    // - root dir, live.
    put_inode(
        &mut img,
        2,
        &inode(0x41ED, 3, 0, BS as u32, Some((ROOT_DIR as u32, 1))),
    );
    // - journal (inode 8), live, mapping the 8 journal blocks.
    put_inode(
        &mut img,
        8,
        &inode(
            0x8180,
            1,
            0,
            (8 * BS) as u32,
            Some((JOURNAL_START as u32, 8)),
        ),
    );
    // - inode 11: DELETED with a zeroed block map (unrecoverable from the live
    //   inode alone).
    put_inode(
        &mut img,
        11,
        &inode(0x81A4, 0, 12345, payload.len() as u32, None),
    );

    // The file's data.
    img[DATA_BLOCK * BS..DATA_BLOCK * BS + payload.len()].copy_from_slice(&payload);

    // Root directory: ".", "..", and a stale entry for the deleted file.
    wd(&mut img, ROOT_DIR, 0, 2, 12, ".", 2);
    wd(&mut img, ROOT_DIR, 12, 2, (BS - 12) as u16, "..", 2);
    wd(&mut img, ROOT_DIR, 28, 11, 24, "secret.txt", 1);

    // --- Journal contents ---
    // Block 0 of the journal: jbd2 superblock.
    let js = JOURNAL_START * BS;
    be32(&mut img, js, 0xC03B_3998); // h_magic
    be32(&mut img, js + 4, 4); // h_blocktype = v2 superblock
    be32(&mut img, js + 0x0C, BS as u32); // s_blocksize
    be32(&mut img, js + 0x10, 8); // s_maxlen
    be32(&mut img, js + 0x14, 1); // s_first
    be32(&mut img, js + 0x28, 0); // s_feature_incompat (simplest tag format)

    // Block 1 of the journal: descriptor naming fs block 6 (inode-table block of
    // inode 11).
    let jd = (JOURNAL_START + 1) * BS;
    be32(&mut img, jd, 0xC03B_3998); // h_magic
    be32(&mut img, jd + 4, 1); // h_blocktype = descriptor
    be32(&mut img, jd + 8, 1); // h_sequence
    be32(&mut img, jd + 12, INODE_TABLE_BLOCK_OF_11 as u32); // tag t_blocknr
    img[jd + 16] = 0x00; // t_checksum (BE u16)
    img[jd + 17] = 0x00;
    img[jd + 18] = 0x00; // t_flags (BE u16) = LAST_TAG (0x0008)
    img[jd + 19] = 0x08;
    // A 16-byte UUID follows (left zeroed).

    // Block 2 of the journal: an older copy of fs block 6, where inode 11 still
    // has an intact extent map. Within block 6, inode 11 sits at offset 256.
    let jdata = (JOURNAL_START + 2) * BS;
    let good = inode(
        0x81A4,
        1,
        0,
        payload.len() as u32,
        Some((DATA_BLOCK as u32, 1)),
    );
    img[jdata + 256..jdata + 256 + INODE_SIZE].copy_from_slice(&good);

    // Run recovery.
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    std::fs::write(&img_path, &img).unwrap();
    let out_dir = tmp.path().join("out");

    let source = Source::open(&img_path).unwrap();
    let vol = ext4::Volume::parse(&source, 0).unwrap();

    // Sanity: the live inode really is unrecoverable on its own.
    let live_only = vol
        .recover_deleted(
            &source,
            &tmp.path().join("none"),
            &RecoverOptions {
                min_size: 0,
                dry_run: true,
            },
        )
        .unwrap();
    // (Dry run still counts it because journal recovery supplies the inode.)
    assert_eq!(live_only.recovered, 1);

    let stats = vol
        .recover_deleted(&source, &out_dir, &RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 1, "should recover via the journal");
    assert_eq!(
        std::fs::read(out_dir.join("secret.txt")).unwrap(),
        payload,
        "journal-recovered contents must match"
    );
}
