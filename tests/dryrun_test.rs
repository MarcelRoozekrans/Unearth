//! Verify `--dry-run` (RecoverOptions::dry_run): files are reported but not
//! written. Uses a minimal ext4 volume.

use filerecovery::ext4;
use filerecovery::recover::RecoverOptions;
use filerecovery::source::Source;

const BS: usize = 1024;
const INODE_SIZE: usize = 128;
const ITAB: usize = 5;
const ROOT: usize = 9;
const DATA: usize = 11;

fn ino_off(i: u32) -> usize {
    ITAB * BS + (i as usize - 1) * INODE_SIZE
}

fn winode(img: &mut [u8], i: u32, mode: u16, links: u16, dtime: u32, size: u32, block: u32) {
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
    n[ib + 16..ib + 18].copy_from_slice(&1u16.to_le_bytes()); // extent length
    n[ib + 20..ib + 24].copy_from_slice(&block.to_le_bytes()); // extent start lo
    let o = ino_off(i);
    img[o..o + INODE_SIZE].copy_from_slice(&n);
}

fn wd(img: &mut [u8], block: usize, off: usize, ino: u32, rec_len: u16, name: &str, ft: u8) {
    let p = block * BS + off;
    img[p..p + 4].copy_from_slice(&ino.to_le_bytes());
    img[p + 4..p + 6].copy_from_slice(&rec_len.to_le_bytes());
    img[p + 6] = name.len() as u8;
    img[p + 7] = ft;
    img[p + 8..p + 8 + name.len()].copy_from_slice(name.as_bytes());
}

#[test]
fn dry_run_reports_without_writing() {
    let mut img = vec![0u8; 32 * BS];
    let sb = 1024;
    img[sb..sb + 4].copy_from_slice(&32u32.to_le_bytes());
    img[sb + 4..sb + 8].copy_from_slice(&32u32.to_le_bytes());
    img[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes());
    img[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes());
    img[sb + 0x28..sb + 0x2C].copy_from_slice(&32u32.to_le_bytes());
    img[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    img[sb + 0x58..sb + 0x5A].copy_from_slice(&(INODE_SIZE as u16).to_le_bytes());
    img[sb + 0x60..sb + 0x64].copy_from_slice(&0x0002u32.to_le_bytes());
    img[2 * BS + 8..2 * BS + 12].copy_from_slice(&(ITAB as u32).to_le_bytes());

    winode(&mut img, 2, 0x41ED, 3, 0, BS as u32, ROOT as u32);
    let payload = b"will not be written in dry run";
    winode(
        &mut img,
        11,
        0x81A4,
        0,
        12345,
        payload.len() as u32,
        DATA as u32,
    );
    img[DATA * BS..DATA * BS + payload.len()].copy_from_slice(payload);
    wd(&mut img, ROOT, 0, 2, 12, ".", 2);
    wd(&mut img, ROOT, 12, 2, (BS - 12) as u16, "..", 2);
    wd(&mut img, ROOT, 28, 11, 24, "ghost.bin", 1);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    std::fs::write(&img_path, &img).unwrap();
    let out_dir = tmp.path().join("out");

    let source = Source::open(&img_path).unwrap();
    let vol = ext4::Volume::parse(&source, 0).unwrap();
    let opts = RecoverOptions {
        min_size: 0,
        max_size: None,
        modified_after: None,
        modified_before: None,
        names: Vec::new(),
        exclude_names: Vec::new(),
        dry_run: true,
    };
    let stats = vol.recover_deleted(&source, &out_dir, &opts).unwrap();

    // Reported as recoverable...
    assert_eq!(stats.recovered, 1);
    assert_eq!(stats.files.len(), 1);
    assert_eq!(stats.files[0].path.to_string_lossy(), "ghost.bin");
    assert!(stats.files[0].recovered);
    // ...but nothing actually written to disk.
    assert!(!out_dir.join("ghost.bin").exists());
}
