//! Shared image builders for integration tests.
//!
//! These hand-craft minimal but valid on-disk structures so tests don't depend
//! on `mkfs`/`mtools` being installed.

#![allow(dead_code)] // each test binary uses a different subset

/// A minimal JPEG (header + payload + `FF D9` footer) for carving tests.
pub fn jpeg(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
    v.extend_from_slice(payload);
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

// --- ext4 ---------------------------------------------------------------

const EXT_BS: usize = 1024;
const EXT_ISIZE: usize = 128;
const EXT_ITAB: usize = 5;
const EXT_ROOT_DIR: usize = 9;
const EXT_DATA: usize = 11;
const EXT_BLOCKS: usize = 32;

fn ext_inode(v: &mut [u8], ino: u32, mode: u16, links: u16, dtime: u32, size: u32, block: u32) {
    let o = EXT_ITAB * EXT_BS + (ino as usize - 1) * EXT_ISIZE;
    v[o..o + 2].copy_from_slice(&mode.to_le_bytes());
    v[o + 4..o + 8].copy_from_slice(&size.to_le_bytes());
    v[o + 0x14..o + 0x18].copy_from_slice(&dtime.to_le_bytes());
    v[o + 0x1A..o + 0x1C].copy_from_slice(&links.to_le_bytes());
    v[o + 0x20..o + 0x24].copy_from_slice(&0x0008_0000u32.to_le_bytes()); // EXTENTS_FL
    let ib = o + 0x28;
    v[ib..ib + 2].copy_from_slice(&0xF30Au16.to_le_bytes());
    v[ib + 2..ib + 4].copy_from_slice(&1u16.to_le_bytes());
    v[ib + 4..ib + 6].copy_from_slice(&4u16.to_le_bytes());
    v[ib + 16..ib + 18].copy_from_slice(&1u16.to_le_bytes());
    v[ib + 20..ib + 24].copy_from_slice(&block.to_le_bytes());
}

fn ext_dirent(v: &mut [u8], block: usize, off: usize, ino: u32, rec_len: u16, name: &str, ft: u8) {
    let p = block * EXT_BS + off;
    v[p..p + 4].copy_from_slice(&ino.to_le_bytes());
    v[p + 4..p + 6].copy_from_slice(&rec_len.to_le_bytes());
    v[p + 6] = name.len() as u8;
    v[p + 7] = ft;
    v[p + 8..p + 8 + name.len()].copy_from_slice(name.as_bytes());
}

/// A bare ext4 volume (no partition table) with one deleted regular file named
/// `name` holding `payload`, reachable as a stale entry in the root directory.
pub fn ext_volume(name: &str, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; EXT_BLOCKS * EXT_BS];
    let sb = 1024;
    v[sb..sb + 4].copy_from_slice(&32u32.to_le_bytes());
    v[sb + 4..sb + 8].copy_from_slice(&(EXT_BLOCKS as u32).to_le_bytes());
    v[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes());
    v[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes());
    v[sb + 0x28..sb + 0x2C].copy_from_slice(&32u32.to_le_bytes());
    v[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    v[sb + 0x58..sb + 0x5A].copy_from_slice(&(EXT_ISIZE as u16).to_le_bytes());
    v[sb + 0x60..sb + 0x64].copy_from_slice(&0x0002u32.to_le_bytes());
    v[2 * EXT_BS + 8..2 * EXT_BS + 12].copy_from_slice(&(EXT_ITAB as u32).to_le_bytes());

    ext_inode(&mut v, 2, 0x41ED, 3, 0, EXT_BS as u32, EXT_ROOT_DIR as u32);
    ext_inode(
        &mut v,
        11,
        0x81A4,
        0,
        12345,
        payload.len() as u32,
        EXT_DATA as u32,
    );
    v[EXT_DATA * EXT_BS..EXT_DATA * EXT_BS + payload.len()].copy_from_slice(payload);

    ext_dirent(&mut v, EXT_ROOT_DIR, 0, 2, 12, ".", 2);
    ext_dirent(&mut v, EXT_ROOT_DIR, 12, 2, (EXT_BS - 12) as u16, "..", 2);
    ext_dirent(&mut v, EXT_ROOT_DIR, 28, 11, 24, name, 1);
    v
}

// --- HFS+ ---------------------------------------------------------------

const HFS_BS: usize = 512;
const HFS_CATALOG_BLOCK: usize = 8; // catalog file starts here (2 nodes)
const HFS_NODE_SIZE: usize = 512;
const HFS_DATA_BLOCK: usize = 12; // file data starts here

fn put_be16(v: &mut [u8], o: usize, x: u16) {
    v[o..o + 2].copy_from_slice(&x.to_be_bytes());
}
fn put_be32(v: &mut [u8], o: usize, x: u32) {
    v[o..o + 4].copy_from_slice(&x.to_be_bytes());
}
fn put_be64(v: &mut [u8], o: usize, x: u64) {
    v[o..o + 8].copy_from_slice(&x.to_be_bytes());
}

/// A bare HFS+ volume (no partition table) with one deleted regular file named
/// `name` holding `payload`, left as a stale record in a catalog leaf node's
/// free space — the situation this backend recovers from.
pub fn hfsplus_volume(name: &str, payload: &[u8]) -> Vec<u8> {
    let name16: Vec<u16> = name.encode_utf16().collect();
    let name_len = name16.len();
    let block_count = payload.len().div_ceil(HFS_BS).max(1);
    let total_blocks = HFS_DATA_BLOCK + block_count + 2;
    let mut v = vec![0u8; total_blocks * HFS_BS];

    // Volume header at offset 1024.
    let vh = 1024;
    put_be16(&mut v, vh, 0x482B); // "H+"
    put_be16(&mut v, vh + 2, 4); // version
    put_be32(&mut v, vh + 40, HFS_BS as u32); // allocation block size
    put_be32(&mut v, vh + 44, total_blocks as u32);
    // Catalog file fork: logicalSize, totalBlocks, then first extent.
    put_be64(&mut v, vh + 272, (2 * HFS_NODE_SIZE) as u64); // two nodes
    put_be32(&mut v, vh + 284, 2);
    put_be32(&mut v, vh + 288, HFS_CATALOG_BLOCK as u32); // extent start block
    put_be32(&mut v, vh + 292, 2); // extent block count

    // Catalog node 0 (header node): the parser only needs the node size.
    let n0 = HFS_CATALOG_BLOCK * HFS_BS;
    v[n0 + 8] = 1; // kind = header node
    put_be16(&mut v, n0 + 32, HFS_NODE_SIZE as u16); // BTHeaderRec.nodeSize

    // Catalog node 1 (leaf node) with no live records; the deleted file record
    // sits in its free space, starting right after the node descriptor.
    let n1 = n0 + HFS_NODE_SIZE;
    v[n1 + 8] = 0xFF; // kind = leaf node (-1)
    put_be16(&mut v, n1 + 10, 0); // numRecords = 0
    put_be16(&mut v, n1 + HFS_NODE_SIZE - 2, 14); // offset[0] -> free space at 14

    // The stale file record at node offset 14.
    let key = n1 + 14;
    let key_len = 6 + 2 * name_len;
    put_be16(&mut v, key, key_len as u16);
    put_be32(&mut v, key + 2, 2); // parentID = root folder
    put_be16(&mut v, key + 6, name_len as u16);
    for (i, &u) in name16.iter().enumerate() {
        put_be16(&mut v, key + 8 + i * 2, u);
    }
    let rec = key + 2 + key_len; // record data follows the key
    put_be16(&mut v, rec, 0x0002); // recordType = file
    put_be32(&mut v, rec + 8, 16); // fileID (CNID)
    put_be32(&mut v, rec + 16, 2_082_844_800 + 1_000_000); // contentModDate
    put_be64(&mut v, rec + 88, payload.len() as u64); // data fork logical size
    put_be32(&mut v, rec + 104, HFS_DATA_BLOCK as u32); // extent start block
    put_be32(&mut v, rec + 108, block_count as u32); // extent block count

    // File data.
    let data_off = HFS_DATA_BLOCK * HFS_BS;
    v[data_off..data_off + payload.len()].copy_from_slice(payload);
    v
}

// --- FAT32 --------------------------------------------------------------

/// A bare FAT32 volume with a cluster-chained root directory containing one
/// deleted file (8.3 short entry). Large enough (>= 65525 clusters) to be
/// classified as FAT32.
pub fn fat32_volume(name8: &[u8; 8], ext3: &[u8; 3], payload: &[u8]) -> Vec<u8> {
    const BPS: usize = 512;
    const RESERVED: usize = 32;
    const FAT_SECTORS: usize = 512;
    const DATA_CLUSTERS: usize = 65530; // > 65524 => FAT32
    const TOTAL: usize = RESERVED + FAT_SECTORS + DATA_CLUSTERS;
    let first_data = RESERVED + FAT_SECTORS; // spc = 1
    let root_cluster = 2usize;
    let file_cluster = 3usize;

    let mut v = vec![0u8; TOTAL * BPS];
    v[0] = 0xEB;
    v[11..13].copy_from_slice(&(BPS as u16).to_le_bytes());
    v[13] = 1; // sectors per cluster
    v[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    v[16] = 1; // num FATs
    v[17..19].copy_from_slice(&0u16.to_le_bytes()); // root entry count (0 for FAT32)
    v[22..24].copy_from_slice(&0u16.to_le_bytes()); // FAT size 16
    v[32..36].copy_from_slice(&(TOTAL as u32).to_le_bytes()); // total sectors 32
    v[36..40].copy_from_slice(&(FAT_SECTORS as u32).to_le_bytes()); // FAT size 32
    v[44..48].copy_from_slice(&(root_cluster as u32).to_le_bytes()); // root cluster
    v[510] = 0x55;
    v[511] = 0xAA;

    // FAT: mark the root directory cluster as end-of-chain.
    let fat_base = RESERVED * BPS;
    v[fat_base + root_cluster * 4..fat_base + root_cluster * 4 + 4]
        .copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());

    // File data.
    let data_off = (first_data + (file_cluster - 2)) * BPS;
    v[data_off..data_off + payload.len()].copy_from_slice(payload);

    // Deleted short directory entry in the root cluster.
    let root_off = (first_data + (root_cluster - 2)) * BPS;
    let e = root_off;
    v[e..e + 8].copy_from_slice(name8);
    v[e + 8..e + 11].copy_from_slice(ext3);
    v[e] = 0xE5; // deletion marker
    v[e + 20..e + 22].copy_from_slice(&0u16.to_le_bytes()); // cluster high
    v[e + 26..e + 28].copy_from_slice(&(file_cluster as u16).to_le_bytes()); // cluster low
    v[e + 28..e + 32].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    v
}

// --- GPT wrapper --------------------------------------------------------

/// Wrap a volume image in a GPT disk using the given logical `sector_size`
/// (512 or 4096), placing the volume at `part_lba`.
pub fn gpt_disk(volume: &[u8], sector_size: usize, part_lba: usize) -> Vec<u8> {
    let part_off = part_lba * sector_size;
    let mut disk = vec![0u8; part_off + volume.len()];
    // Protective MBR signature.
    disk[510] = 0x55;
    disk[511] = 0xAA;
    // GPT header at LBA 1.
    let h = sector_size;
    disk[h..h + 8].copy_from_slice(b"EFI PART");
    disk[h + 72..h + 80].copy_from_slice(&2u64.to_le_bytes()); // entry array LBA
    disk[h + 80..h + 84].copy_from_slice(&4u32.to_le_bytes()); // entry count
    disk[h + 84..h + 88].copy_from_slice(&128u32.to_le_bytes()); // entry size
                                                                 // One partition entry at LBA 2.
    let e = 2 * sector_size;
    disk[e..e + 16].copy_from_slice(&[0x11; 16]); // non-zero type GUID
    disk[e + 32..e + 40].copy_from_slice(&(part_lba as u64).to_le_bytes());
    disk[part_off..part_off + volume.len()].copy_from_slice(volume);
    disk
}
