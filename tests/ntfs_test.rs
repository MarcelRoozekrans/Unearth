//! Integration test: build a minimal NTFS volume (boot sector + a small MFT)
//! by hand, mark file records as deleted, and verify recovery restores names,
//! folder paths, and contents — for resident, non-resident, and nested files.

use filerecovery::ntfs;
use filerecovery::recover;
use filerecovery::source::Source;

const BPS: usize = 512;
const SPC: usize = 1;
const CLUSTER: usize = BPS * SPC;
const RECORD: usize = 1024; // 2 sectors per MFT record

const MFT_CLUSTER: usize = 4; // MFT starts at cluster 4
const MFT_RECORDS: usize = 16; // 16 records => 32 clusters
const TOTAL_CLUSTERS: usize = 64;

fn mft_byte(record: usize) -> usize {
    MFT_CLUSTER * CLUSTER + record * RECORD
}

fn cluster_byte(cluster: usize) -> usize {
    cluster * CLUSTER
}

fn write_boot(img: &mut [u8]) {
    img[0] = 0xEB;
    img[1] = 0x52;
    img[2] = 0x90;
    img[3..11].copy_from_slice(b"NTFS    ");
    img[11..13].copy_from_slice(&(BPS as u16).to_le_bytes());
    img[13] = SPC as u8;
    img[40..48].copy_from_slice(&(TOTAL_CLUSTERS as u64).to_le_bytes()); // total sectors (spc=1)
    img[48..56].copy_from_slice(&(MFT_CLUSTER as u64).to_le_bytes()); // $MFT cluster
    img[64] = (-10i8) as u8; // clusters-per-record => 2^10 = 1024 bytes
    img[510] = 0x55;
    img[511] = 0xAA;
}

/// Pad an attribute to a multiple of 8 bytes.
fn pad8(mut a: Vec<u8>) -> Vec<u8> {
    while a.len() % 8 != 0 {
        a.push(0);
    }
    a
}

/// Build a resident `$FILE_NAME` (0x30) attribute.
fn filename_attr(name: &str, parent_record: u64, namespace: u8) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let mut content = vec![0u8; 0x42 + units.len() * 2];
    content[0..8].copy_from_slice(&parent_record.to_le_bytes()); // parent ref (seq 0)
    content[0x40] = units.len() as u8;
    content[0x41] = namespace;
    for (i, &u) in units.iter().enumerate() {
        content[0x42 + i * 2..0x42 + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
    }

    let mut attr = vec![0u8; 24];
    attr[0..4].copy_from_slice(&0x30u32.to_le_bytes());
    attr[8] = 0; // resident
    attr[10..12].copy_from_slice(&24u16.to_le_bytes()); // name offset
    attr[16..20].copy_from_slice(&(content.len() as u32).to_le_bytes()); // content length
    attr[20..22].copy_from_slice(&24u16.to_le_bytes()); // content offset
    attr.extend_from_slice(&content);
    let attr = pad8(attr);
    let len = attr.len() as u32;
    let mut attr = attr;
    attr[4..8].copy_from_slice(&len.to_le_bytes());
    attr
}

/// Build a resident `$DATA` (0x80) attribute holding `content` inline.
fn data_resident(content: &[u8]) -> Vec<u8> {
    let mut attr = vec![0u8; 24];
    attr[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    attr[8] = 0; // resident
    attr[10..12].copy_from_slice(&24u16.to_le_bytes());
    attr[16..20].copy_from_slice(&(content.len() as u32).to_le_bytes());
    attr[20..22].copy_from_slice(&24u16.to_le_bytes());
    attr.extend_from_slice(content);
    let attr = pad8(attr);
    let len = attr.len() as u32;
    let mut attr = attr;
    attr[4..8].copy_from_slice(&len.to_le_bytes());
    attr
}

/// Build a non-resident `$DATA` (0x80) attribute with the given run list bytes.
fn data_nonresident(real_size: u64, runs: &[u8]) -> Vec<u8> {
    let run_offset = 64usize;
    let mut attr = vec![0u8; run_offset];
    attr[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    attr[8] = 1; // non-resident
    attr[32..34].copy_from_slice(&(run_offset as u16).to_le_bytes()); // data run offset
    attr[40..48].copy_from_slice(&real_size.to_le_bytes()); // allocated size
    attr[48..56].copy_from_slice(&real_size.to_le_bytes()); // real size
    attr[56..64].copy_from_slice(&real_size.to_le_bytes()); // initialized size
    attr.extend_from_slice(runs);
    let attr = pad8(attr);
    let len = attr.len() as u32;
    let mut attr = attr;
    attr[4..8].copy_from_slice(&len.to_le_bytes());
    attr
}

/// Assemble a 1024-byte MFT record from a flags value and attributes.
fn build_record(flags: u16, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut rec = vec![0u8; RECORD];
    rec[0..4].copy_from_slice(b"FILE");
    rec[4..6].copy_from_slice(&48u16.to_le_bytes()); // USA offset
    rec[6..8].copy_from_slice(&3u16.to_le_bytes()); // USA count (1 + 2 sectors)
    rec[16..18].copy_from_slice(&1u16.to_le_bytes()); // sequence number
    rec[18..20].copy_from_slice(&1u16.to_le_bytes()); // hard link count
    rec[20..22].copy_from_slice(&56u16.to_le_bytes()); // first attribute offset
    rec[22..24].copy_from_slice(&flags.to_le_bytes());
    rec[28..32].copy_from_slice(&(RECORD as u32).to_le_bytes()); // allocated size
                                                                 // USA values: check value + two zeroed sector tails.
    rec[48..50].copy_from_slice(&1u16.to_le_bytes());

    let mut off = 56;
    for a in attrs {
        rec[off..off + a.len()].copy_from_slice(a);
        off += a.len();
    }
    rec[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // end marker
    rec[28..32].copy_from_slice(&((off + 8) as u32).to_le_bytes()); // used size
    rec
}

const FLAG_IN_USE: u16 = 0x01;
const FLAG_DIR: u16 = 0x02;

#[test]
fn recovers_deleted_ntfs_files() {
    let mut img = vec![0u8; TOTAL_CLUSTERS * CLUSTER];
    write_boot(&mut img);

    // Record 0: $MFT, in use, non-resident $DATA describing the MFT extent
    // (32 clusters starting at LCN 4).
    let mft_runs = [0x11u8, MFT_RECORDS as u8 * 2, MFT_CLUSTER as u8, 0x00];
    let rec0 = build_record(
        FLAG_IN_USE,
        &[data_nonresident((MFT_RECORDS * RECORD) as u64, &mft_runs)],
    );
    let o = mft_byte(0);
    img[o..o + RECORD].copy_from_slice(&rec0);

    // Record 6: deleted file "report.txt" in root, resident data.
    let report = b"hello from a deleted NTFS file\n";
    let rec6 = build_record(
        0, // deleted (in-use bit clear)
        &[filename_attr("report.txt", 5, 1), data_resident(report)],
    );
    let o = mft_byte(6);
    img[o..o + RECORD].copy_from_slice(&rec6);

    // Record 7: deleted file "photo.jpg" in root, non-resident data at cluster
    // 36 (2 clusters), 700 bytes.
    let payload: Vec<u8> = (0..700u32).map(|i| (i % 251) as u8).collect();
    let file_lcn = 36usize;
    let d = cluster_byte(file_lcn);
    img[d..d + payload.len()].copy_from_slice(&payload);
    let runs = [0x11u8, 0x02, file_lcn as u8, 0x00];
    let rec7 = build_record(
        0,
        &[
            filename_attr("photo.jpg", 5, 1),
            data_nonresident(payload.len() as u64, &runs),
        ],
    );
    let o = mft_byte(7);
    img[o..o + RECORD].copy_from_slice(&rec7);

    // Record 8: live directory "Docs" in root.
    let rec8 = build_record(FLAG_IN_USE | FLAG_DIR, &[filename_attr("Docs", 5, 1)]);
    let o = mft_byte(8);
    img[o..o + RECORD].copy_from_slice(&rec8);

    // Record 9: deleted file "notes.txt" inside "Docs" (parent = record 8).
    let notes = b"nested note contents";
    let rec9 = build_record(0, &[filename_attr("notes.txt", 8, 1), data_resident(notes)]);
    let o = mft_byte(9);
    img[o..o + RECORD].copy_from_slice(&rec9);

    // Write the image and run recovery.
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    std::fs::write(&img_path, &img).unwrap();
    let out_dir = tmp.path().join("out");

    let source = Source::open(&img_path).unwrap();

    let volumes = recover::detect(&source).unwrap();
    assert_eq!(volumes.len(), 1);
    assert_eq!(volumes[0].fs_label(), "NTFS");

    let vol = ntfs::Volume::parse(&source, 0).unwrap();
    let stats = vol.recover_deleted(&source, &out_dir, 0).unwrap();
    assert_eq!(stats.recovered, 3, "report.txt, photo.jpg, Docs/notes.txt");

    assert_eq!(std::fs::read(out_dir.join("report.txt")).unwrap(), report);
    assert_eq!(std::fs::read(out_dir.join("photo.jpg")).unwrap(), payload);
    assert_eq!(
        std::fs::read(out_dir.join("Docs").join("notes.txt")).unwrap(),
        notes
    );
}
