//! Heap-allocation profiling harness (dotMemory-style) for the recovery
//! engines.
//!
//! Build/run with the profiler enabled:
//!
//! ```sh
//! cargo run --profile profiling --features dhat-heap --example heap_profile
//! ```
//!
//! On exit it prints allocation totals/peaks to stderr and writes
//! `dhat-heap.json`, which you can open in the dhat viewer
//! (https://nnethercote.github.io/dh_view/dh_view.html) to drill into the
//! allocation call sites — the Rust analogue of a dotMemory snapshot.
//!
//! Without the feature it just runs the workload (handy as a smoke test).

use std::time::Instant;

use filerecovery::carver::{self, CarveOptions, NoProgress};
use filerecovery::recover::{self, RecoverOptions};
use filerecovery::signatures;
use filerecovery::source::Source;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// A JPEG: SOI + payload + EOI.
fn jpeg(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
    v.extend_from_slice(payload);
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

fn filler(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// Build an image full of many small carveable files, the case that stresses
/// per-file allocation the most.
fn build_carve_image(count: usize, file_bytes: usize) -> Vec<u8> {
    let mut img = Vec::with_capacity(count * (file_bytes + 4096));
    for i in 0..count {
        img.extend_from_slice(&filler(i as u64 * 7 + 1, 512));
        img.extend_from_slice(&jpeg(&filler(i as u64 * 13 + 3, file_bytes)));
    }
    img.extend_from_slice(&filler(0xDEAD, 512));
    img
}

fn main() {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("carve.img");
    let out_dir = tmp.path().join("out");

    // ~12 MiB of small (~60 KiB) JPEGs.
    let count = 200;
    let img = build_carve_image(count, 60 * 1024);
    std::fs::write(&img_path, &img).unwrap();

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&[]).unwrap();
    let opts = CarveOptions {
        output_dir: out_dir.clone(),
        start: 0,
        end: None,
        min_size: 0,
        max_files: None,
        allow_nested: false,
        progress: false,
    };

    let t = Instant::now();
    let stats = carver::carve(&source, &sigs, &opts, &NoProgress).unwrap();
    let carve_ms = t.elapsed().as_secs_f64() * 1000.0;
    eprintln!(
        "carve: {} files, {} bytes, {:.1} ms ({:.0} MiB/s)",
        stats.files_recovered,
        stats.bytes_recovered,
        carve_ms,
        (img.len() as f64 / (1024.0 * 1024.0)) / (carve_ms / 1000.0)
    );

    // An ext volume with one large (multi-block) deleted file: stresses the
    // per-block read path during recovery.
    let ext = build_ext_volume(2048); // 2048 blocks => ~2 MiB file
    let ext_path = tmp.path().join("ext.img");
    std::fs::write(&ext_path, &ext).unwrap();
    let esrc = Source::open(&ext_path).unwrap();
    let t = Instant::now();
    if let Ok(vols) = recover::detect(&esrc) {
        for v in &vols {
            let s = v
                .recover_deleted(&esrc, &tmp.path().join("eout"), &RecoverOptions::default())
                .unwrap();
            eprintln!(
                "undelete (ext): {} file(s), {} bytes in {:.1} ms",
                s.recovered,
                s.bytes_recovered,
                t.elapsed().as_secs_f64() * 1000.0
            );
        }
    }

    // NTFS undelete over a multi-record MFT: stresses the per-record read path.
    let ntfs = build_ntfs_volume(90);
    let ntfs_path = tmp.path().join("ntfs.img");
    std::fs::write(&ntfs_path, &ntfs).unwrap();
    let nsrc = Source::open(&ntfs_path).unwrap();
    let t = Instant::now();
    if let Ok(vols) = recover::detect(&nsrc) {
        for v in &vols {
            let s = v
                .recover_deleted(&nsrc, &tmp.path().join("nout"), &RecoverOptions::default())
                .unwrap();
            eprintln!(
                "undelete (ntfs): {} file(s) in {:.1} ms",
                s.recovered,
                t.elapsed().as_secs_f64() * 1000.0
            );
        }
    }
}

// --- ext4 volume with one large deleted file -----------------------------

fn build_ext_volume(file_blocks: usize) -> Vec<u8> {
    const BS: usize = 1024;
    const ISIZE: usize = 128;
    const ITAB: usize = 5;
    const ROOT: usize = 9;
    const DATA: usize = 16;
    let total_blocks = DATA + file_blocks + 4;
    let size = (file_blocks * BS) as u32;
    let mut v = vec![0u8; total_blocks * BS];
    let sb = 1024;
    let inodes_count = 32u32;
    v[sb..sb + 4].copy_from_slice(&inodes_count.to_le_bytes());
    v[sb + 4..sb + 8].copy_from_slice(&(total_blocks as u32).to_le_bytes());
    v[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes());
    v[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes());
    v[sb + 0x28..sb + 0x2C].copy_from_slice(&32u32.to_le_bytes());
    v[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    v[sb + 0x58..sb + 0x5A].copy_from_slice(&(ISIZE as u16).to_le_bytes());
    v[sb + 0x60..sb + 0x64].copy_from_slice(&0x0002u32.to_le_bytes());
    v[2 * BS + 8..2 * BS + 12].copy_from_slice(&(ITAB as u32).to_le_bytes());
    let mut inode =
        |ino: u32, mode: u16, links: u16, dtime: u32, size: u32, block: u32, len: u16| {
            let o = ITAB * BS + (ino as usize - 1) * ISIZE;
            v[o..o + 2].copy_from_slice(&mode.to_le_bytes());
            v[o + 4..o + 8].copy_from_slice(&size.to_le_bytes());
            v[o + 0x14..o + 0x18].copy_from_slice(&dtime.to_le_bytes());
            v[o + 0x1A..o + 0x1C].copy_from_slice(&links.to_le_bytes());
            v[o + 0x20..o + 0x24].copy_from_slice(&0x0008_0000u32.to_le_bytes());
            let ib = o + 0x28;
            v[ib..ib + 2].copy_from_slice(&0xF30Au16.to_le_bytes());
            v[ib + 2..ib + 4].copy_from_slice(&1u16.to_le_bytes());
            v[ib + 4..ib + 6].copy_from_slice(&4u16.to_le_bytes());
            v[ib + 16..ib + 18].copy_from_slice(&len.to_le_bytes());
            v[ib + 20..ib + 24].copy_from_slice(&block.to_le_bytes());
        };
    inode(2, 0x41ED, 3, 0, BS as u32, ROOT as u32, 1);
    inode(11, 0x81A4, 0, 12345, size, DATA as u32, file_blocks as u16);
    let mut de = |off: usize, ino: u32, rl: u16, name: &str, ft: u8| {
        let p = ROOT * BS + off;
        v[p..p + 4].copy_from_slice(&ino.to_le_bytes());
        v[p + 4..p + 6].copy_from_slice(&rl.to_le_bytes());
        v[p + 6] = name.len() as u8;
        v[p + 7] = ft;
        v[p + 8..p + 8 + name.len()].copy_from_slice(name.as_bytes());
    };
    de(0, 2, 12, ".", 2);
    de(12, 2, (BS - 12) as u16, "..", 2);
    de(28, 11, 24, "recovered.bin", 1);
    v
}

// --- minimal NTFS volume with many deleted files -------------------------

fn build_ntfs_volume(deleted_files: usize) -> Vec<u8> {
    const BPS: usize = 512;
    const CLUSTER: usize = 512; // spc = 1
    const RECORD: usize = 1024; // 2 sectors per record
    const MFT_CLUSTER: usize = 4;
    let mft_records = deleted_files + 32;
    let total_clusters = MFT_CLUSTER + mft_records * (RECORD / CLUSTER) + 16;

    let mut img = vec![0u8; total_clusters * CLUSTER];
    // Boot sector.
    img[3..11].copy_from_slice(b"NTFS    ");
    img[11..13].copy_from_slice(&(BPS as u16).to_le_bytes());
    img[13] = 1;
    img[40..48].copy_from_slice(&(total_clusters as u64).to_le_bytes());
    img[48..56].copy_from_slice(&(MFT_CLUSTER as u64).to_le_bytes());
    img[64] = (-10i8) as u8; // 1024-byte records
    img[510] = 0x55;
    img[511] = 0xAA;

    let mft_byte = |rec: usize| MFT_CLUSTER * CLUSTER + rec * RECORD;

    let pad8 = |mut a: Vec<u8>| {
        while a.len() % 8 != 0 {
            a.push(0);
        }
        a
    };
    let filename_attr = |name: &str, parent: u64| {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut content = vec![0u8; 0x42 + units.len() * 2];
        content[0..8].copy_from_slice(&parent.to_le_bytes());
        content[0x40] = units.len() as u8;
        content[0x41] = 1;
        for (i, &u) in units.iter().enumerate() {
            content[0x42 + i * 2..0x42 + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        let mut attr = vec![0u8; 24];
        attr[0..4].copy_from_slice(&0x30u32.to_le_bytes());
        attr[10..12].copy_from_slice(&24u16.to_le_bytes());
        attr[16..20].copy_from_slice(&(content.len() as u32).to_le_bytes());
        attr[20..22].copy_from_slice(&24u16.to_le_bytes());
        attr.extend_from_slice(&content);
        let mut attr = pad8(attr);
        let len = attr.len() as u32;
        attr[4..8].copy_from_slice(&len.to_le_bytes());
        attr
    };
    let data_resident = |content: &[u8]| {
        let mut attr = vec![0u8; 24];
        attr[0..4].copy_from_slice(&0x80u32.to_le_bytes());
        attr[10..12].copy_from_slice(&24u16.to_le_bytes());
        attr[16..20].copy_from_slice(&(content.len() as u32).to_le_bytes());
        attr[20..22].copy_from_slice(&24u16.to_le_bytes());
        attr.extend_from_slice(content);
        let mut attr = pad8(attr);
        let len = attr.len() as u32;
        attr[4..8].copy_from_slice(&len.to_le_bytes());
        attr
    };
    let data_nonresident = |real_size: u64, runs: &[u8]| {
        let mut attr = vec![0u8; 64];
        attr[0..4].copy_from_slice(&0x80u32.to_le_bytes());
        attr[8] = 1;
        attr[32..34].copy_from_slice(&64u16.to_le_bytes());
        attr[48..56].copy_from_slice(&real_size.to_le_bytes());
        attr.extend_from_slice(runs);
        let mut attr = pad8(attr);
        let len = attr.len() as u32;
        attr[4..8].copy_from_slice(&len.to_le_bytes());
        attr
    };
    let record = |flags: u16, attrs: &[Vec<u8>]| {
        let mut rec = vec![0u8; RECORD];
        rec[0..4].copy_from_slice(b"FILE");
        rec[4..6].copy_from_slice(&48u16.to_le_bytes());
        rec[6..8].copy_from_slice(&3u16.to_le_bytes());
        rec[20..22].copy_from_slice(&56u16.to_le_bytes());
        rec[22..24].copy_from_slice(&flags.to_le_bytes());
        let mut off = 56;
        for a in attrs {
            rec[off..off + a.len()].copy_from_slice(a);
            off += a.len();
        }
        rec[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        rec
    };

    // Record 0: $MFT with a non-resident $DATA describing the whole MFT.
    let mft_run = [
        0x11u8,
        (mft_records * (RECORD / CLUSTER)) as u8,
        MFT_CLUSTER as u8,
        0x00,
    ];
    let rec0 = record(
        0x01,
        &[data_nonresident((mft_records * RECORD) as u64, &mft_run)],
    );
    let o = mft_byte(0);
    img[o..o + RECORD].copy_from_slice(&rec0);

    // Many deleted files with small resident data.
    for i in 0..deleted_files {
        let rec_no = 24 + i;
        let name = format!("file{i:04}.txt");
        let content = format!("deleted file number {i}").into_bytes();
        let rec = record(0, &[filename_attr(&name, 5), data_resident(&content)]);
        let o = mft_byte(rec_no);
        img[o..o + RECORD].copy_from_slice(&rec);
    }
    img
}
