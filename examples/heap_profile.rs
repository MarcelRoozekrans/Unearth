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

    // A small ext volume undelete pass for the recovery path.
    let ext = build_ext_volume(b"profiled recovery payload, repeated a few times. ");
    let ext_path = tmp.path().join("ext.img");
    std::fs::write(&ext_path, &ext).unwrap();
    let esrc = Source::open(&ext_path).unwrap();
    if let Ok(vols) = recover::detect(&esrc) {
        for v in &vols {
            let s = v
                .recover_deleted(&esrc, &tmp.path().join("eout"), &RecoverOptions::default())
                .unwrap();
            eprintln!("undelete: {} file(s) from {}", s.recovered, v.fs_label());
        }
    }
}

// --- minimal ext4 volume with one deleted file ---------------------------

fn build_ext_volume(unit: &[u8]) -> Vec<u8> {
    const BS: usize = 1024;
    const ISIZE: usize = 128;
    const ITAB: usize = 5;
    const ROOT: usize = 9;
    const DATA: usize = 11;
    let payload: Vec<u8> = unit.iter().cycle().take(600).copied().collect();
    let mut v = vec![0u8; 32 * BS];
    let sb = 1024;
    v[sb..sb + 4].copy_from_slice(&32u32.to_le_bytes());
    v[sb + 4..sb + 8].copy_from_slice(&32u32.to_le_bytes());
    v[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes());
    v[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes());
    v[sb + 0x28..sb + 0x2C].copy_from_slice(&32u32.to_le_bytes());
    v[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    v[sb + 0x58..sb + 0x5A].copy_from_slice(&(ISIZE as u16).to_le_bytes());
    v[sb + 0x60..sb + 0x64].copy_from_slice(&0x0002u32.to_le_bytes());
    v[2 * BS + 8..2 * BS + 12].copy_from_slice(&(ITAB as u32).to_le_bytes());
    let mut inode = |ino: u32, mode: u16, links: u16, dtime: u32, size: u32, block: u32| {
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
        v[ib + 16..ib + 18].copy_from_slice(&1u16.to_le_bytes());
        v[ib + 20..ib + 24].copy_from_slice(&block.to_le_bytes());
    };
    inode(2, 0x41ED, 3, 0, BS as u32, ROOT as u32);
    inode(11, 0x81A4, 0, 12345, payload.len() as u32, DATA as u32);
    v[DATA * BS..DATA * BS + payload.len()].copy_from_slice(&payload);
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
