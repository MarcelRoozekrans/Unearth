//! Statistical micro-benchmarks (the Rust analogue of BenchmarkDotNet) for the
//! hot paths: SHA-256 hashing, signature carving, content identification, and
//! filesystem undelete. Run with:
//!
//! ```sh
//! cargo bench
//! ```
//!
//! Criterion warms up, takes many samples, and reports mean/median/std-dev with
//! outlier detection; throughput-annotated benchmarks also print MiB/s. This is
//! console-only (no plotting dependencies) to keep the dev footprint light; the
//! companion `examples/heap_profile.rs` (dhat) covers allocation/memory, the
//! way dotMemory complements dotnet-benchmark.

use std::io::Write;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};

use filerecovery::carver::{self, CarveOptions, NoProgress};
use filerecovery::recover::{self, RecoverOptions};
use filerecovery::source::Source;
use filerecovery::{hash, identify, signatures};

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

fn jpeg(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
    v.extend_from_slice(payload);
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

/// An image full of many small JPEGs separated by noise — the carver's
/// worst case for per-file overhead.
fn build_carve_image(count: usize, file_bytes: usize) -> Vec<u8> {
    let mut img = Vec::with_capacity(count * (file_bytes + 1024));
    for i in 0..count {
        img.extend_from_slice(&filler(i as u64 * 7 + 1, 512));
        img.extend_from_slice(&jpeg(&filler(i as u64 * 13 + 3, file_bytes)));
    }
    img
}

/// A bare ext4 volume with one deleted file holding `payload`.
fn ext_volume(name: &str, payload: &[u8]) -> Vec<u8> {
    const BS: usize = 1024;
    const ISIZE: usize = 128;
    const ITAB: usize = 5;
    const ROOT: usize = 9;
    const DATA: usize = 11;
    const BLOCKS: usize = 64;
    let mut v = vec![0u8; BLOCKS * BS];
    let sb = 1024;
    v[sb..sb + 4].copy_from_slice(&64u32.to_le_bytes());
    v[sb + 4..sb + 8].copy_from_slice(&(BLOCKS as u32).to_le_bytes());
    v[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes());
    v[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes());
    v[sb + 0x28..sb + 0x2C].copy_from_slice(&64u32.to_le_bytes());
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
        v[ib + 4..ib + 6].copy_from_slice(&1u16.to_le_bytes());
        v[ib + 16..ib + 18].copy_from_slice(&1u16.to_le_bytes());
        v[ib + 20..ib + 24].copy_from_slice(&block.to_le_bytes());
    };
    inode(2, 0x41ED, 3, 0, BS as u32, ROOT as u32);
    inode(11, 0x81A4, 0, 12345, payload.len() as u32, DATA as u32);
    v[DATA * BS..DATA * BS + payload.len()].copy_from_slice(payload);

    let mut dirent = |off: usize, ino: u32, rl: u16, name: &str, ft: u8| {
        let p = ROOT * BS + off;
        v[p..p + 4].copy_from_slice(&ino.to_le_bytes());
        v[p + 4..p + 6].copy_from_slice(&rl.to_le_bytes());
        v[p + 6] = name.len() as u8;
        v[p + 7] = ft;
        v[p + 8..p + 8 + name.len()].copy_from_slice(name.as_bytes());
    };
    dirent(0, 2, 12, ".", 2);
    dirent(12, 2, (BS - 12) as u16, "..", 2);
    dirent(28, 11, 24, name, 1);
    v
}

fn bench_hash(c: &mut Criterion) {
    let data = filler(99, 1 << 20); // 1 MiB
    let mut g = c.benchmark_group("hash");
    g.throughput(Throughput::Bytes(data.len() as u64));
    g.bench_function("sha256_1MiB", |b| b.iter(|| hash::digest(black_box(&data))));
    g.finish();
}

fn bench_identify(c: &mut Criterion) {
    let head = jpeg(&filler(1, 4096));
    let mut g = c.benchmark_group("identify");
    g.bench_function("jpeg", |b| b.iter(|| identify::identify(black_box(&head))));
    g.finish();
}

fn bench_carve(c: &mut Criterion) {
    let img = build_carve_image(200, 16 * 1024); // ~3.3 MiB of small JPEGs
    let tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.as_file().write_all(&img).unwrap();
    let source = Source::open(tmp.path()).unwrap();
    let sigs = signatures::select(&[]).unwrap();

    let mut g = c.benchmark_group("carve");
    g.throughput(Throughput::Bytes(img.len() as u64));
    g.bench_function("all_signatures", |b| {
        b.iter_batched(
            || tempfile::tempdir().unwrap(),
            |out| {
                let opts = CarveOptions {
                    output_dir: out.path().to_path_buf(),
                    start: 0,
                    end: None,
                    min_size: 0,
                    max_files: None,
                    allow_nested: false,
                    validate: true,
                    dedup: false,
                    progress: false,
                    checkpoint: None,
                    resume: false,
                    organize: false,
                    dry_run: false,
                };
                carver::carve(&source, &sigs, &opts, &NoProgress).unwrap()
            },
            BatchSize::SmallInput,
        );
    });
    g.finish();
}

fn bench_undelete(c: &mut Criterion) {
    let payload = filler(5, 32 * 1024);
    let vol = ext_volume("recovered.bin", &payload);
    let tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.as_file().write_all(&vol).unwrap();
    let source = Source::open(tmp.path()).unwrap();

    let mut g = c.benchmark_group("undelete");
    g.bench_function("ext_one_file", |b| {
        b.iter_batched(
            || tempfile::tempdir().unwrap(),
            |out| {
                let opts = RecoverOptions {
                    min_size: 0,
                    dry_run: false,
                };
                let volumes = recover::detect(&source).unwrap();
                for v in &volumes {
                    v.recover_deleted(&source, out.path(), &opts).unwrap();
                }
            },
            BatchSize::SmallInput,
        );
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_hash,
    bench_identify,
    bench_carve,
    bench_undelete
);
criterion_main!(benches);
