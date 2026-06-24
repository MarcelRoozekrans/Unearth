//! Carving test for Windows Event Logs (EVTX). A file is built byte-exactly
//! (4096-byte `ElfFile` header recording the chunk count + 64 KiB chunks),
//! embedded in a synthetic image, and recovered byte-for-byte.

use std::io::Write;

use filerecovery::carver::{self, CarveOptions, NoProgress};
use filerecovery::signatures;
use filerecovery::source::Source;

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

/// An EVTX file: a 4096-byte header (magic, header size 0x80, block size
/// 0x1000, `chunks` chunk count) followed by `chunks` 64 KiB chunks.
fn make_evtx(chunks: u16) -> Vec<u8> {
    let mut v = vec![0u8; 4096];
    v[0..8].copy_from_slice(b"ElfFile\x00");
    v[0x20..0x24].copy_from_slice(&0x80u32.to_le_bytes()); // header size
    v[0x28..0x2A].copy_from_slice(&0x1000u16.to_le_bytes()); // header block size
    v[0x2A..0x2C].copy_from_slice(&chunks.to_le_bytes()); // number of chunks
    for c in 0..chunks {
        v.extend_from_slice(&filler(c as u64 + 1, 65536));
    }
    v
}

#[test]
fn recovers_a_windows_event_log() {
    let evtx = make_evtx(2);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 700)).unwrap();
    img.write_all(&evtx).unwrap();
    img.write_all(&filler(11, 700)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["evtx".to_string()]).unwrap();
    let opts = CarveOptions {
        output_dir: out_dir.clone(),
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
    };
    let stats = carver::carve(&source, &sigs, &opts, &NoProgress).unwrap();
    assert_eq!(stats.files_recovered, 1, "one event log");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0], evtx,
        "recovered bytes must match the original"
    );
    assert_eq!(stats.per_type.get("evtx"), Some(&1));
}
