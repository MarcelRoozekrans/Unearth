//! Carving test for NES ROMs (iNES). A ROM is built byte-exactly (a 16-byte
//! header recording the PRG and CHR bank counts and a trainer flag, plus the
//! trainer, PRG, and CHR data), embedded in a synthetic image, and recovered
//! byte-for-byte.

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

/// An iNES ROM with `prg` 16 KiB PRG banks, `chr` 8 KiB CHR banks, and an
/// optional 512-byte trainer.
fn make_nes(prg: u8, chr: u8, trainer: bool) -> Vec<u8> {
    let mut v = vec![0u8; 16];
    v[0..4].copy_from_slice(b"NES\x1a");
    v[4] = prg;
    v[5] = chr;
    if trainer {
        v[6] |= 0x04; // trainer present
    }
    if trainer {
        v.extend_from_slice(&filler(2, 512));
    }
    v.extend_from_slice(&filler(3, prg as usize * 16384));
    v.extend_from_slice(&filler(4, chr as usize * 8192));
    v
}

#[test]
fn recovers_a_nes_rom() {
    let nes = make_nes(1, 1, true);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 700)).unwrap();
    img.write_all(&nes).unwrap();
    img.write_all(&filler(11, 700)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["nes".to_string()]).unwrap();
    let opts = CarveOptions {
        output_dir: out_dir.clone(),
        start: 0,
        end: None,
        min_size: 0,
        max_size: None,
        max_files: None,
        allow_nested: false,
        validate: true,
        dedup: false,
        progress: false,
        checkpoint: None,
        resume: false,
        organize: false,
        dry_run: false,
        align: 1,
    };
    let stats = carver::carve(&source, &sigs, &opts, &NoProgress).unwrap();
    assert_eq!(stats.files_recovered, 1, "one nes rom");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], nes, "recovered bytes must match the original");
    assert_eq!(stats.per_type.get("nes"), Some(&1));
}
