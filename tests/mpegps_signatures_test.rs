//! Carving test for MPEG program streams. A pack header, a few PES packets, and
//! the program-end code are assembled, embedded in a synthetic image, and
//! recovered byte-for-byte.

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

/// A 14-byte MPEG-2 pack header (`00 00 01 BA`, MPEG-2 discriminator, no pack
/// stuffing).
fn pack_header() -> Vec<u8> {
    let mut v = vec![0x00, 0x00, 0x01, 0xBA];
    v.push(0x44); // top two bits 01 => MPEG-2
    v.extend_from_slice(&[0u8; 9]); // SCR/mux-rate + stuffing-length byte = 0
    v
}

/// A PES packet (`00 00 01 E0`) carrying `payload`.
fn pes(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x00, 0x00, 0x01, 0xE0];
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn make_mpg() -> Vec<u8> {
    let mut v = pack_header();
    for i in 0..4 {
        v.extend_from_slice(&pes(&filler(i + 1, 20)));
    }
    v.extend_from_slice(&[0x00, 0x00, 0x01, 0xB9]); // program end code
    v
}

#[test]
fn recovers_an_mpeg_program_stream() {
    let mpg = make_mpg();

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 700)).unwrap();
    img.write_all(&mpg).unwrap();
    img.write_all(&filler(11, 700)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["mpg".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "one program stream");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], mpg, "recovered bytes must match the original");
    assert_eq!(stats.per_type.get("mpg"), Some(&1));
}
