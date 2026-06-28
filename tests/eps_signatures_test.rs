//! Carving test for binary (DOS) EPS. A 30-byte header pointing at a PostScript
//! section is built, embedded in a synthetic image, and recovered byte-for-byte.

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

/// A binary EPS: 30-byte header + a PostScript section of `ps_len` bytes, no
/// WMF/TIFF previews.
fn eps(ps_len: u32) -> Vec<u8> {
    let ps_off: u32 = 30;
    let total = ps_off + ps_len;
    let mut v = vec![0u8; total as usize];
    v[0..4].copy_from_slice(&[0xC5, 0xD0, 0xD3, 0xC6]);
    v[4..8].copy_from_slice(&ps_off.to_le_bytes());
    v[8..12].copy_from_slice(&ps_len.to_le_bytes());
    // WMF (12/16) and TIFF (20/24) offsets/lengths stay zero (no previews).
    v[28..30].copy_from_slice(&0xFFFFu16.to_le_bytes()); // checksum unused
    let body = filler(5, ps_len as usize);
    v[ps_off as usize..].copy_from_slice(&body);
    v
}

#[test]
fn recovers_a_binary_eps() {
    let e = eps(300);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 512)).unwrap();
    img.write_all(&e).unwrap();
    img.write_all(&filler(11, 512)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["eps".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "one EPS");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], e, "recovered bytes must match the original");
    assert_eq!(stats.per_type.get("eps"), Some(&1));
}
