//! Carving tests for the additional signatures: WAV, WEBP, SQLite, 7z, and
//! HEIC. Each is embedded (with a header-derived or atom-walked length) into a
//! synthetic image and recovered byte-for-byte.

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

fn make_riff(form: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut v = b"RIFF".to_vec();
    let chunk = (4 + data.len()) as u32; // "WAVE"/"WEBP" + payload
    v.extend_from_slice(&chunk.to_le_bytes());
    v.extend_from_slice(form);
    v.extend_from_slice(data);
    v
}

fn make_sqlite(page_size: u16, page_count: u32) -> Vec<u8> {
    let total = page_size as usize * page_count as usize;
    let mut v = vec![0u8; total];
    v[0..16].copy_from_slice(b"SQLite format 3\0");
    v[16..18].copy_from_slice(&page_size.to_be_bytes()); // big-endian
                                                         // Fixed header fields the validator checks (file format versions and the
                                                         // payload-fraction constants).
    v[18] = 1; // write version (legacy)
    v[19] = 1; // read version (legacy)
    v[21] = 64; // max embedded payload fraction
    v[22] = 32; // min embedded payload fraction
    v[23] = 32; // leaf payload fraction
    v[28..32].copy_from_slice(&page_count.to_be_bytes());
    // Fill the body so a byte-for-byte comparison is meaningful.
    for (i, b) in v.iter_mut().enumerate().skip(100) {
        *b = (i % 251) as u8;
    }
    v
}

fn make_7z(next_off: u64, next_size: u64) -> Vec<u8> {
    let total = 32 + next_off as usize + next_size as usize;
    let mut v = vec![0u8; total];
    v[0..6].copy_from_slice(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);
    v[12..20].copy_from_slice(&next_off.to_le_bytes());
    v[20..28].copy_from_slice(&next_size.to_le_bytes());
    for (i, b) in v.iter_mut().enumerate().skip(32) {
        *b = (i % 241) as u8;
    }
    v
}

fn make_heic(payload: &[u8]) -> Vec<u8> {
    // ftyp box (size 16): size + "ftyp" + "heic" + minor version.
    let mut v = Vec::new();
    v.extend_from_slice(&16u32.to_be_bytes());
    v.extend_from_slice(b"ftyp");
    v.extend_from_slice(b"heic");
    v.extend_from_slice(&0u32.to_be_bytes());
    // mdat box: size + "mdat" + payload.
    let mdat_size = (8 + payload.len()) as u32;
    v.extend_from_slice(&mdat_size.to_be_bytes());
    v.extend_from_slice(b"mdat");
    v.extend_from_slice(payload);
    v
}

#[test]
fn recovers_new_signature_types() {
    let wav = make_riff(b"WAVE", &filler(1, 2000));
    let webp = make_riff(b"WEBP", &filler(2, 1500));
    let sqlite = make_sqlite(512, 3);
    let sevenz = make_7z(120, 40);
    let heic = make_heic(&filler(3, 2500));

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 1000)).unwrap();
    img.write_all(&wav).unwrap();
    img.write_all(&filler(11, 300)).unwrap();
    img.write_all(&webp).unwrap();
    img.write_all(&filler(12, 300)).unwrap();
    img.write_all(&sqlite).unwrap();
    img.write_all(&filler(13, 300)).unwrap();
    img.write_all(&sevenz).unwrap();
    img.write_all(&filler(14, 300)).unwrap();
    img.write_all(&heic).unwrap();
    // Trailing noise so the HEIC atom walk stops at the end of mdat.
    img.write_all(&filler(15, 1000)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&[]).unwrap();
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
    };
    let stats = carver::carve(&source, &sigs, &opts, &NoProgress).unwrap();
    assert_eq!(stats.files_recovered, 5, "wav, webp, sqlite, 7z, heic");

    let mut recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    recovered.sort();

    let mut originals = vec![wav, webp, sqlite, sevenz, heic];
    originals.sort();

    assert_eq!(recovered, originals, "recovered bytes must match originals");

    // The per-type counts should cover each new extension exactly once.
    for ext in ["wav", "webp", "sqlite", "7z", "heic"] {
        assert_eq!(stats.per_type.get(ext), Some(&1), "missing {ext}");
    }
}
