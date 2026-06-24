//! Carving test for DjVu documents. A DjVu file is built byte-exactly
//! ("AT&T" + IFF "FORM" + big-endian length + form type + content), embedded in
//! a synthetic image, and recovered byte-for-byte.

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

/// A single-page DjVu: "AT&T" + "FORM" + be32 length + "DJVU" + content. The
/// FORM length covers the form type plus the content.
fn make_djvu(content: &[u8]) -> Vec<u8> {
    let mut v = b"AT&TFORM".to_vec();
    let length = (4 + content.len()) as u32; // "DJVU" + content
    v.extend_from_slice(&length.to_be_bytes());
    v.extend_from_slice(b"DJVU");
    v.extend_from_slice(content);
    v
}

#[test]
fn recovers_a_djvu_document() {
    let djvu = make_djvu(&filler(1, 3000));

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 600)).unwrap();
    img.write_all(&djvu).unwrap();
    img.write_all(&filler(11, 600)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["djvu".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "one djvu document");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0], djvu,
        "recovered bytes must match the original"
    );
    assert_eq!(stats.per_type.get("djvu"), Some(&1));
}
