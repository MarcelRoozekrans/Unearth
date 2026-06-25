//! Regression test for GIF carving. GIF previously ended at the first `00 3B`
//! byte pair, which can occur by chance inside the LZW-compressed image data and
//! truncate the file. The block-walking carver follows the GIF structure to the
//! real trailer.

use std::io::Write;

use filerecovery::carver::{self, CarveOptions, NoProgress};
use filerecovery::signatures;
use filerecovery::source::Source;

/// A minimal GIF89a with one image whose data sub-blocks deliberately contain a
/// `00 3B` byte pair (which a naive footer carver would stop at).
fn gif_with_decoy() -> Vec<u8> {
    let mut v = b"GIF89a".to_vec();
    v.extend_from_slice(&4u16.to_le_bytes()); // width
    v.extend_from_slice(&4u16.to_le_bytes()); // height
    v.extend_from_slice(&[0, 0, 0]); // packed (no global colour table), bg, aspect
    v.push(0x2C); // image descriptor
    v.extend_from_slice(&[0u8; 8]); // position + size
    v.push(0); // packed (no local colour table)
    v.push(8); // LZW minimum code size
               // One sub-block whose bytes include a `00 3B` decoy pair.
    let data = [0x10, 0x00, 0x3B, 0x20, 0x00, 0x3B, 0x41, 0x42];
    v.push(data.len() as u8);
    v.extend_from_slice(&data);
    v.push(0x00); // block terminator
    v.push(0x3B); // real trailer
    v
}

#[test]
fn carves_to_the_real_gif_trailer() {
    let gif = gif_with_decoy();

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&[0x11; 400]).unwrap();
    img.write_all(&gif).unwrap();
    img.write_all(&[0x22; 400]).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["gif".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "one gif");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0], gif,
        "must walk to the real trailer, not stop at a 00 3B inside image data"
    );
}
