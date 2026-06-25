//! Regression test for JPEG carving with an embedded thumbnail. Camera/phone
//! JPEGs embed a full JPEG thumbnail (its own `FF D8 ... FF D9`) inside the EXIF
//! APP1 segment. A naive "stop at the first `FF D9`" carver truncates the file
//! at the thumbnail's EOI; the marker-aware carver tracks nested SOI/EOI markers
//! and recovers the whole image, up to the *outer* EOI.

use std::io::Write;

use filerecovery::carver::{self, CarveOptions, NoProgress};
use filerecovery::signatures;
use filerecovery::source::Source;

/// A JPEG with an embedded thumbnail. Bodies use constant 0x41 bytes (no stray
/// `FF`), so the only SOI/EOI markers are the ones placed here.
fn jpeg_with_thumbnail() -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0]; // SOI + APP0 marker
    v.extend_from_slice(&[0x41; 50]); // (stand-in) APP0/EXIF preamble
                                      // Embedded thumbnail: a complete nested JPEG.
    v.extend_from_slice(&[0xFF, 0xD8]); // thumbnail SOI
    v.extend_from_slice(&[0x41; 100]); // thumbnail body
    v.extend_from_slice(&[0xFF, 0xD9]); // thumbnail EOI  <- naive carver stops here
                                        // Main image scan data and the real end.
    v.extend_from_slice(&[0x41; 200]);
    v.extend_from_slice(&[0xFF, 0xD9]); // outer EOI
    v
}

#[test]
fn carves_past_an_embedded_thumbnail() {
    let jpeg = jpeg_with_thumbnail();

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&[0x00; 600]).unwrap();
    img.write_all(&jpeg).unwrap();
    img.write_all(&[0x00; 600]).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["jpg".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "one jpeg");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0], jpeg,
        "must recover the whole image, not truncate at the thumbnail's EOI"
    );
}
