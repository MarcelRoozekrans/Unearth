//! Carving test for raw JPEG 2000 codestreams (`.j2k`/`.j2c`/`.jpc`). A
//! codestream (SOC + SIZ markers, body, EOC marker) is built byte-exactly,
//! embedded in a synthetic image, and recovered byte-for-byte.

use std::io::Write;

use filerecovery::carver::{self, CarveOptions, NoProgress};
use filerecovery::signatures;
use filerecovery::source::Source;

/// A minimal J2K codestream: SOC (FF4F) + SIZ (FF51) + body + EOC (FFD9). The
/// body uses constant 0x41 bytes so it carries no stray FF marker.
fn make_j2k() -> Vec<u8> {
    let mut v = vec![0xFF, 0x4F, 0xFF, 0x51]; // SOC + SIZ
    v.extend_from_slice(&[0x41; 300]); // SIZ segment + packet data (stand-in)
    v.extend_from_slice(&[0xFF, 0xD9]); // EOC
    v
}

#[test]
fn recovers_a_j2k_codestream() {
    let j2k = make_j2k();

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&[0x00; 500]).unwrap();
    img.write_all(&j2k).unwrap();
    img.write_all(&[0x00; 500]).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["j2k".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "one j2k codestream");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], j2k, "recovered bytes must match the original");
    assert_eq!(stats.per_type.get("j2k"), Some(&1));
}
