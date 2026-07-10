//! Regression test for ZIP carving with a ZIP nested inside it (e.g. a JAR or
//! asset bundle stored in a ZIP). The inner archive has its own
//! End-of-Central-Directory record, which appears before the outer one. A naive
//! "stop at the first EOCD" carver truncates the outer archive there; the
//! geometry-validating carver picks the EOCD that actually describes the outer
//! archive and recovers the whole thing.

use std::io::Write;

use unearth::carver::{self, CarveOptions, NoProgress};
use unearth::signatures;
use unearth::source::Source;

/// Wrap `payload` in a ZIP with a self-consistent End-of-Central-Directory
/// record (central directory of size 0 located at the EOCD offset, so
/// `cd_offset + cd_size == eocd_offset`).
fn mkzip(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x50, 0x4B, 0x03, 0x04]; // local file header signature
    v.extend_from_slice(payload);
    let eocd_off = v.len() as u32;
    v.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]); // EOCD signature
    let mut rem = [0u8; 18];
    rem[12..16].copy_from_slice(&eocd_off.to_le_bytes()); // cd offset; cd size = 0
    v.extend_from_slice(&rem);
    v
}

#[test]
fn carves_past_a_nested_zips_eocd() {
    let inner = mkzip(&[0x41; 200]);
    let outer = mkzip(&inner); // the outer archive "stores" the inner ZIP
                               // Sanity: the inner EOCD really does appear before the outer's end.
    assert!(outer.len() > inner.len() + 22);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&[0x00; 600]).unwrap();
    img.write_all(&outer).unwrap();
    img.write_all(&[0x00; 600]).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["zip".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "one (outer) zip");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0], outer,
        "must recover the whole outer archive, not truncate at the nested EOCD"
    );
}

#[test]
fn includes_the_eocd_comment() {
    // A ZIP whose EOCD carries a comment: the comment must be included, not
    // dropped (which would leave the EOCD claiming bytes that aren't there).
    let mut v = vec![0x50, 0x4B, 0x03, 0x04];
    v.extend_from_slice(&[0x42; 100]);
    let eocd_off = v.len() as u32;
    v.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]);
    let comment = b"packed by test";
    let mut rem = [0u8; 18];
    rem[12..16].copy_from_slice(&eocd_off.to_le_bytes()); // cd offset; cd size = 0
    rem[16..18].copy_from_slice(&(comment.len() as u16).to_le_bytes()); // comment length
    v.extend_from_slice(&rem);
    v.extend_from_slice(comment);
    let zip = v;

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&[0x00; 300]).unwrap();
    img.write_all(&zip).unwrap();
    img.write_all(&[0x00; 300]).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["zip".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1);

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered[0], zip, "the EOCD comment must be included");
}
