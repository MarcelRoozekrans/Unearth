//! Test that ZIP-based formats are recovered with their real extension: a ZIP
//! that carries the marker member of a DOCX / EPUB / … is written as `.docx` /
//! `.epub`, while a plain ZIP stays `.zip`.

use std::io::Write;

use unearth::carver::{self, CarveOptions, NoProgress};
use unearth::signatures;
use unearth::source::Source;

/// A geometry-valid ZIP (so the carver accepts it) whose body contains `marker`
/// — standing in for a member name like `word/document.xml`.
fn zip_with(marker: &[u8]) -> Vec<u8> {
    let mut v = vec![0x50, 0x4B, 0x03, 0x04]; // local file header signature
    v.extend_from_slice(marker);
    v.extend_from_slice(&[0x41; 40]);
    let eocd_off = v.len() as u32;
    v.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]); // EOCD signature
    let mut rem = [0u8; 18];
    rem[12..16].copy_from_slice(&eocd_off.to_le_bytes()); // cd offset; cd size = 0
    v.extend_from_slice(&rem);
    v
}

fn carve_one_ext(file: &[u8]) -> (String, std::collections::BTreeMap<String, u64>) {
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&[0x00; 300]).unwrap();
    img.write_all(file).unwrap();
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
    let name = std::fs::read_dir(&out_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name()
        .to_string_lossy()
        .into_owned();
    let per_type = stats
        .per_type
        .iter()
        .map(|(k, v)| (k.to_string(), *v))
        .collect();
    (name, per_type)
}

#[test]
fn zip_based_formats_get_their_real_extension() {
    for (marker, ext) in [
        (&b"word/document.xml"[..], "docx"),
        (&b"xl/workbook.xml"[..], "xlsx"),
        (&b"ppt/presentation.xml"[..], "pptx"),
        (&b"application/epub+zip"[..], "epub"),
        (&b"AndroidManifest.xml"[..], "apk"),
    ] {
        let (name, per_type) = carve_one_ext(&zip_with(marker));
        assert!(
            name.ends_with(&format!(".{ext}")),
            "marker {:?} -> name {name}, expected .{ext}",
            std::str::from_utf8(marker).unwrap()
        );
        assert_eq!(per_type.get(ext), Some(&1));
    }
}

#[test]
fn a_plain_zip_stays_zip() {
    let (name, per_type) = carve_one_ext(&zip_with(b"readme.txt"));
    assert!(name.ends_with(".zip"), "name {name}");
    assert_eq!(per_type.get("zip"), Some(&1));
}
