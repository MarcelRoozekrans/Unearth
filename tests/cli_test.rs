//! End-to-end CLI tests: run the built `filerecovery` binary and check exit
//! codes, output, and side effects on the filesystem.

mod common;

use std::path::Path;
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_filerecovery")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("failed to run filerecovery")
}

#[test]
fn list_types_succeeds() {
    let out = run(&["list-types"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("jpg"));
    assert!(stdout.contains("sqlite"));
}

#[test]
fn unknown_type_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("x.img");
    std::fs::write(&img, vec![0u8; 1024]).unwrap();
    let out = run(&[
        "scan",
        img.to_str().unwrap(),
        "--type",
        "xyz",
        "-o",
        tmp.path().join("out").to_str().unwrap(),
    ]);
    assert!(!out.status.success(), "unknown type should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown file type"), "stderr: {stderr}");
}

#[test]
fn missing_source_fails() {
    let out = run(&["scan", "/no/such/path.img", "-o", "/tmp/whatever"]);
    assert!(!out.status.success());
}

#[test]
fn image_copies_a_source_exactly() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("disk.img");
    let out_img = tmp.path().join("copy.img");
    let summary = tmp.path().join("summary.json");

    let data: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&src, &data).unwrap();

    let out = run(&[
        "image",
        src.to_str().unwrap(),
        out_img.to_str().unwrap(),
        "--no-sparse",
        "--quiet",
        "--summary",
        summary.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "image should succeed on a good source"
    );
    assert_eq!(std::fs::read(&out_img).unwrap(), data);

    let report = std::fs::read_to_string(&summary).unwrap();
    assert!(report.contains("\"command\": \"image\""));
    assert!(report.contains("\"bad_regions\": 0"));
}

#[test]
fn image_writes_a_map_and_resume_completes() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("disk.img");
    let out_img = tmp.path().join("copy.img");
    let map = tmp.path().join("copy.map");

    let data: Vec<u8> = (0..30_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&src, &data).unwrap();

    // First run writes the image and a map recording it finished.
    let out = run(&[
        "image",
        src.to_str().unwrap(),
        out_img.to_str().unwrap(),
        "--no-sparse",
        "--quiet",
        "--map",
        map.to_str().unwrap(),
    ]);
    assert!(out.status.success());
    assert_eq!(std::fs::read(&out_img).unwrap(), data);
    let map_text = std::fs::read_to_string(&map).unwrap();
    assert!(
        map_text.contains(&format!("pos {}", data.len())),
        "{map_text}"
    );

    // Resuming an already-complete copy is a no-op that still succeeds and leaves
    // the image intact.
    let out = run(&[
        "image",
        src.to_str().unwrap(),
        out_img.to_str().unwrap(),
        "--no-sparse",
        "--quiet",
        "--map",
        map.to_str().unwrap(),
        "--resume",
    ]);
    assert!(out.status.success());
    assert_eq!(std::fs::read(&out_img).unwrap(), data);
}

#[test]
fn image_accepts_retry_bad_and_records_it() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("disk.img");
    let out_img = tmp.path().join("copy.img");
    let summary = tmp.path().join("summary.json");

    let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&src, &data).unwrap();

    // A healthy source has nothing to retry, but the flag must be wired through.
    let out = run(&[
        "image",
        src.to_str().unwrap(),
        out_img.to_str().unwrap(),
        "--no-sparse",
        "--quiet",
        "--retry-bad",
        "2",
        "--summary",
        summary.to_str().unwrap(),
    ]);
    assert!(out.status.success());
    assert_eq!(std::fs::read(&out_img).unwrap(), data);
    let report = std::fs::read_to_string(&summary).unwrap();
    assert!(report.contains("\"retry_bad\": 2"), "{report}");
    assert!(report.contains("\"retry_passes\": 0"), "{report}");
}

#[test]
fn image_copies_only_the_requested_range() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("disk.img");
    let out_img = tmp.path().join("slice.img");

    let data: Vec<u8> = (0..8192u32).map(|i| i as u8).collect();
    std::fs::write(&src, &data).unwrap();

    let out = run(&[
        "image",
        src.to_str().unwrap(),
        out_img.to_str().unwrap(),
        "--no-sparse",
        "--quiet",
        "--start",
        "2048",
        "--end",
        "4096",
    ]);
    assert!(out.status.success());
    assert_eq!(std::fs::read(&out_img).unwrap(), data[2048..4096]);
}

#[test]
fn info_reports_no_volume_on_garbage() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("garbage.img");
    std::fs::write(&img, vec![0u8; 4096]).unwrap();
    let out = run(&["info", img.to_str().unwrap()]);
    // `info` exits 0 even when nothing is found, printing a message.
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("No supported volumes"), "stdout: {stdout}");
}

#[test]
fn scan_recovers_embedded_file() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let jpeg = common::jpeg(&vec![0x41u8; 2000]);
    let mut data = vec![0u8; 1000];
    data.extend_from_slice(&jpeg);
    data.extend_from_slice(&vec![0u8; 1000]);
    std::fs::write(&img, &data).unwrap();

    let out = run(&[
        "scan",
        img.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "-q",
    ]);
    assert!(out.status.success());
    let recovered: Vec<_> = std::fs::read_dir(&out_dir).unwrap().collect();
    assert_eq!(recovered.len(), 1, "should carve one jpeg");
}

#[test]
fn undelete_dry_run_with_report_writes_no_files() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("ext.img");
    let out_dir = tmp.path().join("out");
    let report = tmp.path().join("report.csv");

    std::fs::write(&img, common::ext_volume("notes.txt", b"hello world")).unwrap();

    let out = run(&[
        "undelete",
        img.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--dry-run",
        "--report",
        report.to_str().unwrap(),
    ]);
    assert!(out.status.success());

    // Dry run writes a report but no recovered files / output dir.
    assert!(
        !Path::new(&out_dir).exists(),
        "dry run must not create output"
    );
    let csv = std::fs::read_to_string(&report).unwrap();
    assert!(csv.contains("filesystem,volume_offset,path,size,recovered"));
    assert!(csv.contains("notes.txt"));
}

#[test]
fn scan_report_manifest_carries_matching_sha256() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");
    let report = tmp.path().join("carved.json");

    let jpeg = common::jpeg(&vec![0x41u8; 2000]);
    let mut data = vec![0u8; 1000];
    data.extend_from_slice(&jpeg);
    std::fs::write(&img, &data).unwrap();

    let out = run(&[
        "scan",
        img.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
        "-q",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Exactly one file is carved; its digest in the manifest must match a fresh
    // hash of the bytes on disk, and the manifest must name its type and offset.
    let entries: Vec<_> = std::fs::read_dir(&out_dir).unwrap().collect();
    assert_eq!(entries.len(), 1);
    let carved = std::fs::read(entries[0].as_ref().unwrap().path()).unwrap();
    assert_eq!(carved, jpeg, "carved bytes match the planted JPEG");
    let expected = filerecovery::hash::to_hex(&filerecovery::hash::digest(&carved));

    let json = std::fs::read_to_string(&report).unwrap();
    assert!(
        json.contains(&format!("\"sha256\": \"{expected}\"")),
        "manifest missing digest {expected}: {json}"
    );
    assert!(json.contains("\"type\": \"jpg\""), "manifest: {json}");
    // The JPEG starts 1000 bytes into the image.
    assert!(json.contains("\"offset\": 1000"), "manifest: {json}");
}

#[test]
fn report_manifest_carries_matching_sha256() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");
    let report = tmp.path().join("manifest.json");

    let content = b"hash me for the recovery manifest";
    std::fs::write(&img, common::ext_volume("notes.txt", content)).unwrap();

    let out = run(&[
        "undelete",
        img.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The digest in the report must match a fresh hash of the recovered file.
    let recovered = std::fs::read(out_dir.join("notes.txt")).unwrap();
    assert_eq!(recovered, content);
    let expected = filerecovery::hash::to_hex(&filerecovery::hash::digest(&recovered));

    let json = std::fs::read_to_string(&report).unwrap();
    assert!(
        json.contains(&format!("\"sha256\": \"{expected}\"")),
        "report missing expected digest {expected}: {json}"
    );
}

#[test]
fn info_json_lists_volumes() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    std::fs::write(&img, common::ext_volume("notes.txt", b"hello world")).unwrap();

    // Without --deleted: the count is null.
    let out = run(&["info", img.to_str().unwrap(), "--json"]);
    assert!(out.status.success());
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"filesystem\": \"ext2/3/4\""), "{json}");
    assert!(json.contains("\"deleted\": null"), "{json}");
    assert!(json.contains("\"volumes\""), "{json}");

    // With --deleted: the recoverable count is reported.
    let out = run(&["info", img.to_str().unwrap(), "--json", "--deleted"]);
    assert!(out.status.success());
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"deleted\": 1"), "{json}");
}

#[test]
fn info_json_on_garbage_has_empty_volumes() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    std::fs::write(&img, vec![0u8; 4096]).unwrap();

    let out = run(&["info", img.to_str().unwrap(), "--json"]);
    assert!(out.status.success());
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"volumes\": []"), "{json}");
}

#[test]
fn completions_emit_a_script() {
    let out = run(&["completions", "bash"]);
    assert!(out.status.success());
    let script = String::from_utf8_lossy(&out.stdout);
    // The bash completion script references the binary name and registers it.
    assert!(script.contains("filerecovery"), "{script}");
    assert!(script.contains("complete "), "{script}");

    // An invalid shell is rejected.
    assert!(!run(&["completions", "not-a-shell"]).status.success());
}

#[test]
fn identify_detects_type_by_content() {
    let tmp = tempfile::tempdir().unwrap();
    // A JPEG given a misleading .bin extension.
    let jpeg = common::jpeg(&[0x41u8; 100]);
    let f = tmp.path().join("mystery.bin");
    std::fs::write(&f, &jpeg).unwrap();

    let out = run(&["identify", f.to_str().unwrap()]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("jpg"), "{text}");

    let out = run(&["identify", f.to_str().unwrap(), "--json"]);
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"identified\":true"), "{json}");
    assert!(json.contains("\"type\":\"jpg\""), "{json}");
    assert!(json.contains("\"validated\":true"), "{json}");

    // Unknown content is reported as such.
    let g = tmp.path().join("blob.bin");
    std::fs::write(&g, b"not a known file type at all").unwrap();
    let out = run(&["identify", g.to_str().unwrap(), "--json"]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("\"identified\":false"));
}

#[test]
fn triage_summarizes_a_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("rec");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("a.jpg"), vec![1u8; 100]).unwrap();
    std::fs::write(dir.join("b.jpg"), vec![1u8; 100]).unwrap(); // duplicate of a.jpg
    std::fs::write(dir.join("c.png"), vec![9u8; 30]).unwrap();

    // Human output mentions the counts and the duplicate set.
    let out = run(&["triage", dir.to_str().unwrap()]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("3 file(s)"), "{text}");
    assert!(text.contains("duplicate set"), "{text}");

    // JSON output is machine-readable.
    let out = run(&["triage", dir.to_str().unwrap(), "--json"]);
    assert!(out.status.success());
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"total_files\":3"), "{json}");
    assert!(json.contains("\"duplicate_sets\":1"), "{json}");
    assert!(json.contains("\"jpg\""), "{json}");
}

#[test]
fn scan_writes_run_summary() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");
    let summary = tmp.path().join("summary.json");

    let jpeg = common::jpeg(&vec![0x41u8; 2500]);
    let mut data = vec![0u8; 800];
    data.extend_from_slice(&jpeg);
    std::fs::write(&img, &data).unwrap();

    let out = run(&[
        "scan",
        img.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--summary",
        summary.to_str().unwrap(),
        "-q",
    ]);
    assert!(out.status.success());

    let json = std::fs::read_to_string(&summary).unwrap();
    assert!(json.contains("\"command\": \"scan\""), "{json}");
    assert!(json.contains("\"files_recovered\": 1"), "{json}");
    assert!(json.contains("\"per_type\""), "{json}");
    assert!(json.contains("\"jpg\": 1"), "{json}");
    assert!(json.contains("\"timestamp_unix\""), "{json}");
}

#[test]
fn verify_detects_intact_and_tampered_files() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");
    let report = tmp.path().join("carved.csv");

    let jpeg = common::jpeg(&vec![0x42u8; 3000]);
    let mut data = vec![0u8; 500];
    data.extend_from_slice(&jpeg);
    std::fs::write(&img, &data).unwrap();

    let out = run(&[
        "scan",
        img.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
        "-q",
    ]);
    assert!(out.status.success());

    // A fresh recovery verifies clean.
    let out = run(&[
        "verify",
        report.to_str().unwrap(),
        "--base",
        out_dir.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "verify should pass on intact files: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("1 OK"));

    // Tamper with the recovered file; verify must now fail and flag it.
    let carved = std::fs::read_dir(&out_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::write(&carved, b"corrupted contents").unwrap();

    let out = run(&[
        "verify",
        report.to_str().unwrap(),
        "--base",
        out_dir.to_str().unwrap(),
    ]);
    assert!(!out.status.success(), "verify must fail on a tampered file");
    assert!(String::from_utf8_lossy(&out.stdout).contains("MISMATCH"));
}

#[test]
fn undelete_offset_override_recovers() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    // Place an ext volume 1 MiB into the image; auto-detect won't find it, but
    // an explicit --offset will.
    let vol = common::ext_volume("data.bin", b"recover me via offset");
    let off = 1024 * 1024usize;
    let mut disk = vec![0u8; off + vol.len()];
    disk[off..off + vol.len()].copy_from_slice(&vol);
    std::fs::write(&img, &disk).unwrap();

    let out = run(&[
        "undelete",
        img.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--offset",
        &off.to_string(),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(out_dir.join("data.bin")).unwrap(),
        b"recover me via offset"
    );
}
