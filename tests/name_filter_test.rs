//! `--name <GLOB>` restricts the undelete pass to files whose name matches a
//! glob. Exercised against the ext4 backend via the public recover API.

mod common;

use filerecovery::recover::{self, RecoverOptions};
use filerecovery::source::Source;

fn source_of(name: &str) -> (tempfile::TempDir, Source) {
    let img = common::ext_volume(name, b"payload bytes");
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("ext.img");
    std::fs::write(&p, &img).unwrap();
    let src = Source::open(&p).unwrap();
    (tmp, src)
}

fn recovered(src: &Source, out: &std::path::Path, names: &[&str]) -> u64 {
    let opts = RecoverOptions {
        names: names.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    recover::detect(src).unwrap()[0]
        .recover_deleted(src, out, &opts)
        .unwrap()
        .recovered
}

#[test]
fn name_glob_includes_and_excludes() {
    let (tmp, src) = source_of("notes.txt");

    // No filter: recovered.
    assert_eq!(recovered(&src, &tmp.path().join("a"), &[]), 1);
    // Matching extension glob: recovered.
    assert_eq!(recovered(&src, &tmp.path().join("b"), &["*.txt"]), 1);
    // Non-matching glob: excluded.
    assert_eq!(recovered(&src, &tmp.path().join("c"), &["*.jpg"]), 0);
    // `?` matches exactly one character.
    assert_eq!(recovered(&src, &tmp.path().join("d"), &["note?.txt"]), 1);
    // Multiple patterns: a match on any one includes the file.
    assert_eq!(
        recovered(&src, &tmp.path().join("e"), &["*.jpg", "*.txt"]),
        1
    );
}

fn recovered_excluding(src: &Source, out: &std::path::Path, exclude: &[&str]) -> u64 {
    let opts = RecoverOptions {
        exclude_names: exclude.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    recover::detect(src).unwrap()[0]
        .recover_deleted(src, out, &opts)
        .unwrap()
        .recovered
}

#[test]
fn exclude_name_drops_matching_files() {
    let (tmp, src) = source_of("notes.txt");

    // Exclude a non-matching glob: still recovered.
    assert_eq!(
        recovered_excluding(&src, &tmp.path().join("a"), &["*.jpg"]),
        1
    );
    // Exclude a matching glob: dropped.
    assert_eq!(
        recovered_excluding(&src, &tmp.path().join("b"), &["*.txt"]),
        0
    );
}
