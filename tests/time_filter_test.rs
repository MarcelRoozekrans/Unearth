//! `--modified-after`/`--modified-before` filter the undelete pass by each
//! file's modification time. Exercised against the ext4 backend with a known
//! `i_mtime` patched into the deleted file's inode.

mod common;

use unearth::recover::{self, RecoverOptions};
use unearth::source::Source;
use unearth::times::parse_date;

// Inode 11 (the deleted file) lives at EXT_ITAB(5)*EXT_BS(1024) + (11-1)*128 =
// 6400; i_mtime is the u32 at inode offset 0x10.
const MTIME_OFF: usize = 6400 + 0x10;

fn source_with_mtime(mtime: u32) -> (tempfile::TempDir, Source) {
    let mut img = common::ext_volume("notes.txt", b"hello time");
    img[MTIME_OFF..MTIME_OFF + 4].copy_from_slice(&mtime.to_le_bytes());
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("ext.img");
    std::fs::write(&p, &img).unwrap();
    let src = Source::open(&p).unwrap();
    (tmp, src)
}

fn recovered_count(src: &Source, out: &std::path::Path, opts: &RecoverOptions) -> u64 {
    let vols = recover::detect(src).unwrap();
    vols[0].recover_deleted(src, out, opts).unwrap().recovered
}

#[test]
fn modified_after_and_before_bound_the_window() {
    // i_mtime = 1_600_000_000 -> 2020-09-13.
    let (tmp, src) = source_with_mtime(1_600_000_000);

    // No filter: the file is recovered.
    let base = RecoverOptions::default();
    assert_eq!(recovered_count(&src, &tmp.path().join("a"), &base), 1);

    // After a later date: excluded.
    let after_later = RecoverOptions {
        modified_after: Some(parse_date("2021-01-01").unwrap()),
        ..Default::default()
    };
    assert_eq!(
        recovered_count(&src, &tmp.path().join("b"), &after_later),
        0
    );

    // After an earlier date: included.
    let after_earlier = RecoverOptions {
        modified_after: Some(parse_date("2020-01-01").unwrap()),
        ..Default::default()
    };
    assert_eq!(
        recovered_count(&src, &tmp.path().join("c"), &after_earlier),
        1
    );

    // Before an earlier date: excluded.
    let before_earlier = RecoverOptions {
        modified_before: Some(parse_date("2020-01-01").unwrap()),
        ..Default::default()
    };
    assert_eq!(
        recovered_count(&src, &tmp.path().join("d"), &before_earlier),
        0
    );

    // A window that brackets the file: included.
    let window = RecoverOptions {
        modified_after: Some(parse_date("2020-01-01").unwrap()),
        modified_before: Some(parse_date("2020-12-31").unwrap()),
        ..Default::default()
    };
    assert_eq!(recovered_count(&src, &tmp.path().join("e"), &window), 1);
}

#[test]
fn a_file_with_no_timestamp_is_kept() {
    // i_mtime = 0 -> unknown; a time filter must not silently drop it.
    let (tmp, src) = source_with_mtime(0);
    let opts = RecoverOptions {
        modified_after: Some(parse_date("2021-01-01").unwrap()),
        ..Default::default()
    };
    assert_eq!(recovered_count(&src, &tmp.path().join("a"), &opts), 1);
}
