//! UDF (optical/USB media) is recognised by `detect`/`info` and surfaced to the
//! user, but it is not recovered from metadata — `undelete` finds nothing and
//! carving is the fallback.

use std::process::Command;

use filerecovery::recover::{self, RecoverOptions};
use filerecovery::source::Source;

const VRS_OFFSET: usize = 16 * 2048;
const VSD_SIZE: usize = 2048;

/// A minimal UDF image: a reserved area followed by a BEA01 / NSR03 / TEA01
/// Volume Recognition Sequence at sector 16.
fn udf_image() -> Vec<u8> {
    let mut v = vec![0u8; VRS_OFFSET + 8 * VSD_SIZE];
    let put = |v: &mut [u8], index: usize, id: &[u8; 5]| {
        let off = VRS_OFFSET + index * VSD_SIZE;
        v[off + 1..off + 6].copy_from_slice(id);
    };
    put(&mut v, 0, b"BEA01");
    put(&mut v, 1, b"NSR03");
    put(&mut v, 2, b"TEA01");
    v
}

#[test]
fn detect_reports_udf_but_recovers_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disc.img");
    let data = udf_image();
    std::fs::write(&img, &data).unwrap();
    let src = Source::open(&img).unwrap();

    let vols = recover::detect(&src).unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].fs_label(), "UDF");
    assert_eq!(vols[0].size(), data.len() as u64);

    // Recognised, but metadata undelete yields nothing (no error, no files).
    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 0);
}

#[test]
fn info_cli_lists_a_udf_volume() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disc.img");
    std::fs::write(&img, udf_image()).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_filerecovery"))
        .args(["info", img.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("UDF"), "stdout: {stdout}");
}
