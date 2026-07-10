//! Linux swap area detection: a swap partition is recognised (not shown as an
//! unrecognised volume) and its size, UUID, and label are reported.

use unearth::recover;
use unearth::source::Source;

const PAGE: usize = 4096;
const SECTOR: usize = 512;

/// Build a version-2 swap area of `last_page + 1` pages with the given UUID and
/// label.
fn swap_area(last_page: u32, uuid: &[u8; 16], label: &str) -> Vec<u8> {
    let total = (last_page as usize + 1) * PAGE;
    let mut v = vec![0u8; total];
    v[1024..1028].copy_from_slice(&1u32.to_le_bytes()); // version
    v[1028..1032].copy_from_slice(&last_page.to_le_bytes()); // last_page
    v[1036..1052].copy_from_slice(uuid); // sws_uuid
    let lb = label.as_bytes();
    v[1052..1052 + lb.len()].copy_from_slice(lb); // sws_volume
    v[PAGE - 10..PAGE].copy_from_slice(b"SWAPSPACE2"); // magic
    v
}

/// Wrap `payload` in a single-partition MBR starting at LBA 1.
fn mbr_with_partition(payload: &[u8]) -> Vec<u8> {
    let start_lba = 1u32;
    let mut img = vec![0u8; SECTOR + payload.len()];
    img[SECTOR..SECTOR + payload.len()].copy_from_slice(payload);
    // One primary partition entry at offset 446.
    let e = 446;
    img[e] = 0x00; // not bootable
    img[e + 4] = 0x82; // type 0x82 = Linux swap (informational only)
    img[e + 8..e + 12].copy_from_slice(&start_lba.to_le_bytes());
    let sectors = (payload.len() / SECTOR) as u32;
    img[e + 12..e + 16].copy_from_slice(&sectors.to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;
    img
}

#[test]
fn detect_reports_a_swap_partition() {
    let uuid = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99,
    ];
    let img = mbr_with_partition(&swap_area(9, &uuid, "myswap"));

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("swap.img");
    std::fs::write(&path, &img).unwrap();
    let src = Source::open(&path).unwrap();

    let vols = recover::detect(&src).unwrap();
    assert_eq!(vols.len(), 1, "should find one swap volume");
    let v = &vols[0];
    assert_eq!(v.fs_label(), "Linux swap");
    assert_eq!(v.offset(), SECTOR as u64);
    assert_eq!(v.size(), 10 * PAGE as u64);
    assert_eq!(v.volume_label().as_deref(), Some("myswap"));
    assert_eq!(
        v.volume_uuid().as_deref(),
        Some("aabbccdd-eeff-0011-2233-445566778899")
    );
}

#[test]
fn info_cli_reports_swap_uuid_and_label() {
    let uuid = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99,
    ];
    let img = mbr_with_partition(&swap_area(9, &uuid, "myswap"));

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("swap.img");
    std::fs::write(&path, &img).unwrap();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_unearth"))
        .args(["info", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Linux swap"), "stdout: {stdout}");
    assert!(stdout.contains("myswap"), "stdout: {stdout}");
    assert!(
        stdout.contains("aabbccdd-eeff-0011-2233-445566778899"),
        "stdout: {stdout}"
    );
}
