//! Carving tests for the formats added on top of the originals: the ISO-BMFF
//! brands (AVIF, Canon CR3, JPEG XL, 3GP) and ELF objects. Each is embedded in
//! a synthetic image and recovered byte-for-byte.

use std::io::Write;

use filerecovery::carver::{self, CarveOptions, NoProgress};
use filerecovery::signatures;
use filerecovery::source::Source;

fn filler(seed: u64, n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i as u64 + seed) % 251) as u8).collect()
}

/// A minimal ISO base-media file: a 16-byte `ftyp` box with `brand`, then an
/// `mdat` box wrapping the payload.
fn iso_bmff(brand: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&16u32.to_be_bytes());
    v.extend_from_slice(b"ftyp");
    v.extend_from_slice(brand);
    v.extend_from_slice(&0u32.to_be_bytes()); // minor version
    let mdat = (8 + payload.len()) as u32;
    v.extend_from_slice(&mdat.to_be_bytes());
    v.extend_from_slice(b"mdat");
    v.extend_from_slice(payload);
    v
}

/// A minimal 64-bit little-endian ELF whose section-header table (the file's
/// end) holds `shnum` entries of 64 bytes, starting right after the header.
fn elf64(shnum: u16) -> Vec<u8> {
    let entsize: u16 = 64;
    let shoff: u64 = 64;
    let size = 64 + shnum as usize * entsize as usize;
    let mut v = vec![0u8; size];
    v[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    v[4] = 2; // 64-bit
    v[5] = 1; // little-endian
    v[6] = 1; // version
    v[0x28..0x30].copy_from_slice(&shoff.to_le_bytes()); // e_shoff
    v[0x3A..0x3C].copy_from_slice(&entsize.to_le_bytes()); // e_shentsize
    v[0x3C..0x3E].copy_from_slice(&shnum.to_le_bytes()); // e_shnum
    for (i, b) in v.iter_mut().enumerate().skip(64) {
        *b = (i % 251) as u8;
    }
    v
}

#[test]
fn recovers_brands_and_elf() {
    let avif = iso_bmff(b"avif", &filler(1, 1800));
    let cr3 = iso_bmff(b"crx ", &filler(2, 2200));
    let jxl = iso_bmff(b"jxl ", &filler(3, 1500));
    let g3p = iso_bmff(b"3gp4", &filler(4, 2600));
    let elf = elf64(3); // 64 + 3*64 = 256 bytes

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    for (gap, file) in [
        (1000usize, &avif),
        (300, &cr3),
        (300, &jxl),
        (300, &g3p),
        (300, &elf),
    ] {
        img.write_all(&vec![0u8; gap]).unwrap();
        img.write_all(file).unwrap();
    }
    // Trailing noise so the last atom/section walk stops cleanly.
    img.write_all(&vec![0u8; 1000]).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&[]).unwrap();
    let opts = CarveOptions {
        output_dir: out_dir.clone(),
        start: 0,
        end: None,
        min_size: 0,
        max_files: None,
        allow_nested: false,
        validate: true,
        dedup: false,
        progress: false,
    };
    let stats = carver::carve(&source, &sigs, &opts, &NoProgress).unwrap();
    assert_eq!(stats.files_recovered, 5, "avif, cr3, jxl, 3gp, elf");

    for ext in ["avif", "cr3", "jxl", "3gp", "elf"] {
        assert_eq!(stats.per_type.get(ext), Some(&1), "missing {ext}");
    }

    let mut recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    recovered.sort();
    let mut originals = vec![avif, cr3, jxl, g3p, elf];
    originals.sort();
    assert_eq!(recovered, originals, "recovered bytes must match originals");
}

/// A minimal PE32+ executable with two sections and no certificate overlay.
/// Layout: 64-byte DOS header (e_lfanew = 64), PE sig + COFF header, a 112-byte
/// optional header (PE32+ magic, NumberOfRvaAndSizes = 0), then the section
/// table. The file ends at the furthest `PointerToRawData + SizeOfRawData`.
fn pe_exe() -> Vec<u8> {
    let opt_size: usize = 112;
    let headers = 64 + 4 + 20 + opt_size + 2 * 40; // dos + sig + coff + opt + 2 sections
    let s0_ptr = headers; // first section's raw data
    let s0_size = 200usize;
    let s1_ptr = s0_ptr + s0_size;
    let s1_size = 100usize;
    let total = s1_ptr + s1_size;

    let mut v = vec![0u8; total];
    v[0..2].copy_from_slice(b"MZ");
    v[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes()); // e_lfanew

    let pe = 64usize;
    v[pe..pe + 4].copy_from_slice(b"PE\0\0");
    let coff = pe + 4;
    v[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // Machine = x64
    v[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes()); // NumberOfSections
    v[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());

    let opt = coff + 20;
    v[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+ magic
    v[opt + 108..opt + 112].copy_from_slice(&0u32.to_le_bytes()); // NumberOfRvaAndSizes

    let mut section = |i: usize, size_raw: u32, ptr_raw: u32| {
        let s = opt + opt_size + i * 40;
        v[s + 16..s + 20].copy_from_slice(&size_raw.to_le_bytes());
        v[s + 20..s + 24].copy_from_slice(&ptr_raw.to_le_bytes());
    };
    section(0, s0_size as u32, s0_ptr as u32);
    section(1, s1_size as u32, s1_ptr as u32);

    for (i, b) in v.iter_mut().enumerate().skip(s0_ptr) {
        *b = (i % 251) as u8;
    }
    v
}

#[test]
fn recovers_pe_executable() {
    let exe = pe_exe();

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&vec![0u8; 700]).unwrap();
    img.write_all(&exe).unwrap();
    img.write_all(&vec![0u8; 700]).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["exe".to_string()]).unwrap();
    let opts = CarveOptions {
        output_dir: out_dir.clone(),
        start: 0,
        end: None,
        min_size: 0,
        max_files: None,
        allow_nested: false,
        validate: true,
        dedup: false,
        progress: false,
    };
    let stats = carver::carve(&source, &sigs, &opts, &NoProgress).unwrap();
    assert_eq!(stats.files_recovered, 1, "one PE executable");
    assert_eq!(stats.per_type.get("exe"), Some(&1));

    let recovered = std::fs::read_dir(&out_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(
        std::fs::read(recovered).unwrap(),
        exe,
        "byte-for-byte match"
    );
}
