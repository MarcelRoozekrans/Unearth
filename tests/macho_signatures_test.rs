//! Carving test for Mach-O binaries. A 64-bit little-endian Mach-O is built
//! byte-exactly (header + an LC_SEGMENT_64 + an LC_CODE_SIGNATURE whose blob
//! ends the file), embedded in a synthetic image, and recovered byte-for-byte.

use std::io::Write;

use filerecovery::carver::{self, CarveOptions, NoProgress};
use filerecovery::signatures;
use filerecovery::source::Source;

fn filler(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

const LC_SEGMENT_64: u32 = 0x19;
const LC_CODE_SIGNATURE: u32 = 0x1D;

/// A 64-bit LE Mach-O executable with one __TEXT segment covering the start of
/// the file and a code-signature blob appended at the very end (so the file
/// length is the signature's `dataoff + datasize`, exercising the link-edit
/// path that ends real binaries).
fn make_macho() -> Vec<u8> {
    let header_size = 32usize;
    let seg_cmd_size = 72usize; // segment_command_64, no sections
    let sig_cmd_size = 16usize; // linkedit_data_command
    let sizeofcmds = (seg_cmd_size + sig_cmd_size) as u32;
    let cmds_end = header_size + seg_cmd_size + sig_cmd_size; // 120

    let text_filesize: u64 = 200; // __TEXT covers bytes 0..200
    let sig_dataoff: u64 = 200;
    let sig_datasize: u64 = 64;
    let total = (sig_dataoff + sig_datasize) as usize; // 264

    let mut v = Vec::new();
    // mach_header_64
    v.extend_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]); // magic (64-bit LE)
    v.extend_from_slice(&0x0100_0007u32.to_le_bytes()); // cputype = x86_64
    v.extend_from_slice(&3u32.to_le_bytes()); // cpusubtype
    v.extend_from_slice(&2u32.to_le_bytes()); // filetype = MH_EXECUTE
    v.extend_from_slice(&2u32.to_le_bytes()); // ncmds
    v.extend_from_slice(&sizeofcmds.to_le_bytes()); // sizeofcmds
    v.extend_from_slice(&0u32.to_le_bytes()); // flags
    v.extend_from_slice(&0u32.to_le_bytes()); // reserved
    assert_eq!(v.len(), header_size);

    // LC_SEGMENT_64 (__TEXT)
    v.extend_from_slice(&LC_SEGMENT_64.to_le_bytes()); // cmd
    v.extend_from_slice(&(seg_cmd_size as u32).to_le_bytes()); // cmdsize
    let mut segname = [0u8; 16];
    segname[..6].copy_from_slice(b"__TEXT");
    v.extend_from_slice(&segname); // segname[16]
    v.extend_from_slice(&0u64.to_le_bytes()); // vmaddr
    v.extend_from_slice(&text_filesize.to_le_bytes()); // vmsize
    v.extend_from_slice(&0u64.to_le_bytes()); // fileoff
    v.extend_from_slice(&text_filesize.to_le_bytes()); // filesize
    v.extend_from_slice(&7u32.to_le_bytes()); // maxprot
    v.extend_from_slice(&5u32.to_le_bytes()); // initprot
    v.extend_from_slice(&0u32.to_le_bytes()); // nsects
    v.extend_from_slice(&0u32.to_le_bytes()); // flags
    assert_eq!(v.len(), header_size + seg_cmd_size);

    // LC_CODE_SIGNATURE
    v.extend_from_slice(&LC_CODE_SIGNATURE.to_le_bytes()); // cmd
    v.extend_from_slice(&(sig_cmd_size as u32).to_le_bytes()); // cmdsize
    v.extend_from_slice(&(sig_dataoff as u32).to_le_bytes()); // dataoff
    v.extend_from_slice(&(sig_datasize as u32).to_le_bytes()); // datasize
    assert_eq!(v.len(), cmds_end);

    // __TEXT body up to the signature, then the signature blob to the end.
    v.extend_from_slice(&filler(1, sig_dataoff as usize - cmds_end));
    v.extend_from_slice(&filler(2, sig_datasize as usize));
    assert_eq!(v.len(), total);
    v
}

#[test]
fn recovers_a_macho_binary() {
    let macho = make_macho();

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 700)).unwrap();
    img.write_all(&macho).unwrap();
    img.write_all(&filler(11, 700)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["macho".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "one mach-o binary");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0], macho,
        "recovered bytes must match the original"
    );
    assert_eq!(stats.per_type.get("macho"), Some(&1));
}
