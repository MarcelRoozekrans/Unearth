//! Carving tests for RAR archives (v4 and v5). Each is built byte-exactly per
//! the format's block layout, embedded in a synthetic image, and recovered
//! byte-for-byte by walking the block chain to the end-of-archive block.

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

/// A RAR v4 archive: 7-byte marker, one file block (with `data` as its added
/// data area), then the end-of-archive block (type 0x7B).
fn rar4(data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]; // marker

    // File block (type 0x74) with ADD_SIZE flag (0x8000): HEAD_SIZE=11.
    v.extend_from_slice(&[0, 0]); // HEAD_CRC
    v.push(0x74); // HEAD_TYPE
    v.extend_from_slice(&0x8000u16.to_le_bytes()); // HEAD_FLAGS (ADD_SIZE present)
    v.extend_from_slice(&11u16.to_le_bytes()); // HEAD_SIZE
    v.extend_from_slice(&(data.len() as u32).to_le_bytes()); // ADD_SIZE
    v.extend_from_slice(data); // added data area

    // End-of-archive block (type 0x7B), HEAD_SIZE=7, no flags.
    v.extend_from_slice(&[0, 0]); // HEAD_CRC
    v.push(0x7B); // HEAD_TYPE
    v.extend_from_slice(&0u16.to_le_bytes()); // HEAD_FLAGS
    v.extend_from_slice(&7u16.to_le_bytes()); // HEAD_SIZE
    v
}

/// A RAR v5 archive: 8-byte signature, a main header block, a file block (with
/// `data` as its data area), then the end-of-archive block (type 5). All vints
/// here fit in a single byte (values < 128).
fn rar5(data: &[u8]) -> Vec<u8> {
    assert!(
        data.len() < 128,
        "test keeps the data-size vint single-byte"
    );
    let mut v = vec![0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]; // signature

    // Main header block (type 1): CRC32 + header_size(2) + {type=1, flags=0}.
    v.extend_from_slice(&[0, 0, 0, 0]); // CRC32
    v.push(2); // header_size
    v.push(1); // type
    v.push(0); // flags

    // File block (type 2): CRC32 + header_size(3) + {type=2, flags=2, data_size}
    // then the data area.
    v.extend_from_slice(&[0, 0, 0, 0]); // CRC32
    v.push(3); // header_size (type + flags + data_size vints)
    v.push(2); // type
    v.push(2); // flags (0x02 => data area present)
    v.push(data.len() as u8); // data_size vint
    v.extend_from_slice(data);

    // End-of-archive block (type 5): CRC32 + header_size(2) + {type=5, flags=0}.
    v.extend_from_slice(&[0, 0, 0, 0]); // CRC32
    v.push(2); // header_size
    v.push(5); // type
    v.push(0); // flags
    v
}

#[test]
fn recovers_rar_v4_and_v5() {
    let v4 = rar4(&filler(1, 5000));
    let v5 = rar5(&filler(2, 100));

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 700)).unwrap();
    img.write_all(&v4).unwrap();
    img.write_all(&filler(11, 300)).unwrap();
    img.write_all(&v5).unwrap();
    img.write_all(&filler(12, 700)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["rar".to_string()]).unwrap();
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
        checkpoint: None,
        resume: false,
        organize: false,
    };
    let stats = carver::carve(&source, &sigs, &opts, &NoProgress).unwrap();
    assert_eq!(stats.files_recovered, 2, "rar v4 and v5");

    let mut recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    recovered.sort();
    let mut originals = vec![v4, v5];
    originals.sort();
    assert_eq!(recovered, originals, "recovered bytes must match originals");
    assert_eq!(stats.per_type.get("rar"), Some(&2));
}
