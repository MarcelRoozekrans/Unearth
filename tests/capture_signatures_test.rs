//! Carving tests for the container/capture signatures: FLV video and
//! pcap/pcapng network captures. Each is embedded with a walked length into a
//! synthetic image and recovered byte-for-byte.

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

/// An FLV file: a 9-byte header, PreviousTagSize0, then `(type, data)` tags each
/// followed by their previous-tag-size.
fn make_flv(tags: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut v = b"FLV".to_vec();
    v.push(1); // version
    v.push(0x05); // flags: audio + video
    v.extend_from_slice(&9u32.to_be_bytes()); // data offset
    v.extend_from_slice(&0u32.to_be_bytes()); // PreviousTagSize0
    for (ttype, data) in tags {
        v.push(*ttype);
        v.extend_from_slice(&(data.len() as u32).to_be_bytes()[1..4]); // 24-bit size
        v.extend_from_slice(&[0, 0, 0]); // timestamp
        v.push(0); // timestamp extended
        v.extend_from_slice(&[0, 0, 0]); // stream id
        v.extend_from_slice(data);
        v.extend_from_slice(&(11 + data.len() as u32).to_be_bytes()); // previous-tag-size
    }
    v
}

/// A libpcap file with a 24-byte global header and the given packet records.
fn make_pcap(be: bool, records: &[Vec<u8>]) -> Vec<u8> {
    let w16 = |x: u16| if be { x.to_be_bytes() } else { x.to_le_bytes() };
    let w32 = |x: u32| if be { x.to_be_bytes() } else { x.to_le_bytes() };
    let mut v = Vec::new();
    v.extend_from_slice(if be {
        &[0xA1, 0xB2, 0xC3, 0xD4]
    } else {
        &[0xD4, 0xC3, 0xB2, 0xA1]
    });
    v.extend_from_slice(&w16(2)); // version major
    v.extend_from_slice(&w16(4)); // version minor
    v.extend_from_slice(&w32(0)); // thiszone
    v.extend_from_slice(&w32(0)); // sigfigs
    v.extend_from_slice(&w32(65535)); // snaplen
    v.extend_from_slice(&w32(1)); // network = Ethernet
    for rec in records {
        v.extend_from_slice(&w32(0)); // ts_sec
        v.extend_from_slice(&w32(0)); // ts_usec
        v.extend_from_slice(&w32(rec.len() as u32)); // incl_len
        v.extend_from_slice(&w32(rec.len() as u32)); // orig_len
        v.extend_from_slice(rec);
    }
    v
}

/// One pcapng block: `type, total_length, padded body, total_length`.
fn pcapng_block(be: bool, btype: u32, body: &[u8]) -> Vec<u8> {
    let w32 = |x: u32| if be { x.to_be_bytes() } else { x.to_le_bytes() };
    let mut padded = body.to_vec();
    while padded.len() % 4 != 0 {
        padded.push(0);
    }
    let total = 12 + padded.len() as u32;
    let mut v = Vec::new();
    v.extend_from_slice(&w32(btype));
    v.extend_from_slice(&w32(total));
    v.extend_from_slice(&padded);
    v.extend_from_slice(&w32(total));
    v
}

/// A minimal pcapng file: a Section Header Block plus an Interface Description
/// Block.
fn make_pcapng(be: bool) -> Vec<u8> {
    let w16 = |x: u16| if be { x.to_be_bytes() } else { x.to_le_bytes() };
    let w32 = |x: u32| if be { x.to_be_bytes() } else { x.to_le_bytes() };
    let w64 = |x: u64| if be { x.to_be_bytes() } else { x.to_le_bytes() };

    let mut shb = Vec::new();
    shb.extend_from_slice(&w32(0x1A2B_3C4D)); // byte-order magic
    shb.extend_from_slice(&w16(1)); // version major
    shb.extend_from_slice(&w16(0)); // version minor
    shb.extend_from_slice(&w64(u64::MAX)); // section length: unspecified

    let mut idb = Vec::new();
    idb.extend_from_slice(&w16(1)); // linktype: Ethernet
    idb.extend_from_slice(&w16(0)); // reserved
    idb.extend_from_slice(&w32(65535)); // snaplen

    let mut v = pcapng_block(be, 0x0A0D_0D0A, &shb);
    v.extend_from_slice(&pcapng_block(be, 1, &idb));
    v
}

#[test]
fn recovers_capture_and_video_types() {
    let flv = make_flv(&[(9, filler(1, 40)), (8, filler(2, 25)), (9, filler(3, 60))]);
    let pcap = make_pcap(false, &[filler(4, 64), filler(5, 100), filler(6, 48)]);
    let pcapng = make_pcapng(true);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    let planted = [&flv, &pcap, &pcapng];
    img.write_all(&filler(100, 500)).unwrap();
    for (i, p) in planted.iter().enumerate() {
        img.write_all(p).unwrap();
        img.write_all(&filler(200 + i as u64, 400)).unwrap();
    }
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&[]).unwrap();
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

    assert_eq!(stats.files_recovered, 3, "flv, pcap, pcapng");
    for ext in ["flv", "pcap", "pcapng"] {
        assert_eq!(stats.per_type.get(ext), Some(&1), "missing {ext}");
    }

    let mut recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    recovered.sort();
    let mut originals = vec![flv, pcap, pcapng];
    originals.sort();
    assert_eq!(recovered, originals, "recovered bytes must match originals");
}
