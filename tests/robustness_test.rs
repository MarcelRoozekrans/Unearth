//! Robustness tests: malformed, random, and truncated input must never panic —
//! every parser should return `Ok`/`Err` (or empty results), not crash.

use std::path::Path;

use filerecovery::carver::{self, CarveOptions, NoProgress};
use filerecovery::recover::{self, RecoverOptions};
use filerecovery::signatures;
use filerecovery::source::Source;

/// Tiny deterministic xorshift PRNG so failures reproduce.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() >> 24) as u8).collect()
    }
}

fn run_all(src: &Source, out_dir: &Path) {
    // Detection / parsing must not panic.
    let _ = recover::detect(src);
    let _ = recover::parse_at(src, 0);

    // Carving must not panic and must not write outside the (small) buffer.
    let sigs = signatures::select(&[]).unwrap();
    let opts = CarveOptions {
        output_dir: out_dir.to_path_buf(),
        start: 0,
        end: None,
        min_size: 0,
        max_files: Some(50),
        allow_nested: false,
        progress: false,
    };
    let _ = carver::carve(src, &sigs, &opts, &NoProgress);
}

#[test]
fn never_panics_on_random_and_planted_input() {
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("fuzz.img");
    let out_dir = tmp.path().join("out");
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);

    for iter in 0..400u64 {
        let len = 1024 + (rng.next() % 8192) as usize;
        let mut buf = rng.bytes(len);

        // Periodically plant a filesystem/partition magic so the real parser
        // internals run against otherwise-garbage data.
        match iter % 7 {
            1 if len > 11 => buf[3..11].copy_from_slice(b"NTFS    "),
            2 if len > 11 => buf[3..11].copy_from_slice(b"EXFAT   "),
            3 if len > 0x43A => {
                buf[0x438..0x43A].copy_from_slice(&0xEF53u16.to_le_bytes()); // ext magic
            }
            4 if len > 512 => {
                buf[0] = 0xEB; // FAT-ish boot record
                buf[11..13].copy_from_slice(&512u16.to_le_bytes());
                buf[13] = 1;
                buf[16] = 2;
                buf[510] = 0x55;
                buf[511] = 0xAA;
            }
            5 if len > 600 => {
                buf[510] = 0x55; // MBR signature
                buf[511] = 0xAA;
                buf[512..520].copy_from_slice(b"EFI PART"); // GPT header
            }
            _ => {}
        }

        std::fs::write(&img_path, &buf).unwrap();
        let src = Source::open(&img_path).unwrap();
        run_all(&src, &out_dir);
    }
}

/// Build a minimal valid ext4 volume with one deleted file (slack entry).
fn minimal_ext() -> Vec<u8> {
    const BS: usize = 1024;
    const ISIZE: usize = 128;
    const ITAB: usize = 5;
    const ROOT: usize = 9;
    const DATA: usize = 11;
    let mut v = vec![0u8; 32 * BS];
    let sb = 1024;
    v[sb..sb + 4].copy_from_slice(&32u32.to_le_bytes());
    v[sb + 4..sb + 8].copy_from_slice(&32u32.to_le_bytes());
    v[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes());
    v[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes());
    v[sb + 0x28..sb + 0x2C].copy_from_slice(&32u32.to_le_bytes());
    v[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    v[sb + 0x58..sb + 0x5A].copy_from_slice(&(ISIZE as u16).to_le_bytes());
    v[sb + 0x60..sb + 0x64].copy_from_slice(&0x0002u32.to_le_bytes());
    v[2 * BS + 8..2 * BS + 12].copy_from_slice(&(ITAB as u32).to_le_bytes());

    let mut inode = |ino: u32, mode: u16, links: u16, dtime: u32, size: u32, block: u32| {
        let o = ITAB * BS + (ino as usize - 1) * ISIZE;
        v[o..o + 2].copy_from_slice(&mode.to_le_bytes());
        v[o + 4..o + 8].copy_from_slice(&size.to_le_bytes());
        v[o + 0x14..o + 0x18].copy_from_slice(&dtime.to_le_bytes());
        v[o + 0x1A..o + 0x1C].copy_from_slice(&links.to_le_bytes());
        v[o + 0x20..o + 0x24].copy_from_slice(&0x0008_0000u32.to_le_bytes());
        let ib = o + 0x28;
        v[ib..ib + 2].copy_from_slice(&0xF30Au16.to_le_bytes());
        v[ib + 2..ib + 4].copy_from_slice(&1u16.to_le_bytes());
        v[ib + 4..ib + 6].copy_from_slice(&4u16.to_le_bytes());
        v[ib + 16..ib + 18].copy_from_slice(&1u16.to_le_bytes());
        v[ib + 20..ib + 24].copy_from_slice(&block.to_le_bytes());
    };
    inode(2, 0x41ED, 3, 0, BS as u32, ROOT as u32);
    inode(11, 0x81A4, 0, 12345, 200, DATA as u32);

    let mut dirent = |block: usize, off: usize, ino: u32, rl: u16, name: &str, ft: u8| {
        let p = block * BS + off;
        v[p..p + 4].copy_from_slice(&ino.to_le_bytes());
        v[p + 4..p + 6].copy_from_slice(&rl.to_le_bytes());
        v[p + 6] = name.len() as u8;
        v[p + 7] = ft;
        v[p + 8..p + 8 + name.len()].copy_from_slice(name.as_bytes());
    };
    dirent(ROOT, 0, 2, 12, ".", 2);
    dirent(ROOT, 12, 2, (BS - 12) as u16, "..", 2);
    dirent(ROOT, 28, 11, 24, "file.bin", 1);
    v
}

#[test]
fn never_panics_on_truncated_volume() {
    let full = minimal_ext();
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("trunc.img");
    let out_dir = tmp.path().join("out");

    // Truncate the valid image at many lengths; recovery must stay panic-free.
    let mut len = 0usize;
    while len <= full.len() {
        std::fs::write(&img_path, &full[..len]).unwrap();
        if let Ok(src) = Source::open(&img_path) {
            if let Ok(volumes) = recover::detect(&src) {
                for vol in &volumes {
                    let _ = vol.recover_deleted(
                        &src,
                        &out_dir,
                        &RecoverOptions {
                            min_size: 0,
                            dry_run: true,
                        },
                    );
                }
            }
            run_all(&src, &out_dir);
        }
        len += 137; // stride across all structures
    }
}
