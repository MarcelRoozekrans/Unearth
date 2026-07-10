//! Fuzz the carver's extent parsers directly. The general robustness test feeds
//! random data (which almost never contains the 4-byte carve magics), so this
//! complements it by planting **every signature's magic** — with its secondary
//! tag — at the start of adversarial buffers, forcing each extent strategy
//! (footer search, header-size, RIFF/SQLite/7z, MP4 atoms, ELF/PE section math,
//! TIFF IFD walk, EBML/Ogg/ASF/Wasm walks, ICO directory) to run on hostile
//! input. The only assertion is that nothing panics and `carve` returns `Ok`.

use unearth::carver::{self, CarveOptions, NoProgress};
use unearth::signatures::{self, SIGNATURES};
use unearth::source::Source;

/// Tiny deterministic xorshift PRNG so any failure reproduces.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Build a buffer that starts with `sig`'s header (magic at its `magic_offset`,
/// plus any secondary tag) followed by a `tail` fill pattern, so the magic
/// matches and the extent parser runs against adversarial bytes.
fn planted(sig: &signatures::Signature, len: usize, tail: u8) -> Vec<u8> {
    let mut buf = vec![tail; len];
    let off = sig.magic_offset as usize;
    if off + sig.magic.len() <= len {
        buf[off..off + sig.magic.len()].copy_from_slice(sig.magic);
    }
    if let Some((soff, tag)) = sig.secondary {
        let start = off + soff;
        if start + tag.len() <= len {
            buf[start..start + tag.len()].copy_from_slice(tag);
        }
    }
    buf
}

fn carve_buf(buf: &[u8], out_dir: &std::path::Path) {
    let tmp = tempfile::Builder::new().tempfile().unwrap();
    std::fs::write(tmp.path(), buf).unwrap();
    let source = Source::open(tmp.path()).unwrap();
    let sigs = signatures::select(&[]).unwrap();
    let opts = CarveOptions {
        output_dir: out_dir.to_path_buf(),
        start: 0,
        end: None,
        min_size: 0,
        max_size: None,
        max_files: Some(20),
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
    // Must not panic; result content is irrelevant.
    let _ = carver::carve(&source, &sigs, &opts, &NoProgress).unwrap();
}

#[test]
fn carver_never_panics_on_planted_magics() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    let mut rng = Rng(0x0BAD_F00D_1234_5678);

    // For every signature, plant its header then stress the extent parser with
    // a range of buffer sizes and fill patterns (incl. all-0x00 and all-0xFF,
    // which drive size/offset fields to extremes and exercise saturation).
    for sig in SIGNATURES {
        for &len in &[40usize, 256, 4096] {
            for &tail in &[0x00u8, 0xFF] {
                let mut buf = planted(sig, len, tail);
                // Scribble some randomness past the header so size/offset/length
                // fields take on unpredictable (often out-of-range) values.
                for b in buf.iter_mut().skip(sig.magic.len() + 16) {
                    *b = (rng.next() >> 24) as u8;
                }
                carve_buf(&buf, &out);
            }
        }
    }
}

#[test]
fn carver_never_panics_on_random_with_planted_magics() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    let mut rng = Rng(0xFEED_FACE_C0FF_EE01);

    for _ in 0..150 {
        let len = 64 + (rng.next() % 8192) as usize;
        let mut buf: Vec<u8> = (0..len).map(|_| (rng.next() >> 24) as u8).collect();
        // Plant a random signature's magic at a random position so an extent
        // parser runs over the surrounding random bytes.
        let sig = &SIGNATURES[(rng.next() as usize) % SIGNATURES.len()];
        let pos = (rng.next() as usize) % len;
        if pos + sig.magic.len() <= len {
            buf[pos..pos + sig.magic.len()].copy_from_slice(sig.magic);
            if let Some((soff, tag)) = sig.secondary {
                let s = pos + soff;
                if s + tag.len() <= len {
                    buf[s..s + tag.len()].copy_from_slice(tag);
                }
            }
        }
        carve_buf(&buf, &out);
    }
}
