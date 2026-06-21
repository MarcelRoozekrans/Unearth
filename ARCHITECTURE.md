# Architecture

`filerecovery` is a small, dependency-light Rust tool with a library core
(`src/lib.rs`) and a thin CLI (`src/main.rs`, args in `src/cli.rs`). The source
device or image is always accessed **read-only**.

## Module map

| Module             | Responsibility |
|--------------------|----------------|
| `source`           | Read-only, positioned access to a device/image; reports total size. The one I/O primitive everything else builds on. |
| `signatures`       | The carving signature table + the matcher (`SignatureIndex`), including the `secondary` tag used to disambiguate shared magics (RIFF, ISO-BMFF). |
| `carver`           | The `scan` engine: chunked sequential read, header detection, per-type extent computation, streaming writes. |
| `recover`          | Partition/volume **detection** (bare, MBR, GPT) and the `Volume` dispatcher + shared `RecoverOptions`/`RecoverStats`. The single entry point the CLI uses for `undelete`/`info`. |
| `fat`              | FAT12/16/32 undelete. |
| `exfat`            | exFAT undelete. |
| `ntfs`             | NTFS undelete (MFT + data runs). |
| `ext4`            | ext2/3/4 undelete, including jbd2 journal recovery. |
| `times`            | Timestamp conversions (Unix / FILETIME / DOS) and applying them to recovered files. |

## Two recovery strategies

- **Carving (`scan`)** — filesystem-agnostic. Scan raw bytes for known headers
  and reconstruct each file's length from a footer marker, a header size field,
  or a container's box/atom structure. Survives formatting; loses filenames.

- **Filesystem-aware undelete (`undelete`)** — parse the filesystem's own
  metadata that survives deletion to restore names, paths, sizes, and
  timestamps. Each backend exposes the same shape:
  `Volume::parse(src, offset)` then `Volume::recover_deleted(src, out, opts)`,
  unified behind `recover::Volume`.

## Detection flow (`recover::detect`)

1. Try a bare filesystem at offset 0 (`try_parse_volume`, signature-driven).
2. Else parse a GPT (`detect_gpt`, 512- and 4096-byte sectors).
3. Else walk an MBR partition table.

Each candidate partition is probed by filesystem signature, so partition-type
bytes are advisory only.

## Robustness conventions

These keep the parsers safe on malformed/adversarial images (see
`tests/robustness_test.rs`):

- Validate geometry (sector/cluster/record/inode sizes, shift exponents) before
  using it; reject implausible values with an error.
- Use `saturating_add`/`saturating_mul` for any byte offset or size derived
  from on-disk `u64` fields.
- Bound every allocation by real limits (e.g. clamp a recovered file's size to
  the source size); never trust an on-disk length for a `Vec` capacity.

## Testing

- **Unit tests** (in each module) cover the bit-level helpers: data-run
  decoding, jbd2 tag parsing, fixups, name reconstruction, signature matching,
  time conversions.
- **Integration tests** (`tests/`) hand-craft minimal but valid on-disk
  structures (`tests/common/`) — no `mkfs`/`mtools` needed — and assert
  byte-for-byte recovery, plus CLI behavior and no-panic fuzzing.
- CI (`.github/workflows/ci.yml`) runs `cargo fmt --check`,
  `cargo clippy --all-targets -D warnings`, and the full suite.
