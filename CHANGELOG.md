# Changelog

All notable changes to `filerecovery` are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

Recovery reach grows in three directions: every supported filesystem can now
carve only its free space, Mac/Linux copy-on-write and encrypted volumes are
recognised and described, lost partitions can be found and recovered without a
partition table, and the carver gains modern archive/compression and image
formats.

### Added

- **Free-space-aware carving** — `recover --unallocated` and `scan --unallocated`
  carve only a volume's unallocated space (less noise, faster), reading the
  allocation map for FAT, exFAT, ext2/3/4, NTFS, and HFS+/HFSX. Falls back to a
  full-source carve, with a notice, when no map is available.
- **HFS+/HFSX** recovery now reassembles **fragmented files** via the
  extents-overflow B-tree and restores each file's original **folder path** from
  the catalog hierarchy.
- **APFS** volume enumeration and **Btrfs** detection plus **subvolume
  enumeration** in `info`/`list_volumes` — the names of the volumes/subvolumes
  inside the container (and the Btrfs filesystem label). Neither is recovered
  from metadata (copy-on-write); carving remains the fallback.
- **Encrypted-volume recognition** — LUKS (LUKS1/LUKS2) and BitLocker are named
  by `info`/`list_volumes` so the user knows to unlock them first; they hold only
  ciphertext and are not recovered.
- **Lost/corrupt partition recovery** — `info --scan` finds volumes that have no
  partition-table entry via a whole-source signature scan, and `undelete --scan`
  / `recover --scan` recover from every volume found, in one command.
- More **carvable types**: AIFF/AIFF-C audio, Apple ICNS icons, RAR archives
  (v4 and v5), Zstandard (`.zst`), LZ4 (`.lz4`), Photoshop documents (PSD/PSB),
  Windows Metafiles (WMF), DjVu documents, binary glTF (`.glb`), Windows Event
  Logs (EVTX), Rich Text Format (RTF), MP3 audio (ID3v2-anchored MPEG-frame
  walk), Mach-O binaries (macOS/iOS, sized from segment and link-edit
  extents), Windows registry hives (`regf`, base block + hive-bins data
  size), AAC audio (ADTS frame-length walk), Android Dalvik executables
  (DEX, file-size header field), ICC colour profiles (size in the profile
  header), Unix `ar` archives (`.deb`/`.a`, member-chain walk), and ESRI
  Shapefiles (`.shp`, length field in the header), and Blender files
  (`.blend`, block chain walked to the terminating `ENDB` block), and NES ROMs
  (iNES / NES 2.0, sized from the PRG/CHR bank counts), raw JPEG 2000
  codestreams (`.j2k`, ended at the EOC marker), and Windows Imaging images
  (WIM/ESD, sized from the resource-table extents) — each with a deterministic
  length strategy.
- **MP3 without an ID3v2 tag** is now carved by anchoring directly on a Layer III
  frame sync (requiring a long run of valid frames), so ID3v1-only and tagless
  MP3s are recovered, not just ID3v2-tagged ones.
- **Type categories** — `--type` (on `scan` and `recover`) now accepts a category
  name (`image`, `audio`, `video`, `document`, `archive`, `executable`, `font`,
  `system`) to select a whole class of types at once, instead of listing every
  extension. Categories and extensions can be mixed. `list-types` groups its
  output by category so the names are discoverable. The MCP server exposes this
  too: `list_types` now reports each type's `category` (de-duplicated by
  extension), and the `scan` tool's `types` argument accepts category names.
  `identify` (CLI and MCP) reports the detected file's category.

### Fixed

- **JPEG carving no longer truncates at an embedded thumbnail.** Camera and phone
  JPEGs embed a full thumbnail (its own `FF D8 … FF D9`) in the EXIF metadata; the
  carver previously stopped at the thumbnail's End-of-Image marker, producing a
  truncated file. It now tracks nested Start/End-of-Image markers and carves to
  the outer image's `FF D9`.
- **ZIP carving no longer truncates at a nested archive, and keeps the EOCD
  comment.** A ZIP stored inside a ZIP (a JAR/asset bundle, etc.) has its own
  End-of-Central-Directory record; the carver previously stopped at the first one,
  truncating the outer archive, and also dropped any EOCD comment. It now selects
  the EOCD whose recorded central-directory geometry matches the archive and
  includes the declared comment. This also covers the ZIP-based formats (DOCX,
  XLSX, PPTX, ODT, JAR, APK, EPUB).
- **GIF carving now walks the block structure** instead of stopping at the first
  `00 3B` byte pair, which can occur by chance inside the LZW-compressed image
  data and truncate the file. The carver follows the image and extension blocks
  (and their sub-block chains) to the real trailer.

## [0.2.0] - 2026-06-23

A large release that grows `filerecovery` from a signature carver into a
full recovery toolkit: filesystem-aware undelete, robust imaging, a one-pass
combined mode, and an AI-agent interface — all dependency-light and read-only on
the source.

### Added

- **Filesystem-aware undelete** (`undelete`) for FAT12/16/32, exFAT, NTFS, and
  ext2/3/4, restoring original names, paths, sizes, and timestamps. NTFS and ext
  reassemble fragmented files; ext4 falls back to the jbd2 journal when a live
  inode's extents were zeroed.
- **HFS+/HFSX undelete** by scanning catalog B-tree leaf-node free space for
  stale file records.
- **APFS detection** in `info`/`list_volumes` (recognised but not recovered from
  metadata — carving is the fallback).
- **Disk imaging** (`image`): read-only, bad-sector tolerant (sector-granular
  retry, unreadable regions recorded), sparse output, a checkpoint/map file for
  `--resume`, and `--retry-bad` to re-read unreadable regions.
- **One-pass recovery** (`recover`): undelete then content-deduplicated carving,
  written to `named/` and `carved/`, with a verifiable combined `--report`.
- **Resumable carving** (`scan --resume`) via a checkpoint file, plus
  `--organize` to group carved output into per-type subdirectories.
- **MCP server** (`mcp`): a Model Context Protocol server over stdio exposing
  recovery as tools for an AI agent, with `scan`/`image` running as cancellable
  background jobs (poll `scan_status`, stop with `scan_cancel`).
- **Auditing**: SHA-256 manifests (`--report`), run summaries (`--summary`), and
  a `verify` command that re-hashes recovered files against a manifest.
- **Inspection**: `info` (partition/filesystem layout), `triage` (summarize a
  recovery directory), and `identify` (detect a file's type from its contents).
- Many more carvable types — 40 in total, including fonts (TTF/OTF/WOFF/WOFF2/
  TTC), EMF, MIDI, FLV, pcap/pcapng, JPEG 2000, and animated cursors — each with
  a deterministic length strategy and, where useful, a structural validator.
- Shell completions (`completions`), Criterion benchmarks, a dhat heap-profiling
  example, and a release workflow that builds binaries on `v*` tags.

## [0.1.0]

- Initial release: signature-based file carving (`scan`) with structural
  validation, content dedup, and recovery manifests.

[Unreleased]: https://github.com/MarcelRoozekrans/FileRecovery/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/MarcelRoozekrans/FileRecovery/releases/tag/v0.2.0
[0.1.0]: https://github.com/MarcelRoozekrans/FileRecovery/releases/tag/v0.1.0
