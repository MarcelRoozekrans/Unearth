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

- **`triage` reports the modification-time span** — the oldest and newest file
  modification time across the directory, so you can see what period the
  recovered data covers. The text view adds a `Modified: <oldest> .. <newest>`
  line (ISO-8601 UTC) and `--json` / the MCP `triage` tool add `oldest_mtime` /
  `newest_mtime` as Unix seconds.
- **Filesystem UUIDs / volume serials are reported** — `info` / `list_volumes`
  now report each volume's identifier (the `UUID=` value `/etc/fstab` and `blkid`
  use) on a `uuid:` line / `uuid` field, so a recovered filesystem can be
  correlated with a system's configuration. For **ext**, **XFS**, **F2FS**, and
  **Btrfs** this is the filesystem UUID; for **FAT**, **exFAT**, and **NTFS** it
  is the volume serial number in the conventional form (`XXXX-XXXX` for
  FAT/exFAT, 16 hex digits for NTFS). (Distinct from a GPT partition's PARTUUID,
  reported in the partition table.)
- **GPT partition GUIDs are reported** — `info` / `list_volumes` now report each
  GPT partition's **unique GUID** (the PARTUUID that `/etc/fstab`, bootloaders,
  and `/dev/disk/by-partuuid` reference) and the **disk GUID**, so a recovered
  partition can be correlated with a system's configuration. The text view adds
  `disk GUID:` and per-entry `uuid:` lines; `--json` adds `disk_guid` and a
  per-partition `uuid` field, as does the MCP `list_volumes` tool.
- **LVM2 physical volumes are recognised** — a Linux LVM physical volume (how a
  partition holds the logical volumes that contain the real filesystems) is
  detected from its `LABELONE` / `LVM2 001` on-disk label and reported by `info`
  / `list_volumes` with the PV's size, instead of showing as unrecognised. The
  logical volumes are not mapped, so recover with a whole-source `scan` /
  `--scan`, which finds the filesystems inside the LVs at their physical offsets.
- **SquashFS image carving** — the read-only compressed filesystem used by Snap
  packages, AppImages, live media, and router/IoT firmware is carved from its
  `hsqs` superblock, whose `bytes_used` field gives the exact image size. The
  major version (4) and block-size/`block_log` consistency are checked, so a
  coincidental `hsqs` does not produce a bogus file. `identify` and `triage`
  recognise `.squashfs` by content too.
- **`cpio` archive carving** — the "new ASCII" (`newc`, and `070702` CRC) format
  used by Linux initramfs images and RPM payloads is carved by walking the entry
  chain (each 110-byte ASCII header's hex `namesize`/`filesize` fields give the
  next entry, names and data padded to 4 bytes) to the `TRAILER!!!` end marker,
  recovering the exact archive length. Header fields are validated as ASCII hex,
  so a coincidental `070701` does not produce a bogus file. `identify` and
  `triage` recognise `.cpio` by content too.
- **`tar` archive carving** — POSIX/GNU `ustar` archives are carved by walking
  the 512-byte member chain (each header's size field gives the next member) to
  the two-zero-block end-of-archive marker, so the exact archive length is
  recovered. Every header's checksum is verified during the walk, so a
  coincidental `ustar` string does not produce a bogus file. `identify` and
  `triage` recognise `.tar` by content too.
- **F2FS volumes are recognised** — the Flash-Friendly File System (internal
  storage on most Android phones, and many SD cards / embedded devices) is
  detected from its `0xF2F52010` superblock and reported by `info` /
  `list_volumes` with its size and volume **label**. Being log-structured and
  copy-on-write, it has no metadata undelete — fall back to `scan` (carving).
  Detected in the normal layout and the whole-source `--scan` partition search.
- **XFS volumes are recognised** — the high-performance journaling filesystem
  common on Linux servers and NAS appliances (the RHEL/CentOS default) is
  detected from its `XFSB` superblock and reported by `info` / `list_volumes`
  with its size and filesystem **label**. Modern XFS zeroes an inode's
  data-extent list on unlink, so there is no metadata undelete — fall back to
  `scan` (carving). Detected in the normal layout and the whole-source `--scan`
  partition search.
- **MBR logical partitions are enumerated** — `info` / `list_volumes` now walk
  the Extended Boot Record chain inside an extended partition and report each
  logical partition (its type and byte range), so an MBR disk with more than
  four partitions shows all of them instead of just the four primary slots. The
  walk is bounded against a malformed or cyclic chain.
- **GPT backup-header fallback** — when a disk's primary GPT header (LBA 1) is
  missing or corrupt (e.g. its first sectors were overwritten), `info` /
  `list_volumes` now recover the partition layout from the **backup** GPT header
  and entry array kept at the end of the disk, instead of showing no table. The
  text view flags this (`recovered from backup header; …`) and `--json` / the
  MCP `list_volumes` tool add a `gpt_from_backup` boolean.
- **`triage` flags corrupt/truncated files** — a recovered file whose extension
  names a type with a known magic signature, but whose content matches no
  signature at all (a destroyed or truncated header, or a mislabelled blob).
  This is reserved for types with a direct magic number, so unidentifiable-but-
  plausible container subtypes (`docx`, `msg`, …) and empty files never produce
  noise — it complements the existing mismatch check (which flags content that
  *is* a different known type). Reported in the text output, as a `corrupt`
  array in `--json`, and by the MCP `triage` tool (which now also reports
  `mismatches`).
- **ReFS volumes are recognised** — Microsoft's Resilient File System (Windows
  Server, Storage Spaces, Dev Drive) is detected from the `ReFS`/`FSRS`
  signatures in its volume boot record and reported by `info`/`list_volumes`
  with its size (from the boot record's sector geometry). Like APFS and Btrfs it
  is copy-on-write (and undocumented), so there is no metadata undelete — fall
  back to `scan` (carving) to recover data. Detection runs both in the normal
  layout and in the whole-source `--scan` partition search.
- **`triage` flags content/extension mismatches** — files whose bytes identify
  as a different known type than their extension claims (e.g. a `.jpg` that is
  really an executable — a renamed/disguised file, or a recovery mislabel).
  Common aliases (`jpeg`→`jpg`, `mov`→`mp4`, …) are normalised first and only
  recognised types are compared, so generic blobs and unknown formats don't
  produce noise. Reported in the text output and as a `mismatches` array in
  `--json`.
- **`identify` accepts multiple files** — `identify FILE...` (e.g. `identify *`)
  labels each file's type from its contents, one line per file; with `--json` it
  emits an array (a single file still prints one object, unchanged).
- **`info` shows the partition table** — the scheme (GPT or MBR) and each entry's
  type (friendly names for known GPT type GUIDs and MBR type bytes, otherwise the
  raw GUID / `0xNN`), GPT name, and byte range. This reveals the on-disk layout
  even for partitions whose filesystem isn't recovered (EFI System, swap, empty
  slots). `--json` adds `partition_scheme` and a `partitions` array, and the MCP
  `list_volumes` tool reports the same.
- **`info` reports each volume's free (unallocated) space** — read from the
  allocation map for FAT, exFAT, ext2/3/4, NTFS, and HFS+/HFSX — so you can gauge
  how much deleted data might be recoverable before running a carve. The text
  view adds a `free:` line (bytes and unallocated percentage) under each volume;
  `--json` adds a `free_bytes` field (`null` when the filesystem's map is not
  parsed). The MCP `list_volumes` tool reports the same `free_bytes` per volume.
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
- **UDF recognition** — UDF volumes (optical media, and many large USB drives and
  camcorder cards) are detected via their Volume Recognition Sequence and named by
  `info`/`list_volumes`. Their descriptor metadata is not parsed, so UDF is not
  recovered from metadata — carving (`scan`) is the fallback, as for APFS/Btrfs.
- **ISO 9660 detection and file extraction** — data CD/DVD discs and `.iso`
  images are detected via the Primary Volume Descriptor at sector 16 and named by
  `info`/`list_volumes` (with their size and volume label), and `undelete`/
  `recover` **extract their files with original names and folder paths** by
  walking the directory tree — far better than carving, which loses names and
  structure. Long names are decoded from both **Joliet** (Windows discs —
  UCS-2/Unicode) and **Rock Ridge** (`NM` entries on Linux/macOS discs) —
  including names that overflow the directory record into Rock Ridge
  continuation (`CE`) areas — so files come back with their full filenames
  either way. Files stored across several **multi-extent** records (how ISO 9660
  holds files larger than ~4 GiB) are reassembled into one output file rather
  than emitted as separate fragments. A hybrid UDF disc is reported as UDF.
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
  codestreams (`.j2k`, ended at the EOC marker), Windows Imaging images
  (WIM/ESD, sized from the resource-table extents), uncompressed Flash
  movies (`.swf`/`FWS`, length field in the header), and Compound File Binary
  (OLE2) containers — the legacy Microsoft Office formats (`.doc`/`.xls`/`.ppt`)
  and other OLE2 files (e.g. `.msi`) — sized by reading the FAT (located via the
  DIFAT) and taking the highest sector still marked in use, and Outlook data
  files (`.pst`/`.ost`, Unicode format — sized from the `ibFileEof` field in the
  NDB header) — each with a deterministic length strategy.
- **MP3 without an ID3v2 tag** is now carved by anchoring directly on a Layer III
  frame sync (requiring a long run of valid frames), so ID3v1-only and tagless
  MP3s are recovered, not just ID3v2-tagged ones.
- **`scan --dry-run`** previews a recovery: it reports the counts, sizes, per-type
  breakdown, and (with `--report`) the manifest of what *would* be recovered,
  without writing any files — useful for sizing up a device first. Also exposed
  as a `dry_run` argument on the MCP `scan` tool.
- **`recover --dry-run`** previews both passes (filesystem undelete and carving)
  without writing any files, so dry-run is now available on `scan`, `undelete`,
  and `recover` alike.
- **`--volume <N>`** — `undelete` and `recover` can target a single detected
  volume by its `info` index (0-based), a friendlier alternative to copying the
  raw `--offset`. Out-of-range indexes are reported clearly.
- **Name/glob filtering** — `--name <GLOB>` and `--exclude-name <GLOB>` (on
  `undelete` and `recover`, and the MCP `undelete` tool) recover only — or skip —
  files whose name matches a case-insensitive glob (`*` and `?`); repeatable or
  comma-separated (`--name '*.jpg,*.png'`, `--exclude-name '*.tmp,Thumbs.db'`).
  Includes match any pattern; excludes are applied after and win on overlap.
  Applies to every undelete backend (FAT, exFAT, NTFS, ext, HFS+) and to ISO 9660
  file extraction. Completes the recovery filter family alongside
  `--min-size`/`--max-size` and the time bounds.
- **Time-range filtering** — `--modified-after` and `--modified-before` (on
  `undelete` and `recover`, and the MCP `undelete` tool) restrict the undelete
  pass to files whose modification time falls in a window, e.g. `--modified-after
  2021-01-01`. Accepts `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SS` (UTC). Applies to
  every filesystem backend (FAT, exFAT, NTFS, ext, HFS+); a file whose timestamp
  can't be read is kept rather than silently dropped. (As with timestamp
  restoration, FAT/exFAT times are treated as UTC for lack of a recorded zone.)
- **`--align`** — restrict carving (on `scan` and `recover`, and the MCP `scan`
  tool) to candidates whose start offset is a multiple of the given size (e.g.
  `--align 512` or `--align 4K`). Files inside a filesystem begin on cluster
  (sector-multiple) boundaries, so aligning discards the coincidental mid-sector
  magic matches that produce most false positives. Default 1 (every offset).
- **`--max-size`** — a size cap symmetric with `--min-size`, on `scan`, `undelete`,
  and `recover` (and the MCP `scan`/`undelete` tools). Recognised files larger than
  the cap are skipped — carving counts them under `skipped_large` (reported in the
  text output, the `--summary`, and the MCP scan result) rather than writing them.
  Both bounds apply to the undelete *and* carving passes of `recover`. Useful for
  fast triage: recover the small stuff first, or skip multi-gigabyte files.
- **Human-readable size suffixes** — every byte-valued option (`--start`, `--end`,
  `--min-size`, `--offset`, `--scan-step`, `--sector-size`) now accepts binary
  unit suffixes like `5M`, `2G`, or `1.5G` (powers of 1024), not just raw byte
  counts.
- **Type categories** — `--type` (on `scan` and `recover`) now accepts a category
  name (`image`, `audio`, `video`, `document`, `archive`, `executable`, `font`,
  `system`) to select a whole class of types at once, instead of listing every
  extension. Categories and extensions can be mixed. `list-types` groups its
  output by category so the names are discoverable. The MCP server exposes this
  too: `list_types` now reports each type's `category` (de-duplicated by
  extension), and the `scan` tool's `types` argument accepts category names.
  `identify` (CLI and MCP) reports the detected file's category, and `triage`
  adds a per-category rollup (image/audio/video/…) alongside its per-type
  breakdown. `--type` also accepts a comma-separated list (`--type image,pdf`),
  not just repetition. A new `--exclude` option drops types or categories from
  the selection (applied after `--type`), e.g. `--type image --exclude png` or
  `--exclude video`.

- **OLE2 compound files are recovered with their real extension.** A carved
  compound file (`.ole`) is inspected for the marker stream name of the format it
  carries, so it is written as `.doc` (Word), `.xls` (Excel), `.ppt`
  (PowerPoint), or `.msg` (Outlook message) instead of a generic `.ole`; a
  Windows Installer is recognised by its root storage CLSID and written as
  `.msi`. An unrecognised compound file stays `.ole`. `identify` reports the same
  refined type; doc/xls/ppt/msg map to the document category and msi to the
  executable category for `--type`, `triage`, and `identify`.

- **ZIP-based formats are recovered with their real extension.** A carved ZIP is
  inspected for the marker member of the common ZIP container formats, so a
  recovered Office (`.docx`/`.xlsx`/`.pptx`), OpenDocument (`.odt`/`.ods`/`.odp`),
  e-book (`.epub`), Java (`.jar`), or Android (`.apk`) file is written with that
  extension (and counted under it) instead of a generic `.zip`. A plain ZIP stays
  `.zip`. `identify` reports the same refined type, and these types are mapped to
  their categories (documents, archives) for `--type`, `triage`, and `identify`.

### Fixed

- **Fewer carving false positives** — structural validators were added for eight
  more types: PDF (version string), TIFF/BigTIFF (byte order, version, and a
  plausible first-IFD offset), Microsoft Cabinet (zeroed reserved fields),
  WebAssembly and Android DEX (version checks), Photoshop (version + reserved
  fields), and Ogg and FLV (header constants). A coincidental magic match in
  unrelated data now fails these checks and is dropped, on top of the existing
  JPEG/PNG/GIF/BMP/SQLite/ELF/EMF/MIDI validators.
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
