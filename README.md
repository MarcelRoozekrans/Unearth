# filerecovery

Recover deleted files from SD cards, USB sticks, hard drives, and disk images.

`filerecovery` offers two complementary recovery strategies:

| Command    | Strategy                               | Restores names? | Works after format? |
|------------|----------------------------------------|-----------------|---------------------|
| `undelete` | Filesystem-aware (FAT/exFAT/NTFS/ext/HFS+) | **Yes**     | No (needs metadata) |
| `scan`     | Signature carving                      | No              | **Yes**             |

**Use `undelete` first** if the filesystem is still intact (e.g. you just
deleted a file): it reads the directory entries that survive deletion and
restores files with their **original names, folder paths, sizes, and
timestamps**. Fall
back to `scan` (carving) when the filesystem itself is damaged, formatted, or
its partition table is gone.

> These are the same general techniques used by tools like *PhotoRec*,
> *foremost*, *scalpel*, and *testdisk*.

## How each strategy works

### `undelete` — filesystem-aware recovery (FAT12/16/32, exFAT, NTFS, ext2/3/4, HFS+)

The filesystem type is auto-detected (bare volume, or a GPT or MBR partition
table), and FAT, exFAT, NTFS, ext2/3/4, and HFS+/HFSX are all handled by the
same `undelete` command.

**FAT.** When a file is deleted, only the first byte of its 32-byte directory
entry is overwritten (with `0xE5`) and its cluster chain is freed. The entry
still records the original name (including the VFAT long name), starting
cluster, and size. One quirk: because that first byte is lost, the leading
character of a name that had no long-name entry is shown as `_`.

**exFAT** (default on SD/SDXC cards over 32 GB and most modern cameras).
Deletion only clears the *InUse* bit on each directory entry, so the **entire
name and metadata survive** — nothing is lost. exFAT also records whether a file
is stored contiguously, which makes contiguous deleted files recover cleanly.

**NTFS** (Windows drives). Every file is described by a record in the Master
File Table (MFT). Deletion just clears the record's *in-use* flag; the name and
the `$DATA` **data runs** survive. Because NTFS records the full run list,
recovery here reconstructs **fragmented** files correctly — not just contiguous
ones — and small files stored inline in the MFT come back directly. Original
folder paths are rebuilt by following each record's parent reference.

For FAT/exFAT, `filerecovery` reads the surviving directory entries and recovers
each file under the **contiguous-allocation** assumption (the common case for
cameras/SD cards; exFAT additionally follows the FAT for files flagged as
fragmented), then restores them to their original folder paths.

**ext2/ext3/ext4** (Linux drives). ext is the trickiest case. On deletion the
inode's link count is cleared and the directory entry is unlinked by folding its
space into the previous entry — but the removed entry's **name and inode number**
usually remain in the directory block's *slack space*, and the inode's **extent
tree** (or ext2/3 block pointers) often survives. `filerecovery` walks the live
directory tree, scans that slack for stale entries, and recovers any whose inode
is now deleted but still has a readable block map. When ext4 has *zeroed* the
live inode's extent tree on deletion, it scans the filesystem **journal
(jbd2)** for an older copy of the inode-table block — which usually still has
the extents — and recovers from that. Only when neither the live inode nor any
journaled copy has an intact block map (the journal wrapped, or the inode was
reused) is the file unrecoverable by metadata; fall back to `scan`.

**HFS+/HFSX** (Mac drives). Every file and folder lives in the **catalog file**,
a B-tree whose leaf nodes hold one record per object — its name, CNID, and the
data fork's first eight extents inline. Deleting a file removes its record from
the leaf node and shifts the rest down, but the removed record's bytes usually
linger in the node's *free space* until the node is rewritten, and the data
blocks stay put until reused. `filerecovery` reads the catalog, walks every leaf
node, and scans the free space below the live records for stale **file records**
that pass a strict structural check. (This is the catalog-slack analogue of the
ext directory-slack technique.) Each recovered file is restored under its
original **folder path**, rebuilt from the live catalog's folder hierarchy via
each record's parent CNID. It follows the eight extents stored inline in its
catalog record and, for a file **fragmented** beyond them, the remaining extents
from the **extents-overflow B-tree** — so fragmented files come back whole, not
truncated. Only when a file's tail extents survive in neither place (the overflow
tree was itself rewritten after deletion) is it reported skipped; fall back to
`scan`.

### `scan` — signature-based file carving

Carving ignores the filesystem and scans the raw bytes of the device for known
file *signatures* (magic numbers), reconstructing each file's extent. Because
it does not depend on filesystem metadata, it recovers data even after:

- a file was deleted (the data blocks usually remain until overwritten),
- the card/drive was **quick-formatted**,
- the partition table was lost or corrupted.

The trade-off is that carving cannot restore original **filenames** or
directory structure — recovered files are named by their type and the byte
offset where they were found.

## Safety

- The source device/image is opened **read-only**; the tool only ever issues
  positioned reads and never writes to it.
- **Always recover to a different disk** than the one you are scanning. Writing
  recovered files back onto the damaged device can overwrite the very data you
  are trying to recover.
- For the best results, work from an **image** of the device rather than the
  live device — image it once, then run as many scans as you like against the
  copy without stressing the (possibly failing) original. The built-in `image`
  command does this read-only, tolerating bad sectors and writing sparse output:
  ```sh
  sudo filerecovery image /dev/sdb card.img
  filerecovery scan card.img -o recovered
  ```

## Install / build

Requires a Rust toolchain (1.75+).

```sh
cargo build --release
# binary at target/release/filerecovery
```

Prebuilt binaries for Linux (glibc and static musl), macOS (Intel and Apple
Silicon), and Windows are attached to each [GitHub Release](https://github.com/MarcelRoozekrans/FileRecovery/releases);
they are built automatically by the release workflow when a `v*` tag is pushed.
See [CHANGELOG.md](CHANGELOG.md) for the version history.

## Usage

```text
filerecovery <COMMAND>

Commands:
  undelete    Recover deleted files from FAT/exFAT/NTFS/ext/HFS+ (keeps names/paths)
  scan        Carve files from a device or image by signature
  recover     Undelete then carve in one pass (named/ + carved/)
  image       Copy a device/image to an image file (read-only, bad-sector tolerant)
  info        Show the partition / filesystem layout of a source
  verify      Re-hash recovered files against a --report manifest
  triage      Summarize a directory of recovered files
  identify    Identify a file's type from its contents
  list-types  List the file types this build can recover
  mcp         Run as an MCP server so an AI agent can drive recovery
  completions Print a shell completion script
```

### Use from an AI agent (MCP server)

`filerecovery mcp` runs a [Model Context Protocol](https://modelcontextprotocol.io)
server on stdin/stdout, exposing recovery as tools an AI agent (e.g. Claude) can
call: `list_types`, `list_volumes`, `scan`, `scan_status`, `scan_cancel`,
`image` (copy a device/image to an image file, read-only and bad-sector
tolerant), `undelete`, `verify`, `read_file` (read a recovered file's bytes
back, base64, for inspection), `triage` (summarize a recovery directory —
counts per type, largest files, duplicates, empties), and `identify` (detect a
file's type from its contents). It speaks JSON-RPC 2.0 and needs no extra
dependencies or network access.

Because carving or imaging a large drive can take an hour, `scan` and `image`
run as **background jobs**: each returns a `job_id` immediately, the agent polls
`scan_status` for live progress (bytes processed / total) and the final result,
and `scan_cancel` stops a job early (keeping whatever was already produced). The
server stays responsive throughout. `undelete` is metadata-driven and fast, so
it stays synchronous.

Point an MCP client at the binary, for example in a Claude Desktop config:

```json
{
  "mcpServers": {
    "filerecovery": { "command": "filerecovery", "args": ["mcp"] }
  }
}
```

The agent can then detect volumes, carve or undelete into a directory you name,
and verify the results — each tool returns a JSON summary. `scan` and `undelete`
also include a per-file list with each recovered file's path/name, size, and
**SHA-256** (capped at 1000 entries; pass `include_files: false` to omit it), so
the agent can reason over exactly what was recovered. All access is read-only on
the source; the only writes are the recovered files in the output directory you
specify.

### Shell completions

```sh
filerecovery completions bash > /etc/bash_completion.d/filerecovery   # bash
filerecovery completions zsh  > ~/.zfunc/_filerecovery                # zsh
filerecovery completions fish > ~/.config/fish/completions/filerecovery.fish
```

Supported shells: `bash`, `zsh`, `fish`, `powershell`, `elvish`.

### Image a failing drive first (recommended)

If the drive may be failing, copy it once and recover from the copy — every
later pass then reads the image instead of stressing the dying hardware again:

```sh
sudo filerecovery image /dev/sdb card.img      # read-only, bad-sector tolerant
filerecovery scan card.img -o recovered        # then work on the copy
```

The copy is **read-only** on the source. A read that fails is retried at sector
granularity to salvage the good sectors around the bad one; sectors that still
fail are left as zero-filled holes and reported (and the command exits non-zero
so the partial image is obvious). Zero runs are skipped, so an image of a
mostly-empty drive stays small on a filesystem that supports sparse files.

Imaging a large drive can take hours. Pass `--map` to checkpoint progress (the
high-water mark and any unreadable regions) to a small text file as the copy
runs; if it is interrupted, `--resume` continues from where it left off instead
of starting over:

```sh
sudo filerecovery image /dev/sdb card.img --map card.map
# interrupted? pick up where it stopped:
sudo filerecovery image /dev/sdb card.img --map card.map --resume
```

A failing drive often returns data on a later attempt. `--retry-bad <N>` makes
up to `N` extra passes over just the unreadable regions after the main copy,
salvaging sectors the first pass had to zero-fill (it stops early once a pass
recovers nothing):

```sh
sudo filerecovery image /dev/sdb card.img --map card.map --retry-bad 3
```

`image` options:

```text
    --start <BYTES>       Start copying at this offset (default: 0)
    --end <BYTES>         Stop copying at this offset (exclusive)
    --no-sparse           Write every byte, including zero runs (no holes)
    --sector-size <BYTES> Bad-sector retry granularity (default: 512)
    --map <FILE>          Checkpoint progress here for --resume
    --resume              Resume a prior run from its map file
    --retry-bad <PASSES>  Re-read unreadable regions this many extra times
    --summary <FILE>      Write a run summary (.json => JSON, else text)
-q, --quiet               Suppress the progress bar
```

### Inspect the layout of a disk or image

```sh
filerecovery info disk.img
filerecovery info disk.img --deleted   # also count recoverable deleted files
filerecovery info disk.img --json      # machine-readable layout for scripting
```

With `--json`, the detected layout is written to stdout as a single object
(`source`, `source_bytes`, and a `volumes` array of `index`/`filesystem`/`offset`/`size`/`deleted`),
so the tool's output can be consumed by scripts. `deleted` is `null` unless
`--deleted` is also passed.

Example output:

```text
Detected 1 volume(s):

  #   FS         OFFSET         SIZE       DELETED
  -   --         ------         ----       -------
  0   ext2/3/4   17408          32.00 KiB  1
```

The `OFFSET` column is handy if you ever need to pass `--offset` to `undelete`.

### Identify a file by content

Carved files are named by offset, not type — and recovered files may have a
misleading extension. `identify` reports a file's type from its bytes (the same
signatures and structural checks carving uses):

```sh
filerecovery identify recovered/00000007_0x00000000003c1a00.jpg
filerecovery identify mystery.dat --json
```

### Summarize a recovery directory

After recovering, get the shape of what came back — counts per type, the
largest files, content duplicates, and empty files:

```sh
filerecovery triage recovered
filerecovery triage recovered --json   # machine-readable
```

### Undelete from a FAT/exFAT/NTFS/ext/HFS+ card/image (keeps original names)

```sh
filerecovery undelete card.img -o recovered
sudo filerecovery undelete /dev/mmcblk0 -o recovered   # SD card, needs root
```

The filesystem and volume are auto-detected (bare volume, or a GPT or MBR
partition table). Override the location with `--offset <BYTES>` if needed.

`undelete` options:

```text
-o, --output <DIR>     Where to write recovered files (default: ./recovered)
    --offset <BYTES>   Byte offset of the volume (default: auto-detect)
    --min-size <BYTES> Skip deleted files smaller than this
    --dry-run          List what would be recovered without writing any files
    --report <FILE>    Write a report of what was found (.json => JSON, else CSV)
    --summary <FILE>   Write a run summary (.json => JSON, else text)
```

Preview what is recoverable, and save a manifest, without touching the output:

```sh
filerecovery undelete card.img --dry-run --report found.csv
```

The report lists one row per deleted file: filesystem, volume offset, path,
size, whether the data was successfully recovered, and the **SHA-256** of the
recovered bytes. The digest is computed as each file is written (no extra read
pass) and makes the report a forensic manifest — anyone can re-hash a recovered
file and confirm it matches. It is empty for files that could not be recovered
and for `--dry-run` (where nothing is read or written).

### Verify recovered files against a manifest

Both `scan` and `undelete` can write a `--report` manifest that records the
SHA-256 of every recovered file. The `verify` command reads one back and
re-hashes the files to confirm none were altered or lost:

```sh
filerecovery scan card.img -o recovered --report recovered/manifest.csv
filerecovery verify recovered/manifest.csv --base recovered
```

It resolves each manifest row's path relative to `--base` (default: the current
directory), re-hashes the file, and prints a `MISMATCH` or `MISSING` line for
anything that fails. The command exits non-zero if any file mismatched or is
missing, so it can gate a script. Rows without a digest (skipped files, dry
runs) are counted but not checked. Both CSV and JSON manifests are accepted.

### Recover everything in one pass

`recover` runs both strategies for maximum coverage: a filesystem-aware
`undelete` first (restoring names and paths), then carving for whatever the
metadata could not. It writes named files under `<OUTPUT>/named/` and carved
files under `<OUTPUT>/carved/`:

```sh
filerecovery recover card.img -o recovered
```

The carving pass is **content-deduplicated against the undelete results** (by
SHA-256), so `carved/` only holds data that wasn't already recovered by name —
you get the named files plus the extras carving finds, without duplicate copies.
Accepts `--type`, `--min-size`, `--organize` (group `carved/` by type), and
`--offset` (volume offset for the undelete pass).

Add `--unallocated` to carve **only the volume's free space**, skipping clusters
still allocated to live files — so `carved/` holds deleted content with far less
noise (no copies of files that still exist), and the scan is faster:

```sh
filerecovery recover card.img -o recovered --unallocated
```

This reads the filesystem's allocation map (currently supported for FAT, exFAT,
ext2/3/4, NTFS, and HFS+/HFSX); for filesystems whose map isn't parsed yet it
falls back to carving the whole source and says so.

`--report <FILE>` writes a combined manifest of every recovered file (both
passes), each row tagged `named` or `carved` with its path and SHA-256. It is
directly verifiable:

```sh
filerecovery recover card.img -o recovered --report recovered/manifest.csv
filerecovery verify recovered/manifest.csv --base recovered
```

`--summary <FILE>` writes a one-object run summary (counts, bytes, timing).

### Carve a disk image (filesystem-agnostic)

```sh
filerecovery scan card.img -o recovered
```

### Carve a block device (needs root to read it)

```sh
sudo filerecovery scan /dev/mmcblk0 -o recovered     # SD card
sudo filerecovery scan /dev/sdb     -o recovered     # USB stick / disk
```

### Carve only specific types

```sh
filerecovery scan card.img -o recovered --type jpg --type png
```

`scan` options:

```text
-o, --output <DIR>     Where to write recovered files (default: ./recovered)
-t, --type <EXT>       Restrict to a file type; repeatable (default: all)
    --start <BYTES>    Start scanning at this offset
    --end <BYTES>      Stop scanning at this offset (exclusive)
    --min-size <BYTES> Skip carved files smaller than this
    --max-files <N>    Stop after recovering N files
    --allow-nested     Also recover files embedded in other files (e.g. thumbnails)
    --no-validate      Keep every signature match without structural validation
    --dedup            Write identical content (by SHA-256) only once
    --organize         Group recovered files into per-type subdirs (jpg/, png/, ...)
    --unallocated      Carve only the volume's free space (skip live data)
    --report <FILE>    Write a manifest of carved files (.json => JSON, else CSV)
    --summary <FILE>   Write a run summary (.json => JSON, else text)
    --checkpoint <FILE> Checkpoint scan progress here for --resume
    --resume           Resume a prior scan from its checkpoint
-q, --quiet            Hide the progress bar
```

Like `recover`, `scan` accepts `--unallocated` to carve **only the detected
volume's free (unallocated) space**, skipping clusters still in use by live
files — less noise and a faster scan. It reads the filesystem's allocation map
(FAT, exFAT, ext2/3/4, NTFS, HFS+); when no map is available it carves the whole
source and says so. It cannot be combined with `--resume`.

Carving a whole drive can take a long time. Pass `--checkpoint` to record the
scan position and recovered-file tally to a small file as it runs; if the scan
is interrupted, `--resume` continues from where it stopped (reusing the prior
run's tally and dedup set) instead of rescanning from the start:

```sh
filerecovery scan /dev/sdb -o recovered --checkpoint scan.ckpt
# interrupted? continue where it left off:
filerecovery scan /dev/sdb -o recovered --checkpoint scan.ckpt --resume
```

The `--report` manifest lists one row per carved file: output name, type,
source offset, size, and the SHA-256 of the carved bytes — the same verifiable
record the `undelete` report produces, so both recovery modes can be audited.

Both `scan` and `undelete` also accept `--summary <FILE>` to write a one-object
run summary (source, options, counts, per-type breakdown, elapsed time, and a
timestamp) as JSON or plain text — a compact record of the whole run to keep
alongside the per-file manifest.

## Supported file types (`scan` / carving)

| Ext    | Type                                            | How the end is found        |
|--------|-------------------------------------------------|-----------------------------|
| jpg    | JPEG image                                       | footer `FF D9`              |
| png    | PNG image                                        | `IEND` chunk                |
| gif    | GIF image (87a/89a)                              | trailer `00 3B`             |
| bmp    | BMP image                                        | size field in header        |
| ico    | Windows icon                                     | image-directory walk        |
| cur    | Windows cursor                                   | image-directory walk        |
| ani    | Windows animated cursor                          | RIFF size field             |
| jp2    | JPEG 2000 image                                  | ISO box (atom) walk         |
| webp   | WebP image                                       | RIFF size field             |
| heic   | HEIC / HEIF image                               | ISO box (atom) walk         |
| avif   | AVIF image                                       | ISO box (atom) walk         |
| icns   | Apple icon image                                 | size field in header (BE)    |
| cr3    | Canon CR3 raw image                              | ISO box (atom) walk         |
| jxl    | JPEG XL image                                    | ISO box (atom) walk         |
| tif    | TIFF / BigTIFF / raw (DNG/NEF/ARW)              | IFD / strip-tile walk       |
| cr2    | Canon CR2 raw image                              | IFD / strip-tile walk       |
| pdf    | PDF document                                     | `%%EOF`                     |
| zip    | ZIP (also DOCX/XLSX/PPTX/ODT/JAR/APK)            | end-of-central-directory    |
| 7z     | 7-Zip archive                                    | next-header offset + size   |
| rar    | RAR archive (v4 and v5)                          | block-chain walk            |
| cab    | Microsoft Cabinet archive                       | size field in header        |
| sqlite | SQLite database                                 | page size × page count      |
| wav    | WAV audio                                        | RIFF size field             |
| avi    | AVI video                                        | RIFF size field             |
| aiff   | AIFF audio                                        | IFF FORM size field (BE)     |
| aifc   | AIFF-C audio                                      | IFF FORM size field (BE)     |
| mp4    | MP4 / MOV / M4A media                            | ISO box (atom) walk         |
| 3gp    | 3GP video                                        | ISO box (atom) walk         |
| flv    | Flash Video                                      | tag-chain walk              |
| mkv    | Matroska / WebM video                            | EBML segment-size walk      |
| ogg    | Ogg (Vorbis/Opus/Theora)                        | Ogg page-chain walk         |
| asf    | ASF / WMV / WMA media                            | ASF object walk             |
| elf    | ELF executable / shared object                   | section-header table offset |
| exe    | PE executable (EXE/DLL)                          | PE/COFF section table        |
| wasm   | WebAssembly module                               | section (LEB128) walk        |
| ttf    | TrueType font                                    | SFNT table-directory walk    |
| otf    | OpenType font                                    | SFNT table-directory walk    |
| ttc    | TrueType Collection                              | per-font table-directory walk|
| woff   | WOFF web font                                    | size field in header (BE)    |
| woff2  | WOFF2 web font                                   | size field in header (BE)    |
| emf    | Enhanced Metafile (vector)                       | size field in header         |
| mid    | Standard MIDI file                               | MThd / MTrk chunk walk       |
| pcap   | libpcap network capture                          | packet-record walk          |
| pcapng | pcapng network capture                           | block walk                  |

Run `filerecovery list-types` to see what your build supports.

### Adding a new type

Append a `Signature` to the `SIGNATURES` table in
[`src/signatures.rs`](src/signatures.rs). Most formats only need a magic-number
header plus one of the existing extent strategies (`Footer`,
`HeaderSizeLe32`, or `Mp4Atoms`). See [CONTRIBUTING.md](CONTRIBUTING.md) for a
step-by-step walkthrough (signature → extent → validator → test).

## How carving works

1. **Scan.** The device is read sequentially in 8 MiB chunks. Each chunk is
   searched for any registered header magic, with a small carry-over window so
   signatures that straddle a chunk boundary are not missed.
2. **Determine extent.** When a header is found, the file's length is computed
   using its signature's strategy — searching forward for a footer, reading a
   size field, or walking the container's box structure. A per-type maximum
   size guards against runaway carves when an end marker is missing.
3. **Validate.** Before a file is written, its header is checked against the
   format's fixed structure (e.g. a JPEG's first marker, a PNG's `IHDR` chunk,
   a BMP's DIB-header size, SQLite's header constants). A magic that occurred by
   coincidence in unrelated data almost always fails this check and is dropped,
   cutting false positives. The check is conservative — a type with no validator,
   or a file too short to judge, is always kept. Pass `--no-validate` to keep
   every signature match regardless, and the run reports how many candidates the
   validation step rejected.
4. **Write.** The reconstructed byte range is streamed into a new file in the
   output directory, named `<index>_<offset>.<ext>`.

By default, files detected *inside* an already-recovered file (such as a JPEG
thumbnail embedded in a larger JPEG) are skipped to avoid duplicates; pass
`--allow-nested` to recover them too.

The same content can also exist at several *separate* places on a device
(duplicate files, cached copies). Pass `--dedup` to hash each recovered file
(SHA-256) and write byte-identical content only once; the run reports how many
duplicate copies were skipped.

## Limitations

Common to both strategies:

- **Fragmentation:** carving and FAT/exFAT undelete assume a file occupies one
  contiguous run of bytes, so heavily fragmented files may be truncated or have
  trailing garbage. (NTFS and ext undelete are the exceptions — they store
  explicit cluster/extent maps and reassemble fragmented files.)
- A file is only recoverable while its data blocks have not been **overwritten**;
  partially overwritten files come back partially corrupt.

`undelete` specifics:

- Supports **FAT12/16/32**, **exFAT**, **NTFS**, **ext2/3/4**, and **HFS+/HFSX**.
- Recovered files keep their original **modification and access times**. (FAT and
  exFAT store these in local time with no recorded zone, so they are treated as
  UTC — the date is exact but the wall-clock time may be off by your local
  offset. NTFS, ext, and HFS+ store UTC, restored exactly.)
- FAT only: if a deleted file had no long name, the first character of its short
  (8.3) name is lost to the deletion marker and is shown as `_`. exFAT and NTFS
  preserve the full name.
- NTFS and ext reconstruct fragmented files (explicit cluster/extent maps); FAT
  and exFAT assume contiguous data, so badly fragmented files may be partial.
- ext only: when ext4 zeroes the live inode's extents on deletion, recovery
  falls back to an older inode-table copy in the **journal (jbd2)**. If the
  journal has wrapped past it (or the inode was reused), the file is
  unrecoverable by metadata — use `scan`.
- HFS+ only: recovers deleted files from stale **catalog** records left in
  B-tree leaf-node free space, with original folder paths rebuilt from the live
  catalog hierarchy. It follows the eight extents stored inline in the record
  plus any tail extents from the **extents-overflow B-tree**, so fragmented
  files come back whole. A file whose catalog record has been overwritten, or
  whose tail extents survive nowhere, is not recovered by metadata — use `scan`.
- **APFS** is *recognised* and its contained **volumes are listed by name** (so
  `info`/`list_volumes` report the container, its size, and the volumes inside
  it), but it is not recovered from metadata: its copy-on-write design reclaims
  the object map and B-trees through checkpoints, leaving no stale record to
  scavenge. Use `scan` (carving) to recover data from an APFS container.
- **Btrfs** is *recognised* and its **filesystem label**, size, and
  **subvolumes** (by name) are reported by `info`/`list_volumes` — subvolume
  enumeration walks the chunk tree and root tree, translating logical to
  physical addresses through the chunk map. But — like APFS — its copy-on-write
  design leaves no stale metadata to scavenge, so it is not recovered from
  metadata. Use `scan` (carving).

`scan` (carving) specifics:

- Original filenames, timestamps, and folders are not recovered — files are
  named by type and offset.

## Testing

```sh
cargo test
```

The integration tests build synthetic disk images with embedded files and
assert that they are recovered byte-for-byte.

## License

Licensed under the [MIT License](LICENSE).
