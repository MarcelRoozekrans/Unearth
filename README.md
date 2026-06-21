# filerecovery

Recover deleted files from SD cards, USB sticks, hard drives, and disk images.

`filerecovery` offers two complementary recovery strategies:

| Command    | Strategy                               | Restores names? | Works after format? |
|------------|----------------------------------------|-----------------|---------------------|
| `undelete` | Filesystem-aware (FAT/exFAT/NTFS/ext)  | **Yes**         | No (needs metadata) |
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

### `undelete` — filesystem-aware recovery (FAT12/16/32, exFAT, NTFS, ext2/3/4)

The filesystem type is auto-detected (bare volume, or a GPT or MBR partition
table), and FAT, exFAT, NTFS, and ext2/3/4 are all handled by the same
`undelete` command.

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
  live device:
  ```sh
  sudo dd if=/dev/sdb of=card.img bs=4M conv=noerror,sync status=progress
  filerecovery scan card.img -o recovered
  ```

## Install / build

Requires a Rust toolchain (1.74+).

```sh
cargo build --release
# binary at target/release/filerecovery
```

## Usage

```text
filerecovery <COMMAND>

Commands:
  undelete    Recover deleted files from FAT/exFAT/NTFS/ext (keeps names/paths)
  scan        Carve files from a device or image by signature
  info        Show the partition / filesystem layout of a source
  list-types  List the file types this build can recover
```

### Inspect the layout of a disk or image

```sh
filerecovery info disk.img
filerecovery info disk.img --deleted   # also count recoverable deleted files
```

Example output:

```text
Detected 1 volume(s):

  #   FS         OFFSET         SIZE       DELETED
  -   --         ------         ----       -------
  0   ext2/3/4   17408          32.00 KiB  1
```

The `OFFSET` column is handy if you ever need to pass `--offset` to `undelete`.

### Undelete from a FAT/exFAT/NTFS/ext card/image (keeps original names)

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
```

Preview what is recoverable, and save a manifest, without touching the output:

```sh
filerecovery undelete card.img --dry-run --report found.csv
```

The report lists one row per deleted file: filesystem, volume offset, path,
size, and whether the data was successfully recovered.

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
-q, --quiet            Hide the progress bar
```

## Supported file types (`scan` / carving)

| Ext    | Type                                            | How the end is found        |
|--------|-------------------------------------------------|-----------------------------|
| jpg    | JPEG image                                       | footer `FF D9`              |
| png    | PNG image                                        | `IEND` chunk                |
| gif    | GIF image (87a/89a)                              | trailer `00 3B`             |
| bmp    | BMP image                                        | size field in header        |
| webp   | WebP image                                       | RIFF size field             |
| heic   | HEIC / HEIF image                               | ISO box (atom) walk         |
| pdf    | PDF document                                     | `%%EOF`                     |
| zip    | ZIP (also DOCX/XLSX/PPTX/ODT/JAR/APK)            | end-of-central-directory    |
| 7z     | 7-Zip archive                                    | next-header offset + size   |
| cab    | Microsoft Cabinet archive                       | size field in header        |
| sqlite | SQLite database                                 | page size × page count      |
| wav    | WAV audio                                        | RIFF size field             |
| avi    | AVI video                                        | RIFF size field             |
| mp4    | MP4 / MOV / M4A media                            | ISO box (atom) walk         |

Run `filerecovery list-types` to see what your build supports.

### Adding a new type

Append a `Signature` to the `SIGNATURES` table in
[`src/signatures.rs`](src/signatures.rs). Most formats only need a magic-number
header plus one of the existing extent strategies (`Footer`,
`HeaderSizeLe32`, or `Mp4Atoms`).

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

- Supports **FAT12/16/32**, **exFAT**, **NTFS**, and **ext2/3/4**.
- Recovered files keep their original **modification and access times**. (FAT and
  exFAT store these in local time with no recorded zone, so they are treated as
  UTC — the date is exact but the wall-clock time may be off by your local
  offset. NTFS and ext store UTC, restored exactly.)
- FAT only: if a deleted file had no long name, the first character of its short
  (8.3) name is lost to the deletion marker and is shown as `_`. exFAT and NTFS
  preserve the full name.
- NTFS and ext reconstruct fragmented files (explicit cluster/extent maps); FAT
  and exFAT assume contiguous data, so badly fragmented files may be partial.
- ext only: when ext4 zeroes the live inode's extents on deletion, recovery
  falls back to an older inode-table copy in the **journal (jbd2)**. If the
  journal has wrapped past it (or the inode was reused), the file is
  unrecoverable by metadata — use `scan`.

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

MIT
