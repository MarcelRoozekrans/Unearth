# filerecovery

Recover deleted files from SD cards, USB sticks, hard drives, and disk images.

`filerecovery` offers two complementary recovery strategies:

| Command    | Strategy                  | Restores names? | Works after format? |
|------------|---------------------------|-----------------|---------------------|
| `undelete` | Filesystem-aware (FAT)    | **Yes**         | No (needs metadata) |
| `scan`     | Signature carving         | No              | **Yes**             |

**Use `undelete` first** if the filesystem is still intact (e.g. you just
deleted a file): it reads the FAT directory entries that survive deletion and
restores files with their **original names, folder paths, and sizes**. Fall
back to `scan` (carving) when the filesystem itself is damaged, formatted, or
its partition table is gone.

> These are the same general techniques used by tools like *PhotoRec*,
> *foremost*, *scalpel*, and *testdisk*.

## How each strategy works

### `undelete` — filesystem-aware recovery (FAT12/16/32)

When a file is deleted on FAT, only the first byte of its 32-byte directory
entry is overwritten (with `0xE5`) and its cluster chain is freed. The entry
still records the original name (including the VFAT long name), starting
cluster, and size. `filerecovery` reads those entries, assumes the data was
stored **contiguously** (the common case for cameras/SD cards), and restores
each deleted file to its original path. Whole-disk images with an MBR partition
table are auto-detected, as are bare FAT volumes.

> NTFS, ext4, and exFAT are not yet supported by `undelete` — use `scan` for
> those.

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
  undelete    Recover deleted files from a FAT filesystem (keeps names/paths)
  scan        Carve files from a device or image by signature
  list-types  List the file types this build can recover
```

### Undelete from a FAT card/image (keeps original names)

```sh
filerecovery undelete card.img -o recovered
sudo filerecovery undelete /dev/mmcblk0 -o recovered   # SD card, needs root
```

The FAT volume is auto-detected (bare volume or MBR partition table). Override
with `--offset <BYTES>` if needed.

`undelete` options:

```text
-o, --output <DIR>     Where to write recovered files (default: ./recovered)
    --offset <BYTES>   Byte offset of the FAT volume (default: auto-detect)
    --min-size <BYTES> Skip deleted files smaller than this
```

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
-q, --quiet            Hide the progress bar
```

## Supported file types (`scan` / carving)

| Ext  | Type                                              | How the end is found        |
|------|---------------------------------------------------|-----------------------------|
| jpg  | JPEG image                                         | footer `FF D9`              |
| png  | PNG image                                          | `IEND` chunk                |
| gif  | GIF image (87a/89a)                                | trailer `00 3B`             |
| bmp  | BMP image                                          | size field in header        |
| pdf  | PDF document                                       | `%%EOF`                     |
| zip  | ZIP (also DOCX/XLSX/PPTX/ODT/JAR/APK)              | end-of-central-directory    |
| mp4  | MP4 / MOV / M4A media                              | ISO box (atom) walk         |

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
3. **Write.** The reconstructed byte range is streamed into a new file in the
   output directory, named `<index>_<offset>.<ext>`.

By default, files detected *inside* an already-recovered file (such as a JPEG
thumbnail embedded in a larger JPEG) are skipped to avoid duplicates; pass
`--allow-nested` to recover them too.

## Limitations

Common to both strategies:

- **Fragmented files** are not reassembled. Recovery assumes a file occupies one
  contiguous run of bytes. Heavily fragmented files may be truncated or
  recovered with trailing garbage.
- A file is only recoverable while its data blocks have not been **overwritten**;
  partially overwritten files come back partially corrupt.

`undelete` (FAT) specifics:

- Only **FAT12/16/32** is supported so far (NTFS, ext4, and exFAT are planned).
- File **timestamps** are not yet restored (names, paths, and contents are).
- If a deleted file had no long name, the first character of its short (8.3)
  name is lost to the deletion marker and is shown as `_`.

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
