# filerecovery

Recover deleted files from SD cards, USB sticks, hard drives, and disk images
using **signature-based file carving**.

Instead of parsing a specific filesystem (FAT32 / exFAT / NTFS / ext4),
`filerecovery` scans the raw bytes of a device for known file *signatures*
(magic numbers) and reconstructs each file's extent. Because it ignores the
filesystem entirely, it can recover data even after:

- a file was deleted (the data blocks usually remain until overwritten),
- the card/drive was **quick-formatted**,
- the partition table was lost or corrupted.

The trade-off is that carving cannot restore original **filenames** or
directory structure — recovered files are named by their type and the byte
offset where they were found.

> This is the same general technique used by tools like *PhotoRec*, *foremost*,
> and *scalpel*.

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
  scan        Scan a device or image and recover files
  list-types  List the file types this build can recover
```

### Scan a disk image

```sh
filerecovery scan card.img -o recovered
```

### Scan a block device (needs root to read it)

```sh
sudo filerecovery scan /dev/mmcblk0 -o recovered     # SD card
sudo filerecovery scan /dev/sdb     -o recovered     # USB stick / disk
```

### Recover only specific types

```sh
filerecovery scan card.img -o recovered --type jpg --type png
```

### Useful options

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

## Supported file types

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

## How it works

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

- **Fragmented files** are not reassembled. Carving assumes a file occupies one
  contiguous run of bytes. Heavily fragmented files may be truncated or
  recovered with trailing garbage.
- Original **filenames, timestamps, and folders** are not recovered.
- Some recovered files may be partially corrupt if they were partially
  overwritten before recovery.

## Testing

```sh
cargo test
```

The integration tests build synthetic disk images with embedded files and
assert that they are recovered byte-for-byte.

## License

MIT
