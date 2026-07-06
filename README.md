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

The filesystem type is auto-detected (bare volume, or a GPT, MBR, APM, or BSD partition
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
`scan`. An HFS+ volume embedded in an old **HFS wrapper** (the layout used on old
Mac media and hybrid CDs, where the partition begins with an HFS `BD` master
directory block pointing at the real HFS+ volume) is followed transparently to
the embedded volume.

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
dependencies or network access. `list_types` reports each type's category, and
`scan`'s `types` argument accepts either extensions or a category name
(`image`, `audio`, …) to recover a whole class at once.

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
and verify the results — each tool returns a JSON summary. `list_volumes`
reports the **partition table** (`partition_scheme` plus a `partitions` array of
type/name/start/size/attributes) alongside the detected filesystems, and each volume's free
(unallocated) space as `free_bytes` (a number, or
`null` for filesystems whose allocation map is not parsed), so the agent can
gauge recoverable space, and it also takes `scan: true` to find
**lost/orphaned partitions** by a whole-source signature scan when the table is
missing or corrupt. `scan` and `undelete`
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
    --hash                SHA-256 the written image (chain of custody)
    --summary <FILE>      Write a run summary (.json => JSON, else text)
-q, --quiet               Suppress the progress bar
```

Pass `--hash` to compute the SHA-256 of the finished image; it is printed and
recorded in the `--summary` (as `sha256`), giving a chain-of-custody digest you
can re-check later. It reads the image back once, so it adds a pass.

### Inspect the layout of a disk or image

```sh
filerecovery info disk.img
filerecovery info disk.img --deleted   # also count recoverable deleted files
filerecovery info disk.img --json      # machine-readable layout for scripting
filerecovery info disk.img --scan      # find lost partitions (whole-disk signature scan)
```

The **partition table** is shown first when present: the scheme (GPT, MBR,
**APM** — the Apple Partition Map used by PowerPC-era Macs, older Mac disks, and
hybrid CDs — or a **BSD disklabel**, used by FreeBSD/OpenBSD/NetBSD on a
whole-disk layout) and each entry's type (a friendly name for known GPT type
GUIDs / MBR type bytes, the APM type string such as `Apple_HFS`, the BSD
filesystem type such as `4.2BSD (FFS)`, or the raw GUID/`0xNN` otherwise), its
name, and its byte range. This surfaces the on-disk layout even
for partitions whose filesystem isn't recovered (an EFI System Partition, a swap
partition, an empty slot). `--json` adds `partition_scheme` and a `partitions`
array. For MBR disks, the **logical partitions** inside an extended partition are
enumerated too (by walking the Extended Boot Record chain), so a disk with more
than four partitions shows all of them, not just the four primaries. Volumes
inside APM partitions are detected and recovered like any other.

For GPT disks, each partition's **unique GUID** (the PARTUUID referenced by
`/etc/fstab`, bootloaders, and `/dev/disk/by-partuuid`) and the **disk GUID** are
reported as well — useful for correlating a recovered partition with a system's
configuration. The text view prints them on `disk GUID:` and per-entry `uuid:`
lines; `--json` / the MCP `list_volumes` tool add `disk_guid` and a per-partition
`uuid` field.

Each partition's notable **attribute flags** are reported too — for GPT the
attribute bits (`required`, `legacy-bios-bootable`, `read-only`, `hidden`,
`no-automount`, `no-block-io`), and for MBR `active` when the boot flag is set.
This helps spot, for instance, a hidden read-only recovery partition. The text
view prints a `flags:` line under the entry; `--json` / the MCP `list_volumes`
tool add a per-partition `attributes` array (empty when none apply).

For GPT disks, if the **primary** header (LBA 1) is missing or corrupt — e.g.
the first sectors were overwritten — the layout is recovered from the **backup
GPT** header and entry array that the spec keeps at the end of the disk. The
text view notes this (`recovered from backup header; primary GPT is missing or
corrupt`) and `--json` / the MCP `list_volumes` tool add a `gpt_from_backup`
flag.

Each volume's **label** (its user-set name) is shown when set — for FAT,
exFAT, NTFS, ext, Btrfs, XFS, and F2FS (the text view prints it on a `label:`
line under the volume; `--json` includes a `label` field).

Each volume's **identifier** — the `UUID=` value that `/etc/fstab` and `blkid`
use to identify a volume — is reported on a `uuid:` line (and as a `uuid` field
in `--json` and the MCP `list_volumes` tool), so a recovered filesystem can be
correlated with a system's configuration. For **ext**, **XFS**, **F2FS**, and
**Btrfs** this is the filesystem UUID; for **FAT**, **exFAT**, and **NTFS** it is
the volume serial number in the conventional form (`XXXX-XXXX` for FAT/exFAT, 16
hex digits for NTFS), exactly as `blkid` reports them. A **Linux swap** area's
UUID and a **LUKS** container's UUID (the value `cryptsetup luksUUID` shows, plus
a LUKS2 label when set) are reported too, from their headers. (This is the
volume's own identifier, distinct from a GPT partition's PARTUUID reported in the
partition table.)

An **ext** volume's **last-mounted path** — the directory it was last mounted on
(e.g. `/`, `/home`), the `Last mounted on` value `dumpe2fs` shows — is reported
on a `last mounted:` line (and as a `last_mounted` field in `--json` and the MCP
`list_volumes` tool) when the superblock records one, which helps identify which
volume a recovered image came from.

An **ext** volume's precise variant — **ext2**, **ext3**, or **ext4** — is
reported on a `version:` line (and as a `version` field in `--json` and the MCP
`list_volumes` tool), distinguished from the `ext2/3/4` family label by the
superblock feature flags the way `blkid` does: ext2 has no journal, ext3 adds
one, and ext4 carries an ext4-only feature such as extents or 64-bit. (`null`
for filesystems with no such sub-version.)

A volume's **creation** and **last-write** times are reported when the
filesystem records them — for **ext** from the superblock's `s_mkfs_time` /
`s_wtime` (the values `dumpe2fs` shows), for **NTFS** from the `$Volume` file's
`$STANDARD_INFORMATION` (the same timestamps Windows keeps), for **HFS+**
from the volume header's `createDate` / `modifyDate`, and for **ISO 9660** from
the Primary Volume Descriptor's creation / modification date. The text view adds
`created:` and `last written:` lines (ISO-8601 UTC) and `--json` / the MCP
`list_volumes` tool add `created_time` / `written_time` fields (Unix seconds,
`null` when unset), so a recovered volume can be dated and correlated with when
it was made and last used.

Each volume's **clean/dirty state** is reported when the filesystem records it —
ext (`s_state`), exFAT (`VolumeFlags`), and NTFS (`$VOLUME_INFORMATION`). A
volume that was not cleanly unmounted is flagged with a `state: dirty` line in
`info` (clean volumes print nothing), and `--json` / the MCP `list_volumes` tool
add a `clean` boolean (`null` when the filesystem has no such flag). A dirty
volume may be inconsistent, so recovery from it is less reliable.

Each volume's **allocation unit** — the cluster size (FAT, exFAT, NTFS, ReFS) or
block size (ext, HFS+, APFS, XFS, F2FS, Btrfs, ISO 9660) the filesystem allocates
space in — is reported on an `alloc unit:` line (and as an `alloc_unit_bytes`
field in `--json` and the MCP `list_volumes` tool). It is the granularity carving
aligns to and bounds each file's slack space. (`null` for backends with no such
unit, e.g. LVM/swap/encrypted/UDF.)

A volume's **inode usage** — roughly how many files and directories it holds —
is reported for **ext** (`s_inodes_count` / `s_free_inodes_count`) and **XFS**
(`sb_icount` / `sb_ifree`) on an `inodes:` line (and as `inodes_used` /
`inodes_total` fields in `--json` and the MCP `list_volumes` tool), so you can
gauge the scale of data a recovered volume held.

Each volume's **free (unallocated) space** is also reported — from the
filesystem's allocation map for FAT, exFAT, ext2/3/4, NTFS, and HFS+/HFSX, and
from the superblock's free/used counts for **XFS** (`sb_fdblocks`) and **Btrfs**
(`total_bytes` − `bytes_used`). The text view prints a `free:` line (bytes and
the unallocated percentage) under the volume, so you can gauge how much deleted
data might be recoverable before running a carve; `--json` includes a
`free_bytes` field. It is `null` for filesystems whose free space is not parsed.
(For XFS and Btrfs this is a reported count only — free-space-only carving via
`--unallocated` still needs an allocation map, which those backends don't expose,
so a whole-source `scan` is the fallback there.)

With `--json`, the detected layout is written to stdout as a single object
(`source`, `source_bytes`, and a `volumes` array of
`index`/`filesystem`/`offset`/`size`/`alloc_unit_bytes`/`inodes_used`/`inodes_total`/`free_bytes`/`deleted`/`label`/`last_mounted`/`created_time`/`written_time`/`contained_volumes`),
so the tool's output can be consumed by scripts. `deleted` is `null` unless
`--deleted` is also passed; `label` and `free_bytes` are `null` when the volume
has none / cannot report it.

Example output:

```text
Detected 1 volume(s):

  #   FS         OFFSET         SIZE       DELETED
  -   --         ------         ----       -------
  0   ext2/3/4   17408          32.00 KiB  1
      free:  20.00 KiB (62.5% unallocated)
```

The `#` index column can be passed straight to `undelete`/`recover` as
`--volume <N>` to recover from just that volume; the `OFFSET` column is there if
you prefer to target it by byte offset with `--offset`.

#### Find lost or corrupt partitions (`--scan`)

If the partition table is missing or damaged, the normal layout shows nothing.
`--scan` reads the **whole source** and probes for filesystem signatures at
aligned offsets (1 MiB by default, set with `--scan-step`), finding volumes that
have no partition-table entry — the same detectors used for normal detection
(FAT, exFAT, NTFS, ReFS, ext, XFS, F2FS, ReiserFS, JFS, NILFS2, GFS2, OCFS2, Minix,
bcachefs, BeFS, UFS/UFS2, EROFS, cramfs, romfs, HFS+, HFS, APFS, Btrfs, LVM2, Linux
MD/RAID, Linux swap, and LUKS/BitLocker):

```sh
filerecovery info disk.img --scan
# ... then recover from a found volume by its offset:
filerecovery undelete disk.img --offset <OFFSET> -o recovered
filerecovery scan     disk.img --start  <OFFSET> -o recovered
```

Or skip the offsets entirely: `undelete --scan` and `recover --scan` run the
same signature scan and recover from **every** volume it finds, so a disk whose
partition table is gone can be recovered in one command:

```sh
filerecovery undelete disk.img --scan -o recovered   # all lost volumes at once
filerecovery recover  disk.img --scan -o recovered   # undelete + carve
```

A deep scan can take a while on a large device. With `--json`, the results are
added as a `scan` array (`filesystem`/`offset`/`size`).

### Identify a file by content

Carved files are named by offset, not type — and recovered files may have a
misleading extension. `identify` reports a file's type from its bytes (the same
signatures and structural checks carving uses):

```sh
filerecovery identify recovered/00000007_0x00000000003c1a00.jpg
filerecovery identify mystery.dat --json
filerecovery identify recovered/*        # label many files at once
```

Several files can be given at once — one line each (or, with `--json`, a JSON
array; a single file still prints one object).

### Summarize a recovery directory

After recovering, get the shape of what came back — counts per category
(image, audio, video, …) and per type, the largest files, content duplicates,
and empty files:

```sh
filerecovery triage recovered
filerecovery triage recovered --json   # machine-readable
```

`triage` also flags **content/extension mismatches** — files whose bytes
identify as a different (known) type than their extension claims, e.g. a `.jpg`
that's really an executable. Common aliases (`jpeg`→`jpg`, `mov`→`mp4`, …) are
normalised first, and only recognised types are compared, so generic blobs and
unknown formats don't produce noise. (`--json` adds a `mismatches` array.)

It also flags **corrupt or truncated files** — a file whose extension names a
type with a known magic signature, but whose content matches no signature at
all (a destroyed/truncated header, or a mislabelled blob). To stay noise-free
this is reserved for types with a direct magic number, so unidentifiable-but-
plausible container subtypes (`docx`, `msg`, …) and empty files are never
called corrupt. (`--json` adds a `corrupt` array; the MCP `triage` tool reports
both `mismatches` and `corrupt`.)

It also reports the **modification-time span** of the recovered files — the
oldest and newest mtime — so you can see what period the data covers (e.g.
`Modified: 2019-03-02T11:04:00Z .. 2024-06-18T08:51:13Z`). `--json` and the MCP
`triage` tool add `oldest_mtime` / `newest_mtime` as Unix seconds.

### Undelete from a FAT/exFAT/NTFS/ext/HFS+ card/image (keeps original names)

```sh
filerecovery undelete card.img -o recovered
sudo filerecovery undelete /dev/mmcblk0 -o recovered   # SD card, needs root
```

The filesystem and volume are auto-detected (bare volume, or a GPT, MBR, APM, or
BSD partition table). Override the location with `--offset <BYTES>` if needed.

`undelete` options:

```text
-o, --output <DIR>     Where to write recovered files (default: ./recovered)
    --offset <BYTES>   Byte offset of the volume (default: auto-detect)
    --volume <N>       Recover from only this volume index (from `info`)
    --min-size <SIZE>  Skip deleted files smaller than this
    --max-size <SIZE>  Skip deleted files larger than this
    --modified-after <DATE>   Only files modified on/after this UTC date
    --modified-before <DATE>  Only files modified on/before this UTC date
    --name <GLOB>      Only files whose name matches this glob (*/?), repeatable
    --exclude-name <GLOB>  Skip files whose name matches this glob (after --name)
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
Accepts `--type`, `--min-size`, `--max-size` (both size bounds apply to the
undelete *and* carving passes), `--modified-after`/`--modified-before` (filter
the undelete pass by each file's modification date — accepts `YYYY-MM-DD` or
`YYYY-MM-DDTHH:MM:SS`, UTC), `--name`/`--exclude-name` (recover only — or skip — files whose name matches a
glob, e.g. `--name '*.jpg,*.png'` or `--exclude-name '*.tmp'`, undelete pass),
`--align` (carve only
sector/cluster-aligned files), `--organize` (group `carved/` by type),
`--offset`/`--volume` (target one volume for the undelete pass — by byte offset
or by `info` index), and `--dry-run` (preview both
passes — counts, sizes, and the `--report` manifest — without writing anything).

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

`--type` also accepts a *category* to select a whole class at once —
`image`, `audio`, `video`, `document`, `archive`, `executable`, `font`, or
`system`:

```sh
filerecovery scan card.img -o recovered --type image
```

`scan` options:

```text
-o, --output <DIR>     Where to write recovered files (default: ./recovered)
-t, --type <EXT|CAT>   Restrict to a file type or category; repeatable (default: all)
    --exclude <EXT|CAT> Exclude a type or category (applied after --type)
    --start <SIZE>     Start scanning at this offset (accepts K/M/G/T suffixes)
    --end <SIZE>       Stop scanning at this offset (exclusive)
    --min-size <SIZE>  Skip carved files smaller than this
    --max-size <SIZE>  Skip carved files larger than this
    --align <SIZE>     Only carve files starting on a multiple of this (e.g. 512)
    --max-files <N>    Stop after recovering N files
    --allow-nested     Also recover files embedded in other files (e.g. thumbnails)
    --no-validate      Keep every signature match without structural validation
    --dedup            Write identical content (by SHA-256) only once
    --organize         Group recovered files into per-type subdirs (jpg/, png/, ...)
    --dry-run          Preview what would be recovered without writing any files
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
| jpg    | JPEG image                                       | `FF D9`, nesting-aware      |
| png    | PNG image                                        | `IEND` chunk                |
| mng    | MNG animation (PNG-family)                       | `MEND` chunk                |
| jng    | JNG image (PNG-family JPEG)                       | `IEND` chunk                |
| ras    | Sun raster image (.ras/.sun)                     | header + colormap + data    |
| gif    | GIF image (87a/89a)                              | block walk to trailer       |
| bmp    | BMP image                                        | size field in header        |
| psd    | Photoshop document (PSD/PSB)                      | header + sections + image   |
| glb    | glTF binary (3D model)                           | size field in header        |
| ico    | Windows icon                                     | image-directory walk        |
| cur    | Windows cursor                                   | image-directory walk        |
| ani    | Windows animated cursor                          | RIFF size field             |
| jp2    | JPEG 2000 image                                  | ISO box (atom) walk         |
| j2k    | JPEG 2000 codestream                             | EOC marker `FF D9`          |
| swf    | Flash movie (uncompressed FWS)                   | length field in header (LE) |
| webp   | WebP image                                       | RIFF size field             |
| heic   | HEIC / HEIF image                               | ISO box (atom) walk         |
| avif   | AVIF image                                       | ISO box (atom) walk         |
| icns   | Apple icon image                                 | size field in header (BE)    |
| cr3    | Canon CR3 raw image                              | ISO box (atom) walk         |
| jxl    | JPEG XL image                                    | ISO box (atom) walk         |
| ktx2   | KTX2 GPU texture (glTF / WebGPU)                | max section offset + length |
| tif    | TIFF / BigTIFF / raw (DNG/NEF/ARW)              | IFD / strip-tile walk       |
| cr2    | Canon CR2 raw image                              | IFD / strip-tile walk       |
| pdf    | PDF document                                     | `%%EOF`                     |
| djvu   | DjVu document                                    | IFF FORM length             |
| rtf    | Rich Text Format document                        | outer `{ }` group match     |
| zip    | ZIP (DOCX/XLSX/PPTX/ODT/EPUB/JAR/APK auto-named) | EOCD, geometry-validated    |
| 7z     | 7-Zip archive                                    | next-header offset + size   |
| rar    | RAR archive (v4 and v5)                          | block-chain walk            |
| zst    | Zstandard compressed                             | frame block walk            |
| lz4    | LZ4 compressed                                   | frame block walk            |
| cab    | Microsoft Cabinet archive                       | size field in header        |
| ar     | Unix ar archive (deb / static lib)              | member-chain walk           |
| tar    | tar archive (POSIX / GNU ustar)                 | 512-byte member-chain walk  |
| cpio   | cpio archive (newc; initramfs / RPM)            | entry-chain walk to TRAILER |
| pak    | Quake PAK archive (game assets)                 | directory offset + length   |
| zim    | ZIM archive (offline Wikipedia / Kiwix)         | checksum position + MD5     |
| unity3d | Unity asset bundle (UnityFS, game assets)      | total-size field in header  |
| gguf   | GGUF model (llama.cpp / local LLM weights)      | tensor-table walk to data end |
| npy    | NumPy array (np.save, ML/scientific)            | header + shape × itemsize   |
| img    | Android boot image (boot.img, v0–v4)            | sum of page-rounded sections |
| dtbo   | Android DTBO/DTB image (device-tree overlays)   | total_size field in header  |
| img    | Android vendor_boot image (GKI, v3/v4)          | sum of page-rounded sections |
| md2    | Quake II model (animated mesh)                  | ofs_end field in header     |
| squashfs | SquashFS image (Snap / AppImage / firmware)   | bytes_used in superblock    |
| uimage | U-Boot uImage (router/IoT firmware)             | 64-byte header + data size  |
| dtb    | Device Tree Blob (FDT, embedded Linux)          | totalsize field in header   |
| trx    | TRX firmware (Broadcom/OpenWrt routers)         | len field in header         |
| sqlite | SQLite database                                 | page size × page count      |
| wav    | WAV audio                                        | RIFF size field             |
| sf2    | SoundFont 2 (sampled instruments)               | RIFF size field             |
| mp3    | MP3 audio                                        | ID3v2 tag or frame-sync walk |
| aac    | AAC audio (ADTS)                                 | ADTS frame-length walk      |
| avi    | AVI video                                        | RIFF size field             |
| aiff   | AIFF audio                                        | IFF FORM size field (BE)     |
| aifc   | AIFF-C audio                                      | IFF FORM size field (BE)     |
| mp4    | MP4 media                                        | ISO box (atom) walk         |
| mov    | QuickTime movie (iPhone/Mac)                    | ISO box (atom) walk         |
| m4a    | M4A audio                                        | ISO box (atom) walk         |
| m4v    | M4V video                                        | ISO box (atom) walk         |
| 3gp    | 3GP video                                        | ISO box (atom) walk         |
| flv    | Flash Video                                      | tag-chain walk              |
| mkv    | Matroska / WebM video                            | EBML segment-size walk      |
| ivf    | IVF video (AV1 / VP9 / VP8 bitstream)            | frame-count walk in header  |
| ts     | MPEG transport stream (DVB/DVR)                  | 188-byte packet-sync walk   |
| mpg    | MPEG program stream (DVD/VOB)                    | pack/PES walk to end code    |
| ogg    | Ogg (Vorbis/Opus/Theora)                        | Ogg page-chain walk         |
| qoa    | QOA audio (Quite OK Audio)                       | frame-chain walk (fsize)    |
| asf    | ASF / WMV / WMA media                            | ASF object walk             |
| elf    | ELF executable / shared object                   | section-header table offset |
| exe    | PE executable (EXE/DLL)                          | PE/COFF section table        |
| pdb    | Program Database (MSVC debug symbols)           | MSF block-size × block-count |
| eps    | Encapsulated PostScript (binary/DOS)            | section offset+length table  |
| macho  | Mach-O binary (macOS/iOS)                        | segment + link-edit extents  |
| dex    | Android Dalvik executable                        | file-size field in header   |
| wasm   | WebAssembly module                               | section (LEB128) walk        |
| ttf    | TrueType font                                    | SFNT table-directory walk    |
| otf    | OpenType font                                    | SFNT table-directory walk    |
| ttc    | TrueType Collection                              | per-font table-directory walk|
| woff   | WOFF web font                                    | size field in header (BE)    |
| woff2  | WOFF2 web font                                   | size field in header (BE)    |
| pcf    | PCF bitmap font (X11)                            | max table offset + size     |
| emf    | Enhanced Metafile (vector)                       | size field in header         |
| wmf    | Windows Metafile (vector, placeable too)         | mtSize words in header       |
| mid    | Standard MIDI file                               | MThd / MTrk chunk walk       |
| pcap   | libpcap network capture                          | packet-record walk          |
| pcapng | pcapng network capture                           | block walk                  |
| evtx   | Windows Event Log                                | chunk count in header       |
| journal | systemd journal (Linux logs)                   | header size + arena size    |
| regf   | Windows registry hive                            | base block + hive-bins size |
| wim    | Windows Imaging (WIM/ESD)                        | resource-table extents      |
| icc    | ICC colour profile                               | size field in profile header |
| shp    | ESRI Shapefile                                   | length field in header (BE)  |
| blend  | Blender file                                     | block chain to ENDB block   |
| nes    | NES ROM (iNES / NES 2.0)                         | PRG/CHR bank counts         |
| gb     | Game Boy / Game Boy Color ROM                    | size code in header (0x148) |
| wad    | Doom WAD (IWAD/PWAD)                              | lump count + directory offset |
| au     | Sun/NeXT audio (.au/.snd)                        | data offset + size in header |
| md     | Sega Mega Drive / Genesis ROM                    | ROM end address in header    |
| voc    | Creative Voice audio (.voc)                      | block chain to terminator   |
| amr    | AMR audio (mobile voice, .amr)                   | fixed-size frame walk       |
| wv     | WavPack lossless audio (.wv)                     | wvpk block-chain walk       |
| ape    | Monkey's Audio lossless (.ape)                   | sum of descriptor segments  |
| dsf    | DSF DSD audio (.dsf, SACD-style)                 | total size in header field  |
| dff    | DSDIFF DSD audio (.dff)                          | FRM8 form size + 12         |
| psexe  | PlayStation executable (PS-X EXE)                | 2 KiB header + text size     |
| simg   | Android sparse image (fastboot/factory)          | sum of chunk sizes          |
| iso    | ISO 9660 disc image (CD/DVD, installers)         | volume size × block size    |
| fli    | Autodesk FLIC animation (FLI/FLC)                | total size in header field  |
| dpx    | DPX film frame (SMPTE ST 268, VFX)               | total size in header field  |
| cin    | Cineon film frame (Kodak, film scanning)         | total size in header field  |
| applesingle | AppleSingle container (RFC 1740)            | max entry offset + length   |
| appledouble | AppleDouble sidecar (`._` resource fork)    | max entry offset + length   |
| ole    | Compound File (OLE2) — doc/xls/ppt/msg/msi       | FAT walk to last used sector |
| pst    | Outlook data file (PST/OST, Unicode)             | ibFileEof field in header   |

Run `filerecovery list-types` to see what your build supports.

Compound files (`.ole`) are refined to their real extension — `.doc`, `.xls`,
`.ppt` (legacy Office), `.msg` (Outlook message), or `.msi` (Windows Installer)
— by inspecting the directory stream names, or the root storage CLSID for an
installer, the same way a carved ZIP becomes `.docx`/`.xlsx`/etc. An
unrecognised compound file stays `.ole`.

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
   a BMP's DIB-header size, SQLite's header constants, a PDF version string, a
   TIFF IFD offset, a CAB's reserved fields, a WASM/DEX version, a PSD
   version/reserved fields, an Ogg/FLV header). A magic that
   occurred by
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
- **HFS** (the original **Mac OS Standard** filesystem, 1985–1998, found on old
  Mac floppies, disks, and CDs — the predecessor of HFS+) is *recognised* and its
  size and **volume name** are reported by `info`/`list_volumes` (from the `BD`
  Master Directory Block 1024 bytes in). Its catalog is a different, long-obsolete
  on-disk B-tree from HFS+, so it is not recovered from metadata — use `scan`
  (carving). An MDB that instead *wraps* an embedded HFS+ volume is followed to
  the HFS+ volume and recovered as HFS+ (see the **HFS wrapper** note above), so
  only a *pure* old-HFS volume is reported as `HFS`.
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
- **ReFS** (Microsoft's Resilient File System — Windows Server, Storage Spaces,
  and Dev Drive) is *recognised* and its size is reported by `info`/`list_volumes`
  (from the `ReFS`/`FSRS` signatures and geometry in the volume boot record). But
  — like APFS and Btrfs — its copy-on-write design leaves no stale metadata to
  scavenge (and the format is undocumented), so it is not recovered from metadata.
  Use `scan` (carving).
- **XFS** (the high-performance journaling filesystem common on Linux servers and
  NAS appliances — the RHEL/CentOS default) is *recognised* and its size and
  **label** are reported by `info`/`list_volumes` (from the `XFSB` superblock).
  But modern XFS zeroes an inode's data-extent list on unlink, leaving no stale
  mapping to scavenge, so it is not recovered from metadata. Use `scan` (carving).
- **F2FS** (the Flash-Friendly File System — internal storage on most Android
  phones, and many SD cards and embedded devices) is *recognised* and its size
  and **label** are reported by `info`/`list_volumes` (from the `0xF2F52010`
  superblock). But its log-structured, copy-on-write design leaves no stale
  metadata to scavenge, so it is not recovered from metadata. Use `scan`
  (carving).
- **ReiserFS** (Hans Reiser's journaling filesystem — the default on SUSE and
  widely used on Linux through the 2000s, now deprecated and removed from the
  mainline kernel) is *recognised* and its size, **label**, and **UUID** are
  reported by `info`/`list_volumes` (from the `ReIsEr2Fs`/`ReIsErFs` superblock,
  64 KiB in for 3.6 or 8 KiB in for the older 3.5). Its single balanced-tree
  layout is unlike the ext family and the format is long obsolete, so it is not
  recovered from metadata — use `scan` (carving).
- **JFS** (IBM's Journaled File System, ported to Linux from AIX/OS2) is
  *recognised* and its size, **label**, and **UUID** are reported by
  `info`/`list_volumes` (from the `JFS1` aggregate superblock 32 KiB in). Its
  inode/directory B+tree layout is unlike the ext family, so it is not recovered
  from metadata — use `scan` (carving).
- **NILFS2** (the New Implementation of a Log-structured File System — a Linux
  filesystem with continuous snapshotting) is *recognised* and its size,
  **label**, and **UUID** are reported by `info`/`list_volumes` (from the
  superblock 1 KiB in, magic `0x3434`). Like the other copy-on-write/log-structured
  filesystems here, it leaves no stale metadata to scavenge, so it is not recovered
  from metadata — use `scan` (carving).
- **GFS2** (Red Hat's Global File System 2 — a shared-disk cluster filesystem,
  and the original **GFS**) is *recognised* and its **lock table** (e.g.
  `cluster:fs`) and **UUID** are reported by `info`/`list_volumes` (from the
  superblock 64 KiB in, big-endian magic `0x01161970`). Its metadata is
  cluster-coordinated and a member device is meaningful only as part of the
  cluster, so it is not recovered from metadata — use `scan` (carving). The
  superblock records no total size, so the source span is reported.
- **OCFS2** (the Oracle Cluster File System 2 — also a shared-disk Linux cluster
  filesystem) is *recognised* and its size, **label**, and **UUID** are reported
  by `info`/`list_volumes` (from the `OCFSV2` superblock inode at block #2). Like
  GFS2 its metadata is cluster-managed, so it is not recovered from metadata —
  use `scan` (carving).
- **Minix** (the filesystem the earliest Linux ran on, still found on boot
  floppies, small/embedded media, and RAM disks) is *recognised* and its
  on-disk **version** (v1/v2/v3) and size are reported by `info`/`list_volumes`
  (from the superblock in the second 1 KiB block). Minix has no on-disk label or
  UUID, and the format is long superseded, so it is not recovered from metadata —
  use `scan` (carving).
- **bcachefs** (the modern copy-on-write Linux filesystem merged into the kernel
  in 6.7, with built-in multi-device, tiering, and checksumming) is *recognised*
  and its **label** and **UUID** are reported by `info`/`list_volumes` (from the
  superblock 4 KiB in, identified by a 16-byte magic). Like the other
  copy-on-write filesystems here it leaves no stale metadata to scavenge, so it is
  not recovered from metadata — use `scan` (carving). Its total size spans member
  devices rather than a single superblock field, so the source span is reported.
- **BeFS** (the Be File System — the native filesystem of BeOS and of **Haiku**,
  its modern open-source successor) is *recognised* and its **volume name** and
  size are reported by `info`/`list_volumes` (from the superblock 512 bytes in,
  identified by dual magics, big- or little-endian). Its B+tree metadata is
  specialised, so it is not recovered from metadata — use `scan` (carving).
- **UFS / UFS2** (the BSD Fast File System — the traditional filesystem of
  FreeBSD/OpenBSD/NetBSD and Solaris) is *recognised* and its version, size, and
  block size are reported by `info`/`list_volumes` (from the superblock 8 KiB in
  for UFS1 or 64 KiB in for UFS2, magic at 0x55C, either byte order). Its
  cylinder-group layout is unlike the ext family, so it is not recovered from
  metadata — use `scan` (carving).
- **EROFS** (the Enhanced Read-Only File System — used for Android system/vendor
  images and ChromeOS) is *recognised* and its size, **label**, **UUID**, and
  build time are reported by `info`/`list_volumes` (from the superblock 1 KiB in,
  magic `0xE0F5E1E2`). Being read-only it has no deleted files to undelete, so use
  `scan` (carving) to extract its (compressed) contents.
- **cramfs** (the Compressed ROM File System — initrds, embedded systems, and
  router/appliance firmware) is *recognised* and its size and **label** are
  reported by `info`/`list_volumes` (from the `0x28CD3D45` magic plus the
  `Compressed ROMFS` signature at offset 0x10, either byte order). Being read-only
  it has no deleted files to undelete — use `scan` (carving).
- **romfs** (the minimal ROM File System — small initrds and embedded systems) is
  *recognised* and its size and **volume name** are reported by
  `info`/`list_volumes` (from the 8-byte `-rom1fs-` magic). Being read-only it has
  no deleted files to undelete — use `scan` (carving).
- **LVM2** (the Linux Logical Volume Manager) physical volumes are *recognised*
  from their `LABELONE` / `LVM2 001` on-disk label, and the PV's size is reported
  by `info`/`list_volumes`. The logical volumes inside are not mapped, so recover
  with a whole-source `scan` (or `--scan`), which finds the filesystems inside the
  LVs at their physical offsets.
- **Linux MD/RAID** members are *recognised* from their version-1 `mdadm`
  superblock (1.1 at the device start, 1.2 at 4 KiB in), and `info`/`list_volumes`
  report the array's **RAID level** (e.g. `Linux RAID5`), **UUID**, name, and the
  member's data size. The array is not assembled, so assemble it with `mdadm
  --assemble` first and recover from the assembled device (or `scan` the member to
  carve whatever lies contiguously within it). The 1.0 layout (superblock near the
  end of the device) is not detected.
- **Linux swap** areas are *recognised* (rather than shown as an unrecognised
  volume) and their size, **UUID**, and **label** are reported by
  `info`/`list_volumes`, read from the version-2 swap header (`SWAPSPACE2`). A
  swap partition holds no files to recover, but identifying it by its `UUID=`
  (the value `/etc/fstab` uses) helps confirm which disk an image came from and
  rules the area out as a place to look for lost data.
- **UDF** (optical discs — DVD/Blu-ray — and many large USB drives and camcorder
  cards) is *recognised* and reported by `info`/`list_volumes` (via its Volume
  Recognition Sequence at sector 16), but its descriptor metadata is not parsed,
  so it is not recovered from metadata. Use `scan` (carving).
- **ISO 9660** (data CD/DVD discs and `.iso` images) is recognised by
  `info`/`list_volumes` (with its size and volume label from the Primary Volume
  Descriptor at sector 16), and its **files are extracted with their original
  names and folder paths** by `undelete`/`recover`, walking the directory tree —
  far better than carving, which loses names and structure. Long names are
  recovered from both **Joliet** (Windows-authored discs — UCS-2) and **Rock
  Ridge** (`NM` entries on Linux/macOS-authored discs) — including long names
  that spill into Rock Ridge continuation (`CE`) areas — so files come back with
  their full filenames either way. Each extracted file's **recording date** (from
  its directory record) is preserved as the output file's modification time, just
  as the undelete backends preserve a deleted file's timestamps. Files split
  across **multi-extent** records (how ISO 9660 stores files larger than ~4 GiB)
  are reassembled into one file.
  A hybrid UDF disc is reported as UDF. A disc with an **El Torito** boot record
  is flagged as bootable with its boot platform(s) — e.g. `El Torito (BIOS,
  UEFI)`, read from the boot catalog — distinguishing a legacy-BIOS, UEFI, or
  hybrid image from a pure data disc (a `boot:` line in `info`, a `boot` field in
  `--json` / `list_volumes`).
- **Encrypted volumes** — **LUKS** (LUKS1/LUKS2) and **BitLocker** — are
  *recognised* and reported by `info`/`list_volumes`, but they hold only
  ciphertext until unlocked, so nothing can be recovered (and carving the raw
  container is useless). Unlock first — `cryptsetup open` on Linux, or Windows
  for BitLocker — then image the mapped plaintext device and recover from that.

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
