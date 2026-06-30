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

- **Monkey's Audio is carved** — `scan` now recovers `.ape` lossless-audio
  files (version 3.98 and later). The exact length is the sum of the segment
  byte counts in the file's descriptor (descriptor, header, seek table, WAV
  header, APE frame data, and terminating data). The version and descriptor
  size are checked to reject a coincidental magic.
- **WavPack audio is carved** — `scan` now recovers `.wv` lossless-audio files.
  The exact length is found by walking the `wvpk` block chain to the last whole
  block, with the first block's format version checked to reject a coincidental
  magic.
- **Cineon film frames are carved** — `scan` now recovers `.cin` images, the
  Kodak film-scan format DPX descends from. The exact length comes from the
  total-file-size field at offset 0x14 of the big-endian file-information
  header.
- **DPX film frames are carved** — `scan` now recovers `.dpx` images (SMPTE
  ST 268, the standard frame format in film scanning and VFX). Both byte
  orders (`SDPX`/`XPDS`) are recognised, and the exact length comes from the
  total-file-size field at offset 0x10 of the generic file header.
- **Autodesk FLIC animations are carved** — `scan` now recovers `.fli`/`.flc`
  palette animations (Autodesk Animator / Animator Pro, old games and demos).
  The exact length is the total-size field at the start of the 128-byte header.
  The format magic (`0xAF11`/`0xAF12`), colour depth, frame count, and frame
  dimensions are range-checked to reject a coincidental two-byte magic.
- **ISO 9660 disc images are carved** — `scan` now recovers `.iso` images
  (CD/DVD filesystems, distro installers, optical-media backups). The exact
  length comes from the primary volume descriptor at sector 16: the volume
  space size multiplied by the logical block size. The descriptor type/version
  and the both-endian halves of each field must agree, rejecting a coincidental
  `CD001` match. This complements the existing ISO 9660 filesystem reader.
- **Android sparse images are carved** — `scan` now recovers `.simg` sparse
  images (the format `fastboot` and Android factory images use), with the exact
  length summed from each chunk header's on-disk size. The header sizes and chunk
  count are range-checked to reject a coincidental magic.
- **romfs volumes are recognised** — the minimal ROM File System (small initrds
  and embedded systems) is now detected from its `-rom1fs-` magic, so `info` /
  `list_volumes` report its size and volume name instead of leaving it
  unrecognised. Read-only, so use `scan` (carving) for its contents.
- **cramfs volumes are recognised** — the Compressed ROM File System (initrds,
  embedded systems, and router/appliance firmware) is now detected from its
  `0x28CD3D45` magic and `Compressed ROMFS` signature, so `info` / `list_volumes`
  report its size and label instead of leaving it unrecognised. Read-only, so use
  `scan` (carving) for its contents.
- **EROFS volumes are recognised** — the Enhanced Read-Only File System (used for
  Android system/vendor images and ChromeOS) is now detected from its
  `0xE0F5E1E2` superblock, so `info` / `list_volumes` report its size, label,
  UUID, and build time instead of leaving it unrecognised. Being read-only it has
  no deleted files to undelete — use `scan` (carving) for its contents.
- **UFS / UFS2 volumes are recognised** — the BSD Fast File System (also Solaris
  and historical Unix) is now detected from its superblock magic (8 KiB in for
  UFS1, 64 KiB for UFS2), in either byte order, so `info` / `list_volumes` report
  its version, size, and block size instead of leaving it unrecognised. Its
  cylinder-group layout is unlike the filesystems recovered from metadata, so use
  `scan` (carving).
- **BSD disklabels are read** — `info` / `list_volumes` now recognise a BSD
  disklabel (FreeBSD/OpenBSD/NetBSD on a whole-disk "dangerously dedicated"
  layout) as a fourth partition scheme alongside GPT, MBR, and APM, listing each
  partition's filesystem type, letter, and byte range. Both byte orders are
  handled, and the dual `d_magic` is required to avoid false matches.
- **Volume timestamps reported for NILFS2 and JFS** — `info` now shows NILFS2's
  creation (`s_ctime`) and last-write (`s_wtime`) times and JFS's last-updated
  time (`s_time`), the same way the ext / NTFS / HFS+ / ISO 9660 backends already
  report volume timestamps.
- **Clean/dirty state reported for ReiserFS and NILFS2** — `info` now flags
  whether these volumes were cleanly unmounted (a dirty volume is a sign the
  filesystem may need a check and that recovery may be less reliable), the same
  as for ext / exFAT / NTFS.
- **Free space reported for ReiserFS, NILFS2, and BeFS** — `info` /
  `list_volumes` now show how much of these volumes is unallocated, read from the
  superblock's free/used-block counts (the same as XFS and Btrfs already do).
- **Allocation unit reported for more filesystems** — `info` / `list_volumes`
  now show the allocation-unit (block/cluster) size for ReiserFS, JFS, NILFS2,
  GFS2, OCFS2, Minix, bcachefs, and BeFS, the same as for the filesystems that
  already exposed it. It documents the volume's geometry and bounds per-file
  slack when carving within one of these volumes.
- **PlayStation executables are carved** — `scan` now recovers PS1 `PS-X EXE`
  programs, with the exact length taken from the 2 KiB header plus the
  text-section size at offset 0x1C. A non-zero, 2 KiB-aligned text size guards
  the match alongside the 8-byte magic.
- **AMR audio is carved** — `scan` now recovers `.amr` (AMR narrowband) audio —
  the codec mobile phones use for voice recordings and voicemail — by walking the
  fixed-size speech frames from the `#!AMR\n` header to the end of the stream.
- **Creative Voice (`.voc`) audio is carved** — `scan` now recovers Sound
  Blaster / DOS-era `.voc` audio files, walking the data-block chain from the
  header to the terminator block to find the exact end. The 20-byte ASCII magic
  makes a false match effectively impossible.
- **Sega Mega Drive / Genesis ROMs are carved** — `scan` now recovers `.md` ROM
  images, anchored on the `SEGA` cartridge-header signature at 0x100 with the
  exact length taken from the ROM end address in the header. The start address
  and a plausible end address are checked to reject a coincidental match. (This
  is the plain, non-interleaved ROM layout.)
- **Sun/NeXT `.au` audio is carved** — `scan` now recovers `.au` / `.snd` audio
  files (the default sound format in Java and classic Unix), with the exact length
  taken from the header's data offset and data size. Streamed files with an
  unknown size are skipped, and the data offset and encoding code are
  range-checked to reject a coincidental `.snd` match.
- **Doom WAD archives are carved** — `scan` now recovers `.wad` files (`IWAD` /
  `PWAD`), with the exact length computed from the header's lump count and
  directory offset (the Doom engine writes the lump directory last). The two
  fields are range-checked to reject a coincidental magic.
- **Game Boy / Game Boy Color ROMs are carved** — `scan` now recovers `.gb` ROM
  images, anchored on the 48-byte Nintendo logo (an exact, boot-ROM-verified
  magic) with the exact length read from the cartridge header's size code and the
  header checksum verified to reject false matches.
- **BeFS volumes are recognised** — the Be File System (the native filesystem of
  BeOS and of Haiku, its modern successor) is now detected from its superblock's
  dual magics, in either byte order, so `info` / `list_volumes` report its volume
  name and size instead of leaving it unrecognised. Its B+tree metadata is
  specialised, so it is not recovered from metadata — use `scan` (carving).
- **bcachefs volumes are recognised** — the modern copy-on-write Linux filesystem
  (merged into the mainline kernel in 6.7) is now detected from its superblock's
  16-byte magic, so `info` / `list_volumes` report its label and UUID instead of
  leaving it unrecognised. Like the other copy-on-write filesystems it leaves no
  stale metadata to scavenge, so it is not recovered from metadata — use `scan`
  (carving).
- **Minix volumes are recognised** — the filesystem the earliest Linux ran on
  (still found on boot floppies and small/embedded media) is now detected from
  its superblock, so `info` / `list_volumes` report its on-disk version (v1/v2/v3)
  and size instead of leaving it unrecognised. All three versions are handled.
  Minix has no on-disk label or UUID, and the format is long superseded, so it is
  not recovered from metadata — use `scan` (carving).
- **OCFS2 volumes are recognised** — the Oracle Cluster File System 2, a
  shared-disk Linux cluster filesystem, is now detected from its `OCFSV2`
  superblock inode (probed across the supported block sizes), so `info` /
  `list_volumes` report its size, label, and UUID instead of leaving it
  unrecognised. Its metadata is cluster-managed, so it is not recovered from
  metadata — use `scan` (carving).
- **GFS2 / GFS volumes are recognised** — Red Hat's Global File System 2 (and the
  original GFS), a shared-disk cluster filesystem, is now detected from its
  superblock's big-endian `0x01161970` magic, so `info` / `list_volumes` report
  its lock table and UUID instead of leaving it unrecognised. Its metadata is
  cluster-coordinated, so it is not recovered from metadata — use `scan`
  (carving).
- **NILFS2 volumes are recognised** — the log-structured Linux filesystem with
  continuous snapshotting is now detected from its `0x3434` superblock, so
  `info` / `list_volumes` report its size, label, and UUID instead of leaving it
  unrecognised. Like the other log-structured/copy-on-write filesystems, it leaves
  no stale metadata to scavenge, so it is not recovered from metadata — use `scan`
  (carving).
- **JFS volumes are recognised** — IBM's Journaled File System (ported to Linux
  from AIX/OS2) is now detected from its `JFS1` aggregate superblock, so
  `info` / `list_volumes` report its size, label, and UUID instead of leaving it
  unrecognised. Its B+tree layout is unlike the ext family, so it is not recovered
  from metadata — use `scan` (carving).
- **ReiserFS volumes are recognised** — the once-popular Linux journaling
  filesystem (the SUSE default through the 2000s, now removed from the mainline
  kernel) is now detected from its `ReIsEr2Fs` / `ReIsErFs` superblock, so
  `info` / `list_volumes` report its size, label, and UUID instead of leaving it
  unrecognised. Both on-disk layouts are handled — 3.6 (64 KiB in, with UUID and
  label) and the older 3.5 (8 KiB in). Its tree layout is long obsolete, so it is
  not recovered from metadata — use `scan` (carving).
- **Old HFS (Mac OS Standard) volumes are recognised** — the original HFS
  filesystem (1985–1998, found on old Mac floppies, disks, and CDs) is now
  detected from its `BD` Master Directory Block, so `info` / `list_volumes`
  report its size and volume name instead of leaving it unrecognised. Its catalog
  is a long-obsolete on-disk format, so it is not recovered from metadata — use
  `scan` (carving). A `BD` block that wraps an embedded HFS+ volume is still
  followed to the HFS+ volume, so only a pure old-HFS volume is reported as `HFS`.
  This completes the Mac filesystem family (HFS / HFS+ / HFSX, plus the HFS
  wrapper and Apple Partition Map).
- **QuickTime / M4A / M4V get their own extensions when carved** — ISO base-media
  files are now carved to a brand-specific extension instead of always `.mp4`:
  the `qt  ` major brand (iPhone/Mac video) → `.mov`, `M4A ` → `.m4a`, and
  `M4V ` → `.m4v`. `identify` and `triage` recognise them by content too. (Other
  brands still carve as `.mp4`.)
- **HFS-wrapped HFS+ volumes are detected** — an HFS+ volume embedded inside an
  old HFS `BD` wrapper (the layout on old Mac media and hybrid CDs) is now
  followed to the embedded volume, so `info` / `undelete` / `scan` work on it
  instead of seeing only the wrapper. Both 512-byte and larger allocation blocks
  are handled.
- **More GPT partition types are named** — `info` / `list_volumes` now give
  friendly names to many more GPT type GUIDs (Linux root for x86-64/ARM64,
  `/srv`, extended boot, LUKS/dm-crypt, reserved; Windows LDM data/metadata;
  ChromeOS kernel/root; Apple UFS/RAID; FreeBSD data/swap/UFS/boot) instead of
  showing the raw GUID.
- **Apple Partition Map (APM) is supported** — disks partitioned with the Apple
  Partition Map (PowerPC-era Macs, older Mac disks, hybrid CDs) are now
  recognised: `info` / `list_volumes` report the `apm` scheme and each entry's
  type (e.g. `Apple_HFS`), name, and byte range, and `undelete` / `scan` /
  `recover` detect and recover the volumes inside APM partitions. Both 512-byte
  and 2048-byte block maps are handled. This is the third partition scheme
  alongside GPT and MBR.
- **Extracted ISO 9660 files keep their recording date** — a file extracted from
  an ISO 9660 disc now has its directory-record recording date/time applied as
  the output file's modification time, matching how the undelete backends already
  preserve a deleted file's timestamps. The 7-byte binary date in each directory
  record is parsed (new `times::from_iso9660_dir`) and applied via the shared
  `times::apply`.
- **LUKS UUID and LUKS2 label are reported** — `info` / `list_volumes` now report
  a LUKS container's UUID (the value `cryptsetup luksUUID` / `blkid` show), read
  from offset 0xA8 of the LUKS1/LUKS2 header, plus the LUKS2 label when set — so
  an encrypted volume can be correlated with a system's configuration even though
  its contents can't be read without the key. Surfaced on the existing `uuid:` /
  `label:` lines and `uuid` / `label` fields.
- **Binary EPS (`.eps`) carving** — Encapsulated PostScript with a DOS preview
  header (`C5 D0 D3 C6`) is carved from the section table in its 30-byte header:
  the file ends at the furthest `offset + length` of the PostScript section and
  the optional WMF/TIFF previews. The plain-text EPS form (no binary header)
  carries no length and is not carved. `identify` and `triage` recognise binary
  `.eps` by content too.
- **Microsoft Program Database (`.pdb`) carving** — the debug-symbol file every
  MSVC build produces is carved from its MSF 7.0 superblock, whose block size
  (offset 0x20) and block count (offset 0x28) give the exact size
  (`block_size × num_blocks`). The 32-byte magic and a power-of-two block-size
  check reject a coincidental match. `identify` and `triage` recognise `.pdb` by
  content too.
- **Partition attribute flags are reported** — `info` / `list_volumes` now report
  each partition's notable flags: for GPT the attribute bits (`required`,
  `legacy-bios-bootable`, `read-only`, `hidden`, `no-automount`, `no-block-io`)
  and for MBR `active` when the boot flag is set — helping spot, for instance, a
  hidden read-only recovery partition. The text view adds a `flags:` line under
  the entry and `--json` / the MCP `list_volumes` tool a per-partition
  `attributes` array (empty when none apply).
- **MPEG program stream (`.mpg`) carving** — the container used by DVDs, VCDs,
  and older camcorders/recorders is carved by walking its pack / system-header /
  PES-packet chain (each introduced by a `00 00 01` start code) to the
  program-end code (`00 00 01 B9`), giving an exact end — or to the last whole
  packet when the stream is truncated. Pack headers are sized from the
  MPEG-1/MPEG-2 layout (with pack stuffing); a run of consecutive valid packets
  is required so the start code cannot trigger a false carve. `identify` and
  `triage` recognise `.mpg` by content too.
- **Free space is reported for XFS and Btrfs** — `info` / `list_volumes` now show
  free space for XFS (from `sb_fdblocks`) and Btrfs (`total_bytes` −
  `bytes_used`), read straight from the superblock, in addition to the
  allocation-map-based free space already reported for FAT/exFAT/ext/NTFS/HFS+.
  This is a reported `free_bytes` count only — free-space-only carving
  (`--unallocated`) still needs an allocation map, which those backends don't
  expose.
- **Linux MD/RAID members are recognised** — a software-RAID member device is
  detected from its version-1 `mdadm` superblock (1.1 at the device start, 1.2 at
  4 KiB in) and reported by `info` / `list_volumes` with the array's RAID level
  (e.g. `Linux RAID5`), UUID, name, and the member's data size, instead of
  showing as an unrecognised volume. The array is not assembled — assemble it
  with `mdadm` first, then recover from the assembled device. The 1.0 layout
  (superblock near the end of the device) is not detected.
- **Inode (file) usage is reported** — `info` / `list_volumes` now show roughly
  how many files and directories a volume holds, for **ext**
  (`s_inodes_count` / `s_free_inodes_count`) and **XFS** (`sb_icount` /
  `sb_ifree`), so you can gauge the scale of data on a recovered volume. The text
  view adds an `inodes: <used> used / <total>` line and `--json` / the MCP
  `list_volumes` tool add `inodes_used` / `inodes_total` fields (`null` for
  filesystems without fixed inode accounting).
- **The ext last-mounted path is reported** — `info` / `list_volumes` now show
  the directory an ext volume was last mounted on (`s_last_mounted`, e.g. `/` or
  `/home` — the `Last mounted on` value `dumpe2fs` reports), which helps identify
  which volume a recovered image came from. The text view adds a `last mounted:`
  line and `--json` / the MCP `list_volumes` tool a `last_mounted` field (`null`
  when unset).
- **MPEG transport stream (`.ts`) carving** — the container used by DVB/ATSC
  broadcast captures, HDHomeRun/DVR recordings, and many camcorders is carved by
  walking its fixed 188-byte packets (each starting with the `0x47` sync byte) to
  the end of the stream, giving an exact end at the last whole packet. The sync
  byte is required at two packet boundaries plus a longer consecutive run, so the
  single-byte sync cannot trigger a false carve. The 192-byte (M2TS) and 204-byte
  (FEC) variants are not carved. `identify` and `triage` recognise `.ts` by
  content too.
- **Filesystem creation / last-write times are reported** — `info` /
  `list_volumes` now show a volume's creation and last-write times when the
  filesystem records them: **ext** from `s_mkfs_time` / `s_wtime` (the values
  `dumpe2fs` reports), **NTFS** from the `$Volume` file's `$STANDARD_INFORMATION`
  (the timestamps Windows keeps), **HFS+** from the volume header's
  `createDate` / `modifyDate`, and **ISO 9660** from the Primary Volume
  Descriptor's creation / modification date, so a recovered volume can be dated.
  The text view adds `created:` and `last written:` lines (ISO-8601 UTC) and
  `--json` / the MCP `list_volumes` tool add `created_time` / `written_time`
  fields (Unix seconds, `null` when unset).
- **The allocation-unit size is reported** — `info` / `list_volumes` now report
  each volume's cluster size (FAT, exFAT, NTFS, ReFS) or block size (ext, HFS+,
  APFS, XFS, F2FS, Btrfs, ISO 9660) — the granularity the filesystem allocates
  space in, which carving aligns to and which bounds per-file slack. The text
  view adds an `alloc unit:` line and `--json` / the MCP `list_volumes` tool an
  `alloc_unit_bytes` field (`null` for backends with no such unit).
- **The ext variant (ext2 / ext3 / ext4) is reported** — `info` / `list_volumes`
  now refine the `ext2/3/4` family label to the precise variant, read from the
  superblock feature flags the way `blkid` classifies them: ext2 has no journal,
  ext3 adds a journal, and ext4 carries an ext4-only feature such as extents or
  64-bit block addressing. The text view adds a `version:` line and `--json` /
  the MCP `list_volumes` tool a `version` field (`null` for filesystems without a
  sub-version).
- **Linux swap areas are recognised** — a swap partition is detected from its
  version-2 swap header (`SWAPSPACE2`) and reported by `info` / `list_volumes`
  with its size, **UUID**, and **label**, instead of showing as an unrecognised
  volume. A swap area holds no files to recover, but identifying it by its
  `UUID=` (the value `/etc/fstab` uses) helps confirm which disk an image came
  from and rules the area out as a place to look for lost data. The header's page
  size is detected from the magic's position (4–64 KiB), and the area is checked
  before the boot-sector filesystems so a stale disklabel in the reserved
  `bootbits` region is not misread as FAT/NTFS.
- **Volume clean/dirty state is reported** — `info` / `list_volumes` now report
  whether a volume was cleanly unmounted, from ext (`s_state`), exFAT
  (`VolumeFlags`), and NTFS (`$VOLUME_INFORMATION`). A volume that is marked
  dirty (potentially inconsistent, so less reliable to recover from) gets a
  `state: dirty` line in the text view; `--json` / the MCP `list_volumes` tool
  add a `clean` boolean (`null` for filesystems without the flag).
- **Bootable ISOs are flagged with their boot platform (El Torito)** — `info` /
  `list_volumes` report whether an ISO 9660 disc carries an El Torito boot record
  and the platform(s) it boots — e.g. `El Torito (BIOS, UEFI)`, read from the
  boot catalog's validation entry and section headers — distinguishing a
  legacy-BIOS, UEFI, or hybrid image from a pure data disc. The text view adds a
  `boot:` line and `--json` / the MCP `list_volumes` tool a `boot` field.
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
