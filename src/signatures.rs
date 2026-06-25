//! Known file-type signatures and the strategy used to find where each
//! recovered file ends.
//!
//! Carving works by locating a *header* (a magic byte sequence) on the raw
//! device, then determining the file's length with one of a few strategies:
//!
//! * [`Extent::Footer`] — scan forward for a trailing marker (JPEG, PNG, ...).
//! * [`Extent::HeaderSizeLe32`] — read a little-endian u32 size field (BMP, CAB).
//! * [`Extent::RiffSize`] — RIFF container size at offset 4, plus the 8-byte
//!   chunk header (WAV, AVI, WEBP).
//! * [`Extent::FormSize`] — IFF "FORM" container size (big-endian) at offset 4,
//!   plus the 8-byte chunk header (AIFF, AIFF-C).
//! * [`Extent::Sqlite`] — page size × page count from the SQLite header.
//! * [`Extent::SevenZip`] — next-header offset + size from the 7z header.
//! * [`Extent::Mp4Atoms`] — walk the ISO base-media box/atom structure (MP4,
//!   MOV, HEIC, AVIF, CR3, ...).
//! * [`Extent::Elf`] — read the ELF header's section-header-table location to
//!   find where the file ends.
//! * [`Extent::Pe`] — walk a PE/COFF section table (and the certificate
//!   overlay) to find where a Windows executable ends.
//! * [`Extent::Tiff`] — walk the TIFF IFD chain (and sub-IFDs, strip/tile
//!   arrays) to find the end of a TIFF or TIFF-based raw image.
//! * [`Extent::Ebml`] — read the Matroska/WebM segment size (or walk its
//!   top-level elements) to find where the container ends.
//! * [`Extent::Ogg`] — walk the chain of Ogg pages (each sized by its segment
//!   table) to the end of the bitstream.
//! * [`Extent::Asf`] — walk the top-level ASF objects (WMV/WMA), each a GUID
//!   plus a 64-bit size, to the end of the container.
//! * [`Extent::Wasm`] — walk a WebAssembly module's sections (LEB128-sized) to
//!   the end of the module.
//! * [`Extent::IcoCur`] — take the furthest `offset + size` across an ICO/CUR
//!   image directory.
//! * [`Extent::HeaderSizeBe32`] — read a big-endian u32 size field (WOFF fonts).
//! * [`Extent::Sfnt`] — walk a TrueType/OpenType font's table directory.
//! * [`Extent::Midi`] — walk a Standard MIDI file's `MThd`/`MTrk` chunks.
//! * [`Extent::Flv`] — walk a Flash Video tag chain.
//! * [`Extent::Pcap`] / [`Extent::Pcapng`] — walk a network-capture file's
//!   packet records / blocks.
//! * [`Extent::Ttc`] — walk a TrueType Collection's member font directories.
//! * [`Extent::Rar`] — walk a RAR archive's block chain (v4 and v5) to the
//!   end-of-archive block.
//! * [`Extent::Zstd`] — walk a Zstandard frame's data blocks to the last block
//!   (plus the optional content checksum).
//! * [`Extent::Lz4`] — walk an LZ4 frame's data blocks to the end mark (plus
//!   optional block/content checksums).
//! * [`Extent::Psd`] — sum a Photoshop document's header, length-prefixed
//!   sections, and image data (raw or RLE).
//! * [`Extent::Wmf`] — read a Windows Metafile's `mtSize` (total size in words).
//! * [`Extent::Djvu`] — read a DjVu document's IFF `FORM` length.
//! * [`Extent::Evtx`] — size a Windows Event Log from its chunk count.
//! * [`Extent::Rtf`] — match an RTF document's outer `{ ... }` group.
//! * [`Extent::Mp3`] — walk MPEG audio frames from an ID3v2 tag to the end.
//! * [`Extent::MachO`] — sum a Mach-O binary's segments and link-edit tables.
//! * [`Extent::Regf`] — Windows registry hive: base block + hive-bins data.
//! * [`Extent::Aac`] — walk ADTS AAC audio frames to the end of the stream.
//! * [`Extent::Dex`] — Android Dalvik executable: `file_size` header field.
//! * [`Extent::Icc`] — ICC colour profile: total size in the profile header.
//! * [`Extent::Ar`] — Unix `ar` archive (`.a`/`.deb`): walk the member chain.
//! * [`Extent::Shp`] — ESRI Shapefile: total length (in 16-bit words) in header.
//! * [`Extent::Blend`] — Blender file: walk the block chain to the `ENDB` block.
//! * [`Extent::Nes`] — iNES / NES 2.0 ROM: size from the PRG/CHR bank counts.
//! * [`Extent::Mp3Raw`] — MP3 anchored on a frame sync (no ID3v2 tag).
//! * [`Extent::Wim`] — Windows Imaging (WIM): furthest resource-table extent.
//! * [`Extent::Swf`] — uncompressed Flash movie (`FWS`): `FileLength` at offset 4.
//! * [`Extent::Cfbf`] — OLE2 compound file: walk the FAT to the last used sector.
//! * [`Extent::Pst`] — Outlook data file (PST/OST): `ibFileEof` in the header.
//!
//! Adding a new file type is just a matter of appending a [`Signature`] to
//! [`SIGNATURES`].

/// How to determine the length of a carved file once its header is found.
#[derive(Clone, Copy, Debug)]
pub enum Extent {
    /// Search forward for `marker`; the file ends `trailing` bytes after the
    /// end of the marker.
    Footer {
        marker: &'static [u8],
        trailing: u64,
    },
    /// The total file size is stored as a little-endian u32 at `offset` bytes
    /// into the file (relative to the file start).
    HeaderSizeLe32 { offset: usize },
    /// RIFF container: total size = (little-endian u32 at offset 4) + 8.
    RiffSize,
    /// IFF "FORM" container (AIFF/AIFF-C, and other EA-IFF-85 types): total size
    /// = (big-endian u32 at offset 4) + 8. The big-endian sibling of
    /// [`Extent::RiffSize`].
    FormSize,
    /// SQLite database: total size = page_size × page_count (big-endian fields
    /// in the file header).
    Sqlite,
    /// 7-Zip archive: total size = 32 + NextHeaderOffset + NextHeaderSize
    /// (little-endian u64 fields in the signature header).
    SevenZip,
    /// Parse the ISO base-media (MP4/QuickTime/HEIF) box structure to sum atoms.
    Mp4Atoms,
    /// ELF object: total size = section-header-table offset + entry count ×
    /// entry size (the section header table normally ends the file). Handles
    /// 32/64-bit and either byte order from the ELF identification bytes.
    Elf,
    /// PE (Windows EXE/DLL): follow the DOS stub to the PE header, then take the
    /// largest `PointerToRawData + SizeOfRawData` across the section table, also
    /// accounting for an appended certificate (Authenticode) overlay.
    Pe,
    /// TIFF / TIFF-based raw (CR2, NEF, DNG, ARW, ...): walk the IFD chain and
    /// sub-IFDs, taking the furthest extent of all field data and the strip/tile
    /// image arrays. Handles little- and big-endian.
    Tiff,
    /// Matroska / WebM (EBML): take the Segment element's declared size, or, for
    /// an unknown-size Segment, sum its top-level child elements.
    Ebml,
    /// Ogg (Vorbis/Opus/Theora): walk consecutive `OggS` pages, each sized by
    /// its segment table, to the end of the bitstream.
    Ogg,
    /// ASF (WMV/WMA/ASF): walk the top-level objects, each a 16-byte GUID plus a
    /// 64-bit little-endian size, stopping at the first unrecognised object.
    Asf,
    /// WebAssembly: after the 8-byte header, walk the sections (each a 1-byte id
    /// and an unsigned LEB128 size) to the end of the module.
    Wasm,
    /// ICO / CUR: the icon directory lists each image's size and offset; the
    /// file ends at the furthest `offset + size`.
    IcoCur,
    /// The total file size is stored as a big-endian u32 at `offset` bytes into
    /// the file (e.g. WOFF/WOFF2 web fonts store their length at offset 8).
    HeaderSizeBe32 { offset: usize },
    /// SFNT font (TrueType/OpenType): walk the table directory, taking the
    /// furthest `offset + length` (padded to 4 bytes) across all tables.
    Sfnt,
    /// Standard MIDI file: an `MThd` header chunk followed by `MTrk` chunks, each
    /// a 4-byte tag and a big-endian u32 length; walk them to the end.
    Midi,
    /// Flash Video (FLV): a 9-byte header then a chain of tags, each an 11-byte
    /// tag header (with a 24-bit big-endian data size) plus a trailing 4-byte
    /// previous-tag-size field; walk them to the end.
    Flv,
    /// libpcap capture: a 24-byte global header (whose magic also gives the byte
    /// order) followed by packet records, each a 16-byte header with a captured
    /// length; walk the records to the end.
    Pcap,
    /// pcapng capture: a chain of blocks, each carrying its own total length as a
    /// u32 (byte order from the first Section Header Block); walk them to the end.
    Pcapng,
    /// TrueType Collection (`ttcf`): a header listing each member font's table
    /// directory; walk every font's tables to the furthest `offset + length`.
    Ttc,
    /// RAR archive (v4 and v5): walk the block chain — each block carries its
    /// own header and data sizes — to the end-of-archive marker block. Handles
    /// both the classic v4 layout and the v5 variable-length-integer layout.
    Rar,
    /// Zstandard frame: parse the frame header, then walk the data blocks (each
    /// a 3-byte header giving its size and a last-block flag) to the final
    /// block, adding the 4-byte content checksum when the header flags one.
    Zstd,
    /// LZ4 frame: parse the frame descriptor, then walk the data blocks (each a
    /// 4-byte size prefix) to the zero-sized end mark, accounting for optional
    /// per-block and content checksums.
    Lz4,
    /// Photoshop document (PSD/PSB): a fixed header, three length-prefixed
    /// sections (colour-mode data, image resources, layer & mask info), then the
    /// image data whose size is computed from the dimensions for raw storage or
    /// summed from the per-scanline byte counts for PackBits (RLE).
    Psd,
    /// Windows Metafile (WMF): the metafile header records its total size in
    /// 16-bit words (`mtSize`); the file ends there, after the 22-byte placeable
    /// header when one is present.
    Wmf,
    /// DjVu document (`AT&TFORM` + IFF `FORM`): the big-endian FORM length at
    /// offset 8 covers everything after it, so the file ends at `12 + length`.
    Djvu,
    /// Windows Event Log (`ElfFile\0`): a 4096-byte file header records the
    /// number of 64 KiB chunks, so the file ends at `4096 + chunks * 65536`.
    Evtx,
    /// Rich Text Format: the document is one big `{ ... }` group, so the file
    /// ends where the opening brace's match closes. Backslash escapes (`\{`,
    /// `\}`, `\\`) are honoured. (Embedded `\bin` binary blobs, which are
    /// uncommon, are not specially skipped.)
    Rtf,
    /// MPEG audio (MP3): anchored on an ID3v2 tag, skip the tag (using its
    /// synchsafe size, plus a footer when flagged) and walk the MPEG audio
    /// frames — each header encoding version/layer/bitrate/sample-rate, from
    /// which the frame length is computed — to the end of the stream, including
    /// a trailing 128-byte ID3v1 (`TAG`) tag when present.
    Mp3,
    /// Mach-O binary (macOS/iOS executables, dylibs, bundles): parse the header
    /// to read the load commands, then take the furthest extent of every
    /// `LC_SEGMENT`/`LC_SEGMENT_64` (`fileoff + filesize`) and link-edit table
    /// (symbol/string tables and `dataoff + datasize` blobs such as the code
    /// signature, which normally ends the file). Handles 32/64-bit and either
    /// byte order from the magic. Fat/universal binaries (`0xCAFEBABE`, which
    /// collides with Java class files) are not carved.
    MachO,
    /// Windows registry hive (`regf`): the 4096-byte base block records the
    /// total size of the hive-bins data area at offset 0x28, so the file ends at
    /// `4096 + hive_bins_data_size`. The version and file-type fields are checked
    /// to reject a coincidental magic.
    Regf,
    /// AAC audio in an ADTS stream: each 7-byte (or 9-byte with CRC) frame
    /// header carries a 13-bit frame length, so the stream is walked frame to
    /// frame to its end. Frames are validated (sync word, fixed layer bits, a
    /// valid and consistent sample-rate index) and several consecutive frames
    /// are required, so the short sync word cannot trigger a false carve.
    Aac,
    /// Android Dalvik executable (`dex\n`): the header stores the total file
    /// size as a little-endian u32 at offset 0x20, so the file ends there. The
    /// endian tag (0x12345678 at 0x28) and header size (0x70 at 0x24) are
    /// checked to reject a coincidental magic.
    Dex,
    /// ICC colour profile: the 128-byte profile header opens with the total
    /// profile size as a big-endian u32 at offset 0, and carries the `acsp`
    /// file signature at offset 36 (the magic anchors there). The size must be
    /// at least the header size and a multiple of 4 (profiles are 4-byte
    /// padded), which rejects a coincidental `acsp` match.
    Icc,
    /// Unix `ar` archive (Debian `.deb` packages and `.a` static libraries):
    /// after the `!<arch>\n` global header, walk the member chain. Each member
    /// has a 60-byte header ending in the `` `\n `` sentinel (validated to find
    /// the archive's end) and carrying its data size as a decimal field; member
    /// data is padded to an even length.
    Ar,
    /// ESRI Shapefile (`.shp`/`.shx`): the 100-byte header stores the total file
    /// length as a big-endian u32 at offset 24, counted in 16-bit words, so the
    /// file ends at `length * 2`. The file code (9994 at offset 0) and version
    /// (1000 at offset 28) are checked to reject a coincidental magic.
    Shp,
    /// Blender file (`.blend`): a 12-byte header (`BLENDER` + pointer-size and
    /// endianness flags + version) followed by a chain of file blocks, each with
    /// a header carrying its data size; walk the chain to the terminating `ENDB`
    /// block, which gives an exact end. The pointer-size and endianness flags are
    /// validated to reject a coincidental magic.
    Blend,
    /// iNES / NES 2.0 ROM (`NES\x1a`): the 16-byte header records the PRG and
    /// CHR ROM bank counts, so the file ends at `16 + trainer + prg * 16384 +
    /// chr * 8192` (the trainer is an optional 512 bytes). NES 2.0 extends the
    /// bank counts with high bits; ROMs using the exponent bank form or carrying
    /// an indeterminate miscellaneous-ROM area are rejected.
    Nes,
    /// MP3 anchored directly on an MPEG (Layer III) frame sync, for the many
    /// MP3s that carry only an ID3v1 trailer or no tag at all (the [`Extent::Mp3`]
    /// anchor needs an ID3v2 tag). The frame chain is walked like [`Extent::Mp3`];
    /// because the sync is only 11 bits, a longer run of consecutive valid frames
    /// is required to avoid a false carve.
    Mp3Raw,
    /// JPEG image: scan for the End-of-Image marker (`FF D9`), but track nested
    /// Start-of-Image markers (`FF D8`, e.g. an embedded EXIF thumbnail) so the
    /// file ends at the *outer* image's `FF D9` rather than a thumbnail's. Within
    /// JPEG entropy data `FF` is only ever followed by `00` or `D0`–`D7`, so
    /// scanning for `FF D8`/`FF D9` is unambiguous for well-formed images.
    Jpeg,
    /// ZIP archive (and the many ZIP-based formats: DOCX/XLSX/PPTX, ODT, JAR,
    /// APK, EPUB): locate the End-of-Central-Directory record (`PK\x05\x06`) and
    /// end the file after it and its declared comment. The EOCD records the
    /// central directory's offset and size, so the record whose geometry matches
    /// this archive is chosen — this skips the EOCD of a ZIP nested inside the
    /// archive (which would otherwise truncate it) and rejects a coincidental
    /// marker.
    Zip,
    /// GIF image: walk the block stream — the logical-screen descriptor and any
    /// colour tables, then image (`0x2C`) and extension (`0x21`) blocks with
    /// their length-prefixed sub-block chains — to the trailer (`0x3B`). This
    /// finds the true end rather than stopping at a `00 3B` byte pair that occurs
    /// by chance inside the LZW image data.
    Gif,
    /// Windows Imaging Format (WIM/ESD): the 208-byte header carries a resource
    /// header (offset + size) for the offset/lookup table, XML data, boot
    /// metadata, and integrity table. The file ends at the furthest
    /// `offset + size` of these — one of them (normally the integrity table or
    /// XML data) is the last structure in the file. The header size field
    /// (0xD0) is checked to reject a coincidental magic.
    Wim,
    /// Uncompressed Flash movie (`FWS`): the 8-byte header stores the total file
    /// length as a little-endian u32 at offset 4. Only the uncompressed variant
    /// is carved — the compressed `CWS`/`ZWS` variants store the *uncompressed*
    /// length there, which is not the on-disk size. The version byte and a
    /// minimum length are checked to reject a coincidental magic.
    Swf,
    /// Compound File Binary Format (OLE2 — legacy `.doc`/`.xls`/`.ppt`/`.msi`).
    /// The 512-byte header records the sector size (`1 << shift` at offset 30,
    /// either 512 or 4096), the number of FAT sectors, and a DIFAT array
    /// listing them (the first 109 in the header, the rest via a DIFAT-sector
    /// chain). The file is a whole number of sectors; its length is found by
    /// reading the FAT and taking the highest sector index that is not marked
    /// free, so the file ends at `(max_used_sector + 2) * sector_size`.
    Cfbf,
    /// Outlook data file (PST/OST). The NDB header records the file's own end
    /// offset (`ibFileEof`) directly: a little-endian u64 at offset 0xB8 in the
    /// Unicode format (`wVer` >= 23). The ANSI format (`wVer` 14/15) stores a
    /// 32-bit `ibFileEof` at a different offset and is not carved. The version
    /// and the `SM` client signature are checked to reject a coincidental magic.
    Pst,
}

/// A recoverable file type.
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    /// Human-readable name, e.g. `"JPEG image"`.
    pub name: &'static str,
    /// Output file extension (without the dot), e.g. `"jpg"`.
    pub ext: &'static str,
    /// Magic bytes that identify the type.
    pub magic: &'static [u8],
    /// Where the magic appears relative to the start of the file. This is `0`
    /// for most formats but `4` for MP4/HEIC where the `ftyp` marker follows a
    /// 4-byte box-size field.
    pub magic_offset: u64,
    /// Optional secondary tag to disambiguate formats that share a magic, given
    /// as `(offset_from_magic, bytes)`. Used to tell RIFF (WAV/AVI/WEBP) and
    /// ISO-BMFF brands (HEIC vs MP4) apart.
    pub secondary: Option<(usize, &'static [u8])>,
    /// Strategy used to compute the file length.
    pub extent: Extent,
    /// Hard cap on carved size; protects against runaway files when an end
    /// marker is missing or corrupt.
    pub max_size: u64,
}

const KB: u64 = 1024;
const MB: u64 = 1024 * KB;
const GB: u64 = 1024 * MB;

/// The built-in signature table.
///
/// Order matters where magics overlap: more specific entries (with a
/// `secondary` tag) must precede the generic fallback for the same magic, so
/// HEIC is matched before the generic MP4 `ftyp` entry.
pub static SIGNATURES: &[Signature] = &[
    Signature {
        name: "JPEG image",
        ext: "jpg",
        magic: &[0xFF, 0xD8, 0xFF],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Jpeg,
        max_size: 50 * MB,
    },
    Signature {
        name: "PNG image",
        ext: "png",
        magic: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Footer {
            // IEND chunk: length(0) + "IEND" + CRC
            marker: &[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82],
            trailing: 0,
        },
        max_size: 100 * MB,
    },
    Signature {
        name: "GIF image (89a)",
        ext: "gif",
        magic: b"GIF89a",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Gif,
        max_size: 30 * MB,
    },
    Signature {
        name: "GIF image (87a)",
        ext: "gif",
        magic: b"GIF87a",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Gif,
        max_size: 30 * MB,
    },
    Signature {
        name: "BMP image",
        ext: "bmp",
        magic: b"BM",
        magic_offset: 0,
        secondary: None,
        // Total file size is a LE u32 at offset 2.
        extent: Extent::HeaderSizeLe32 { offset: 2 },
        max_size: 100 * MB,
    },
    Signature {
        name: "PDF document",
        ext: "pdf",
        magic: b"%PDF",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Footer {
            marker: b"%%EOF",
            trailing: 2, // allow a trailing CR/LF
        },
        max_size: 500 * MB,
    },
    Signature {
        name: "ZIP archive (also DOCX/XLSX/PPTX/ODT/JAR/APK)",
        ext: "zip",
        magic: &[0x50, 0x4B, 0x03, 0x04],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Zip,
        max_size: 2 * GB,
    },
    Signature {
        name: "WAV audio",
        ext: "wav",
        magic: b"RIFF",
        magic_offset: 0,
        secondary: Some((8, b"WAVE")),
        extent: Extent::RiffSize,
        max_size: 2 * GB,
    },
    Signature {
        name: "AVI video",
        ext: "avi",
        magic: b"RIFF",
        magic_offset: 0,
        secondary: Some((8, b"AVI ")),
        extent: Extent::RiffSize,
        max_size: 4 * GB,
    },
    Signature {
        name: "WebP image",
        ext: "webp",
        magic: b"RIFF",
        magic_offset: 0,
        secondary: Some((8, b"WEBP")),
        extent: Extent::RiffSize,
        max_size: 100 * MB,
    },
    Signature {
        name: "AIFF audio",
        ext: "aiff",
        magic: b"FORM",
        magic_offset: 0,
        secondary: Some((8, b"AIFF")),
        extent: Extent::FormSize,
        max_size: 2 * GB,
    },
    Signature {
        name: "AIFF-C audio",
        ext: "aifc",
        magic: b"FORM",
        magic_offset: 0,
        secondary: Some((8, b"AIFC")),
        extent: Extent::FormSize,
        max_size: 2 * GB,
    },
    Signature {
        name: "Apple icon image",
        ext: "icns",
        magic: b"icns",
        magic_offset: 0,
        secondary: None,
        // Total file size is a big-endian u32 at offset 4 (includes the header).
        extent: Extent::HeaderSizeBe32 { offset: 4 },
        max_size: 50 * MB,
    },
    Signature {
        name: "SQLite database",
        ext: "sqlite",
        magic: b"SQLite format 3\0",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Sqlite,
        max_size: 2 * GB,
    },
    Signature {
        name: "7-Zip archive",
        ext: "7z",
        magic: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
        magic_offset: 0,
        secondary: None,
        extent: Extent::SevenZip,
        max_size: 4 * GB,
    },
    Signature {
        name: "Microsoft Cabinet archive",
        ext: "cab",
        magic: b"MSCF",
        magic_offset: 0,
        secondary: None,
        // Cabinet size is a LE u32 at offset 8.
        extent: Extent::HeaderSizeLe32 { offset: 8 },
        max_size: 2 * GB,
    },
    Signature {
        name: "RAR archive",
        ext: "rar",
        // The 6-byte prefix shared by RAR v4 (`Rar!\x1A\x07\x00`) and v5
        // (`Rar!\x1A\x07\x01\x00`); the version byte that follows is read by the
        // block walk.
        magic: b"Rar!\x1a\x07",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Rar,
        max_size: 8 * GB,
    },
    Signature {
        name: "Zstandard compressed",
        ext: "zst",
        magic: &[0x28, 0xB5, 0x2F, 0xFD],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Zstd,
        max_size: 8 * GB,
    },
    Signature {
        name: "LZ4 compressed",
        ext: "lz4",
        magic: &[0x04, 0x22, 0x4D, 0x18],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Lz4,
        max_size: 8 * GB,
    },
    Signature {
        name: "Photoshop document",
        ext: "psd",
        magic: b"8BPS",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Psd,
        max_size: 4 * GB,
    },
    Signature {
        name: "Windows Metafile (placeable)",
        ext: "wmf",
        magic: &[0xD7, 0xCD, 0xC6, 0x9A],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Wmf,
        max_size: 256 * MB,
    },
    Signature {
        name: "Windows Metafile",
        ext: "wmf",
        // METAHEADER: mtType=1 (memory), mtHeaderSize=9 words. The metafile
        // version and size are validated by the extent walk.
        magic: &[0x01, 0x00, 0x09, 0x00],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Wmf,
        max_size: 256 * MB,
    },
    Signature {
        name: "Windows Metafile",
        ext: "wmf",
        // METAHEADER with mtType=2 (disk).
        magic: &[0x02, 0x00, 0x09, 0x00],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Wmf,
        max_size: 256 * MB,
    },
    Signature {
        name: "glTF binary (3D model)",
        ext: "glb",
        magic: b"glTF",
        magic_offset: 0,
        secondary: None,
        // The 12-byte header stores total length as a LE u32 at offset 8.
        extent: Extent::HeaderSizeLe32 { offset: 8 },
        max_size: 2 * GB,
    },
    Signature {
        name: "DjVu document",
        ext: "djvu",
        magic: b"AT&TFORM",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Djvu,
        max_size: 512 * MB,
    },
    Signature {
        name: "Windows Event Log",
        ext: "evtx",
        magic: b"ElfFile\x00",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Evtx,
        max_size: 2 * GB,
    },
    Signature {
        name: "Rich Text Format",
        ext: "rtf",
        magic: b"{\\rtf1",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Rtf,
        max_size: 100 * MB,
    },
    Signature {
        name: "MP3 audio",
        ext: "mp3",
        magic: b"ID3",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Mp3,
        max_size: 100 * MB,
    },
    // MP3 with no ID3v2 tag: anchor on a Layer III frame sync. One entry per
    // common second byte — MPEG 1/2/2.5, CRC present or absent. `mp3_raw_length`
    // requires a long run of valid frames, so these short magics do not
    // false-carve.
    Signature {
        name: "MP3 audio (frame sync)",
        ext: "mp3",
        magic: &[0xFF, 0xFB], // MPEG-1 Layer III, no CRC
        magic_offset: 0,
        secondary: None,
        extent: Extent::Mp3Raw,
        max_size: 100 * MB,
    },
    Signature {
        name: "MP3 audio (frame sync)",
        ext: "mp3",
        magic: &[0xFF, 0xFA], // MPEG-1 Layer III, CRC
        magic_offset: 0,
        secondary: None,
        extent: Extent::Mp3Raw,
        max_size: 100 * MB,
    },
    Signature {
        name: "MP3 audio (frame sync)",
        ext: "mp3",
        magic: &[0xFF, 0xF3], // MPEG-2 Layer III, no CRC
        magic_offset: 0,
        secondary: None,
        extent: Extent::Mp3Raw,
        max_size: 100 * MB,
    },
    Signature {
        name: "MP3 audio (frame sync)",
        ext: "mp3",
        magic: &[0xFF, 0xF2], // MPEG-2 Layer III, CRC
        magic_offset: 0,
        secondary: None,
        extent: Extent::Mp3Raw,
        max_size: 100 * MB,
    },
    Signature {
        name: "MP3 audio (frame sync)",
        ext: "mp3",
        magic: &[0xFF, 0xE3], // MPEG-2.5 Layer III, no CRC
        magic_offset: 0,
        secondary: None,
        extent: Extent::Mp3Raw,
        max_size: 100 * MB,
    },
    Signature {
        name: "MP3 audio (frame sync)",
        ext: "mp3",
        magic: &[0xFF, 0xE2], // MPEG-2.5 Layer III, CRC
        magic_offset: 0,
        secondary: None,
        extent: Extent::Mp3Raw,
        max_size: 100 * MB,
    },
    // HEIC/HEIF brands share the `ftyp` magic with MP4, so they must come first
    // and use a secondary brand tag (at offset 8 in the file => 4 past `ftyp`).
    Signature {
        name: "HEIC image",
        ext: "heic",
        magic: b"ftyp",
        magic_offset: 4,
        secondary: Some((4, b"heic")),
        extent: Extent::Mp4Atoms,
        max_size: 100 * MB,
    },
    Signature {
        name: "HEIC image",
        ext: "heic",
        magic: b"ftyp",
        magic_offset: 4,
        secondary: Some((4, b"heix")),
        extent: Extent::Mp4Atoms,
        max_size: 100 * MB,
    },
    Signature {
        name: "HEIF image",
        ext: "heic",
        magic: b"ftyp",
        magic_offset: 4,
        secondary: Some((4, b"mif1")),
        extent: Extent::Mp4Atoms,
        max_size: 100 * MB,
    },
    Signature {
        name: "AVIF image",
        ext: "avif",
        magic: b"ftyp",
        magic_offset: 4,
        secondary: Some((4, b"avif")),
        extent: Extent::Mp4Atoms,
        max_size: 100 * MB,
    },
    Signature {
        name: "Canon CR3 raw image",
        ext: "cr3",
        magic: b"ftyp",
        magic_offset: 4,
        secondary: Some((4, b"crx ")),
        extent: Extent::Mp4Atoms,
        max_size: 200 * MB,
    },
    Signature {
        name: "JPEG XL image",
        ext: "jxl",
        magic: b"ftyp",
        magic_offset: 4,
        secondary: Some((4, b"jxl ")),
        extent: Extent::Mp4Atoms,
        max_size: 200 * MB,
    },
    Signature {
        name: "3GP video",
        ext: "3gp",
        magic: b"ftyp",
        magic_offset: 4,
        // A 3-byte tag matches the "3gp4"/"3gp5"/"3gp6" major brands.
        secondary: Some((4, b"3gp")),
        extent: Extent::Mp4Atoms,
        max_size: 4 * GB,
    },
    Signature {
        name: "MP4/MOV/M4A media",
        ext: "mp4",
        magic: b"ftyp",
        magic_offset: 4, // preceded by a 4-byte box size
        secondary: None,
        extent: Extent::Mp4Atoms,
        max_size: 4 * GB,
    },
    Signature {
        name: "ELF executable / shared object",
        ext: "elf",
        magic: &[0x7F, b'E', b'L', b'F'],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Elf,
        max_size: 2 * GB,
    },
    Signature {
        name: "PE executable (EXE/DLL)",
        ext: "exe",
        magic: b"MZ",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Pe,
        max_size: 2 * GB,
    },
    // Mach-O thin binaries: one entry per magic (32/64-bit × byte order). Fat
    // (universal) binaries share Java's 0xCAFEBABE magic and are not carved.
    Signature {
        name: "Mach-O binary (64-bit LE)",
        ext: "macho",
        magic: &[0xCF, 0xFA, 0xED, 0xFE],
        magic_offset: 0,
        secondary: None,
        extent: Extent::MachO,
        max_size: 2 * GB,
    },
    Signature {
        name: "Mach-O binary (32-bit LE)",
        ext: "macho",
        magic: &[0xCE, 0xFA, 0xED, 0xFE],
        magic_offset: 0,
        secondary: None,
        extent: Extent::MachO,
        max_size: 2 * GB,
    },
    Signature {
        name: "Mach-O binary (64-bit BE)",
        ext: "macho",
        magic: &[0xFE, 0xED, 0xFA, 0xCF],
        magic_offset: 0,
        secondary: None,
        extent: Extent::MachO,
        max_size: 2 * GB,
    },
    Signature {
        name: "Mach-O binary (32-bit BE)",
        ext: "macho",
        magic: &[0xFE, 0xED, 0xFA, 0xCE],
        magic_offset: 0,
        secondary: None,
        extent: Extent::MachO,
        max_size: 2 * GB,
    },
    Signature {
        name: "Windows registry hive",
        ext: "regf",
        magic: b"regf",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Regf,
        max_size: 2 * GB,
    },
    // ADTS AAC: one entry per common first-two-byte sync (the sync word is
    // 0xFFF; the low nibble of byte 1 varies by MPEG version and CRC presence).
    // The frame-walk in `aac_length` rejects coincidental matches.
    Signature {
        name: "AAC audio (ADTS, MPEG-4)",
        ext: "aac",
        magic: &[0xFF, 0xF1],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Aac,
        max_size: 200 * MB,
    },
    Signature {
        name: "AAC audio (ADTS, MPEG-2)",
        ext: "aac",
        magic: &[0xFF, 0xF9],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Aac,
        max_size: 200 * MB,
    },
    Signature {
        name: "AAC audio (ADTS, MPEG-4, CRC)",
        ext: "aac",
        magic: &[0xFF, 0xF0],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Aac,
        max_size: 200 * MB,
    },
    Signature {
        name: "AAC audio (ADTS, MPEG-2, CRC)",
        ext: "aac",
        magic: &[0xFF, 0xF8],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Aac,
        max_size: 200 * MB,
    },
    Signature {
        name: "Android Dalvik executable (DEX)",
        ext: "dex",
        magic: b"dex\n",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Dex,
        max_size: GB,
    },
    Signature {
        name: "Windows Imaging (WIM)",
        ext: "wim",
        magic: b"MSWIM\x00\x00\x00",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Wim,
        max_size: 8 * GB,
    },
    Signature {
        name: "Flash movie (uncompressed)",
        ext: "swf",
        magic: b"FWS",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Swf,
        max_size: 500 * MB,
    },
    Signature {
        name: "ICC colour profile",
        ext: "icc",
        magic: b"acsp",
        magic_offset: 36,
        secondary: None,
        extent: Extent::Icc,
        max_size: 64 * MB,
    },
    Signature {
        name: "Unix ar archive (deb/static lib)",
        ext: "ar",
        magic: b"!<arch>\n",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Ar,
        max_size: 2 * GB,
    },
    Signature {
        name: "ESRI Shapefile",
        ext: "shp",
        magic: &[0x00, 0x00, 0x27, 0x0A], // file code 9994 (big-endian)
        magic_offset: 0,
        secondary: None,
        extent: Extent::Shp,
        max_size: 2 * GB,
    },
    Signature {
        name: "Blender file",
        ext: "blend",
        magic: b"BLENDER",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Blend,
        max_size: 2 * GB,
    },
    Signature {
        name: "NES ROM (iNES)",
        ext: "nes",
        magic: b"NES\x1a",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Nes,
        max_size: 64 * MB,
    },
    // Canon CR2 raw shares the little-endian TIFF magic, but carries a "CR" tag
    // at offset 8, so it must precede the generic TIFF entry.
    Signature {
        name: "Canon CR2 raw image",
        ext: "cr2",
        magic: &[0x49, 0x49, 0x2A, 0x00],
        magic_offset: 0,
        secondary: Some((8, b"CR")),
        extent: Extent::Tiff,
        max_size: 200 * MB,
    },
    Signature {
        name: "TIFF image / raw (DNG/NEF/ARW)",
        ext: "tif",
        magic: &[0x49, 0x49, 0x2A, 0x00], // little-endian ("II*\0")
        magic_offset: 0,
        secondary: None,
        extent: Extent::Tiff,
        max_size: 500 * MB,
    },
    Signature {
        name: "TIFF image / raw (DNG/NEF/ARW)",
        ext: "tif",
        magic: &[0x4D, 0x4D, 0x00, 0x2A], // big-endian ("MM\0*")
        magic_offset: 0,
        secondary: None,
        extent: Extent::Tiff,
        max_size: 500 * MB,
    },
    Signature {
        name: "BigTIFF image",
        ext: "tif",
        magic: &[0x49, 0x49, 0x2B, 0x00], // little-endian BigTIFF ("II+\0")
        magic_offset: 0,
        secondary: None,
        extent: Extent::Tiff,
        max_size: 2 * GB,
    },
    Signature {
        name: "BigTIFF image",
        ext: "tif",
        magic: &[0x4D, 0x4D, 0x00, 0x2B], // big-endian BigTIFF ("MM\0+")
        magic_offset: 0,
        secondary: None,
        extent: Extent::Tiff,
        max_size: 2 * GB,
    },
    Signature {
        name: "Matroska / WebM video",
        ext: "mkv",
        magic: &[0x1A, 0x45, 0xDF, 0xA3], // EBML header element ID
        magic_offset: 0,
        secondary: None,
        extent: Extent::Ebml,
        max_size: 16 * GB,
    },
    Signature {
        name: "Ogg (Vorbis/Opus/Theora)",
        ext: "ogg",
        magic: b"OggS",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Ogg,
        max_size: 2 * GB,
    },
    Signature {
        name: "ASF / WMV / WMA media",
        ext: "asf",
        // ASF Header Object GUID (75B22630-668E-11CF-A6D9-00AA0062CE6C).
        magic: &[
            0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62,
            0xCE, 0x6C,
        ],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Asf,
        max_size: 8 * GB,
    },
    Signature {
        name: "WebAssembly module",
        ext: "wasm",
        magic: &[0x00, 0x61, 0x73, 0x6D], // "\0asm"
        magic_offset: 0,
        secondary: None,
        extent: Extent::Wasm,
        max_size: GB,
    },
    Signature {
        name: "Windows icon",
        ext: "ico",
        magic: &[0x00, 0x00, 0x01, 0x00], // reserved=0, type=1 (icon)
        magic_offset: 0,
        secondary: None,
        extent: Extent::IcoCur,
        max_size: 16 * MB,
    },
    Signature {
        name: "Windows cursor",
        ext: "cur",
        magic: &[0x00, 0x00, 0x02, 0x00], // reserved=0, type=2 (cursor)
        magic_offset: 0,
        secondary: None,
        extent: Extent::IcoCur,
        max_size: 16 * MB,
    },
    Signature {
        name: "TrueType font",
        ext: "ttf",
        magic: &[0x00, 0x01, 0x00, 0x00], // sfnt version 1.0
        magic_offset: 0,
        secondary: None,
        extent: Extent::Sfnt,
        max_size: 64 * MB,
    },
    Signature {
        name: "OpenType font",
        ext: "otf",
        magic: b"OTTO", // sfnt with CFF outlines
        magic_offset: 0,
        secondary: None,
        extent: Extent::Sfnt,
        max_size: 64 * MB,
    },
    Signature {
        name: "WOFF web font",
        ext: "woff",
        magic: b"wOFF",
        magic_offset: 0,
        secondary: None,
        extent: Extent::HeaderSizeBe32 { offset: 8 },
        max_size: 64 * MB,
    },
    Signature {
        name: "WOFF2 web font",
        ext: "woff2",
        magic: b"wOF2",
        magic_offset: 0,
        secondary: None,
        extent: Extent::HeaderSizeBe32 { offset: 8 },
        max_size: 64 * MB,
    },
    Signature {
        name: "Enhanced Metafile",
        ext: "emf",
        // The EMR_HEADER's dSignature " EMF" sits 40 bytes into the file.
        magic: b" EMF",
        magic_offset: 40,
        secondary: None,
        extent: Extent::HeaderSizeLe32 { offset: 48 },
        max_size: 64 * MB,
    },
    Signature {
        name: "Standard MIDI",
        ext: "mid",
        magic: b"MThd",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Midi,
        max_size: 16 * MB,
    },
    Signature {
        name: "Flash Video",
        ext: "flv",
        magic: &[0x46, 0x4C, 0x56, 0x01], // "FLV" + version 1
        magic_offset: 0,
        secondary: None,
        extent: Extent::Flv,
        max_size: 2 * GB,
    },
    // libpcap: the magic is written in the host byte order, so it appears on
    // disk in either orientation; the microsecond and nanosecond variants
    // differ in the low bytes. The walker reads the byte order back from it.
    Signature {
        name: "pcap capture",
        ext: "pcap",
        magic: &[0xD4, 0xC3, 0xB2, 0xA1], // microsecond, little-endian host
        magic_offset: 0,
        secondary: None,
        extent: Extent::Pcap,
        max_size: 4 * GB,
    },
    Signature {
        name: "pcap capture",
        ext: "pcap",
        magic: &[0xA1, 0xB2, 0xC3, 0xD4], // microsecond, big-endian host
        magic_offset: 0,
        secondary: None,
        extent: Extent::Pcap,
        max_size: 4 * GB,
    },
    Signature {
        name: "pcap capture",
        ext: "pcap",
        magic: &[0x4D, 0x3C, 0xB2, 0xA1], // nanosecond, little-endian host
        magic_offset: 0,
        secondary: None,
        extent: Extent::Pcap,
        max_size: 4 * GB,
    },
    Signature {
        name: "pcap capture",
        ext: "pcap",
        magic: &[0xA1, 0xB2, 0x3C, 0x4D], // nanosecond, big-endian host
        magic_offset: 0,
        secondary: None,
        extent: Extent::Pcap,
        max_size: 4 * GB,
    },
    Signature {
        name: "pcapng capture",
        ext: "pcapng",
        // Section Header Block type, then the byte-order magic follows at +8.
        magic: &[0x0A, 0x0D, 0x0D, 0x0A],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Pcapng,
        max_size: 4 * GB,
    },
    Signature {
        name: "TrueType Collection",
        ext: "ttc",
        magic: b"ttcf",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Ttc,
        max_size: 256 * MB,
    },
    Signature {
        name: "JPEG 2000 image",
        ext: "jp2",
        // The 12-byte JP2 signature box: length 12, "jP  ", then 0D 0A 87 0A.
        magic: &[
            0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A,
        ],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Mp4Atoms,
        max_size: 512 * MB,
    },
    Signature {
        name: "JPEG 2000 codestream",
        ext: "j2k",
        // SOC marker (FF4F) immediately followed by the SIZ marker (FF51).
        magic: &[0xFF, 0x4F, 0xFF, 0x51],
        magic_offset: 0,
        secondary: None,
        // The codestream ends at the EOC marker (FF D9). JPEG 2000 packet data is
        // bit-stuffed so an FF is never followed by a marker byte, making FF D9
        // unambiguous.
        extent: Extent::Footer {
            marker: &[0xFF, 0xD9],
            trailing: 0,
        },
        max_size: 512 * MB,
    },
    Signature {
        name: "Windows animated cursor",
        ext: "ani",
        magic: b"RIFF",
        magic_offset: 0,
        secondary: Some((8, b"ACON")),
        extent: Extent::RiffSize,
        max_size: 16 * MB,
    },
    Signature {
        // Legacy Office and other OLE2 containers; refined to doc/xls/ppt by
        // inspecting the directory stream names (see `classify_cfbf`).
        name: "Compound File Binary (OLE2)",
        ext: "ole",
        magic: &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
        magic_offset: 0,
        // The little-endian byte-order mark at offset 28 rejects a coincidental
        // magic; CFBF is always little-endian in practice.
        secondary: Some((28, &[0xFE, 0xFF])),
        extent: Extent::Cfbf,
        max_size: 2 * GB,
    },
    Signature {
        // Outlook data file (PST/OST). "!BDN" magic, then the "SM" client tag at
        // offset 8; the size is read from the header's ibFileEof field.
        name: "Outlook data file (PST/OST)",
        ext: "pst",
        magic: &[0x21, 0x42, 0x44, 0x4E],
        magic_offset: 0,
        secondary: Some((8, b"SM")),
        extent: Extent::Pst,
        max_size: 50 * GB,
    },
];

/// Look up signatures relevant to a single source byte, keyed by the first
/// byte of their magic *as it appears on disk*. The on-disk first byte is the
/// first byte of `magic` (because `magic_offset` shifts the file start
/// backward, not the magic position).
pub struct SignatureIndex {
    /// For each possible leading byte, the signatures whose magic starts with
    /// it. Most slots are empty, keeping per-byte work tiny.
    by_first_byte: [Vec<&'static Signature>; 256],
    /// Largest number of bytes we must inspect from the magic position to
    /// confirm any magic *and* its secondary tag.
    pub max_lookahead: usize,
}

impl SignatureIndex {
    pub fn build(active: &[&'static Signature]) -> Self {
        // `Vec` is not `Copy`, so build the array element by element.
        let by_first_byte: [Vec<&'static Signature>; 256] = std::array::from_fn(|_| Vec::new());
        let mut idx = SignatureIndex {
            by_first_byte,
            max_lookahead: 0,
        };
        for sig in active {
            let first = sig.magic[0] as usize;
            idx.by_first_byte[first].push(sig);
            let reach = match sig.secondary {
                Some((off, tag)) => sig.magic.len().max(off + tag.len()),
                None => sig.magic.len(),
            };
            idx.max_lookahead = idx.max_lookahead.max(reach);
        }
        idx
    }

    /// Return the signature whose magic (and secondary tag, if any) matches the
    /// bytes starting at `window`. `window` must begin at the on-disk position
    /// of a candidate magic.
    pub fn match_at(&self, window: &[u8]) -> Option<&'static Signature> {
        let first = *window.first()? as usize;
        for sig in &self.by_first_byte[first] {
            if window.len() < sig.magic.len() || &window[..sig.magic.len()] != sig.magic {
                continue;
            }
            if let Some((off, tag)) = sig.secondary {
                if window.len() < off + tag.len() || &window[off..off + tag.len()] != tag {
                    continue;
                }
            }
            return Some(sig);
        }
        None
    }
}

/// Resolve user-requested type names (extensions or `"all"`) to signatures.
///
/// Returns an error listing the offending name if one is unknown.
pub fn select(types: &[String]) -> anyhow::Result<Vec<&'static Signature>> {
    if types.is_empty() || types.iter().any(|t| t.eq_ignore_ascii_case("all")) {
        return Ok(SIGNATURES.iter().collect());
    }
    let mut selected = Vec::new();
    for t in types {
        // A token may name a whole category (e.g. "image", "audio") or a single
        // extension. Categories are tried first so they take precedence.
        if let Some(cat) = Category::from_name(t) {
            selected.extend(SIGNATURES.iter().filter(|s| category_of(s.ext) == cat));
            continue;
        }
        let matches: Vec<&'static Signature> = SIGNATURES
            .iter()
            .filter(|s| s.ext.eq_ignore_ascii_case(t))
            .collect();
        if matches.is_empty() {
            // De-duplicate known extensions for the error message.
            let mut known: Vec<&str> = SIGNATURES.iter().map(|s| s.ext).collect();
            known.dedup();
            anyhow::bail!(
                "unknown file type or category '{t}'. Categories: {}. Known types: {}",
                Category::NAMES.join(", "),
                known.join(", ")
            );
        }
        selected.extend(matches);
    }
    Ok(selected)
}

/// A broad grouping of file types, so a whole class (e.g. all images) can be
/// selected with one name instead of listing every extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    Image,
    Audio,
    Video,
    Document,
    Archive,
    Executable,
    Font,
    System,
    Other,
}

impl Category {
    /// The selectable category names, in display order.
    pub const NAMES: &'static [&'static str] = &[
        "image",
        "audio",
        "video",
        "document",
        "archive",
        "executable",
        "font",
        "system",
    ];

    /// Resolve a user-supplied category name (case-insensitive; a trailing "s"
    /// is allowed, e.g. "images"). `Other` is not selectable by name.
    pub fn from_name(name: &str) -> Option<Category> {
        let n = name.trim().to_ascii_lowercase();
        let n = n.strip_suffix('s').unwrap_or(&n);
        match n {
            "image" => Some(Category::Image),
            "audio" => Some(Category::Audio),
            "video" => Some(Category::Video),
            "document" | "doc" => Some(Category::Document),
            "archive" => Some(Category::Archive),
            "executable" => Some(Category::Executable), // "exe" stays a file type
            "font" => Some(Category::Font),
            "system" => Some(Category::System),
            _ => None,
        }
    }

    /// The category's lowercase name (the inverse of [`Category::from_name`]).
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Image => "image",
            Category::Audio => "audio",
            Category::Video => "video",
            Category::Document => "document",
            Category::Archive => "archive",
            Category::Executable => "executable",
            Category::Font => "font",
            Category::System => "system",
            Category::Other => "other",
        }
    }
}

/// Refine a ZIP into the specific ZIP-based format it carries, by looking for a
/// marker member name in its bytes. Returns `(extension, name)` for a known
/// format, or `None` for a plain ZIP. APK is checked before JAR because both
/// carry `META-INF/MANIFEST.MF`.
pub fn classify_zip(head: &[u8]) -> Option<(&'static str, &'static str)> {
    let has = |needle: &[u8]| head.windows(needle.len()).any(|w| w == needle);
    if has(b"application/epub+zip") {
        Some(("epub", "EPUB e-book"))
    } else if has(b"application/vnd.oasis.opendocument.text") {
        Some(("odt", "OpenDocument text"))
    } else if has(b"application/vnd.oasis.opendocument.spreadsheet") {
        Some(("ods", "OpenDocument spreadsheet"))
    } else if has(b"application/vnd.oasis.opendocument.presentation") {
        Some(("odp", "OpenDocument presentation"))
    } else if has(b"AndroidManifest.xml") {
        Some(("apk", "Android package"))
    } else if has(b"word/document.xml") {
        Some(("docx", "Word (OOXML) document"))
    } else if has(b"xl/workbook.xml") {
        Some(("xlsx", "Excel (OOXML) workbook"))
    } else if has(b"ppt/presentation.xml") {
        Some(("pptx", "PowerPoint (OOXML) presentation"))
    } else if has(b"META-INF/MANIFEST.MF") {
        Some(("jar", "Java archive"))
    } else {
        None
    }
}

/// Root storage CLSID of a Windows Installer database (`{000C1084-0000-0000-
/// C000-000000000046}`), stored as a GUID: the first three fields little-endian,
/// the last eight bytes in order.
const MSI_CLSID: [u8; 16] = [
    0x84, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// Read the root directory entry's CLSID (16 bytes at directory-entry offset 80)
/// and compare it to `clsid`. Returns false if the directory sector isn't within
/// `head` (so the caller falls back to other checks).
fn root_clsid_is(head: &[u8], clsid: &[u8; 16]) -> bool {
    if head.len() < 512 {
        return false;
    }
    let sector_size = match u16::from_le_bytes([head[30], head[31]]) {
        9 => 512usize,
        12 => 4096usize,
        _ => return false,
    };
    let first_dir = u32::from_le_bytes([head[48], head[49], head[50], head[51]]) as usize;
    // The root entry is the first 128-byte record of the directory sector, which
    // starts at byte `(sector + 1) * sector_size`.
    let clsid_off = match first_dir
        .checked_add(1)
        .and_then(|s| s.checked_mul(sector_size))
        .and_then(|o| o.checked_add(80))
    {
        Some(o) => o,
        None => return false,
    };
    head.len() >= clsid_off + 16 && &head[clsid_off..clsid_off + 16] == clsid
}

/// Refine a Compound File Binary (OLE2) container into the specific format it
/// carries. Most legacy formats are recognised by a marker stream name (stored
/// as UTF-16LE, so each ASCII letter is matched interleaved with a NUL byte);
/// installer databases, whose stream names are mangled, are recognised by the
/// root storage CLSID instead. Returns `(extension, name)`, or `None` for an
/// unrecognised compound file (which stays a generic `.ole`).
pub fn classify_cfbf(head: &[u8]) -> Option<(&'static str, &'static str)> {
    let has = |name: &str| {
        let needle: Vec<u8> = name.bytes().flat_map(|b| [b, 0]).collect();
        head.windows(needle.len()).any(|w| w == needle)
    };
    if root_clsid_is(head, &MSI_CLSID) {
        Some(("msi", "Windows Installer package"))
    } else if has("__substg1.0_") {
        // Property-stream prefix unique to Outlook .msg messages.
        Some(("msg", "Outlook message"))
    } else if has("PowerPoint Document") {
        Some(("ppt", "PowerPoint 97-2003 presentation"))
    } else if has("WordDocument") {
        Some(("doc", "Word 97-2003 document"))
    } else if has("Workbook") || has("Book") {
        Some(("xls", "Excel 97-2003 workbook"))
    } else {
        None
    }
}

/// Classify a file-type extension into a [`Category`].
pub fn category_of(ext: &str) -> Category {
    match ext {
        "jpg" | "png" | "gif" | "bmp" | "tif" | "webp" | "heic" | "avif" | "jp2" | "j2k"
        | "jxl" | "ico" | "cur" | "icns" | "cr2" | "cr3" | "psd" | "wmf" | "emf" | "djvu"
        | "ani" => Category::Image,
        "mp3" | "aac" | "wav" | "aiff" | "aifc" | "ogg" | "mid" => Category::Audio,
        "mp4" | "3gp" | "mkv" | "avi" | "flv" | "asf" => Category::Video,
        // The OOXML/OpenDocument/e-book types come from ZIP-content
        // classification; doc/xls/ppt/msg (and a generic OLE2 container) from
        // CFBF.
        "pdf" | "rtf" | "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" | "epub" | "doc"
        | "xls" | "ppt" | "msg" | "pst" | "ole" => Category::Document,
        "zip" | "7z" | "rar" | "cab" | "ar" | "zst" | "lz4" | "jar" => Category::Archive,
        "elf" | "exe" | "macho" | "dex" | "wasm" | "apk" | "msi" => Category::Executable,
        "ttf" | "otf" | "woff" | "woff2" | "ttc" => Category::Font,
        "regf" | "evtx" | "wim" | "sqlite" | "pcap" | "pcapng" => Category::System,
        _ => Category::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index() -> SignatureIndex {
        let all = select(&[]).unwrap();
        SignatureIndex::build(&all)
    }

    fn ext_of(window: &[u8]) -> Option<&'static str> {
        index().match_at(window).map(|s| s.ext)
    }

    #[test]
    fn riff_secondary_tag_disambiguates() {
        assert_eq!(ext_of(b"RIFF\0\0\0\0WAVE"), Some("wav"));
        assert_eq!(ext_of(b"RIFF\0\0\0\0AVI "), Some("avi"));
        assert_eq!(ext_of(b"RIFF\0\0\0\0WEBP"), Some("webp"));
        // An unknown RIFF form type matches nothing (no generic fallback).
        assert_eq!(ext_of(b"RIFF\0\0\0\0JUNK"), None);
    }

    #[test]
    fn ftyp_brand_picks_heic_over_mp4() {
        // The window starts at the `ftyp` magic; the brand is 4 bytes later.
        assert_eq!(ext_of(b"ftypheic"), Some("heic"));
        assert_eq!(ext_of(b"ftypmif1"), Some("heic"));
        // A non-HEIF brand falls through to the generic MP4 entry.
        assert_eq!(ext_of(b"ftypqt  "), Some("mp4"));
    }

    #[test]
    fn plain_magics_match() {
        assert_eq!(ext_of(&[0xFF, 0xD8, 0xFF, 0x00]), Some("jpg"));
        assert_eq!(ext_of(b"SQLite format 3\0"), Some("sqlite"));
        assert_eq!(ext_of(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]), Some("7z"));
        assert_eq!(ext_of(b"not a magic"), None);
    }

    #[test]
    fn select_filters_and_rejects() {
        assert_eq!(select(&["jpg".to_string()]).unwrap().len(), 1);
        // "gif" maps to two entries (87a and 89a).
        assert_eq!(select(&["gif".to_string()]).unwrap().len(), 2);
        assert!(select(&["all".to_string()]).unwrap().len() >= 13);
        let err = select(&["nope".to_string()]).unwrap_err().to_string();
        assert!(err.contains("unknown file type or category"));
    }

    #[test]
    fn select_by_category() {
        // A category expands to every signature classified into it.
        let images = select(&["image".to_string()]).unwrap();
        assert!(images.iter().all(|s| category_of(s.ext) == Category::Image));
        assert!(images.iter().any(|s| s.ext == "jpg"));
        assert!(images.iter().any(|s| s.ext == "png"));
        assert!(!images.iter().any(|s| s.ext == "mp3"));

        // Plural form is accepted.
        assert_eq!(select(&["images".to_string()]).unwrap().len(), images.len());

        // "executable" is a category; "exe" remains a single file type.
        assert!(select(&["executable".to_string()])
            .unwrap()
            .iter()
            .any(|s| s.ext == "elf"));
        assert_eq!(select(&["exe".to_string()]).unwrap().len(), 1);

        // Categories and extensions can be mixed in one selection.
        let mixed = select(&["audio".to_string(), "pdf".to_string()]).unwrap();
        assert!(mixed.iter().any(|s| s.ext == "mp3"));
        assert!(mixed.iter().any(|s| s.ext == "pdf"));
    }
}
