//! Partition-table inspection for `info`/`list_volumes`.
//!
//! [`recover::detect`](crate::recover::detect) walks the partition table to find
//! *filesystems*; this module instead reports the **table itself** — the scheme
//! (GPT or MBR) and each entry's type, name, and byte range — so a user can see
//! the on-disk layout even for partitions whose filesystem isn't recovered
//! (e.g. an EFI System Partition, a swap partition, or an empty slot).
//!
//! For GPT, if the primary header (LBA 1) is missing or corrupt the layout is
//! read from the backup header and entry array at the end of the disk, with
//! [`Table::from_backup`] set so callers can flag it. For MBR, the logical
//! partitions inside an extended partition are enumerated by walking the
//! Extended Boot Record chain, so disks with more than four partitions report
//! all of them. For GPT, each partition's unique GUID (PARTUUID) and the disk
//! GUID are reported too.

use crate::source::Source;

/// The partitioning scheme of a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Gpt,
    Mbr,
    /// No partition table (a bare filesystem, or an unrecognised source).
    None,
}

/// One partition-table entry.
pub struct Partition {
    /// Human-readable partition type (a known GPT type, a known MBR type byte,
    /// or the raw GUID / `0xNN` code for an unrecognised one).
    pub kind: String,
    /// GPT partition name, when present and non-empty. Always `None` for MBR.
    pub name: Option<String>,
    /// The partition's **unique** GUID (the PARTUUID that `/etc/fstab`,
    /// bootloaders, and `/dev/disk/by-partuuid` reference). `None` for MBR.
    pub uuid: Option<String>,
    /// Byte offset of the partition within the source.
    pub start: u64,
    /// Size of the partition in bytes.
    pub size: u64,
    /// Notable attribute flags: GPT attribute bits (`required`,
    /// `legacy-bios-bootable`, `hidden`, `read-only`, …) or, for MBR, `active`
    /// when the boot flag is set. Empty when none apply.
    pub attributes: Vec<&'static str>,
}

/// Decode the GPT partition-entry attribute bitmask (a u64 at entry offset 48)
/// into human-readable flag names. The low bits are generic; bits 60–63 are the
/// type-specific flags used by Microsoft Basic Data partitions.
fn gpt_attributes(attr: u64) -> Vec<&'static str> {
    let mut out = Vec::new();
    if attr & (1 << 0) != 0 {
        out.push("required");
    }
    if attr & (1 << 1) != 0 {
        out.push("no-block-io");
    }
    if attr & (1 << 2) != 0 {
        out.push("legacy-bios-bootable");
    }
    if attr & (1 << 60) != 0 {
        out.push("read-only");
    }
    if attr & (1 << 62) != 0 {
        out.push("hidden");
    }
    if attr & (1 << 63) != 0 {
        out.push("no-automount");
    }
    out
}

/// A parsed partition table.
pub struct Table {
    pub scheme: Scheme,
    pub partitions: Vec<Partition>,
    /// True when a GPT was read from the **backup** header at the end of the
    /// disk because the primary header (LBA 1) was missing or corrupt. Always
    /// `false` for MBR or when the primary GPT was used.
    pub from_backup: bool,
    /// The GPT disk GUID (a unique identifier for the whole disk). `None` for
    /// MBR or when there is no table.
    pub disk_guid: Option<String>,
}

/// Read the partition table of `src`: GPT if a protective header is present,
/// else an MBR if the boot signature is present, else `Scheme::None`.
pub fn read(src: &Source) -> Table {
    if let Some(t) = read_gpt(src) {
        return t;
    }
    if let Some(t) = read_mbr(src) {
        return t;
    }
    Table {
        scheme: Scheme::None,
        partitions: Vec::new(),
        from_backup: false,
        disk_guid: None,
    }
}

/// Read a GPT, preferring the primary header at LBA 1 but falling back to the
/// backup header at the last LBA when the primary is missing or corrupt (e.g.
/// the first sectors were overwritten). Tries 512- and 4096-byte sectors.
fn read_gpt(src: &Source) -> Option<Table> {
    for sector_size in [512u64, 4096] {
        // Primary GPT header sits at LBA 1.
        if let Some((partitions, disk_guid)) = parse_gpt_at(src, sector_size, sector_size) {
            return Some(Table {
                scheme: Scheme::Gpt,
                partitions,
                from_backup: false,
                disk_guid,
            });
        }
        // Backup GPT header sits at the last LBA of the disk.
        if let Some(backup_off) = src.size.checked_sub(sector_size) {
            if let Some((partitions, disk_guid)) = parse_gpt_at(src, sector_size, backup_off) {
                return Some(Table {
                    scheme: Scheme::Gpt,
                    partitions,
                    from_backup: true,
                    disk_guid,
                });
            }
        }
    }
    None
}

/// Parse a GPT header located at byte offset `hdr_off` and read its partition
/// entries (the header's own `PartitionEntryLBA` field locates the array, so
/// this works for both the primary and the backup header). `None` if there is
/// no valid `EFI PART` header there.
fn parse_gpt_at(
    src: &Source,
    sector_size: u64,
    hdr_off: u64,
) -> Option<(Vec<Partition>, Option<String>)> {
    let mut hdr = [0u8; 92];
    if src.read_at(hdr_off, &mut hdr).ok()? < 92 || &hdr[0..8] != b"EFI PART" {
        return None;
    }
    let entry_lba = u64::from_le_bytes(hdr[72..80].try_into().unwrap());
    let num_entries = (u32::from_le_bytes(hdr[80..84].try_into().unwrap()) as u64).min(1024);
    let entry_size = u32::from_le_bytes(hdr[84..88].try_into().unwrap()) as u64;
    if !(128..=4096).contains(&entry_size) {
        return None;
    }
    // The disk GUID lives at header offset 56.
    let disk_guid = non_zero_guid(&hdr[56..72]);
    let array_start = entry_lba.checked_mul(sector_size)?;
    let mut partitions = Vec::new();
    let mut entry = vec![0u8; entry_size as usize];
    for i in 0..num_entries {
        let off = array_start + i * entry_size;
        if src.read_at(off, &mut entry).ok()? < entry_size as usize {
            break;
        }
        if entry[0..16].iter().all(|&b| b == 0) {
            continue; // unused slot
        }
        let first = u64::from_le_bytes(entry[32..40].try_into().unwrap());
        let last = u64::from_le_bytes(entry[40..48].try_into().unwrap());
        let size = last.saturating_sub(first).saturating_add(1) * sector_size;
        partitions.push(Partition {
            kind: gpt_type_name(&entry[0..16]),
            name: gpt_name(&entry[56..entry_size.min(128) as usize]),
            // The unique partition GUID (PARTUUID) is at entry offset 16.
            uuid: non_zero_guid(&entry[16..32]),
            start: first * sector_size,
            size,
            attributes: gpt_attributes(u64::from_le_bytes(entry[48..56].try_into().unwrap())),
        });
    }
    Some((partitions, disk_guid))
}

/// Format a 16-byte GUID, returning `None` when it is all zero (unset).
fn non_zero_guid(g: &[u8]) -> Option<String> {
    if g.iter().all(|&b| b == 0) {
        None
    } else {
        Some(guid_string(g))
    }
}

fn read_mbr(src: &Source) -> Option<Table> {
    let mut sec = [0u8; 512];
    if src.read_at(0, &mut sec).ok()? < 512 || sec[510] != 0x55 || sec[511] != 0xAA {
        return None;
    }
    let mut partitions = Vec::new();
    for i in 0..4 {
        let e = 446 + i * 16;
        let kind = sec[e + 4];
        let start_lba = u32::from_le_bytes(sec[e + 8..e + 12].try_into().unwrap()) as u64;
        let sectors = u32::from_le_bytes(sec[e + 12..e + 16].try_into().unwrap()) as u64;
        if kind == 0 || start_lba == 0 {
            continue; // empty slot
        }
        partitions.push(Partition {
            kind: mbr_type_name(kind),
            name: None,
            uuid: None,
            start: start_lba * 512,
            size: sectors * 512,
            // The entry's status byte: 0x80 marks the active (bootable) partition.
            attributes: if sec[e] == 0x80 {
                vec!["active"]
            } else {
                vec![]
            },
        });
        // An extended partition holds a linked list of logical partitions in
        // Extended Boot Records; walk that chain so they show up too.
        if is_extended_mbr(kind) {
            walk_ebr_chain(src, start_lba, &mut partitions);
        }
    }
    if partitions.is_empty() {
        return None;
    }
    Some(Table {
        scheme: Scheme::Mbr,
        partitions,
        from_backup: false,
        disk_guid: None,
    })
}

/// MBR partition type codes for an extended (container) partition.
fn is_extended_mbr(kind: u8) -> bool {
    matches!(kind, 0x05 | 0x0F | 0x85)
}

/// Walk the Extended Boot Record chain of an extended partition that begins at
/// `ext_base_lba`, appending each logical partition to `out`. Each EBR holds the
/// logical partition (offset relative to the EBR) and a pointer to the next EBR
/// (offset relative to the extended-partition base). Bounded against a
/// malformed or cyclic chain.
fn walk_ebr_chain(src: &Source, ext_base_lba: u64, out: &mut Vec<Partition>) {
    const MAX_LOGICAL: usize = 256;
    let mut ebr_lba = ext_base_lba;
    let mut visited = std::collections::HashSet::new();
    for _ in 0..MAX_LOGICAL {
        if !visited.insert(ebr_lba) {
            break; // a self-referential chain would otherwise loop forever
        }
        let Some(off) = ebr_lba.checked_mul(512) else {
            break;
        };
        let mut sec = [0u8; 512];
        if src.read_at(off, &mut sec).unwrap_or(0) < 512 || sec[510] != 0x55 || sec[511] != 0xAA {
            break;
        }
        // Entry 0: the logical partition, its start relative to this EBR.
        let kind = sec[446 + 4];
        let rel = u32::from_le_bytes(sec[446 + 8..446 + 12].try_into().unwrap()) as u64;
        let sectors = u32::from_le_bytes(sec[446 + 12..446 + 16].try_into().unwrap()) as u64;
        if kind != 0 && sectors != 0 {
            out.push(Partition {
                kind: mbr_type_name(kind),
                name: None,
                uuid: None,
                start: ebr_lba.saturating_add(rel) * 512,
                size: sectors * 512,
                attributes: if sec[446] == 0x80 {
                    vec!["active"]
                } else {
                    vec![]
                },
            });
        }
        // Entry 1: pointer to the next EBR, its start relative to the extended
        // base. An empty or non-extended pointer ends the chain.
        let next_kind = sec[446 + 16 + 4];
        let next_rel =
            u32::from_le_bytes(sec[446 + 16 + 8..446 + 16 + 12].try_into().unwrap()) as u64;
        if !is_extended_mbr(next_kind) || next_rel == 0 {
            break;
        }
        ebr_lba = ext_base_lba.saturating_add(next_rel);
    }
}

/// Format a 16-byte GPT GUID in canonical `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`
/// form (the first three groups are little-endian on disk, the rest big-endian).
fn guid_string(g: &[u8]) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15],
    )
}

/// Map a GPT type GUID to a friendly name, or fall back to the raw GUID.
fn gpt_type_name(g: &[u8]) -> String {
    let guid = guid_string(g);
    let name = match guid.as_str() {
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => "EFI System",
        "21686148-6449-6E6F-744E-656564454649" => "BIOS boot",
        "E3C9E316-0B5C-4DB8-817D-F92DF00215AE" => "Microsoft reserved",
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => "Microsoft basic data",
        "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC" => "Windows recovery",
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => "Linux filesystem",
        "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F" => "Linux swap",
        "E6D6D379-F507-44C2-A23C-238F2A3DF928" => "Linux LVM",
        "A19D880F-05FC-4D3B-A006-743F0F84911E" => "Linux RAID",
        "933AC7E1-2EB4-4F13-B844-0E14E2AEF915" => "Linux /home",
        "7C3457EF-0000-11AA-AA11-00306543ECAC" => "Apple APFS",
        "48465300-0000-11AA-AA11-00306543ECAC" => "Apple HFS+",
        "426F6F74-0000-11AA-AA11-00306543ECAC" => "Apple boot (recovery)",
        _ => return guid,
    };
    name.to_string()
}

/// Map a common MBR partition type byte to a friendly name.
fn mbr_type_name(t: u8) -> String {
    let name = match t {
        0x07 => "NTFS / exFAT",
        0x0B | 0x0C => "FAT32",
        0x04 | 0x06 | 0x0E => "FAT16",
        0x01 => "FAT12",
        0x05 | 0x0F => "Extended",
        0x82 => "Linux swap",
        0x83 => "Linux",
        0x8E => "Linux LVM",
        0xFD => "Linux RAID",
        0xAF => "Apple HFS+",
        0xEE => "GPT protective",
        0xEF => "EFI System",
        _ => return format!("0x{t:02X}"),
    };
    name.to_string()
}

/// Decode a GPT partition name (UTF-16LE, NUL-padded), or `None` if empty.
fn gpt_name(raw: &[u8]) -> Option<String> {
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    if units.is_empty() {
        None
    } else {
        Some(String::from_utf16_lossy(&units))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("d.img");
        std::fs::write(&p, bytes).unwrap();
        (tmp, Source::open(&p).unwrap())
    }

    #[test]
    fn reads_an_mbr_table() {
        let mut disk = vec![0u8; 4096];
        disk[510] = 0x55;
        disk[511] = 0xAA;
        // Partition 0: Linux (0x83) at LBA 2048, 100 sectors, marked active.
        let e = 446;
        disk[e] = 0x80; // boot/active flag
        disk[e + 4] = 0x83;
        disk[e + 8..e + 12].copy_from_slice(&2048u32.to_le_bytes());
        disk[e + 12..e + 16].copy_from_slice(&100u32.to_le_bytes());
        // Partition 1: NTFS/exFAT (0x07) at LBA 4096, 200 sectors.
        let e = 446 + 16;
        disk[e + 4] = 0x07;
        disk[e + 8..e + 12].copy_from_slice(&4096u32.to_le_bytes());
        disk[e + 12..e + 16].copy_from_slice(&200u32.to_le_bytes());

        let (_t, src) = source_of(&disk);
        let table = read(&src);
        assert_eq!(table.scheme, Scheme::Mbr);
        assert_eq!(table.partitions.len(), 2);
        assert_eq!(table.partitions[0].kind, "Linux");
        assert_eq!(table.partitions[0].start, 2048 * 512);
        assert_eq!(table.partitions[0].size, 100 * 512);
        assert_eq!(table.partitions[0].attributes, vec!["active"]);
        assert_eq!(table.partitions[1].kind, "NTFS / exFAT");
        assert!(table.partitions[1].attributes.is_empty());
    }

    #[test]
    fn walks_mbr_extended_logical_partitions() {
        const SS: usize = 512;
        let mut disk = vec![0u8; 64 * SS];
        disk[510] = 0x55;
        disk[511] = 0xAA;
        // Primary 0: Linux (0x83) at LBA 1, 4 sectors.
        let e = 446;
        disk[e + 4] = 0x83;
        disk[e + 8..e + 12].copy_from_slice(&1u32.to_le_bytes());
        disk[e + 12..e + 16].copy_from_slice(&4u32.to_le_bytes());
        // Primary 1: Extended (0x05) container at LBA 20, 40 sectors.
        let e = 446 + 16;
        disk[e + 4] = 0x05;
        disk[e + 8..e + 12].copy_from_slice(&20u32.to_le_bytes());
        disk[e + 12..e + 16].copy_from_slice(&40u32.to_le_bytes());

        // EBR 1 at LBA 20: logical Linux at +2 (LBA 22), next EBR at base+10.
        let b = 20 * SS;
        disk[b + 510] = 0x55;
        disk[b + 511] = 0xAA;
        let e = b + 446;
        disk[e + 4] = 0x83;
        disk[e + 8..e + 12].copy_from_slice(&2u32.to_le_bytes());
        disk[e + 12..e + 16].copy_from_slice(&4u32.to_le_bytes());
        let e = b + 446 + 16;
        disk[e + 4] = 0x05;
        disk[e + 8..e + 12].copy_from_slice(&10u32.to_le_bytes());
        disk[e + 12..e + 16].copy_from_slice(&20u32.to_le_bytes());

        // EBR 2 at LBA 30: logical NTFS at +2 (LBA 32); chain ends (entry 1 = 0).
        let b = 30 * SS;
        disk[b + 510] = 0x55;
        disk[b + 511] = 0xAA;
        let e = b + 446;
        disk[e + 4] = 0x07;
        disk[e + 8..e + 12].copy_from_slice(&2u32.to_le_bytes());
        disk[e + 12..e + 16].copy_from_slice(&4u32.to_le_bytes());

        let (_t, src) = source_of(&disk);
        let table = read(&src);
        assert_eq!(table.scheme, Scheme::Mbr);
        // primary Linux, the extended container, then the two logicals.
        assert_eq!(table.partitions.len(), 4);
        assert_eq!(table.partitions[0].kind, "Linux");
        assert_eq!(table.partitions[1].kind, "Extended");
        assert_eq!(table.partitions[2].kind, "Linux");
        assert_eq!(table.partitions[2].start, 22 * 512); // EBR1 LBA + relative 2
        assert_eq!(table.partitions[3].kind, "NTFS / exFAT");
        assert_eq!(table.partitions[3].start, 32 * 512); // EBR2 LBA + relative 2
    }

    #[test]
    fn reads_a_gpt_table_with_type_and_name() {
        const SS: usize = 512;
        let mut disk = vec![0u8; 64 * SS];
        // Protective MBR signature (GPT readers still want it; our reader checks
        // the GPT header directly).
        disk[510] = 0x55;
        disk[511] = 0xAA;
        // GPT header at LBA 1.
        let h = SS;
        disk[h..h + 8].copy_from_slice(b"EFI PART");
        disk[h + 72..h + 80].copy_from_slice(&2u64.to_le_bytes()); // entry array at LBA 2
        disk[h + 80..h + 84].copy_from_slice(&1u32.to_le_bytes()); // 1 entry
        disk[h + 84..h + 88].copy_from_slice(&128u32.to_le_bytes()); // entry size
                                                                     // Disk GUID at header offset 56.
        disk[h + 56..h + 72].copy_from_slice(&[0xAB; 16]);

        // Entry 0 at LBA 2: EFI System type, name "EFI", LBAs 34..=2081.
        let e = 2 * SS;
        let efi = [
            0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E,
            0xC9, 0x3B,
        ];
        disk[e..e + 16].copy_from_slice(&efi);
        // The unique partition GUID at entry offset 16.
        disk[e + 16..e + 32].copy_from_slice(&[0xCD; 16]);
        disk[e + 32..e + 40].copy_from_slice(&34u64.to_le_bytes());
        disk[e + 40..e + 48].copy_from_slice(&2081u64.to_le_bytes());
        // Attributes (offset 48): Required (bit 0) | Legacy BIOS Bootable (bit 2).
        disk[e + 48..e + 56].copy_from_slice(&0b101u64.to_le_bytes());
        for (i, u) in "EFI".encode_utf16().enumerate() {
            disk[e + 56 + i * 2..e + 58 + i * 2].copy_from_slice(&u.to_le_bytes());
        }

        let (_t, src) = source_of(&disk);
        let table = read(&src);
        assert_eq!(table.scheme, Scheme::Gpt);
        assert!(!table.from_backup, "primary header was used");
        // The disk GUID and the partition's unique GUID are parsed in canonical
        // 8-4-4-4-12 form.
        let disk_guid = table.disk_guid.as_deref().unwrap();
        assert_eq!(disk_guid.len(), 36);
        assert_eq!(disk_guid.matches('-').count(), 4);
        assert_eq!(table.partitions.len(), 1);
        assert_eq!(table.partitions[0].kind, "EFI System");
        assert_eq!(table.partitions[0].name.as_deref(), Some("EFI"));
        assert_eq!(table.partitions[0].uuid.as_deref().unwrap().len(), 36);
        assert_eq!(table.partitions[0].start, 34 * 512);
        assert_eq!(
            table.partitions[0].attributes,
            vec!["required", "legacy-bios-bootable"]
        );
    }

    #[test]
    fn falls_back_to_backup_gpt_header() {
        const SS: usize = 512;
        let sectors = 64usize;
        let mut disk = vec![0u8; sectors * SS];
        // The primary GPT header (LBA 1) is wiped: no "EFI PART" there. The
        // backup header lives at the last LBA and points to its own entry array.
        let b = (sectors - 1) * SS;
        disk[b..b + 8].copy_from_slice(b"EFI PART");
        disk[b + 72..b + 80].copy_from_slice(&((sectors as u64) - 3).to_le_bytes()); // array LBA
        disk[b + 80..b + 84].copy_from_slice(&1u32.to_le_bytes()); // 1 entry
        disk[b + 84..b + 88].copy_from_slice(&128u32.to_le_bytes()); // entry size

        // Backup entry array (LBA 61): one EFI System entry, LBAs 34..=2081.
        let e = (sectors - 3) * SS;
        let efi = [
            0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E,
            0xC9, 0x3B,
        ];
        disk[e..e + 16].copy_from_slice(&efi);
        disk[e + 32..e + 40].copy_from_slice(&34u64.to_le_bytes());
        disk[e + 40..e + 48].copy_from_slice(&2081u64.to_le_bytes());

        let (_t, src) = source_of(&disk);
        let table = read(&src);
        assert_eq!(table.scheme, Scheme::Gpt);
        assert!(table.from_backup, "primary missing, backup header used");
        assert_eq!(table.partitions.len(), 1);
        assert_eq!(table.partitions[0].kind, "EFI System");
        assert_eq!(table.partitions[0].start, 34 * 512);
    }

    #[test]
    fn bare_source_has_no_table() {
        let (_t, src) = source_of(&vec![0u8; 4096]);
        assert_eq!(read(&src).scheme, Scheme::None);
    }
}
