//! Allocation-free partition discovery over a block device.
//!
//! [`discover`] reads logical block 0 and classifies the disk as one of:
//!
//! - a protective MBR followed by a GUID Partition Table (UEFI 2.10 §5.2.3 and
//!   §5.3). The primary header at LBA 1 and its partition-entry array are
//!   validated; if either is defective the backup header at the last LBA is
//!   validated the same way and used instead;
//! - a plain MBR: up to four primary partitions. Extended partitions are
//!   reported as such but not walked;
//! - no partition table: no `0x55AA` signature, or a FAT boot sector that
//!   occupies LBA 0 of an unpartitioned ("superfloppy") disk.
//!
//! Every malformed input fails closed with a typed [`Error`]. All arithmetic
//! on on-disk values is checked, every loop is bounded by the constants below,
//! and the only buffer is one block on the stack.
//!
//! MBR LBA fields are interpreted in units of the device's logical block size,
//! as GPT LBAs are.

#![no_std]
#![forbid(unsafe_code)]

/// Largest supported logical block, and the size of the stack block buffer.
pub const MAX_BLOCK_BYTES: usize = 4096;
/// Logical block sizes [`discover`] accepts.
pub const SUPPORTED_BLOCK_BYTES: [u32; 2] = [512, 4096];
/// Most in-use GPT entries one table may hold; a table with more is rejected.
pub const MAX_GPT_PARTITIONS: usize = 128;
/// Largest GPT partition-entry array (entry count × entry size) accepted.
///
/// This bounds the device reads per header to 512 blocks of 512 bytes or 64
/// blocks of 4096 bytes, whatever the header claims.
pub const MAX_GPT_ENTRY_ARRAY_BYTES: u64 = 256 * 1024;
/// Primary partitions in an MBR.
pub const MBR_PARTITIONS: usize = 4;
/// UTF-16 code units in a GPT partition name.
pub const GPT_NAME_UNITS: usize = 36;

const GPT_SIGNATURE: [u8; 8] = *b"EFI PART";
const GPT_REVISION_1_0: u32 = 0x0001_0000;
const GPT_HEADER_MIN_BYTES: u32 = 92;
const GPT_ENTRY_MIN_BYTES: u32 = 128;
const GPT_ENTRY_BYTES: usize = 128;
const MBR_BYTES: usize = 512;
const MBR_TABLE_OFFSET: usize = 446;
const MBR_RECORD_BYTES: usize = 16;
const MBR_SIGNATURE: [u8; 2] = [0x55, 0xaa];
const MBR_TYPE_EMPTY: u8 = 0x00;
const MBR_TYPE_PROTECTIVE: u8 = 0xee;
const MBR_BOOT_INACTIVE: u8 = 0x00;
const MBR_BOOT_ACTIVE: u8 = 0x80;

/// A failed device read, carrying a driver-defined code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceError(pub u32);

/// Reads whole logical blocks from a device.
///
/// [`discover`] calls [`read_block`](Self::read_block) only for
/// `lba < block_count()` and always with a buffer of exactly `block_size()`
/// bytes. An implementation reports failure through [`DeviceError`]; it must
/// not panic.
pub trait BlockSource {
    /// Logical block size in bytes; [`discover`] accepts 512 and 4096.
    fn block_size(&self) -> u32;
    /// Number of logical blocks on the device.
    fn block_count(&self) -> u64;
    /// Fills `buffer` with logical block `lba`.
    fn read_block(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), DeviceError>;
}

/// A GUID in its on-disk byte order (first three fields little-endian).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Guid([u8; 16]);

impl Guid {
    /// The all-zero GUID, which marks an unused GPT entry.
    pub const ZERO: Self = Self([0; 16]);

    /// Wraps 16 bytes in on-disk (mixed-endian) order.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Builds a GUID from its textual fields, e.g. `C12A7328-F81F-11D2-BA4B-00A0C93EC93B`
    /// is `from_fields(0xC12A7328, 0xF81F, 0x11D2, [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B])`.
    pub const fn from_fields(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        let a = data1.to_le_bytes();
        let b = data2.to_le_bytes();
        let c = data3.to_le_bytes();
        Self([
            a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], data4[0], data4[1], data4[2], data4[3],
            data4[4], data4[5], data4[6], data4[7],
        ])
    }

    /// Returns the on-disk bytes.
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Whether this is the all-zero GUID.
    pub const fn is_zero(self) -> bool {
        let mut index = 0;
        while index < 16 {
            if self.0[index] != 0 {
                return false;
            }
            index += 1;
        }
        true
    }

    /// Names the partition types this crate recognizes.
    pub fn partition_type(self) -> PartitionType {
        if self == EFI_SYSTEM_PARTITION {
            PartitionType::EfiSystem
        } else if self == LINUX_FILESYSTEM_DATA {
            PartitionType::LinuxFilesystemData
        } else {
            PartitionType::Other
        }
    }
}

/// EFI System Partition type GUID, C12A7328-F81F-11D2-BA4B-00A0C93EC93B.
pub const EFI_SYSTEM_PARTITION: Guid = Guid::from_fields(
    0xc12a_7328,
    0xf81f,
    0x11d2,
    [0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b],
);

/// Linux filesystem data type GUID, 0FC63DAF-8483-4772-8E79-3D69D8477DE4.
pub const LINUX_FILESYSTEM_DATA: Guid = Guid::from_fields(
    0x0fc6_3daf,
    0x8483,
    0x4772,
    [0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4],
);

/// A recognized GPT partition type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PartitionType {
    /// [`EFI_SYSTEM_PARTITION`]: FAT, mounted as the ESP.
    EfiSystem,
    /// [`LINUX_FILESYSTEM_DATA`]: e.g. the ext4 root.
    LinuxFilesystemData,
    /// Any other type GUID.
    Other,
}

/// One in-use, validated GPT entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GptPartition {
    index: u32,
    type_guid: Guid,
    unique_guid: Guid,
    first_lba: u64,
    last_lba: u64,
    attributes: u64,
    name: [u16; GPT_NAME_UNITS],
}

impl GptPartition {
    const EMPTY: Self = Self {
        index: 0,
        type_guid: Guid::ZERO,
        unique_guid: Guid::ZERO,
        first_lba: 0,
        last_lba: 0,
        attributes: 0,
        name: [0; GPT_NAME_UNITS],
    };

    /// Zero-based position in the partition-entry array.
    pub const fn index(&self) -> u32 {
        self.index
    }
    /// Partition type GUID (never zero).
    pub const fn type_guid(&self) -> Guid {
        self.type_guid
    }
    /// Unique partition GUID.
    pub const fn unique_guid(&self) -> Guid {
        self.unique_guid
    }
    /// First LBA, within the header's usable range.
    pub const fn first_lba(&self) -> u64 {
        self.first_lba
    }
    /// Last LBA, inclusive, within the header's usable range.
    pub const fn last_lba(&self) -> u64 {
        self.last_lba
    }
    /// Number of blocks, `last_lba - first_lba + 1` (at least one).
    pub const fn block_count(&self) -> u64 {
        self.last_lba - self.first_lba + 1
    }
    /// Raw attribute bits.
    pub const fn attributes(&self) -> u64 {
        self.attributes
    }
    /// Raw UTF-16LE name code units, NUL padding included, not validated.
    pub const fn name_units(&self) -> &[u16; GPT_NAME_UNITS] {
        &self.name
    }
    /// Name code units up to the first NUL.
    pub fn name(&self) -> &[u16] {
        let end = self
            .name
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(GPT_NAME_UNITS);
        &self.name[..end]
    }
    /// Recognized type of this partition.
    pub fn partition_type(&self) -> PartitionType {
        self.type_guid.partition_type()
    }
}

/// One in-use, validated MBR primary partition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MbrPartition {
    slot: u8,
    bootable: bool,
    os_type: u8,
    first_lba: u64,
    block_count: u64,
}

impl MbrPartition {
    const EMPTY: Self = Self {
        slot: 0,
        bootable: false,
        os_type: 0,
        first_lba: 0,
        block_count: 0,
    };

    /// Table slot, 0 to 3.
    pub const fn slot(&self) -> u8 {
        self.slot
    }
    /// Boot indicator was `0x80`.
    pub const fn bootable(&self) -> bool {
        self.bootable
    }
    /// The partition type byte.
    pub const fn os_type(&self) -> u8 {
        self.os_type
    }
    /// First LBA (at least 1).
    pub const fn first_lba(&self) -> u64 {
        self.first_lba
    }
    /// Number of blocks (at least 1); the partition ends within the disk.
    pub const fn block_count(&self) -> u64 {
        self.block_count
    }
    /// Last LBA, inclusive.
    pub const fn last_lba(&self) -> u64 {
        self.first_lba + self.block_count - 1
    }
    /// An extended-partition container (types 0x05, 0x0F, 0x85). Its logical
    /// partitions are not walked.
    pub const fn is_extended(&self) -> bool {
        matches!(self.os_type, 0x05 | 0x0f | 0x85)
    }
}

/// Which GPT header the table was read through.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderSource {
    /// The primary header at LBA 1.
    Primary,
    /// The backup header at the last LBA; the primary was defective.
    Backup {
        /// Why the primary set was rejected.
        primary_defect: GptDefect,
    },
}

/// Disk-wide GPT facts from the header that was used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GptInfo {
    /// Which header was used.
    pub header: HeaderSource,
    /// Disk GUID.
    pub disk_guid: Guid,
    /// First usable LBA.
    pub first_usable_lba: u64,
    /// Last usable LBA, inclusive.
    pub last_usable_lba: u64,
}

/// The partitioning scheme found on a disk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scheme {
    /// No partition table.
    None {
        /// LBA 0 holds a FAT boot sector: the whole disk is one FAT volume.
        fat_boot_sector: bool,
    },
    /// A plain MBR; see [`PartitionTable::mbr_partitions`].
    Mbr,
    /// A GPT; see [`PartitionTable::gpt_partitions`].
    Gpt(GptInfo),
}

/// Fixed-capacity discovery result; no allocation.
///
/// It holds up to [`MAX_GPT_PARTITIONS`] GPT entries inline (about 17 KiB),
/// so callers with small stacks should keep it in static or heap storage.
#[derive(Clone, Debug)]
pub struct PartitionTable {
    scheme: Scheme,
    gpt: [GptPartition; MAX_GPT_PARTITIONS],
    gpt_len: usize,
    mbr: [MbrPartition; MBR_PARTITIONS],
    mbr_len: usize,
}

impl Default for PartitionTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PartitionTable {
    /// An empty table with scheme `None`.
    pub const fn new() -> Self {
        Self {
            scheme: Scheme::None {
                fat_boot_sector: false,
            },
            gpt: [GptPartition::EMPTY; MAX_GPT_PARTITIONS],
            gpt_len: 0,
            mbr: [MbrPartition::EMPTY; MBR_PARTITIONS],
            mbr_len: 0,
        }
    }

    /// The discovered scheme.
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// In-use GPT entries, in entry-array order. Empty unless the scheme is GPT.
    pub fn gpt_partitions(&self) -> &[GptPartition] {
        &self.gpt[..self.gpt_len]
    }

    /// In-use MBR primary partitions, in slot order. Empty unless the scheme is MBR.
    pub fn mbr_partitions(&self) -> &[MbrPartition] {
        &self.mbr[..self.mbr_len]
    }

    fn clear(&mut self) {
        self.scheme = Scheme::None {
            fat_boot_sector: false,
        };
        self.gpt_len = 0;
        self.mbr_len = 0;
    }
}

/// Why one GPT header and its entry array were rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GptDefect {
    /// The disk has no block where this header would live.
    DiskTooSmall,
    /// Signature is not `EFI PART`.
    Signature,
    /// Revision is not 1.0.
    Revision,
    /// Header size is below 92 or above the block size.
    HeaderSize,
    /// Header CRC32 mismatch.
    HeaderCrc,
    /// The reserved field after the header CRC is not zero.
    Reserved,
    /// MyLBA is not the LBA the header was read from.
    MyLba,
    /// AlternateLBA is MyLBA or beyond the disk.
    AlternateLba,
    /// Usable range is inverted, covers LBA 0/1, or reaches the last LBA.
    UsableRange,
    /// Entry size is not 128 × 2^n.
    EntrySize,
    /// Entry count is zero or the array exceeds [`MAX_GPT_ENTRY_ARRAY_BYTES`].
    EntryCount,
    /// The entry array overlaps LBA 0/1, the last LBA, the usable range, or
    /// leaves the disk.
    EntryArrayLocation,
    /// Partition-entry array CRC32 mismatch.
    EntryArrayCrc,
    /// Entry `index` has first > last or lies outside the usable range.
    EntryRange {
        /// Entry-array index.
        index: u32,
    },
    /// Entries `first` and `second` share at least one block.
    Overlap {
        /// Lower entry-array index.
        first: u32,
        /// Higher entry-array index.
        second: u32,
    },
    /// More than [`MAX_GPT_PARTITIONS`] entries are in use.
    TooManyPartitions,
}

/// Why a plain MBR was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MbrDefect {
    /// Boot indicator is neither 0x00 nor 0x80.
    BootIndicator {
        /// Table slot.
        slot: u8,
    },
    /// A used slot has a zero sector count.
    Empty {
        /// Table slot.
        slot: u8,
    },
    /// A used slot starts at LBA 0, over the MBR itself.
    StartsAtMbr {
        /// Table slot.
        slot: u8,
    },
    /// A used slot ends beyond the disk.
    BeyondDisk {
        /// Table slot.
        slot: u8,
    },
    /// Two used slots share at least one block.
    Overlap {
        /// Lower slot.
        first: u8,
        /// Higher slot.
        second: u8,
    },
}

/// Discovery failure. The output table is left empty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The device's block size is not 512 or 4096.
    UnsupportedBlockSize(u32),
    /// The device has no blocks.
    EmptyDevice,
    /// The device failed to read `lba`.
    Read {
        /// Block that failed.
        lba: u64,
        /// Driver-defined error.
        error: DeviceError,
    },
    /// LBA 1 holds a GPT signature but LBA 0 has no MBR signature.
    GptWithoutProtectiveMbr,
    /// The protective (0xEE) record does not start at LBA 1.
    InvalidProtectiveMbr,
    /// The plain MBR is malformed.
    Mbr(MbrDefect),
    /// Both GPT headers (with their entry arrays) are defective.
    Gpt {
        /// Defect of the primary at LBA 1.
        primary: GptDefect,
        /// Defect of the backup at the last LBA.
        backup: GptDefect,
    },
}

/// Discovers the partition table of `device` into `table`.
///
/// Device errors are returned at once; they do not trigger the GPT backup
/// fallback, which is reserved for on-disk defects.
pub fn discover<D: BlockSource + ?Sized>(
    device: &mut D,
    table: &mut PartitionTable,
) -> Result<(), Error> {
    table.clear();
    let result = discover_into(device, table);
    if result.is_err() {
        table.clear();
    }
    result
}

fn discover_into<D: BlockSource + ?Sized>(
    device: &mut D,
    table: &mut PartitionTable,
) -> Result<(), Error> {
    let block_bytes = device.block_size();
    if !SUPPORTED_BLOCK_BYTES.contains(&block_bytes) {
        return Err(Error::UnsupportedBlockSize(block_bytes));
    }
    let blocks = device.block_count();
    if blocks == 0 {
        return Err(Error::EmptyDevice);
    }
    let mut buffer = [0_u8; MAX_BLOCK_BYTES];
    let block = &mut buffer[..block_bytes as usize];
    read(device, 0, block)?;
    let mut mbr = [0_u8; MBR_BYTES];
    mbr.copy_from_slice(&block[..MBR_BYTES]);

    if mbr[510..512] != MBR_SIGNATURE {
        if blocks > 1 {
            read(device, 1, block)?;
            if block[..8] == GPT_SIGNATURE {
                return Err(Error::GptWithoutProtectiveMbr);
            }
        }
        table.scheme = Scheme::None {
            fat_boot_sector: false,
        };
        return Ok(());
    }

    let records = mbr_records(&mbr);
    let fat = looks_like_fat_boot_sector(&mbr);
    if let Some(slot) = (0..MBR_PARTITIONS).find(|&slot| {
        let boot = records[slot].boot;
        boot != MBR_BOOT_INACTIVE && boot != MBR_BOOT_ACTIVE
    }) {
        if fat {
            table.scheme = Scheme::None {
                fat_boot_sector: true,
            };
            return Ok(());
        }
        return Err(Error::Mbr(MbrDefect::BootIndicator { slot: slot as u8 }));
    }
    if let Some(protective) = records
        .iter()
        .find(|record| record.os_type == MBR_TYPE_PROTECTIVE)
    {
        if protective.start != 1 {
            return Err(Error::InvalidProtectiveMbr);
        }
        return discover_gpt(device, blocks, &mut buffer[..block_bytes as usize], table);
    }
    if fat
        && records
            .iter()
            .all(|record| record.os_type == MBR_TYPE_EMPTY)
    {
        table.scheme = Scheme::None {
            fat_boot_sector: true,
        };
        return Ok(());
    }
    parse_mbr(&records, blocks, table).map_err(Error::Mbr)
}

fn read<D: BlockSource + ?Sized>(device: &mut D, lba: u64, block: &mut [u8]) -> Result<(), Error> {
    device
        .read_block(lba, block)
        .map_err(|error| Error::Read { lba, error })
}

#[derive(Clone, Copy)]
struct MbrRecord {
    boot: u8,
    os_type: u8,
    start: u32,
    count: u32,
}

fn mbr_records(mbr: &[u8; MBR_BYTES]) -> [MbrRecord; MBR_PARTITIONS] {
    let mut records = [MbrRecord {
        boot: 0,
        os_type: 0,
        start: 0,
        count: 0,
    }; MBR_PARTITIONS];
    for (slot, record) in records.iter_mut().enumerate() {
        let base = MBR_TABLE_OFFSET + slot * MBR_RECORD_BYTES;
        *record = MbrRecord {
            boot: mbr[base],
            os_type: mbr[base + 4],
            start: le_u32(mbr, base + 8),
            count: le_u32(mbr, base + 12),
        };
    }
    records
}

/// A FAT BIOS parameter block in LBA 0: the disk is an unpartitioned volume.
fn looks_like_fat_boot_sector(sector: &[u8; MBR_BYTES]) -> bool {
    let jump = (sector[0] == 0xeb && sector[2] == 0x90) || sector[0] == 0xe9;
    let bytes_per_sector = le_u16(sector, 11);
    let sectors_per_cluster = sector[13];
    let reserved_sectors = le_u16(sector, 14);
    let fats = sector[16];
    let media = sector[21];
    jump && matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096)
        && sectors_per_cluster.is_power_of_two()
        && reserved_sectors != 0
        && (fats == 1 || fats == 2)
        && (media == 0xf0 || media >= 0xf8)
}

fn parse_mbr(
    records: &[MbrRecord; MBR_PARTITIONS],
    blocks: u64,
    table: &mut PartitionTable,
) -> Result<(), MbrDefect> {
    for (slot, record) in records.iter().enumerate() {
        if record.os_type == MBR_TYPE_EMPTY {
            continue;
        }
        let slot = slot as u8;
        if record.count == 0 {
            return Err(MbrDefect::Empty { slot });
        }
        if record.start == 0 {
            return Err(MbrDefect::StartsAtMbr { slot });
        }
        // Both operands are below 2^32, so the sum cannot overflow u64.
        if u64::from(record.start) + u64::from(record.count) > blocks {
            return Err(MbrDefect::BeyondDisk { slot });
        }
        table.mbr[table.mbr_len] = MbrPartition {
            slot,
            bootable: record.boot == MBR_BOOT_ACTIVE,
            os_type: record.os_type,
            first_lba: u64::from(record.start),
            block_count: u64::from(record.count),
        };
        table.mbr_len += 1;
    }
    let used = &table.mbr[..table.mbr_len];
    for (position, a) in used.iter().enumerate() {
        for b in &used[position + 1..] {
            if a.first_lba <= b.last_lba() && b.first_lba <= a.last_lba() {
                return Err(MbrDefect::Overlap {
                    first: a.slot,
                    second: b.slot,
                });
            }
        }
    }
    table.scheme = Scheme::Mbr;
    Ok(())
}

enum Fault {
    Device(Error),
    Defect(GptDefect),
}

impl From<GptDefect> for Fault {
    fn from(defect: GptDefect) -> Self {
        Self::Defect(defect)
    }
}

fn discover_gpt<D: BlockSource + ?Sized>(
    device: &mut D,
    blocks: u64,
    block: &mut [u8],
    table: &mut PartitionTable,
) -> Result<(), Error> {
    let primary = match load_gpt(device, 1, blocks, block, table) {
        Ok(info) => {
            table.scheme = Scheme::Gpt(info);
            return Ok(());
        }
        Err(Fault::Device(error)) => return Err(error),
        Err(Fault::Defect(defect)) => defect,
    };
    table.gpt_len = 0;
    let last = blocks - 1;
    let backup = if last <= 1 {
        GptDefect::DiskTooSmall
    } else {
        match load_gpt(device, last, blocks, block, table) {
            Ok(mut info) => {
                info.header = HeaderSource::Backup {
                    primary_defect: primary,
                };
                table.scheme = Scheme::Gpt(info);
                return Ok(());
            }
            Err(Fault::Device(error)) => return Err(error),
            Err(Fault::Defect(defect)) => defect,
        }
    };
    Err(Error::Gpt { primary, backup })
}

/// Validates the header at `lba` and its entry array, filling `table.gpt`.
fn load_gpt<D: BlockSource + ?Sized>(
    device: &mut D,
    lba: u64,
    blocks: u64,
    block: &mut [u8],
    table: &mut PartitionTable,
) -> Result<GptInfo, Fault> {
    if lba >= blocks {
        return Err(GptDefect::DiskTooSmall.into());
    }
    read(device, lba, block).map_err(Fault::Device)?;
    let block_bytes = block.len() as u64;

    if block[..8] != GPT_SIGNATURE {
        return Err(GptDefect::Signature.into());
    }
    if le_u32(block, 8) != GPT_REVISION_1_0 {
        return Err(GptDefect::Revision.into());
    }
    let header_bytes = le_u32(block, 12);
    if header_bytes < GPT_HEADER_MIN_BYTES || u64::from(header_bytes) > block_bytes {
        return Err(GptDefect::HeaderSize.into());
    }
    let mut crc = crc32_update(CRC32_INIT, &block[..16]);
    crc = crc32_update(crc, &[0; 4]);
    crc = crc32_update(crc, &block[20..header_bytes as usize]);
    if !crc != le_u32(block, 16) {
        return Err(GptDefect::HeaderCrc.into());
    }
    if le_u32(block, 20) != 0 {
        return Err(GptDefect::Reserved.into());
    }
    if le_u64(block, 24) != lba {
        return Err(GptDefect::MyLba.into());
    }
    let alternate = le_u64(block, 32);
    if alternate == lba || alternate >= blocks {
        return Err(GptDefect::AlternateLba.into());
    }
    let first_usable = le_u64(block, 40);
    let last_usable = le_u64(block, 48);
    // `blocks >= 2` because `lba >= 1` and `lba < blocks`.
    if first_usable < 2 || first_usable > last_usable || last_usable > blocks - 2 {
        return Err(GptDefect::UsableRange.into());
    }
    let disk_guid = guid_at(block, 56);
    let entry_lba = le_u64(block, 72);
    let entry_count = le_u32(block, 80);
    let entry_bytes = le_u32(block, 84);
    let entry_crc = le_u32(block, 88);

    if entry_bytes < GPT_ENTRY_MIN_BYTES
        || !entry_bytes.is_multiple_of(GPT_ENTRY_MIN_BYTES)
        || !(entry_bytes / GPT_ENTRY_MIN_BYTES).is_power_of_two()
    {
        return Err(GptDefect::EntrySize.into());
    }
    // Both factors are below 2^32, so the product cannot overflow u64.
    let array_bytes = u64::from(entry_count) * u64::from(entry_bytes);
    if entry_count == 0 || array_bytes > MAX_GPT_ENTRY_ARRAY_BYTES {
        return Err(GptDefect::EntryCount.into());
    }
    let array_blocks = array_bytes.div_ceil(block_bytes);
    let array_last = entry_lba
        .checked_add(array_blocks - 1)
        .ok_or(GptDefect::EntryArrayLocation)?;
    if entry_lba < 2
        || array_last > blocks - 2
        || !(array_last < first_usable || entry_lba > last_usable)
    {
        return Err(GptDefect::EntryArrayLocation.into());
    }

    table.gpt_len = 0;
    let mut crc = CRC32_INIT;
    let mut entry_defect = None;
    let mut next_entry: u64 = 0;
    let mut index: u32 = 0;
    for block_index in 0..array_blocks {
        read(device, entry_lba + block_index, block).map_err(Fault::Device)?;
        let block_start = block_index * block_bytes;
        let take = (array_bytes - block_start).min(block_bytes);
        crc = crc32_update(crc, &block[..take as usize]);
        while index < entry_count && next_entry < block_start + take {
            // Entry offsets and block sizes are multiples of 128, so each
            // entry's 128 defined bytes lie inside one block.
            let local = (next_entry - block_start) as usize;
            let raw = block
                .get(local..local + GPT_ENTRY_BYTES)
                .ok_or(GptDefect::EntrySize)?;
            if entry_defect.is_none() {
                entry_defect = collect_entry(raw, index, first_usable, last_usable, table);
            }
            index += 1;
            next_entry += u64::from(entry_bytes);
        }
    }
    if !crc != entry_crc {
        return Err(GptDefect::EntryArrayCrc.into());
    }
    if let Some(defect) = entry_defect {
        return Err(defect.into());
    }
    let used = &table.gpt[..table.gpt_len];
    for (position, a) in used.iter().enumerate() {
        for b in &used[position + 1..] {
            if a.first_lba <= b.last_lba && b.first_lba <= a.last_lba {
                return Err(GptDefect::Overlap {
                    first: a.index,
                    second: b.index,
                }
                .into());
            }
        }
    }
    Ok(GptInfo {
        header: HeaderSource::Primary,
        disk_guid,
        first_usable_lba: first_usable,
        last_usable_lba: last_usable,
    })
}

fn collect_entry(
    raw: &[u8],
    index: u32,
    first_usable: u64,
    last_usable: u64,
    table: &mut PartitionTable,
) -> Option<GptDefect> {
    let type_guid = guid_at(raw, 0);
    if type_guid.is_zero() {
        return None;
    }
    let first_lba = le_u64(raw, 32);
    let last_lba = le_u64(raw, 40);
    if first_lba > last_lba || first_lba < first_usable || last_lba > last_usable {
        return Some(GptDefect::EntryRange { index });
    }
    if table.gpt_len == MAX_GPT_PARTITIONS {
        return Some(GptDefect::TooManyPartitions);
    }
    let mut name = [0_u16; GPT_NAME_UNITS];
    for (unit, value) in name.iter_mut().enumerate() {
        *value = le_u16(raw, 56 + unit * 2);
    }
    table.gpt[table.gpt_len] = GptPartition {
        index,
        type_guid,
        unique_guid: guid_at(raw, 16),
        first_lba,
        last_lba,
        attributes: le_u64(raw, 48),
        name,
    };
    table.gpt_len += 1;
    None
}

const CRC32_INIT: u32 = !0;
const CRC32_TABLE: [u32; 256] = crc32_table();

const fn crc32_table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 != 0 {
                0xedb8_8320 ^ (value >> 1)
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
}

fn crc32_update(mut crc: u32, bytes: &[u8]) -> u32 {
    for &byte in bytes {
        crc = CRC32_TABLE[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

/// CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320) as GPT uses it.
pub fn crc32(bytes: &[u8]) -> u32 {
    !crc32_update(CRC32_INIT, bytes)
}

fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

fn guid_at(bytes: &[u8], offset: usize) -> Guid {
    let mut value = [0; 16];
    value.copy_from_slice(&bytes[offset..offset + 16]);
    Guid(value)
}
