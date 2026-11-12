//! Allocation-free ext4 (root `STORAGE_PLAN.md` W7).
//!
//! Written from the kernel.org ext4 disk-layout documentation as shipped in
//! Linux 7.2.14 (`Documentation/filesystems/ext4/`: `super.rst`,
//! `group_descr.rst`, `inodes.rst`, `ifork.rst`, `directory.rst`,
//! `checksums.rst`, `bitmaps.rst`, `blockgroup.rst`, `special_inodes.rst`).
//! No implementation source was copied. `ext4-view` (MIT/Apache-2.0) is
//! read-only and needs `alloc`; `lwext4` is C with per-file BSD/GPL-2.0
//! licensing and its own I/O model. Neither was adopted.
//!
//! What it does:
//!
//! - Mounts block sizes 1 to 4 KiB with 128- or 256-byte inodes, the
//!   `filetype`, `extents`, `64bit`, `flex_bg` and `metadata_csum_seed`
//!   incompatible features, and every checksum `metadata_csum` defines for
//!   the structures it touches. An unknown incompatible feature, a journal
//!   that still needs recovery ([`recover`] replays it first), `meta_bg`,
//!   `bigalloc` or a non-Linux creator is refused; an unknown read-only-compatible feature, an orphan list or
//!   recorded errors mount read-only.
//! - Reads directories linearly (htree index blocks look empty to a linear
//!   reader) and files through extent trees of any legal depth.
//! - Writes files, creates files and directories, truncates and unlinks,
//!   allocating from initialised groups only. Directories with an htree
//!   index and extent trees deeper than one level are not modified.
//! - Formats a volume ([`format`]) with a fixed modern feature set and,
//!   optionally, a journal.
//! - Journals metadata in `data=ordered` mode ([`journal`]): through a
//!   [`Journaled`] device, a crash leaves the volume as of the last commit.
//!   Used directly, a mutation writes data blocks first and metadata after,
//!   and a crash part-way may leave work for `e2fsck`.
//!
//! Every on-disk value is checked before use, every walk is bounded, and a
//! checksum mismatch is [`Error::Corrupt`].

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod crc;
mod dir;
mod extent;
mod format;
pub mod journal;
mod write;

pub use format::{FormatParams, MIN_JOURNAL_BLOCKS, format};
pub use journal::{Journal, Journaled, Store, Transaction, recover};

/// A failed device transfer, carrying a source-defined code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceError(pub u32);

/// Byte-addressed access to the volume. Transfers are whole filesystem
/// blocks at block-aligned offsets, except the superblock's 1024 bytes at
/// offset 1024.
pub trait Device {
    fn read(&mut self, offset: u64, out: &mut [u8]) -> Result<(), DeviceError>;
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), DeviceError>;
    /// Makes every completed write durable.
    fn flush(&mut self) -> Result<(), DeviceError>;
    /// Writes file data. Through a [`Journaled`] device it goes straight to
    /// the volume, never through the journal.
    fn write_data(&mut self, offset: u64, data: &[u8]) -> Result<(), DeviceError> {
        self.write(offset, data)
    }
    /// Reads what the last commit left, ignoring uncommitted metadata.
    fn read_committed(&mut self, offset: u64, out: &mut [u8]) -> Result<(), DeviceError> {
        self.read(offset, out)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Device(DeviceError),
    /// No ext4 superblock.
    NotExt4,
    /// A valid volume or request this implementation does not handle.
    Unsupported,
    /// Metadata contradicts itself, the documentation, or its checksum.
    Corrupt,
    NotFound,
    NotDirectory,
    IsDirectory,
    /// Neither a regular file nor a directory.
    NotFileOrDirectory,
    Exists,
    NotEmpty,
    NoSpace,
    ReadOnly,
    /// Empty, longer than 255 bytes, `.`, `..`, or holding `/` or NUL.
    InvalidName,
    /// Past the largest file this volume stores.
    TooLarge,
}

impl From<DeviceError> for Error {
    fn from(error: DeviceError) -> Self {
        Self::Device(error)
    }
}

/// The largest block size mounted.
pub const MAX_BLOCK_BYTES: usize = 4096;
/// The longest name stored.
pub const MAX_NAME_BYTES: usize = 255;
/// The root directory's inode.
pub const ROOT_INODE: u32 = 2;

const SUPERBLOCK_OFFSET: u64 = 1024;
const SUPERBLOCK_BYTES: usize = 1024;
const MAGIC: u16 = 0xEF53;
const MAX_INODE_BYTES: usize = 256;

// Feature bits (`super.rst`).
const INCOMPAT_FILETYPE: u32 = 0x2;
const INCOMPAT_RECOVER: u32 = 0x4;
const INCOMPAT_EXTENTS: u32 = 0x40;
const INCOMPAT_64BIT: u32 = 0x80;
const INCOMPAT_FLEX_BG: u32 = 0x200;
const INCOMPAT_CSUM_SEED: u32 = 0x2000;
const INCOMPAT_LARGEDIR: u32 = 0x4000;
const INCOMPAT_KNOWN: u32 = INCOMPAT_FILETYPE
    | INCOMPAT_RECOVER
    | INCOMPAT_EXTENTS
    | INCOMPAT_64BIT
    | INCOMPAT_FLEX_BG
    | INCOMPAT_CSUM_SEED
    | INCOMPAT_LARGEDIR;
const RO_COMPAT_SPARSE_SUPER: u32 = 0x1;
const RO_COMPAT_LARGE_FILE: u32 = 0x2;
const RO_COMPAT_HUGE_FILE: u32 = 0x8;
const RO_COMPAT_GDT_CSUM: u32 = 0x10;
const RO_COMPAT_DIR_NLINK: u32 = 0x20;
const RO_COMPAT_EXTRA_ISIZE: u32 = 0x40;
const RO_COMPAT_BIGALLOC: u32 = 0x200;
const RO_COMPAT_METADATA_CSUM: u32 = 0x400;
/// Features this implementation keeps consistent while writing.
const RO_COMPAT_WRITABLE: u32 = RO_COMPAT_SPARSE_SUPER
    | RO_COMPAT_LARGE_FILE
    | RO_COMPAT_HUGE_FILE
    | RO_COMPAT_DIR_NLINK
    | RO_COMPAT_EXTRA_ISIZE
    | RO_COMPAT_METADATA_CSUM;
const INCOMPAT_META_BG: u32 = 0x10;
const STATE_ERRORS: u16 = 0x2;

// Group descriptor flags (`group_descr.rst`).
const BG_INODE_UNINIT: u16 = 0x1;
const BG_BLOCK_UNINIT: u16 = 0x2;

// Inode fields (`inodes.rst`).
const S_IFMT: u16 = 0xF000;
const S_IFDIR: u16 = 0x4000;
const S_IFREG: u16 = 0x8000;
const EXT4_INDEX_FL: u32 = 0x1000;
const EXT4_HUGE_FILE_FL: u32 = 0x40000;
const EXT4_EXTENTS_FL: u32 = 0x80000;
const EXT4_INLINE_DATA_FL: u32 = 0x1000_0000;

pub(crate) fn get16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
pub(crate) fn get32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}
pub(crate) fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
pub(crate) fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Directory,
    File,
}

/// What a node reports about itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stat {
    pub inode: u32,
    pub kind: Kind,
    pub size: u64,
}

/// One directory entry passed to a [`Volume::read_dir`] callback.
#[derive(Clone, Copy, Debug)]
pub struct Entry<'a> {
    pub name: &'a [u8],
    pub inode: u32,
    pub kind: Kind,
}

/// Space accounting, in blocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    pub block_size: u32,
    pub blocks: u64,
    pub free_blocks: u64,
}

/// One inode as stored, with its number.
#[derive(Clone, Copy)]
pub(crate) struct Inode {
    pub(crate) number: u32,
    pub(crate) raw: [u8; MAX_INODE_BYTES],
}

impl Inode {
    pub(crate) fn mode(&self) -> u16 {
        get16(&self.raw, 0x0)
    }
    pub(crate) fn flags(&self) -> u32 {
        get32(&self.raw, 0x20)
    }
    pub(crate) fn set_flags(&mut self, flags: u32) {
        put32(&mut self.raw, 0x20, flags);
    }
    pub(crate) fn links(&self) -> u16 {
        get16(&self.raw, 0x1A)
    }
    pub(crate) fn set_links(&mut self, links: u16) {
        put16(&mut self.raw, 0x1A, links);
    }
    pub(crate) fn generation(&self) -> u32 {
        get32(&self.raw, 0x64)
    }
    pub(crate) fn size(&self) -> u64 {
        u64::from(get32(&self.raw, 0x4)) | u64::from(get32(&self.raw, 0x6C)) << 32
    }
    pub(crate) fn set_size(&mut self, size: u64) {
        put32(&mut self.raw, 0x4, size as u32);
        put32(&mut self.raw, 0x6C, (size >> 32) as u32);
    }
    /// 512-byte units; [`EXT4_HUGE_FILE_FL`] inodes are never written.
    pub(crate) fn sectors(&self) -> u64 {
        u64::from(get32(&self.raw, 0x1C)) | u64::from(get16(&self.raw, 0x74)) << 32
    }
    pub(crate) fn set_sectors(&mut self, sectors: u64) {
        put32(&mut self.raw, 0x1C, sectors as u32);
        put16(&mut self.raw, 0x74, (sectors >> 32) as u16);
    }
    pub(crate) fn kind(&self) -> Option<Kind> {
        match self.mode() & S_IFMT {
            S_IFDIR => Some(Kind::Directory),
            S_IFREG => Some(Kind::File),
            _ => None,
        }
    }
    pub(crate) fn root(&self) -> &[u8] {
        &self.raw[0x28..0x28 + 60]
    }
    pub(crate) fn root_mut(&mut self) -> &mut [u8] {
        &mut self.raw[0x28..0x28 + 60]
    }
    pub(crate) fn set_times(&mut self, now: u32, ctime: bool, mtime: bool) {
        if ctime {
            put32(&mut self.raw, 0xC, now);
        }
        if mtime {
            put32(&mut self.raw, 0x10, now);
        }
    }
}

/// One group descriptor as stored, with its group.
#[derive(Clone, Copy)]
pub(crate) struct Group {
    pub(crate) number: u32,
    pub(crate) raw: [u8; 64],
}

impl Group {
    fn wide(&self, lo: usize, hi: usize, wide: bool) -> u64 {
        u64::from(get32(&self.raw, lo))
            | if wide {
                u64::from(get32(&self.raw, hi)) << 32
            } else {
                0
            }
    }
    fn count(&self, lo: usize, hi: usize, wide: bool) -> u32 {
        u32::from(get16(&self.raw, lo))
            | if wide {
                u32::from(get16(&self.raw, hi)) << 16
            } else {
                0
            }
    }
    fn set_count(&mut self, lo: usize, hi: usize, wide: bool, value: u32) {
        put16(&mut self.raw, lo, value as u16);
        if wide {
            put16(&mut self.raw, hi, (value >> 16) as u16);
        }
    }
    pub(crate) fn flags(&self) -> u16 {
        get16(&self.raw, 0x12)
    }
}

/// A mounted volume. It holds the superblock; everything else is read from
/// the device when needed, so one volume may be used with any [`Device`]
/// that reaches the same bytes.
pub struct Volume {
    pub(crate) sb: [u8; SUPERBLOCK_BYTES],
    pub(crate) block_size: u32,
    pub(crate) blocks: u64,
    pub(crate) first_data_block: u32,
    pub(crate) blocks_per_group: u32,
    pub(crate) inodes_per_group: u32,
    pub(crate) inodes: u32,
    pub(crate) first_inode: u32,
    pub(crate) inode_size: usize,
    pub(crate) desc_size: usize,
    pub(crate) groups: u32,
    pub(crate) wide: bool,
    /// `metadata_csum`, with its seed.
    pub(crate) csum: Option<u32>,
    pub(crate) writable: bool,
    pub(crate) now: u32,
}

impl Volume {
    /// Mounts the volume on `device`, whose size is `device_bytes`.
    /// `writable` asks for a read-write mount; a volume that can only be
    /// read is mounted read-only instead (see [`Volume::read_only`]).
    pub fn mount<D: Device>(
        device: &mut D,
        device_bytes: u64,
        writable: bool,
    ) -> Result<Self, Error> {
        Self::mount_inner(device, device_bytes, writable, false)
    }

    /// [`Volume::mount`]; `recovering` also takes a volume whose journal
    /// needs recovery, read-only, for [`recover`] to replay it.
    pub(crate) fn mount_inner<D: Device>(
        device: &mut D,
        device_bytes: u64,
        writable: bool,
        recovering: bool,
    ) -> Result<Self, Error> {
        let mut sb = [0u8; SUPERBLOCK_BYTES];
        device.read(SUPERBLOCK_OFFSET, &mut sb)?;
        if get16(&sb, 0x38) != MAGIC {
            return Err(Error::NotExt4);
        }
        let log = get32(&sb, 0x18);
        if log > 2 {
            return Err(Error::Unsupported);
        }
        let block_size = 1024u32 << log;
        let incompat = get32(&sb, 0x60);
        let ro_compat = get32(&sb, 0x64);
        let rev = get32(&sb, 0x4C);
        if incompat & !INCOMPAT_KNOWN != 0
            || incompat & INCOMPAT_FILETYPE == 0
            || (incompat & INCOMPAT_RECOVER != 0 && !recovering)
            || incompat & INCOMPAT_META_BG != 0
            || ro_compat & RO_COMPAT_BIGALLOC != 0
            || get32(&sb, 0x48) != 0
            || rev > 1
        {
            return Err(Error::Unsupported);
        }
        let csum = if ro_compat & RO_COMPAT_METADATA_CSUM != 0 {
            if sb[0x175] != 1 {
                return Err(Error::Unsupported);
            }
            if crc::update(!0, &sb[..0x3FC]) != get32(&sb, 0x3FC) {
                return Err(Error::Corrupt);
            }
            Some(if incompat & INCOMPAT_CSUM_SEED != 0 {
                get32(&sb, 0x270)
            } else {
                crc::update(!0, &sb[0x68..0x78])
            })
        } else {
            None
        };
        let gdt_csum_only = csum.is_none() && ro_compat & RO_COMPAT_GDT_CSUM != 0;
        let wide = incompat & INCOMPAT_64BIT != 0;
        let (inode_size, first_inode) = if rev == 0 {
            (128, 11)
        } else {
            (usize::from(get16(&sb, 0x58)), get32(&sb, 0x54))
        };
        if inode_size != 128 && inode_size != 256 {
            return Err(Error::Unsupported);
        }
        let desc_size = if wide {
            usize::from(get16(&sb, 0xFE))
        } else {
            32
        };
        if desc_size != 32 && desc_size != 64 {
            return Err(Error::Unsupported);
        }
        let blocks = u64::from(get32(&sb, 0x4))
            | if wide {
                u64::from(get32(&sb, 0x150)) << 32
            } else {
                0
            };
        let first_data_block = get32(&sb, 0x14);
        let blocks_per_group = get32(&sb, 0x20);
        let inodes_per_group = get32(&sb, 0x28);
        let inodes = get32(&sb, 0x0);
        let bits = block_size * 8;
        let expected_first = u32::from(block_size == 1024);
        if first_data_block != expected_first
            || blocks_per_group < 8
            || blocks_per_group > bits
            || get32(&sb, 0x24) != blocks_per_group
            || get32(&sb, 0x1C) != log
            || inodes_per_group == 0
            || inodes_per_group > bits
            || !inodes_per_group.is_multiple_of(8)
            || blocks <= u64::from(first_data_block)
            || first_inode < 11
            || !blocks
                .checked_mul(u64::from(block_size))
                .is_some_and(|bytes| bytes <= device_bytes)
        {
            return Err(Error::Corrupt);
        }
        let groups = (blocks - u64::from(first_data_block)).div_ceil(u64::from(blocks_per_group));
        let groups = u32::try_from(groups).map_err(|_| Error::Corrupt)?;
        if u64::from(inodes) != u64::from(groups) * u64::from(inodes_per_group)
            || first_inode > inodes
        {
            return Err(Error::Corrupt);
        }
        // The descriptor table must fit in group 0 after the superblock.
        let table_blocks = (u64::from(groups) * desc_size as u64).div_ceil(u64::from(block_size));
        if table_blocks + 1 >= u64::from(blocks_per_group) {
            return Err(Error::Corrupt);
        }
        let state = get16(&sb, 0x3A);
        let writable = writable
            && !recovering
            && ro_compat & !RO_COMPAT_WRITABLE == 0
            && !gdt_csum_only
            && state & STATE_ERRORS == 0
            && get32(&sb, 0xE8) == 0
            && incompat & INCOMPAT_EXTENTS != 0;
        let now = get32(&sb, 0x30)
            .max(get32(&sb, 0x2C))
            .max(get32(&sb, 0x108));
        let volume = Self {
            sb,
            block_size,
            blocks,
            first_data_block,
            blocks_per_group,
            inodes_per_group,
            inodes,
            first_inode,
            inode_size,
            desc_size,
            groups,
            wide,
            csum,
            writable,
            now,
        };
        let root = volume.inode(device, ROOT_INODE)?;
        if root.kind() != Some(Kind::Directory) {
            return Err(Error::Corrupt);
        }
        Ok(volume)
    }

    /// Whether mutations are refused.
    pub fn read_only(&self) -> bool {
        !self.writable
    }

    /// Refuses mutations from now on.
    pub fn set_read_only(&mut self) {
        self.writable = false;
    }

    pub(crate) fn set_needs_recovery(&mut self, needed: bool) {
        let incompat = get32(&self.sb, 0x60);
        let incompat = if needed {
            incompat | INCOMPAT_RECOVER
        } else {
            incompat & !INCOMPAT_RECOVER
        };
        put32(&mut self.sb, 0x60, incompat);
    }

    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// The volume's UUID (`s_uuid`).
    pub fn uuid(&self) -> [u8; 16] {
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&self.sb[0x68..0x78]);
        uuid
    }

    /// The time stamped on what this volume changes, in seconds since the
    /// epoch. It starts as the superblock's latest recorded time.
    pub fn set_now(&mut self, now: u32) {
        self.now = now;
    }

    pub fn usage(&self) -> Usage {
        Usage {
            block_size: self.block_size,
            blocks: self.blocks,
            free_blocks: self.free_blocks(),
        }
    }

    pub(crate) fn free_blocks(&self) -> u64 {
        u64::from(get32(&self.sb, 0xC))
            | if self.wide {
                u64::from(get32(&self.sb, 0x158)) << 32
            } else {
                0
            }
    }

    pub(crate) fn has_ro_compat(&self, bit: u32) -> bool {
        get32(&self.sb, 0x64) & bit != 0
    }

    pub(crate) fn bs(&self) -> usize {
        self.block_size as usize
    }

    pub(crate) fn read_block<D: Device>(
        &self,
        device: &mut D,
        block: u64,
        out: &mut [u8],
    ) -> Result<(), Error> {
        if block >= self.blocks || out.len() != self.bs() {
            return Err(Error::Corrupt);
        }
        device.read(block * u64::from(self.block_size), out)?;
        Ok(())
    }

    pub(crate) fn write_block<D: Device>(
        &self,
        device: &mut D,
        block: u64,
        data: &[u8],
    ) -> Result<(), Error> {
        // Block 0 holds the superblock (or, at 1 KiB, the boot block).
        if block == 0 || block >= self.blocks || data.len() != self.bs() {
            return Err(Error::Corrupt);
        }
        device.write(block * u64::from(self.block_size), data)?;
        Ok(())
    }

    /// Writes a file data block ([`Device::write_data`]).
    pub(crate) fn write_data_block<D: Device>(
        &self,
        device: &mut D,
        block: u64,
        data: &[u8],
    ) -> Result<(), Error> {
        if block == 0 || block >= self.blocks || data.len() != self.bs() {
            return Err(Error::Corrupt);
        }
        device.write_data(block * u64::from(self.block_size), data)?;
        Ok(())
    }

    /// Reads group `number`'s descriptor and checks it.
    pub(crate) fn group<D: Device>(&self, device: &mut D, number: u32) -> Result<Group, Error> {
        if number >= self.groups {
            return Err(Error::Corrupt);
        }
        let mut group = Group {
            number,
            raw: [0; 64],
        };
        let size = self.desc_size;
        device.read(self.group_offset(number), &mut group.raw[..size])?;
        if let Some(seed) = self.csum
            && Self::group_checksum(seed, number, &group.raw[..size]) != get16(&group.raw, 0x1E)
        {
            return Err(Error::Corrupt);
        }
        for block in [self.block_bitmap(&group), self.inode_bitmap(&group)] {
            if block < u64::from(self.first_data_block) || block >= self.blocks {
                return Err(Error::Corrupt);
            }
        }
        let table = self.inode_table(&group);
        let table_blocks = self.inode_table_blocks();
        if table < u64::from(self.first_data_block)
            || !table
                .checked_add(table_blocks)
                .is_some_and(|end| end <= self.blocks)
        {
            return Err(Error::Corrupt);
        }
        Ok(group)
    }

    pub(crate) fn write_group<D: Device>(
        &self,
        device: &mut D,
        group: &mut Group,
    ) -> Result<(), Error> {
        let size = self.desc_size;
        if let Some(seed) = self.csum {
            let sum = Self::group_checksum(seed, group.number, &group.raw[..size]);
            put16(&mut group.raw, 0x1E, sum);
        }
        device.write(self.group_offset(group.number), &group.raw[..size])?;
        Ok(())
    }

    fn group_offset(&self, number: u32) -> u64 {
        (u64::from(self.first_data_block) + 1) * u64::from(self.block_size)
            + u64::from(number) * self.desc_size as u64
    }

    pub(crate) fn group_checksum(seed: u32, number: u32, raw: &[u8]) -> u16 {
        let crc = crc::update(seed, &number.to_le_bytes());
        let crc = crc::update(crc, &raw[..0x1E]);
        let crc = crc::update_zeros(crc, 2);
        (crc::update(crc, &raw[0x20..]) & 0xFFFF) as u16
    }

    pub(crate) fn group_first_block(&self, number: u32) -> u64 {
        u64::from(self.first_data_block) + u64::from(number) * u64::from(self.blocks_per_group)
    }

    pub(crate) fn blocks_in_group(&self, number: u32) -> u32 {
        let first = self.group_first_block(number);
        (self.blocks - first).min(u64::from(self.blocks_per_group)) as u32
    }

    pub(crate) fn block_bitmap(&self, group: &Group) -> u64 {
        group.wide(0x0, 0x20, self.wide)
    }
    pub(crate) fn inode_bitmap(&self, group: &Group) -> u64 {
        group.wide(0x4, 0x24, self.wide)
    }
    pub(crate) fn inode_table(&self, group: &Group) -> u64 {
        group.wide(0x8, 0x28, self.wide)
    }
    pub(crate) fn free_blocks_in(&self, group: &Group) -> u32 {
        group.count(0xC, 0x2C, self.wide)
    }
    pub(crate) fn set_free_blocks_in(&self, group: &mut Group, value: u32) {
        group.set_count(0xC, 0x2C, self.wide, value);
    }
    pub(crate) fn free_inodes_in(&self, group: &Group) -> u32 {
        group.count(0xE, 0x2E, self.wide)
    }
    pub(crate) fn set_free_inodes_in(&self, group: &mut Group, value: u32) {
        group.set_count(0xE, 0x2E, self.wide, value);
    }
    pub(crate) fn used_dirs_in(&self, group: &Group) -> u32 {
        group.count(0x10, 0x30, self.wide)
    }
    pub(crate) fn set_used_dirs_in(&self, group: &mut Group, value: u32) {
        group.set_count(0x10, 0x30, self.wide, value);
    }
    pub(crate) fn itable_unused_in(&self, group: &Group) -> u32 {
        group.count(0x1C, 0x32, self.wide)
    }
    pub(crate) fn set_itable_unused_in(&self, group: &mut Group, value: u32) {
        group.set_count(0x1C, 0x32, self.wide, value);
    }
    pub(crate) fn inode_table_blocks(&self) -> u64 {
        (u64::from(self.inodes_per_group) * self.inode_size as u64)
            .div_ceil(u64::from(self.block_size))
    }

    /// Bitmap checksum fields: (lo offset, hi offset) in the descriptor.
    pub(crate) fn bitmap_checksum_matches(
        &self,
        group: &Group,
        block_bitmap: bool,
        bitmap: &[u8],
    ) -> bool {
        let Some(seed) = self.csum else {
            return true;
        };
        let (lo, hi) = if block_bitmap {
            (0x18, 0x38)
        } else {
            (0x1A, 0x3A)
        };
        let sum = crc::update(seed, bitmap);
        let stored = u32::from(get16(&group.raw, lo))
            | if self.desc_size >= 64 {
                u32::from(get16(&group.raw, hi)) << 16
            } else {
                0
            };
        let mask = if self.desc_size >= 64 {
            u32::MAX
        } else {
            0xFFFF
        };
        sum & mask == stored
    }

    pub(crate) fn set_bitmap_checksum(&self, group: &mut Group, block_bitmap: bool, bitmap: &[u8]) {
        let Some(seed) = self.csum else {
            return;
        };
        let (lo, hi) = if block_bitmap {
            (0x18, 0x38)
        } else {
            (0x1A, 0x3A)
        };
        let sum = crc::update(seed, bitmap);
        put16(&mut group.raw, lo, sum as u16);
        if self.desc_size >= 64 {
            put16(&mut group.raw, hi, (sum >> 16) as u16);
        }
    }

    fn inode_offset<D: Device>(&self, device: &mut D, number: u32) -> Result<u64, Error> {
        if number == 0 || number > self.inodes {
            return Err(Error::Corrupt);
        }
        let group = self.group(device, (number - 1) / self.inodes_per_group)?;
        let index = u64::from((number - 1) % self.inodes_per_group);
        Ok(self.inode_table(&group) * u64::from(self.block_size) + index * self.inode_size as u64)
    }

    /// The per-inode checksum seed (`checksums.rst`: UUID, inode number,
    /// generation).
    pub(crate) fn inode_seed(&self, seed: u32, inode: &Inode) -> u32 {
        let crc = crc::update(seed, &inode.number.to_le_bytes());
        crc::update(crc, &inode.generation().to_le_bytes())
    }

    /// Whether the inode's extra fields reach `i_checksum_hi`.
    fn has_checksum_hi(&self, raw: &[u8]) -> bool {
        self.inode_size > 128 && get16(raw, 0x80) >= 4
    }

    fn inode_checksum(&self, seed: u32, inode: &Inode) -> u32 {
        let raw = &inode.raw[..self.inode_size];
        let crc = self.inode_seed(seed, inode);
        let crc = crc::update(crc, &raw[..0x7C]);
        let crc = crc::update_zeros(crc, 2);
        let crc = crc::update(crc, &raw[0x7E..128]);
        if self.inode_size == 128 {
            return crc;
        }
        if self.has_checksum_hi(raw) {
            let crc = crc::update(crc, &raw[128..0x82]);
            let crc = crc::update_zeros(crc, 2);
            crc::update(crc, &raw[0x84..])
        } else {
            crc::update(crc, &raw[128..])
        }
    }

    pub(crate) fn inode<D: Device>(&self, device: &mut D, number: u32) -> Result<Inode, Error> {
        let offset = self.inode_offset(device, number)?;
        let mut inode = Inode {
            number,
            raw: [0; MAX_INODE_BYTES],
        };
        device.read(offset, &mut inode.raw[..self.inode_size])?;
        if self.inode_size > 128 {
            let extra = usize::from(get16(&inode.raw, 0x80));
            if 128 + extra > self.inode_size || extra % 4 != 0 {
                return Err(Error::Corrupt);
            }
        }
        if let Some(seed) = self.csum {
            let sum = self.inode_checksum(seed, &inode);
            let lo = u32::from(get16(&inode.raw, 0x7C));
            let ok = if self.has_checksum_hi(&inode.raw) {
                sum == lo | u32::from(get16(&inode.raw, 0x82)) << 16
            } else {
                sum & 0xFFFF == lo
            };
            if !ok {
                return Err(Error::Corrupt);
            }
        }
        if inode.flags() & EXT4_INLINE_DATA_FL != 0 && inode.kind().is_some() {
            return Err(Error::Unsupported);
        }
        Ok(inode)
    }

    pub(crate) fn write_inode<D: Device>(
        &self,
        device: &mut D,
        inode: &mut Inode,
    ) -> Result<(), Error> {
        let offset = self.inode_offset(device, inode.number)?;
        if let Some(seed) = self.csum {
            let sum = self.inode_checksum(seed, inode);
            put16(&mut inode.raw, 0x7C, sum as u16);
            if self.has_checksum_hi(&inode.raw) {
                put16(&mut inode.raw, 0x82, (sum >> 16) as u16);
            }
        }
        device.write(offset, &inode.raw[..self.inode_size])?;
        Ok(())
    }

    /// The live node `inode` must be a file or directory in use.
    fn live<D: Device>(&self, device: &mut D, number: u32) -> Result<(Inode, Kind), Error> {
        let inode = self.inode(device, number)?;
        if inode.links() == 0 {
            return Err(Error::NotFound);
        }
        let kind = inode.kind().ok_or(Error::NotFileOrDirectory)?;
        Ok((inode, kind))
    }

    pub fn stat<D: Device>(&self, device: &mut D, inode: u32) -> Result<Stat, Error> {
        let (raw, kind) = self.live(device, inode)?;
        Ok(Stat {
            inode,
            kind,
            size: raw.size(),
        })
    }

    /// Reads from file `inode` at `offset`; returns how many bytes were read,
    /// zero at or past the end.
    pub fn read<D: Device>(
        &self,
        device: &mut D,
        inode: u32,
        offset: u64,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let (raw, kind) = self.live(device, inode)?;
        if kind != Kind::File {
            return Err(Error::IsDirectory);
        }
        let size = raw.size();
        if offset >= size || out.is_empty() {
            return Ok(0);
        }
        let length = (size - offset).min(out.len() as u64) as usize;
        let bs = u64::from(self.block_size);
        let mut done = 0;
        let mut block = [0u8; MAX_BLOCK_BYTES];
        while done < length {
            let at = offset + done as u64;
            let logical = u32::try_from(at / bs).map_err(|_| Error::Corrupt)?;
            let within = (at % bs) as usize;
            let take = (self.bs() - within).min(length - done);
            match self.map(device, &raw, logical)? {
                Some(mapped) if !mapped.uninit => {
                    self.read_block(device, mapped.physical, &mut block[..self.bs()])?;
                    out[done..done + take].copy_from_slice(&block[within..within + take]);
                }
                _ => out[done..done + take].fill(0),
            }
            done += take;
        }
        Ok(length)
    }

    /// Finds `name` in directory `dir`.
    pub fn lookup<D: Device>(&self, device: &mut D, dir: u32, name: &[u8]) -> Result<Stat, Error> {
        let (raw, kind) = self.live(device, dir)?;
        if kind != Kind::Directory {
            return Err(Error::NotDirectory);
        }
        let found = self
            .find_entry(device, &raw, name)?
            .ok_or(Error::NotFound)?;
        self.stat(device, found.inode)
    }

    /// Resolves a canonical relative `path` (components joined by `/`)
    /// below directory `dir`; an empty path is `dir` itself.
    pub fn resolve<D: Device>(&self, device: &mut D, dir: u32, path: &[u8]) -> Result<Stat, Error> {
        let mut here = self.stat(device, dir)?;
        if path.is_empty() {
            return Ok(here);
        }
        for component in path.split(|&byte| byte == b'/') {
            if here.kind != Kind::Directory {
                return Err(Error::NotDirectory);
            }
            here = self.lookup(device, here.inode, component)?;
        }
        Ok(here)
    }

    /// Lists directory `dir` from `cookie` (0 starts), calling `entry` for
    /// each file and directory other than `.` and `..`; nodes of other
    /// kinds are skipped. `entry` returns false to stop before taking the
    /// entry. Returns the cookie that resumes at the first entry not taken,
    /// or `None` at the end.
    pub fn read_dir<D: Device, F: FnMut(Entry<'_>) -> bool>(
        &self,
        device: &mut D,
        dir: u32,
        cookie: u64,
        entry: F,
    ) -> Result<Option<u64>, Error> {
        let (raw, kind) = self.live(device, dir)?;
        if kind != Kind::Directory {
            return Err(Error::NotDirectory);
        }
        self.list(device, &raw, cookie, entry)
    }

    /// Makes every completed write durable.
    pub fn sync<D: Device>(&self, device: &mut D) -> Result<(), Error> {
        device.flush()?;
        Ok(())
    }
}

/// Whether `name` may be stored in a directory.
pub fn valid_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name != b"."
        && name != b".."
        && !name.iter().any(|&byte| byte == b'/' || byte == 0)
}

#[cfg(test)]
mod tests;
