//! The ext4 journal (jbd2), in `data=ordered` mode.
//!
//! Written from the kernel.org documentation as shipped in Linux 7.2.14
//! (`Documentation/filesystems/ext4/journal.rst`, with `checksums.rst` and
//! `super.rst`). The checksum details the document leaves open (which bytes
//! each crc32c covers) were settled against journals written by e2fsprogs
//! 1.47.4's `debugfs` (`jo -c`, `jw`), and what this module writes is checked
//! by `e2fsck` and `debugfs logdump` (`tests/e2fsprogs.rs`). No jbd2 or
//! e2fsprogs source was read or adapted.
//!
//! Metadata changes collect in a [`Transaction`] held in memory, through a
//! [`Journaled`] device; file data goes straight to its home blocks. A
//! commit makes the data durable, logs the metadata blocks, writes the
//! commit block, then writes every block home and marks the journal empty.
//! So the log always starts at its first block and holds at most one
//! transaction, which needs no revoke records: a block freed and reused as
//! data can never be overwritten by a later replay. A block freed in the
//! running transaction is not reallocated until it commits (the allocator
//! also consults [`Device::read_committed`]), so a crash never shows one
//! file's data in another.
//!
//! [`recover`] replays journals written by this module and by Linux:
//! descriptor, revoke and commit blocks, with no, v2 or v3 checksums.
//! Fast commits and external journals are refused.

use crate::extent::Run;
use crate::{
    BG_BLOCK_UNINIT, Device, DeviceError, Error, INCOMPAT_RECOVER, Kind, MAX_BLOCK_BYTES,
    RO_COMPAT_SPARSE_SUPER, ROOT_INODE, SUPERBLOCK_BYTES, Volume, crc, get16, get32,
};

/// `s_feature_compat` bit: the volume has a journal.
pub(crate) const COMPAT_HAS_JOURNAL: u32 = 0x4;
/// `s_feature_incompat` bit: the journal is on another device.
const INCOMPAT_JOURNAL_DEV: u32 = 0x8;
/// `s_feature_compat` bit: superblock backups only where
/// `s_backup_bgs` says, which [`Log::load`] does not check against.
const COMPAT_SPARSE_SUPER2: u32 = 0x200;
/// The most extents a journal file may have.
const MAX_RUNS: usize = 64;
/// The inode `format` gives the journal.
pub(crate) const JOURNAL_INODE: u32 = 8;

const MAGIC: u32 = 0xC03B_3998;
const DESCRIPTOR: u32 = 1;
const COMMIT: u32 = 2;
const SUPERBLOCK_V2: u32 = 4;
const REVOKE: u32 = 5;

const J_COMPAT_CHECKSUM: u32 = 0x1;
const J_REVOKE: u32 = 0x1;
const J_64BIT: u32 = 0x2;
const J_ASYNC_COMMIT: u32 = 0x4;
const J_CSUM_V2: u32 = 0x8;
const J_CSUM_V3: u32 = 0x10;
const J_KNOWN: u32 = J_REVOKE | J_64BIT | J_ASYNC_COMMIT | J_CSUM_V2 | J_CSUM_V3;
const CHECKSUM_CRC32C: u8 = 4;

const TAG_ESCAPED: u32 = 0x1;
const TAG_SAME_UUID: u32 = 0x2;
const TAG_LAST: u32 = 0x8;

/// The most revoked blocks [`recover`] tracks.
const MAX_REVOKES: usize = 256;
/// The most tags one descriptor holds (4 KiB blocks, 8-byte tags).
const MAX_TAGS: usize = MAX_BLOCK_BYTES / 8;

/// A device error raised by [`Journaled`] when the transaction is full.
pub const TRANSACTION_FULL: DeviceError = DeviceError(0x4A46_554C);
/// A device error raised by [`Journaled`] when its store fails.
pub const STORE_FAILED: DeviceError = DeviceError(0x4A53_5446);

fn be32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}
fn put_be32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_be_bytes());
}
fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

/// One block's tag in a descriptor.
#[derive(Clone, Copy, Default)]
struct Tag {
    block: u64,
    flags: u32,
    checksum: u32,
}

/// The journal file: where it is and how its blocks are laid out.
struct Log {
    /// The journal file's extents, contiguous from logical block 0.
    runs: [Run; MAX_RUNS],
    run_count: usize,
    block_size: usize,
    first: u32,
    maxlen: u32,
    incompat: u32,
    /// crc32c of the journal UUID, when blocks carry v2 or v3 checksums.
    seed: Option<u32>,
    uuid: [u8; 16],
}

impl Log {
    /// Reads and checks `volume`'s journal: its inode, where its blocks are,
    /// and its superblock. The journal must be a reserved regular inode
    /// whose blocks are distinct, in use and clear of the superblocks, group
    /// descriptors, bitmaps and inode tables, as Linux and e2fsck require;
    /// a journal that cannot be one is [`Error::Corrupt`].
    fn load<D: Device>(
        volume: &Volume,
        device: &mut D,
        sb: &mut [u8; SUPERBLOCK_BYTES],
    ) -> Result<Self, Error> {
        let incompat = get32(&volume.sb, 0x60);
        if incompat & INCOMPAT_JOURNAL_DEV != 0
            || volume.sb[0xE4..0xE8] != [0; 4]
            || get32(&volume.sb, 0x5C) & COMPAT_SPARSE_SUPER2 != 0
        {
            return Err(Error::Unsupported);
        }
        let number = get32(&volume.sb, 0xE0);
        if number == 0 || number == ROOT_INODE || number >= volume.first_inode {
            return Err(Error::Corrupt);
        }
        let inode = volume.inode(device, number)?;
        if inode.kind() != Some(Kind::File) || inode.links() == 0 {
            return Err(Error::Corrupt);
        }
        let block_size = volume.bs();
        let mut log = Self {
            runs: [Run::default(); MAX_RUNS],
            run_count: 0,
            block_size,
            first: 0,
            maxlen: 0,
            incompat: 0,
            seed: None,
            uuid: [0; 16],
        };
        log.run_count = volume.runs(device, &inode, &mut log.runs)?;
        let mut mapped = 0u32;
        for run in &log.runs[..log.run_count] {
            if run.logical != mapped {
                return Err(Error::Corrupt);
            }
            mapped = mapped.checked_add(run.len).ok_or(Error::Corrupt)?;
        }
        log.check_placement(volume, device)?;
        let at = log.physical(volume, device, 0)?;
        device.read(at * block_size as u64, sb)?;
        if be32(sb, 0) != MAGIC || be32(sb, 4) != SUPERBLOCK_V2 {
            return Err(Error::Unsupported);
        }
        let maxlen = be32(sb, 0x10);
        let first = be32(sb, 0x14);
        log.incompat = be32(sb, 0x28);
        if be32(sb, 0xC) as usize != block_size
            || first == 0
            || first >= maxlen
            || maxlen > mapped
            || u64::from(maxlen) * block_size as u64 > inode.size()
            || be32(sb, 0x40) > 1
        {
            return Err(Error::Corrupt);
        }
        if log.incompat & !J_KNOWN != 0 || be32(sb, 0x2C) != 0 || be32(sb, 0x20) != 0 {
            return Err(Error::Unsupported);
        }
        log.first = first;
        log.maxlen = maxlen;
        log.uuid.copy_from_slice(&sb[0x30..0x40]);
        if log.incompat & (J_CSUM_V2 | J_CSUM_V3) != 0 {
            if sb[0x50] != CHECKSUM_CRC32C {
                return Err(Error::Unsupported);
            }
            if superblock_checksum(sb) != be32(sb, 0xFC) {
                return Err(Error::Corrupt);
            }
            log.seed = Some(crc::update(!0, &log.uuid));
        }
        Ok(log)
    }

    /// The journal's blocks: pairwise distinct, marked in use, and clear
    /// of every group's superblock and descriptor copies, bitmaps and inode
    /// table.
    fn check_placement<D: Device>(&self, volume: &Volume, device: &mut D) -> Result<(), Error> {
        let runs = &self.runs[..self.run_count];
        for (index, run) in runs.iter().enumerate() {
            let end = run.physical + u64::from(run.len);
            if runs[index + 1..].iter().any(|other| {
                other.physical < end && run.physical < other.physical + u64::from(other.len)
            }) {
                return Err(Error::Corrupt);
            }
        }
        let overlaps = |first: u64, count: u64| {
            runs.iter().any(|run| {
                first < run.physical + u64::from(run.len) && run.physical < first + count
            })
        };
        let sparse = volume.has_ro_compat(RO_COMPAT_SPARSE_SUPER);
        let descriptor_blocks =
            (u64::from(volume.groups) * volume.desc_size as u64).div_ceil(volume.bs() as u64);
        let reserved = u64::from(get16(&volume.sb, 0xCE));
        if overlaps(0, u64::from(volume.first_data_block) + 1) {
            return Err(Error::Corrupt);
        }
        let mut bitmap = [0u8; MAX_BLOCK_BYTES];
        let bitmap = &mut bitmap[..volume.bs()];
        for number in 0..volume.groups {
            let start = volume.group_first_block(number);
            if (!sparse || crate::format::has_backup(number))
                && overlaps(start, 1 + descriptor_blocks + reserved)
            {
                return Err(Error::Corrupt);
            }
            let group = volume.group(device, number)?;
            if overlaps(volume.block_bitmap(&group), 1)
                || overlaps(volume.inode_bitmap(&group), 1)
                || overlaps(volume.inode_table(&group), volume.inode_table_blocks())
            {
                return Err(Error::Corrupt);
            }
            let count = u64::from(volume.blocks_in_group(number));
            if !overlaps(start, count) {
                continue;
            }
            if group.flags() & BG_BLOCK_UNINIT != 0 {
                return Err(Error::Corrupt);
            }
            volume.read_block(device, volume.block_bitmap(&group), bitmap)?;
            for run in runs {
                let from = run.physical.max(start);
                let to = (run.physical + u64::from(run.len)).min(start + count);
                for block in from..to {
                    let index = (block - start) as usize;
                    if bitmap[index / 8] & (1 << (index % 8)) == 0 {
                        return Err(Error::Corrupt);
                    }
                }
            }
        }
        Ok(())
    }

    /// Where journal block `logical` lives.
    fn physical<D: Device>(
        &self,
        _volume: &Volume,
        _device: &mut D,
        logical: u32,
    ) -> Result<u64, Error> {
        self.runs[..self.run_count]
            .iter()
            .find(|run| logical >= run.logical && logical - run.logical < run.len)
            .map(|run| run.physical + u64::from(logical - run.logical))
            .ok_or(Error::Corrupt)
    }

    fn read<D: Device>(
        &self,
        volume: &Volume,
        device: &mut D,
        position: u32,
        out: &mut [u8],
    ) -> Result<(), Error> {
        let at = self.physical(volume, device, position)?;
        volume.read_block(device, at, out)
    }

    fn write<D: Device>(
        &self,
        volume: &Volume,
        device: &mut D,
        position: u32,
        data: &[u8],
    ) -> Result<(), Error> {
        let at = self.physical(volume, device, position)?;
        device.write(at * self.block_size as u64, data)?;
        Ok(())
    }

    fn next(&self, position: u32) -> u32 {
        if position + 1 >= self.maxlen {
            self.first
        } else {
            position + 1
        }
    }

    fn v3(&self) -> bool {
        self.incompat & J_CSUM_V3 != 0
    }

    fn wide(&self) -> bool {
        self.incompat & J_64BIT != 0
    }

    /// A tag's size. Linux adds two bytes to v2 tags, which `journal.rst`
    /// omits (Linux 7.2.14 `journal_tag_bytes`, D3 of the W11 review).
    fn tag_bytes(&self) -> usize {
        if self.v3() {
            return 16;
        }
        let v2 = if self.incompat & J_CSUM_V2 != 0 { 2 } else { 0 };
        if self.wide() { 12 + v2 } else { 8 + v2 }
    }

    /// Where descriptor and revoke blocks' records end.
    fn records_end(&self) -> usize {
        self.block_size - if self.seed.is_some() { 4 } else { 0 }
    }

    /// Whether a descriptor or revoke block's tail checksum holds.
    fn tail_matches(&self, block: &[u8]) -> bool {
        let Some(seed) = self.seed else {
            return true;
        };
        let end = self.block_size - 4;
        crc::update_zeros(crc::update(seed, &block[..end]), 4) == be32(block, end)
    }

    fn set_tail(&self, block: &mut [u8]) {
        if let Some(seed) = self.seed {
            let end = self.block_size - 4;
            let sum = crc::update_zeros(crc::update(seed, &block[..end]), 4);
            put_be32(block, end, sum);
        }
    }

    fn commit_matches(&self, block: &[u8]) -> bool {
        let Some(seed) = self.seed else {
            return true;
        };
        commit_checksum(seed, block) == be32(block, 0x10)
    }

    /// A data block's tag checksum (UUID, sequence, the block as logged).
    fn tag_checksum(&self, sequence: u32, data: &[u8]) -> u32 {
        let seed = self.seed.unwrap_or(0);
        crc::update(crc::update(seed, &sequence.to_be_bytes()), data)
    }

    /// Reads a descriptor's tags into `tags`; returns how many.
    fn tags(&self, block: &[u8], tags: &mut [Tag; MAX_TAGS]) -> usize {
        let size = self.tag_bytes();
        let end = self.records_end();
        let mut at = 12;
        let mut count = 0;
        while at + size <= end && count < MAX_TAGS {
            let low = u64::from(be32(block, at));
            let (flags, checksum, high) = if self.v3() {
                (
                    be32(block, at + 4),
                    be32(block, at + 12),
                    be32(block, at + 8),
                )
            } else {
                let high = if self.wide() { be32(block, at + 8) } else { 0 };
                (
                    u32::from(be16(block, at + 6)),
                    u32::from(be16(block, at + 4)),
                    high,
                )
            };
            let high = if self.wide() { u64::from(high) } else { 0 };
            tags[count] = Tag {
                block: low | high << 32,
                flags,
                checksum,
            };
            count += 1;
            at += size;
            if flags & TAG_SAME_UUID == 0 {
                at += 16;
            }
            if flags & TAG_LAST != 0 {
                break;
            }
        }
        count
    }

    /// How many tags fit in one descriptor block this module writes (the
    /// first carries the UUID).
    fn tags_per_descriptor(&self) -> usize {
        (self.records_end() - 12 - 16) / self.tag_bytes()
    }
}

fn superblock_checksum(sb: &[u8]) -> u32 {
    let crc = crc::update(!0, &sb[..0xFC]);
    let crc = crc::update_zeros(crc, 4);
    crc::update(crc, &sb[0x100..SUPERBLOCK_BYTES])
}

fn commit_checksum(seed: u32, block: &[u8]) -> u32 {
    let crc = crc::update(seed, &block[..0x10]);
    let crc = crc::update_zeros(crc, 4);
    crc::update(crc, &block[0x14..])
}

/// An empty v2 journal superblock (sequence 1, v3 checksums, 64-bit tags),
/// zero-padded to the block.
pub(crate) fn empty_superblock(block: &mut [u8], block_size: u32, blocks: u32, uuid: &[u8; 16]) {
    block.fill(0);
    put_be32(block, 0, MAGIC);
    put_be32(block, 4, SUPERBLOCK_V2);
    put_be32(block, 0xC, block_size);
    put_be32(block, 0x10, blocks);
    put_be32(block, 0x14, 1);
    put_be32(block, 0x18, 1);
    put_be32(block, 0x28, J_64BIT | J_CSUM_V3);
    block[0x30..0x40].copy_from_slice(uuid);
    put_be32(block, 0x40, 1);
    block[0x50] = CHECKSUM_CRC32C;
    let sum = superblock_checksum(block);
    put_be32(block, 0xFC, sum);
}

/// Blocks revoked by committed transactions, with the latest revoking
/// sequence.
struct Revoked {
    entries: [(u64, u32); MAX_REVOKES],
    len: usize,
}

impl Revoked {
    fn add(&mut self, block: u64, sequence: u32) -> Result<(), Error> {
        if let Some(entry) = self.entries[..self.len]
            .iter_mut()
            .find(|entry| entry.0 == block)
        {
            entry.1 = entry.1.max(sequence);
            return Ok(());
        }
        if self.len == MAX_REVOKES {
            return Err(Error::Unsupported);
        }
        self.entries[self.len] = (block, sequence);
        self.len += 1;
        Ok(())
    }

    fn skips(&self, block: u64, sequence: u32) -> bool {
        self.entries[..self.len]
            .iter()
            .any(|entry| entry.0 == block && entry.1.wrapping_sub(sequence) as i32 >= 0)
    }
}

/// One walk over the log from its start: calls `visit` with each block's
/// position, type and sequence until the first block that does not
/// continue the log, and returns the first sequence not committed.
fn walk<D: Device>(
    volume: &Volume,
    device: &mut D,
    log: &Log,
    start: u32,
    sequence: u32,
    end: Option<u32>,
    mut visit: impl FnMut(&mut D, u32, u32, u32, &[u8]) -> Result<(), Error>,
) -> Result<u32, Error> {
    let mut block = [0u8; MAX_BLOCK_BYTES];
    let block = &mut block[..log.block_size];
    let mut tags = [Tag::default(); MAX_TAGS];
    let mut position = start;
    let mut expected = sequence;
    let mut steps = 0u32;
    while steps < log.maxlen && end.is_none_or(|end| expected != end) {
        log.read(volume, device, position, block)?;
        if be32(block, 0) != MAGIC || be32(block, 8) != expected {
            break;
        }
        let kind = be32(block, 4);
        match kind {
            DESCRIPTOR => {
                if !log.tail_matches(block) {
                    break;
                }
                let count = log.tags(block, &mut tags);
                visit(device, position, kind, expected, block)?;
                for _ in 0..=count {
                    position = log.next(position);
                }
                steps = steps.saturating_add(1 + count as u32);
                continue;
            }
            REVOKE => {
                if !log.tail_matches(block) {
                    break;
                }
                visit(device, position, kind, expected, block)?;
            }
            COMMIT => {
                if !log.commit_matches(block) {
                    break;
                }
                expected = expected.wrapping_add(1);
            }
            _ => break,
        }
        position = log.next(position);
        steps = steps.saturating_add(1);
    }
    Ok(expected)
}

/// Replays `device`'s journal if it holds committed transactions, then
/// marks it empty and clears the volume's needs-recovery flag. Returns
/// whether anything was replayed. A volume without a journal is left
/// alone. Run before [`Volume::mount`], which refuses a volume that still
/// needs recovery.
pub fn recover<D: Device>(device: &mut D, device_bytes: u64) -> Result<bool, Error> {
    let volume = Volume::mount_inner(device, device_bytes, false, true)?;
    if get32(&volume.sb, 0x5C) & COMPAT_HAS_JOURNAL == 0 {
        return if get32(&volume.sb, 0x60) & INCOMPAT_RECOVER != 0 {
            Err(Error::Corrupt)
        } else {
            Ok(false)
        };
    }
    let mut sb = [0u8; SUPERBLOCK_BYTES];
    let needs_recovery = get32(&volume.sb, 0x60) & INCOMPAT_RECOVER != 0;
    let log = match Log::load(&volume, device, &mut sb) {
        // A journal this module cannot use, on a volume that needs no
        // recovery, is left for the mount to decide on (read-only).
        Err(Error::Unsupported) if !needs_recovery => return Ok(false),
        other => other?,
    };
    let start = be32(&sb, 0x1C);
    let sequence = be32(&sb, 0x18);
    let mut replayed = false;
    if start != 0 {
        if start < log.first || start >= log.maxlen {
            return Err(Error::Corrupt);
        }
        // Asynchronous commits are only safe to replay when every block's
        // checksum is checked.
        if log.incompat & J_ASYNC_COMMIT != 0 && log.seed.is_none() {
            return Err(Error::Unsupported);
        }
        let end = walk(
            &volume,
            device,
            &log,
            start,
            sequence,
            None,
            |_, _, _, _, _| Ok(()),
        )?;
        let mut revoked = Revoked {
            entries: [(0, 0); MAX_REVOKES],
            len: 0,
        };
        let record = if log.wide() { 8 } else { 4 };
        walk(
            &volume,
            device,
            &log,
            start,
            sequence,
            Some(end),
            |_, _, kind, sequence, block| {
                if kind != REVOKE {
                    return Ok(());
                }
                let used = be32(block, 12) as usize;
                if used < 16 || used > log.records_end() {
                    return Err(Error::Corrupt);
                }
                let mut at = 16;
                while at + record <= used {
                    let target = if record == 8 {
                        u64::from(be32(block, at)) << 32 | u64::from(be32(block, at + 4))
                    } else {
                        u64::from(be32(block, at))
                    };
                    revoked.add(target, sequence)?;
                    at += record;
                }
                Ok(())
            },
        )?;
        let mut tags = [Tag::default(); MAX_TAGS];
        let mut data = [0u8; MAX_BLOCK_BYTES];
        walk(
            &volume,
            device,
            &log,
            start,
            sequence,
            Some(end),
            |device, position, kind, sequence, block| {
                if kind != DESCRIPTOR {
                    return Ok(());
                }
                let data = &mut data[..log.block_size];
                let count = log.tags(block, &mut tags);
                let mut at = position;
                for tag in &tags[..count] {
                    at = log.next(at);
                    if revoked.skips(tag.block, sequence) {
                        continue;
                    }
                    if tag.block >= volume.blocks {
                        return Err(Error::Corrupt);
                    }
                    log.read(&volume, device, at, data)?;
                    if log.seed.is_some() {
                        let sum = log.tag_checksum(sequence, data);
                        let sum = if log.v3() { sum } else { sum & 0xFFFF };
                        if sum != tag.checksum {
                            return Err(Error::Corrupt);
                        }
                    }
                    if tag.flags & TAG_ESCAPED != 0 {
                        put_be32(data, 0, MAGIC);
                    }
                    device.write(tag.block * log.block_size as u64, data)?;
                }
                Ok(())
            },
        )?;
        device.flush()?;
        // The next transaction starts past the last one replayed, so a
        // stale commit block can never be taken for it (as Linux does).
        put_be32(&mut sb, 0x18, end.wrapping_add(1));
        put_be32(&mut sb, 0x1C, 0);
        if log.seed.is_some() {
            let sum = superblock_checksum(&sb);
            put_be32(&mut sb, 0xFC, sum);
        }
        log.write_superblock(&volume, device, &sb)?;
        replayed = end != sequence;
    }
    // The replay may have rewritten the superblock itself.
    let mut volume = Volume::mount_inner(device, device_bytes, false, true)?;
    if get32(&volume.sb, 0x60) & INCOMPAT_RECOVER != 0 {
        volume.set_needs_recovery(false);
        volume.write_superblock(device)?;
    }
    device.flush()?;
    Ok(replayed)
}

impl Log {
    fn write_superblock<D: Device>(
        &self,
        volume: &Volume,
        device: &mut D,
        sb: &[u8; SUPERBLOCK_BYTES],
    ) -> Result<(), Error> {
        let at = self.physical(volume, device, 0)?;
        device.write(at * self.block_size as u64, sb)?;
        Ok(())
    }
}

/// Byte storage for a transaction's blocks: slot `n` is at `n` times the
/// block size.
pub trait Store {
    fn load(&mut self, offset: usize, out: &mut [u8]) -> bool;
    fn save(&mut self, offset: usize, data: &[u8]) -> bool;
}

/// The running transaction: up to `SLOTS` metadata blocks, by home block,
/// with their contents in a [`Store`].
pub struct Transaction<S, const SLOTS: usize> {
    store: S,
    homes: [u64; SLOTS],
    len: usize,
    limit: usize,
    block_size: usize,
}

impl<S: Store, const SLOTS: usize> Transaction<S, SLOTS> {
    /// A transaction over `store`, which must hold `SLOTS` blocks of the
    /// journal's block size.
    pub fn new(store: S, journal: &Journal) -> Self {
        Self {
            store,
            homes: [0; SLOTS],
            len: 0,
            limit: SLOTS.min(journal.capacity()),
            block_size: journal.log.block_size,
        }
    }

    /// Blocks changed since the last commit.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The most blocks it holds.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Forgets every change (after a failure that left them unknown).
    pub fn discard(&mut self) {
        self.len = 0;
    }

    fn slot(&self, home: u64) -> Option<usize> {
        self.homes[..self.len].iter().position(|&at| at == home)
    }

    fn load(&mut self, slot: usize, within: usize, out: &mut [u8]) -> Result<(), DeviceError> {
        if self.store.load(slot * self.block_size + within, out) {
            Ok(())
        } else {
            Err(STORE_FAILED)
        }
    }

    fn save(&mut self, slot: usize, within: usize, data: &[u8]) -> Result<(), DeviceError> {
        if self.store.save(slot * self.block_size + within, data) {
            Ok(())
        } else {
            Err(STORE_FAILED)
        }
    }

    /// Takes slot `slot` out, moving the last slot into its place.
    fn remove(&mut self, slot: usize) -> Result<(), DeviceError> {
        let last = self.len - 1;
        if slot != last {
            let mut block = [0u8; MAX_BLOCK_BYTES];
            let block = &mut block[..self.block_size];
            self.load(last, 0, block)?;
            self.save(slot, 0, block)?;
            self.homes[slot] = self.homes[last];
        }
        self.len = last;
        Ok(())
    }
}

/// A device whose metadata writes collect in a [`Transaction`] until
/// [`Journal::commit`]; reads see them, data writes and committed reads go
/// to `device`.
pub struct Journaled<'a, D, S, const SLOTS: usize> {
    pub device: &'a mut D,
    pub transaction: &'a mut Transaction<S, SLOTS>,
}

impl<D: Device, S: Store, const SLOTS: usize> Device for Journaled<'_, D, S, SLOTS> {
    fn read(&mut self, offset: u64, out: &mut [u8]) -> Result<(), DeviceError> {
        if self.transaction.is_empty() {
            return self.device.read(offset, out);
        }
        let size = self.transaction.block_size;
        let mut done = 0;
        while done < out.len() {
            let at = offset.checked_add(done as u64).ok_or(DeviceError(0))?;
            let block = at / size as u64;
            let within = (at % size as u64) as usize;
            let take = (size - within).min(out.len() - done);
            let piece = &mut out[done..done + take];
            match self.transaction.slot(block) {
                Some(slot) => self.transaction.load(slot, within, piece)?,
                None => self.device.read(at, piece)?,
            }
            done += take;
        }
        Ok(())
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), DeviceError> {
        let size = self.transaction.block_size;
        let mut done = 0;
        while done < data.len() {
            let at = offset.checked_add(done as u64).ok_or(DeviceError(0))?;
            let block = at / size as u64;
            let within = (at % size as u64) as usize;
            let take = (size - within).min(data.len() - done);
            let transaction = &mut *self.transaction;
            let slot = match transaction.slot(block) {
                Some(slot) => slot,
                None => {
                    if transaction.len == transaction.limit {
                        return Err(TRANSACTION_FULL);
                    }
                    // The slot holds its whole block before it is counted.
                    let slot = transaction.len;
                    let mut whole = [0u8; MAX_BLOCK_BYTES];
                    let whole = &mut whole[..size];
                    if take != size {
                        self.device.read(block * size as u64, whole)?;
                    }
                    whole[within..within + take].copy_from_slice(&data[done..done + take]);
                    transaction.save(slot, 0, whole)?;
                    transaction.homes[slot] = block;
                    transaction.len += 1;
                    done += take;
                    continue;
                }
            };
            transaction.save(slot, within, &data[done..done + take])?;
            done += take;
        }
        Ok(())
    }

    fn write_data(&mut self, offset: u64, data: &[u8]) -> Result<(), DeviceError> {
        let size = self.transaction.block_size;
        let mut done = 0;
        while done < data.len() {
            let at = offset.checked_add(done as u64).ok_or(DeviceError(0))?;
            let block = at / size as u64;
            let within = (at % size as u64) as usize;
            let take = (size - within).min(data.len() - done);
            let piece = &data[done..done + take];
            match self.transaction.slot(block) {
                // Metadata freed in this transaction and reused for data: the
                // block leaves the transaction and goes home whole now.
                Some(slot) => {
                    let mut whole = [0u8; MAX_BLOCK_BYTES];
                    let whole = &mut whole[..size];
                    self.transaction.load(slot, 0, whole)?;
                    whole[within..within + take].copy_from_slice(piece);
                    self.device.write(block * size as u64, whole)?;
                    self.transaction.remove(slot)?;
                }
                None => self.device.write(at, piece)?,
            }
            done += take;
        }
        Ok(())
    }

    fn read_committed(&mut self, offset: u64, out: &mut [u8]) -> Result<(), DeviceError> {
        self.device.read(offset, out)
    }

    fn flush(&mut self) -> Result<(), DeviceError> {
        self.device.flush()
    }
}

/// A mounted volume's journal, open for writing.
pub struct Journal {
    log: Log,
    sb: [u8; SUPERBLOCK_BYTES],
    /// The next transaction's sequence.
    sequence: u32,
}

impl Journal {
    /// Opens `volume`'s journal for its read-write mount. Returns `None` for
    /// a read-only mount or a volume without a journal. The journal must be
    /// empty ([`recover`] runs before mounting). Marks the volume as needing
    /// recovery until [`Journal::close`].
    pub fn open<D: Device>(volume: &mut Volume, device: &mut D) -> Result<Option<Self>, Error> {
        if volume.read_only() || get32(&volume.sb, 0x5C) & COMPAT_HAS_JOURNAL == 0 {
            return Ok(None);
        }
        let mut sb = [0u8; SUPERBLOCK_BYTES];
        let mut log = Log::load(volume, device, &mut sb)?;
        if be32(&sb, 0x1C) != 0 {
            return Err(Error::Corrupt);
        }
        // What this module writes: v3 checksums with metadata_csum, 64-bit
        // tags on a 64-bit volume.
        let mut incompat = log.incompat & !(J_CSUM_V2 | J_CSUM_V3 | J_64BIT | J_ASYNC_COMMIT);
        if volume.csum.is_some() {
            incompat |= J_CSUM_V3;
            sb[0x50] = CHECKSUM_CRC32C;
            log.seed = Some(crc::update(!0, &log.uuid));
        } else {
            log.seed = None;
        }
        if volume.wide {
            incompat |= J_64BIT;
        }
        log.incompat = incompat;
        put_be32(&mut sb, 0x28, incompat);
        // v1 block checksums are never written, and Linux refuses them
        // beside v2 or v3 (W11 review D5).
        let compat = be32(&sb, 0x24) & !J_COMPAT_CHECKSUM;
        put_be32(&mut sb, 0x24, compat);
        let sequence = be32(&sb, 0x18);
        let journal = Self { log, sb, sequence };
        journal.write_superblock(volume, device, 0)?;
        volume.set_needs_recovery(true);
        volume.write_superblock(device)?;
        device.flush()?;
        Ok(Some(journal))
    }

    /// The most blocks one transaction may hold.
    pub fn capacity(&self) -> usize {
        // Descriptors, the logged blocks and the commit block must fit
        // between the first log block and the end.
        let room = (self.log.maxlen - self.log.first) as usize;
        let per = self.log.tags_per_descriptor();
        // n + ceil(n / per) + 1 <= room
        let n = (room.saturating_sub(1) * per) / (per + 1);
        n.min(room.saturating_sub(2))
    }

    fn write_superblock<D: Device>(
        &self,
        volume: &Volume,
        device: &mut D,
        start: u32,
    ) -> Result<(), Error> {
        let mut sb = self.sb;
        put_be32(&mut sb, 0x18, self.sequence);
        put_be32(&mut sb, 0x1C, start);
        if self.log.seed.is_some() {
            let sum = superblock_checksum(&sb);
            put_be32(&mut sb, 0xFC, sum);
        }
        self.log.write_superblock(volume, device, &sb)
    }

    /// Commits `transaction`: makes the data written so far durable, logs
    /// and commits the metadata, then writes it home and empties the
    /// journal. `device` is the volume itself, not the [`Journaled`] view.
    /// On failure before the checkpoint ends, the transaction is kept and
    /// committing it again is safe.
    pub fn commit<D: Device, S: Store, const SLOTS: usize>(
        &mut self,
        volume: &Volume,
        device: &mut D,
        transaction: &mut Transaction<S, SLOTS>,
    ) -> Result<(), Error> {
        device.flush()?;
        if transaction.is_empty() {
            return Ok(());
        }
        let log = &self.log;
        let size = log.block_size;
        let sequence = self.sequence;
        let mut block = [0u8; MAX_BLOCK_BYTES];
        let block = &mut block[..size];
        let mut data = [0u8; MAX_BLOCK_BYTES];
        let data = &mut data[..size];
        let per = log.tags_per_descriptor();
        let mut position = log.first;
        let mut index = 0;
        while index < transaction.len {
            let count = per.min(transaction.len - index);
            block.fill(0);
            put_be32(block, 0, MAGIC);
            put_be32(block, 4, DESCRIPTOR);
            put_be32(block, 8, sequence);
            let descriptor = position;
            let mut at = 12;
            for n in 0..count {
                let slot = index + n;
                transaction.load(slot, 0, data)?;
                let home = transaction.homes[slot];
                let mut flags = if n == 0 { 0 } else { TAG_SAME_UUID };
                if n + 1 == count {
                    flags |= TAG_LAST;
                }
                if be32(data, 0) == MAGIC {
                    flags |= TAG_ESCAPED;
                    data[..4].fill(0);
                }
                // The checksum covers the block as logged, escaped.
                let checksum = log.tag_checksum(sequence, data);
                put_be32(block, at, home as u32);
                if log.v3() {
                    put_be32(block, at + 4, flags);
                    put_be32(block, at + 8, (home >> 32) as u32);
                    put_be32(block, at + 12, checksum);
                } else {
                    block[at + 4..at + 6].copy_from_slice(&(checksum as u16).to_be_bytes());
                    block[at + 6..at + 8].copy_from_slice(&(flags as u16).to_be_bytes());
                    if log.wide() {
                        put_be32(block, at + 8, (home >> 32) as u32);
                    }
                }
                at += log.tag_bytes();
                if n == 0 {
                    block[at..at + 16].copy_from_slice(&log.uuid);
                    at += 16;
                }
                position = log.next(position);
                log.write(volume, device, position, data)?;
            }
            log.set_tail(block);
            log.write(volume, device, descriptor, block)?;
            position = log.next(position);
            index += count;
        }
        self.write_superblock(volume, device, log.first)?;
        device.flush()?;
        block.fill(0);
        put_be32(block, 0, MAGIC);
        put_be32(block, 4, COMMIT);
        put_be32(block, 8, sequence);
        block[0x30..0x38].copy_from_slice(&u64::from(volume.now).to_be_bytes());
        if let Some(seed) = log.seed {
            let sum = commit_checksum(seed, block);
            put_be32(block, 0x10, sum);
        }
        self.log.write(volume, device, position, block)?;
        device.flush()?;
        // Checkpoint: every block home, then the journal is empty.
        for slot in 0..transaction.len {
            transaction.load(slot, 0, data)?;
            device.write(transaction.homes[slot] * size as u64, data)?;
        }
        device.flush()?;
        self.sequence = sequence.wrapping_add(1);
        transaction.len = 0;
        // Durable before the next commit's log writes: its first flush.
        self.write_superblock(volume, device, 0)
    }

    /// Commits what is left and marks the volume clean.
    pub fn close<D: Device, S: Store, const SLOTS: usize>(
        &mut self,
        volume: &mut Volume,
        device: &mut D,
        transaction: &mut Transaction<S, SLOTS>,
    ) -> Result<(), Error> {
        self.commit(volume, device, transaction)?;
        device.flush()?;
        volume.set_needs_recovery(false);
        volume.write_superblock(device)?;
        device.flush()?;
        Ok(())
    }
}
