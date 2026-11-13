//! A formatter for the one feature set this implementation writes:
//! `filetype`, `extents` and `64bit` (incompatible), `sparse_super`,
//! `large_file`, `dir_nlink`, `extra_isize` and `metadata_csum`
//! (read-only compatible), and optionally a journal (`has_journal`, in inode
//! 8, contiguous in group 0, with v3 checksums and 64-bit tags). Every
//! group's bitmaps and inode table live in the group and are written in full,
//! so no group is uninitialised. The root holds `lost+found`.

use crate::dir::TYPE_DIRECTORY;
use crate::journal::{COMPAT_HAS_JOURNAL, JOURNAL_INODE};
use crate::{
    Device, Error, INCOMPAT_64BIT, INCOMPAT_EXTENTS, INCOMPAT_FILETYPE, MAGIC, MAX_BLOCK_BYTES,
    RO_COMPAT_DIR_NLINK, RO_COMPAT_EXTRA_ISIZE, RO_COMPAT_LARGE_FILE, RO_COMPAT_METADATA_CSUM,
    RO_COMPAT_SPARSE_SUPER, ROOT_INODE, SUPERBLOCK_BYTES, SUPERBLOCK_OFFSET, Volume, crc, put16,
    put32,
};

const INODE_BYTES: u32 = 256;
const BYTES_PER_INODE: u64 = 16384;
const FIRST_INODE: u32 = 11;
const LOST_FOUND: u32 = 11;
const DESC_BYTES: u32 = 64;
/// The smallest volume formatted.
pub const MIN_BYTES: u64 = 1 << 20;

/// What [`format`] is told.
#[derive(Clone, Copy, Debug)]
pub struct FormatParams {
    /// 1024, 2048 or 4096.
    pub block_size: u32,
    pub uuid: [u8; 16],
    /// NUL-padded.
    pub label: [u8; 16],
    /// Seconds since the epoch, stamped on everything created.
    pub time: u32,
    /// The journal's length in blocks, 0 for none. It must fit in group 0
    /// and be at least [`MIN_JOURNAL_BLOCKS`].
    pub journal_blocks: u32,
}

/// The shortest journal formatted.
pub const MIN_JOURNAL_BLOCKS: u32 = 1024;

struct Layout {
    bs: u32,
    blocks: u64,
    first_data_block: u32,
    blocks_per_group: u32,
    groups: u32,
    inodes_per_group: u32,
    table_blocks: u32,
    gdt_blocks: u32,
}

/// Whether group `number` holds a superblock backup (`sparse_super`:
/// 0, 1 and powers of 3, 5 and 7).
pub(crate) fn has_backup(number: u32) -> bool {
    if number <= 1 {
        return true;
    }
    [3u32, 5, 7].iter().any(|&base| {
        let mut power = base;
        while power < number {
            match power.checked_mul(base) {
                Some(next) => power = next,
                None => return false,
            }
        }
        power == number
    })
}

impl Layout {
    fn new(bytes: u64, bs: u32) -> Result<Self, Error> {
        if !matches!(bs, 1024 | 2048 | 4096) || bytes < MIN_BYTES {
            return Err(Error::Unsupported);
        }
        let first_data_block = u32::from(bs == 1024);
        let blocks_per_group = bs * 8;
        let mut blocks = (bytes / u64::from(bs)).min(u64::from(u32::MAX));
        let per_table_block = bs / INODE_BYTES;
        loop {
            let groups = u32::try_from(
                (blocks - u64::from(first_data_block)).div_ceil(u64::from(blocks_per_group)),
            )
            .map_err(|_| Error::Unsupported)?;
            let inodes = (blocks * u64::from(bs) / BYTES_PER_INODE).max(u64::from(FIRST_INODE) + 5);
            let mut per_group = u32::try_from(inodes.div_ceil(u64::from(groups)))
                .map_err(|_| Error::Unsupported)?;
            let unit = per_table_block.max(8);
            per_group = per_group.div_ceil(unit) * unit;
            per_group = per_group.min(bs * 8);
            let table_blocks = per_group * INODE_BYTES / bs;
            let gdt_blocks = (groups * DESC_BYTES).div_ceil(bs);
            let last = groups - 1;
            let last_blocks = blocks
                - u64::from(first_data_block)
                - u64::from(last) * u64::from(blocks_per_group);
            let overhead =
                u64::from(if has_backup(last) { 1 + gdt_blocks } else { 0 } + 2 + table_blocks);
            if last_blocks < overhead + 16 {
                if groups == 1 {
                    return Err(Error::Unsupported);
                }
                blocks -= last_blocks;
                continue;
            }
            return Ok(Self {
                bs,
                blocks,
                first_data_block,
                blocks_per_group,
                groups,
                inodes_per_group: per_group,
                table_blocks,
                gdt_blocks,
            });
        }
    }

    fn group_start(&self, number: u32) -> u64 {
        u64::from(self.first_data_block) + u64::from(number) * u64::from(self.blocks_per_group)
    }

    fn group_blocks(&self, number: u32) -> u32 {
        (self.blocks - self.group_start(number)).min(u64::from(self.blocks_per_group)) as u32
    }

    /// (block bitmap, inode bitmap, inode table) of a group.
    fn metadata(&self, number: u32) -> (u64, u64, u64) {
        let start = self.group_start(number);
        let skip = if has_backup(number) {
            1 + u64::from(self.gdt_blocks)
        } else {
            0
        };
        (start + skip, start + skip + 1, start + skip + 2)
    }

    /// Blocks at the start of a group used by metadata.
    fn overhead(&self, number: u32) -> u32 {
        let (_, _, table) = self.metadata(number);
        (table - self.group_start(number)) as u32 + self.table_blocks
    }
}

fn write_at<D: Device>(
    device: &mut D,
    layout: &Layout,
    block: u64,
    data: &[u8],
) -> Result<(), Error> {
    device.write(block * u64::from(layout.bs), data)?;
    Ok(())
}

/// Formats `device`, `bytes` long, as an empty ext4 volume.
pub fn format<D: Device>(device: &mut D, bytes: u64, params: &FormatParams) -> Result<(), Error> {
    let layout = Layout::new(bytes, params.block_size)?;
    let bs = layout.bs as usize;
    let mut block = [0u8; MAX_BLOCK_BYTES];
    let block = &mut block[..bs];

    // Inode tables, zeroed.
    block.fill(0);
    for number in 0..layout.groups {
        let (_, _, table) = layout.metadata(number);
        for index in 0..u64::from(layout.table_blocks) {
            write_at(device, &layout, table + index, block)?;
        }
    }

    // The root and lost+found take one block each, right after group 0's
    // metadata.
    let root_block = layout.group_start(0) + u64::from(layout.overhead(0));
    let lost_block = root_block + 1;
    let journal_block = lost_block + 1;
    let journal_blocks = params.journal_blocks;
    if journal_blocks != 0
        && (!(MIN_JOURNAL_BLOCKS..=32768).contains(&journal_blocks)
            || journal_block + u64::from(journal_blocks) + 16
                > layout.group_start(0) + u64::from(layout.group_blocks(0)))
    {
        return Err(Error::Unsupported);
    }
    let used_inodes = FIRST_INODE;

    let mut sb = [0u8; SUPERBLOCK_BYTES];
    let inodes = layout.groups * layout.inodes_per_group;
    let mut free_blocks = 0u64;
    for number in 0..layout.groups {
        free_blocks += u64::from(layout.group_blocks(number) - layout.overhead(number));
    }
    free_blocks -= 2 + u64::from(journal_blocks);
    put32(&mut sb, 0x0, inodes);
    put32(&mut sb, 0x4, layout.blocks as u32);
    put32(&mut sb, 0xC, free_blocks as u32);
    put32(&mut sb, 0x10, inodes - used_inodes);
    put32(&mut sb, 0x14, layout.first_data_block);
    let log = layout.bs.trailing_zeros() - 10;
    put32(&mut sb, 0x18, log);
    put32(&mut sb, 0x1C, log);
    put32(&mut sb, 0x20, layout.blocks_per_group);
    put32(&mut sb, 0x24, layout.blocks_per_group);
    put32(&mut sb, 0x28, layout.inodes_per_group);
    put32(&mut sb, 0x30, params.time);
    put16(&mut sb, 0x36, 0xFFFF);
    put16(&mut sb, 0x38, MAGIC);
    put16(&mut sb, 0x3A, 1);
    put16(&mut sb, 0x3C, 1);
    put32(&mut sb, 0x40, params.time);
    put32(&mut sb, 0x4C, 1);
    put32(&mut sb, 0x54, FIRST_INODE);
    put16(&mut sb, 0x58, INODE_BYTES as u16);
    put32(
        &mut sb,
        0x60,
        INCOMPAT_FILETYPE | INCOMPAT_EXTENTS | INCOMPAT_64BIT,
    );
    put32(
        &mut sb,
        0x64,
        RO_COMPAT_SPARSE_SUPER
            | RO_COMPAT_LARGE_FILE
            | RO_COMPAT_DIR_NLINK
            | RO_COMPAT_EXTRA_ISIZE
            | RO_COMPAT_METADATA_CSUM,
    );
    sb[0x68..0x78].copy_from_slice(&params.uuid);
    sb[0x78..0x88].copy_from_slice(&params.label);
    put16(&mut sb, 0xFE, DESC_BYTES as u16);
    put32(&mut sb, 0x108, params.time);
    put32(&mut sb, 0x150, (layout.blocks >> 32) as u32);
    put32(&mut sb, 0x158, (free_blocks >> 32) as u32);
    put16(&mut sb, 0x15C, 32);
    put16(&mut sb, 0x15E, 32);
    sb[0x175] = 1;
    put32(&mut sb, 0x268, LOST_FOUND);
    let journal_inode = (journal_blocks != 0).then(|| {
        let inode = journal_inode(journal_block, journal_blocks, layout.bs, params.time);
        put32(&mut sb, 0x5C, COMPAT_HAS_JOURNAL);
        put32(&mut sb, 0xE0, JOURNAL_INODE);
        // s_jnl_blocks: i_block, then i_size_high and i_size.
        sb[0xFD] = 1;
        sb[0x10C..0x10C + 60].copy_from_slice(inode.root());
        put32(&mut sb, 0x10C + 60, (inode.size() >> 32) as u32);
        put32(&mut sb, 0x10C + 64, inode.size() as u32);
        inode
    });
    let seed = crc::update(!0, &params.uuid);

    // Bitmaps and descriptors.
    let mut table = [0u8; MAX_BLOCK_BYTES];
    let mut gdt_block_index = u64::MAX;
    for number in 0..layout.groups {
        let (block_bitmap, inode_bitmap, inode_table) = layout.metadata(number);
        let mut used = layout.overhead(number);
        if number == 0 {
            // Block 0 at 1 KiB (the boot block) is outside the groups; the
            // root and lost+found blocks follow the metadata, then the
            // journal.
            used += 2 + journal_blocks;
        }
        let count = layout.group_blocks(number);
        block.fill(0);
        for index in 0..layout.blocks_per_group {
            if index < used || index >= count {
                block[(index / 8) as usize] |= 1 << (index % 8);
            }
        }
        // Bits past the group (a short last group) and the bitmap's
        // padding are set, as e2fsck expects.
        for index in layout.blocks_per_group..(bs as u32 * 8) {
            block[(index / 8) as usize] |= 1 << (index % 8);
        }
        let block_sum = crc::update(seed, &block[..(layout.blocks_per_group / 8) as usize]);
        write_at(device, &layout, block_bitmap, block)?;

        block.fill(0);
        let inodes_used = if number == 0 { used_inodes } else { 0 };
        for index in 0..(bs as u32 * 8) {
            if index < inodes_used || index >= layout.inodes_per_group {
                block[(index / 8) as usize] |= 1 << (index % 8);
            }
        }
        let inode_sum = crc::update(seed, &block[..(layout.inodes_per_group / 8) as usize]);
        write_at(device, &layout, inode_bitmap, block)?;

        let mut desc = [0u8; DESC_BYTES as usize];
        put32(&mut desc, 0x0, block_bitmap as u32);
        put32(&mut desc, 0x4, inode_bitmap as u32);
        put32(&mut desc, 0x8, inode_table as u32);
        let free = count - used;
        put16(&mut desc, 0xC, free as u16);
        let free_inodes = layout.inodes_per_group - inodes_used;
        put16(&mut desc, 0xE, free_inodes as u16);
        put16(&mut desc, 0x10, if number == 0 { 2 } else { 0 });
        // EXT4_BG_INODE_ZEROED: the table was written above.
        put16(&mut desc, 0x12, 0x4);
        put16(&mut desc, 0x18, block_sum as u16);
        put16(&mut desc, 0x1A, inode_sum as u16);
        put32(&mut desc, 0x20, (block_bitmap >> 32) as u32);
        put32(&mut desc, 0x24, (inode_bitmap >> 32) as u32);
        put32(&mut desc, 0x28, (inode_table >> 32) as u32);
        put16(&mut desc, 0x2C, (free >> 16) as u16);
        put16(&mut desc, 0x2E, (free_inodes >> 16) as u16);
        put16(&mut desc, 0x38, (block_sum >> 16) as u16);
        put16(&mut desc, 0x3A, (inode_sum >> 16) as u16);
        let sum = Volume::group_checksum(seed, number, &desc);
        put16(&mut desc, 0x1E, sum);
        // Collect descriptors one table block at a time.
        let offset = number as usize * DESC_BYTES as usize;
        let index = (offset / bs) as u64;
        if index != gdt_block_index {
            if gdt_block_index != u64::MAX {
                write_gdt_block(device, &layout, gdt_block_index, &table[..bs])?;
            }
            table[..bs].fill(0);
            gdt_block_index = index;
        }
        table[offset % bs..offset % bs + DESC_BYTES as usize].copy_from_slice(&desc);
    }
    write_gdt_block(device, &layout, gdt_block_index, &table[..bs])?;

    // Superblock copies, each naming its group.
    for number in (0..layout.groups).filter(|&number| has_backup(number)) {
        put16(&mut sb, 0x5A, number as u16);
        let sum = crc::update(!0, &sb[..0x3FC]);
        put32(&mut sb, 0x3FC, sum);
        if number == 0 {
            device.write(SUPERBLOCK_OFFSET, &sb)?;
        } else {
            block.fill(0);
            block[..SUPERBLOCK_BYTES].copy_from_slice(&sb);
            write_at(device, &layout, layout.group_start(number), block)?;
        }
    }
    put16(&mut sb, 0x5A, 0);
    let sum = crc::update(!0, &sb[..0x3FC]);
    put32(&mut sb, 0x3FC, sum);

    // The two directories, through the volume's own inode and directory code.
    let volume = Volume::fresh(sb, &layout);
    volume.write_fresh_dir(
        device,
        ROOT_INODE,
        ROOT_INODE,
        root_block,
        3,
        Some(LOST_FOUND),
        params.time,
    )?;
    volume.write_fresh_dir(
        device,
        LOST_FOUND,
        ROOT_INODE,
        lost_block,
        2,
        None,
        params.time,
    )?;
    if let Some(mut inode) = journal_inode {
        volume.write_inode(device, &mut inode)?;
        write_journal(device, &layout, journal_block, journal_blocks, &params.uuid)?;
    }
    device.flush()?;
    Ok(())
}

/// The journal inode: a regular file of `blocks` blocks from `first`.
fn journal_inode(first: u64, blocks: u32, bs: u32, time: u32) -> crate::Inode {
    let mut node = crate::Inode {
        number: JOURNAL_INODE,
        raw: [0; crate::MAX_INODE_BYTES],
    };
    put16(&mut node.raw, 0x0, crate::S_IFREG | 0o600);
    for at in [0x8, 0xC, 0x10, 0x90] {
        put32(&mut node.raw, at, time);
    }
    node.set_links(1);
    node.set_flags(crate::EXT4_EXTENTS_FL);
    put16(&mut node.raw, 0x80, 32);
    let root = node.root_mut();
    crate::extent::empty_root(root);
    put16(root, 2, 1);
    put32(root, 12, 0);
    put16(root, 16, blocks as u16);
    put16(root, 18, (first >> 32) as u16);
    put32(root, 20, first as u32);
    node.set_size(u64::from(blocks) * u64::from(bs));
    node.set_sectors(u64::from(blocks) * u64::from(bs / 512));
    node
}

/// Zeroes the journal and writes its superblock: empty, sequence 1.
fn write_journal<D: Device>(
    device: &mut D,
    layout: &Layout,
    first: u64,
    blocks: u32,
    uuid: &[u8; 16],
) -> Result<(), Error> {
    let mut block = [0u8; MAX_BLOCK_BYTES];
    let block = &mut block[..layout.bs as usize];
    for index in 1..u64::from(blocks) {
        write_at(device, layout, first + index, block)?;
    }
    crate::journal::empty_superblock(block, layout.bs, blocks, uuid);
    write_at(device, layout, first, block)
}

fn write_gdt_block<D: Device>(
    device: &mut D,
    layout: &Layout,
    index: u64,
    data: &[u8],
) -> Result<(), Error> {
    for number in (0..layout.groups).filter(|&number| has_backup(number)) {
        let at = layout.group_start(number) + 1 + index;
        write_at(device, layout, at, data)?;
    }
    Ok(())
}

impl Volume {
    /// The volume being formatted, before its root exists to mount.
    fn fresh(sb: [u8; SUPERBLOCK_BYTES], layout: &Layout) -> Self {
        Self {
            sb,
            block_size: layout.bs,
            blocks: layout.blocks,
            first_data_block: layout.first_data_block,
            blocks_per_group: layout.blocks_per_group,
            inodes_per_group: layout.inodes_per_group,
            inodes: layout.groups * layout.inodes_per_group,
            first_inode: FIRST_INODE,
            inode_size: INODE_BYTES as usize,
            desc_size: DESC_BYTES as usize,
            groups: layout.groups,
            wide: true,
            csum: Some(crc::update(!0, &sb[0x68..0x78])),
            writable: true,
            now: crate::get32(&sb, 0x30),
            held: [0; crate::MAX_HELD],
            held_len: 0,
            orphans_pending: false,
            free_room: usize::MAX,
        }
    }

    /// Writes directory inode `number` with one block at `physical` holding
    /// `.`, `..` and optionally `lost+found`.
    #[allow(clippy::too_many_arguments)]
    fn write_fresh_dir<D: Device>(
        &self,
        device: &mut D,
        number: u32,
        parent: u32,
        physical: u64,
        links: u16,
        child: Option<u32>,
        time: u32,
    ) -> Result<(), Error> {
        let mut node = crate::Inode {
            number,
            raw: [0; crate::MAX_INODE_BYTES],
        };
        let mode = crate::S_IFDIR | if child.is_some() { 0o755 } else { 0o700 };
        put16(&mut node.raw, 0x0, mode);
        for at in [0x8, 0xC, 0x10, 0x90] {
            put32(&mut node.raw, at, time);
        }
        node.set_links(links);
        node.set_flags(crate::EXT4_EXTENTS_FL);
        put16(&mut node.raw, 0x80, 32);
        let root = node.root_mut();
        crate::extent::empty_root(root);
        // One extent: logical 0, one block.
        put16(root, 2, 1);
        put32(root, 12, 0);
        put16(root, 16, 1);
        put16(root, 18, (physical >> 32) as u16);
        put32(root, 20, physical as u32);
        node.set_size(u64::from(self.block_size));
        node.set_sectors(u64::from(self.block_size / 512));
        self.write_inode(device, &mut node)?;
        let mut block = [0u8; MAX_BLOCK_BYTES];
        let block = &mut block[..self.bs()];
        self.init_dir_block(block, number, parent);
        if let Some(child) = child {
            // Shorten `..` and give the rest of the block to the child.
            let limit = crate::get16(block, 16) as usize + 12;
            put16(block, 16, 12);
            put32(block, 24, child);
            put16(block, 28, (limit - 24) as u16);
            block[30] = 10;
            block[31] = TYPE_DIRECTORY;
            block[32..42].copy_from_slice(b"lost+found");
        }
        self.write_new_dir_block(device, &node, physical, block)
    }
}

#[cfg(test)]
pub(crate) fn backup(number: u32) -> bool {
    has_backup(number)
}
