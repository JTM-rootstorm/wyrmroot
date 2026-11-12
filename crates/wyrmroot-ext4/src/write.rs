//! Allocation and the mutating operations. Each public operation writes
//! data before the metadata that points at it, and the superblock's free
//! counts last.

use crate::dir::{TYPE_DIRECTORY, TYPE_FILE};
use crate::extent::empty_root;
use crate::{
    BG_BLOCK_UNINIT, BG_INODE_UNINIT, Device, EXT4_EXTENTS_FL, Error, Inode, Kind, MAX_BLOCK_BYTES,
    MAX_INODE_BYTES, RO_COMPAT_DIR_NLINK, RO_COMPAT_LARGE_FILE, S_IFDIR, S_IFREG,
    SUPERBLOCK_OFFSET, Stat, Volume, crc, get32, put16, put32, valid_name,
};

/// A directory's link count past which it records 1 ("many").
const MAX_DIR_LINKS: u16 = 65000;
const NEW_EXTRA_ISIZE: u16 = 32;

fn bit(bitmap: &[u8], index: u32) -> bool {
    bitmap[(index / 8) as usize] & (1 << (index % 8)) != 0
}

fn set_bit(bitmap: &mut [u8], index: u32, value: bool) {
    let byte = &mut bitmap[(index / 8) as usize];
    if value {
        *byte |= 1 << (index % 8);
    } else {
        *byte &= !(1 << (index % 8));
    }
}

impl Volume {
    fn require_writable(&self) -> Result<(), Error> {
        if self.writable {
            Ok(())
        } else {
            Err(Error::ReadOnly)
        }
    }

    fn set_free_blocks(&mut self, value: u64) {
        put32(&mut self.sb, 0xC, value as u32);
        if self.wide {
            put32(&mut self.sb, 0x158, (value >> 32) as u32);
        }
    }

    fn free_inodes(&self) -> u32 {
        get32(&self.sb, 0x10)
    }

    /// Writes the superblock (free counts, write time) with its checksum.
    pub(crate) fn write_superblock<D: Device>(&mut self, device: &mut D) -> Result<(), Error> {
        put32(&mut self.sb, 0x30, self.now);
        if self.csum.is_some() {
            let sum = crc::update(!0, &self.sb[..0x3FC]);
            put32(&mut self.sb, 0x3FC, sum);
        }
        device.write(SUPERBLOCK_OFFSET, &self.sb)?;
        Ok(())
    }

    /// Allocates one block, preferring `goal` and the blocks after it. A
    /// block freed since the last commit stays taken until it commits
    /// ([`Device::read_committed`]): reused for data before then, a crash
    /// would show it in the file that still owns it.
    pub(crate) fn alloc_block<D: Device>(
        &mut self,
        device: &mut D,
        goal: u64,
    ) -> Result<u64, Error> {
        let goal = if goal < u64::from(self.first_data_block) || goal >= self.blocks {
            u64::from(self.first_data_block)
        } else {
            goal
        };
        let start =
            ((goal - u64::from(self.first_data_block)) / u64::from(self.blocks_per_group)) as u32;
        let mut bitmap = [0u8; MAX_BLOCK_BYTES];
        let bitmap = &mut bitmap[..self.bs()];
        let mut committed = [0u8; MAX_BLOCK_BYTES];
        let committed = &mut committed[..self.bs()];
        for step in 0..self.groups {
            let number = (start + step) % self.groups;
            let mut group = self.group(device, number)?;
            let free = self.free_blocks_in(&group);
            if free == 0 || group.flags() & BG_BLOCK_UNINIT != 0 {
                continue;
            }
            let location = self.block_bitmap(&group);
            self.read_block(device, location, bitmap)?;
            let bytes = (self.blocks_per_group / 8) as usize;
            if !self.bitmap_checksum_matches(&group, true, &bitmap[..bytes]) {
                return Err(Error::Corrupt);
            }
            let count = self.blocks_in_group(number);
            let from = if step == 0 {
                (goal - self.group_first_block(number)) as u32
            } else {
                0
            };
            if !(0..count).any(|index| !bit(bitmap, index)) {
                // The descriptor said there was room.
                return Err(Error::Corrupt);
            }
            device.read_committed(location * u64::from(self.block_size), committed)?;
            let found = (from..count)
                .chain(0..from)
                .find(|&index| !bit(bitmap, index) && !bit(committed, index));
            let Some(index) = found else {
                continue;
            };
            set_bit(bitmap, index, true);
            self.set_bitmap_checksum(&mut group, true, &bitmap[..bytes]);
            self.write_block(device, location, bitmap)?;
            self.set_free_blocks_in(&mut group, free - 1);
            self.write_group(device, &mut group)?;
            let total = self.free_blocks();
            self.set_free_blocks(total.saturating_sub(1));
            return Ok(self.group_first_block(number) + u64::from(index));
        }
        Err(Error::NoSpace)
    }

    /// Frees `count` blocks from `first`; every one must be in use.
    pub(crate) fn free_blocks_range<D: Device>(
        &mut self,
        device: &mut D,
        first: u64,
        count: u32,
    ) -> Result<(), Error> {
        let mut bitmap = [0u8; MAX_BLOCK_BYTES];
        let bitmap = &mut bitmap[..self.bs()];
        let mut block = first;
        let end = first.checked_add(u64::from(count)).ok_or(Error::Corrupt)?;
        if first < u64::from(self.first_data_block) || end > self.blocks {
            return Err(Error::Corrupt);
        }
        while block < end {
            let number = ((block - u64::from(self.first_data_block))
                / u64::from(self.blocks_per_group)) as u32;
            let base = self.group_first_block(number);
            let stop = end.min(base + u64::from(self.blocks_in_group(number)));
            let mut group = self.group(device, number)?;
            if group.flags() & BG_BLOCK_UNINIT != 0 {
                return Err(Error::Corrupt);
            }
            let location = self.block_bitmap(&group);
            self.read_block(device, location, bitmap)?;
            let bytes = (self.blocks_per_group / 8) as usize;
            if !self.bitmap_checksum_matches(&group, true, &bitmap[..bytes]) {
                return Err(Error::Corrupt);
            }
            let freed = (stop - block) as u32;
            for at in block..stop {
                let index = (at - base) as u32;
                if !bit(bitmap, index) {
                    return Err(Error::Corrupt);
                }
                set_bit(bitmap, index, false);
            }
            self.set_bitmap_checksum(&mut group, true, &bitmap[..bytes]);
            self.write_block(device, location, bitmap)?;
            let free = self.free_blocks_in(&group) + freed;
            self.set_free_blocks_in(&mut group, free);
            self.write_group(device, &mut group)?;
            let total = self.free_blocks();
            self.set_free_blocks(total + u64::from(freed));
            block = stop;
        }
        Ok(())
    }

    /// Allocates an inode, preferring group `near`.
    fn alloc_inode<D: Device>(
        &mut self,
        device: &mut D,
        near: u32,
        directory: bool,
    ) -> Result<u32, Error> {
        let mut bitmap = [0u8; MAX_BLOCK_BYTES];
        let bitmap = &mut bitmap[..self.bs()];
        let bytes = (self.inodes_per_group / 8) as usize;
        for step in 0..self.groups {
            let number = (near + step) % self.groups;
            let mut group = self.group(device, number)?;
            let free = self.free_inodes_in(&group);
            if free == 0 || group.flags() & BG_INODE_UNINIT != 0 {
                continue;
            }
            let location = self.inode_bitmap(&group);
            self.read_block(device, location, bitmap)?;
            if !self.bitmap_checksum_matches(&group, false, &bitmap[..bytes]) {
                return Err(Error::Corrupt);
            }
            let base = number * self.inodes_per_group;
            let from = (self.first_inode - 1)
                .saturating_sub(base)
                .min(self.inodes_per_group);
            let Some(index) = (from..self.inodes_per_group).find(|&index| !bit(bitmap, index))
            else {
                continue;
            };
            set_bit(bitmap, index, true);
            self.set_bitmap_checksum(&mut group, false, &bitmap[..bytes]);
            self.write_block(device, location, bitmap)?;
            self.set_free_inodes_in(&mut group, free - 1);
            if directory {
                let dirs = self.used_dirs_in(&group);
                self.set_used_dirs_in(&mut group, dirs + 1);
            }
            if self.csum.is_some() {
                let unused = self.itable_unused_in(&group);
                if index >= self.inodes_per_group - unused.min(self.inodes_per_group) {
                    self.set_itable_unused_in(&mut group, self.inodes_per_group - index - 1);
                }
            }
            self.write_group(device, &mut group)?;
            let total = self.free_inodes();
            put32(&mut self.sb, 0x10, total.saturating_sub(1));
            return Ok(base + index + 1);
        }
        Err(Error::NoSpace)
    }

    fn free_inode<D: Device>(
        &mut self,
        device: &mut D,
        number: u32,
        directory: bool,
    ) -> Result<(), Error> {
        let mut bitmap = [0u8; MAX_BLOCK_BYTES];
        let bitmap = &mut bitmap[..self.bs()];
        let bytes = (self.inodes_per_group / 8) as usize;
        let group_number = (number - 1) / self.inodes_per_group;
        let index = (number - 1) % self.inodes_per_group;
        let mut group = self.group(device, group_number)?;
        let location = self.inode_bitmap(&group);
        self.read_block(device, location, bitmap)?;
        if !self.bitmap_checksum_matches(&group, false, &bitmap[..bytes]) || !bit(bitmap, index) {
            return Err(Error::Corrupt);
        }
        set_bit(bitmap, index, false);
        self.set_bitmap_checksum(&mut group, false, &bitmap[..bytes]);
        self.write_block(device, location, bitmap)?;
        let free = self.free_inodes_in(&group);
        self.set_free_inodes_in(&mut group, free + 1);
        if directory {
            let dirs = self.used_dirs_in(&group);
            self.set_used_dirs_in(&mut group, dirs.saturating_sub(1));
        }
        self.write_group(device, &mut group)?;
        let total = self.free_inodes();
        put32(&mut self.sb, 0x10, total + 1);
        Ok(())
    }

    fn writable_node<D: Device>(
        &self,
        device: &mut D,
        number: u32,
        kind: Kind,
    ) -> Result<Inode, Error> {
        self.require_writable()?;
        let (inode, found) = self.live(device, number)?;
        match (kind, found) {
            (Kind::File, Kind::Directory) => Err(Error::IsDirectory),
            (Kind::Directory, Kind::File) => Err(Error::NotDirectory),
            _ => Ok(inode),
        }
    }

    /// The largest file size the volume stores.
    fn max_size(&self) -> u64 {
        let by_blocks = u64::from(u32::MAX) * u64::from(self.block_size);
        if self.has_ro_compat(RO_COMPAT_LARGE_FILE) {
            by_blocks
        } else {
            by_blocks.min((1 << 31) - 1)
        }
    }

    /// Writes `data` to file `inode` at `offset`, allocating as needed.
    /// Returns how much was written; a failure after the first block is a
    /// short write.
    pub fn write<D: Device>(
        &mut self,
        device: &mut D,
        inode: u32,
        offset: u64,
        data: &[u8],
    ) -> Result<usize, Error> {
        let mut node = self.writable_node(device, inode, Kind::File)?;
        if data.is_empty() {
            return Ok(0);
        }
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(Error::TooLarge)?;
        if end > self.max_size() {
            return Err(Error::TooLarge);
        }
        let bs = u64::from(self.block_size);
        let mut block = [0u8; MAX_BLOCK_BYTES];
        let block = &mut block[..self.bs()];
        let mut done = 0usize;
        let mut failure = None;
        let mut goal = 0u64;
        while done < data.len() {
            let at = offset + done as u64;
            let logical = (at / bs) as u32;
            let within = (at % bs) as usize;
            let take = (self.bs() - within).min(data.len() - done);
            let step = (|| -> Result<(), Error> {
                match self.map(device, &node, logical)? {
                    Some(mapped) if mapped.uninit => Err(Error::Unsupported),
                    Some(mapped) => {
                        if take != self.bs() {
                            self.read_block(device, mapped.physical, block)?;
                        }
                        block[within..within + take].copy_from_slice(&data[done..done + take]);
                        goal = mapped.physical + 1;
                        self.write_data_block(device, mapped.physical, block)
                    }
                    None => {
                        if goal == 0 && logical > 0 {
                            goal = self
                                .map(device, &node, logical - 1)?
                                .map_or(0, |mapped| mapped.physical + 1);
                        }
                        if goal == 0 {
                            let group = (node.number - 1) / self.inodes_per_group;
                            goal = self.group_first_block(group);
                        }
                        let physical = self.alloc_block(device, goal)?;
                        block.fill(0);
                        block[within..within + take].copy_from_slice(&data[done..done + take]);
                        if let Err(error) = self
                            .write_data_block(device, physical, block)
                            .and_then(|()| self.map_insert(device, &mut node, logical, physical))
                        {
                            let _ = self.free_blocks_range(device, physical, 1);
                            return Err(error);
                        }
                        self.charge(&mut node, 1, true);
                        goal = physical + 1;
                        Ok(())
                    }
                }
            })();
            if let Err(error) = step {
                failure = Some(error);
                break;
            }
            done += take;
        }
        let written_end = offset + done as u64;
        if written_end > node.size() {
            node.set_size(written_end);
        }
        node.set_times(self.now, true, true);
        self.write_inode(device, &mut node)?;
        self.write_superblock(device)?;
        match failure {
            Some(error) if done == 0 => Err(error),
            _ => Ok(done),
        }
    }

    /// Sets file `inode`'s size, freeing blocks past it.
    pub fn truncate<D: Device>(
        &mut self,
        device: &mut D,
        inode: u32,
        size: u64,
    ) -> Result<(), Error> {
        let mut node = self.writable_node(device, inode, Kind::File)?;
        if size > self.max_size() {
            return Err(Error::TooLarge);
        }
        self.truncate_node(device, &mut node, size)?;
        node.set_times(self.now, true, true);
        self.write_inode(device, &mut node)?;
        self.write_superblock(device)
    }

    fn truncate_node<D: Device>(
        &mut self,
        device: &mut D,
        node: &mut Inode,
        size: u64,
    ) -> Result<(), Error> {
        let bs = u64::from(self.block_size);
        if size < node.size() {
            let keep = u32::try_from(size.div_ceil(bs)).map_err(|_| Error::TooLarge)?;
            self.map_truncate(device, node, keep)?;
            // Bytes past the new end of the last block must read as zeros if
            // the file grows again.
            let within = (size % bs) as usize;
            if within != 0
                && let Some(mapped) = self.map(device, node, keep - 1)?
                && !mapped.uninit
            {
                let mut block = [0u8; MAX_BLOCK_BYTES];
                let block = &mut block[..self.bs()];
                self.read_block(device, mapped.physical, block)?;
                block[within..].fill(0);
                self.write_data_block(device, mapped.physical, block)?;
            }
        }
        node.set_size(size);
        Ok(())
    }

    /// Creates `name` in directory `dir` as an empty file or directory.
    pub fn create<D: Device>(
        &mut self,
        device: &mut D,
        dir: u32,
        name: &[u8],
        kind: Kind,
    ) -> Result<Stat, Error> {
        let mut parent = self.writable_node(device, dir, Kind::Directory)?;
        if !valid_name(name) {
            return Err(Error::InvalidName);
        }
        if self.find_entry(device, &parent, name)?.is_some() {
            return Err(Error::Exists);
        }
        let directory = kind == Kind::Directory;
        let parent_links = if directory {
            let links = parent.links();
            let nlink = self.has_ro_compat(RO_COMPAT_DIR_NLINK);
            if links == 1 || (links + 1 >= MAX_DIR_LINKS && nlink) {
                1
            } else if links + 1 >= MAX_DIR_LINKS {
                return Err(Error::NoSpace);
            } else {
                links + 1
            }
        } else {
            parent.links()
        };
        let near = (dir - 1) / self.inodes_per_group;
        let number = self.alloc_inode(device, near, directory)?;
        let mut node = Inode {
            number,
            raw: [0; MAX_INODE_BYTES],
        };
        let mode = if directory {
            S_IFDIR | 0o755
        } else {
            S_IFREG | 0o644
        };
        put16(&mut node.raw, 0x0, mode);
        put32(&mut node.raw, 0x8, self.now);
        node.set_times(self.now, true, true);
        node.set_links(if directory { 2 } else { 1 });
        node.set_flags(EXT4_EXTENTS_FL);
        empty_root(node.root_mut());
        if self.inode_size > 128 {
            put16(&mut node.raw, 0x80, NEW_EXTRA_ISIZE);
            put32(&mut node.raw, 0x90, self.now);
        }
        let result = (|| -> Result<(), Error> {
            if directory {
                let goal = self.group_first_block(near);
                let physical = self.alloc_block(device, goal)?;
                let mut block = [0u8; MAX_BLOCK_BYTES];
                let block = &mut block[..self.bs()];
                self.init_dir_block(block, number, dir);
                self.write_new_dir_block(device, &node, physical, block)?;
                self.map_insert(device, &mut node, 0, physical)?;
                self.charge(&mut node, 1, true);
                node.set_size(u64::from(self.block_size));
            }
            self.write_inode(device, &mut node)?;
            self.add_entry(
                device,
                &mut parent,
                name,
                number,
                if directory { TYPE_DIRECTORY } else { TYPE_FILE },
            )?;
            parent.set_links(parent_links);
            parent.set_times(self.now, true, true);
            self.write_inode(device, &mut parent)
        })();
        if let Err(error) = result {
            // Give back what was taken; the entry was the last step.
            let _ = self.map_truncate(device, &mut node, 0);
            let _ = self.free_inode(device, number, directory);
            let _ = self.write_superblock(device);
            return Err(error);
        }
        self.write_superblock(device)?;
        Ok(Stat {
            inode: number,
            kind,
            size: node.size(),
        })
    }

    /// Removes `name` from directory `dir`; a directory must be empty. The
    /// node's blocks and inode are freed with its last name.
    pub fn unlink<D: Device>(
        &mut self,
        device: &mut D,
        dir: u32,
        name: &[u8],
    ) -> Result<(), Error> {
        let mut parent = self.writable_node(device, dir, Kind::Directory)?;
        if !valid_name(name) {
            return Err(Error::InvalidName);
        }
        let found = self
            .find_entry(device, &parent, name)?
            .ok_or(Error::NotFound)?;
        let (mut node, kind) = self.live(device, found.inode)?;
        let directory = kind == Kind::Directory;
        if directory && !self.dir_is_empty(device, &node)? {
            return Err(Error::NotEmpty);
        }
        self.remove_entry(device, &parent, found)?;
        if directory {
            let links = parent.links();
            if links > 2 {
                parent.set_links(links - 1);
            }
            node.set_links(0);
        } else {
            node.set_links(node.links().saturating_sub(1));
        }
        parent.set_times(self.now, true, true);
        self.write_inode(device, &mut parent)?;
        if node.links() == 0 {
            self.truncate_node(device, &mut node, 0)?;
            put32(&mut node.raw, 0x14, self.now.max(1));
            node.set_times(self.now, true, false);
            self.write_inode(device, &mut node)?;
            self.free_inode(device, node.number, directory)?;
        } else {
            node.set_times(self.now, true, false);
            self.write_inode(device, &mut node)?;
        }
        self.write_superblock(device)
    }
}
