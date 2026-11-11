//! Linear directories (`directory.rst`). An htree directory reads the same
//! way, since its index blocks look like single empty entries, but is never
//! modified: adding an entry linearly would make its index lie.

use core::ops::ControlFlow;

use crate::{
    Device, EXT4_INDEX_FL, Entry, Error, Inode, Kind, MAX_BLOCK_BYTES, Volume, crc, get16, get32,
    put16, put32,
};

const TAIL: usize = 12;
const TAIL_TYPE: u8 = 0xDE;
pub(crate) const TYPE_FILE: u8 = 1;
pub(crate) const TYPE_DIRECTORY: u8 = 2;

/// Bytes an entry with a `name_len`-byte name needs.
fn needed(name_len: usize) -> usize {
    (8 + name_len + 3) & !3
}

/// One live entry's place.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Found {
    pub(crate) inode: u32,
    block: u32,
    offset: usize,
    /// The previous entry in the same block, if any.
    previous: Option<usize>,
}

struct Raw<'a> {
    offset: usize,
    inode: u32,
    rec_len: usize,
    file_type: u8,
    name: &'a [u8],
}

fn has_tail(block: &[u8]) -> bool {
    let at = block.len() - TAIL;
    get32(block, at) == 0
        && get16(block, at + 4) == TAIL as u16
        && block[at + 6] == 0
        && block[at + 7] == TAIL_TYPE
}

/// Walks the entries of one checked block up to `limit`.
fn walk<'a, T>(
    block: &'a [u8],
    limit: usize,
    mut visit: impl FnMut(Raw<'a>) -> ControlFlow<T>,
) -> Option<T> {
    let mut offset = 0;
    while offset < limit {
        let rec_len = usize::from(get16(block, offset + 4));
        let name_len = usize::from(block[offset + 6]);
        let raw = Raw {
            offset,
            inode: get32(block, offset),
            rec_len,
            file_type: block[offset + 7],
            name: &block[offset + 8..offset + 8 + name_len],
        };
        if let ControlFlow::Break(value) = visit(raw) {
            return Some(value);
        }
        offset += rec_len;
    }
    None
}

impl Volume {
    fn dir_seed(&self, seed: u32, dir: &Inode) -> u32 {
        self.inode_seed(seed, dir)
    }

    pub(crate) fn dir_block_count(&self, dir: &Inode) -> Result<u32, Error> {
        let size = dir.size();
        if !size.is_multiple_of(u64::from(self.block_size)) {
            return Err(Error::Corrupt);
        }
        u32::try_from(size / u64::from(self.block_size)).map_err(|_| Error::Corrupt)
    }

    /// Reads and checks directory block `index` of `dir` into `block`;
    /// returns where its entries end and the physical block.
    fn read_dir_block<D: Device>(
        &self,
        device: &mut D,
        dir: &Inode,
        index: u32,
        block: &mut [u8],
    ) -> Result<(usize, u64), Error> {
        let mapped = self.map(device, dir, index)?;
        let Some(mapped) = mapped.filter(|mapped| !mapped.uninit) else {
            return Err(Error::Corrupt);
        };
        self.read_block(device, mapped.physical, block)?;
        let bs = block.len();
        let tail = has_tail(block);
        if let Some(seed) = self.csum {
            if tail {
                let sum = crc::update(self.dir_seed(seed, dir), &block[..bs - TAIL]);
                if sum != get32(block, bs - 4) {
                    return Err(Error::Corrupt);
                }
            } else if dir.flags() & EXT4_INDEX_FL == 0 {
                return Err(Error::Corrupt);
            }
        }
        let limit = if tail { bs - TAIL } else { bs };
        // Every entry must fit, name included, and the walk must end at the limit.
        let mut offset = 0;
        while offset < limit {
            if offset + 8 > limit {
                return Err(Error::Corrupt);
            }
            let rec_len = usize::from(get16(block, offset + 4));
            let name_len = usize::from(block[offset + 6]);
            let inode = get32(block, offset);
            if rec_len < 8 || rec_len % 4 != 0 || offset + rec_len > limit {
                return Err(Error::Corrupt);
            }
            if inode != 0 && (name_len == 0 || 8 + name_len > rec_len || inode > self.inodes) {
                return Err(Error::Corrupt);
            }
            offset += rec_len;
        }
        Ok((limit, mapped.physical))
    }

    fn write_dir_block<D: Device>(
        &self,
        device: &mut D,
        dir: &Inode,
        physical: u64,
        block: &mut [u8],
    ) -> Result<(), Error> {
        if let Some(seed) = self.csum {
            let bs = block.len();
            let sum = crc::update(self.dir_seed(seed, dir), &block[..bs - TAIL]);
            put32(block, bs - 4, sum);
        }
        self.write_block(device, physical, block)
    }

    /// Lays out an empty directory block for `dir` holding `.` and `..`.
    pub(crate) fn init_dir_block(&self, block: &mut [u8], dir: u32, parent: u32) {
        block.fill(0);
        let limit = self.entry_limit(block.len());
        put32(block, 0, dir);
        put16(block, 4, 12);
        block[6] = 1;
        block[7] = TYPE_DIRECTORY;
        block[8] = b'.';
        put32(block, 12, parent);
        put16(block, 16, (limit - 12) as u16);
        block[18] = 2;
        block[19] = TYPE_DIRECTORY;
        block[20..22].copy_from_slice(b"..");
        self.set_tail(block);
    }

    fn entry_limit(&self, bs: usize) -> usize {
        if self.csum.is_some() { bs - TAIL } else { bs }
    }

    fn set_tail(&self, block: &mut [u8]) {
        if self.csum.is_some() {
            let at = block.len() - TAIL;
            block[at..].fill(0);
            put16(block, at + 4, TAIL as u16);
            block[at + 7] = TAIL_TYPE;
        }
    }

    /// Writes a fresh directory block (see [`Volume::init_dir_block`]).
    pub(crate) fn write_new_dir_block<D: Device>(
        &self,
        device: &mut D,
        dir: &Inode,
        physical: u64,
        block: &mut [u8],
    ) -> Result<(), Error> {
        if self.csum.is_some() {
            self.write_dir_block(device, dir, physical, block)
        } else {
            self.write_block(device, physical, block)
        }
    }

    pub(crate) fn list<D: Device, F: FnMut(Entry<'_>) -> bool>(
        &self,
        device: &mut D,
        dir: &Inode,
        cookie: u64,
        mut entry: F,
    ) -> Result<Option<u64>, Error> {
        let blocks = self.dir_block_count(dir)?;
        let bs = u64::from(self.block_size);
        let first = u32::try_from(cookie / bs).map_err(|_| Error::NotFound)?;
        let mut block = [0u8; MAX_BLOCK_BYTES];
        let block = &mut block[..self.bs()];
        for index in first..blocks {
            let (limit, _) = self.read_dir_block(device, dir, index, block)?;
            let base = u64::from(index) * bs;
            let mut failure = None;
            let stop = walk(block, limit, |raw| {
                let position = base + raw.offset as u64;
                if raw.inode == 0 || position < cookie || raw.name == b"." || raw.name == b".." {
                    return ControlFlow::Continue(());
                }
                let kind = match raw.file_type {
                    TYPE_FILE => Some(Kind::File),
                    TYPE_DIRECTORY => Some(Kind::Directory),
                    0 => match self.inode(device, raw.inode) {
                        Ok(inode) => inode.kind(),
                        Err(error) => {
                            failure = Some(error);
                            return ControlFlow::Break(0);
                        }
                    },
                    _ => None,
                };
                let Some(kind) = kind else {
                    return ControlFlow::Continue(());
                };
                if entry(Entry {
                    name: raw.name,
                    inode: raw.inode,
                    kind,
                }) {
                    ControlFlow::Continue(())
                } else {
                    ControlFlow::Break(position)
                }
            });
            if let Some(error) = failure {
                return Err(error);
            }
            if let Some(position) = stop {
                return Ok(Some(position));
            }
        }
        Ok(None)
    }

    pub(crate) fn find_entry<D: Device>(
        &self,
        device: &mut D,
        dir: &Inode,
        name: &[u8],
    ) -> Result<Option<Found>, Error> {
        let blocks = self.dir_block_count(dir)?;
        let mut block = [0u8; MAX_BLOCK_BYTES];
        let block = &mut block[..self.bs()];
        for index in 0..blocks {
            let (limit, _) = self.read_dir_block(device, dir, index, block)?;
            let mut previous = None;
            let found = walk(block, limit, |raw| {
                if raw.inode != 0 && raw.name == name {
                    return ControlFlow::Break(Found {
                        inode: raw.inode,
                        block: index,
                        offset: raw.offset,
                        previous,
                    });
                }
                previous = Some(raw.offset);
                ControlFlow::Continue(())
            });
            if found.is_some() {
                return Ok(found);
            }
        }
        Ok(None)
    }

    /// Whether `dir` holds nothing but `.` and `..`.
    pub(crate) fn dir_is_empty<D: Device>(
        &self,
        device: &mut D,
        dir: &Inode,
    ) -> Result<bool, Error> {
        let mut empty = true;
        self.list(device, dir, 0, |_| {
            empty = false;
            false
        })?;
        Ok(empty)
    }

    /// Adds `name` for `inode` to `dir`, growing it by a block if no block
    /// has room. Writes `dir` when it grows.
    pub(crate) fn add_entry<D: Device>(
        &mut self,
        device: &mut D,
        dir: &mut Inode,
        name: &[u8],
        inode: u32,
        file_type: u8,
    ) -> Result<(), Error> {
        if dir.flags() & EXT4_INDEX_FL != 0 {
            return Err(Error::Unsupported);
        }
        let need = needed(name.len());
        let blocks = self.dir_block_count(dir)?;
        let mut block = [0u8; MAX_BLOCK_BYTES];
        let block = &mut block[..self.bs()];
        for index in 0..blocks {
            let (limit, physical) = self.read_dir_block(device, dir, index, block)?;
            if self.csum.is_some() && limit != block.len() - TAIL {
                return Err(Error::Corrupt);
            }
            let slot = walk(block, limit, |raw| {
                let used = if raw.inode == 0 {
                    0
                } else {
                    needed(raw.name.len())
                };
                if raw.rec_len - used >= need {
                    ControlFlow::Break((raw.offset, raw.rec_len, used))
                } else {
                    ControlFlow::Continue(())
                }
            });
            if let Some((offset, rec_len, used)) = slot {
                let at = if used == 0 {
                    offset
                } else {
                    put16(block, offset + 4, used as u16);
                    offset + used
                };
                write_entry(block, at, rec_len - used, inode, file_type, name);
                return self.write_dir_block(device, dir, physical, block);
            }
        }
        let goal = match blocks.checked_sub(1) {
            Some(last) => self
                .map(device, dir, last)?
                .map_or(0, |mapped| mapped.physical),
            None => 0,
        };
        let physical = self.alloc_block(device, goal)?;
        block.fill(0);
        let limit = self.entry_limit(block.len());
        write_entry(block, 0, limit, inode, file_type, name);
        self.set_tail(block);
        self.write_new_dir_block(device, dir, physical, block)?;
        if let Err(error) = self.map_insert(device, dir, blocks, physical) {
            let _ = self.free_blocks_range(device, physical, 1);
            return Err(error);
        }
        self.charge(dir, 1, true);
        dir.set_size(dir.size() + u64::from(self.block_size));
        self.write_inode(device, dir)
    }

    /// Removes the entry `found` from `dir`.
    pub(crate) fn remove_entry<D: Device>(
        &self,
        device: &mut D,
        dir: &Inode,
        found: Found,
    ) -> Result<(), Error> {
        if dir.flags() & EXT4_INDEX_FL != 0 {
            return Err(Error::Unsupported);
        }
        let mut block = [0u8; MAX_BLOCK_BYTES];
        let block = &mut block[..self.bs()];
        let (_, physical) = self.read_dir_block(device, dir, found.block, block)?;
        let rec_len = get16(block, found.offset + 4);
        match found.previous {
            Some(previous) => {
                let merged = get16(block, previous + 4) + rec_len;
                put16(block, previous + 4, merged);
            }
            None => put32(block, found.offset, 0),
        }
        self.write_dir_block(device, dir, physical, block)
    }
}

fn write_entry(
    block: &mut [u8],
    at: usize,
    rec_len: usize,
    inode: u32,
    file_type: u8,
    name: &[u8],
) {
    put32(block, at, inode);
    put16(block, at + 4, rec_len as u16);
    block[at + 6] = name.len() as u8;
    block[at + 7] = file_type;
    block[at + 8..at + 8 + name.len()].copy_from_slice(name);
    // Clear the old bytes up to the next 4-byte boundary.
    let end = needed(name.len()).min(rec_len);
    block[at + 8 + name.len()..at + end].fill(0);
}
