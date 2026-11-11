//! Extent trees (`ifork.rst`). Reads walk any legal depth; writes keep the
//! tree at depth 0 (four extents in the inode) or depth 1 (up to four leaf
//! blocks), which covers every file this implementation creates.

use crate::{
    Device, EXT4_EXTENTS_FL, EXT4_HUGE_FILE_FL, Error, Inode, MAX_BLOCK_BYTES, Volume, crc, get16,
    get32, put16, put32,
};

const MAGIC: u16 = 0xF30A;
const HEADER: usize = 12;
const ENTRY: usize = 12;
const MAX_DEPTH: u16 = 5;
/// The longest initialised extent.
const MAX_LEN: u32 = 32768;
const ROOT_ENTRIES: u16 = 4;

/// Where one logical block lives.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Mapped {
    pub(crate) physical: u64,
    /// Allocated but unwritten: reads as zeros.
    pub(crate) uninit: bool,
}

#[derive(Clone, Copy)]
struct Header {
    entries: u16,
    max: u16,
    depth: u16,
}

fn header(node: &[u8]) -> Result<Header, Error> {
    let capacity = (node.len() - HEADER) / ENTRY;
    let header = Header {
        entries: get16(node, 2),
        max: get16(node, 4),
        depth: get16(node, 6),
    };
    if get16(node, 0) != MAGIC
        || header.max == 0
        || usize::from(header.max) > capacity
        || header.entries > header.max
        || header.depth > MAX_DEPTH
    {
        return Err(Error::Corrupt);
    }
    Ok(header)
}

fn set_header(node: &mut [u8], header: Header) {
    put16(node, 0, MAGIC);
    put16(node, 2, header.entries);
    put16(node, 4, header.max);
    put16(node, 6, header.depth);
    put32(node, 8, 0);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Extent {
    logical: u32,
    len: u32,
    physical: u64,
    uninit: bool,
}

fn extent(node: &[u8], index: usize) -> Result<Extent, Error> {
    let at = HEADER + index * ENTRY;
    let raw = u32::from(get16(node, at + 4));
    let (len, uninit) = if raw > MAX_LEN {
        (raw - MAX_LEN, true)
    } else {
        (raw, false)
    };
    if len == 0 {
        return Err(Error::Corrupt);
    }
    Ok(Extent {
        logical: get32(node, at),
        len,
        physical: u64::from(get32(node, at + 8)) | u64::from(get16(node, at + 6)) << 32,
        uninit,
    })
}

fn set_extent(node: &mut [u8], index: usize, extent: Extent) {
    let at = HEADER + index * ENTRY;
    put32(node, at, extent.logical);
    let raw = if extent.uninit {
        extent.len + MAX_LEN
    } else {
        extent.len
    };
    put16(node, at + 4, raw as u16);
    put16(node, at + 6, (extent.physical >> 32) as u16);
    put32(node, at + 8, extent.physical as u32);
}

fn index_entry(node: &[u8], index: usize) -> (u32, u64) {
    let at = HEADER + index * ENTRY;
    (
        get32(node, at),
        u64::from(get32(node, at + 4)) | u64::from(get16(node, at + 8)) << 32,
    )
}

fn set_index_entry(node: &mut [u8], index: usize, logical: u32, block: u64) {
    let at = HEADER + index * ENTRY;
    put32(node, at, logical);
    put32(node, at + 4, block as u32);
    put16(node, at + 8, (block >> 32) as u16);
    put16(node, at + 10, 0);
}

/// Moves entries `from..entries` of `node` one slot right.
fn open_slot(node: &mut [u8], from: usize, entries: usize) {
    let start = HEADER + from * ENTRY;
    let end = HEADER + entries * ENTRY;
    node.copy_within(start..end, start + ENTRY);
}

/// Removes entry `at` of `node`.
fn close_slot(node: &mut [u8], at: usize, entries: usize) {
    let start = HEADER + at * ENTRY;
    let end = HEADER + entries * ENTRY;
    node.copy_within(start + ENTRY..end, start);
}

impl Volume {
    fn leaf_capacity(&self) -> u16 {
        ((self.bs() - HEADER) / ENTRY) as u16
    }

    fn tree_checksum(
        &self,
        seed: u32,
        inode: &Inode,
        node: &[u8],
        max: u16,
    ) -> Result<(u32, usize), Error> {
        let tail = HEADER + usize::from(max) * ENTRY;
        if tail + 4 > node.len() {
            return Err(Error::Corrupt);
        }
        Ok((
            crc::update(self.inode_seed(seed, inode), &node[..tail]),
            tail,
        ))
    }

    /// Reads tree block `block` at the expected `depth` into `node`.
    fn read_node<D: Device>(
        &self,
        device: &mut D,
        inode: &Inode,
        block: u64,
        depth: u16,
        node: &mut [u8],
    ) -> Result<Header, Error> {
        self.read_block(device, block, node)?;
        let header = header(node)?;
        if header.depth != depth {
            return Err(Error::Corrupt);
        }
        if let Some(seed) = self.csum {
            let (sum, tail) = self.tree_checksum(seed, inode, node, header.max)?;
            if sum != get32(node, tail) {
                return Err(Error::Corrupt);
            }
        }
        Ok(header)
    }

    fn write_node<D: Device>(
        &self,
        device: &mut D,
        inode: &Inode,
        block: u64,
        node: &mut [u8],
    ) -> Result<(), Error> {
        if let Some(seed) = self.csum {
            let max = get16(node, 4);
            let (sum, tail) = self.tree_checksum(seed, inode, node, max)?;
            put32(node, tail, sum);
        }
        self.write_block(device, block, node)
    }

    fn check_extent(&self, extent: Extent) -> Result<(), Error> {
        let end = extent.physical.checked_add(u64::from(extent.len));
        if extent.physical < u64::from(self.first_data_block)
            || !end.is_some_and(|end| end <= self.blocks)
            || extent.logical.checked_add(extent.len - 1).is_none()
        {
            return Err(Error::Corrupt);
        }
        Ok(())
    }

    /// Maps logical block `logical` of `inode`.
    pub(crate) fn map<D: Device>(
        &self,
        device: &mut D,
        inode: &Inode,
        logical: u32,
    ) -> Result<Option<Mapped>, Error> {
        if inode.flags() & EXT4_EXTENTS_FL == 0 {
            // Only an empty node may lack extents: block maps are not read.
            return if inode.size() == 0 && inode.root().iter().all(|&byte| byte == 0) {
                Ok(None)
            } else {
                Err(Error::Unsupported)
            };
        }
        let mut node = [0u8; MAX_BLOCK_BYTES];
        node[..60].copy_from_slice(inode.root());
        let mut len = 60;
        let mut head = header(&node[..len])?;
        loop {
            if head.depth == 0 {
                for index in 0..usize::from(head.entries) {
                    let found = extent(&node[..len], index)?;
                    self.check_extent(found)?;
                    if logical >= found.logical && logical - found.logical < found.len {
                        let skip = logical - found.logical;
                        return Ok(Some(Mapped {
                            physical: found.physical + u64::from(skip),
                            uninit: found.uninit,
                        }));
                    }
                }
                return Ok(None);
            }
            let mut child = None;
            for index in 0..usize::from(head.entries) {
                let (first, block) = index_entry(&node[..len], index);
                if first <= logical {
                    child = Some(block);
                } else {
                    break;
                }
            }
            let Some(block) = child else {
                return Ok(None);
            };
            let depth = head.depth - 1;
            len = self.bs();
            head = self.read_node(device, inode, block, depth, &mut node[..len])?;
        }
    }

    /// Records that logical block `logical` of `inode` lives at `physical`.
    /// The block must be unmapped. The caller writes the inode.
    pub(crate) fn map_insert<D: Device>(
        &mut self,
        device: &mut D,
        inode: &mut Inode,
        logical: u32,
        physical: u64,
    ) -> Result<(), Error> {
        if inode.flags() & EXT4_EXTENTS_FL == 0 || inode.flags() & EXT4_HUGE_FILE_FL != 0 {
            return Err(Error::Unsupported);
        }
        let new = Extent {
            logical,
            len: 1,
            physical,
            uninit: false,
        };
        let root = header(inode.root())?;
        match root.depth {
            0 => {
                if leaf_insert(inode.root_mut(), new)? {
                    return Ok(());
                }
                // Grow: the four extents move to a new leaf block.
                let goal = extent(inode.root(), usize::from(root.entries) - 1)?.physical;
                let block = self.alloc_block(device, goal)?;
                let mut leaf = [0u8; MAX_BLOCK_BYTES];
                let leaf = &mut leaf[..self.bs()];
                set_header(
                    leaf,
                    Header {
                        entries: root.entries,
                        max: self.leaf_capacity(),
                        depth: 0,
                    },
                );
                let count = usize::from(root.entries) * ENTRY;
                leaf[HEADER..HEADER + count].copy_from_slice(&inode.root()[HEADER..HEADER + count]);
                if !leaf_insert(leaf, new)? {
                    return Err(Error::Corrupt);
                }
                let first = extent(leaf, 0)?.logical;
                self.write_node(device, inode, block, leaf)?;
                let node = inode.root_mut();
                node.fill(0);
                set_header(
                    node,
                    Header {
                        entries: 1,
                        max: ROOT_ENTRIES,
                        depth: 1,
                    },
                );
                set_index_entry(node, 0, first, block);
                self.charge(inode, 1, true);
                Ok(())
            }
            1 => self.insert_depth_one(device, inode, root, new),
            _ => Err(Error::Unsupported),
        }
    }

    fn insert_depth_one<D: Device>(
        &mut self,
        device: &mut D,
        inode: &mut Inode,
        root: Header,
        new: Extent,
    ) -> Result<(), Error> {
        if root.entries == 0 {
            return Err(Error::Corrupt);
        }
        let entries = usize::from(root.entries);
        let mut slot = 0;
        for index in 0..entries {
            if index_entry(inode.root(), index).0 <= new.logical {
                slot = index;
            }
        }
        let (first, block) = index_entry(inode.root(), slot);
        let mut leaf = [0u8; MAX_BLOCK_BYTES];
        let leaf = &mut leaf[..self.bs()];
        let head = self.read_node(device, inode, block, 0, leaf)?;
        if leaf_insert(leaf, new)? {
            self.write_node(device, inode, block, leaf)?;
            if new.logical < first {
                set_index_entry(inode.root_mut(), slot, new.logical, block);
            }
            return Ok(());
        }
        if entries == usize::from(ROOT_ENTRIES) {
            return Err(Error::NoSpace);
        }
        // Split: a new leaf after this one takes the upper half, or, when
        // the file grows past its last extent, only the new extent.
        let last = extent(leaf, usize::from(head.entries) - 1)?;
        let appending = slot == entries - 1 && new.logical > last.logical;
        let keep = if appending {
            usize::from(head.entries)
        } else {
            usize::from(head.entries) / 2
        };
        let moved = usize::from(head.entries) - keep;
        let sibling_block = self.alloc_block(device, last.physical)?;
        let mut sibling = [0u8; MAX_BLOCK_BYTES];
        let sibling = &mut sibling[..self.bs()];
        set_header(
            sibling,
            Header {
                entries: moved as u16,
                max: self.leaf_capacity(),
                depth: 0,
            },
        );
        sibling[HEADER..HEADER + moved * ENTRY]
            .copy_from_slice(&leaf[HEADER + keep * ENTRY..HEADER + (keep + moved) * ENTRY]);
        put16(leaf, 2, keep as u16);
        let sibling_first = if moved == 0 {
            new.logical
        } else {
            extent(sibling, 0)?.logical
        };
        let into_sibling = new.logical >= sibling_first;
        let inserted = if into_sibling {
            leaf_insert(sibling, new)?
        } else {
            leaf_insert(leaf, new)?
        };
        if !inserted {
            return Err(Error::Corrupt);
        }
        let sibling_first = extent(sibling, 0)?.logical;
        self.write_node(device, inode, sibling_block, sibling)?;
        self.write_node(device, inode, block, leaf)?;
        let node = inode.root_mut();
        open_slot(node, slot + 1, entries);
        set_index_entry(node, slot + 1, sibling_first, sibling_block);
        put16(node, 2, (entries + 1) as u16);
        if !into_sibling && new.logical < first {
            set_index_entry(node, slot, new.logical, block);
        }
        self.charge(inode, 1, true);
        Ok(())
    }

    /// Frees every block of `inode` at or past logical block `keep`,
    /// including leaf blocks left empty. The caller writes the inode.
    pub(crate) fn map_truncate<D: Device>(
        &mut self,
        device: &mut D,
        inode: &mut Inode,
        keep: u32,
    ) -> Result<(), Error> {
        if inode.flags() & EXT4_EXTENTS_FL == 0 {
            return if inode.root().iter().all(|&byte| byte == 0) {
                Ok(())
            } else {
                Err(Error::Unsupported)
            };
        }
        if inode.flags() & EXT4_HUGE_FILE_FL != 0 {
            return Err(Error::Unsupported);
        }
        let root = header(inode.root())?;
        match root.depth {
            0 => {
                let mut node = [0u8; 60];
                node.copy_from_slice(inode.root());
                self.trim_leaf(device, inode, &mut node, keep)?;
                inode.root_mut().copy_from_slice(&node);
                Ok(())
            }
            1 => {
                let mut index = usize::from(root.entries);
                while index > 0 {
                    index -= 1;
                    let (_, block) = index_entry(inode.root(), index);
                    let mut leaf = [0u8; MAX_BLOCK_BYTES];
                    let leaf = &mut leaf[..self.bs()];
                    self.read_node(device, inode, block, 0, leaf)?;
                    self.trim_leaf(device, inode, leaf, keep)?;
                    if get16(leaf, 2) == 0 {
                        self.free_blocks_range(device, block, 1)?;
                        self.charge(inode, 1, false);
                        let entries = usize::from(get16(inode.root(), 2));
                        close_slot(inode.root_mut(), index, entries);
                        put16(inode.root_mut(), 2, (entries - 1) as u16);
                    } else {
                        self.write_node(device, inode, block, leaf)?;
                    }
                }
                if get16(inode.root(), 2) == 0 {
                    let node = inode.root_mut();
                    node.fill(0);
                    set_header(
                        node,
                        Header {
                            entries: 0,
                            max: ROOT_ENTRIES,
                            depth: 0,
                        },
                    );
                }
                Ok(())
            }
            _ => Err(Error::Unsupported),
        }
    }

    /// Trims one leaf `node` to logical blocks below `keep`, freeing the rest.
    fn trim_leaf<D: Device>(
        &mut self,
        device: &mut D,
        inode: &mut Inode,
        node: &mut [u8],
        keep: u32,
    ) -> Result<(), Error> {
        let mut entries = usize::from(header(node)?.entries);
        let mut index = entries;
        while index > 0 {
            index -= 1;
            let mut found = extent(node, index)?;
            self.check_extent(found)?;
            if found.logical >= keep {
                self.free_blocks_range(device, found.physical, found.len)?;
                self.charge(inode, found.len, false);
                close_slot(node, index, entries);
                entries -= 1;
                put16(node, 2, entries as u16);
            } else if found.logical + (found.len - 1) >= keep {
                let kept = keep - found.logical;
                let freed = found.len - kept;
                self.free_blocks_range(device, found.physical + u64::from(kept), freed)?;
                self.charge(inode, freed, false);
                found.len = kept;
                set_extent(node, index, found);
            }
        }
        Ok(())
    }

    /// Adds or removes `blocks` filesystem blocks from `inode`'s count.
    pub(crate) fn charge(&self, inode: &mut Inode, blocks: u32, add: bool) {
        let sectors = u64::from(blocks) * u64::from(self.block_size / 512);
        let now = inode.sectors();
        inode.set_sectors(if add {
            now + sectors
        } else {
            now.saturating_sub(sectors)
        });
    }
}

/// Initialises an empty in-inode extent root.
pub(crate) fn empty_root(root: &mut [u8]) {
    root.fill(0);
    set_header(
        root,
        Header {
            entries: 0,
            max: ROOT_ENTRIES,
            depth: 0,
        },
    );
}

/// Adds the one-block extent `new` to the leaf `node`, merging with a
/// neighbour where possible. `Ok(false)`: the leaf is full.
fn leaf_insert(node: &mut [u8], new: Extent) -> Result<bool, Error> {
    let head = header(node)?;
    if head.depth != 0 {
        return Err(Error::Corrupt);
    }
    let entries = usize::from(head.entries);
    let mut at = entries;
    for index in 0..entries {
        let found = extent(node, index)?;
        if new.logical >= found.logical && new.logical - found.logical < found.len {
            return Err(Error::Corrupt);
        }
        if found.logical > new.logical {
            at = index;
            break;
        }
    }
    if at > 0 {
        let mut before = extent(node, at - 1)?;
        if !before.uninit
            && before.len < MAX_LEN
            && before.logical + before.len == new.logical
            && before.physical + u64::from(before.len) == new.physical
        {
            before.len += 1;
            set_extent(node, at - 1, before);
            return Ok(true);
        }
    }
    if at < entries {
        let mut after = extent(node, at)?;
        if !after.uninit
            && after.len < MAX_LEN
            && after.logical == new.logical + 1
            && after.physical == new.physical + 1
        {
            after.logical = new.logical;
            after.physical = new.physical;
            after.len += 1;
            set_extent(node, at, after);
            return Ok(true);
        }
    }
    if entries == usize::from(head.max) {
        return Ok(false);
    }
    open_slot(node, at, entries);
    set_extent(node, at, new);
    put16(node, 2, (entries + 1) as u16);
    Ok(true)
}

#[cfg(test)]
pub(crate) fn root_depth(inode_root: &[u8]) -> u16 {
    get16(inode_root, 6)
}
