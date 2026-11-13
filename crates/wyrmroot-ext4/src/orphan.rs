//! The orphan list (`orphan.rst`; `inodes.rst`, "Inode Timestamps";
//! `super.rst`, `s_last_orphan`): inodes with no name left that must still
//! be freed. The superblock's `s_last_orphan` names the first, and each
//! orphan's `i_dtime` names the next, zero ending the list.
//!
//! A file whose last name is removed while a caller holds it open joins the
//! list in the change that removes the name ([`Volume::unlink_held`]) and
//! leaves it in the change that frees it ([`Volume::release`]). Through a
//! journal the first is one transaction, so a crash finds the file either
//! named or on the list, and [`Volume::recover_orphan`] frees what a crash
//! left there. Without a journal a crash between the writes of one change
//! may leave work for `e2fsck`, as for every other change.
//!
//! Freeing is bounded so that it always fits a journal transaction: one
//! call frees blocks from the end of the file in as many block groups as
//! the `room` it is given allows, and writes the shrunken inode, still on
//! the list with no links. Only the call that finds nothing left takes the
//! inode off the list and frees it. A crash between calls leaves an orphan
//! the next mount finishes, so no file is too large or too scattered to
//! free, and the caller commits between calls.
//!
//! The volume holds the list it wrote in memory ([`Volume::held`]). A mount
//! empties the list before anything else changes, so the two always agree,
//! and what the disk says is still checked against it before it is used.
//!
//! Not handled, and left read-only for Linux or `e2fsck`: an orphan that
//! still has links (Linux lists an inode while it truncates it), one that is
//! neither a file nor a directory, and any orphan beside an orphan file
//! (`COMPAT_ORPHAN_FILE`), whose volumes this module never gives orphans.

use crate::extent::GroupBudget;
use crate::{COMPAT_ORPHAN_FILE, Device, Error, Inode, Kind, MAX_HELD, Volume, get32, put32};

/// Metadata blocks one freeing call may write besides a bitmap and a
/// descriptor block for each block group it frees from: four extent leaves,
/// the bitmaps and descriptors of four freed leaves, the inode's block and
/// its list predecessor's, the superblock, and the inode bitmap with its
/// descriptor.
const FIXED_ROOM: usize = 17;
/// The least `room` [`Volume::release`] and [`Volume::recover_orphan`]
/// work in: one block group a call.
pub const MIN_FREE_ROOM: usize = FIXED_ROOM + 2;

/// How many block groups a call given `room` metadata blocks frees from.
fn step_groups(room: usize) -> Result<usize, Error> {
    match room.saturating_sub(FIXED_ROOM) / 2 {
        0 => Err(Error::Unsupported),
        groups => Ok(groups),
    }
}

/// `s_last_orphan`.
const LAST_ORPHAN: usize = 0xE8;
/// `i_dtime`: the next orphan while the inode is on the list.
const DTIME: usize = 0x14;

impl Volume {
    /// Whether the mount found an orphan list that
    /// [`Volume::recover_orphan`] has not emptied yet. Until it has, every
    /// change is [`Error::ReadOnly`].
    pub fn orphans_pending(&self) -> bool {
        self.orphans_pending
    }

    /// The unlinked inodes kept for their holders.
    pub fn held(&self) -> &[u32] {
        &self.held[..self.held_len]
    }

    /// Whether `inode` has no name and is kept for its holders.
    pub fn is_held(&self, inode: u32) -> bool {
        self.held().contains(&inode)
    }

    /// Tells the volume how many metadata blocks one change may write: a
    /// journaling caller's transaction limit. Unlimited by default, as it
    /// is without a journal, where every write goes straight to the device.
    /// Below [`MIN_FREE_ROOM`] no orphan could ever be freed, so
    /// [`Volume::unlink_held`] keeps none ([`Error::Busy`]).
    pub fn set_free_room(&mut self, room: usize) {
        self.free_room = room;
    }

    /// Whether an orphan can be freed in the room the volume was given
    /// ([`Volume::set_free_room`]).
    pub fn frees_orphans(&self) -> bool {
        self.free_room >= MIN_FREE_ROOM
    }

    /// Whether [`Volume::unlink_held`] can keep one more node: the volume
    /// takes changes, has no orphan file, has room to free an orphan, and
    /// holds fewer than [`MAX_HELD`].
    pub fn keeps_unlinked(&self) -> bool {
        self.require_writable().is_ok()
            && self.frees_orphans()
            && get32(&self.sb, 0x5C) & COMPAT_ORPHAN_FILE == 0
            && self.held_len < MAX_HELD
    }

    /// [`Volume::unlink`] for a node some caller holds open. A file whose
    /// last name this removes keeps its inode and blocks, reads and writes
    /// as before, and is freed by [`Volume::release`]; it is on the orphan
    /// list meanwhile, so a crash frees it at the next mount. A file with
    /// another name only loses this one. [`Error::Busy`], with nothing
    /// changed, for a directory and when the volume cannot keep the node
    /// ([`Volume::keeps_unlinked`]).
    pub fn unlink_held<D: Device>(
        &mut self,
        device: &mut D,
        dir: u32,
        name: &[u8],
    ) -> Result<(), Error> {
        self.unlink_node(device, dir, name, true)
    }

    /// The superblock must name the first held inode.
    pub(crate) fn check_held_first(&self) -> Result<(), Error> {
        if get32(&self.sb, LAST_ORPHAN) == self.held().first().copied().unwrap_or(0) {
            Ok(())
        } else {
            Err(Error::Corrupt)
        }
    }

    /// Puts `node`, whose last name is gone, at the head of the orphan
    /// list. The caller writes the superblock.
    pub(crate) fn hold<D: Device>(
        &mut self,
        device: &mut D,
        node: &mut Inode,
    ) -> Result<(), Error> {
        self.check_held_first()?;
        if self.held_len == MAX_HELD || self.is_held(node.number) {
            return Err(Error::Corrupt);
        }
        let head = get32(&self.sb, LAST_ORPHAN);
        node.set_links(0);
        put32(&mut node.raw, DTIME, head);
        self.write_inode(device, node)?;
        put32(&mut self.sb, LAST_ORPHAN, node.number);
        self.held.copy_within(..self.held_len, 1);
        self.held[0] = node.number;
        self.held_len += 1;
        Ok(())
    }

    /// Frees the held `inode` and its blocks, once nothing holds it, writing
    /// at most `room` metadata blocks (at least [`MIN_FREE_ROOM`]; a
    /// journal transaction's limit, with the transaction empty). Returns
    /// whether the inode is freed: `false` means blocks were freed, the inode
    /// is still held and listed, and the caller calls again (through a
    /// journal, after committing). A failure part-way leaves it held, the
    /// volume read-only with its free counts as they were, and what was
    /// written unknown (through a journal, the caller drops the
    /// transaction); the next mount frees it.
    pub fn release<D: Device>(
        &mut self,
        device: &mut D,
        inode: u32,
        room: usize,
    ) -> Result<bool, Error> {
        self.require_writable()?;
        let groups = step_groups(room)?;
        let at = self
            .held()
            .iter()
            .position(|&held| held == inode)
            .ok_or(Error::NotFound)?;
        let node = self.inode(device, inode)?;
        let next = self.held().get(at + 1).copied().unwrap_or(0);
        if node.links() != 0 || node.kind() != Some(Kind::File) || get32(&node.raw, DTIME) != next {
            return Err(Error::Corrupt);
        }
        let previous = at.checked_sub(1).map(|at| self.held[at]);
        let before = self.sb;
        let freed = self
            .free_orphan(device, node, previous, false, groups)
            .and_then(|freed| self.write_superblock(device).map(|()| freed));
        match freed {
            Ok(true) => {
                self.held.copy_within(at + 1..self.held_len, at);
                self.held_len -= 1;
                Ok(true)
            }
            Ok(false) => Ok(false),
            Err(error) => {
                self.sb = before;
                self.writable = false;
                Err(error)
            }
        }
    }

    /// Frees blocks of `node` in up to `groups` block groups; once none are
    /// left, takes it off the orphan list, where `previous` (the superblock
    /// when `None`) names it, and frees its inode. Returns whether it did.
    /// The caller writes the superblock.
    fn free_orphan<D: Device>(
        &mut self,
        device: &mut D,
        mut node: Inode,
        previous: Option<u32>,
        directory: bool,
        groups: usize,
    ) -> Result<bool, Error> {
        let next = get32(&node.raw, DTIME);
        // Every block, whatever the size says; the blocks still to free
        // lie past the end meanwhile.
        let emptied = self.trim_tail(device, &mut node, &mut GroupBudget::new(groups))?;
        node.set_size(0);
        node.set_times(self.now, true, false);
        if !emptied {
            self.write_inode(device, &mut node)?;
            return Ok(false);
        }
        match previous {
            Some(previous) => {
                let mut before = self.inode(device, previous)?;
                if before.links() != 0 || get32(&before.raw, DTIME) != node.number {
                    return Err(Error::Corrupt);
                }
                put32(&mut before.raw, DTIME, next);
                self.write_inode(device, &mut before)?;
            }
            None => {
                if get32(&self.sb, LAST_ORPHAN) != node.number {
                    return Err(Error::Corrupt);
                }
                put32(&mut self.sb, LAST_ORPHAN, next);
            }
        }
        put32(&mut node.raw, DTIME, self.now.max(1));
        self.write_inode(device, &mut node)?;
        self.free_inode(device, node.number, directory)?;
        Ok(true)
    }

    /// Frees blocks of the first inode on the orphan list a mount found,
    /// and the inode once it has none, writing at most `room` metadata
    /// blocks (as [`Volume::release`]) and the superblock. Returns whether
    /// anything is still listed; once nothing is, the volume takes changes.
    /// Through a journal the caller commits between calls.
    ///
    /// A list this module cannot process ([`Error::Unsupported`]) or cannot
    /// trust ([`Error::Corrupt`]), and any other failure, leaves the volume
    /// read-only with its free counts as mounted; what was written is then
    /// unknown (through a journal, the caller drops the transaction).
    pub fn recover_orphan<D: Device>(
        &mut self,
        device: &mut D,
        room: usize,
    ) -> Result<bool, Error> {
        if !self.orphans_pending {
            return Ok(false);
        }
        if !self.writable {
            return Err(Error::ReadOnly);
        }
        let mounted = self.sb;
        match self.recover_first(device, room) {
            Ok(more) => {
                self.orphans_pending = more;
                Ok(more)
            }
            Err(error) => {
                self.sb = mounted;
                self.writable = false;
                Err(error)
            }
        }
    }

    fn recover_first<D: Device>(&mut self, device: &mut D, room: usize) -> Result<bool, Error> {
        let first = get32(&self.sb, LAST_ORPHAN);
        if first == 0 {
            return Ok(false);
        }
        let groups = step_groups(room)?;
        // Reserved inodes are never orphans.
        if first < self.first_inode || first > self.inodes {
            return Err(Error::Corrupt);
        }
        let node = self.inode(device, first)?;
        // An inode with links is listed only while Linux truncates it.
        let directory = match node.kind() {
            Some(kind) if node.links() == 0 => kind == Kind::Directory,
            _ => return Err(Error::Unsupported),
        };
        self.check_freeable(&node)?;
        let next = get32(&node.raw, DTIME);
        if next == first {
            return Err(Error::Corrupt);
        }
        // A list that loops reaches an inode already freed, which
        // `free_inode` refuses, so the walk ends within the inode count.
        let freed = self.free_orphan(device, node, None, directory, groups)?;
        self.write_superblock(device)?;
        Ok(!freed || next != 0)
    }
}
