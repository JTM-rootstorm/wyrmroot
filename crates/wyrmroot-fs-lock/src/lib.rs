//! The advisory byte-range locks a WRFS server keeps (WRFS 1.1, W10).
//!
//! A [`LockTable`] holds every lock a filesystem server has granted: a
//! range of one node (a file, named by the server's own node identity),
//! shared or exclusive, owned by one opaque owner (the server uses the
//! Channel the lock was taken on). An owner's locks on a node never
//! overlap and same-mode neighbours are merged, so a lock replaces the
//! owner's own locks where it overlaps them, as POSIX `fcntl` and Linux
//! open-file-description locks do. A change that would not fit, in the
//! table or in the owner's limit, is refused whole, before anything moves.
//! A server that sizes the table to the sum of its owners' limits can never
//! have it filled by one owner (W10 review D1).

#![no_std]
#![forbid(unsafe_code)]

use wyrmroot_fs_proto::node::{Lock, LockMode};

#[cfg(test)]
mod tests;

/// One granted lock. `end` is exclusive; `u64::MAX` runs to the end of any
/// file size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Held {
    pub node: u64,
    pub owner: u64,
    pub start: u64,
    pub end: u64,
    pub exclusive: bool,
}

impl Held {
    /// The lock as the protocol carries it.
    pub fn lock(&self) -> Lock {
        Lock {
            start: self.start,
            length: if self.end == u64::MAX {
                0
            } else {
                self.end - self.start
            },
            mode: if self.exclusive {
                LockMode::Exclusive
            } else {
                LockMode::Shared
            },
        }
    }

    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start < end && start < self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockError {
    /// Another owner holds a conflicting lock.
    Conflict,
    /// The table, or the owner's limit, has no room for the change.
    NoRoom,
}

pub struct LockTable<const N: usize> {
    entries: [Option<Held>; N],
    /// The most locks one owner holds at once.
    owner_limit: usize,
}

impl<const N: usize> Default for LockTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// `lock`'s range as an exclusive end, or `None` for an empty range.
fn range(lock: Lock) -> Option<(u64, u64)> {
    let end = lock.end().unwrap_or(u64::MAX);
    (lock.start < end).then_some((lock.start, end))
}

impl<const N: usize> LockTable<N> {
    /// A table whose owners may hold up to `N` locks each.
    pub const fn new() -> Self {
        Self::with_owner_limit(N)
    }

    /// A table whose owners may hold up to `owner_limit` locks each.
    pub const fn with_owner_limit(owner_limit: usize) -> Self {
        Self {
            entries: [None; N],
            owner_limit,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Held> {
        self.entries.iter().flatten()
    }

    /// A lock of another owner on `node` that `lock` (shared or exclusive)
    /// would conflict with.
    pub fn conflict(&self, node: u64, owner: u64, lock: Lock) -> Option<Held> {
        let (start, end) = range(lock)?;
        let exclusive = lock.mode == LockMode::Exclusive;
        self.iter()
            .find(|held| {
                held.node == node
                    && held.owner != owner
                    && held.overlaps(start, end)
                    && (exclusive || held.exclusive)
            })
            .copied()
    }

    /// Locks, or with [`LockMode::Unlock`] unlocks, `lock`'s range of
    /// `node` for `owner`. An empty range changes nothing.
    pub fn set(&mut self, node: u64, owner: u64, lock: Lock) -> Result<(), LockError> {
        let Some((start, end)) = range(lock) else {
            return Ok(());
        };
        let granting = lock.mode != LockMode::Unlock;
        let exclusive = lock.mode == LockMode::Exclusive;
        if granting && self.conflict(node, owner, lock).is_some() {
            return Err(LockError::Conflict);
        }
        let own = |held: &Held| held.node == node && held.owner == owner;
        // Same-mode locks that overlap or touch are absorbed into the new
        // one. The owner's locks are disjoint, so what they add overlaps
        // none of its other locks.
        let absorbs = |held: &Held| {
            granting && held.exclusive == exclusive && held.start <= end && start <= held.end
        };
        let (mut merged_start, mut merged_end) = (start, end);
        let mut removed = [false; N];
        let mut pieces: [Option<Held>; 2] = [None; 2];
        let mut piece_count = 0;
        let mut removed_count = 0;
        for (index, held) in self.entries.iter().enumerate() {
            let Some(held) = held.filter(own) else {
                continue;
            };
            if absorbs(&held) {
                merged_start = merged_start.min(held.start);
                merged_end = merged_end.max(held.end);
            } else if held.overlaps(start, end) {
                // What lies outside the range survives; only a lock that
                // contains an edge of the range leaves a piece, and the
                // owner's locks are disjoint, so there are at most two.
                if held.start < start {
                    pieces[piece_count] = Some(Held { end: start, ..held });
                    piece_count += 1;
                }
                if held.end > end {
                    pieces[piece_count] = Some(Held { start: end, ..held });
                    piece_count += 1;
                }
            } else {
                continue;
            }
            removed[index] = true;
            removed_count += 1;
        }
        let added = piece_count + usize::from(granting);
        let free = self.entries.iter().filter(|held| held.is_none()).count();
        let owned = self.iter().filter(|held| held.owner == owner).count();
        if free + removed_count < added || owned - removed_count + added > self.owner_limit {
            return Err(LockError::NoRoom);
        }
        for (slot, remove) in self.entries.iter_mut().zip(removed) {
            if remove {
                *slot = None;
            }
        }
        let new = granting.then_some(Held {
            node,
            owner,
            start: merged_start,
            end: merged_end,
            exclusive,
        });
        for held in pieces.into_iter().chain([new]).flatten() {
            let slot = self
                .entries
                .iter_mut()
                .find(|slot| slot.is_none())
                .expect("room was counted before anything moved");
            *slot = Some(held);
        }
        Ok(())
    }

    /// Releases every lock `owner` holds, on every node.
    pub fn release(&mut self, owner: u64) {
        for slot in &mut self.entries {
            if slot.is_some_and(|held| held.owner == owner) {
                *slot = None;
            }
        }
    }
}
