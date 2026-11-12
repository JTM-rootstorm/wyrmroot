//! Lock groups, waiting and deadlocks (WRFS 1.2) over a [`LockTable`].
//!
//! Every owner that has made a lock request is recorded with its lock
//! group and, while its LOCK waits, the request it waits with. A waiting
//! request is granted when nothing conflicts any more, oldest first. Before
//! a request waits, the wait-for graph between groups is walked: the groups
//! holding what it waits for, the groups holding what their waiting owners
//! wait for, and so on. Reaching the request's own group means the wait
//! would never end, and the request is answered [`Outcome::Deadlock`]
//! instead. Each group is visited once, so the walk is bounded by the
//! number of owners.

use wyrmroot_fs_proto::node::{LOCK_WAIT, Lock};

use crate::{LockError, LockTable};

/// What a lock request comes to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Done; the owner's lock group.
    Granted(u64),
    /// It waits; [`LockServer::take_granted`] reports it later.
    Waiting,
    /// Another owner holds a conflicting lock, and the request does not
    /// wait.
    Busy,
    /// Waiting would never end.
    Deadlock,
    /// No room for the change, or for another owner.
    NoRoom,
    /// The group is neither 0, the owner's own, nor a live group; or the
    /// owner is already waiting.
    Invalid,
}

#[derive(Clone, Copy, Debug)]
struct Waiter {
    node: u64,
    lock: Lock,
    /// The caller's reference for the reply.
    token: u64,
    /// Arrival order.
    sequence: u64,
}

#[derive(Clone, Copy, Debug)]
struct Owner {
    owner: u64,
    group: u64,
    waiting: Option<Waiter>,
}

/// Locks, their owners' groups and the requests waiting, for `OWNERS`
/// owners holding at most `N` locks between them.
pub struct LockServer<const N: usize, const OWNERS: usize> {
    table: LockTable<N>,
    owners: [Option<Owner>; OWNERS],
    next_group: u64,
    next_sequence: u64,
}

impl<const N: usize, const OWNERS: usize> Default for LockServer<N, OWNERS> {
    fn default() -> Self {
        Self::with_owner_limit(N)
    }
}

impl<const N: usize, const OWNERS: usize> LockServer<N, OWNERS> {
    /// A server whose owners hold at most `owner_limit` locks each.
    pub const fn with_owner_limit(owner_limit: usize) -> Self {
        Self {
            table: LockTable::with_owner_limit(owner_limit),
            owners: [None; OWNERS],
            next_group: 1,
            next_sequence: 0,
        }
    }

    pub fn table(&self) -> &LockTable<N> {
        &self.table
    }

    /// A lock of another owner that `lock` would conflict with.
    pub fn conflict(&self, node: u64, owner: u64, lock: Lock) -> Option<crate::Held> {
        self.table.conflict(node, owner, lock)
    }

    pub fn is_waiting(&self, owner: u64) -> bool {
        self.record(owner)
            .is_some_and(|record| record.waiting.is_some())
    }

    fn record(&self, owner: u64) -> Option<&Owner> {
        self.owners
            .iter()
            .flatten()
            .find(|record| record.owner == owner)
    }

    fn group_of(&self, owner: u64) -> Option<u64> {
        self.record(owner).map(|record| record.group)
    }

    /// LOCK from `owner` on `node`; `token` comes back with a later grant.
    pub fn request(
        &mut self,
        owner: u64,
        node: u64,
        lock: Lock,
        flags: u32,
        group: u64,
        token: u64,
    ) -> Outcome {
        let index = match self
            .owners
            .iter()
            .position(|record| record.is_some_and(|record| record.owner == owner))
        {
            Some(index) => {
                let record = self.owners[index].expect("found above");
                if record.waiting.is_some() || (group != 0 && group != record.group) {
                    return Outcome::Invalid;
                }
                index
            }
            None => {
                let live = group == 0 || self.owners.iter().flatten().any(|r| r.group == group);
                if !live {
                    return Outcome::Invalid;
                }
                let Some(index) = self.owners.iter().position(Option::is_none) else {
                    return Outcome::NoRoom;
                };
                let group = if group == 0 {
                    let fresh = self.next_group;
                    self.next_group = fresh.wrapping_add(1).max(1);
                    fresh
                } else {
                    group
                };
                self.owners[index] = Some(Owner {
                    owner,
                    group,
                    waiting: None,
                });
                index
            }
        };
        let group = self.owners[index].expect("recorded above").group;
        match self.table.set(node, owner, lock) {
            Ok(()) => Outcome::Granted(group),
            Err(LockError::NoRoom) => Outcome::NoRoom,
            Err(LockError::Conflict) if flags & LOCK_WAIT == 0 => Outcome::Busy,
            Err(LockError::Conflict) => {
                if self.would_deadlock(group, node, owner, lock) {
                    return Outcome::Deadlock;
                }
                let sequence = self.next_sequence;
                self.next_sequence = sequence.wrapping_add(1);
                if let Some(record) = self.owners[index].as_mut() {
                    record.waiting = Some(Waiter {
                        node,
                        lock,
                        token,
                        sequence,
                    });
                }
                Outcome::Waiting
            }
        }
    }

    /// Whether `owner` (of `group`) waiting for `lock` on `node` would wait
    /// on its own group, directly or through other groups' waits.
    fn would_deadlock(&self, group: u64, node: u64, owner: u64, lock: Lock) -> bool {
        let mut seen = [0u64; OWNERS];
        let mut seen_count = 0;
        let mut pending = [0u64; OWNERS];
        let mut pending_count = 0;
        let push = |group: u64, seen: &[u64], pending: &mut [u64; OWNERS], count: &mut usize| {
            if !seen.contains(&group) && !pending[..*count].contains(&group) && *count < OWNERS {
                pending[*count] = group;
                *count += 1;
            }
        };
        for held in self.table.conflicts(node, owner, lock) {
            if let Some(holder) = self.group_of(held.owner) {
                push(
                    holder,
                    &seen[..seen_count],
                    &mut pending,
                    &mut pending_count,
                );
            }
        }
        while pending_count > 0 {
            pending_count -= 1;
            let next = pending[pending_count];
            if next == group {
                return true;
            }
            if seen_count == OWNERS {
                // More groups than owners cannot exist; refuse to wait
                // rather than walk without a bound.
                return true;
            }
            seen[seen_count] = next;
            seen_count += 1;
            for record in self.owners.iter().flatten() {
                let Some(waiter) = record.waiting.filter(|_| record.group == next) else {
                    continue;
                };
                for held in self.table.conflicts(waiter.node, record.owner, waiter.lock) {
                    if let Some(holder) = self.group_of(held.owner) {
                        push(
                            holder,
                            &seen[..seen_count],
                            &mut pending,
                            &mut pending_count,
                        );
                    }
                }
            }
        }
        false
    }

    /// The oldest waiting request that can now be answered: its owner, its
    /// token and its outcome ([`Outcome::Granted`] or [`Outcome::NoRoom`]).
    /// Call until `None` after anything that releases locks.
    pub fn take_granted(&mut self) -> Option<(u64, u64, Outcome)> {
        let mut order: [(u64, usize); OWNERS] = [(u64::MAX, usize::MAX); OWNERS];
        let mut count = 0;
        for (index, record) in self.owners.iter().enumerate() {
            if let Some(waiter) = record.and_then(|record| record.waiting) {
                order[count] = (waiter.sequence, index);
                count += 1;
            }
        }
        order[..count].sort_unstable();
        for &(_, index) in &order[..count] {
            let record = self.owners[index].expect("waiting owners are recorded");
            let waiter = record.waiting.expect("collected as waiting");
            let outcome = match self.table.set(waiter.node, record.owner, waiter.lock) {
                Ok(()) => Outcome::Granted(record.group),
                Err(LockError::NoRoom) => Outcome::NoRoom,
                Err(LockError::Conflict) => continue,
            };
            if let Some(record) = self.owners[index].as_mut() {
                record.waiting = None;
            }
            return Some((record.owner, waiter.token, outcome));
        }
        None
    }

    /// Forgets `owner`: its locks, its wait and its group membership.
    pub fn release(&mut self, owner: u64) {
        self.table.release(owner);
        for slot in &mut self.owners {
            if slot.is_some_and(|record| record.owner == owner) {
                *slot = None;
            }
        }
    }
}
