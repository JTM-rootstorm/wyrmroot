extern crate std;

use std::vec::Vec;

use wyrmroot_fs_proto::node::{Lock, LockMode};

use crate::{Held, LockError, LockTable};

fn lock(start: u64, length: u64, mode: LockMode) -> Lock {
    Lock {
        start,
        length,
        mode,
    }
}

fn held<const N: usize>(table: &LockTable<N>) -> Vec<(u64, u64, u64, u64, bool)> {
    let mut all: Vec<_> = table
        .iter()
        .map(|held| (held.node, held.owner, held.start, held.end, held.exclusive))
        .collect();
    all.sort_unstable();
    all
}

#[test]
fn locks_conflict_only_between_owners_and_only_with_an_exclusive_side() {
    let mut table = LockTable::<8>::new();
    table.set(1, 10, lock(0, 100, LockMode::Shared)).unwrap();
    table.set(1, 11, lock(50, 10, LockMode::Shared)).unwrap();
    assert_eq!(
        table.set(1, 11, lock(90, 20, LockMode::Exclusive)),
        Err(LockError::Conflict)
    );
    // Another node, the range past the lock, and the owner itself.
    table.set(2, 11, lock(0, 0, LockMode::Exclusive)).unwrap();
    table.set(1, 11, lock(100, 0, LockMode::Exclusive)).unwrap();
    table
        .set(1, 10, lock(0, 100, LockMode::Exclusive))
        .unwrap_err();
    assert_eq!(
        table.conflict(1, 10, lock(55, 1, LockMode::Shared)),
        None,
        "shared against shared"
    );
    assert_eq!(
        table.conflict(1, 12, lock(200, 1, LockMode::Shared)),
        Some(Held {
            node: 1,
            owner: 11,
            start: 100,
            end: u64::MAX,
            exclusive: true,
        })
    );
    assert_eq!(
        table
            .conflict(1, 12, lock(200, 1, LockMode::Shared))
            .unwrap()
            .lock(),
        lock(100, 0, LockMode::Exclusive)
    );
    table.release(11);
    assert_eq!(held(&table), [(1, 10, 0, 100, false)]);
    table.set(1, 10, lock(0, 100, LockMode::Exclusive)).unwrap();
    assert_eq!(held(&table), [(1, 10, 0, 100, true)]);
}

#[test]
fn an_owner_s_locks_replace_split_and_merge() {
    let mut table = LockTable::<8>::new();
    table.set(1, 10, lock(0, 100, LockMode::Shared)).unwrap();
    // Exclusive in the middle splits the shared lock in three.
    table.set(1, 10, lock(40, 20, LockMode::Exclusive)).unwrap();
    assert_eq!(
        held(&table),
        [
            (1, 10, 0, 40, false),
            (1, 10, 40, 60, true),
            (1, 10, 60, 100, false)
        ]
    );
    // Shared over the middle merges all three back.
    table.set(1, 10, lock(40, 20, LockMode::Shared)).unwrap();
    assert_eq!(held(&table), [(1, 10, 0, 100, false)]);
    // Unlocking the middle leaves two; touching ranges of one mode merge.
    table.set(1, 10, lock(10, 10, LockMode::Unlock)).unwrap();
    assert_eq!(
        held(&table),
        [(1, 10, 0, 10, false), (1, 10, 20, 100, false)]
    );
    table.set(1, 10, lock(100, 5, LockMode::Shared)).unwrap();
    table.set(1, 10, lock(10, 10, LockMode::Shared)).unwrap();
    assert_eq!(held(&table), [(1, 10, 0, 105, false)]);
    table.set(1, 10, lock(0, 0, LockMode::Unlock)).unwrap();
    assert_eq!(held(&table), []);
}

#[test]
fn a_change_that_does_not_fit_moves_nothing() {
    let mut table = LockTable::<2>::new();
    table.set(1, 10, lock(0, 100, LockMode::Shared)).unwrap();
    table.set(2, 10, lock(0, 1, LockMode::Shared)).unwrap();
    assert_eq!(
        table.set(1, 10, lock(40, 20, LockMode::Unlock)),
        Err(LockError::NoRoom)
    );
    assert_eq!(
        table.set(3, 10, lock(0, 1, LockMode::Shared)),
        Err(LockError::NoRoom)
    );
    assert_eq!(held(&table), [(1, 10, 0, 100, false), (2, 10, 0, 1, false)]);
    // Replacing in place needs no room.
    table.set(1, 10, lock(0, 100, LockMode::Exclusive)).unwrap();
    table.set(1, 10, lock(0, 40, LockMode::Unlock)).unwrap();
    assert_eq!(held(&table), [(1, 10, 40, 100, true), (2, 10, 0, 1, false)]);
}

/// Per byte and owner: 0 unlocked, 1 shared, 2 exclusive. Bytes 0..24 are
/// tracked one by one, and byte 24 stands for everything past them.
const BYTES: usize = 25;
const OWNERS: usize = 3;

#[test]
fn random_operations_match_a_byte_model() {
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut next = |bound: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % bound
    };
    for _ in 0..200 {
        let mut table = LockTable::<64>::new();
        let mut model = [[0u8; BYTES]; OWNERS];
        for _ in 0..60 {
            let owner = next(OWNERS as u64) as usize;
            let start = next(BYTES as u64 - 1);
            // Finite ranges stay inside the tracked bytes.
            let length = if next(4) == 0 {
                0
            } else {
                1 + next(8.min(24 - start))
            };
            let mode = match next(3) {
                0 => LockMode::Unlock,
                1 => LockMode::Shared,
                _ => LockMode::Exclusive,
            };
            let request = lock(start, length, mode);
            let end = if length == 0 {
                BYTES
            } else {
                (start + length) as usize
            };
            let bytes = start as usize..end;
            let conflicts = mode != LockMode::Unlock
                && (0..OWNERS).any(|other| {
                    other != owner
                        && bytes.clone().any(|byte| {
                            model[other][byte] == 2
                                || (mode == LockMode::Exclusive && model[other][byte] == 1)
                        })
                });
            let result = table.set(7, owner as u64, request);
            if conflicts {
                assert_eq!(result, Err(LockError::Conflict));
                continue;
            }
            result.unwrap();
            for byte in bytes {
                model[owner][byte] = mode as u8;
            }
            // The table holds exactly the model, as disjoint merged runs.
            for (owner, bytes) in model.iter().enumerate() {
                let mut runs: Vec<(u64, u64, bool)> = table
                    .iter()
                    .filter(|held| held.owner == owner as u64)
                    .map(|held| (held.start, held.end, held.exclusive))
                    .collect();
                runs.sort_unstable();
                let mut expected = Vec::new();
                let mut byte = 0;
                while byte < BYTES {
                    let mode = bytes[byte];
                    let from = byte;
                    while byte < BYTES && bytes[byte] == mode {
                        byte += 1;
                    }
                    if mode != 0 {
                        let end = if byte == BYTES { u64::MAX } else { byte as u64 };
                        expected.push((from as u64, end, mode == 2));
                    }
                }
                assert_eq!(runs, expected, "owner {owner}");
            }
        }
    }
}

#[test]
fn an_owner_s_limit_holds_however_the_change_splits() {
    let mut table = LockTable::<16>::with_owner_limit(2);
    table.set(1, 10, lock(0, 100, LockMode::Shared)).unwrap();
    table.set(2, 10, lock(0, 1, LockMode::Shared)).unwrap();
    // A split would make three; another owner still has room.
    assert_eq!(
        table.set(1, 10, lock(40, 20, LockMode::Unlock)),
        Err(LockError::NoRoom)
    );
    assert_eq!(
        table.set(3, 10, lock(0, 1, LockMode::Shared)),
        Err(LockError::NoRoom)
    );
    table.set(3, 11, lock(0, 1, LockMode::Shared)).unwrap();
    assert_eq!(held(&table).len(), 3);
    // Replacing in place stays within the limit.
    table.set(1, 10, lock(0, 0, LockMode::Exclusive)).unwrap();
    table.set(2, 10, lock(0, 0, LockMode::Unlock)).unwrap();
    table.set(3, 10, lock(0, 1, LockMode::Shared)).unwrap();
}

mod server {
    use wyrmroot_fs_proto::node::{LOCK_WAIT, Lock, LockMode};

    use super::lock;
    use crate::{LockServer, Outcome};

    type Server = LockServer<64, 8>;

    fn exclusive() -> Lock {
        lock(0, 0, LockMode::Exclusive)
    }

    // Owners are Channels; groups are the clients the caller names.
    const A: u64 = 100;
    const B: u64 = 200;
    const C: u64 = 300;

    #[test]
    fn a_waiting_lock_is_granted_in_arrival_order_when_the_holder_goes() {
        let mut server = Server::with_owner_limit(8);
        assert_eq!(
            server.request(1, A, 7, exclusive(), 0, 100),
            Outcome::Granted
        );
        assert_eq!(server.request(2, B, 7, exclusive(), 0, 200), Outcome::Busy);
        assert_eq!(
            server.request(2, B, 7, exclusive(), LOCK_WAIT, 201),
            Outcome::Waiting
        );
        assert_eq!(
            server.request(3, C, 7, exclusive(), LOCK_WAIT, 300),
            Outcome::Waiting
        );
        assert!(server.is_waiting(2));
        // A waiting owner's other requests are refused.
        assert_eq!(
            server.request(2, B, 8, exclusive(), 0, 202),
            Outcome::Invalid
        );
        assert_eq!(server.take_granted(), None);
        server.release(1);
        assert_eq!(server.take_granted(), Some((2, 201, Outcome::Granted)));
        assert_eq!(server.take_granted(), None);
        server.request(2, B, 7, lock(0, 0, LockMode::Unlock), 0, 203);
        assert_eq!(server.take_granted(), Some((3, 300, Outcome::Granted)));
        assert!(!server.is_waiting(3));
    }

    #[test]
    fn waiters_are_granted_by_arrival_not_by_slot() {
        let mut server = Server::with_owner_limit(8);
        // Owner 3 is recorded first, so it has the earlier slot.
        server.request(3, C, 9, lock(0, 0, LockMode::Unlock), 0, 0);
        server.request(1, A, 7, exclusive(), 0, 0);
        assert_eq!(
            server.request(2, B, 7, exclusive(), LOCK_WAIT, 20),
            Outcome::Waiting
        );
        assert_eq!(
            server.request(3, C, 7, exclusive(), LOCK_WAIT, 30),
            Outcome::Waiting
        );
        server.release(1);
        assert_eq!(server.take_granted(), Some((2, 20, Outcome::Granted)));
    }

    #[test]
    fn two_clients_waiting_for_each_other_are_refused_the_second_wait() {
        // Client A holds file 1 and waits for file 2; client B holds file 2
        // and asks to wait for file 1, each through one Channel per file.
        let mut server = Server::with_owner_limit(8);
        assert_eq!(
            server.request(10, A, 1, exclusive(), 0, 0),
            Outcome::Granted
        );
        assert_eq!(
            server.request(20, B, 2, exclusive(), 0, 0),
            Outcome::Granted
        );
        assert_eq!(
            server.request(11, A, 2, exclusive(), LOCK_WAIT, 1),
            Outcome::Waiting
        );
        assert_eq!(
            server.request(21, B, 1, exclusive(), LOCK_WAIT, 2),
            Outcome::Deadlock
        );
        // A wait that closes no cycle still waits.
        assert_eq!(
            server.request(30, C, 1, exclusive(), LOCK_WAIT, 3),
            Outcome::Waiting
        );
    }

    #[test]
    fn a_cycle_through_a_third_client_is_found() {
        let mut server = Server::with_owner_limit(8);
        server.request(10, A, 1, exclusive(), 0, 0);
        server.request(20, B, 2, exclusive(), 0, 0);
        server.request(30, C, 3, exclusive(), 0, 0);
        assert_eq!(
            server.request(11, A, 2, exclusive(), LOCK_WAIT, 0),
            Outcome::Waiting
        );
        assert_eq!(
            server.request(21, B, 3, exclusive(), LOCK_WAIT, 0),
            Outcome::Waiting
        );
        assert_eq!(
            server.request(31, C, 1, exclusive(), LOCK_WAIT, 0),
            Outcome::Deadlock
        );
    }

    #[test]
    fn waiting_on_one_s_own_client_is_a_deadlock() {
        // A process's description lock blocks its own classic lock: Linux
        // waits for ever, this refuses.
        let mut server = Server::with_owner_limit(8);
        assert_eq!(
            server.request(10, A, 1, exclusive(), 0, 0),
            Outcome::Granted
        );
        assert_eq!(
            server.request(11, A, 1, exclusive(), LOCK_WAIT, 0),
            Outcome::Deadlock
        );
    }

    #[test]
    fn a_cycle_closed_by_a_grant_ends_a_wait_at_the_next_pass() {
        let mut server = Server::with_owner_limit(8);
        assert_eq!(
            server.request(20, B, 2, exclusive(), 0, 0),
            Outcome::Granted
        );
        // A waits for B.
        assert_eq!(
            server.request(11, A, 2, exclusive(), LOCK_WAIT, 1),
            Outcome::Waiting
        );
        // B waits for file 3, which only C holds: no cycle yet.
        assert_eq!(
            server.request(30, C, 3, lock(0, 10, LockMode::Shared), 0, 0),
            Outcome::Granted
        );
        assert_eq!(
            server.request(22, B, 3, exclusive(), LOCK_WAIT, 2),
            Outcome::Waiting
        );
        // A takes a shared lock B's wait now also needs, without waiting:
        // B now waits for A, which waits for B.
        assert_eq!(
            server.request(12, A, 3, lock(20, 10, LockMode::Shared), 0, 3),
            Outcome::Granted
        );
        // The oldest waiter in the cycle is refused, which breaks it.
        assert_eq!(server.take_granted(), Some((11, 1, Outcome::Deadlock)));
        assert!(server.is_waiting(22), "B still waits, now only for C and A");
        assert_eq!(server.take_granted(), None);
    }

    #[test]
    fn an_owner_keeps_the_group_it_was_first_recorded_with() {
        let mut server = Server::with_owner_limit(8);
        assert_eq!(
            server.request(10, A, 1, exclusive(), 0, 0),
            Outcome::Granted
        );
        // A later request naming another group does not move it.
        assert_eq!(
            server.request(20, B, 2, exclusive(), 0, 0),
            Outcome::Granted
        );
        assert_eq!(
            server.request(10, B, 2, exclusive(), LOCK_WAIT, 0),
            Outcome::Waiting
        );
        assert_eq!(
            server.request(21, B, 1, exclusive(), LOCK_WAIT, 0),
            Outcome::Deadlock
        );
    }
}
