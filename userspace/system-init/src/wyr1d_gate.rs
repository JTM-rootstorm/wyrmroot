//! Selector32 trusted ordering and WRD1 encoding. Native callers establish
//! driver custody and JobV2 readiness before supplying a console status.

use wyrmroot_consoled::selector32::{Error, OBSERVED, READY, Status, Tuple, fnv, response};
use wyrmroot_device_proto::d5_controller::{
    D5ControllerMessage, D5DrainIdentity, D5DriverIdentity, RECORD_BYTES, encode,
};

pub const GATE_PATH: &str = "system/bootstrap/wyr1-d5-gate-v1";

/// The two independent retirement facts join before a single rebind claim.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RetirementJoin {
    driver: D5DriverIdentity,
    deadline: u64,
    retired: bool,
    released: bool,
    claimed: bool,
}

impl RetirementJoin {
    pub(crate) fn new(driver: D5DriverIdentity, now: u64, timeout: u64) -> Result<Self, Error> {
        encode(
            D5ControllerMessage::RequestRetire(driver),
            &mut [0; RECORD_BYTES],
        )
        .map_err(|_| Error)?;
        let deadline = now.checked_add(timeout).filter(|v| *v > now).ok_or(Error)?;
        Ok(Self {
            driver,
            deadline,
            retired: false,
            released: false,
            claimed: false,
        })
    }

    pub(crate) fn observe_retired(&mut self, driver: D5DriverIdentity) -> Result<(), Error> {
        if driver != self.driver || self.retired || self.claimed {
            return Err(Error);
        }
        self.retired = true;
        Ok(())
    }

    pub(crate) fn release_sent(&mut self, driver: D5DriverIdentity) -> Result<(), Error> {
        if driver != self.driver || self.released || self.claimed {
            return Err(Error);
        }
        self.released = true;
        Ok(())
    }

    pub(crate) fn claim_rebind(&mut self, now: u64) -> Result<bool, Error> {
        if self.claimed {
            return Ok(false);
        }
        if now >= self.deadline {
            return Err(Error);
        }
        if !self.retired || !self.released {
            return Ok(false);
        }
        self.claimed = true;
        Ok(true)
    }
}

pub fn parse_config(bytes: &[u8]) -> Result<u64, Error> {
    let text = core::str::from_utf8(bytes).map_err(|_| Error)?;
    let mut lines = text.lines();
    for expected in [
        "schema = 1",
        "selector = \"native-console-streams\"",
        "test_id = 32",
        "evidence_protocol = \"WRD1\"",
    ] {
        if lines.next() != Some(expected) {
            return Err(Error);
        }
    }
    let hex = lines
        .next()
        .and_then(|s| s.strip_prefix("nonce = \""))
        .and_then(|s| s.strip_suffix('"'))
        .ok_or(Error)?;
    if hex.len() != 16
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
        || lines.next().is_some()
    {
        return Err(Error);
    }
    let nonce = u64::from_str_radix(hex, 16).map_err(|_| Error)?;
    if nonce == 0 {
        return Err(Error);
    }
    Ok(nonce)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Batch {
    pub records: [[u8; 192]; 5],
    pub count: usize,
    pub ready: Option<[u8; 178]>,
    pub retire_driver: bool,
}

impl Batch {
    const fn new() -> Self {
        Self {
            records: [[0; 192]; 5],
            count: 0,
            ready: None,
            retire_driver: false,
        }
    }
}

/// One withheld observation. Neither retirement nor terminal publication may
/// consume its batch until the exact requested UART drain has completed.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DrainFence {
    identity: D5DrainIdentity,
    batch: Batch,
    requested: bool,
}

impl DrainFence {
    pub(crate) fn new(
        driver: D5DriverIdentity,
        status: Status,
        batch: Batch,
    ) -> Result<Self, Error> {
        let (record, target) = match status.leg {
            2 => (8u32, 45),
            4 => (12u32, 46),
            _ => return Err(Error),
        };
        if status.kind != OBSERVED
            || batch.count != 1
            || batch.ready.is_some()
            || batch.retire_driver != (status.leg == 2)
            || batch.records[0][8..12] != record.to_le_bytes()
            || status.tuple.role != driver.device_role_id
            || status.tuple.bundle != driver.bundle_generation
            || status.tuple.attempt != driver.driver_attempt_generation
            || status.tuple.endpoint != driver.driver_control_endpoint_id
            || status.tuple.endpoint_generation != driver.driver_control_endpoint_generation
        {
            return Err(Error);
        }
        let identity = D5DrainIdentity {
            driver,
            attach_transaction_id: status.tuple.transaction,
            stream_generation: status.tuple.stream,
            target_tx_bytes: target,
            leg: status.leg,
        };
        encode(
            D5ControllerMessage::RequestDrain(identity),
            &mut [0; RECORD_BYTES],
        )
        .map_err(|_| Error)?;
        Ok(Self {
            identity,
            batch,
            requested: false,
        })
    }

    pub(crate) fn request(&self) -> Result<D5ControllerMessage, Error> {
        if self.requested {
            return Err(Error);
        }
        Ok(D5ControllerMessage::RequestDrain(self.identity))
    }

    pub(crate) fn mark_requested(&mut self) -> Result<(), Error> {
        self.request()?;
        self.requested = true;
        Ok(())
    }

    pub(crate) fn completed(&self, identity: D5DrainIdentity) -> Result<&Batch, Error> {
        if !self.requested || identity != self.identity {
            return Err(Error);
        }
        Ok(&self.batch)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Gate {
    nonce: u64,
    status_sequence: u64,
    records: u32,
    tuple: Tuple,
    job: u64,
    publication: u64,
    client_transaction: u64,
}

impl Gate {
    pub fn new(nonce: u64) -> Result<Self, Error> {
        if nonce == 0 {
            return Err(Error);
        }
        Ok(Self {
            nonce,
            status_sequence: 0,
            records: 0,
            tuple: Tuple::default(),
            job: 0,
            publication: 0,
            client_transaction: 0,
        })
    }
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }
    pub const fn job(&self) -> u64 {
        self.job
    }
    pub const fn tuple(&self) -> Tuple {
        self.tuple
    }
    pub const fn record_count(&self) -> u32 {
        self.records
    }

    /// `old_clean` comes from actual driver reaping and absence of the previous
    /// child in the retained JobDispatcher, never from a console assertion.
    pub fn accept(&mut self, status: Status, old_clean: bool) -> Result<Batch, Error> {
        status.encode()?;
        if status.nonce != self.nonce || status.sequence != self.status_sequence + 1 {
            return Err(Error);
        }
        let mut next = *self;
        let mut batch = Batch::new();
        match (self.records, status.kind) {
            (0, READY) => {
                next.tuple = status.tuple;
                next.job = status.job;
                next.publication = status.publication;
                next.client_transaction = status.client_transaction;
                next.push(&mut batch, 1, 0, None)?;
                next.push(&mut batch, 2, 0, None)?;
                batch.ready = Some(ready_line(self.nonce, status.tuple));
            }
            (2, OBSERVED) => {
                self.observation(status, 1)?;
                next.push(&mut batch, 3, status.rx, None)?;
                next.push(&mut batch, 4, status.tx, None)?;
                next.push(&mut batch, 5, 0, None)?;
                next.push(&mut batch, 6, 0, None)?;
                next.push(&mut batch, 7, status.value, None)?;
            }
            (7, OBSERVED) => {
                self.observation(status, 2)?;
                next.push(&mut batch, 8, status.value, None)?;
                batch.retire_driver = true;
            }
            (8, READY) => {
                let old = self.tuple;
                let new = status.tuple;
                if !old_clean
                    || status.job == self.job
                    || new.role != old.role
                    || new.bundle != old.bundle
                    || new.attempt <= old.attempt
                    || (new.endpoint, new.endpoint_generation)
                        == (old.endpoint, old.endpoint_generation)
                    || new.transaction <= old.transaction
                    || new.stream <= old.stream
                    || new.console <= old.console
                    || new.child <= old.child
                {
                    return Err(Error);
                }
                if status.publication <= self.publication
                    || status.client_transaction <= self.client_transaction
                {
                    return Err(Error);
                }
                next.tuple = new;
                next.job = status.job;
                next.publication = status.publication;
                next.client_transaction = status.client_transaction;
                next.push(&mut batch, 9, 0, Some(old))?;
                batch.ready = Some(ready_line(self.nonce, new));
            }
            (9, OBSERVED) => {
                self.observation(status, 3)?;
                next.push(&mut batch, 10, status.value, None)?;
            }
            (10, READY) => {
                let mut old = self.tuple;
                let new = status.tuple;
                if !old_clean
                    || status.job == self.job
                    || new.child <= old.child
                    || status.publication != self.publication
                    || status.client_transaction != self.client_transaction
                {
                    return Err(Error);
                }
                old.child = new.child;
                if old != new {
                    return Err(Error);
                }
                next.tuple = new;
                next.job = status.job;
                next.push(&mut batch, 11, 0, Some(self.tuple))?;
                batch.ready = Some(ready_line(self.nonce, new));
            }
            (11, OBSERVED) => {
                self.observation(status, 4)?;
                next.push(&mut batch, 12, status.value, None)?;
            }
            _ => return Err(Error),
        }
        next.status_sequence = status.sequence;
        *self = next;
        Ok(batch)
    }

    fn observation(&self, status: Status, leg: u64) -> Result<(), Error> {
        let (bytes, len) = response(self.nonce, leg, self.tuple);
        if status.tuple != self.tuple
            || status.job != self.job
            || status.leg != leg
            || status.value != fnv(&bytes[..len])
            || status.publication != self.publication
            || status.client_transaction != self.client_transaction
        {
            return Err(Error);
        }
        Ok(())
    }

    fn push(
        &mut self,
        batch: &mut Batch,
        kind: u32,
        value: u64,
        previous: Option<Tuple>,
    ) -> Result<(), Error> {
        if self.records + 1 != kind || batch.count >= batch.records.len() {
            return Err(Error);
        }
        let mut bytes = [0; 192];
        bytes[..4].copy_from_slice(b"WRD1");
        bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
        bytes[8..12].copy_from_slice(&kind.to_le_bytes());
        bytes[16..20].copy_from_slice(&192u32.to_le_bytes());
        put(&mut bytes, 24, u64::from(kind));
        put(&mut bytes, 32, self.nonce);
        let mut current = self.tuple;
        if kind == 1 {
            current.stream = 0;
        }
        if kind <= 4 {
            current.console = 0;
        }
        if kind <= 5 {
            current.child = 0;
        }
        for (i, value) in current.words().into_iter().enumerate() {
            put(&mut bytes, 40 + i * 8, value);
        }
        if let Some(old) = previous {
            for (i, value) in old.words()[1..].iter().copied().enumerate() {
                put(&mut bytes, 112 + i * 8, value);
            }
        }
        put(&mut bytes, 176, value);
        batch.records[batch.count] = bytes;
        batch.count += 1;
        self.records = kind;
        Ok(())
    }
}

fn put(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub fn ready_line(nonce: u64, tuple: Tuple) -> [u8; 178] {
    let mut out = [0; 178];
    out[..8].copy_from_slice(b"D5READY|");
    let mut words = [0; 10];
    words[0] = nonce;
    words[1..].copy_from_slice(&tuple.words());
    for (i, value) in words.into_iter().enumerate() {
        for digit in 0..16 {
            out[8 + i * 17 + digit] =
                b"0123456789ABCDEF"[((value >> ((15 - digit) * 4)) & 15) as usize];
        }
        out[8 + i * 17 + 16] = if i == 9 { b'\n' } else { b'|' };
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retirement_joins_both_orders_before_one_rebind_and_bounds_missing_facts() {
        let driver = D5DriverIdentity {
            device_role_id: 1,
            bundle_generation: 2,
            driver_attempt_generation: 3,
            driver_control_endpoint_id: 4,
            driver_control_endpoint_generation: 1,
            launch_transaction_id: 6,
        };
        for release_first in [false, true] {
            let mut join = RetirementJoin::new(driver, 100, 100).unwrap();
            let wrong = D5DriverIdentity {
                driver_attempt_generation: 4,
                ..driver
            };
            assert!(join.observe_retired(wrong).is_err());
            assert!(join.release_sent(wrong).is_err());
            assert!(!join.claim_rebind(110).unwrap());
            if release_first {
                join.release_sent(driver).unwrap();
            } else {
                join.observe_retired(driver).unwrap();
            }
            // Multiple job/control ticks can run while the other channel's
            // exact fact has not arrived; none starts synchronous rebind.
            for now in 111..150 {
                assert!(!join.claim_rebind(now).unwrap());
            }
            if release_first {
                join.observe_retired(driver).unwrap();
            } else {
                join.release_sent(driver).unwrap();
            }
            assert!(join.claim_rebind(150).unwrap());
            assert!(!join.claim_rebind(151).unwrap());
            assert!(!join.claim_rebind(300).unwrap());
            assert!(join.observe_retired(driver).is_err());
            assert!(join.release_sent(driver).is_err());
        }
        let mut expired = RetirementJoin::new(driver, 100, 100).unwrap();
        expired.observe_retired(driver).unwrap();
        assert!(expired.claim_rebind(200).is_err());
        assert!(RetirementJoin::new(driver, u64::MAX, 1).is_err());
        assert!(RetirementJoin::new(driver, 100, 0).is_err());
    }

    fn tuple() -> Tuple {
        Tuple {
            role: 1,
            bundle: 2,
            attempt: 3,
            endpoint: 4,
            endpoint_generation: 1,
            transaction: 6,
            stream: 7,
            console: 8,
            child: 9,
        }
    }
    fn ready(sequence: u64, t: Tuple, job: u64) -> Status {
        Status {
            kind: READY,
            sequence,
            nonce: 42,
            tuple: t,
            job,
            rx: 0,
            tx: 0,
            leg: 0,
            value: 0,
            publication: t.stream + 100,
            client_transaction: t.stream + 200,
        }
    }
    fn observation(sequence: u64, leg: u64, t: Tuple, job: u64) -> Status {
        let (bytes, len) = response(42, leg, t);
        Status {
            kind: OBSERVED,
            sequence,
            nonce: 42,
            tuple: t,
            job,
            rx: len as u64,
            tx: len as u64,
            leg,
            value: fnv(&bytes[..len]),
            publication: t.stream + 100,
            client_transaction: t.stream + 200,
        }
    }
    #[test]
    fn complete_chain_requires_old_cleanup_and_exact_channel_hash() {
        let mut gate = Gate::new(42).unwrap();
        let first = tuple();
        assert_eq!(gate.accept(ready(1, first, 1), false).unwrap().count, 2);
        let before = gate;
        assert!(gate.accept(observation(2, 2, first, 1), false).is_err());
        assert_eq!(gate, before);
        assert_eq!(
            gate.accept(observation(2, 1, first, 1), false)
                .unwrap()
                .count,
            5
        );
        assert!(
            gate.accept(observation(3, 2, first, 1), false)
                .unwrap()
                .retire_driver
        );
        let second = Tuple {
            attempt: 13,
            endpoint: 14,
            transaction: 16,
            stream: 17,
            console: 18,
            child: 19,
            ..first
        };
        assert!(gate.accept(ready(4, second, 2), false).is_err());
        let before = gate;
        for invalid in [
            Tuple {
                bundle: first.bundle + 1,
                ..second
            },
            Tuple {
                endpoint: first.endpoint,
                endpoint_generation: first.endpoint_generation,
                ..second
            },
            Tuple {
                transaction: first.transaction,
                ..second
            },
        ] {
            assert!(gate.accept(ready(4, invalid, 2), true).is_err());
            assert_eq!(gate, before);
        }
        assert_eq!(gate.accept(ready(4, second, 2), true).unwrap().count, 1);
        gate.accept(observation(5, 3, second, 2), false).unwrap();
        let third = Tuple {
            child: 20,
            ..second
        };
        let before = gate;
        assert!(
            gate.accept(
                ready(
                    6,
                    Tuple {
                        transaction: third.transaction + 1,
                        ..third
                    },
                    3
                ),
                true
            )
            .is_err()
        );
        assert_eq!(gate, before);
        gate.accept(ready(6, third, 3), true).unwrap();
        gate.accept(observation(7, 4, third, 3), false).unwrap();
        assert_eq!(gate.record_count(), 12);
        assert!(gate.accept(observation(8, 4, third, 3), false).is_err());
    }
    #[test]
    fn ready_and_certificate_use_attach_transaction() {
        let t = tuple();
        let mut gate = Gate::new(42).unwrap();
        let batch = gate.accept(ready(1, t, 1), false).unwrap();
        assert_eq!(&batch.records[0][80..88], &t.transaction.to_le_bytes());
        let line = batch.ready.unwrap();
        assert_eq!(line.len(), 178);
        assert_eq!(&line[110..126], b"0000000000000006");
        let mut different = t;
        different.transaction = 99;
        assert!(gate.accept(observation(2, 1, different, 1), false).is_err());
    }
    #[test]
    fn config_rejects_extra_zero_and_lowercase() {
        let valid=b"schema = 1\nselector = \"native-console-streams\"\ntest_id = 32\nevidence_protocol = \"WRD1\"\nnonce = \"000000000000002A\"\n";
        assert_eq!(parse_config(valid), Ok(42));
        let mut bad = *valid;
        bad[valid.len() - 3] = b'a';
        assert!(parse_config(&bad).is_err());
        assert!(parse_config(b"schema = 1").is_err());
    }

    fn driver(t: Tuple) -> D5DriverIdentity {
        D5DriverIdentity {
            device_role_id: t.role,
            bundle_generation: t.bundle,
            driver_attempt_generation: t.attempt,
            driver_control_endpoint_id: t.endpoint,
            driver_control_endpoint_generation: t.endpoint_generation,
            launch_transaction_id: 100 + t.attempt,
        }
    }

    #[test]
    fn full_sequence_withholds_retire_and_terminal_until_exact_requested_drain() {
        let first = tuple();
        let second = Tuple {
            attempt: first.attempt + 1,
            endpoint: first.endpoint + 1,
            transaction: first.transaction + 1,
            stream: first.stream + 1,
            console: first.console + 1,
            child: first.child + 1,
            ..first
        };
        let third = Tuple {
            child: second.child + 1,
            ..second
        };
        let mut gate = Gate::new(42).unwrap();
        let mut published = 0;
        let mut retirements = 0;
        for (status, old_clean) in [
            (ready(1, first, 1), false),
            (observation(2, 1, first, 1), false),
            (observation(3, 2, first, 1), false),
            (ready(4, second, 2), true),
            (observation(5, 3, second, 2), false),
            (ready(6, third, 3), true),
            (observation(7, 4, third, 3), false),
        ] {
            let batch = gate.accept(status, old_clean).unwrap();
            if matches!(status.leg, 2 | 4) {
                assert_eq!(published, if status.leg == 2 { 7 } else { 11 });
                let mut fence = DrainFence::new(driver(status.tuple), status, batch).unwrap();
                let D5ControllerMessage::RequestDrain(identity) = fence.request().unwrap() else {
                    panic!()
                };
                assert_eq!(identity.attach_transaction_id, status.tuple.transaction);
                assert_ne!(
                    identity.attach_transaction_id,
                    identity.driver.launch_transaction_id
                );
                assert_eq!(
                    identity.target_tx_bytes,
                    if status.leg == 2 { 45 } else { 46 }
                );
                assert!(fence.completed(identity).is_err());
                assert_eq!(retirements, if status.leg == 2 { 0 } else { 1 });
                fence.mark_requested().unwrap();
                assert!(fence.request().is_err());
                assert!(fence.mark_requested().is_err());
                for stale in [
                    D5DrainIdentity {
                        attach_transaction_id: identity.attach_transaction_id + 1,
                        ..identity
                    },
                    D5DrainIdentity {
                        stream_generation: identity.stream_generation + 1,
                        ..identity
                    },
                    D5DrainIdentity {
                        target_tx_bytes: identity.target_tx_bytes + 1,
                        ..identity
                    },
                    D5DrainIdentity {
                        leg: identity.leg + 1,
                        ..identity
                    },
                    D5DrainIdentity {
                        driver: D5DriverIdentity {
                            launch_transaction_id: identity.driver.launch_transaction_id + 1,
                            ..identity.driver
                        },
                        ..identity
                    },
                ] {
                    assert!(fence.completed(stale).is_err());
                }
                let committed = fence.completed(identity).unwrap();
                published += committed.count;
                retirements += usize::from(committed.retire_driver);
            } else {
                published += batch.count;
                assert!(!batch.retire_driver);
            }
        }
        assert_eq!(published, 12);
        assert_eq!(retirements, 1);
    }
}
