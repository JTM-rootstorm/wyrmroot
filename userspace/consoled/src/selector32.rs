//! Fixed selector-private console status and exact stream observation.

pub const STATUS_BYTES: usize = 176;
pub const CONFIGURE: u32 = 1;
pub const READY: u32 = 2;
pub const OBSERVED: u32 = 3;
pub const RELEASED: u32 = 4;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Tuple {
    pub role: u64,
    pub bundle: u64,
    pub attempt: u64,
    pub endpoint: u64,
    pub endpoint_generation: u64,
    pub transaction: u64,
    pub stream: u64,
    pub console: u64,
    pub child: u64,
}

impl Tuple {
    pub fn words(self) -> [u64; 9] {
        [
            self.role,
            self.bundle,
            self.attempt,
            self.endpoint,
            self.endpoint_generation,
            self.transaction,
            self.stream,
            self.console,
            self.child,
        ]
    }

    pub fn complete(self) -> bool {
        self.words().iter().all(|v| *v != 0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    pub kind: u32,
    pub sequence: u64,
    pub nonce: u64,
    pub tuple: Tuple,
    pub job: u64,
    pub rx: u64,
    pub tx: u64,
    pub leg: u64,
    pub value: u64,
    pub publication: u64,
    pub client_transaction: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error;

impl Status {
    pub fn configure(nonce: u64) -> Self {
        Self {
            kind: CONFIGURE,
            sequence: 1,
            nonce,
            tuple: Tuple::default(),
            job: 0,
            rx: 0,
            tx: 0,
            leg: 0,
            value: 0,
            publication: 0,
            client_transaction: 0,
        }
    }

    fn valid(self) -> bool {
        if self.nonce == 0 {
            return false;
        }
        if self.kind == RELEASED {
            return self.sequence == 0
                && self.tuple.complete()
                && self.job != 0
                && self.publication != 0
                && self.client_transaction != 0
                && self.rx == 0
                && self.tx == 0
                && self.leg == 0
                && self.value == 0;
        }
        if self.sequence == 0 {
            return false;
        }
        match self.kind {
            CONFIGURE => self == Self::configure(self.nonce),
            READY => {
                self.tuple.complete()
                    && self.job != 0
                    && self.publication != 0
                    && self.client_transaction != 0
                    && self.rx == 0
                    && self.tx == 0
                    && self.leg == 0
                    && self.value == 0
            }
            OBSERVED => {
                self.tuple.complete()
                    && self.job != 0
                    && self.publication != 0
                    && self.client_transaction != 0
                    && (1..=4).contains(&self.leg)
                    && self.rx == if self.leg == 2 { 22 } else { 23 }
                    && self.tx == if self.leg == 2 { 22 } else { 23 }
            }
            _ => false,
        }
    }

    pub fn encode(self) -> Result<[u8; STATUS_BYTES], Error> {
        if !self.valid() {
            return Err(Error);
        }
        let mut bytes = [0; STATUS_BYTES];
        bytes[..4].copy_from_slice(b"D5CS");
        bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.kind.to_le_bytes());
        bytes[16..20].copy_from_slice(&(STATUS_BYTES as u32).to_le_bytes());
        put(&mut bytes, 24, self.sequence);
        put(&mut bytes, 32, self.nonce);
        for (i, word) in self.tuple.words().into_iter().enumerate() {
            put(&mut bytes, 40 + i * 8, word);
        }
        for (i, word) in [self.job, self.rx, self.tx, self.leg, self.value]
            .into_iter()
            .enumerate()
        {
            put(&mut bytes, 112 + i * 8, word);
        }
        put(&mut bytes, 152, self.publication);
        put(&mut bytes, 160, self.client_transaction);
        Ok(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != STATUS_BYTES
            || &bytes[..4] != b"D5CS"
            || bytes[4..8] != [1, 0, 0, 0]
            || bytes[12..16] != [0; 4]
            || bytes[16..20] != (STATUS_BYTES as u32).to_le_bytes()
            || bytes[20..24] != [0; 4]
            || bytes[168..] != [0; 8]
        {
            return Err(Error);
        }
        let s = Self {
            kind: u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| Error)?),
            sequence: get(bytes, 24),
            nonce: get(bytes, 32),
            tuple: Tuple {
                role: get(bytes, 40),
                bundle: get(bytes, 48),
                attempt: get(bytes, 56),
                endpoint: get(bytes, 64),
                endpoint_generation: get(bytes, 72),
                transaction: get(bytes, 80),
                stream: get(bytes, 88),
                console: get(bytes, 96),
                child: get(bytes, 104),
            },
            job: get(bytes, 112),
            rx: get(bytes, 120),
            tx: get(bytes, 128),
            leg: get(bytes, 136),
            value: get(bytes, 144),
            publication: get(bytes, 152),
            client_transaction: get(bytes, 160),
        };
        if s.valid() { Ok(s) } else { Err(Error) }
    }
}

fn put(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn get(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

pub fn fnv(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
    })
}

pub fn challenge(nonce: u64, leg: u64, t: Tuple) -> [u8; 16] {
    let mut bytes = [0; 64];
    for (i, v) in [
        nonce, 32, leg, t.bundle, t.attempt, t.stream, t.console, t.child,
    ]
    .into_iter()
    .enumerate()
    {
        put(&mut bytes, i * 8, v);
    }
    let value = fnv(&bytes);
    let mut out = [0; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = b"0123456789ABCDEF"[((value >> ((15 - i) * 4)) & 15) as usize];
    }
    out
}

pub fn response(nonce: u64, leg: u64, tuple: Tuple) -> ([u8; 23], usize) {
    let mut bytes = [0; 23];
    let prefix: &[u8] = if leg == 2 { b"err " } else { b"pong " };
    bytes[..prefix.len()].copy_from_slice(prefix);
    bytes[prefix.len()..prefix.len() + 16].copy_from_slice(&challenge(nonce, leg, tuple));
    bytes[prefix.len() + 16..prefix.len() + 18].copy_from_slice(b"\r\n");
    (bytes, prefix.len() + 18)
}

/// Each byte is checked when crossing its actual native stream boundary.
/// Reporting waits for both the channel-specific child payload and raw TX commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capture {
    nonce: u64,
    sequence: u64,
    tuple: Tuple,
    job: u64,
    leg: u64,
    rx: usize,
    child: usize,
    tx: usize,
    exit: usize,
    publication: u64,
    client_transaction: u64,
}

impl Capture {
    pub fn new(nonce: u64) -> Result<Self, Error> {
        if nonce == 0 {
            return Err(Error);
        }
        Ok(Self {
            nonce,
            sequence: 0,
            tuple: Tuple::default(),
            job: 0,
            leg: 0,
            rx: 0,
            child: 0,
            tx: 0,
            exit: 0,
            publication: 0,
            client_transaction: 0,
        })
    }

    pub fn ready(
        &mut self,
        tuple: Tuple,
        job: u64,
        publication: u64,
        client_transaction: u64,
    ) -> Result<Option<Status>, Error> {
        if tuple == self.tuple && job == self.job {
            return Ok(None);
        }
        let leg = if self.sequence == 0 {
            1
        } else if self.leg == 3
            && tuple.stream != self.tuple.stream
            && tuple.console > self.tuple.console
            && tuple.child > self.tuple.child
        {
            3
        } else if self.leg == 4
            && tuple.stream == self.tuple.stream
            && tuple.console == self.tuple.console
            && tuple.child > self.tuple.child
            && self.exit == 6
        {
            4
        } else {
            return Err(Error);
        };
        self.tuple = tuple;
        self.job = job;
        self.leg = leg;
        self.publication = publication;
        self.client_transaction = client_transaction;
        self.rx = 0;
        self.child = 0;
        self.tx = 0;
        self.exit = 0;
        self.sequence = self.sequence.checked_add(1).ok_or(Error)?;
        let status = Status {
            kind: READY,
            sequence: self.sequence,
            nonce: self.nonce,
            tuple,
            job,
            rx: 0,
            tx: 0,
            leg: 0,
            value: 0,
            publication,
            client_transaction,
        };
        if !status.valid() {
            return Err(Error);
        }
        Ok(Some(status))
    }

    pub fn raw_rx(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.leg == 4 && self.tx != 0 {
            return compare(b"exit\r\n", &mut self.exit, bytes);
        }
        let (mut expected, len) = response(self.nonce, self.leg, self.tuple);
        if self.leg != 2 {
            expected[..5].copy_from_slice(b"ping ");
        }
        compare(&expected[..len], &mut self.rx, bytes)
    }

    pub fn child_output(&mut self, stderr: bool, bytes: &[u8]) -> Result<(), Error> {
        if stderr != (self.leg == 2) {
            return Err(Error);
        }
        let (mut expected, len) = response(self.nonce, self.leg, self.tuple);
        expected[len - 2] = b'\n';
        compare(&expected[..len - 1], &mut self.child, bytes)
    }

    pub fn raw_tx(&mut self, bytes: &[u8]) -> Result<Option<Status>, Error> {
        let (expected, len) = response(self.nonce, self.leg, self.tuple);
        compare(&expected[..len], &mut self.tx, bytes)?;
        if self.tx != len {
            return Ok(None);
        }
        if self.rx != len || self.child != len - 1 {
            return Err(Error);
        }
        self.sequence = self.sequence.checked_add(1).ok_or(Error)?;
        let status = Status {
            kind: OBSERVED,
            sequence: self.sequence,
            nonce: self.nonce,
            tuple: self.tuple,
            job: self.job,
            rx: self.rx as u64,
            tx: self.tx as u64,
            leg: self.leg,
            value: fnv(&expected[..len]),
            publication: self.publication,
            client_transaction: self.client_transaction,
        };
        self.leg += 1;
        if self.leg == 2 {
            self.rx = 0;
            self.child = 0;
            self.tx = 0;
        }
        Ok(Some(status))
    }
}

fn compare(expected: &[u8], used: &mut usize, bytes: &[u8]) -> Result<(), Error> {
    let end = used.checked_add(bytes.len()).ok_or(Error)?;
    if bytes.is_empty() || expected.get(*used..end) != Some(bytes) {
        return Err(Error);
    }
    *used = end;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tuple() -> Tuple {
        Tuple {
            role: 1,
            bundle: 2,
            attempt: 3,
            endpoint: 4,
            endpoint_generation: 5,
            transaction: 6,
            stream: 7,
            console: 8,
            child: 9,
        }
    }
    #[test]
    fn codec_rejects_reserved_trailing_unknown_and_zero() {
        let s = Status::configure(42);
        let good = s.encode().unwrap();
        assert_eq!(Status::parse(&good), Ok(s));
        for i in [6, 12, 20, 168] {
            let mut b = good;
            b[i] = 1;
            assert_eq!(Status::parse(&b), Err(Error));
        }
        assert!(Status::configure(0).encode().is_err());
        assert!(Status::parse(&good[..159]).is_err());
    }
    #[test]
    fn capture_requires_exact_channel_raw_commit_and_input() {
        let mut c = Capture::new(42).unwrap();
        let t = tuple();
        assert!(c.ready(t, 1, 10, 11).unwrap().is_some());
        let (response, len) = response(42, 1, t);
        let mut input = response;
        input[..5].copy_from_slice(b"ping ");
        c.raw_rx(&input[..5]).unwrap();
        c.raw_rx(&input[5..len]).unwrap();
        let mut child = response;
        child[len - 2] = b'\n';
        assert!(c.child_output(true, &child[..len - 1]).is_err());
        c.child_output(false, &child[..len - 1]).unwrap();
        assert!(c.raw_tx(&response[..2]).unwrap().is_none());
        let observed = c.raw_tx(&response[2..len]).unwrap().unwrap();
        assert_eq!(observed.leg, 1);
        assert_eq!(observed.value, fnv(&response[..len]));
        assert!(c.raw_rx(b"stale").is_err());
    }

    fn round_trip(capture: &mut Capture, leg: u64, tuple: Tuple) -> Status {
        let (response, len) = response(42, leg, tuple);
        let mut input = response;
        if leg != 2 {
            input[..5].copy_from_slice(b"ping ");
        }
        capture.raw_rx(&input[..len - 1]).unwrap();
        capture.raw_rx(&input[len - 1..len]).unwrap();
        let mut child = response;
        child[len - 2] = b'\n';
        capture.child_output(leg == 2, &child[..len - 1]).unwrap();
        assert!(capture.raw_tx(&response[..len - 1]).unwrap().is_none());
        capture.raw_tx(&response[len - 1..len]).unwrap().unwrap()
    }

    #[test]
    fn all_four_legs_rejoin_driver_and_child_replacement_without_stale_bytes() {
        let first = tuple();
        let mut capture = Capture::new(42).unwrap();
        assert_eq!(
            capture.ready(first, 1, 10, 11).unwrap().unwrap().sequence,
            1
        );
        assert_eq!(round_trip(&mut capture, 1, first).sequence, 2);
        assert_eq!(round_trip(&mut capture, 2, first).sequence, 3);
        let second = Tuple {
            attempt: first.attempt + 1,
            endpoint: first.endpoint + 1,
            transaction: first.transaction + 1,
            stream: first.stream + 1,
            console: first.console + 1,
            child: first.child + 1,
            ..first
        };
        assert_eq!(
            capture.ready(second, 2, 12, 13).unwrap().unwrap().sequence,
            4
        );
        assert_eq!(round_trip(&mut capture, 3, second).sequence, 5);
        let third = Tuple {
            child: second.child + 1,
            ..second
        };
        assert!(capture.ready(third, 3, 12, 13).is_err());
        capture.raw_rx(b"ex").unwrap();
        capture.raw_rx(b"it\r\n").unwrap();
        assert_eq!(
            capture.ready(third, 3, 12, 13).unwrap().unwrap().sequence,
            6
        );
        assert!(capture.ready(third, 3, 12, 13).unwrap().is_none());
        assert_eq!(round_trip(&mut capture, 4, third).sequence, 7);
    }
}
