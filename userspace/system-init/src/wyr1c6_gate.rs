//! Selector-29-only WRC6 evidence gate.
//!
//! This module is deliberately a producer, not an observer.  Callers must
//! supply generation-correlated facts they actually received from the native
//! coordinator path; the producer only enforces the frozen schema, event
//! order, bounded record size, and terminal withholding rule.

pub const GATE_PATH: &str = "system/bootstrap/wyr1-c6-gate-v1";
pub const RECORD_BYTES: usize = 113;
pub const EVIDENCE_RECORDS: usize = 27;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GateConfig {
    pub nonce: u64,
    pub physical_io_not_performed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateError {
    InvalidUtf8,
    WrongContract,
    InvalidNonce,
    InvalidEvent,
    SequenceOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GateEvent {
    D1Begin = 1,
    D1Lease = 2,
    U1Start = 3,
    U1Ready = 4,
    P1Publish = 5,
    U1Failure = 6,
    P1Retire = 7,
    U1Reap = 8,
    OldIrqReleased = 9,
    U2Start = 10,
    U2Ready = 11,
    P2Publish = 12,
    StaleReject = 13,
    D1Failure = 14,
    P2Retire = 15,
    U2Reap = 16,
    D1GenerationClean = 17,
    D1GrantAvailable = 18,
    D2Lease = 19,
    D2Start = 20,
    D2Claim = 21,
    D2Ready = 22,
    NoAuthority = 23,
    NoIo = 24,
    Accounting = 25,
    Bounded = 26,
    Terminal = 0xff,
}

const EVIDENCE_ORDER: [GateEvent; EVIDENCE_RECORDS] = [
    GateEvent::D1Begin,
    GateEvent::D1Lease,
    GateEvent::U1Start,
    GateEvent::U1Ready,
    GateEvent::P1Publish,
    GateEvent::U1Failure,
    GateEvent::P1Retire,
    GateEvent::U1Reap,
    GateEvent::OldIrqReleased,
    GateEvent::U2Start,
    GateEvent::U2Ready,
    GateEvent::P2Publish,
    GateEvent::StaleReject,
    GateEvent::D1Failure,
    GateEvent::P2Retire,
    GateEvent::U2Reap,
    GateEvent::D1GenerationClean,
    GateEvent::D1GrantAvailable,
    GateEvent::D2Lease,
    GateEvent::D2Start,
    GateEvent::D2Claim,
    GateEvent::D2Ready,
    GateEvent::NoAuthority,
    GateEvent::NoIo,
    GateEvent::Accounting,
    GateEvent::Bounded,
    GateEvent::Terminal,
];

pub fn parse_config(bytes: &[u8]) -> Result<GateConfig, GateError> {
    let text = core::str::from_utf8(bytes).map_err(|_| GateError::InvalidUtf8)?;
    let mut lines = text.lines();
    exact(lines.next(), "schema = 1")?;
    exact(lines.next(), "selector = \"device-coordinator-restart\"")?;
    exact(lines.next(), "test_id = 29")?;
    exact(lines.next(), "evidence_protocol = \"WRC6\"")?;
    let nonce = lines
        .next()
        .and_then(|line| {
            line.strip_prefix("nonce = \"")
                .and_then(|v| v.strip_suffix('"'))
        })
        .ok_or(GateError::WrongContract)?;
    exact(lines.next(), "physical_io = \"not-performed\"")?;
    if nonce.len() != 16
        || !nonce
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
        || lines.next().is_some()
    {
        return Err(GateError::WrongContract);
    }
    let nonce = u64::from_str_radix(nonce, 16).map_err(|_| GateError::InvalidNonce)?;
    if nonce == 0 {
        return Err(GateError::InvalidNonce);
    }
    Ok(GateConfig {
        nonce,
        physical_io_not_performed: true,
    })
}

fn exact(actual: Option<&str>, expected: &str) -> Result<(), GateError> {
    if actual == Some(expected) {
        Ok(())
    } else {
        Err(GateError::WrongContract)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceProducer {
    nonce: u64,
    sequence: u32,
    terminal: bool,
}

impl EvidenceProducer {
    pub const fn new(nonce: u64) -> Result<Self, GateError> {
        if nonce == 0 {
            return Err(GateError::InvalidNonce);
        }
        Ok(Self {
            nonce,
            sequence: 0,
            terminal: false,
        })
    }

    pub fn encode(
        &mut self,
        event: GateEvent,
        lease: u64,
        binding: u64,
        value: u64,
        aux: u64,
    ) -> Result<[u8; RECORD_BYTES], GateError> {
        if self.terminal
            || (event == GateEvent::Terminal)
                != (lease == 0 && binding == 0 && value == 0 && aux == 0)
        {
            return Err(GateError::InvalidEvent);
        }
        let mut output = [b'|'; RECORD_BYTES];
        output[..4].copy_from_slice(b"WRC6");
        put_hex(&mut output[5..7], 1);
        put_hex(&mut output[8..24], self.nonce);
        put_hex(&mut output[25..33], u64::from(self.sequence));
        put_hex(&mut output[34..36], event as u64);
        put_hex(&mut output[37..53], lease);
        put_hex(&mut output[54..70], binding);
        put_hex(&mut output[71..87], value);
        put_hex(&mut output[88..104], aux);
        let checksum = fnv1a32(&output[..105]);
        put_hex(&mut output[105..113], u64::from(checksum));
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(GateError::SequenceOverflow)?;
        self.terminal = event == GateEvent::Terminal;
        Ok(output)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceLog {
    nonce: u64,
    facts: [[u64; 5]; EVIDENCE_RECORDS],
    len: usize,
}

impl EvidenceLog {
    pub const fn new(nonce: u64) -> Result<Self, GateError> {
        Ok(Self {
            nonce,
            facts: [[0; 5]; EVIDENCE_RECORDS],
            len: 0,
        })
    }

    pub fn record(
        &mut self,
        event: GateEvent,
        lease: u64,
        binding: u64,
        value: u64,
        aux: u64,
    ) -> Result<(), GateError> {
        if EVIDENCE_ORDER.get(self.len).copied() != Some(event) {
            return Err(GateError::InvalidEvent);
        }
        let mut producer = EvidenceProducer::new(self.nonce)?;
        for (sequence, fact) in self.facts.iter().take(self.len).enumerate() {
            let prior = event_from_sequence(sequence, fact[0])?;
            let _ = producer.encode(prior, fact[1], fact[2], fact[3], fact[4])?;
        }
        let _ = producer.encode(event, lease, binding, value, aux)?;
        self.facts[self.len] = [event as u64, lease, binding, value, aux];
        self.len += 1;
        Ok(())
    }

    pub fn finish(&mut self) -> Result<(), GateError> {
        self.record(GateEvent::Terminal, 0, 0, 0, 0)
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.len == EVIDENCE_RECORDS
    }

    #[must_use]
    pub const fn ready_for_terminal(&self) -> bool {
        self.len == EVIDENCE_RECORDS - 1
    }

    #[must_use]
    pub const fn next_expected_event(&self) -> Option<GateEvent> {
        if self.len < EVIDENCE_RECORDS {
            Some(EVIDENCE_ORDER[self.len])
        } else {
            None
        }
    }

    #[cfg(test)]
    const fn recorded_events(&self) -> usize {
        self.len
    }

    /// Partial transcripts are withheld so an incomplete join is never a
    /// claim-bearing selector result.
    #[must_use]
    pub fn encode_record_at(&self, index: usize, output: &mut [u8; RECORD_BYTES]) -> Option<()> {
        if !self.is_complete() {
            return None;
        }
        if index >= self.len {
            return None;
        }
        let mut producer = EvidenceProducer::new(self.nonce).ok()?;
        for (sequence, fact) in self.facts.iter().take(index + 1).enumerate() {
            let event = event_from_sequence(sequence, fact[0]).ok()?;
            let record = producer
                .encode(event, fact[1], fact[2], fact[3], fact[4])
                .ok()?;
            if sequence == index {
                *output = record;
            }
        }
        Some(())
    }
}

fn event_from_sequence(sequence: usize, discriminant: u64) -> Result<GateEvent, GateError> {
    if EVIDENCE_ORDER
        .get(sequence)
        .copied()
        .is_some_and(|event| event as u64 == discriminant)
    {
        return Ok(EVIDENCE_ORDER[sequence]);
    }
    Err(GateError::InvalidEvent)
}

fn put_hex(output: &mut [u8], value: u64) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let width = output.len();
    for (index, byte) in output.iter_mut().enumerate() {
        let shift = (width - index - 1) * 4;
        *byte = HEX[((value >> shift) & 0xf) as usize];
    }
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c9dc5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &[u8] = b"schema = 1\nselector = \"device-coordinator-restart\"\ntest_id = 29\nevidence_protocol = \"WRC6\"\nnonce = \"0123456789ABCDEF\"\nphysical_io = \"not-performed\"\n";

    #[test]
    fn config_is_strict() {
        assert_eq!(
            parse_config(CONFIG),
            Ok(GateConfig {
                nonce: 0x0123_4567_89ab_cdef,
                physical_io_not_performed: true,
            })
        );
        assert_eq!(parse_config(b"schema = 6\n"), Err(GateError::WrongContract));
        assert_eq!(
            parse_config(&CONFIG[..CONFIG.len() - 1]),
            Ok(GateConfig {
                nonce: 0x0123_4567_89ab_cdef,
                physical_io_not_performed: true,
            })
        );
        let mut extra = [0u8; CONFIG.len() + 6];
        extra[..CONFIG.len()].copy_from_slice(CONFIG);
        extra[CONFIG.len()..].copy_from_slice(b"extra\n");
        assert_eq!(parse_config(&extra), Err(GateError::WrongContract));
    }

    #[test]
    fn records_are_exactly_113_bytes_and_ordered() {
        let mut producer = EvidenceProducer::new(0x0123_4567_89ab_cdef).unwrap();
        let record = producer.encode(GateEvent::D1Begin, 1, 2, 3, 4).unwrap();
        assert_eq!(record.len(), RECORD_BYTES);
        assert_eq!(&record[..4], b"WRC6");
        assert_eq!(&record[25..33], b"00000000");
        assert_eq!(&record[34..36], b"01");
        assert_eq!(&record[37..53], b"0000000000000001");
        assert_eq!(&record[71..87], b"0000000000000003");
        assert_eq!(&record[88..104], b"0000000000000004");
        assert_eq!(record[104], b'|');
        assert_eq!(
            producer.encode(GateEvent::D1Lease, 1, 2, 3, 4).unwrap()[25..33],
            *b"00000001"
        );
        assert_eq!(
            producer.encode(GateEvent::Terminal, 0, 0, 0, 1),
            Err(GateError::InvalidEvent)
        );
    }

    #[test]
    fn complete_log_withholds_partial_and_requires_frozen_order() {
        let mut log = EvidenceLog::new(1).unwrap();
        let mut output = [0; RECORD_BYTES];
        assert_eq!(log.encode_record_at(0, &mut output), None);
        assert_eq!(
            log.record(GateEvent::D1Lease, 1, 2, 3, 4),
            Err(GateError::InvalidEvent)
        );
        for (index, event) in EVIDENCE_ORDER[..EVIDENCE_RECORDS - 1]
            .iter()
            .copied()
            .enumerate()
        {
            log.record(event, 1, 2, index as u64 + 1, 0).unwrap();
            assert_eq!(log.encode_record_at(index, &mut output), None);
        }
        assert_eq!(log.recorded_events(), EVIDENCE_RECORDS - 1);
        log.finish().unwrap();
        assert!(log.is_complete());
        assert!(log.encode_record_at(0, &mut output).is_some());
        assert_eq!(
            log.record(GateEvent::Terminal, 0, 0, 0, 0),
            Err(GateError::InvalidEvent)
        );
    }

    #[test]
    fn ordered_transcript_model_reaches_terminal_only_after_all_26_facts() {
        let mut log = EvidenceLog::new(0x1234).unwrap();
        for (index, event) in EVIDENCE_ORDER[..26].iter().copied().enumerate() {
            let (lease, binding, value, aux) = if index == 25 {
                (29, 0, 4, 25_000_000)
            } else {
                (29, index as u64 + 1, index as u64 + 1, index as u64 + 2)
            };
            log.record(event, lease, binding, value, aux).unwrap();
        }
        assert!(log.ready_for_terminal());
        let mut record = [0; RECORD_BYTES];
        assert_eq!(log.encode_record_at(25, &mut record), None);
        log.finish().unwrap();
        assert!(log.is_complete());
        assert!(log.encode_record_at(25, &mut record).is_some());
        assert_eq!(&record[34..36], b"1A");
    }

    #[test]
    fn next_expected_event_tracks_the_frozen_sequence() {
        let mut log = EvidenceLog::new(0x1234).unwrap();
        assert_eq!(log.next_expected_event(), Some(GateEvent::D1Begin));
        for event in EVIDENCE_ORDER[..EVIDENCE_RECORDS - 1].iter().copied() {
            log.record(event, 1, 1, 1, 1).unwrap();
        }
        log.finish().unwrap();
        assert_eq!(log.next_expected_event(), None);
    }
}
