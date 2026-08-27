//! Selector-27-only gate configuration and controller-originated WRB1 evidence.

pub const GATE_PATH: &str = "system/bootstrap/wyr1-b-gate-v1";
pub const RECORD_BYTES: usize = 96;
pub const EVIDENCE_RECORDS: usize = 14;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GateConfig {
    pub nonce: u64,
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
    RegistryReady = 1,
    PublisherReady = 2,
    ClientReady = 3,
    Published = 4,
    Connected = 5,
    DirectExchange = 6,
    Retired = 7,
    StaleRejected = 8,
    JobAccepted = 9,
    JobExitZero = 10,
    JobReaped = 11,
    ForeignRejected = 12,
    OrphanReaped = 13,
    Terminal = 0xff,
}

const EVIDENCE_ORDER: [GateEvent; EVIDENCE_RECORDS] = [
    GateEvent::RegistryReady,
    GateEvent::PublisherReady,
    GateEvent::ClientReady,
    GateEvent::Published,
    GateEvent::Connected,
    GateEvent::DirectExchange,
    GateEvent::Retired,
    GateEvent::StaleRejected,
    GateEvent::JobAccepted,
    GateEvent::JobExitZero,
    GateEvent::JobReaped,
    GateEvent::ForeignRejected,
    GateEvent::OrphanReaped,
    GateEvent::Terminal,
];

pub fn parse_config(bytes: &[u8]) -> Result<GateConfig, GateError> {
    let text = core::str::from_utf8(bytes).map_err(|_| GateError::InvalidUtf8)?;
    let mut lines = text.lines();
    exact(lines.next(), "schema = 6")?;
    exact(lines.next(), "selector = \"bootstrap-registry-launch\"")?;
    exact(lines.next(), "test_id = 27")?;
    exact(lines.next(), "evidence_protocol = \"wrb1\"")?;
    let nonce = lines
        .next()
        .and_then(|line| line.strip_prefix("nonce = \""))
        .and_then(|line| line.strip_suffix('"'))
        .ok_or(GateError::WrongContract)?;
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
    Ok(GateConfig { nonce })
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
        subject: u64,
        generation: u64,
        value: u64,
    ) -> Result<[u8; RECORD_BYTES], GateError> {
        if self.terminal
            || (event == GateEvent::Terminal) != (subject == 0 && generation == 0 && value == 0)
        {
            return Err(GateError::InvalidEvent);
        }
        if event != GateEvent::Terminal && (subject == 0 || generation == 0) {
            return Err(GateError::InvalidEvent);
        }
        let mut output = [b'|'; RECORD_BYTES];
        output[..4].copy_from_slice(b"WRB1");
        put_hex(&mut output[5..7], 1);
        put_hex(&mut output[8..24], self.nonce);
        put_hex(&mut output[25..33], u64::from(self.sequence));
        put_hex(&mut output[34..36], event as u64);
        put_hex(&mut output[37..53], subject);
        put_hex(&mut output[54..70], generation);
        put_hex(&mut output[71..87], value);
        let checksum = fnv1a32(&output[..88]);
        put_hex(&mut output[88..96], u64::from(checksum));
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(GateError::SequenceOverflow)?;
        self.terminal = event == GateEvent::Terminal;
        Ok(output)
    }
}

/// Bounded selector-27 evidence which becomes claim-bearing only after every
/// relational join and the terminal record have been produced in order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceLog {
    producer: EvidenceProducer,
    records: [[u8; RECORD_BYTES]; EVIDENCE_RECORDS],
    len: usize,
}

impl EvidenceLog {
    pub const fn new(nonce: u64) -> Result<Self, GateError> {
        Ok(Self {
            producer: match EvidenceProducer::new(nonce) {
                Ok(producer) => producer,
                Err(error) => return Err(error),
            },
            records: [[0; RECORD_BYTES]; EVIDENCE_RECORDS],
            len: 0,
        })
    }

    pub fn record(
        &mut self,
        event: GateEvent,
        subject: u64,
        generation: u64,
        value: u64,
    ) -> Result<(), GateError> {
        if EVIDENCE_ORDER.get(self.len).copied() != Some(event) {
            return Err(GateError::InvalidEvent);
        }
        self.records[self.len] = self.producer.encode(event, subject, generation, value)?;
        self.len += 1;
        Ok(())
    }

    pub fn finish(&mut self) -> Result<(), GateError> {
        self.record(GateEvent::Terminal, 0, 0, 0)
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.len == EVIDENCE_RECORDS
    }

    /// Partial transcripts are deliberately withheld: without `Terminal`, the
    /// selector has no success evidence claim.
    #[must_use]
    pub fn record_at(&self, index: usize) -> Option<&[u8; RECORD_BYTES]> {
        if !self.is_complete() {
            return None;
        }
        self.records.get(index)
    }
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
    const CONFIG: &[u8] = b"schema = 6\nselector = \"bootstrap-registry-launch\"\ntest_id = 27\nevidence_protocol = \"wrb1\"\nnonce = \"0123456789ABCDEF\"\n";
    #[test]
    fn config_and_evidence_are_exact_and_terminal() {
        assert_eq!(
            parse_config(CONFIG),
            Ok(GateConfig {
                nonce: 0x0123_4567_89ab_cdef
            })
        );
        let mut producer = EvidenceProducer::new(1).unwrap();
        let record = producer.encode(GateEvent::RegistryReady, 1, 1, 0).unwrap();
        assert_eq!(&record[..4], b"WRB1");
        producer.encode(GateEvent::Terminal, 0, 0, 0).unwrap();
        assert_eq!(
            producer.encode(GateEvent::Published, 1, 1, 0),
            Err(GateError::InvalidEvent)
        );
    }

    #[test]
    fn bounded_log_requires_exact_order_and_withholds_partial_nonclaims() {
        let mut log = EvidenceLog::new(1).unwrap();
        assert_eq!(log.record_at(0), None);
        assert_eq!(
            log.record(GateEvent::PublisherReady, 1, 1, 0),
            Err(GateError::InvalidEvent)
        );
        for (index, event) in EVIDENCE_ORDER[..EVIDENCE_RECORDS - 1]
            .iter()
            .copied()
            .enumerate()
        {
            log.record(event, index as u64 + 1, 1, index as u64)
                .unwrap();
            assert_eq!(log.record_at(index), None);
        }
        log.finish().unwrap();
        assert!(log.is_complete());
        for (sequence, expected) in EVIDENCE_ORDER.iter().copied().enumerate() {
            let record = log.record_at(sequence).unwrap();
            assert_eq!(
                u64::from_str_radix(core::str::from_utf8(&record[25..33]).unwrap(), 16),
                Ok(sequence as u64)
            );
            assert_eq!(
                u64::from_str_radix(core::str::from_utf8(&record[34..36]).unwrap(), 16),
                Ok(expected as u64)
            );
        }
        assert_eq!(log.finish(), Err(GateError::InvalidEvent));
        assert_eq!(log.record_at(EVIDENCE_RECORDS), None);
    }
}
