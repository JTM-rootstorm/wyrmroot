//! Allocation-free fixed WYR1EVID1 records for the selector-25 collector.

use crate::gate::GateScenario;

pub const RECORD_BYTES: usize = 114;
pub const MAX_TRANSCRIPT_RECORDS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceEvent {
    Ready,
    Reap,
    Restart,
    PermanentFailure,
    Terminal,
}

impl EvidenceEvent {
    const fn kind(self) -> u8 {
        match self {
            Self::Ready => 0x01,
            Self::Reap => 0x02,
            Self::Restart => 0x03,
            Self::PermanentFailure => 0x04,
            Self::Terminal => 0xff,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceError {
    ZeroNonce,
    InvalidIdentity,
    InvalidValue,
    SequenceOverflow,
    TranscriptFull,
    AlreadyTerminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceProducer {
    nonce: u64,
    sequence: u32,
    scenario: GateScenario,
    terminal: bool,
}

impl EvidenceProducer {
    pub const fn new(nonce: u64, scenario: GateScenario) -> Result<Self, EvidenceError> {
        if nonce == 0 {
            return Err(EvidenceError::ZeroNonce);
        }
        Ok(Self {
            nonce,
            sequence: 0,
            scenario,
            terminal: false,
        })
    }

    pub fn encode(
        &mut self,
        event: EvidenceEvent,
        role: u32,
        generation: u64,
        transaction: u64,
        value: u64,
    ) -> Result<[u8; RECORD_BYTES], EvidenceError> {
        if self.terminal {
            return Err(EvidenceError::AlreadyTerminal);
        }
        let terminal = event == EvidenceEvent::Terminal;
        if terminal {
            if role != 0 || generation != 0 || transaction != 0 || value != 0 {
                return Err(EvidenceError::InvalidIdentity);
            }
        } else if role == 0 || generation == 0 || transaction == 0 {
            return Err(EvidenceError::InvalidIdentity);
        }
        match event {
            EvidenceEvent::Ready if value != 0 => return Err(EvidenceError::InvalidValue),
            EvidenceEvent::Restart if value <= generation => {
                return Err(EvidenceError::InvalidValue);
            }
            EvidenceEvent::PermanentFailure if value == 0 => {
                return Err(EvidenceError::InvalidValue);
            }
            _ => {}
        }

        let mut output = [b'|'; RECORD_BYTES];
        output[..9].copy_from_slice(b"WYR1EVID1");
        put_hex(&mut output[10..12], 1);
        put_hex(&mut output[13..29], self.nonce);
        put_hex(&mut output[30..38], u64::from(self.sequence));
        put_hex(&mut output[39..41], u64::from(event.kind()));
        put_hex(
            &mut output[42..44],
            match self.scenario {
                GateScenario::Normal => 1,
                GateScenario::DegradedRecovery => 2,
            },
        );
        put_hex(&mut output[45..53], u64::from(role));
        put_hex(&mut output[54..70], generation);
        put_hex(&mut output[71..87], transaction);
        put_hex(&mut output[88..104], value);
        let checksum = fnv1a32(&output[..105]);
        put_hex(&mut output[105..113], u64::from(checksum));
        output[113] = b'\n';
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(EvidenceError::SequenceOverflow)?;
        self.terminal = terminal;
        Ok(output)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct EvidenceLog {
    producer: EvidenceProducer,
    lines: [[u8; RECORD_BYTES]; MAX_TRANSCRIPT_RECORDS],
    count: usize,
}

impl EvidenceLog {
    pub const fn new(nonce: u64, scenario: GateScenario) -> Result<Self, EvidenceError> {
        Ok(Self {
            producer: match EvidenceProducer::new(nonce, scenario) {
                Ok(producer) => producer,
                Err(error) => return Err(error),
            },
            lines: [[0; RECORD_BYTES]; MAX_TRANSCRIPT_RECORDS],
            count: 0,
        })
    }

    pub fn record(
        &mut self,
        event: EvidenceEvent,
        role: u32,
        generation: u64,
        transaction: u64,
        value: u64,
    ) -> Result<(), EvidenceError> {
        let slot = self
            .lines
            .get_mut(self.count)
            .ok_or(EvidenceError::TranscriptFull)?;
        *slot = self
            .producer
            .encode(event, role, generation, transaction, value)?;
        self.count += 1;
        Ok(())
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[must_use]
    pub fn line(&self, index: usize) -> Option<&[u8; RECORD_BYTES]> {
        self.lines.get(index).filter(|_| index < self.count)
    }
}

fn put_hex(output: &mut [u8], value: u64) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let length = output.len();
    for (index, byte) in output.iter_mut().enumerate() {
        let shift = (length - index - 1) * 4;
        *byte = HEX[((value >> shift) & 0xf) as usize];
    }
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5_u32;
    for byte in bytes {
        hash = (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_wire_offsets_length_and_checksum_are_stable() {
        let mut producer =
            EvidenceProducer::new(0x0123_4567_89ab_cdef, GateScenario::Normal).unwrap();
        let line = producer.encode(EvidenceEvent::Ready, 1, 1, 2, 0).unwrap();
        assert_eq!(&line[..10], b"WYR1EVID1|");
        assert_eq!(&line[10..13], b"01|");
        assert_eq!(&line[13..30], b"0123456789ABCDEF|");
        assert_eq!(&line[39..45], b"01|01|");
        assert_eq!(line[113], b'\n');
        let checksum = core::str::from_utf8(&line[105..113]).unwrap();
        assert_eq!(
            u32::from_str_radix(checksum, 16).unwrap(),
            fnv1a32(&line[..105])
        );
    }

    #[test]
    fn transcript_enforces_restart_and_terminal_semantics() {
        let mut log = EvidenceLog::new(1, GateScenario::DegradedRecovery).unwrap();
        log.record(EvidenceEvent::Ready, 1, 1, 2, 0).unwrap();
        assert_eq!(
            log.record(EvidenceEvent::Restart, 1, 1, 2, 1),
            Err(EvidenceError::InvalidValue)
        );
        log.record(EvidenceEvent::Restart, 1, 1, 2, 2).unwrap();
        log.record(EvidenceEvent::PermanentFailure, 1, 2, 3, 1)
            .unwrap();
        log.record(EvidenceEvent::Terminal, 0, 0, 0, 0).unwrap();
        assert_eq!(log.len(), 4);
        assert_eq!(
            log.record(EvidenceEvent::Reap, 1, 2, 3, 0),
            Err(EvidenceError::AlreadyTerminal)
        );
    }
}
