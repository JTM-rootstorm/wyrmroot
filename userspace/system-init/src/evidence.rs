//! Allocation-free WYR1EVID1 records emitted from supervisor transitions.

/// Largest canonical WYR1 evidence record, including its newline.
pub const MAX_RECORD_BYTES: usize = 192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceEvent {
    Ready,
    Reap,
    Restart,
    PermanentFailure,
    Normal,
    Degraded,
}

impl EvidenceEvent {
    const fn name(self) -> &'static [u8] {
        match self {
            Self::Ready => b"READY",
            Self::Reap => b"REAP",
            Self::Restart => b"RESTART",
            Self::PermanentFailure => b"PermanentFailure",
            Self::Normal => b"NORMAL",
            Self::Degraded => b"DEGRADED",
        }
    }

    const fn terminal(self) -> bool {
        matches!(self, Self::Normal | Self::Degraded)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceError {
    ZeroNonce,
    InvalidIdentity,
    SequenceOverflow,
    BufferTooSmall,
    AlreadyTerminal,
}

/// Current-boot producer state. Sequence and terminal ordering are not caller supplied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceProducer {
    nonce: u64,
    sequence: u64,
    terminal: bool,
}

impl EvidenceProducer {
    pub const fn new(nonce: u64) -> Result<Self, EvidenceError> {
        if nonce == 0 {
            return Err(EvidenceError::ZeroNonce);
        }
        Ok(Self {
            nonce,
            sequence: 0,
            terminal: false,
        })
    }

    pub fn encode(
        &mut self,
        event: EvidenceEvent,
        role: u32,
        generation: u64,
        transaction: u64,
        output: &mut [u8],
    ) -> Result<usize, EvidenceError> {
        if self.terminal {
            return Err(EvidenceError::AlreadyTerminal);
        }
        if event.terminal() {
            if role != 0 || generation != 0 || transaction != 0 {
                return Err(EvidenceError::InvalidIdentity);
            }
        } else if role == 0 || generation == 0 || transaction == 0 {
            return Err(EvidenceError::InvalidIdentity);
        }

        let mut writer = Writer::new(output);
        writer.bytes(b"wyr1evid1|nonce=")?;
        writer.hex_u64(self.nonce)?;
        writer.bytes(b"|seq=")?;
        writer.decimal_u64(self.sequence)?;
        writer.bytes(b"|event=")?;
        writer.bytes(event.name())?;
        writer.bytes(b"|role=")?;
        writer.hex_u32(role)?;
        writer.bytes(b"|generation=")?;
        writer.hex_u64(generation)?;
        writer.bytes(b"|transaction=")?;
        writer.hex_u64(transaction)?;
        let checksum = fnv1a32(&writer.output[..writer.position]);
        writer.bytes(b"|checksum=")?;
        writer.hex_u32(checksum)?;
        writer.byte(b'\n')?;
        let size = writer.position;

        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(EvidenceError::SequenceOverflow)?;
        self.terminal = event.terminal();
        Ok(size)
    }
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5_u32;
    for byte in bytes {
        hash = (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193);
    }
    hash
}

struct Writer<'a> {
    output: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    const fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            position: 0,
        }
    }

    fn byte(&mut self, value: u8) -> Result<(), EvidenceError> {
        let slot = self
            .output
            .get_mut(self.position)
            .ok_or(EvidenceError::BufferTooSmall)?;
        *slot = value;
        self.position += 1;
        Ok(())
    }

    fn bytes(&mut self, values: &[u8]) -> Result<(), EvidenceError> {
        for value in values {
            self.byte(*value)?;
        }
        Ok(())
    }

    fn hex_u32(&mut self, value: u32) -> Result<(), EvidenceError> {
        self.hex(u64::from(value), 8)
    }

    fn hex_u64(&mut self, value: u64) -> Result<(), EvidenceError> {
        self.hex(value, 16)
    }

    fn hex(&mut self, value: u64, digits: usize) -> Result<(), EvidenceError> {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        for shift in (0..digits).rev() {
            self.byte(HEX[((value >> (shift * 4)) & 0xf) as usize])?;
        }
        Ok(())
    }

    fn decimal_u64(&mut self, value: u64) -> Result<(), EvidenceError> {
        let mut digits = [0_u8; 20];
        let mut index = digits.len();
        let mut remaining = value;
        loop {
            index -= 1;
            digits[index] = b'0' + (remaining % 10) as u8;
            remaining /= 10;
            if remaining == 0 {
                break;
            }
        }
        self.bytes(&digits[index..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_records_match_tooling_protocol() {
        let mut producer = EvidenceProducer::new(0x0123_4567_89ab_cdef).unwrap();
        let mut output = [0; MAX_RECORD_BYTES];
        let size = producer
            .encode(EvidenceEvent::Ready, 1, 1, 2, &mut output)
            .unwrap();
        assert_eq!(
            core::str::from_utf8(&output[..size]).unwrap(),
            "wyr1evid1|nonce=0123456789ABCDEF|seq=0|event=READY|role=00000001|generation=0000000000000001|transaction=0000000000000002|checksum=16116C74\n"
        );
        let size = producer
            .encode(EvidenceEvent::Normal, 0, 0, 0, &mut output)
            .unwrap();
        assert!(
            core::str::from_utf8(&output[..size])
                .unwrap()
                .contains("|seq=1|event=NORMAL|")
        );
        assert_eq!(
            producer.encode(EvidenceEvent::Reap, 1, 1, 2, &mut output),
            Err(EvidenceError::AlreadyTerminal)
        );
    }
}
