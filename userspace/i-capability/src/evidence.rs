//! Fixed-width trusted-controller `WRCAP1` v1 evidence framing.

use deepwyrm_syscall::{DW_RIGHT_INSPECT, DW_RIGHT_MAP, DW_RIGHT_READ, DW_TERMINATION_AUTHORIZED};

pub const WRCAP1_RECORD_BYTES: usize = 117;
pub const WRCAP1_EVENT_COUNT: usize = 15;
pub const REQUIRED_CAPABILITY_MASK: u16 = (1 << 10) - 1;

pub const CONTENT_TOKEN: u64 = 0x2401_0001;
pub const NORMAL_TRANSACTION: u64 = 0x2402_0001;
pub const MEMORY_TRANSACTION: u64 = 0x2403_0001;
pub const CHANNEL_TOKEN: u64 = 0x2404_0001;
pub const WAIT_TOKEN: u64 = 0x2405_0001;
pub const CANCEL_TRANSACTION: u64 = 0x2406_0001;
pub const RESTART_TRANSACTION_BASE: u64 = 0x2407_0000;
pub const EXHAUST_TRANSACTION_BASE: u64 = 0x2408_0000;

pub const MEMORY_PAGE_BYTES: u64 = wyrmroot_runtime::PAGE_SIZE;
pub const MEMORY_CHILD_RIGHTS_MASK: u64 = DW_RIGHT_READ.0 | DW_RIGHT_MAP.0 | DW_RIGHT_INSPECT.0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EvidenceKind {
    ContentDelivery = 0x01,
    ProcessLifecycle = 0x02,
    MemoryShare = 0x03,
    ChannelLifecycle = 0x04,
    WaitEventTimer = 0x05,
    Cancellation = 0x06,
    RestartReplacement = 0x07,
    RestartExhausted = 0x08,
    OverloadReplayRejected = 0x09,
    CleanupBaseline = 0x0A,
}

impl EvidenceKind {
    #[must_use]
    pub const fn mask(self) -> u16 {
        1 << (self as u8 - 1)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceEvent {
    pub kind: EvidenceKind,
    pub peer: u32,
    pub generation: u32,
    pub token: u64,
    pub arg0: u64,
    pub arg1: u64,
}

const EMPTY_EVENT: EvidenceEvent = EvidenceEvent {
    kind: EvidenceKind::ContentDelivery,
    peer: 0,
    generation: 0,
    token: 0,
    arg0: 0,
    arg1: 0,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceError {
    ZeroNonce,
    Capacity,
    KindOrder,
    InvalidJoin,
    DuplicateToken,
    Incomplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceTranscript {
    nonce: u64,
    events: [EvidenceEvent; WRCAP1_EVENT_COUNT],
    len: u8,
    observed_mask: u16,
}

impl EvidenceTranscript {
    pub fn new(nonce: u64) -> Result<Self, EvidenceError> {
        if nonce == 0 {
            return Err(EvidenceError::ZeroNonce);
        }
        Ok(Self {
            nonce,
            events: [EMPTY_EVENT; WRCAP1_EVENT_COUNT],
            len: 0,
            observed_mask: 0,
        })
    }

    pub fn push(&mut self, event: EvidenceEvent) -> Result<(), EvidenceError> {
        let index = usize::from(self.len);
        if index == WRCAP1_EVENT_COUNT {
            return Err(EvidenceError::Capacity);
        }
        if expected_kind(index) != Some(event.kind) {
            return Err(EvidenceError::KindOrder);
        }
        validate_join(index, event)?;
        if event.token != 0
            && self.events[..index]
                .iter()
                .any(|record| record.token == event.token)
            && !matches!(index, 2 | 13)
        {
            return Err(EvidenceError::DuplicateToken);
        }
        self.events[index] = event;
        self.len += 1;
        self.observed_mask |= event.kind.mask();
        Ok(())
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub const fn observed_mask(&self) -> u16 {
        self.observed_mask
    }

    pub fn encoded(&self, index: usize) -> Result<[u8; WRCAP1_RECORD_BYTES], EvidenceError> {
        if self.len() != WRCAP1_EVENT_COUNT || self.observed_mask != REQUIRED_CAPABILITY_MASK {
            return Err(EvidenceError::Incomplete);
        }
        let event = *self.events.get(index).ok_or(EvidenceError::Capacity)?;
        Ok(encode_record(self.nonce, index as u32, event))
    }
}

/// Validates the fixed record identity needed by a byte-for-byte relay. The relay does not
/// reinterpret or rewrite facts; request, candidate, and provenance matching remain host-owned.
#[must_use]
pub fn validate_relay_record(record: &[u8], expected_sequence: u32) -> bool {
    let framing = record.len() == WRCAP1_RECORD_BYTES
        && &record[..10] == b"WRCAP1|01|"
        && [26, 35, 38, 47, 56, 73, 90, 107]
            .into_iter()
            .all(|index| record[index] == b'|')
        && record[116] == b'\n'
        && parse_hex(&record[10..26]).is_some_and(|nonce| nonce != 0)
        && parse_hex(&record[27..35]) == Some(u64::from(expected_sequence))
        && parse_hex(&record[36..38]).is_some()
        && parse_hex(&record[39..47]).is_some()
        && parse_hex(&record[48..56]).is_some()
        && parse_hex(&record[57..73]).is_some()
        && parse_hex(&record[74..90]).is_some()
        && parse_hex(&record[91..107]).is_some()
        && parse_hex(&record[108..116]) == Some(u64::from(fnv1a32(&record[..108])));
    if !framing {
        return false;
    }
    let Ok(peer) = u32::try_from(parse_hex(&record[39..47]).unwrap()) else {
        return false;
    };
    let Ok(generation) = u32::try_from(parse_hex(&record[48..56]).unwrap()) else {
        return false;
    };
    let Some(kind) = expected_kind(expected_sequence as usize) else {
        return false;
    };
    if parse_hex(&record[36..38]) != Some(u64::from(kind as u8)) {
        return false;
    }
    validate_join(
        expected_sequence as usize,
        EvidenceEvent {
            kind,
            peer,
            generation,
            token: parse_hex(&record[57..73]).unwrap(),
            arg0: parse_hex(&record[74..90]).unwrap(),
            arg1: parse_hex(&record[91..107]).unwrap(),
        },
    )
    .is_ok()
}

fn validate_join(index: usize, event: EvidenceEvent) -> Result<(), EvidenceError> {
    let valid = match index {
        0 => {
            event.peer == 0
                && event.generation == 0
                && event.token == CONTENT_TOKEN
                && event.kind == EvidenceKind::ContentDelivery
        }
        1 => process_join(event, 1),
        2 => process_join(event, 2),
        3 => {
            peer_join(event, EvidenceKind::MemoryShare, 1, 1, MEMORY_TRANSACTION)
                && event.arg0 == MEMORY_PAGE_BYTES
                && event.arg1 == MEMORY_CHILD_RIGHTS_MASK
        }
        4 => {
            peer_join(event, EvidenceKind::ChannelLifecycle, 1, 1, CHANNEL_TOKEN)
                && event.arg0 == 0xF
                && event.arg1 == 32
        }
        5 => {
            peer_join(event, EvidenceKind::WaitEventTimer, 1, 1, WAIT_TOKEN)
                && event.arg0 == 0xF
                && event.arg1 == 0
        }
        6 => {
            peer_join(event, EvidenceKind::Cancellation, 2, 1, CANCEL_TRANSACTION)
                && event.arg0 == u64::from(DW_TERMINATION_AUTHORIZED.0)
                && event.arg1 == 0
        }
        7 | 8 => {
            let generation = index as u32 - 6;
            peer_join(
                event,
                EvidenceKind::RestartReplacement,
                3,
                generation,
                RESTART_TRANSACTION_BASE + u64::from(generation),
            ) && event.arg0 == u64::from(generation)
                && event.arg1 == u64::from(3 - generation)
        }
        9..=12 => {
            let generation = index as u32 - 8;
            peer_join(
                event,
                EvidenceKind::RestartExhausted,
                4,
                generation,
                EXHAUST_TRANSACTION_BASE + u64::from(generation),
            ) && event.arg0 == u64::from(generation)
                && event.arg1
                    == if generation == 4 {
                        0
                    } else {
                        u64::from(generation + 1)
                    }
        }
        13 => {
            peer_join(
                event,
                EvidenceKind::OverloadReplayRejected,
                1,
                1,
                NORMAL_TRANSACTION,
            ) && event.arg0 == 0xF
                && event.arg1 == 2
        }
        14 => {
            event.kind == EvidenceKind::CleanupBaseline
                && event.peer == 0
                && event.generation == 0
                && event.token == 0
                && event.arg0 == 0
                && event.arg1 == 0
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(EvidenceError::InvalidJoin)
    }
}

fn process_join(event: EvidenceEvent, phase: u64) -> bool {
    peer_join(
        event,
        EvidenceKind::ProcessLifecycle,
        1,
        1,
        NORMAL_TRANSACTION,
    ) && event.arg0 == phase
        && event.arg1 == 0
}

fn peer_join(
    event: EvidenceEvent,
    kind: EvidenceKind,
    peer: u32,
    generation: u32,
    token: u64,
) -> bool {
    event.kind == kind
        && event.peer == peer
        && event.generation == generation
        && event.token == token
}

const fn expected_kind(index: usize) -> Option<EvidenceKind> {
    match index {
        0 => Some(EvidenceKind::ContentDelivery),
        1 | 2 => Some(EvidenceKind::ProcessLifecycle),
        3 => Some(EvidenceKind::MemoryShare),
        4 => Some(EvidenceKind::ChannelLifecycle),
        5 => Some(EvidenceKind::WaitEventTimer),
        6 => Some(EvidenceKind::Cancellation),
        7 | 8 => Some(EvidenceKind::RestartReplacement),
        9..=12 => Some(EvidenceKind::RestartExhausted),
        13 => Some(EvidenceKind::OverloadReplayRejected),
        14 => Some(EvidenceKind::CleanupBaseline),
        _ => None,
    }
}

fn encode_record(nonce: u64, sequence: u32, event: EvidenceEvent) -> [u8; WRCAP1_RECORD_BYTES] {
    let mut output = [0_u8; WRCAP1_RECORD_BYTES];
    output[..10].copy_from_slice(b"WRCAP1|01|");
    put_hex(&mut output[10..26], nonce);
    output[26] = b'|';
    put_hex(&mut output[27..35], u64::from(sequence));
    output[35] = b'|';
    put_hex(&mut output[36..38], u64::from(event.kind as u8));
    output[38] = b'|';
    put_hex(&mut output[39..47], u64::from(event.peer));
    output[47] = b'|';
    put_hex(&mut output[48..56], u64::from(event.generation));
    output[56] = b'|';
    put_hex(&mut output[57..73], event.token);
    output[73] = b'|';
    put_hex(&mut output[74..90], event.arg0);
    output[90] = b'|';
    put_hex(&mut output[91..107], event.arg1);
    output[107] = b'|';
    let checksum = fnv1a32(&output[..108]);
    put_hex(&mut output[108..116], u64::from(checksum));
    output[116] = b'\n';
    output
}

fn put_hex(output: &mut [u8], mut value: u64) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in output.iter_mut().rev() {
        *byte = HEX[(value & 0xF) as usize];
        value >>= 4;
    }
}

fn parse_hex(bytes: &[u8]) -> Option<u64> {
    let mut value = 0_u64;
    for byte in bytes {
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        value = value.checked_mul(16)?.checked_add(u64::from(nibble))?;
    }
    Some(value)
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut value = 0x811C_9DC5_u32;
    for byte in bytes {
        value ^= u32::from(*byte);
        value = value.wrapping_mul(0x0100_0193);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_is_fixed_uppercase_contiguous_and_checksummed() {
        let transcript = complete_transcript();
        assert_eq!(transcript.len(), 15);
        assert_eq!(transcript.observed_mask(), REQUIRED_CAPABILITY_MASK);
        let content = transcript.encoded(0).unwrap();
        assert_eq!(content.len(), WRCAP1_RECORD_BYTES);
        assert_eq!(&content[..10], b"WRCAP1|01|");
        assert_eq!(&content[10..26], b"0123456789ABCDEF");
        assert_eq!(&content[27..35], b"00000000");
        assert_eq!(&content[36..38], b"01");
        assert_eq!(content[116], b'\n');
        assert!(content[..116].iter().all(|byte| !byte.is_ascii_lowercase()));
        let checksum = core::str::from_utf8(&content[108..116]).unwrap();
        assert_eq!(
            u32::from_str_radix(checksum, 16).unwrap(),
            fnv1a32(&content[..108])
        );
        assert!(validate_relay_record(&content, 0));
        let mut malformed = content;
        malformed[73] = b':';
        let checksum = fnv1a32(&malformed[..108]);
        put_hex(&mut malformed[108..116], u64::from(checksum));
        assert!(!validate_relay_record(&malformed, 0));
        let mut lowercase = content;
        lowercase[10] = b'a';
        let checksum = fnv1a32(&lowercase[..108]);
        put_hex(&mut lowercase[108..116], u64::from(checksum));
        assert!(!validate_relay_record(&lowercase, 0));
        let cleanup = transcript.encoded(14).unwrap();
        assert_eq!(&cleanup[27..35], b"0000000E");
        assert_eq!(&cleanup[36..38], b"0A");
    }

    #[test]
    fn fail_closed_join_rejects_wrong_order_role_and_join_token() {
        let mut transcript = EvidenceTranscript::new(1).unwrap();
        assert_eq!(
            transcript.push(event(
                EvidenceKind::ProcessLifecycle,
                1,
                1,
                NORMAL_TRANSACTION,
                1,
                0,
            )),
            Err(EvidenceError::KindOrder)
        );
        transcript
            .push(event(
                EvidenceKind::ContentDelivery,
                0,
                0,
                CONTENT_TOKEN,
                2,
                3,
            ))
            .unwrap();
        assert_eq!(
            transcript.push(event(
                EvidenceKind::ProcessLifecycle,
                2,
                1,
                NORMAL_TRANSACTION,
                1,
                0,
            )),
            Err(EvidenceError::InvalidJoin)
        );
        transcript
            .push(event(
                EvidenceKind::ProcessLifecycle,
                1,
                1,
                NORMAL_TRANSACTION,
                1,
                0,
            ))
            .unwrap();
        assert_eq!(
            transcript.push(event(
                EvidenceKind::ProcessLifecycle,
                1,
                1,
                MEMORY_TRANSACTION,
                2,
                0,
            )),
            Err(EvidenceError::InvalidJoin)
        );
    }

    fn complete_transcript() -> EvidenceTranscript {
        let mut transcript = EvidenceTranscript::new(0x0123_4567_89AB_CDEF).unwrap();
        for item in [
            event(EvidenceKind::ContentDelivery, 0, 0, CONTENT_TOKEN, 2, 3),
            event(
                EvidenceKind::ProcessLifecycle,
                1,
                1,
                NORMAL_TRANSACTION,
                1,
                0,
            ),
            event(
                EvidenceKind::ProcessLifecycle,
                1,
                1,
                NORMAL_TRANSACTION,
                2,
                0,
            ),
            event(
                EvidenceKind::MemoryShare,
                1,
                1,
                MEMORY_TRANSACTION,
                4096,
                MEMORY_CHILD_RIGHTS_MASK,
            ),
            event(EvidenceKind::ChannelLifecycle, 1, 1, CHANNEL_TOKEN, 0xF, 32),
            event(EvidenceKind::WaitEventTimer, 1, 1, WAIT_TOKEN, 0xF, 0),
            event(
                EvidenceKind::Cancellation,
                2,
                1,
                CANCEL_TRANSACTION,
                u64::from(DW_TERMINATION_AUTHORIZED.0),
                0,
            ),
            event(
                EvidenceKind::RestartReplacement,
                3,
                1,
                RESTART_TRANSACTION_BASE + 1,
                1,
                2,
            ),
            event(
                EvidenceKind::RestartReplacement,
                3,
                2,
                RESTART_TRANSACTION_BASE + 2,
                2,
                1,
            ),
            event(
                EvidenceKind::RestartExhausted,
                4,
                1,
                EXHAUST_TRANSACTION_BASE + 1,
                1,
                2,
            ),
            event(
                EvidenceKind::RestartExhausted,
                4,
                2,
                EXHAUST_TRANSACTION_BASE + 2,
                2,
                3,
            ),
            event(
                EvidenceKind::RestartExhausted,
                4,
                3,
                EXHAUST_TRANSACTION_BASE + 3,
                3,
                4,
            ),
            event(
                EvidenceKind::RestartExhausted,
                4,
                4,
                EXHAUST_TRANSACTION_BASE + 4,
                4,
                0,
            ),
            event(
                EvidenceKind::OverloadReplayRejected,
                1,
                1,
                NORMAL_TRANSACTION,
                0xF,
                2,
            ),
            event(EvidenceKind::CleanupBaseline, 0, 0, 0, 0, 0),
        ] {
            transcript.push(item).unwrap();
        }
        transcript
    }

    const fn event(
        kind: EvidenceKind,
        peer: u32,
        generation: u32,
        token: u64,
        arg0: u64,
        arg1: u64,
    ) -> EvidenceEvent {
        EvidenceEvent {
            kind,
            peer,
            generation,
            token,
            arg0,
            arg1,
        }
    }
}
