#![no_std]
#![forbid(unsafe_code)]

//! Fixed selector-30 actor identities and deterministic build binding.

use deepwyrm_syscall as _;
use wyrmroot_loader as _;
use wyrmroot_runtime as _;

pub const RESOURCE_ID: u64 = 1;
pub const EXPECTED_SOURCE: u32 = 3;
pub const SCRATCH_OFFSET: u32 = 7;
pub const PIO_WIDTH_1: u32 = 1;
pub const DELIVERY_CYCLES: u64 = 5;
pub const CONTROLLER_MESSAGE_BYTES: usize = 24;
pub const FIRST_DELIVERY_SEQUENCE: u64 = 1;
pub const PENDING_DELIVERY_SEQUENCE: u64 = 6;
pub const RACE_PERMIT_SEQUENCE: u64 = 7;
pub const STALE_DELIVERY_SEQUENCE: u64 = 8;
/// Frozen absolute status magnitude carried by event 11's auxiliary field.
pub const BAD_STATE_STATUS: i32 = -5;

const CONTROLLER_MAGIC: &[u8; 4] = b"D6CP";
const CONTROLLER_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageKind {
    FirstOwnerBound = 1,
    OwnerWaitIntent = 2,
    OwnerWaitComplete = 3,
    OwnerAckPermit = 4,
    OwnerAckComplete = 5,
    FirstOwnerClosed = 6,
    TriggerDeliver = 7,
    TriggerComplete = 8,
    TriggerFinish = 9,
    TriggerFinished = 10,
    ReplacementBound = 11,
    ReplacementWaitIntent = 12,
    OwnerStartPermit = 13,
}

impl MessageKind {
    const fn from_wire(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::FirstOwnerBound,
            2 => Self::OwnerWaitIntent,
            3 => Self::OwnerWaitComplete,
            4 => Self::OwnerAckPermit,
            5 => Self::OwnerAckComplete,
            6 => Self::FirstOwnerClosed,
            7 => Self::TriggerDeliver,
            8 => Self::TriggerComplete,
            9 => Self::TriggerFinish,
            10 => Self::TriggerFinished,
            11 => Self::ReplacementBound,
            12 => Self::ReplacementWaitIntent,
            13 => Self::OwnerStartPermit,
            _ => return None,
        })
    }
}

/// Exact handle-free controller datagram shared by all three D6 actors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerMessage {
    pub kind: MessageKind,
    pub sequence: u64,
    /// Zero denotes success; failures carry the generated signed native status.
    pub status: i32,
}

impl ControllerMessage {
    pub const fn new(kind: MessageKind, sequence: u64, status: i32) -> Self {
        Self {
            kind,
            sequence,
            status,
        }
    }

    pub const fn encode(self) -> [u8; CONTROLLER_MESSAGE_BYTES] {
        let sequence = self.sequence.to_le_bytes();
        let status = self.status.to_le_bytes();
        [
            CONTROLLER_MAGIC[0],
            CONTROLLER_MAGIC[1],
            CONTROLLER_MAGIC[2],
            CONTROLLER_MAGIC[3],
            CONTROLLER_VERSION,
            self.kind as u8,
            0,
            0,
            sequence[0],
            sequence[1],
            sequence[2],
            sequence[3],
            sequence[4],
            sequence[5],
            sequence[6],
            sequence[7],
            status[0],
            status[1],
            status[2],
            status[3],
            0,
            0,
            0,
            0,
        ]
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ControllerProtocolError> {
        let bytes: &[u8; CONTROLLER_MESSAGE_BYTES] = bytes
            .try_into()
            .map_err(|_| ControllerProtocolError::Malformed)?;
        if &bytes[..4] != CONTROLLER_MAGIC
            || bytes[4] != CONTROLLER_VERSION
            || bytes[6..8] != [0; 2]
            || bytes[20..24] != [0; 4]
        {
            return Err(ControllerProtocolError::Malformed);
        }
        let kind = MessageKind::from_wire(bytes[5]).ok_or(ControllerProtocolError::Malformed)?;
        let mut sequence = [0_u8; 8];
        sequence.copy_from_slice(&bytes[8..16]);
        let mut status = [0_u8; 4];
        status.copy_from_slice(&bytes[16..20]);
        Ok(Self {
            kind,
            sequence: u64::from_le_bytes(sequence),
            status: i32::from_le_bytes(status),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerProtocolError {
    Malformed,
    OutOfOrder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControllerPhase {
    FirstOwnerBound,
    OwnerWaitIntent(u64),
    TriggerComplete(u64),
    OwnerWaitComplete(u64),
    OwnerAckComplete(u64),
    FirstOwnerClosed,
    ReplacementBound,
    ReplacementWaitIntent,
    TriggerShutdown,
    Complete,
}

/// Pure host-testable controller ordering model. Kernel evidence remains the
/// authority for wait registration, delivery, ack, finalization, and teardown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerModel {
    phase: ControllerPhase,
}

impl ControllerModel {
    pub const fn new() -> Self {
        Self {
            phase: ControllerPhase::FirstOwnerBound,
        }
    }

    pub fn accept(
        &mut self,
        message: ControllerMessage,
    ) -> Result<Option<ControllerMessage>, ControllerProtocolError> {
        use ControllerPhase as Phase;
        use MessageKind as Kind;
        let next_command = match (self.phase, message) {
            (
                Phase::FirstOwnerBound,
                ControllerMessage {
                    kind: Kind::FirstOwnerBound,
                    sequence: 0,
                    status: 0,
                },
            ) => {
                self.phase = Phase::OwnerWaitIntent(FIRST_DELIVERY_SEQUENCE);
                None
            }
            (
                Phase::OwnerWaitIntent(expected),
                ControllerMessage {
                    kind: Kind::OwnerWaitIntent,
                    sequence,
                    status: 0,
                },
            ) if sequence == expected => {
                self.phase = Phase::TriggerComplete(sequence);
                Some(deliver_command(sequence, 0))
            }
            (
                Phase::TriggerComplete(expected),
                ControllerMessage {
                    kind: Kind::TriggerComplete,
                    sequence,
                    status: 0,
                },
            ) if sequence == expected && sequence <= RACE_PERMIT_SEQUENCE => {
                if sequence <= DELIVERY_CYCLES {
                    self.phase = Phase::OwnerWaitComplete(sequence);
                    None
                } else if sequence == PENDING_DELIVERY_SEQUENCE {
                    self.phase = Phase::TriggerComplete(RACE_PERMIT_SEQUENCE);
                    Some(deliver_command(RACE_PERMIT_SEQUENCE, 0))
                } else {
                    self.phase = Phase::OwnerAckComplete(DELIVERY_CYCLES);
                    Some(owner_ack_permit(DELIVERY_CYCLES))
                }
            }
            (
                Phase::OwnerWaitComplete(expected),
                ControllerMessage {
                    kind: Kind::OwnerWaitComplete,
                    sequence,
                    status: 0,
                },
            ) if sequence == expected => {
                if sequence < DELIVERY_CYCLES {
                    self.phase = Phase::OwnerAckComplete(sequence);
                    Some(owner_ack_permit(sequence))
                } else {
                    self.phase = Phase::TriggerComplete(PENDING_DELIVERY_SEQUENCE);
                    Some(deliver_command(PENDING_DELIVERY_SEQUENCE, 0))
                }
            }
            (
                Phase::OwnerAckComplete(expected),
                ControllerMessage {
                    kind: Kind::OwnerAckComplete,
                    sequence,
                    status: 0,
                },
            ) if sequence == expected => {
                if sequence < DELIVERY_CYCLES {
                    self.phase = Phase::OwnerWaitIntent(sequence + 1);
                } else {
                    self.phase = Phase::FirstOwnerClosed;
                }
                None
            }
            (
                Phase::FirstOwnerClosed,
                ControllerMessage {
                    kind: Kind::FirstOwnerClosed,
                    sequence: 0,
                    status: 0,
                },
            ) => {
                self.phase = Phase::TriggerComplete(STALE_DELIVERY_SEQUENCE);
                Some(deliver_command(STALE_DELIVERY_SEQUENCE, BAD_STATE_STATUS))
            }
            (
                Phase::TriggerComplete(STALE_DELIVERY_SEQUENCE),
                ControllerMessage {
                    kind: Kind::TriggerComplete,
                    sequence: STALE_DELIVERY_SEQUENCE,
                    status: BAD_STATE_STATUS,
                },
            ) => {
                self.phase = Phase::ReplacementBound;
                None
            }
            (
                Phase::ReplacementBound,
                ControllerMessage {
                    kind: Kind::ReplacementBound,
                    sequence: 0,
                    status: 0,
                },
            ) => {
                self.phase = Phase::ReplacementWaitIntent;
                None
            }
            (
                Phase::ReplacementWaitIntent,
                ControllerMessage {
                    kind: Kind::ReplacementWaitIntent,
                    sequence: 0,
                    status: 0,
                },
            ) => {
                self.phase = Phase::TriggerShutdown;
                None
            }
            (
                Phase::TriggerShutdown,
                ControllerMessage {
                    kind: Kind::TriggerFinished,
                    sequence: 0,
                    status: 0,
                },
            ) => {
                self.phase = Phase::Complete;
                None
            }
            _ => return Err(ControllerProtocolError::OutOfOrder),
        };
        Ok(next_command)
    }

    pub const fn trigger_finish_command(
        &self,
    ) -> Result<ControllerMessage, ControllerProtocolError> {
        if matches!(self.phase, ControllerPhase::TriggerShutdown) {
            Ok(ControllerMessage::new(MessageKind::TriggerFinish, 0, 0))
        } else {
            Err(ControllerProtocolError::OutOfOrder)
        }
    }

    pub const fn is_complete(&self) -> bool {
        matches!(self.phase, ControllerPhase::Complete)
    }
}

impl Default for ControllerModel {
    fn default() -> Self {
        Self::new()
    }
}

pub const fn deliver_command(sequence: u64, expected_status: i32) -> ControllerMessage {
    ControllerMessage::new(MessageKind::TriggerDeliver, sequence, expected_status)
}

pub const fn owner_ack_permit(sequence: u64) -> ControllerMessage {
    ControllerMessage::new(MessageKind::OwnerAckPermit, sequence, 0)
}

pub const fn owner_start_permit() -> ControllerMessage {
    ControllerMessage::new(MessageKind::OwnerStartPermit, 0, 0)
}

pub const BUILD_NONCE: u64 = parse_hex(match option_env!("DEEPWYRM_DW1D6_BUILD_NONCE") {
    Some(value) => value,
    None => "D6D6000000000030",
});
pub const BUILD_CHALLENGE: u64 = parse_hex(match option_env!("DEEPWYRM_DW1D6_BUILD_CHALLENGE") {
    Some(value) => value,
    None => "5A5A30D6C0DEC0DE",
});

const fn parse_hex(text: &str) -> u64 {
    let bytes = text.as_bytes();
    assert!(bytes.len() == 16);
    let mut value = 0_u64;
    let mut index = 0;
    while index < bytes.len() {
        value = (value << 4) | hex(bytes[index]);
        index += 1;
    }
    value
}

const fn hex(byte: u8) -> u64 {
    match byte {
        b'0'..=b'9' => (byte - b'0') as u64,
        b'A'..=b'F' => (byte - b'A' + 10) as u64,
        b'a'..=b'f' => (byte - b'a' + 10) as u64,
        _ => panic!("invalid D6 hex value"),
    }
}
