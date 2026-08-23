//! Field-by-field little-endian bootstrap envelope encoding.

/// ASCII `WRBP`, encoded in little-endian byte order.
pub const PROTOCOL_MAGIC: [u8; 4] = *b"WRBP";
/// Supported bootstrap protocol major version.
pub const PROTOCOL_MAJOR: u16 = 1;
/// Supported bootstrap protocol minor version.
pub const PROTOCOL_MINOR: u16 = 0;
/// Canonical H bootstrap protocol minor version with TaskGroup delegation.
pub const PROTOCOL_MINOR_V2: u16 = 1;
/// Fixed header size in bytes.
pub const HEADER_SIZE: usize = 40;
/// Exact `BOOTSTRAP_INIT_V1` payload size.
pub const BOOTSTRAP_INIT_V1_SIZE: usize = 56;
/// Exact `BOOTSTRAP_INIT_V2` payload size.
pub const BOOTSTRAP_INIT_V2_SIZE: usize = 64;
/// Exact `BOOTSTRAP_READY_V1` payload size.
pub const BOOTSTRAP_READY_V1_SIZE: usize = 40;
/// Exact `BOOTSTRAP_READY_V2` payload size.
pub const BOOTSTRAP_READY_V2_SIZE: usize = 40;
/// The current H bootstrap envelope permits at most three INIT handles and no READY handles.
pub const MAX_BOOTSTRAP_HANDLES: usize = 3;

const INIT_TYPE: u32 = 1;
const READY_TYPE: u32 = 2;
const INIT_CAPABILITY_COUNT: u32 = 2;
const INIT_V2_CAPABILITY_COUNT: u32 = 3;
const READY_CAPABILITY_COUNT: u32 = 0;
const ROLE_DESCRIPTOR_SIZE: usize = 8;

/// Bootstrap message type supported by protocol V1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageType {
    /// The kernel's initial capability-bearing message.
    BootstrapInitV1,
    /// The bootstrap process's completion acknowledgement.
    BootstrapReadyV1,
    /// H's capability-bearing bootstrap message.
    BootstrapInitV2,
    /// H's handle-free acknowledgement.
    BootstrapReadyV2,
}

/// Semantic position of a capability in `BOOTSTRAP_INIT_V1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CapabilityRole {
    /// The child's root address-region capability.
    SelfRootAddressRegion = 1,
    /// Immutable bytes of the Wyrmroot boot filesystem.
    BootfsMemoryObject = 2,
    /// Delegated authority to construct descendant processes.
    LoaderTaskGroup = 3,
}

/// Decoded INIT message. Its two roles are fixed by V1 and are not caller-selectable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitMessage {
    /// Nonzero transaction identifier to echo in READY.
    pub transaction_id: u64,
}

/// Decoded H INIT message with the exact three V2 roles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitMessageV2 {
    pub transaction_id: u64,
}

/// Decoded READY message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadyMessage {
    /// The INIT transaction identifier being acknowledged.
    pub transaction_id: u64,
}

/// H READY message echoing one V2 transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadyMessageV2 {
    pub transaction_id: u64,
}

/// A successfully decoded V1 bootstrap message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapMessage {
    /// A valid INIT with the exact V1 role ordering.
    Init(InitMessage),
    /// A valid handle-free READY.
    Ready(ReadyMessage),
    /// A valid H INIT with TaskGroup delegation.
    InitV2(InitMessageV2),
    /// A valid H READY.
    ReadyV2(ReadyMessageV2),
}

impl InitMessageV2 {
    pub const fn primordial() -> Self {
        Self { transaction_id: 1 }
    }

    pub fn encode_into(self, output: &mut [u8]) -> Result<usize, DecodeError> {
        if self.transaction_id == 0 {
            return Err(DecodeError::ZeroTransactionId);
        }
        if output.len() < BOOTSTRAP_INIT_V2_SIZE {
            return Err(DecodeError::EncodeBufferTooSmall);
        }
        write_header_version(
            output,
            MessageType::BootstrapInitV2,
            PROTOCOL_MINOR_V2,
            BOOTSTRAP_INIT_V2_SIZE as u32,
            INIT_V2_CAPABILITY_COUNT,
            self.transaction_id,
        );
        for (index, role) in [
            CapabilityRole::SelfRootAddressRegion,
            CapabilityRole::BootfsMemoryObject,
            CapabilityRole::LoaderTaskGroup,
        ]
        .into_iter()
        .enumerate()
        {
            write_u32(
                output,
                HEADER_SIZE + index * ROLE_DESCRIPTOR_SIZE,
                role as u32,
            );
            write_u32(output, HEADER_SIZE + index * ROLE_DESCRIPTOR_SIZE + 4, 0);
        }
        Ok(BOOTSTRAP_INIT_V2_SIZE)
    }
}

impl ReadyMessageV2 {
    pub fn encode_into(self, output: &mut [u8]) -> Result<usize, DecodeError> {
        if self.transaction_id == 0 {
            return Err(DecodeError::ZeroTransactionId);
        }
        if output.len() < BOOTSTRAP_READY_V2_SIZE {
            return Err(DecodeError::EncodeBufferTooSmall);
        }
        write_header_version(
            output,
            MessageType::BootstrapReadyV2,
            PROTOCOL_MINOR_V2,
            BOOTSTRAP_READY_V2_SIZE as u32,
            READY_CAPABILITY_COUNT,
            self.transaction_id,
        );
        Ok(BOOTSTRAP_READY_V2_SIZE)
    }
}

/// Reason a bootstrap wire message was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The supplied bytes cannot contain the fixed header.
    TruncatedHeader,
    /// The envelope magic was not `WRBP`.
    WrongMagic,
    /// The message major version is unsupported.
    UnsupportedMajor,
    /// The message minor version is unsupported.
    UnsupportedMinor,
    /// The message type is unknown.
    UnknownMessageType,
    /// V1 does not define flags.
    NonzeroFlags,
    /// A V1 reserved field was nonzero.
    NonzeroReserved,
    /// The total-size field was not the actual exact message size.
    WrongTotalSize,
    /// The wire capability count does not match the message kind.
    WrongCapabilityCount,
    /// Channel handle metadata count does not match the encoded count.
    WrongHandleCount,
    /// The transaction identifier was zero.
    ZeroTransactionId,
    /// INIT did not contain the exact two fixed V1 role descriptors.
    WrongCapabilityRoles,
    /// The caller supplied insufficient capacity for deterministic encoding.
    EncodeBufferTooSmall,
}

impl InitMessage {
    /// The fixed primordial G0 INIT transaction.
    pub const fn primordial() -> Self {
        Self { transaction_id: 1 }
    }

    /// Encodes the exact V1 INIT payload into `output`.
    pub fn encode_into(self, output: &mut [u8]) -> Result<usize, DecodeError> {
        if self.transaction_id == 0 {
            return Err(DecodeError::ZeroTransactionId);
        }
        if output.len() < BOOTSTRAP_INIT_V1_SIZE {
            return Err(DecodeError::EncodeBufferTooSmall);
        }
        write_header(
            output,
            MessageType::BootstrapInitV1,
            BOOTSTRAP_INIT_V1_SIZE as u32,
            INIT_CAPABILITY_COUNT,
            self.transaction_id,
        );
        write_u32(
            output,
            HEADER_SIZE,
            CapabilityRole::SelfRootAddressRegion as u32,
        );
        write_u32(output, HEADER_SIZE + 4, 0);
        write_u32(
            output,
            HEADER_SIZE + ROLE_DESCRIPTOR_SIZE,
            CapabilityRole::BootfsMemoryObject as u32,
        );
        write_u32(output, HEADER_SIZE + ROLE_DESCRIPTOR_SIZE + 4, 0);
        Ok(BOOTSTRAP_INIT_V1_SIZE)
    }
}

impl ReadyMessage {
    /// Encodes the exact V1 READY payload into `output`.
    pub fn encode_into(self, output: &mut [u8]) -> Result<usize, DecodeError> {
        if self.transaction_id == 0 {
            return Err(DecodeError::ZeroTransactionId);
        }
        if output.len() < BOOTSTRAP_READY_V1_SIZE {
            return Err(DecodeError::EncodeBufferTooSmall);
        }
        write_header(
            output,
            MessageType::BootstrapReadyV1,
            BOOTSTRAP_READY_V1_SIZE as u32,
            READY_CAPABILITY_COUNT,
            self.transaction_id,
        );
        Ok(BOOTSTRAP_READY_V1_SIZE)
    }
}

/// Decodes a complete message and independently verifies its received-handle count.
pub fn decode(input: &[u8], received_handle_count: usize) -> Result<BootstrapMessage, DecodeError> {
    if input.len() < HEADER_SIZE {
        return Err(DecodeError::TruncatedHeader);
    }
    if input[..4] != PROTOCOL_MAGIC {
        return Err(DecodeError::WrongMagic);
    }
    if read_u16(input, 4) != PROTOCOL_MAJOR {
        return Err(DecodeError::UnsupportedMajor);
    }
    let minor = read_u16(input, 6);
    if !matches!(minor, PROTOCOL_MINOR | PROTOCOL_MINOR_V2) {
        return Err(DecodeError::UnsupportedMinor);
    }
    if read_u32(input, 12) != 0 {
        return Err(DecodeError::NonzeroFlags);
    }
    if read_u64(input, 32) != 0 {
        return Err(DecodeError::NonzeroReserved);
    }
    let transaction_id = read_u64(input, 24);
    if transaction_id == 0 {
        return Err(DecodeError::ZeroTransactionId);
    }
    match read_u32(input, 8) {
        INIT_TYPE if minor == PROTOCOL_MINOR => {
            decode_init(input, received_handle_count, transaction_id)
        }
        INIT_TYPE => decode_init_v2(input, received_handle_count, transaction_id),
        READY_TYPE if minor == PROTOCOL_MINOR => {
            decode_ready(input, received_handle_count, transaction_id)
        }
        READY_TYPE => decode_ready_v2(input, received_handle_count, transaction_id),
        _ => Err(DecodeError::UnknownMessageType),
    }
}

fn decode_init_v2(
    input: &[u8],
    received_handle_count: usize,
    transaction_id: u64,
) -> Result<BootstrapMessage, DecodeError> {
    if read_u32(input, 16) != BOOTSTRAP_INIT_V2_SIZE as u32 || input.len() != BOOTSTRAP_INIT_V2_SIZE
    {
        return Err(DecodeError::WrongTotalSize);
    }
    if read_u32(input, 20) != INIT_V2_CAPABILITY_COUNT {
        return Err(DecodeError::WrongCapabilityCount);
    }
    if received_handle_count != MAX_BOOTSTRAP_HANDLES {
        return Err(DecodeError::WrongHandleCount);
    }
    for (index, role) in [
        CapabilityRole::SelfRootAddressRegion,
        CapabilityRole::BootfsMemoryObject,
        CapabilityRole::LoaderTaskGroup,
    ]
    .into_iter()
    .enumerate()
    {
        if read_u32(input, HEADER_SIZE + index * ROLE_DESCRIPTOR_SIZE) != role as u32
            || read_u32(input, HEADER_SIZE + index * ROLE_DESCRIPTOR_SIZE + 4) != 0
        {
            return Err(DecodeError::WrongCapabilityRoles);
        }
    }
    Ok(BootstrapMessage::InitV2(InitMessageV2 { transaction_id }))
}

fn decode_init(
    input: &[u8],
    received_handle_count: usize,
    transaction_id: u64,
) -> Result<BootstrapMessage, DecodeError> {
    if read_u32(input, 16) != BOOTSTRAP_INIT_V1_SIZE as u32 || input.len() != BOOTSTRAP_INIT_V1_SIZE
    {
        return Err(DecodeError::WrongTotalSize);
    }
    if read_u32(input, 20) != INIT_CAPABILITY_COUNT {
        return Err(DecodeError::WrongCapabilityCount);
    }
    if received_handle_count != INIT_CAPABILITY_COUNT as usize {
        return Err(DecodeError::WrongHandleCount);
    }
    if read_u32(input, HEADER_SIZE) != CapabilityRole::SelfRootAddressRegion as u32
        || read_u32(input, HEADER_SIZE + 4) != 0
        || read_u32(input, HEADER_SIZE + ROLE_DESCRIPTOR_SIZE)
            != CapabilityRole::BootfsMemoryObject as u32
        || read_u32(input, HEADER_SIZE + ROLE_DESCRIPTOR_SIZE + 4) != 0
    {
        return Err(DecodeError::WrongCapabilityRoles);
    }
    Ok(BootstrapMessage::Init(InitMessage { transaction_id }))
}

fn decode_ready(
    input: &[u8],
    received_handle_count: usize,
    transaction_id: u64,
) -> Result<BootstrapMessage, DecodeError> {
    if read_u32(input, 16) != BOOTSTRAP_READY_V1_SIZE as u32
        || input.len() != BOOTSTRAP_READY_V1_SIZE
    {
        return Err(DecodeError::WrongTotalSize);
    }
    if read_u32(input, 20) != READY_CAPABILITY_COUNT {
        return Err(DecodeError::WrongCapabilityCount);
    }
    if received_handle_count != 0 {
        return Err(DecodeError::WrongHandleCount);
    }
    Ok(BootstrapMessage::Ready(ReadyMessage { transaction_id }))
}

fn decode_ready_v2(
    input: &[u8],
    received_handle_count: usize,
    transaction_id: u64,
) -> Result<BootstrapMessage, DecodeError> {
    if read_u32(input, 16) != BOOTSTRAP_READY_V2_SIZE as u32
        || input.len() != BOOTSTRAP_READY_V2_SIZE
    {
        return Err(DecodeError::WrongTotalSize);
    }
    if read_u32(input, 20) != READY_CAPABILITY_COUNT {
        return Err(DecodeError::WrongCapabilityCount);
    }
    if received_handle_count != 0 {
        return Err(DecodeError::WrongHandleCount);
    }
    Ok(BootstrapMessage::ReadyV2(ReadyMessageV2 { transaction_id }))
}

fn write_header(
    output: &mut [u8],
    message_type: MessageType,
    total_size: u32,
    capability_count: u32,
    transaction_id: u64,
) {
    write_header_version(
        output,
        message_type,
        PROTOCOL_MINOR,
        total_size,
        capability_count,
        transaction_id,
    );
}

fn write_header_version(
    output: &mut [u8],
    message_type: MessageType,
    minor: u16,
    total_size: u32,
    capability_count: u32,
    transaction_id: u64,
) {
    output[..HEADER_SIZE].fill(0);
    output[..4].copy_from_slice(&PROTOCOL_MAGIC);
    write_u16(output, 4, PROTOCOL_MAJOR);
    write_u16(output, 6, minor);
    write_u32(
        output,
        8,
        match message_type {
            MessageType::BootstrapInitV1 => INIT_TYPE,
            MessageType::BootstrapReadyV1 => READY_TYPE,
            MessageType::BootstrapInitV2 => INIT_TYPE,
            MessageType::BootstrapReadyV2 => READY_TYPE,
        },
    );
    write_u32(output, 16, total_size);
    write_u32(output, 20, capability_count);
    write_u64(output, 24, transaction_id);
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([input[offset], input[offset + 1]])
}
fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}
fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
        input[offset + 4],
        input[offset + 5],
        input[offset + 6],
        input[offset + 7],
    ])
}
fn write_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn write_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn write_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    const INIT_GOLDEN: [u8; BOOTSTRAP_INIT_V1_SIZE] = [
        0x57, 0x52, 0x42, 0x50, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 2, 0, 0, 0, 1, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0,
    ];
    const READY_GOLDEN: [u8; BOOTSTRAP_READY_V1_SIZE] = [
        0x57, 0x52, 0x42, 0x50, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 1, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    const INIT_V2_GOLDEN: [u8; BOOTSTRAP_INIT_V2_SIZE] = [
        0x57, 0x52, 0x42, 0x50, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 3, 0, 0, 0, 1, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0,
        3, 0, 0, 0, 0, 0, 0, 0,
    ];
    const READY_V2_GOLDEN: [u8; BOOTSTRAP_READY_V2_SIZE] = [
        0x57, 0x52, 0x42, 0x50, 1, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 1, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    #[test]
    fn g0_golden_vectors_round_trip() {
        let mut init = [0u8; BOOTSTRAP_INIT_V1_SIZE];
        assert_eq!(
            InitMessage::primordial().encode_into(&mut init),
            Ok(init.len())
        );
        assert_eq!(init, INIT_GOLDEN);
        assert_eq!(
            decode(&init, 2),
            Ok(BootstrapMessage::Init(InitMessage::primordial()))
        );
        let mut ready = [0u8; BOOTSTRAP_READY_V1_SIZE];
        assert_eq!(
            ReadyMessage { transaction_id: 1 }.encode_into(&mut ready),
            Ok(ready.len())
        );
        assert_eq!(ready, READY_GOLDEN);
        assert_eq!(
            decode(&ready, 0),
            Ok(BootstrapMessage::Ready(ReadyMessage { transaction_id: 1 }))
        );
    }

    #[test]
    fn h_golden_vectors_round_trip() {
        let mut init = [0u8; BOOTSTRAP_INIT_V2_SIZE];
        assert_eq!(
            InitMessageV2::primordial().encode_into(&mut init),
            Ok(init.len())
        );
        assert_eq!(init, INIT_V2_GOLDEN);
        assert_eq!(
            decode(&init, 3),
            Ok(BootstrapMessage::InitV2(InitMessageV2::primordial()))
        );
        let mut ready = [0u8; BOOTSTRAP_READY_V2_SIZE];
        assert_eq!(
            ReadyMessageV2 { transaction_id: 1 }.encode_into(&mut ready),
            Ok(ready.len())
        );
        assert_eq!(ready, READY_V2_GOLDEN);
        assert_eq!(
            decode(&ready, 0),
            Ok(BootstrapMessage::ReadyV2(ReadyMessageV2 {
                transaction_id: 1
            }))
        );
    }

    #[test]
    fn rejects_header_constraints() {
        let cases = [
            (0usize, 0x58, DecodeError::WrongMagic),
            (4, 2, DecodeError::UnsupportedMajor),
            (6, 2, DecodeError::UnsupportedMinor),
            (8, 3, DecodeError::UnknownMessageType),
            (12, 1, DecodeError::NonzeroFlags),
            (16, 55, DecodeError::WrongTotalSize),
            (20, 1, DecodeError::WrongCapabilityCount),
            (24, 0, DecodeError::ZeroTransactionId),
            (32, 1, DecodeError::NonzeroReserved),
        ];
        for (offset, value, expected) in cases {
            let mut bytes = INIT_GOLDEN;
            bytes[offset] = value;
            assert_eq!(decode(&bytes, 2), Err(expected), "offset {offset}");
        }
        assert_eq!(
            decode(&INIT_GOLDEN[..39], 2),
            Err(DecodeError::TruncatedHeader)
        );
    }

    #[test]
    fn rejects_handle_role_and_trailing_confusion() {
        assert_eq!(decode(&INIT_GOLDEN, 1), Err(DecodeError::WrongHandleCount));
        let mut duplicate = INIT_GOLDEN;
        duplicate[48] = 1;
        assert_eq!(
            decode(&duplicate, 2),
            Err(DecodeError::WrongCapabilityRoles)
        );
        let mut reserved = INIT_GOLDEN;
        reserved[44] = 1;
        assert_eq!(decode(&reserved, 2), Err(DecodeError::WrongCapabilityRoles));
        let mut trailing = [0u8; BOOTSTRAP_INIT_V1_SIZE + 1];
        trailing[..BOOTSTRAP_INIT_V1_SIZE].copy_from_slice(&INIT_GOLDEN);
        assert_eq!(decode(&trailing, 2), Err(DecodeError::WrongTotalSize));
    }

    #[test]
    fn encoder_rejects_zero_transaction_and_short_buffer() {
        assert_eq!(
            InitMessage { transaction_id: 0 }.encode_into(&mut [0; 56]),
            Err(DecodeError::ZeroTransactionId)
        );
        assert_eq!(
            ReadyMessage { transaction_id: 1 }.encode_into(&mut [0; 39]),
            Err(DecodeError::EncodeBufferTooSmall)
        );
    }
}
