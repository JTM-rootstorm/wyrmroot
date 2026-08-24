//! Wyrmroot parent/child launch protocol (`WRLP`) encoding and validation.

use deepwyrm_syscall::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_MEMORY_OBJECT, DW_OBJECT_TYPE_TASK_GROUP,
    DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT, DW_RIGHT_MAP, DW_RIGHT_MODIFY, DW_RIGHT_READ,
    DW_RIGHT_TRANSFER, DwObjectType, DwReceivedHandleInfoV1, DwRights,
};

pub const HEADER_BYTES: usize = 40;
pub const INIT0_BYTES: usize = 64;
pub const MAX_CAPABILITIES: usize = 3;

const MAGIC: &[u8; 4] = b"WRLP";
const MAJOR: u16 = 1;
const MINOR: u16 = 0;
const TYPE_INIT: u32 = 1;
const TYPE_READY: u32 = 2;
const ROLE_SELF_ROOT: u32 = 1;
const ROLE_BOOTFS: u32 = 2;
const ROLE_LOADER_TASK_GROUP: u32 = 3;

pub const SELF_ROOT_RIGHTS: DwRights =
    DwRights(DW_RIGHT_MAP.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0);
pub const BOOTFS_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0
        | DW_RIGHT_MAP.0
        | DW_RIGHT_INSPECT.0
        | DW_RIGHT_DUPLICATE.0
        | DW_RIGHT_TRANSFER.0,
);
pub const LOADER_TASK_GROUP_RIGHTS: DwRights =
    DwRights(DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_DUPLICATE.0 | DW_RIGHT_TRANSFER.0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchProfile {
    Init0,
    /// Test-only I2 controller.  It receives the same explicitly delegated
    /// construction authority as init0, but is selected only by the I2 image.
    I2Stress,
    Hello,
}

impl LaunchProfile {
    pub const fn capability_count(self) -> usize {
        match self {
            Self::Init0 | Self::I2Stress => 3,
            Self::Hello => 0,
        }
    }

    pub const fn init_size(self) -> usize {
        HEADER_BYTES + self.capability_count() * 8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedMessage {
    pub transaction_id: u64,
    pub profile: LaunchProfile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchError {
    BufferSize,
    BadMagic,
    BadVersion,
    BadType,
    NonzeroFlags,
    BadTotalSize,
    BadCapabilityCount,
    ZeroTransaction,
    TransactionMismatch,
    NonzeroReserved,
    BadCapabilityRole { index: usize },
    HandleCount,
    HandleMetadata { index: usize },
}

pub fn encode_init(
    profile: LaunchProfile,
    transaction_id: u64,
    output: &mut [u8],
) -> Result<usize, LaunchError> {
    let size = profile.init_size();
    if output.len() < size {
        return Err(LaunchError::BufferSize);
    }
    if transaction_id == 0 {
        return Err(LaunchError::ZeroTransaction);
    }
    output[..size].fill(0);
    write_header(
        &mut output[..size],
        TYPE_INIT,
        size as u32,
        profile.capability_count() as u32,
        transaction_id,
    );
    if profile.has_init0_capabilities() {
        for (index, role) in [ROLE_SELF_ROOT, ROLE_BOOTFS, ROLE_LOADER_TASK_GROUP]
            .into_iter()
            .enumerate()
        {
            put_u32(output, HEADER_BYTES + index * 8, role);
        }
    }
    Ok(size)
}

pub fn parse_init(
    profile: LaunchProfile,
    bytes: &[u8],
    handles: &[DwReceivedHandleInfoV1],
) -> Result<ParsedMessage, LaunchError> {
    let transaction_id = parse_header(
        bytes,
        TYPE_INIT,
        profile.init_size(),
        profile.capability_count(),
    )?;
    if handles.len() != profile.capability_count() {
        return Err(LaunchError::HandleCount);
    }
    if profile.has_init0_capabilities() {
        let expected = [
            (
                ROLE_SELF_ROOT,
                DW_OBJECT_TYPE_ADDRESS_REGION,
                SELF_ROOT_RIGHTS,
            ),
            (ROLE_BOOTFS, DW_OBJECT_TYPE_MEMORY_OBJECT, BOOTFS_RIGHTS),
            (
                ROLE_LOADER_TASK_GROUP,
                DW_OBJECT_TYPE_TASK_GROUP,
                LOADER_TASK_GROUP_RIGHTS,
            ),
        ];
        for (index, (role, object_type, rights)) in expected.into_iter().enumerate() {
            if get_u32(bytes, HEADER_BYTES + index * 8) != role
                || get_u32(bytes, HEADER_BYTES + index * 8 + 4) != 0
            {
                return Err(LaunchError::BadCapabilityRole { index });
            }
            validate_handle(handles[index], object_type, rights, index)?;
        }
    }
    Ok(ParsedMessage {
        transaction_id,
        profile,
    })
}

impl LaunchProfile {
    pub const fn has_init0_capabilities(self) -> bool {
        matches!(self, Self::Init0 | Self::I2Stress)
    }
}

pub fn encode_ready(transaction_id: u64, output: &mut [u8]) -> Result<usize, LaunchError> {
    if output.len() < HEADER_BYTES {
        return Err(LaunchError::BufferSize);
    }
    if transaction_id == 0 {
        return Err(LaunchError::ZeroTransaction);
    }
    output[..HEADER_BYTES].fill(0);
    write_header(output, TYPE_READY, HEADER_BYTES as u32, 0, transaction_id);
    Ok(HEADER_BYTES)
}

pub fn parse_ready(bytes: &[u8], expected_transaction: u64) -> Result<(), LaunchError> {
    let transaction_id = parse_header(bytes, TYPE_READY, HEADER_BYTES, 0)?;
    if transaction_id != expected_transaction {
        return Err(LaunchError::TransactionMismatch);
    }
    Ok(())
}

fn parse_header(
    bytes: &[u8],
    message_type: u32,
    expected_size: usize,
    expected_capabilities: usize,
) -> Result<u64, LaunchError> {
    if bytes.len() != expected_size {
        return Err(LaunchError::BufferSize);
    }
    if &bytes[..4] != MAGIC {
        return Err(LaunchError::BadMagic);
    }
    if get_u16(bytes, 4) != MAJOR || get_u16(bytes, 6) != MINOR {
        return Err(LaunchError::BadVersion);
    }
    if get_u32(bytes, 8) != message_type {
        return Err(LaunchError::BadType);
    }
    if get_u32(bytes, 12) != 0 {
        return Err(LaunchError::NonzeroFlags);
    }
    if get_u32(bytes, 16) as usize != expected_size {
        return Err(LaunchError::BadTotalSize);
    }
    if get_u32(bytes, 20) as usize != expected_capabilities {
        return Err(LaunchError::BadCapabilityCount);
    }
    let transaction_id = get_u64(bytes, 24);
    if transaction_id == 0 {
        return Err(LaunchError::ZeroTransaction);
    }
    if get_u64(bytes, 32) != 0 {
        return Err(LaunchError::NonzeroReserved);
    }
    Ok(transaction_id)
}

fn validate_handle(
    handle: DwReceivedHandleInfoV1,
    object_type: DwObjectType,
    rights: DwRights,
    index: usize,
) -> Result<(), LaunchError> {
    if handle.handle.0 == 0
        || handle.object_type != object_type
        || handle.rights != rights
        || handle.reserved0 != 0
        || handle.reserved != [0; 2]
    {
        return Err(LaunchError::HandleMetadata { index });
    }
    Ok(())
}

fn write_header(
    output: &mut [u8],
    message_type: u32,
    total_size: u32,
    capabilities: u32,
    transaction_id: u64,
) {
    output[..4].copy_from_slice(MAGIC);
    put_u16(output, 4, MAJOR);
    put_u16(output, 6, MINOR);
    put_u32(output, 8, message_type);
    put_u32(output, 16, total_size);
    put_u32(output, 20, capabilities);
    put_u64(output, 24, transaction_id);
}

fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
