//! Wyrmroot parent/child launch protocol (`WRLP`) encoding and validation.
//!
//! Existing launch profiles retain the WRLP 1.0 wire shape. WYR0-I probe
//! children use the explicit WRLP 1.1 profile for both INIT and READY so a
//! self-root-only startup grant cannot be confused with the controller's
//! authority trio.

use deepwyrm_syscall::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_MEMORY_OBJECT,
    DW_OBJECT_TYPE_TASK_GROUP, DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT, DW_RIGHT_MAP, DW_RIGHT_MODIFY,
    DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DW_RIGHT_WRITE, DwObjectType,
    DwReceivedHandleInfoV1, DwRights,
};

pub const HEADER_BYTES: usize = 40;
pub const INIT0_BYTES: usize = 64;
pub const SUPERVISOR_BYTES: usize = 64;
pub const PROBE_CHILD_BYTES: usize = 48;
pub const MAX_CAPABILITIES: usize = 3;

const MAGIC: &[u8; 4] = b"WRLP";
const MAJOR: u16 = 1;
const MINOR_V1_0: u16 = 0;
const MINOR_V1_1: u16 = 1;
const MINOR_V1_2: u16 = 2;
const MINOR_V1_3: u16 = 3;
const MINOR_V1_4_TEST: u16 = 4;
const MINOR_V1_5: u16 = 5;
const TYPE_INIT: u32 = 1;
const TYPE_READY: u32 = 2;
const ROLE_SELF_ROOT: u32 = 1;
const ROLE_BOOTFS: u32 = 2;
const ROLE_LOADER_TASK_GROUP: u32 = 3;
const ROLE_SUPERVISOR_CONTROL: u32 = 4;
const ROLE_PUBLICATION_AUTHORITY: u32 = 5;
const ROLE_REGISTRY_CLIENT: u32 = 6;
const ROLE_LAUNCH_SESSION: u32 = 7;
const ROLE_STDIN: u32 = 8;
const ROLE_STDOUT: u32 = 9;
const ROLE_STDERR: u32 = 10;
const ROLE_DW1B_PROGRESS_DATA: u32 = 11;
const ROLE_DEVICE_MANIFEST: u32 = 12;

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
pub const CHILD_CHANNEL_RIGHTS: DwRights =
    DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0);
/// Exact read-only manifest view delegated to the WYR1-C device coordinator.
pub const DEVICE_MANIFEST_RIGHTS: DwRights =
    DwRights(DW_RIGHT_READ.0 | DW_RIGHT_MAP.0 | DW_RIGHT_INSPECT.0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchProfile {
    Init0,
    /// Test-only I2 controller.  It receives the same explicitly delegated
    /// construction authority as init0, but is selected only by the I2 image.
    I2Stress,
    /// WYR0-I controller. It retains the established WRLP 1.0 authority trio
    /// so it can launch and supervise its own probe children.
    CapabilityController,
    /// WYR0-I ordinary probe child. Its WRLP 1.1 INIT carries only the child
    /// self-root; controller-originated objects arrive after startup.
    ProbeChild,
    /// Permanent WYR1 supervisor with the exact loader authority trio.
    Supervisor,
    /// WYR1-A early-role stub with only its generation-bound launch Channel.
    EarlyBootStub,
    /// Separate resident WYR1-B registry with self root and supervisor control.
    BootstrapRegistry,
    /// WYR1-B publisher with self root and one publication authority endpoint.
    BootstrapService,
    /// WYR1-B registry client with self root and one client endpoint.
    RegistryClient,
    /// WYR1-B launch client with self root and one launch-session endpoint.
    LaunchClient,
    /// WYR1-B launched job with no startup stream roles.
    JobV2,
    /// WYR1-B launched job with exact stdin/stdout/stderr Channel roles.
    JobV2Streams,
    /// Selector-26-only progress peer with exactly one test data Channel.
    Dw1bProgress,
    /// WYR1-C device coordinator with self root, publication authority, and
    /// one immutable device-role manifest object. This profile contains no
    /// hardware authority.
    DeviceCoordinator,
    Hello,
}

impl LaunchProfile {
    pub const fn capability_count(self) -> usize {
        match self {
            Self::Init0 | Self::I2Stress | Self::CapabilityController | Self::Supervisor => 3,
            Self::ProbeChild | Self::Dw1bProgress => 1,
            Self::BootstrapRegistry
            | Self::BootstrapService
            | Self::RegistryClient
            | Self::LaunchClient => 2,
            Self::JobV2Streams => 3,
            Self::DeviceCoordinator => 3,
            Self::Hello | Self::EarlyBootStub | Self::JobV2 => 0,
        }
    }

    pub const fn protocol_minor(self) -> u16 {
        match self {
            Self::ProbeChild => MINOR_V1_1,
            Self::Supervisor | Self::EarlyBootStub => MINOR_V1_2,
            Self::BootstrapRegistry
            | Self::BootstrapService
            | Self::RegistryClient
            | Self::LaunchClient
            | Self::JobV2
            | Self::JobV2Streams => MINOR_V1_3,
            Self::Dw1bProgress => MINOR_V1_4_TEST,
            Self::DeviceCoordinator => MINOR_V1_5,
            Self::Init0 | Self::I2Stress | Self::CapabilityController | Self::Hello => MINOR_V1_0,
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
        profile.protocol_minor(),
        TYPE_INIT,
        size as u32,
        profile.capability_count() as u32,
        transaction_id,
    );
    if profile.has_loader_authority_trio() {
        for (index, role) in [ROLE_SELF_ROOT, ROLE_BOOTFS, ROLE_LOADER_TASK_GROUP]
            .into_iter()
            .enumerate()
        {
            put_u32(output, HEADER_BYTES + index * 8, role);
        }
    } else if profile == LaunchProfile::DeviceCoordinator {
        for (index, role) in [
            ROLE_SELF_ROOT,
            ROLE_PUBLICATION_AUTHORITY,
            ROLE_DEVICE_MANIFEST,
        ]
        .into_iter()
        .enumerate()
        {
            put_u32(output, HEADER_BYTES + index * 8, role);
        }
    } else if profile == LaunchProfile::Dw1bProgress {
        put_u32(output, HEADER_BYTES, ROLE_DW1B_PROGRESS_DATA);
    } else if profile.needs_self_root() {
        put_u32(output, HEADER_BYTES, ROLE_SELF_ROOT);
        if let Some(role) = profile.channel_role() {
            put_u32(output, HEADER_BYTES + 8, role);
        }
    } else if profile == LaunchProfile::JobV2Streams {
        for (index, role) in [ROLE_STDIN, ROLE_STDOUT, ROLE_STDERR]
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
        profile.protocol_minor(),
        profile.init_size(),
        profile.capability_count(),
    )?;
    if handles.len() != profile.capability_count() {
        return Err(LaunchError::HandleCount);
    }
    if profile.has_loader_authority_trio() {
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
    } else if profile == LaunchProfile::DeviceCoordinator {
        let expected = [
            (
                ROLE_SELF_ROOT,
                DW_OBJECT_TYPE_ADDRESS_REGION,
                SELF_ROOT_RIGHTS,
            ),
            (
                ROLE_PUBLICATION_AUTHORITY,
                DW_OBJECT_TYPE_CHANNEL,
                CHILD_CHANNEL_RIGHTS,
            ),
            (
                ROLE_DEVICE_MANIFEST,
                DW_OBJECT_TYPE_MEMORY_OBJECT,
                DEVICE_MANIFEST_RIGHTS,
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
    } else if profile == LaunchProfile::Dw1bProgress {
        if get_u32(bytes, HEADER_BYTES) != ROLE_DW1B_PROGRESS_DATA
            || get_u32(bytes, HEADER_BYTES + 4) != 0
        {
            return Err(LaunchError::BadCapabilityRole { index: 0 });
        }
        validate_handle(handles[0], DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS, 0)?;
    } else if profile.needs_self_root() {
        if get_u32(bytes, HEADER_BYTES) != ROLE_SELF_ROOT || get_u32(bytes, HEADER_BYTES + 4) != 0 {
            return Err(LaunchError::BadCapabilityRole { index: 0 });
        }
        validate_handle(
            handles[0],
            DW_OBJECT_TYPE_ADDRESS_REGION,
            SELF_ROOT_RIGHTS,
            0,
        )?;
        if let Some(role) = profile.channel_role() {
            if get_u32(bytes, HEADER_BYTES + 8) != role || get_u32(bytes, HEADER_BYTES + 12) != 0 {
                return Err(LaunchError::BadCapabilityRole { index: 1 });
            }
            validate_handle(handles[1], DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS, 1)?;
        }
    } else if profile == LaunchProfile::JobV2Streams {
        for (index, role) in [ROLE_STDIN, ROLE_STDOUT, ROLE_STDERR]
            .into_iter()
            .enumerate()
        {
            if get_u32(bytes, HEADER_BYTES + index * 8) != role
                || get_u32(bytes, HEADER_BYTES + index * 8 + 4) != 0
            {
                return Err(LaunchError::BadCapabilityRole { index });
            }
            validate_handle(
                handles[index],
                DW_OBJECT_TYPE_CHANNEL,
                CHILD_CHANNEL_RIGHTS,
                index,
            )?;
        }
    }
    Ok(ParsedMessage {
        transaction_id,
        profile,
    })
}

impl LaunchProfile {
    pub const fn has_loader_authority_trio(self) -> bool {
        matches!(
            self,
            Self::Init0 | Self::I2Stress | Self::CapabilityController | Self::Supervisor
        )
    }

    pub const fn needs_self_root(self) -> bool {
        self.has_loader_authority_trio()
            || matches!(
                self,
                Self::ProbeChild
                    | Self::BootstrapRegistry
                    | Self::BootstrapService
                    | Self::RegistryClient
                    | Self::LaunchClient
                    | Self::DeviceCoordinator
            )
    }

    pub const fn channel_role(self) -> Option<u32> {
        match self {
            Self::BootstrapRegistry => Some(ROLE_SUPERVISOR_CONTROL),
            Self::BootstrapService => Some(ROLE_PUBLICATION_AUTHORITY),
            Self::RegistryClient => Some(ROLE_REGISTRY_CLIENT),
            Self::LaunchClient => Some(ROLE_LAUNCH_SESSION),
            Self::Dw1bProgress => Some(ROLE_DW1B_PROGRESS_DATA),
            _ => None,
        }
    }
}

pub fn encode_ready(transaction_id: u64, output: &mut [u8]) -> Result<usize, LaunchError> {
    // Compatibility entry point for existing WRLP 1.0 callers. New launch
    // flows must bind READY to the same profile used to validate INIT.
    encode_ready_for_profile(LaunchProfile::Hello, transaction_id, output)
}

pub fn encode_ready_for_profile(
    profile: LaunchProfile,
    transaction_id: u64,
    output: &mut [u8],
) -> Result<usize, LaunchError> {
    if output.len() < HEADER_BYTES {
        return Err(LaunchError::BufferSize);
    }
    if transaction_id == 0 {
        return Err(LaunchError::ZeroTransaction);
    }
    output[..HEADER_BYTES].fill(0);
    write_header(
        output,
        profile.protocol_minor(),
        TYPE_READY,
        HEADER_BYTES as u32,
        0,
        transaction_id,
    );
    Ok(HEADER_BYTES)
}

pub fn parse_ready(bytes: &[u8], expected_transaction: u64) -> Result<(), LaunchError> {
    // Compatibility entry point for existing WRLP 1.0 callers. New launch
    // flows must bind READY to the same profile used to validate INIT.
    parse_ready_for_profile(LaunchProfile::Hello, bytes, expected_transaction)
}

pub fn parse_ready_for_profile(
    profile: LaunchProfile,
    bytes: &[u8],
    expected_transaction: u64,
) -> Result<(), LaunchError> {
    let transaction_id =
        parse_header(bytes, TYPE_READY, profile.protocol_minor(), HEADER_BYTES, 0)?;
    if transaction_id != expected_transaction {
        return Err(LaunchError::TransactionMismatch);
    }
    Ok(())
}

fn parse_header(
    bytes: &[u8],
    message_type: u32,
    expected_minor: u16,
    expected_size: usize,
    expected_capabilities: usize,
) -> Result<u64, LaunchError> {
    if bytes.len() != expected_size {
        return Err(LaunchError::BufferSize);
    }
    if &bytes[..4] != MAGIC {
        return Err(LaunchError::BadMagic);
    }
    if get_u16(bytes, 4) != MAJOR || get_u16(bytes, 6) != expected_minor {
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
    minor: u16,
    message_type: u32,
    total_size: u32,
    capabilities: u32,
    transaction_id: u64,
) {
    output[..4].copy_from_slice(MAGIC);
    put_u16(output, 4, MAJOR);
    put_u16(output, 6, minor);
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
