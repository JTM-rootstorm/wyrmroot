#![no_std]
#![forbid(unsafe_code)]

//! Primordial Wyrmroot bootstrap transaction shared by the native entry and host fixtures.

use deepwyrm_syscall::{DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights};
use wyrmroot_bootfs::archive::{Archive, LookupError, ParseError};
use wyrmroot_bootstrap_proto::{
    BOOTSTRAP_INIT_V1_SIZE, BOOTSTRAP_READY_V1_SIZE, BootstrapMessage, DecodeError, InitMessage,
    MAX_BOOTSTRAP_HANDLES, ReadyMessage, decode,
};
use wyrmroot_runtime::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, CapabilityValidationError,
    InitCapability, MappingPlan, MappingPlanError, NativeError, ReceiveCounts,
    SELF_ROOT_EXPECTATION, validate_bootstrap_channel, validate_init_capabilities,
};

/// Canonical init executable required in the primordial bootfs.
pub const INIT0_PATH: &[u8] = b"system/init0";
/// Canonical smoke executable required in the primordial bootfs.
pub const HELLO_PATH: &[u8] = b"bin/hello";

/// Native operations used by the shared bootstrap transaction.
pub trait BootstrapSystem {
    /// Queries fresh basic object metadata.
    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError>;

    /// Receives one complete Channel datagram.
    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError>;

    /// Queries an immutable MemoryObject's exact logical size.
    fn query_memory_object_size(&mut self, handle: DwHandle) -> Result<u64, NativeError>;

    /// Maps the bootfs for one non-escaping logical-byte callback, then unmaps it.
    fn with_bootfs_bytes<R>(
        &mut self,
        root_region: DwHandle,
        bootfs: DwHandle,
        plan: MappingPlan,
        use_bytes: impl for<'bytes> FnOnce(&'bytes [u8]) -> R,
    ) -> Result<R, NativeError>;

    /// Sends one handle-free Channel datagram.
    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError>;

    /// Closes one caller-local handle.
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError>;
}

/// Why the primordial bootstrap transaction failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapError {
    /// A native Deepwyrm operation failed or returned malformed output.
    Native(NativeError),
    /// The startup Channel did not have its exact type and rights.
    BootstrapChannel(CapabilityValidationError),
    /// INIT bytes or handle counts violated the locked protocol.
    Protocol(DecodeError),
    /// A valid protocol message was not the single expected INIT message.
    UnexpectedMessage,
    /// INIT used a nonzero transaction identifier other than the G0 primordial value `1`.
    UnexpectedTransactionId,
    /// Received or freshly queried capability metadata violated the exact role contract.
    Capability(CapabilityValidationError),
    /// The bootfs logical size could not produce a bounded mapping.
    Mapping(MappingPlanError),
    /// The mapped bootfs archive was malformed.
    Bootfs(ParseError),
    /// A required canonical bootfs entry was absent.
    MissingRequiredEntry,
    /// A required bootfs entry was not immutable executable content.
    RequiredEntryNotExecutable,
}

/// Executes the complete D2 bootstrap handshake without exiting the process.
pub fn run_bootstrap<System: BootstrapSystem>(
    system: &mut System,
    bootstrap_channel: DwHandle,
) -> Result<(), BootstrapError> {
    let channel_info = system
        .query_capability_info(bootstrap_channel)
        .map_err(BootstrapError::Native)?;
    validate_bootstrap_channel(channel_info, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(BootstrapError::BootstrapChannel)?;

    let mut bytes = [0_u8; BOOTSTRAP_INIT_V1_SIZE];
    let mut handles = [DwReceivedHandleInfoV1::default(); MAX_BOOTSTRAP_HANDLES];
    let counts = system
        .receive_channel(bootstrap_channel, &mut bytes, &mut handles)
        .map_err(BootstrapError::Native)?;

    let operation = (|| {
        let transaction_id = match decode(&bytes[..counts.bytes], counts.handles)
            .map_err(BootstrapError::Protocol)?
        {
            BootstrapMessage::Init(message) => {
                if message.transaction_id != InitMessage::primordial().transaction_id {
                    return Err(BootstrapError::UnexpectedTransactionId);
                }
                message.transaction_id
            }
            BootstrapMessage::Ready(_) => return Err(BootstrapError::UnexpectedMessage),
        };
        process_init(system, &handles[..counts.handles])?;
        Ok(transaction_id)
    })();
    let cleanup = close_received_handles(system, &handles[..counts.handles]);
    let transaction_id = operation?;
    cleanup?;

    let mut ready = [0_u8; BOOTSTRAP_READY_V1_SIZE];
    let ready_size = ReadyMessage { transaction_id }
        .encode_into(&mut ready)
        .map_err(BootstrapError::Protocol)?;
    system
        .send_channel(bootstrap_channel, &ready[..ready_size])
        .map_err(BootstrapError::Native)?;
    system
        .close_handle(bootstrap_channel)
        .map_err(BootstrapError::Native)
}

fn process_init<System: BootstrapSystem>(
    system: &mut System,
    handles: &[DwReceivedHandleInfoV1],
) -> Result<(), BootstrapError> {
    if handles.len() != MAX_BOOTSTRAP_HANDLES {
        return Err(BootstrapError::Capability(
            CapabilityValidationError::WrongInitCapabilityCount,
        ));
    }
    let received = [
        received_capability(handles[0]),
        received_capability(handles[1]),
    ];
    let fresh = [
        system
            .query_capability_info(handles[0].handle)
            .map_err(BootstrapError::Native)?,
        system
            .query_capability_info(handles[1].handle)
            .map_err(BootstrapError::Native)?,
    ];
    let capabilities = [
        InitCapability {
            received: received[0],
            fresh: fresh[0],
        },
        InitCapability {
            received: received[1],
            fresh: fresh[1],
        },
    ];
    validate_init_capabilities(&capabilities, SELF_ROOT_EXPECTATION, BOOTFS_EXPECTATION)
        .map_err(BootstrapError::Capability)?;

    let logical_size = system
        .query_memory_object_size(handles[1].handle)
        .map_err(BootstrapError::Native)?;
    let plan = MappingPlan::for_bootfs(logical_size).map_err(BootstrapError::Mapping)?;
    system
        .with_bootfs_bytes(handles[0].handle, handles[1].handle, plan, validate_bootfs)
        .map_err(BootstrapError::Native)?
}

fn received_capability(info: DwReceivedHandleInfoV1) -> CapabilityInfo<DwObjectType, DwRights> {
    CapabilityInfo {
        object_type: info.object_type,
        rights: info.rights,
    }
}

fn close_received_handles<System: BootstrapSystem>(
    system: &mut System,
    handles: &[DwReceivedHandleInfoV1],
) -> Result<(), BootstrapError> {
    let mut first_error = None;
    for info in handles {
        if let Err(error) = system.close_handle(info.handle)
            && first_error.is_none()
        {
            first_error = Some(BootstrapError::Native(error));
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn validate_bootfs(bytes: &[u8]) -> Result<(), BootstrapError> {
    let archive = Archive::new(bytes).map_err(BootstrapError::Bootfs)?;
    for path in [INIT0_PATH, HELLO_PATH] {
        let entry = archive.lookup(path).map_err(|error| match error {
            LookupError::NotFound | LookupError::InvalidPath(_) => {
                BootstrapError::MissingRequiredEntry
            }
        })?;
        if !entry.is_executable() || entry.data().is_empty() {
            return Err(BootstrapError::RequiredEntryNotExecutable);
        }
    }
    Ok(())
}
