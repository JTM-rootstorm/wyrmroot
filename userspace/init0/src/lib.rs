#![no_std]
#![forbid(unsafe_code)]

//! Temporary WYR0 `init0` application contract.
//!
//! WYR0-F validates its one-time loader handoff and publishes READY.  It intentionally does not
//! interpret the delegated bootfs or create a descendant; those are WYR0-G responsibilities.

use deepwyrm_syscall::{DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights};
use wyrmroot_loader::launch::{
    HEADER_BYTES, INIT0_BYTES, LaunchError, LaunchProfile, encode_ready, parse_init,
};
use wyrmroot_runtime::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, CapabilityValidationError,
    InitCapability, LOADER_TASK_GROUP_EXPECTATION, NativeError, ReceiveCounts,
    SELF_ROOT_EXPECTATION, validate_bootstrap_channel, validate_init_capabilities_v2,
};

/// Native operations used by the deliberately minimal WYR0-F `init0` handoff.
pub trait Init0System {
    /// Queries current object metadata for a locally held capability.
    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError>;

    /// Receives one complete loader launch datagram.
    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError>;

    /// Sends one handle-free loader READY datagram.
    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError>;

    /// Closes one caller-local handle.
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError>;
}

/// Why the WYR0-F `init0` startup transaction failed.
#[derive(Debug, Eq, PartialEq)]
pub enum Init0Error {
    /// A typed native operation failed or reported malformed output.
    Native(NativeError),
    /// The startup Channel did not have the exact locked type and rights.
    BootstrapChannel(CapabilityValidationError),
    /// The loader INIT or READY encoding violated WRLP.
    Launch(LaunchError),
    /// The receive result exceeded the caller-provided fixed protocol buffers.
    ReceiveCounts(ReceiveCounts),
    /// Received or freshly queried capability metadata violated the exact Init0 contract.
    Capability(CapabilityValidationError),
}

/// Validates the WYR0-F loader handoff, then publishes the matching handle-free READY.
///
/// The native entry macro has already validated the immutable startup page before this function
/// receives the bootstrap Channel.  This transaction re-queries every received authority before
/// use, closes all three delegated capabilities, and intentionally performs no bootfs parsing or
/// child creation.
pub fn run_init0<System: Init0System>(
    system: &mut System,
    bootstrap_channel: DwHandle,
) -> Result<(), Init0Error> {
    let channel = system
        .query_capability_info(bootstrap_channel)
        .map_err(Init0Error::Native)?;
    validate_bootstrap_channel(channel, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(Init0Error::BootstrapChannel)?;

    let mut bytes = [0_u8; INIT0_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 3];
    let counts = system
        .receive_channel(bootstrap_channel, &mut bytes, &mut handles)
        .map_err(Init0Error::Native)?;
    if counts.bytes > bytes.len() || counts.handles > handles.len() {
        return Err(Init0Error::ReceiveCounts(counts));
    }
    let operation = (|| {
        let message = parse_init(
            LaunchProfile::Init0,
            &bytes[..counts.bytes],
            &handles[..counts.handles],
        )
        .map_err(Init0Error::Launch)?;
        let capabilities = [
            init_capability(system, handles[0])?,
            init_capability(system, handles[1])?,
            init_capability(system, handles[2])?,
        ];
        validate_init_capabilities_v2(
            &capabilities,
            SELF_ROOT_EXPECTATION,
            BOOTFS_EXPECTATION,
            LOADER_TASK_GROUP_EXPECTATION,
        )
        .map_err(Init0Error::Capability)?;
        Ok(message.transaction_id)
    })();
    let cleanup = close_received_handles(system, &handles[..counts.handles]);
    let transaction_id = operation?;
    cleanup?;
    send_ready(system, bootstrap_channel, transaction_id)
}

fn init_capability<System: Init0System>(
    system: &mut System,
    received: DwReceivedHandleInfoV1,
) -> Result<InitCapability<DwObjectType, DwRights>, Init0Error> {
    Ok(InitCapability {
        received: CapabilityInfo {
            object_type: received.object_type,
            rights: received.rights,
        },
        fresh: system
            .query_capability_info(received.handle)
            .map_err(Init0Error::Native)?,
    })
}

fn close_received_handles<System: Init0System>(
    system: &mut System,
    handles: &[DwReceivedHandleInfoV1],
) -> Result<(), Init0Error> {
    let mut first_error = None;
    for handle in handles {
        if let Err(error) = system.close_handle(handle.handle)
            && first_error.is_none()
        {
            first_error = Some(Init0Error::Native(error));
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn send_ready<System: Init0System>(
    system: &mut System,
    bootstrap_channel: DwHandle,
    transaction_id: u64,
) -> Result<(), Init0Error> {
    let mut ready = [0_u8; HEADER_BYTES];
    let size = encode_ready(transaction_id, &mut ready).map_err(Init0Error::Launch)?;
    system
        .send_channel(bootstrap_channel, &ready[..size])
        .map_err(Init0Error::Native)?;
    system
        .close_handle(bootstrap_channel)
        .map_err(Init0Error::Native)
}
