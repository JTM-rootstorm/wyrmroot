#![no_std]
#![forbid(unsafe_code)]

//! WYR0 `hello` descendant smoke-test application contract.
//!
//! `hello` accepts only its retained loader Channel, validates the handle-free `Hello` WRLP
//! message, sends the matching READY reply, and then exits normally.  The reply is deliberately
//! small: it proves a capability-mediated parent/child exchange without delegating authority to
//! this smoke executable.

use deepwyrm_syscall::{DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights};
use wyrmroot_loader::launch::{HEADER_BYTES, LaunchError, LaunchProfile, encode_ready, parse_init};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, CapabilityValidationError, NativeError,
    ReceiveCounts, native_error_code, validate_bootstrap_channel,
};

/// Native operations used by the WYR0-G `hello` parent-channel exchange.
pub trait HelloSystem {
    /// Queries current object metadata for a locally held capability.
    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError>;

    /// Receives the single handle-free loader launch datagram.
    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError>;

    /// Sends the matching handle-free READY datagram.
    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError>;

    /// Closes one caller-local handle.
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError>;
}

/// Why the WYR0-G `hello` startup exchange failed.
#[derive(Debug, Eq, PartialEq)]
pub enum HelloError {
    /// A typed native operation failed or returned malformed output.
    Native {
        /// The exact hello-owned native operation that failed.
        operation: HelloNativeOperation,
        /// The bounded native status or malformed-output cause.
        cause: NativeError,
    },
    /// The startup Channel did not have its exact locked type and rights.
    BootstrapChannel(CapabilityValidationError),
    /// The receive result exceeded the caller-provided fixed protocol buffers.
    ReceiveCounts(ReceiveCounts),
    /// The loader INIT or READY encoding violated WRLP.
    Launch(LaunchError),
}

/// Exact hello-owned native operation associated with a live failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HelloNativeOperation {
    /// Query the inherited bootstrap Channel's fresh type and rights.
    QueryBootstrapChannel = 1,
    /// Receive the loader INIT datagram.
    ReceiveInit = 2,
    /// Send the matching READY datagram.
    SendReady = 3,
    /// Close the caller-local bootstrap Channel handle.
    CloseBootstrapChannel = 4,
}

impl HelloError {
    /// Returns a bounded native application exit code for live integration diagnostics.
    #[must_use]
    pub const fn exit_code(&self) -> u32 {
        const PREFIX: u32 = 0x4800_0000;
        match self {
            Self::Native { operation, cause } => {
                PREFIX | ((*operation as u32) << 16) | native_error_code(*cause)
            }
            Self::BootstrapChannel(_) => PREFIX | 0x02,
            Self::ReceiveCounts(_) => PREFIX | 0x03,
            Self::Launch(_) => PREFIX | 0x04,
        }
    }
}

/// Completes the capability-mediated WYR0-G parent-channel exchange.
pub fn run_hello<System: HelloSystem>(
    system: &mut System,
    bootstrap_channel: DwHandle,
) -> Result<(), HelloError> {
    let channel = system
        .query_capability_info(bootstrap_channel)
        .map_err(|cause| HelloError::Native {
            operation: HelloNativeOperation::QueryBootstrapChannel,
            cause,
        })?;
    validate_bootstrap_channel(channel, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(HelloError::BootstrapChannel)?;

    let mut init = [0_u8; HEADER_BYTES];
    let mut handles = [];
    let counts = system
        .receive_channel(bootstrap_channel, &mut init, &mut handles)
        .map_err(|cause| HelloError::Native {
            operation: HelloNativeOperation::ReceiveInit,
            cause,
        })?;
    if counts.bytes > init.len() || counts.handles != 0 {
        return Err(HelloError::ReceiveCounts(counts));
    }
    let parsed = parse_init(LaunchProfile::Hello, &init[..counts.bytes], &handles)
        .map_err(HelloError::Launch)?;

    let mut ready = [0_u8; HEADER_BYTES];
    let ready_size = encode_ready(parsed.transaction_id, &mut ready).map_err(HelloError::Launch)?;
    system
        .send_channel(bootstrap_channel, &ready[..ready_size])
        .map_err(|cause| HelloError::Native {
            operation: HelloNativeOperation::SendReady,
            cause,
        })?;
    system
        .close_handle(bootstrap_channel)
        .map_err(|cause| HelloError::Native {
            operation: HelloNativeOperation::CloseBootstrapChannel,
            cause,
        })
}
