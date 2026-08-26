//! Separate WYR1-A bootstrap-role stub behavior.

#![no_std]
#![forbid(unsafe_code)]

use deepwyrm_syscall::{DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights};
use wyrmroot_loader::launch::{self, HEADER_BYTES, LaunchError, LaunchProfile};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, CapabilityValidationError, NativeError,
    ReceiveCounts, validate_bootstrap_channel,
};

pub trait StubSystem {
    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError>;
    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError>;
    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError>;
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StubError {
    Native(NativeError),
    Channel(CapabilityValidationError),
    Counts(ReceiveCounts),
    Launch(LaunchError),
}

pub fn run_stub<S: StubSystem>(system: &mut S, channel: DwHandle) -> Result<(), StubError> {
    let transaction = receive_init(system, channel)?;
    let mut ready = [0; HEADER_BYTES];
    let size =
        launch::encode_ready_for_profile(LaunchProfile::EarlyBootStub, transaction, &mut ready)
            .map_err(StubError::Launch)?;
    system
        .send_channel(channel, &ready[..size])
        .map_err(StubError::Native)?;
    system.close_handle(channel).map_err(StubError::Native)
}

/// Accepts the exact launch profile and then deterministically retires before
/// READY. This distinct artifact exists only so degraded WYR1 media can drive
/// the supervisor's real four-attempt exhaustion path.
pub fn run_fail_before_ready<S: StubSystem>(
    system: &mut S,
    channel: DwHandle,
) -> Result<(), StubError> {
    let _transaction = receive_init(system, channel)?;
    system.close_handle(channel).map_err(StubError::Native)
}

fn receive_init<S: StubSystem>(system: &mut S, channel: DwHandle) -> Result<u64, StubError> {
    let info = system
        .query_capability_info(channel)
        .map_err(StubError::Native)?;
    validate_bootstrap_channel(info, BOOTSTRAP_CHANNEL_EXPECTATION).map_err(StubError::Channel)?;
    let mut init = [0; HEADER_BYTES];
    let mut handles = [];
    let counts = system
        .receive_channel(channel, &mut init, &mut handles)
        .map_err(StubError::Native)?;
    if counts
        != (ReceiveCounts {
            bytes: HEADER_BYTES,
            handles: 0,
        })
    {
        return Err(StubError::Counts(counts));
    }
    let transaction = launch::parse_init(LaunchProfile::EarlyBootStub, &init, &handles)
        .map_err(StubError::Launch)?
        .transaction_id;
    Ok(transaction)
}
