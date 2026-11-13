#![no_std]
#![forbid(unsafe_code)]

//! WYR0 `hello` descendant smoke-test application contract.
//!
//! `hello` accepts only its retained loader Channel and validates its handle-free WRLP message.
//! The legacy profile sends READY and exits normally. The WYR1-B job profile remains alive after
//! READY until the controller releases its Channel endpoint, preventing scheduler timing from
//! turning readiness publication into a READY-and-exited race.

use deepwyrm_syscall::{
    DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwHandle, DwObjectType, DwReceivedHandleInfoV1,
    DwRights, DwSignals,
};
use wyrmroot_loader::launch::{
    HEADER_BYTES, LaunchError, LaunchProfile, encode_ready_for_profile, parse_init,
};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, CapabilityValidationError, NativeError,
    NativeOutput, ReceiveCounts, StreamError, StreamSystem, extract_job_v2_streams,
    native_error_code, validate_bootstrap_channel,
};
#[cfg(test)]
use wyrmroot_stream_proto as _;

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

/// Additional blocking operation required only by the WYR1-B job profile.
pub trait JobHelloSystem: HelloSystem {
    /// Waits for the job controller to release its launch-Channel endpoint.
    fn wait_channel(
        &mut self,
        channel: DwHandle,
        signals: DwSignals,
    ) -> Result<DwSignals, NativeError>;
}

/// The selected WYR1-D hello path receives the reached JobV2 stream roles and
/// writes only via its native stdout Channel. It has no debug-write fallback.
pub trait StreamHelloSystem: JobHelloSystem + StreamSystem {}
impl<T: JobHelloSystem + StreamSystem> StreamHelloSystem for T {}

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
    /// The post-READY wait did not observe one clean peer closure.
    PostReadySignals(DwSignals),
    /// The reached JobV2 stream-role handoff was malformed.
    StreamLaunch(LaunchError),
    /// Native stdout could not commit the bounded greeting record.
    Stream(StreamError),
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
    /// Wait for the controller's post-acceptance launch-Channel release.
    WaitForRelease = 5,
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
            Self::PostReadySignals(_) => PREFIX | 0x05,
            Self::StreamLaunch(_) => PREFIX | 0x06,
            Self::Stream(_) => PREFIX | 0x07,
        }
    }
}

/// Completes the capability-mediated WYR0-G parent-channel exchange.
pub fn run_hello<System: HelloSystem>(
    system: &mut System,
    bootstrap_channel: DwHandle,
) -> Result<(), HelloError> {
    run_profile(system, bootstrap_channel, LaunchProfile::Hello)
}

/// Completes the WYR1-B startup exchange for policy-launched `bin/hello`.
pub fn run_job_hello<System: JobHelloSystem>(
    system: &mut System,
    bootstrap_channel: DwHandle,
) -> Result<(), HelloError> {
    run_profile_ready(system, bootstrap_channel, LaunchProfile::JobV2)?;
    wait_for_release(system, bootstrap_channel)?;
    close_bootstrap(system, bootstrap_channel)
}

fn wait_for_release<System: JobHelloSystem>(
    system: &mut System,
    bootstrap_channel: DwHandle,
) -> Result<(), HelloError> {
    let requested = DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0);
    let observed = system
        .wait_channel(bootstrap_channel, requested)
        .map_err(|cause| HelloError::Native {
            operation: HelloNativeOperation::WaitForRelease,
            cause,
        })?;
    if observed.0 & DW_SIGNAL_READABLE.0 != 0
        || observed.0 & DW_SIGNAL_PEER_CLOSED.0 == 0
        || observed.0 & !requested.0 != 0
    {
        return Err(HelloError::PostReadySignals(observed));
    }
    Ok(())
}

/// Completes the D1 stream-profile hello exchange and writes a binary-safe
/// greeting through the child stdout role. The child never writes diagnostic
/// success through COM1 or a historical debug facility.
pub fn run_stream_hello<System: StreamHelloSystem>(
    system: &mut System,
    bootstrap_channel: DwHandle,
) -> Result<(), HelloError> {
    run_stream_hello_with(system, bootstrap_channel, None)
}

/// [`run_stream_hello`], and when `probe` is given, runs it with the job's
/// own AddressRegion before letting that go and writes the line it returns
/// after the greeting (`run bin/hello on-demand`, Deepwyrm DW2 M6).
pub fn run_stream_hello_with<System: StreamHelloSystem>(
    system: &mut System,
    bootstrap_channel: DwHandle,
    mut probe: Option<&mut dyn FnMut(DwHandle) -> &'static [u8]>,
) -> Result<(), HelloError> {
    let channel = system
        .query_capability_info(bootstrap_channel)
        .map_err(|cause| HelloError::Native {
            operation: HelloNativeOperation::QueryBootstrapChannel,
            cause,
        })?;
    validate_bootstrap_channel(channel, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(HelloError::BootstrapChannel)?;
    // A bootfs launch carries the streams; a file launch also carries a
    // namespace (WRLP 1.13), which is one record and one handle longer.
    let mut init = [0_u8; 80];
    let mut handles = [DwReceivedHandleInfoV1::default(); 5];
    let counts = system
        .receive_channel(bootstrap_channel, &mut init, &mut handles)
        .map_err(|cause| HelloError::Native {
            operation: HelloNativeOperation::ReceiveInit,
            cause,
        })?;
    if counts.bytes > init.len() || !(4..=handles.len()).contains(&counts.handles) {
        return Err(HelloError::ReceiveCounts(counts));
    }
    let streams = extract_job_v2_streams(&init[..counts.bytes], &handles[..counts.handles])
        .map_err(HelloError::StreamLaunch)?;
    // Hello maps nothing and opens no paths, so its self root and any
    // namespace go at once, after the probe if there is one.
    let probed = probe.as_mut().map(|probe| probe(streams.self_root));
    for handle in core::iter::once(streams.self_root).chain(streams.namespace) {
        system
            .close_handle(handle)
            .map_err(|cause| HelloError::Native {
                operation: HelloNativeOperation::CloseBootstrapChannel,
                cause,
            })?;
    }
    let mut stdout = NativeOutput::new(streams.stdout);
    if stdout
        .write(system, b"hello from native stdout\n")
        .map_err(HelloError::Stream)?
        != 25
    {
        return Err(HelloError::Stream(StreamError::Protocol));
    }
    if let Some(line) = probed
        && stdout.write(system, line).map_err(HelloError::Stream)? != line.len()
    {
        return Err(HelloError::Stream(StreamError::Protocol));
    }
    system
        .close_handle(streams.stdin.handle())
        .map_err(|cause| HelloError::Native {
            operation: HelloNativeOperation::CloseBootstrapChannel,
            cause,
        })?;
    system
        .close_handle(streams.stdout.handle())
        .map_err(|cause| HelloError::Native {
            operation: HelloNativeOperation::CloseBootstrapChannel,
            cause,
        })?;
    system
        .close_handle(streams.stderr.handle())
        .map_err(|cause| HelloError::Native {
            operation: HelloNativeOperation::CloseBootstrapChannel,
            cause,
        })?;
    let mut ready = [0_u8; HEADER_BYTES];
    let parsed = wyrmroot_loader::launch::parse_init(
        streams.profile,
        &init[..counts.bytes],
        &handles[..counts.handles],
    )
    .map_err(HelloError::Launch)?;
    let size = encode_ready_for_profile(streams.profile, parsed.transaction_id, &mut ready)
        .map_err(HelloError::Launch)?;
    system
        .send_channel(bootstrap_channel, &ready[..size])
        .map_err(|cause| HelloError::Native {
            operation: HelloNativeOperation::SendReady,
            cause,
        })?;
    wait_for_release(system, bootstrap_channel)?;
    close_bootstrap(system, bootstrap_channel)
}

fn run_profile<System: HelloSystem>(
    system: &mut System,
    bootstrap_channel: DwHandle,
    profile: LaunchProfile,
) -> Result<(), HelloError> {
    run_profile_ready(system, bootstrap_channel, profile)?;
    close_bootstrap(system, bootstrap_channel)
}

fn run_profile_ready<System: HelloSystem>(
    system: &mut System,
    bootstrap_channel: DwHandle,
    profile: LaunchProfile,
) -> Result<u64, HelloError> {
    let channel = system
        .query_capability_info(bootstrap_channel)
        .map_err(|cause| HelloError::Native {
            operation: HelloNativeOperation::QueryBootstrapChannel,
            cause,
        })?;
    validate_bootstrap_channel(channel, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(HelloError::BootstrapChannel)?;

    // A JobV2 INIT carries the job's self root (WRLP 1.12); the WYR0-G
    // profile carries nothing.
    let mut init = [0_u8; HEADER_BYTES + 8];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let expected = profile.capability_count();
    let counts = system
        .receive_channel(bootstrap_channel, &mut init, &mut handles)
        .map_err(|cause| HelloError::Native {
            operation: HelloNativeOperation::ReceiveInit,
            cause,
        })?;
    if counts.bytes > init.len() || counts.handles != expected {
        return Err(HelloError::ReceiveCounts(counts));
    }
    let parsed = parse_init(profile, &init[..counts.bytes], &handles[..expected]);
    // Hello maps nothing: the self root is closed whatever INIT said.
    for info in &handles[..expected] {
        system
            .close_handle(info.handle)
            .map_err(|cause| HelloError::Native {
                operation: HelloNativeOperation::CloseBootstrapChannel,
                cause,
            })?;
    }
    let parsed = parsed.map_err(HelloError::Launch)?;

    let mut ready = [0_u8; HEADER_BYTES];
    let ready_size = encode_ready_for_profile(profile, parsed.transaction_id, &mut ready)
        .map_err(HelloError::Launch)?;
    system
        .send_channel(bootstrap_channel, &ready[..ready_size])
        .map_err(|cause| HelloError::Native {
            operation: HelloNativeOperation::SendReady,
            cause,
        })?;
    Ok(parsed.transaction_id)
}

fn close_bootstrap<System: HelloSystem>(
    system: &mut System,
    bootstrap_channel: DwHandle,
) -> Result<(), HelloError> {
    system
        .close_handle(bootstrap_channel)
        .map_err(|cause| HelloError::Native {
            operation: HelloNativeOperation::CloseBootstrapChannel,
            cause,
        })
}
