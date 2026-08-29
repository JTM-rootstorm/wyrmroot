#![no_std]
#![forbid(unsafe_code)]

//! Temporary WYR0 `init0` application contract.
//!
//! WYR0-G validates its one-time loader handoff, maps the delegated read-only bootfs just long
//! enough to select `bin/hello`, and launches that descendant only through `wyrmroot-loader`.
//! It reports READY to its primordial parent only after `hello` acknowledges its parent Channel
//! and exits normally with application code zero.

#[cfg(test)]
extern crate std;

#[cfg(feature = "dw1b-preemption-integration")]
use deepwyrm_syscall::DW_RIGHT_DUPLICATE;
#[cfg(any(
    feature = "dw1b-preemption-integration",
    feature = "dw1c-preemption-integration"
))]
use deepwyrm_syscall::DW_SIGNAL_EXITED;
#[cfg(any(
    feature = "i-capability-integration",
    feature = "dw1b-preemption-integration"
))]
use deepwyrm_syscall::DW_SIGNAL_WRITABLE;
#[cfg(any(
    feature = "i-capability-integration",
    feature = "dw1b-preemption-integration",
    feature = "dw1c-preemption-integration"
))]
use deepwyrm_syscall::DW_STATUS_WOULD_BLOCK;
#[cfg(feature = "dw1c-preemption-integration")]
use deepwyrm_syscall::{
    DW_HANDLE_TRANSFER_MOVE, DW_STATUS_TIMED_OUT, DW_TASK_TERMINATION_INFO_V1_SIZE,
    DW_TERMINATION_AUTHORIZED, DwHandleTransferV1,
};
#[cfg(any(
    feature = "dw1b-preemption-integration",
    feature = "dw1c-preemption-integration"
))]
use deepwyrm_syscall::{
    DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_INSPECT, DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WAIT,
    DW_RIGHT_WRITE,
};
#[cfg(any(
    feature = "i-capability-integration",
    feature = "dw1b-preemption-integration"
))]
use deepwyrm_syscall::{DW_SIGNAL_PEER_CLOSED, DwSignals};
#[cfg(any(
    feature = "i-capability-integration",
    feature = "dw1b-preemption-integration",
    feature = "dw1c-preemption-integration"
))]
use deepwyrm_syscall::{DW_SIGNAL_READABLE, DwWaitItemV1};
use deepwyrm_syscall::{
    DW_TASK_STATE_EXITED, DwDeadline, DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights,
    DwTaskTerminationInfoV1,
};
use wyrmroot_bootfs::archive::{Archive, LookupError, ParseError};
#[cfg(feature = "dw1b-preemption-integration")]
use wyrmroot_loader::{
    launch::CHILD_CHANNEL_RIGHTS,
    process::{ServiceLoadRequest, load_service_process},
};
use wyrmroot_loader::{
    launch::{HEADER_BYTES, INIT0_BYTES, LaunchError, LaunchProfile, encode_ready, parse_init},
    process::{
        LoadAuthority, LoadError, LoadRequest, LoadStage, LoadedProcess, LoaderPlatform,
        load_process,
    },
};
#[cfg(feature = "dw1c-preemption-integration")]
use wyrmroot_runtime::LOADER_ABORT_CODE;
#[cfg(any(
    feature = "dw1b-preemption-integration",
    feature = "dw1c-preemption-integration"
))]
use wyrmroot_runtime::await_child_ready_profile;
use wyrmroot_runtime::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, CapabilityValidationError,
    ExitObservedReadinessError, ExitValidationError, InitCapability, LOADER_TASK_GROUP_EXPECTATION,
    MappingPlan, MappingPlanError, NativeError, ReceiveCounts, SELF_ROOT_EXPECTATION,
    SupervisionError, SupervisionPlatform, supervise_child, validate_bootstrap_channel,
    validate_init_capabilities_v2, validate_successful_exit,
};

/// The only bootfs path selected by the WYR0-G descendant smoke chain.
pub const HELLO_PATH: &[u8] = b"bin/hello";
/// The I2 image deliberately replaces the normal hello artifact at this path
/// with the dedicated stress controller.  Normal init0 images never select it.
#[cfg(feature = "i2-stress-integration")]
pub const I2_STRESS_PATH: &[u8] = b"bin/hello";
/// The WYR0-I image supplies its dedicated controller through the existing selector payload slot.
#[cfg(feature = "i-capability-integration")]
pub const I_CAPABILITY_PATH: &[u8] = b"bin/hello";
/// Nonzero WRLP transaction identifier for the `init0 -> hello` launch.
pub const HELLO_TRANSACTION_ID: u64 = 2;
#[cfg(feature = "dw1b-preemption-integration")]
pub const DW1B_HOG_PATH: &[u8] = b"test/dw1-b/cpu-hog";
#[cfg(feature = "dw1b-preemption-integration")]
pub const DW1B_PROGRESS_PATH: &[u8] = b"test/dw1-b/progress";

// Retained by the native linker as a candidate-assembly attestation. Each
// selector build has exactly one marker, so host tooling can reject a stale
// Cargo output from a different init0 feature set before constructing media.
#[cfg(not(any(
    feature = "i2-stress-integration",
    feature = "i-capability-integration",
    feature = "dw1b-preemption-integration",
    feature = "dw1c-preemption-integration"
)))]
#[used]
static INIT0_PROFILE_MARKER: [u8; 29] = *b"WYRMINIT0-PROFILE-V1:ordinary";

#[cfg(all(
    feature = "i2-stress-integration",
    not(any(
        feature = "i-capability-integration",
        feature = "dw1b-preemption-integration",
        feature = "dw1c-preemption-integration"
    ))
))]
#[used]
static INIT0_PROFILE_MARKER: [u8; 30] = *b"WYRMINIT0-PROFILE-V1:i2-stress";

#[cfg(all(
    feature = "i-capability-integration",
    not(any(
        feature = "i2-stress-integration",
        feature = "dw1b-preemption-integration",
        feature = "dw1c-preemption-integration"
    ))
))]
#[used]
static INIT0_PROFILE_MARKER: [u8; 33] = *b"WYRMINIT0-PROFILE-V1:i-capability";

#[cfg(all(
    feature = "dw1b-preemption-integration",
    not(any(
        feature = "i2-stress-integration",
        feature = "i-capability-integration",
        feature = "dw1c-preemption-integration"
    ))
))]
#[used]
static INIT0_PROFILE_MARKER: [u8; 36] = *b"WYRMINIT0-PROFILE-V1:dw1b-preemption";

#[cfg(all(
    feature = "dw1c-preemption-integration",
    not(any(
        feature = "i2-stress-integration",
        feature = "i-capability-integration",
        feature = "dw1b-preemption-integration"
    ))
))]
#[used]
static INIT0_PROFILE_MARKER: [u8; 36] = *b"WYRMINIT0-PROFILE-V1:dw1c-preemption";

#[cfg(feature = "dw1c-preemption-integration")]
const DW1C_ROLE_CODES: [u64; wyrmroot_runtime::DW1C_ACTOR_COUNT] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
#[cfg(feature = "dw1c-preemption-integration")]
const DW1C_WORKLOAD_DEADLINE_NS: u64 = 240_000_000_000;
#[cfg(feature = "dw1c-preemption-integration")]
const DW1C_CLEANUP_DEADLINE_NS: u64 = 5_000_000_000;

/// Commits the selector-local ARM only after the controller has retained ten
/// distinct live Process handles in fixed token order.  Process creation and
/// READY supervision remain outside this small linear commit point so every
/// earlier failure can use the ordinary loader cleanup path.
#[cfg(feature = "dw1c-preemption-integration")]
fn arm_dw1c_after_ready<System: Init0System>(
    system: &mut System,
    processes: [DwHandle; wyrmroot_runtime::DW1C_ACTOR_COUNT],
    deadline: DwDeadline,
) -> Result<(), Init0Error> {
    let bindings = dw1c_bindings(processes)?;
    system
        .arm_dw1c_preemption(&bindings, deadline)
        .map_err(Init0Error::Native)
}

#[cfg(feature = "dw1c-preemption-integration")]
fn dw1c_bindings(
    processes: [DwHandle; wyrmroot_runtime::DW1C_ACTOR_COUNT],
) -> Result<[wyrmroot_runtime::Dw1cActorBindV1; wyrmroot_runtime::DW1C_ACTOR_COUNT], Init0Error> {
    let mut bindings = [wyrmroot_runtime::Dw1cActorBindV1 {
        token: 0,
        role: 0,
        process: DwHandle(0),
    }; wyrmroot_runtime::DW1C_ACTOR_COUNT];
    let mut index = 0;
    while index < bindings.len() {
        let process = processes[index];
        if process.0 == 0 || processes[..index].contains(&process) {
            return Err(Init0Error::MissingLoadedProcess);
        }
        bindings[index] = wyrmroot_runtime::Dw1cActorBindV1 {
            token: (index + 1) as u64,
            role: DW1C_ROLE_CODES[index],
            process,
        };
        index += 1;
    }
    Ok(bindings)
}

#[cfg(all(test, feature = "dw1c-preemption-integration"))]
mod dw1c_binding_tests {
    use super::dw1c_bindings;
    use deepwyrm_syscall::DwHandle;

    #[test]
    fn bindings_are_distinct_and_follow_token_role_order() {
        let processes = core::array::from_fn(|index| DwHandle(0x100 + index as u64));
        let bindings = dw1c_bindings(processes).unwrap();
        for (index, binding) in bindings.into_iter().enumerate() {
            assert_eq!(binding.token, index as u64 + 1);
            assert_eq!(binding.role, index as u64 + 1);
            assert_eq!(binding.process, DwHandle(0x100 + index as u64));
        }
    }

    #[test]
    fn bindings_reject_zero_or_duplicate_process_handles() {
        let mut processes = core::array::from_fn(|index| DwHandle(0x200 + index as u64));
        processes[3] = DwHandle(0);
        assert!(dw1c_bindings(processes).is_err());
        processes[3] = processes[2];
        assert!(dw1c_bindings(processes).is_err());
    }
}

/// Native operations used by the WYR0-G `init0` descendant transaction.
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

    /// Sends one handle-free loader READY datagram.
    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError>;

    #[cfg(feature = "dw1c-preemption-integration")]
    fn create_dw1c_relay(&mut self, _: DwRights) -> Result<(DwHandle, DwHandle), NativeError> {
        Err(NativeError::Status(deepwyrm_syscall::DW_STATUS_BAD_STATE))
    }

    #[cfg(feature = "dw1c-preemption-integration")]
    fn send_dw1c_with_handles(
        &mut self,
        _: DwHandle,
        _: &[u8],
        _: &[DwHandleTransferV1],
    ) -> Result<(), NativeError> {
        Err(NativeError::Status(deepwyrm_syscall::DW_STATUS_BAD_STATE))
    }

    #[cfg(feature = "dw1c-preemption-integration")]
    fn await_dw1c_token2_relay_ready(&mut self, _: DwDeadline) -> Result<(), NativeError> {
        Err(NativeError::Status(deepwyrm_syscall::DW_STATUS_BAD_STATE))
    }

    #[cfg(feature = "dw1c-preemption-integration")]
    fn dw1c_deadline_after(&mut self, _: u64) -> Result<DwDeadline, NativeError> {
        Err(NativeError::Status(deepwyrm_syscall::DW_STATUS_BAD_STATE))
    }

    /// Closes one caller-local handle.
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError>;

    /// Submits selector 26's test-private ARM operation.
    #[cfg(feature = "dw1b-preemption-integration")]
    fn arm_dw1b_preemption(
        &mut self,
        hog_process: DwHandle,
        progress_process: DwHandle,
    ) -> Result<(), NativeError>;

    /// Arms selector 28 after all ten distinct actor processes have reached
    /// READY.  Kept selector-local: it is not part of the generated ABI.
    #[cfg(feature = "dw1c-preemption-integration")]
    fn arm_dw1c_preemption(
        &mut self,
        bindings: &[wyrmroot_runtime::Dw1cActorBindV1; wyrmroot_runtime::DW1C_ACTOR_COUNT],
        deadline: DwDeadline,
    ) -> Result<(), NativeError>;

    #[cfg(feature = "dw1c-preemption-integration")]
    fn complete_dw1c_workload(&mut self, digest: u64) -> Result<(), NativeError>;
}

/// Why the WYR0-G `init0` descendant transaction failed.
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
    /// The bootfs logical size could not produce a bounded mapping.
    Mapping(MappingPlanError),
    /// The mapped bootfs archive was malformed.
    Bootfs(ParseError),
    /// `bin/hello` was absent or had an invalid bootfs name.
    MissingHello,
    /// `bin/hello` was not immutable executable content.
    HelloNotExecutable,
    /// The reusable loader could not construct the descendant transactionally.
    Loader(LoadError<NativeError>),
    /// `hello` did not acknowledge and exit under the bounded supervision contract.
    Supervision(SupervisionError<NativeError>),
    /// Cleanup of an already-published descendant failed.
    Cleanup(NativeError),
    /// A selector-bound WRCAP1 datagram could not be received and relayed byte-for-byte.
    CapabilityEvidence,
    /// A successful bootfs callback did not retain the descendant it created.
    MissingLoadedProcess,
}

impl Init0Error {
    /// Returns a bounded native application exit code for live integration diagnostics.
    #[must_use]
    pub fn exit_code(&self) -> u32 {
        const PREFIX: u32 = 0x1000_0000;
        match self {
            Self::Native(_) => PREFIX | 0x01,
            Self::BootstrapChannel(_) => PREFIX | 0x02,
            Self::Launch(error) => PREFIX | 0x0300 | launch_error_code(*error),
            Self::ReceiveCounts(_) => PREFIX | 0x04,
            Self::Capability(_) => PREFIX | 0x05,
            Self::Mapping(_) => PREFIX | 0x06,
            Self::Bootfs(_) => PREFIX | 0x07,
            Self::MissingHello => PREFIX | 0x08,
            Self::HelloNotExecutable => PREFIX | 0x09,
            Self::Loader(LoadError::Platform {
                stage,
                cause,
                rollback_failed,
            }) => loader_platform_exit_code(*stage, *cause, *rollback_failed),
            Self::Loader(_) => PREFIX | 0x01FF,
            Self::Supervision(SupervisionError::Exit(
                wyrmroot_runtime::ExitValidationError::NonzeroApplicationCode(code),
            )) => *code,
            Self::Supervision(error) => supervision_exit_code(error),
            Self::Cleanup(error) => cleanup_exit_code(*error),
            Self::CapabilityEvidence => PREFIX | 0x0A,
            Self::MissingLoadedProcess => PREFIX | 0x0301,
        }
    }
}

/// Encodes final descendant-cleanup failures without collapsing the native
/// cause. The `0x12` high byte is init0-owned; bit 15 distinguishes bounded
/// native-output failures from native status values.
const fn cleanup_exit_code(error: NativeError) -> u32 {
    const PREFIX: u32 = 0x1200_0000;
    match error {
        NativeError::Status(status) => PREFIX | bounded_status_code(status.0.unsigned_abs()),
        NativeError::Output(output) => PREFIX | 0x8000 | native_output_code(output),
    }
}

/// Encodes bounded child-supervision failures without collapsing the exact
/// wait, readiness, or terminal-record stage. The `0x13` high byte is
/// init0-owned; bits 23..16 identify the supervision stage and the low 16 bits
/// retain a bounded native or protocol cause where one exists.
const fn supervision_exit_code(error: &SupervisionError<NativeError>) -> u32 {
    const PREFIX: u32 = 0x1300_0000;
    match error {
        SupervisionError::UnboundedDeadline => PREFIX | 0x0001_0000,
        SupervisionError::Platform(error) => PREFIX | 0x0002_0000 | native_error_code(*error),
        SupervisionError::ExitQuery(error) => PREFIX | 0x0003_0000 | native_error_code(*error),
        SupervisionError::InvalidWaitResult => PREFIX | 0x0004_0000,
        SupervisionError::InvalidReadyReceive(_) => PREFIX | 0x0005_0000,
        SupervisionError::Ready(error) => PREFIX | 0x0006_0000 | launch_error_code(*error),
        SupervisionError::ExitedBeforeReady => PREFIX | 0x0007_0000,
        SupervisionError::PeerClosedBeforeReady => PREFIX | 0x0008_0000,
        SupervisionError::DuplicateReady => PREFIX | 0x0009_0000,
        SupervisionError::Exit(error) => PREFIX | 0x000A_0000 | exit_validation_code(*error),
        SupervisionError::ExitObservedReadiness(error) => {
            PREFIX | 0x000B_0000 | exit_observed_readiness_code(error)
        }
    }
}

const fn native_error_code(error: NativeError) -> u32 {
    match error {
        NativeError::Status(status) => bounded_status_code(status.0.unsigned_abs()),
        NativeError::Output(output) => 0x8000 | native_output_code(output),
    }
}

const fn exit_validation_code(error: ExitValidationError) -> u32 {
    match error {
        ExitValidationError::InvalidEnvelope => 1,
        ExitValidationError::NotExited => 2,
        ExitValidationError::NotNormalExit => 3,
        ExitValidationError::NonzeroApplicationCode(_) => 4,
        ExitValidationError::NonzeroExceptionFields => 5,
    }
}

const fn exit_observed_readiness_code(error: &ExitObservedReadinessError<NativeError>) -> u32 {
    match error {
        ExitObservedReadinessError::Platform(error) => 0x1000 | native_error_code(*error),
        ExitObservedReadinessError::InvalidWaitResult => 0x2000,
        ExitObservedReadinessError::InvalidReadyReceive(_) => 0x3000,
        ExitObservedReadinessError::Ready(error) => 0x4000 | launch_error_code(*error),
        ExitObservedReadinessError::DuplicateReady => 0x5000,
    }
}

/// Encodes a native loader-platform failure without losing its bounded cause.
///
/// The `0x11` high byte is reserved for init0 loader-platform exits, separate from init0's
/// ordinary `0x10` application-owned categories. Bit 23 records failed rollback, bits 22..16
/// identify the loader stage, bit 15 selects a bounded native-output cause, and bits 14..0 carry
/// either that output code or a saturating absolute native status value.
const fn loader_platform_exit_code(
    stage: LoadStage,
    cause: NativeError,
    rollback_failed: bool,
) -> u32 {
    const PREFIX: u32 = 0x1100_0000;
    let rollback = if rollback_failed { 1 << 23 } else { 0 };
    let cause = match cause {
        NativeError::Status(status) => bounded_status_code(status.0.unsigned_abs()),
        NativeError::Output(output) => 0x8000 | native_output_code(output),
    };
    PREFIX | rollback | (load_stage_code(stage) << 16) | cause
}

const fn bounded_status_code(code: u32) -> u32 {
    if code > 0x7fff { 0x7fff } else { code }
}

const fn launch_error_code(error: LaunchError) -> u32 {
    match error {
        LaunchError::BufferSize => 0x01,
        LaunchError::BadMagic => 0x02,
        LaunchError::BadVersion => 0x03,
        LaunchError::BadType => 0x04,
        LaunchError::NonzeroFlags => 0x05,
        LaunchError::BadTotalSize => 0x06,
        LaunchError::BadCapabilityCount => 0x07,
        LaunchError::ZeroTransaction => 0x08,
        LaunchError::TransactionMismatch => 0x09,
        LaunchError::NonzeroReserved => 0x0A,
        LaunchError::BadCapabilityRole { index } => 0x10 | bounded_index(index),
        LaunchError::HandleCount => 0x20,
        LaunchError::HandleMetadata { index } => 0x30 | bounded_index(index),
        LaunchError::ProfileSpecificEncoderRequired => 0x40,
    }
}

const fn bounded_index(index: usize) -> u32 {
    if index < 16 { index as u32 } else { 15 }
}

const fn load_stage_code(stage: LoadStage) -> u32 {
    match stage {
        LoadStage::ChannelCreate => 1,
        LoadStage::ChannelReduce => 2,
        LoadStage::ProcessCreate => 3,
        LoadStage::MemoryCreate => 4,
        LoadStage::ParentMaterialize => 5,
        LoadStage::ParentUnmap => 6,
        LoadStage::ChildMap => 7,
        LoadStage::ThreadCreate => 8,
        LoadStage::CapabilityDuplicate => 9,
        LoadStage::InitSend => 10,
        LoadStage::ThreadStart => 11,
        LoadStage::SuccessCleanup => 12,
    }
}

const fn native_output_code(output: wyrmroot_runtime::NativeOutputError) -> u32 {
    use wyrmroot_runtime::NativeOutputError;
    match output {
        NativeOutputError::InvalidObjectInfo => 1,
        NativeOutputError::InvalidMemoryObjectInfo => 2,
        NativeOutputError::InvalidChannelReceive => 3,
        NativeOutputError::InvalidMappedRange => 4,
        NativeOutputError::InvalidLoaderOutput => 5,
        NativeOutputError::InvalidWaitResult => 6,
        NativeOutputError::InvalidTaskTerminationInfo => 7,
        NativeOutputError::DeadlineOverflow => 8,
    }
}

/// Validates the WYR0-F handoff, then completes the WYR0-G descendant smoke chain.
///
/// The native entry macro has already validated the immutable startup page before this function
/// receives the bootstrap Channel. This transaction re-queries every received authority before
/// use. It retains those handles only while it maps the bootfs and constructs one child in the
/// delegated TaskGroup, then closes all three before publishing its own READY.
pub fn run_init0<
    System: Init0System,
    Loader: LoaderPlatform<Error = NativeError>,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    loader: &mut Loader,
    supervisor: &mut Supervisor,
    bootstrap_channel: DwHandle,
    deadline: DwDeadline,
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
        let authority = LoadAuthority {
            parent_root: handles[0].handle,
            bootfs: handles[1].handle,
            task_group: handles[2].handle,
        };
        let plan = bootfs_mapping_plan(system, authority.bootfs)?;
        #[cfg(feature = "dw1b-preemption-integration")]
        {
            run_dw1b_preemption(system, loader, supervisor, authority, plan, deadline)?;
            Ok(message.transaction_id)
        }
        #[cfg(feature = "dw1c-preemption-integration")]
        {
            run_dw1c_preemption(system, loader, supervisor, authority, plan, deadline)?;
            Ok(message.transaction_id)
        }
        #[cfg(not(any(
            feature = "dw1b-preemption-integration",
            feature = "dw1c-preemption-integration"
        )))]
        {
            let mut loaded = None;
            let mapped =
                system.with_bootfs_bytes(authority.parent_root, authority.bootfs, plan, |bootfs| {
                    match load_selected_child(loader, authority, bootfs) {
                        Ok(candidate) => {
                            loaded = Some(candidate);
                            Ok(())
                        }
                        Err(error) => Err(error),
                    }
                });
            let loaded = match (mapped, loaded) {
                (Ok(Ok(())), Some(loaded)) => loaded,
                (Ok(Err(error)), _) => return Err(error),
                (Err(error), Some(loaded)) => {
                    if let Err(cleanup) = cleanup_loaded_process(system, loader, loaded, true) {
                        return Err(Init0Error::Cleanup(cleanup));
                    }
                    return Err(Init0Error::Native(error));
                }
                (Err(error), None) => return Err(Init0Error::Native(error)),
                (Ok(Ok(())), None) => return Err(Init0Error::MissingLoadedProcess),
            };
            #[cfg(feature = "i-capability-integration")]
            if let Err(evidence) = relay_capability_evidence(
                system,
                supervisor,
                bootstrap_channel,
                loaded.launch_channel,
                deadline,
            ) {
                let terminal = supervisor
                    .query_task_termination(loaded.process)
                    .ok()
                    .filter(|info| info.state == DW_TASK_STATE_EXITED);
                let cleanup_exit = cleanup_supervised_process(
                    system,
                    loader,
                    supervisor,
                    loaded,
                    terminal.is_none(),
                )
                .map_err(Init0Error::Cleanup)?;
                if let Some(error) = terminal
                    .or(cleanup_exit)
                    .and_then(capability_terminal_error)
                {
                    return Err(error);
                }
                return Err(evidence);
            }
            let supervision = supervise_child(
                supervisor,
                loaded.process,
                loaded.launch_channel,
                HELLO_TRANSACTION_ID,
                deadline,
            );
            let late_exit = match &supervision {
                Err(error) if !error.process_exit_observed() => supervisor
                    .query_task_termination(loaded.process)
                    .ok()
                    .filter(|info| info.state == DW_TASK_STATE_EXITED),
                _ => None,
            };
            let terminate = matches!(
                &supervision,
                Err(error) if !error.process_exit_observed()
            ) && late_exit.is_none();
            let cleanup_exit =
                cleanup_supervised_process(system, loader, supervisor, loaded, terminate)
                    .map_err(Init0Error::Cleanup)?;
            if let Some(info) = late_exit.or(cleanup_exit) {
                validate_successful_exit(&info)
                    .map_err(|error| Init0Error::Supervision(SupervisionError::Exit(error)))?;
            }
            supervision.map_err(Init0Error::Supervision)?;
            Ok(message.transaction_id)
        }
    })();
    let cleanup = close_received_handles(system, &handles[..counts.handles]);
    let transaction_id = operation?;
    cleanup?;
    send_ready(system, bootstrap_channel, transaction_id)
}

#[cfg(feature = "i-capability-integration")]
fn capability_terminal_error(info: DwTaskTerminationInfoV1) -> Option<Init0Error> {
    validate_successful_exit(&info)
        .err()
        .map(|error| Init0Error::Supervision(SupervisionError::Exit(error)))
}

fn bootfs_mapping_plan<System: Init0System>(
    system: &mut System,
    bootfs: DwHandle,
) -> Result<MappingPlan, Init0Error> {
    system
        .query_memory_object_size(bootfs)
        .map_err(Init0Error::Native)
        .and_then(|size| MappingPlan::for_bootfs(size).map_err(Init0Error::Mapping))
}

#[cfg(feature = "dw1b-preemption-integration")]
#[derive(Clone, Copy)]
struct Dw1bPeers {
    hog: LoadedProcess,
    progress: LoadedProcess,
    progress_data: DwHandle,
}

#[cfg(feature = "dw1b-preemption-integration")]
const DW1B_CHANNEL_BROAD_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0
        | DW_RIGHT_WRITE.0
        | DW_RIGHT_WAIT.0
        | DW_RIGHT_DUPLICATE.0
        | DW_RIGHT_TRANSFER.0
        | DW_RIGHT_INSPECT.0,
);

#[cfg(feature = "dw1b-preemption-integration")]
fn run_dw1b_preemption<
    System: Init0System,
    Loader: LoaderPlatform<Error = NativeError>,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    loader: &mut Loader,
    supervisor: &mut Supervisor,
    authority: LoadAuthority,
    plan: MappingPlan,
    deadline: DwDeadline,
) -> Result<(), Init0Error> {
    let mut hog = None;
    let mapped =
        system.with_bootfs_bytes(authority.parent_root, authority.bootfs, plan, |bootfs| {
            let archive = Archive::new(bootfs).map_err(Init0Error::Bootfs)?;
            load_dw1b_peer(
                loader,
                authority,
                &archive,
                DW1B_HOG_PATH,
                wyrmroot_dw1b_preemption::HOG_TRANSACTION_ID,
            )
            .map(|loaded| hog = Some(loaded))
        });
    let hog = match (mapped, hog) {
        (Ok(Ok(())), Some(hog)) => hog,
        (Ok(Err(error)), _) => return Err(error),
        (Err(error), Some(hog)) => {
            return Err(prefer_cleanup(
                Init0Error::Native(error),
                terminate_reap_close(loader, supervisor, hog, deadline),
            ));
        }
        (Err(error), None) => return Err(Init0Error::Native(error)),
        (Ok(Ok(())), None) => return Err(Init0Error::MissingLoadedProcess),
    };
    if let Err(error) = await_child_ready_profile(
        supervisor,
        hog.process,
        hog.launch_channel,
        LaunchProfile::Hello,
        wyrmroot_dw1b_preemption::HOG_TRANSACTION_ID,
        deadline,
    ) {
        return Err(prefer_cleanup(
            Init0Error::Supervision(error),
            terminate_reap_close(loader, supervisor, hog, deadline),
        ));
    }

    let (progress_data, progress_child) = match create_dw1b_data_pair(system, loader) {
        Ok(pair) => pair,
        Err(error) => {
            return Err(prefer_cleanup(
                error,
                terminate_reap_close(loader, supervisor, hog, deadline),
            ));
        }
    };
    let mut progress = None;
    let mut progress_attempted = false;
    let mapped =
        system.with_bootfs_bytes(authority.parent_root, authority.bootfs, plan, |bootfs| {
            progress_attempted = true;
            load_dw1b_progress(loader, authority, bootfs, progress_child)
                .map(|loaded| progress = Some(loaded))
        });
    let progress = match (mapped, progress) {
        (Ok(Ok(())), Some(progress)) => progress,
        (Ok(Err(error)), _) => {
            let cleanup = cleanup_unloaded_progress(
                system,
                loader,
                supervisor,
                hog,
                progress_data,
                None,
                deadline,
            );
            return Err(prefer_cleanup(error, cleanup));
        }
        (Err(error), Some(progress)) => {
            let peers = Dw1bPeers {
                hog,
                progress,
                progress_data,
            };
            cleanup_dw1b_peers(system, loader, supervisor, peers, false, deadline)?;
            return Err(Init0Error::Native(error));
        }
        (Err(error), None) => {
            let child = (!progress_attempted).then_some(progress_child);
            let cleanup = cleanup_unloaded_progress(
                system,
                loader,
                supervisor,
                hog,
                progress_data,
                child,
                deadline,
            );
            return Err(prefer_cleanup(Init0Error::Native(error), cleanup));
        }
        (Ok(Ok(())), None) => {
            let child = (!progress_attempted).then_some(progress_child);
            let cleanup = cleanup_unloaded_progress(
                system,
                loader,
                supervisor,
                hog,
                progress_data,
                child,
                deadline,
            );
            return Err(prefer_cleanup(Init0Error::MissingLoadedProcess, cleanup));
        }
    };
    let peers = Dw1bPeers {
        hog,
        progress,
        progress_data,
    };

    let mut progress_reaped = false;
    let operation = (|| {
        await_child_ready_profile(
            supervisor,
            peers.progress.process,
            peers.progress.launch_channel,
            LaunchProfile::Dw1bProgress,
            wyrmroot_dw1b_preemption::PROGRESS_TRANSACTION_ID,
            deadline,
        )
        .map_err(Init0Error::Supervision)?;
        system
            .arm_dw1b_preemption(peers.hog.process, peers.progress.process)
            .map_err(Init0Error::Native)?;
        exchange_dw1b_progress(system, supervisor, peers.progress_data, deadline)?;
        wait_dw1b_normal_exit(supervisor, peers.progress.process, deadline)?;
        progress_reaped = true;
        close_dw1b_progress(system, peers)?;

        let mut hello = None;
        let mapped =
            system.with_bootfs_bytes(authority.parent_root, authority.bootfs, plan, |bootfs| {
                match load_selected_child(loader, authority, bootfs) {
                    Ok(loaded) => {
                        hello = Some(loaded);
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            });
        let hello = match (mapped, hello) {
            (Ok(Ok(())), Some(hello)) => hello,
            (Ok(Err(error)), _) => return Err(error),
            (Err(error), Some(hello)) => {
                cleanup_loaded_process(system, loader, hello, true).map_err(Init0Error::Cleanup)?;
                return Err(Init0Error::Native(error));
            }
            (Err(error), None) => return Err(Init0Error::Native(error)),
            (Ok(Ok(())), None) => return Err(Init0Error::MissingLoadedProcess),
        };
        let supervision = supervise_child(
            supervisor,
            hello.process,
            hello.launch_channel,
            HELLO_TRANSACTION_ID,
            deadline,
        );
        let exited = supervision
            .as_ref()
            .map(|_| true)
            .unwrap_or_else(|error| error.process_exit_observed());
        cleanup_supervised_process(system, loader, supervisor, hello, !exited)
            .map_err(Init0Error::Cleanup)?;
        supervision.map_err(Init0Error::Supervision)
    })();

    let cleanup = cleanup_dw1b_peers(system, loader, supervisor, peers, progress_reaped, deadline);
    finish_dw1b_operation(operation, cleanup)
}

#[cfg(feature = "dw1c-preemption-integration")]
const DW1C_ACTOR_PATHS: [&[u8]; wyrmroot_runtime::DW1C_ACTOR_COUNT] = [
    b"test/dw1-c/actor1",
    b"test/dw1-c/actor2",
    b"test/dw1-c/actor3",
    b"test/dw1-c/actor4",
    b"test/dw1-c/actor5",
    b"test/dw1-c/actor6",
    b"test/dw1-c/actor7",
    b"test/dw1-c/actor8",
    b"test/dw1-c/actor9",
    b"test/dw1-c/actor10",
];

#[cfg(feature = "dw1c-preemption-integration")]
const DW1C_GO: [u8; 1] = [1];
#[cfg(feature = "dw1c-preemption-integration")]
const DW1C_TOKEN2_RELAY_SETUP: [u8; 4] = [0xD1, 0xC5, 0x10, 2];
#[cfg(feature = "dw1c-preemption-integration")]
const DW1C_TOKEN7_RELAY_START: [u8; 4] = [0xD1, 0xC5, 0x11, 7];
#[cfg(feature = "dw1c-preemption-integration")]
const DW1C_RELAY_BROAD_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_TRANSFER.0,
);
#[cfg(feature = "dw1c-preemption-integration")]
const DW1C_RELAY_READ_RIGHTS: DwRights =
    DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0);
#[cfg(feature = "dw1c-preemption-integration")]
const DW1C_RELAY_WRITE_RIGHTS: DwRights = DwRights(DW_RIGHT_WRITE.0 | DW_RIGHT_INSPECT.0);
#[cfg(feature = "dw1c-preemption-integration")]
const DW1C_ACTOR_ACK_PREFIX: u8 = 0xAC;
#[cfg(feature = "dw1c-preemption-integration")]
const DW1C_TOKEN7_SIDE_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_TRANSFER.0,
);
#[cfg(feature = "dw1c-preemption-integration")]
const DW1C_TOKEN7_SETUP: [u8; 2] = [0xA7, 0x01];
#[cfg(feature = "dw1c-preemption-integration")]
const DW1C_TOKEN7_SETUP_ACK: [u8; 2] = [0xA7, 0x02];
#[cfg(feature = "dw1c-preemption-integration")]
const DW1C_TOKEN7_FULL: [u8; 2] = [0xA7, 0x03];
#[cfg(feature = "dw1c-preemption-integration")]
const DW1C_TOKEN7_WOKE: [u8; 2] = [0xA7, 0x04];
#[cfg(feature = "dw1c-preemption-integration")]
#[cfg(all(test, feature = "dw1c-preemption-integration"))]
const DW1C_POST_ARM_ORDER: [u8; wyrmroot_runtime::DW1C_ACTOR_COUNT] =
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

#[cfg(all(test, feature = "dw1c-preemption-integration"))]
mod dw1c_protocol_tests {
    use deepwyrm_syscall::{
        DW_STATUS_BAD_STATE, DW_STATUS_TIMED_OUT, DW_STATUS_WOULD_BLOCK, DW_TASK_STATE_EXITED,
        DW_TASK_TERMINATION_INFO_V1_SIZE, DW_TERMINATION_AUTHORIZED, DwDeadline,
        DwTaskTerminationInfoV1,
    };

    use super::{
        DW1C_ACTOR_ACK_PREFIX, DW1C_GO, DW1C_POST_ARM_ORDER, DW1C_TOKEN2_RELAY_SETUP,
        DW1C_TOKEN7_FULL, DW1C_TOKEN7_RELAY_START, DW1C_TOKEN7_SETUP, DW1C_TOKEN7_SETUP_ACK,
        DW1C_TOKEN7_WOKE, LOADER_ABORT_CODE, terminate_dw1c_token8_bounded,
        valid_dw1c_authorized_termination,
    };

    #[test]
    fn post_arm_protocol_has_one_go_per_actor_and_orders_reaps() {
        assert_eq!(DW1C_GO, [1]);
        assert_eq!(DW1C_ACTOR_ACK_PREFIX, 0xAC);
        assert_eq!(DW1C_TOKEN7_SETUP, [0xA7, 0x01]);
        assert_eq!(DW1C_TOKEN7_SETUP_ACK, [0xA7, 0x02]);
        assert_eq!(DW1C_TOKEN7_FULL, [0xA7, 0x03]);
        assert_eq!(DW1C_TOKEN7_WOKE, [0xA7, 0x04]);
        assert_eq!(DW1C_TOKEN2_RELAY_SETUP, [0xD1, 0xC5, 0x10, 2]);
        assert_eq!(DW1C_TOKEN7_RELAY_START, [0xD1, 0xC5, 0x11, 7]);
        assert_eq!(DW1C_POST_ARM_ORDER, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(&DW1C_POST_ARM_ORDER[8..], &[9, 10]);
    }

    #[test]
    fn actor8_requires_the_exact_authorized_loader_termination_record() {
        let accepted = DwTaskTerminationInfoV1 {
            size: DW_TASK_TERMINATION_INFO_V1_SIZE,
            version: 1,
            state: DW_TASK_STATE_EXITED,
            reason: DW_TERMINATION_AUTHORIZED,
            detail: LOADER_ABORT_CODE,
            ..DwTaskTerminationInfoV1::default()
        };
        assert!(valid_dw1c_authorized_termination(&accepted));

        let mut wrong_reason = accepted;
        wrong_reason.reason = deepwyrm_syscall::DW_TERMINATION_NORMAL_EXIT;
        assert!(!valid_dw1c_authorized_termination(&wrong_reason));

        let mut wrong_detail = accepted;
        wrong_detail.detail ^= 1;
        assert!(!valid_dw1c_authorized_termination(&wrong_detail));
    }

    #[test]
    fn actor8_termination_retries_would_block_across_syscall_boundaries() {
        let mut attempts = 0;
        let mut clock_reads = 0;
        let result = terminate_dw1c_token8_bounded(
            DwDeadline(100),
            || {
                attempts += 1;
                if attempts < 3 {
                    Err(wyrmroot_runtime::NativeError::Status(DW_STATUS_WOULD_BLOCK))
                } else {
                    Ok(())
                }
            },
            || {
                clock_reads += 1;
                Ok(10)
            },
        );
        assert_eq!(result, Ok(()));
        assert_eq!(attempts, 3);
        assert_eq!(clock_reads, 2);
    }

    #[test]
    fn actor8_termination_timeout_and_nonretry_errors_are_bounded() {
        let timed_out = terminate_dw1c_token8_bounded(
            DwDeadline(10),
            || Err(wyrmroot_runtime::NativeError::Status(DW_STATUS_WOULD_BLOCK)),
            || Ok(10),
        );
        assert_eq!(
            timed_out,
            Err(wyrmroot_runtime::NativeError::Status(DW_STATUS_TIMED_OUT))
        );

        let mut clock_called = false;
        let rejected = terminate_dw1c_token8_bounded(
            DwDeadline(10),
            || Err(wyrmroot_runtime::NativeError::Status(DW_STATUS_BAD_STATE)),
            || {
                clock_called = true;
                Ok(0)
            },
        );
        assert_eq!(
            rejected,
            Err(wyrmroot_runtime::NativeError::Status(DW_STATUS_BAD_STATE))
        );
        assert!(!clock_called);
    }

    #[test]
    fn source_contract_keeps_work_after_ready_and_retires_actors_after_completion() {
        let actor = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dw1c-preemption/src/bin/actor_body.rs"
        ));
        let gate = actor.find("let relay = match").unwrap();
        assert!(actor[gate..].contains("submit_dw1c_progress(TOKEN"));
        assert!(actor[gate..].contains("ACTOR_ACK_PREFIX, TOKEN"));
        assert!(actor[..gate].find("submit_dw1c_progress(TOKEN").is_none());
        assert!(!actor[gate..].contains("0xC6"));
        assert!(actor[gate..].contains("if TOKEN == 7"));
        assert!(actor[gate..].contains("if TOKEN == 2"));
        assert!(actor[gate..].contains("RELAY_GO"));
        assert!(actor[gate..].contains("DW_STATUS_WOULD_BLOCK"));
        assert!(actor[gate..].contains("TOKEN7_FULL"));
        assert!(actor[gate..].contains("TOKEN7_WOKE"));

        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
        let controller = &source[source.rfind("\nfn run_dw1c_preemption<").unwrap() + 1..];
        let arm = controller
            .find("    if let Err(error) = arm_dw1c_after_ready(system, processes, deadline)")
            .unwrap();
        let first_go = controller[arm..].find("DW1C_GO").unwrap() + arm;
        let complete = controller
            .rfind("        .complete_dw1c_workload(")
            .unwrap();
        assert!(arm < first_go);
        assert!(first_go < complete);
        assert!(controller[arm..complete].contains("DW1C_TOKEN2_RELAY_SETUP"));
        assert!(controller[arm..complete].contains("await_dw1c_token2_relay_ready"));
        assert!(controller[arm..complete].contains("receive_dw1c_actor_ack"));
        assert!(controller[arm..complete].contains("DW1C_TOKEN7_RELAY_START"));
        assert!(controller[arm..complete].contains("drive_dw1c_token7_capacity"));
        assert!(controller[arm..complete].contains("actor9.launch_channel"));
        assert!(controller[arm..complete].contains("actor10.launch_channel"));

        let drive = controller
            .find("    if let Err(error) = drive_dw1c_workload(")
            .unwrap();
        let cleanup = "cleanup_dw1c_actors(";
        let arm_cleanup = controller[arm..drive].find(cleanup).unwrap() + arm;
        let error_cleanup = controller[drive..].find(cleanup).unwrap() + drive;
        let success_cleanup = controller[error_cleanup + cleanup.len()..]
            .find(cleanup)
            .unwrap()
            + error_cleanup
            + cleanup.len();
        assert!(arm < arm_cleanup);
        assert!(arm_cleanup < drive);
        assert!(drive < success_cleanup);
    }
}

#[cfg(feature = "dw1c-preemption-integration")]
fn run_dw1c_preemption<
    System: Init0System,
    Loader: LoaderPlatform<Error = NativeError>,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    loader: &mut Loader,
    supervisor: &mut Supervisor,
    authority: LoadAuthority,
    plan: MappingPlan,
    deadline: DwDeadline,
) -> Result<(), Init0Error> {
    let mut actors = [None; wyrmroot_runtime::DW1C_ACTOR_COUNT];
    let mapped =
        system.with_bootfs_bytes(authority.parent_root, authority.bootfs, plan, |bootfs| {
            let archive = Archive::new(bootfs).map_err(Init0Error::Bootfs)?;
            let mut index = 0;
            while index < DW1C_ACTOR_PATHS.len() {
                let entry = archive
                    .lookup(DW1C_ACTOR_PATHS[index])
                    .map_err(|_| Init0Error::MissingHello)?;
                if !entry.is_executable() || entry.data().is_empty() {
                    return Err(Init0Error::HelloNotExecutable);
                }
                let display_path = entry.name_utf8().map_err(|_| Init0Error::MissingHello)?;
                let transaction_id = 0xD1C0_0000_u64 + (index as u64 + 1);
                actors[index] = Some(
                    load_process(
                        loader,
                        authority,
                        LoadRequest {
                            image: entry.data(),
                            display_path,
                            profile: LaunchProfile::Hello,
                            transaction_id,
                        },
                    )
                    .map_err(Init0Error::Loader)?,
                );
                index += 1;
            }
            Ok(())
        });
    match mapped {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            return Err(prefer_dw1c_cleanup(
                error,
                cleanup_dw1c_actors(loader, supervisor, actors, deadline),
            ));
        }
        Err(error) => {
            return Err(prefer_dw1c_cleanup(
                Init0Error::Native(error),
                cleanup_dw1c_actors(loader, supervisor, actors, deadline),
            ));
        }
    }
    let mut index = 0;
    while index < actors.len() {
        let actor = actors[index].ok_or(Init0Error::MissingLoadedProcess)?;
        if let Err(error) = await_child_ready_profile(
            supervisor,
            actor.process,
            actor.launch_channel,
            LaunchProfile::Hello,
            0xD1C0_0000_u64 + (index as u64 + 1),
            deadline,
        ) {
            return Err(prefer_dw1c_cleanup(
                Init0Error::Supervision(error),
                cleanup_dw1c_actors(loader, supervisor, actors, deadline),
            ));
        }
        index += 1;
    }
    // The READY loop intentionally walks the same table to preserve token order;
    // restart at zero before materializing the ARM bindings.
    index = 0;
    let mut processes = [DwHandle(0); wyrmroot_runtime::DW1C_ACTOR_COUNT];
    while index < actors.len() {
        processes[index] = actors[index]
            .ok_or(Init0Error::MissingLoadedProcess)?
            .process;
        index += 1;
    }
    if let Err(error) = arm_dw1c_after_ready(system, processes, deadline) {
        return Err(prefer_dw1c_cleanup(
            error,
            cleanup_dw1c_actors(
                loader,
                supervisor,
                actors,
                system
                    .dw1c_deadline_after(DW1C_CLEANUP_DEADLINE_NS)
                    .unwrap_or(deadline),
            ),
        ));
    }
    let workload_deadline = match system.dw1c_deadline_after(DW1C_WORKLOAD_DEADLINE_NS) {
        Ok(deadline) => deadline,
        Err(error) => {
            let cleanup_deadline = system
                .dw1c_deadline_after(DW1C_CLEANUP_DEADLINE_NS)
                .unwrap_or(deadline);
            return Err(prefer_dw1c_cleanup(
                Init0Error::Native(error),
                cleanup_dw1c_actors(loader, supervisor, actors, cleanup_deadline),
            ));
        }
    };
    if let Err(error) = drive_dw1c_workload(system, loader, supervisor, actors, workload_deadline) {
        let cleanup_deadline = system
            .dw1c_deadline_after(DW1C_CLEANUP_DEADLINE_NS)
            .unwrap_or(workload_deadline);
        return Err(prefer_dw1c_cleanup(
            error,
            cleanup_dw1c_actors(loader, supervisor, actors, cleanup_deadline),
        ));
    }
    // Actors 1..7 deliberately remain live after publishing their workload
    // facts. Retire the complete actor set after WORKLOAD_COMPLETE so the
    // successful controller does not leave runnable children behind and can
    // reach the normal primordial terminal path. The cleanup helper accepts
    // the already-terminal actors 8..10 and still closes every retained handle.
    let cleanup_deadline = system
        .dw1c_deadline_after(DW1C_CLEANUP_DEADLINE_NS)
        .unwrap_or(workload_deadline);
    cleanup_dw1c_actors(loader, supervisor, actors, cleanup_deadline)
}

#[cfg(feature = "dw1c-preemption-integration")]
fn drive_dw1c_workload<
    System: Init0System,
    Loader: LoaderPlatform<Error = NativeError>,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    loader: &mut Loader,
    supervisor: &mut Supervisor,
    actors: [Option<LoadedProcess>; wyrmroot_runtime::DW1C_ACTOR_COUNT],
    deadline: DwDeadline,
) -> Result<(), Init0Error> {
    let actor = |index: usize| actors[index].ok_or(Init0Error::MissingLoadedProcess);
    let go = DW1C_GO;
    let actor1 = actor(0)?;
    system
        .send_channel(actor1.launch_channel, &go)
        .map_err(Init0Error::Native)?;

    let actor2 = actor(1)?;
    let (relay_reader, relay_writer) = system
        .create_dw1c_relay(DW1C_RELAY_BROAD_RIGHTS)
        .map_err(Init0Error::Native)?;
    let reader_transfer = DwHandleTransferV1 {
        handle: relay_reader,
        requested_rights: DW1C_RELAY_READ_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if let Err(error) = system.send_dw1c_with_handles(
        actor2.launch_channel,
        &DW1C_TOKEN2_RELAY_SETUP,
        core::slice::from_ref(&reader_transfer),
    ) {
        let _ = system.close_handle(relay_reader);
        let _ = system.close_handle(relay_writer);
        return Err(Init0Error::Native(error));
    }

    for index in [2_usize, 4] {
        let child = actor(index)?;
        if let Err(error) = system.send_channel(child.launch_channel, &go) {
            let _ = system.close_handle(relay_writer);
            return Err(Init0Error::Native(error));
        }
    }
    if let Err(error) = system.await_dw1c_token2_relay_ready(deadline) {
        let _ = system.close_handle(relay_writer);
        return Err(Init0Error::Native(error));
    }

    let actor7 = actor(6)?;
    let writer_transfer = DwHandleTransferV1 {
        handle: relay_writer,
        requested_rights: DW1C_RELAY_WRITE_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if let Err(error) = system.send_dw1c_with_handles(
        actor7.launch_channel,
        &DW1C_TOKEN7_RELAY_START,
        core::slice::from_ref(&writer_transfer),
    ) {
        let _ = system.close_handle(relay_writer);
        return Err(Init0Error::Native(error));
    }

    for index in [3_usize, 5] {
        let child = actor(index)?;
        system
            .send_channel(child.launch_channel, &go)
            .map_err(Init0Error::Native)?;
    }

    // GO only makes the actors eligible. Exact acknowledgements prove that
    // tokens 1..5 committed their progress syscalls and token 6 resumed from
    // its ARM-bound wait before the controller may claim workload completion.
    let mut index = 0;
    while index < 6 {
        let child = actor(index)?;
        receive_dw1c_actor_ack(supervisor, child.launch_channel, index as u8 + 1, deadline)?;
        index += 1;
    }

    drive_dw1c_token7_capacity(system, loader, supervisor, actor7.launch_channel, deadline)?;

    let actor8 = actor(7)?;
    system
        .send_channel(actor8.launch_channel, &go)
        .map_err(Init0Error::Native)?;
    terminate_dw1c_token8_bounded(
        deadline,
        || loader.process_terminate(actor8.process),
        wyrmroot_runtime::monotonic_active_now,
    )
    .map_err(Init0Error::Cleanup)?;
    wait_actor_authorized_termination(supervisor, actor8.process, deadline)?;

    let actor9 = actor(8)?;
    system
        .send_channel(actor9.launch_channel, &go)
        .map_err(Init0Error::Native)?;
    wait_actor_exit(supervisor, actor9.process, deadline)?;
    let actor10 = actor(9)?;
    system
        .send_channel(actor10.launch_channel, &go)
        .map_err(Init0Error::Native)?;
    wait_actor_exit(supervisor, actor10.process, deadline)?;

    // Actors 1..5 publish their progress claims directly to the selector
    // collector.  The completion operation is the single controller commit
    // after all ordered drive operations above have succeeded.
    system
        .complete_dw1c_workload(parse_dw1c_progress_digest())
        .map_err(Init0Error::Native)
}

#[cfg(feature = "dw1c-preemption-integration")]
fn terminate_dw1c_token8_bounded(
    deadline: DwDeadline,
    mut terminate: impl FnMut() -> Result<(), NativeError>,
    mut monotonic_now: impl FnMut() -> Result<u64, NativeError>,
) -> Result<(), NativeError> {
    loop {
        match terminate() {
            Ok(()) => return Ok(()),
            Err(NativeError::Status(status)) if status == DW_STATUS_WOULD_BLOCK => {}
            Err(error) => return Err(error),
        }
        if monotonic_now()? >= deadline.0 {
            return Err(NativeError::Status(DW_STATUS_TIMED_OUT));
        }
        core::hint::spin_loop();
    }
}

#[cfg(feature = "dw1c-preemption-integration")]
fn receive_dw1c_actor_ack<Supervisor: SupervisionPlatform<Error = NativeError>>(
    supervisor: &mut Supervisor,
    channel: DwHandle,
    token: u8,
    deadline: DwDeadline,
) -> Result<(), Init0Error> {
    receive_dw1c_marker(
        supervisor,
        channel,
        [DW1C_ACTOR_ACK_PREFIX, token],
        deadline,
    )
}

#[cfg(feature = "dw1c-preemption-integration")]
fn drive_dw1c_token7_capacity<
    System: Init0System,
    Loader: LoaderPlatform<Error = NativeError>,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    loader: &mut Loader,
    supervisor: &mut Supervisor,
    launch_channel: DwHandle,
    deadline: DwDeadline,
) -> Result<(), Init0Error> {
    // The side Channel removes a four-CPU timing assumption from the capacity
    // proof. Actor 7 explicitly reports that its launch Channel is full before
    // init0 drains it, then acknowledges that the resulting WRITABLE wake has
    // resumed userspace.
    wait_actor_signal(supervisor, launch_channel, DW_SIGNAL_READABLE, deadline)?;
    let mut setup = [0_u8; 2];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = supervisor
        .receive_channel(launch_channel, &mut setup, &mut handles)
        .map_err(Init0Error::Native)?;
    if counts.bytes != DW1C_TOKEN7_SETUP.len()
        || counts.handles != 1
        || setup != DW1C_TOKEN7_SETUP
        || handles[0].handle.0 == 0
        || handles[0].object_type != DW_OBJECT_TYPE_CHANNEL
        || handles[0].rights != DW1C_TOKEN7_SIDE_RIGHTS
    {
        if counts.handles == 1 && handles[0].handle.0 != 0 {
            loader
                .close(handles[0].handle)
                .map_err(Init0Error::Cleanup)?;
        }
        return Err(Init0Error::ReceiveCounts(counts));
    }
    let side = handles[0].handle;
    let operation = (|| {
        system
            .send_channel(launch_channel, &DW1C_TOKEN7_SETUP_ACK)
            .map_err(Init0Error::Native)?;
        receive_dw1c_marker(supervisor, side, DW1C_TOKEN7_FULL, deadline)?;

        let mut payload = [0_u8; 128];
        let mut no_handles = [];
        let counts = supervisor
            .receive_channel(launch_channel, &mut payload, &mut no_handles)
            .map_err(Init0Error::Native)?;
        if counts.bytes != payload.len()
            || counts.handles != 0
            || payload.iter().any(|byte| *byte != 0xA7)
        {
            return Err(Init0Error::ReceiveCounts(counts));
        }

        receive_dw1c_marker(supervisor, side, DW1C_TOKEN7_WOKE, deadline)
    })();
    let close = loader.close(side).map_err(Init0Error::Cleanup);
    match (operation, close) {
        (Err(primary), _) => Err(primary),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

#[cfg(feature = "dw1c-preemption-integration")]
fn receive_dw1c_marker<Supervisor: SupervisionPlatform<Error = NativeError>>(
    supervisor: &mut Supervisor,
    channel: DwHandle,
    expected: [u8; 2],
    deadline: DwDeadline,
) -> Result<(), Init0Error> {
    wait_actor_signal(supervisor, channel, DW_SIGNAL_READABLE, deadline)?;
    let mut marker = [0_u8; 2];
    let mut handles = [];
    let counts = supervisor
        .receive_channel(channel, &mut marker, &mut handles)
        .map_err(Init0Error::Native)?;
    if counts.bytes != expected.len() || counts.handles != 0 || marker != expected {
        return Err(Init0Error::ReceiveCounts(counts));
    }
    Ok(())
}

#[cfg(feature = "dw1c-preemption-integration")]
const fn parse_dw1c_progress_digest() -> u64 {
    let bytes = option_env!("DEEPWYRM_DW1C_PROGRESS_DIGEST");
    let Some(text) = bytes else { return 0 };
    let input = text.as_bytes();
    let mut value = 0;
    let mut index = 0;
    while index < 16 {
        value = (value << 4)
            | match input[index] {
                b'0'..=b'9' => (input[index] - b'0') as u64,
                b'A'..=b'F' => (input[index] - b'A' + 10) as u64,
                _ => 0,
            };
        index += 1;
    }
    value
}

#[cfg(feature = "dw1c-preemption-integration")]
fn wait_actor_signal<Supervisor: SupervisionPlatform<Error = NativeError>>(
    supervisor: &mut Supervisor,
    handle: DwHandle,
    signal: deepwyrm_syscall::DwSignals,
    deadline: DwDeadline,
) -> Result<(), Init0Error> {
    let item = DwWaitItemV1 {
        handle,
        signals: signal,
    };
    let result = supervisor
        .wait_many(core::slice::from_ref(&item), deadline)
        .map_err(Init0Error::Native)?;
    if result.index != 0 || result.observed.0 & signal.0 == 0 {
        return Err(Init0Error::CapabilityEvidence);
    }
    Ok(())
}

#[cfg(feature = "dw1c-preemption-integration")]
fn wait_actor_exit<Supervisor: SupervisionPlatform<Error = NativeError>>(
    supervisor: &mut Supervisor,
    process: DwHandle,
    deadline: DwDeadline,
) -> Result<(), Init0Error> {
    wait_actor_signal(supervisor, process, DW_SIGNAL_EXITED, deadline)?;
    let info = supervisor
        .query_task_termination(process)
        .map_err(Init0Error::Native)?;
    validate_successful_exit(&info)
        .map_err(|error| Init0Error::Supervision(SupervisionError::Exit(error)))
}

#[cfg(feature = "dw1c-preemption-integration")]
fn wait_actor_authorized_termination<Supervisor: SupervisionPlatform<Error = NativeError>>(
    supervisor: &mut Supervisor,
    process: DwHandle,
    deadline: DwDeadline,
) -> Result<(), Init0Error> {
    wait_actor_signal(supervisor, process, DW_SIGNAL_EXITED, deadline)?;
    let info = supervisor
        .query_task_termination(process)
        .map_err(Init0Error::Native)?;
    if !valid_dw1c_authorized_termination(&info) {
        return Err(Init0Error::CapabilityEvidence);
    }
    Ok(())
}

#[cfg(feature = "dw1c-preemption-integration")]
fn valid_dw1c_authorized_termination(info: &DwTaskTerminationInfoV1) -> bool {
    info.size == DW_TASK_TERMINATION_INFO_V1_SIZE
        && info.version == 1
        && info.state == DW_TASK_STATE_EXITED
        && info.reason == DW_TERMINATION_AUTHORIZED
        && info.application_code == 0
        && info.exception_type.0 == 0
        && info.detail == LOADER_ABORT_CODE
        && info.reserved0 == 0
        && info.fault_address == 0
        && info.reserved == [0; 3]
}

#[cfg(feature = "dw1c-preemption-integration")]
fn cleanup_dw1c_actors<
    Loader: LoaderPlatform<Error = NativeError>,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    loader: &mut Loader,
    supervisor: &mut Supervisor,
    actors: [Option<LoadedProcess>; wyrmroot_runtime::DW1C_ACTOR_COUNT],
    deadline: DwDeadline,
) -> Result<(), Init0Error> {
    let mut first = None;
    for actor in actors.into_iter().flatten() {
        if let Err(error) = loader.process_terminate(actor.process) {
            let already_exited = supervisor
                .query_task_termination(actor.process)
                .is_ok_and(|info| info.state == DW_TASK_STATE_EXITED);
            if !already_exited {
                first.get_or_insert(Init0Error::Cleanup(error));
            }
        }
        let item = DwWaitItemV1 {
            handle: actor.process,
            signals: DW_SIGNAL_EXITED,
        };
        if supervisor
            .wait_many(core::slice::from_ref(&item), deadline)
            .is_err()
        {
            first.get_or_insert(Init0Error::CapabilityEvidence);
        }
        for handle in [actor.launch_channel, actor.process] {
            if let Err(error) = loader.close(handle) {
                first.get_or_insert(Init0Error::Cleanup(error));
            }
        }
    }
    first.map_or(Ok(()), Err)
}

#[cfg(feature = "dw1c-preemption-integration")]
fn prefer_dw1c_cleanup(primary: Init0Error, cleanup: Result<(), Init0Error>) -> Init0Error {
    cleanup.err().unwrap_or(primary)
}

#[cfg(feature = "dw1b-preemption-integration")]
fn load_dw1b_progress<Loader: LoaderPlatform<Error = NativeError>>(
    loader: &mut Loader,
    authority: LoadAuthority,
    bytes: &[u8],
    progress_child: DwHandle,
) -> Result<LoadedProcess, Init0Error> {
    let archive = match Archive::new(bytes) {
        Ok(archive) => archive,
        Err(error) => {
            loader.close(progress_child).map_err(Init0Error::Cleanup)?;
            return Err(Init0Error::Bootfs(error));
        }
    };
    let entry = match archive.lookup(DW1B_PROGRESS_PATH) {
        Ok(entry) if entry.is_executable() && !entry.data().is_empty() => entry,
        _ => {
            loader.close(progress_child).map_err(Init0Error::Cleanup)?;
            return Err(Init0Error::MissingHello);
        }
    };
    let display_path = match entry.name_utf8() {
        Ok(path) => path,
        Err(_) => {
            loader.close(progress_child).map_err(Init0Error::Cleanup)?;
            return Err(Init0Error::MissingHello);
        }
    };
    match load_service_process(
        loader,
        authority,
        ServiceLoadRequest {
            image: entry.data(),
            display_path,
            profile: LaunchProfile::Dw1bProgress,
            service_channel: progress_child,
            correlation: None,
            transaction_id: wyrmroot_dw1b_preemption::PROGRESS_TRANSACTION_ID,
        },
    ) {
        Ok(progress) => Ok(progress),
        Err(failure) => {
            if !failure.service_channel_consumed {
                loader.close(progress_child).map_err(Init0Error::Cleanup)?;
            }
            Err(Init0Error::Loader(failure.error))
        }
    }
}

#[cfg(feature = "dw1b-preemption-integration")]
fn create_dw1b_data_pair<System: Init0System, Loader: LoaderPlatform<Error = NativeError>>(
    system: &mut System,
    loader: &mut Loader,
) -> Result<(DwHandle, DwHandle), Init0Error> {
    let (broad_parent, child) = loader
        .channel_create(DW1B_CHANNEL_BROAD_RIGHTS)
        .map_err(Init0Error::Native)?;
    let parent = match loader.duplicate(broad_parent, CHILD_CHANNEL_RIGHTS) {
        Ok(parent) => parent,
        Err(error) => {
            return Err(prefer_cleanup(
                Init0Error::Native(error),
                close_loader_handles(loader, &[broad_parent, child]),
            ));
        }
    };
    if let Err(error) = loader.close(broad_parent) {
        let _ = close_loader_handles(loader, &[parent, child]);
        return Err(Init0Error::Cleanup(error));
    }
    let parent_info = match system.query_capability_info(parent) {
        Ok(info) => info,
        Err(error) => {
            return Err(prefer_cleanup(
                Init0Error::Native(error),
                close_loader_handles(loader, &[parent, child]),
            ));
        }
    };
    let child_info = match system.query_capability_info(child) {
        Ok(info) => info,
        Err(error) => {
            return Err(prefer_cleanup(
                Init0Error::Native(error),
                close_loader_handles(loader, &[parent, child]),
            ));
        }
    };
    if parent_info.object_type != DW_OBJECT_TYPE_CHANNEL
        || parent_info.rights != CHILD_CHANNEL_RIGHTS
        || child_info.object_type != DW_OBJECT_TYPE_CHANNEL
        || child_info.rights != DW1B_CHANNEL_BROAD_RIGHTS
    {
        return Err(prefer_cleanup(
            Init0Error::Capability(CapabilityValidationError::InvalidFreshCapability),
            close_loader_handles(loader, &[parent, child]),
        ));
    }
    Ok((parent, child))
}

#[cfg(feature = "dw1b-preemption-integration")]
fn close_loader_handles<Loader: LoaderPlatform<Error = NativeError>>(
    loader: &mut Loader,
    handles: &[DwHandle],
) -> Result<(), Init0Error> {
    let mut first = None;
    for handle in handles {
        record_cleanup(
            &mut first,
            loader.close(*handle).map_err(Init0Error::Cleanup),
        );
    }
    first.map_or(Ok(()), Err)
}

#[cfg(feature = "dw1b-preemption-integration")]
fn load_dw1b_peer<Loader: LoaderPlatform<Error = NativeError>>(
    loader: &mut Loader,
    authority: LoadAuthority,
    archive: &Archive<'_>,
    path: &[u8],
    transaction_id: u64,
) -> Result<LoadedProcess, Init0Error> {
    let entry = archive.lookup(path).map_err(|_| Init0Error::MissingHello)?;
    if !entry.is_executable() || entry.data().is_empty() {
        return Err(Init0Error::HelloNotExecutable);
    }
    let display_path = entry.name_utf8().map_err(|_| Init0Error::MissingHello)?;
    load_process(
        loader,
        authority,
        LoadRequest {
            image: entry.data(),
            display_path,
            profile: LaunchProfile::Hello,
            transaction_id,
        },
    )
    .map_err(Init0Error::Loader)
}

#[cfg(feature = "dw1b-preemption-integration")]
fn exchange_dw1b_progress<
    System: Init0System,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    supervisor: &mut Supervisor,
    channel: DwHandle,
    deadline: DwDeadline,
) -> Result<(), Init0Error> {
    for round in 0..wyrmroot_dw1b_preemption::ROUND_COUNT {
        system
            .send_channel(channel, &wyrmroot_dw1b_preemption::encode_challenge(round))
            .map_err(Init0Error::Native)?;
        let item = DwWaitItemV1 {
            handle: channel,
            signals: DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        };
        let observed = supervisor
            .wait_many(core::slice::from_ref(&item), deadline)
            .map_err(Init0Error::Native)?;
        if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
            return Err(Init0Error::CapabilityEvidence);
        }
        let mut reply = [0; wyrmroot_dw1b_preemption::RECORD_BYTES];
        let mut handles = [];
        let counts = supervisor
            .receive_channel(channel, &mut reply, &mut handles)
            .map_err(Init0Error::Native)?;
        if counts.bytes != reply.len()
            || counts.handles != 0
            || wyrmroot_dw1b_preemption::parse_reply(&reply, round).is_err()
        {
            return Err(Init0Error::CapabilityEvidence);
        }
    }
    Ok(())
}

#[cfg(feature = "dw1b-preemption-integration")]
fn wait_dw1b_normal_exit<Supervisor: SupervisionPlatform<Error = NativeError>>(
    supervisor: &mut Supervisor,
    process: DwHandle,
    deadline: DwDeadline,
) -> Result<(), Init0Error> {
    let item = DwWaitItemV1 {
        handle: process,
        signals: DW_SIGNAL_EXITED,
    };
    let observed = supervisor
        .wait_many(core::slice::from_ref(&item), deadline)
        .map_err(Init0Error::Native)?;
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_EXITED.0 == 0 {
        return Err(Init0Error::CapabilityEvidence);
    }
    let info = supervisor
        .query_task_termination(process)
        .map_err(Init0Error::Native)?;
    validate_successful_exit(&info)
        .map_err(|error| Init0Error::Supervision(SupervisionError::Exit(error)))
}

#[cfg(feature = "dw1b-preemption-integration")]
fn close_dw1b_progress<System: Init0System>(
    system: &mut System,
    peers: Dw1bPeers,
) -> Result<(), Init0Error> {
    let mut first = None;
    for handle in [
        peers.progress_data,
        peers.progress.launch_channel,
        peers.progress.process,
    ] {
        if let Err(error) = system.close_handle(handle)
            && first.is_none()
        {
            first = Some(error);
        }
    }
    first.map_or(Ok(()), |error| Err(Init0Error::Cleanup(error)))
}

#[cfg(feature = "dw1b-preemption-integration")]
fn terminate_reap_close<
    Loader: LoaderPlatform<Error = NativeError>,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    loader: &mut Loader,
    supervisor: &mut Supervisor,
    loaded: LoadedProcess,
    deadline: DwDeadline,
) -> Result<(), Init0Error> {
    let mut first = None;
    record_cleanup(
        &mut first,
        loader
            .process_terminate(loaded.process)
            .map_err(Init0Error::Cleanup),
    );
    let item = DwWaitItemV1 {
        handle: loaded.process,
        signals: DW_SIGNAL_EXITED,
    };
    match supervisor.wait_many(core::slice::from_ref(&item), deadline) {
        Ok(observed) if observed.index == 0 && observed.observed.0 & DW_SIGNAL_EXITED.0 != 0 => {}
        Ok(_) => record_cleanup(&mut first, Err(Init0Error::CapabilityEvidence)),
        Err(error) => record_cleanup(&mut first, Err(Init0Error::Cleanup(error))),
    }
    match supervisor.query_task_termination(loaded.process) {
        Ok(info) if info.state == DW_TASK_STATE_EXITED => {}
        Ok(_) => record_cleanup(&mut first, Err(Init0Error::CapabilityEvidence)),
        Err(error) => record_cleanup(&mut first, Err(Init0Error::Cleanup(error))),
    }
    for handle in [loaded.launch_channel, loaded.process] {
        record_cleanup(
            &mut first,
            loader.close(handle).map_err(Init0Error::Cleanup),
        );
    }
    first.map_or(Ok(()), Err)
}

#[cfg(feature = "dw1b-preemption-integration")]
fn cleanup_dw1b_peers<
    System: Init0System,
    Loader: LoaderPlatform<Error = NativeError>,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    loader: &mut Loader,
    supervisor: &mut Supervisor,
    peers: Dw1bPeers,
    progress_reaped: bool,
    deadline: DwDeadline,
) -> Result<(), Init0Error> {
    let mut first = None;
    if !progress_reaped {
        record_cleanup(
            &mut first,
            terminate_reap_close(loader, supervisor, peers.progress, deadline),
        );
        record_cleanup(
            &mut first,
            system
                .close_handle(peers.progress_data)
                .map_err(Init0Error::Cleanup),
        );
    }
    record_cleanup(
        &mut first,
        terminate_reap_close(loader, supervisor, peers.hog, deadline),
    );
    first.map_or(Ok(()), Err)
}

#[cfg(feature = "dw1b-preemption-integration")]
fn cleanup_unloaded_progress<
    System: Init0System,
    Loader: LoaderPlatform<Error = NativeError>,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    loader: &mut Loader,
    supervisor: &mut Supervisor,
    hog: LoadedProcess,
    progress_data: DwHandle,
    progress_child: Option<DwHandle>,
    deadline: DwDeadline,
) -> Result<(), Init0Error> {
    let mut first = None;
    if let Some(progress_child) = progress_child {
        record_cleanup(
            &mut first,
            loader.close(progress_child).map_err(Init0Error::Cleanup),
        );
    }
    record_cleanup(
        &mut first,
        system
            .close_handle(progress_data)
            .map_err(Init0Error::Cleanup),
    );
    record_cleanup(
        &mut first,
        terminate_reap_close(loader, supervisor, hog, deadline),
    );
    first.map_or(Ok(()), Err)
}

#[cfg(feature = "dw1b-preemption-integration")]
fn record_cleanup(first: &mut Option<Init0Error>, result: Result<(), Init0Error>) {
    if let Err(error) = result
        && first.is_none()
    {
        *first = Some(error);
    }
}

#[cfg(feature = "dw1b-preemption-integration")]
fn finish_dw1b_operation(
    operation: Result<(), Init0Error>,
    cleanup: Result<(), Init0Error>,
) -> Result<(), Init0Error> {
    let mut first_cleanup = None;
    let primary = match operation {
        Err(error @ Init0Error::Cleanup(_)) => {
            record_cleanup(&mut first_cleanup, Err(error));
            None
        }
        Err(error) => Some(error),
        Ok(()) => None,
    };
    record_cleanup(&mut first_cleanup, cleanup);
    match (first_cleanup, primary) {
        (Some(error), _) | (None, Some(error)) => Err(error),
        (None, None) => Ok(()),
    }
}

#[cfg(feature = "dw1b-preemption-integration")]
fn prefer_cleanup(primary: Init0Error, cleanup: Result<(), Init0Error>) -> Init0Error {
    cleanup.err().unwrap_or(primary)
}

fn load_selected_child<Loader: LoaderPlatform<Error = NativeError>>(
    loader: &mut Loader,
    authority: LoadAuthority,
    bytes: &[u8],
) -> Result<LoadedProcess, Init0Error> {
    let archive = Archive::new(bytes).map_err(Init0Error::Bootfs)?;
    #[cfg(all(
        feature = "i2-stress-integration",
        not(feature = "i-capability-integration")
    ))]
    let path = I2_STRESS_PATH;
    #[cfg(all(
        feature = "i-capability-integration",
        not(feature = "i2-stress-integration")
    ))]
    let path = I_CAPABILITY_PATH;
    #[cfg(not(any(
        feature = "i2-stress-integration",
        feature = "i-capability-integration"
    )))]
    let path = HELLO_PATH;
    let entry = archive.lookup(path).map_err(|error| match error {
        LookupError::NotFound | LookupError::InvalidPath(_) => Init0Error::MissingHello,
    })?;
    if !entry.is_executable() || entry.data().is_empty() {
        return Err(Init0Error::HelloNotExecutable);
    }
    let display_path = entry.name_utf8().map_err(|_| Init0Error::MissingHello)?;
    load_process(
        loader,
        authority,
        LoadRequest {
            image: entry.data(),
            display_path,
            profile: selected_profile(),
            transaction_id: HELLO_TRANSACTION_ID,
        },
    )
    .map_err(Init0Error::Loader)
}

const fn selected_profile() -> LaunchProfile {
    #[cfg(all(
        feature = "i2-stress-integration",
        not(feature = "i-capability-integration")
    ))]
    {
        LaunchProfile::I2Stress
    }
    #[cfg(all(
        feature = "i-capability-integration",
        not(feature = "i2-stress-integration")
    ))]
    {
        LaunchProfile::CapabilityController
    }
    #[cfg(not(any(
        feature = "i2-stress-integration",
        feature = "i-capability-integration"
    )))]
    {
        LaunchProfile::Hello
    }
}

#[cfg(any(
    all(
        feature = "i2-stress-integration",
        feature = "i-capability-integration"
    ),
    all(
        feature = "i2-stress-integration",
        feature = "dw1b-preemption-integration"
    ),
    all(
        feature = "i-capability-integration",
        feature = "dw1b-preemption-integration"
    ),
    all(
        feature = "i2-stress-integration",
        feature = "dw1c-preemption-integration"
    ),
    all(
        feature = "i-capability-integration",
        feature = "dw1c-preemption-integration"
    ),
    all(
        feature = "dw1b-preemption-integration",
        feature = "dw1c-preemption-integration"
    )
))]
compile_error!("init0 selector integrations are mutually exclusive");

#[cfg(feature = "i-capability-integration")]
fn relay_capability_evidence<
    System: Init0System,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    supervisor: &mut Supervisor,
    parent_channel: DwHandle,
    child_channel: DwHandle,
    deadline: DwDeadline,
) -> Result<(), Init0Error> {
    for sequence in 0..wyrmroot_i_capability::WRCAP1_EVENT_COUNT {
        let item = DwWaitItemV1 {
            handle: child_channel,
            signals: DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        };
        let observed = supervisor
            .wait_many(core::slice::from_ref(&item), deadline)
            .map_err(|_| Init0Error::CapabilityEvidence)?;
        if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
            return Err(Init0Error::CapabilityEvidence);
        }
        let mut record = [0_u8; wyrmroot_i_capability::WRCAP1_RECORD_BYTES];
        let mut no_handles = [];
        let received = supervisor
            .receive_channel(child_channel, &mut record, &mut no_handles)
            .map_err(|_| Init0Error::CapabilityEvidence)?;
        if received.bytes != record.len()
            || received.handles != 0
            || !wyrmroot_i_capability::validate_relay_record(&record, sequence as u32)
        {
            return Err(Init0Error::CapabilityEvidence);
        }
        send_capability_record_bounded(system, supervisor, parent_channel, &record, deadline)?;
    }
    Ok(())
}

#[cfg(feature = "i-capability-integration")]
fn send_capability_record_bounded<
    System: Init0System,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    supervisor: &mut Supervisor,
    parent_channel: DwHandle,
    record: &[u8],
    deadline: DwDeadline,
) -> Result<(), Init0Error> {
    for _ in 0..32 {
        match system.send_channel(parent_channel, record) {
            Ok(()) => return Ok(()),
            Err(NativeError::Status(status)) if status == DW_STATUS_WOULD_BLOCK => {
                let item = DwWaitItemV1 {
                    handle: parent_channel,
                    signals: DwSignals(DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
                };
                let observed = supervisor
                    .wait_many(core::slice::from_ref(&item), deadline)
                    .map_err(|_| Init0Error::CapabilityEvidence)?;
                if observed.index != 0
                    || observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0
                    || observed.observed.0 & DW_SIGNAL_WRITABLE.0 == 0
                {
                    return Err(Init0Error::CapabilityEvidence);
                }
            }
            Err(_) => return Err(Init0Error::CapabilityEvidence),
        }
    }
    Err(Init0Error::CapabilityEvidence)
}

fn cleanup_loaded_process<System: Init0System, Loader: LoaderPlatform<Error = NativeError>>(
    system: &mut System,
    loader: &mut Loader,
    loaded: LoadedProcess,
    terminate: bool,
) -> Result<(), NativeError> {
    let mut first_error = None;
    if terminate && let Err(error) = loader.process_terminate(loaded.process) {
        first_error = Some(error);
    }
    for handle in [loaded.launch_channel, loaded.process] {
        if let Err(error) = system.close_handle(handle)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn cleanup_supervised_process<
    System: Init0System,
    Loader: LoaderPlatform<Error = NativeError>,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    loader: &mut Loader,
    supervisor: &mut Supervisor,
    loaded: LoadedProcess,
    terminate: bool,
) -> Result<Option<DwTaskTerminationInfoV1>, NativeError> {
    let mut first_error = None;
    let mut observed_exit = None;
    if terminate && let Err(error) = loader.process_terminate(loaded.process) {
        observed_exit = supervisor
            .query_task_termination(loaded.process)
            .ok()
            .filter(|info| info.state == DW_TASK_STATE_EXITED);
        if observed_exit.is_none() {
            first_error = Some(error);
        }
    }
    for handle in [loaded.launch_channel, loaded.process] {
        if let Err(error) = system.close_handle(handle)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(observed_exit),
    }
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

#[cfg(all(test, feature = "i-capability-integration"))]
mod capability_relay_tests {
    use deepwyrm_syscall::{
        DW_SIGNAL_READABLE, DW_TASK_TERMINATION_INFO_V1_SIZE, DW_TERMINATION_AUTHORIZED,
        DW_TERMINATION_NORMAL_EXIT, DW_WAIT_RESULT_V1_SIZE, DwTaskTerminationInfoV1,
        DwWaitResultV1,
    };
    use wyrmroot_i_capability::{
        CANCEL_TRANSACTION, CHANNEL_TOKEN, EXHAUST_TRANSACTION_BASE, EvidenceEvent, EvidenceKind,
        EvidenceTranscript, MEMORY_CHILD_RIGHTS_MASK, MEMORY_PAGE_BYTES, MEMORY_TRANSACTION,
        NORMAL_TRANSACTION, RESTART_TRANSACTION_BASE, WAIT_TOKEN, WRCAP1_EVENT_COUNT,
        WRCAP1_RECORD_BYTES,
    };

    use super::*;

    #[test]
    fn terminal_controller_failure_is_preserved_before_relay_cleanup() {
        let mut info = DwTaskTerminationInfoV1::default();
        info.size = DW_TASK_TERMINATION_INFO_V1_SIZE;
        info.version = 1;
        info.state = DW_TASK_STATE_EXITED;
        info.reason = DW_TERMINATION_NORMAL_EXIT;
        info.application_code = 0x2402_8c0d;
        assert_eq!(
            capability_terminal_error(info),
            Some(Init0Error::Supervision(SupervisionError::Exit(
                ExitValidationError::NonzeroApplicationCode(0x2402_8c0d)
            )))
        );

        info.application_code = 0;
        assert_eq!(capability_terminal_error(info), None);

        info.reason = DW_TERMINATION_AUTHORIZED;
        assert_eq!(
            capability_terminal_error(info),
            Some(Init0Error::Supervision(SupervisionError::Exit(
                ExitValidationError::NotNormalExit
            )))
        );

        info.reason = DW_TERMINATION_NORMAL_EXIT;
        info.detail = 7;
        assert_eq!(
            capability_terminal_error(info),
            Some(Init0Error::Supervision(SupervisionError::Exit(
                ExitValidationError::NonzeroExceptionFields
            )))
        );

        info.detail = 0;
        info.size = 0;
        assert_eq!(
            capability_terminal_error(info),
            Some(Init0Error::Supervision(SupervisionError::Exit(
                ExitValidationError::InvalidEnvelope
            )))
        );
    }

    const PARENT_CHANNEL: DwHandle = DwHandle(90);
    const CHILD_CHANNEL: DwHandle = DwHandle(91);
    const DEADLINE: DwDeadline = DwDeadline(1234);

    struct RelaySystem {
        relayed: [[u8; WRCAP1_RECORD_BYTES]; WRCAP1_EVENT_COUNT],
        count: usize,
        block_first_send: bool,
    }

    impl RelaySystem {
        const fn new() -> Self {
            Self {
                relayed: [[0; WRCAP1_RECORD_BYTES]; WRCAP1_EVENT_COUNT],
                count: 0,
                block_first_send: false,
            }
        }
    }

    impl Init0System for RelaySystem {
        fn query_capability_info(
            &mut self,
            _: DwHandle,
        ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
            unreachable!("relay does not query capabilities")
        }

        fn receive_channel(
            &mut self,
            _: DwHandle,
            _: &mut [u8],
            _: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, NativeError> {
            unreachable!("relay receives through the supervision adapter")
        }

        fn query_memory_object_size(&mut self, _: DwHandle) -> Result<u64, NativeError> {
            unreachable!("relay does not query memory")
        }

        fn with_bootfs_bytes<R>(
            &mut self,
            _: DwHandle,
            _: DwHandle,
            _: MappingPlan,
            _: impl for<'bytes> FnOnce(&'bytes [u8]) -> R,
        ) -> Result<R, NativeError> {
            unreachable!("relay does not map bootfs")
        }

        fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
            assert_eq!(channel, PARENT_CHANNEL);
            if self.block_first_send {
                self.block_first_send = false;
                return Err(NativeError::Status(deepwyrm_syscall::DW_STATUS_WOULD_BLOCK));
            }
            self.relayed[self.count].copy_from_slice(bytes);
            self.count += 1;
            Ok(())
        }

        fn close_handle(&mut self, _: DwHandle) -> Result<(), NativeError> {
            unreachable!("relay does not own handle cleanup")
        }
    }

    struct RelaySupervisor {
        records: [[u8; WRCAP1_RECORD_BYTES]; WRCAP1_EVENT_COUNT],
        next: usize,
        writable_waits: usize,
    }

    impl SupervisionPlatform for RelaySupervisor {
        type Error = NativeError;

        fn wait_many(
            &mut self,
            items: &[DwWaitItemV1],
            deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, Self::Error> {
            assert_eq!(deadline, DEADLINE);
            assert_eq!(items.len(), 1);
            let observed = if items[0].handle == CHILD_CHANNEL {
                DW_SIGNAL_READABLE
            } else {
                assert_eq!(items[0].handle, PARENT_CHANNEL);
                assert_eq!(
                    items[0].signals.0,
                    deepwyrm_syscall::DW_SIGNAL_WRITABLE.0
                        | deepwyrm_syscall::DW_SIGNAL_PEER_CLOSED.0
                );
                self.writable_waits += 1;
                deepwyrm_syscall::DW_SIGNAL_WRITABLE
            };
            Ok(DwWaitResultV1 {
                size: DW_WAIT_RESULT_V1_SIZE,
                version: 1,
                index: 0,
                observed,
                ..DwWaitResultV1::default()
            })
        }

        fn receive_channel(
            &mut self,
            channel: DwHandle,
            bytes: &mut [u8],
            handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, Self::Error> {
            assert_eq!(channel, CHILD_CHANNEL);
            assert!(handles.is_empty());
            bytes.copy_from_slice(&self.records[self.next]);
            self.next += 1;
            Ok(ReceiveCounts {
                bytes: WRCAP1_RECORD_BYTES,
                handles: 0,
            })
        }

        fn query_task_termination(
            &mut self,
            _: DwHandle,
        ) -> Result<DwTaskTerminationInfoV1, Self::Error> {
            unreachable!("relay runs before child supervision")
        }
    }

    #[test]
    fn relays_exactly_fifteen_controller_records_without_rewriting() {
        let records = records();
        let mut system = RelaySystem::new();
        let mut supervisor = RelaySupervisor {
            records,
            next: 0,
            writable_waits: 0,
        };

        relay_capability_evidence(
            &mut system,
            &mut supervisor,
            PARENT_CHANNEL,
            CHILD_CHANNEL,
            DEADLINE,
        )
        .unwrap();

        assert_eq!(system.count, WRCAP1_EVENT_COUNT);
        assert_eq!(system.relayed, records);
        assert_eq!(supervisor.next, WRCAP1_EVENT_COUNT);
        assert_eq!(supervisor.writable_waits, 0);
    }

    #[test]
    fn retries_a_would_block_relay_send_only_after_writable() {
        let records = records();
        let mut system = RelaySystem::new();
        system.block_first_send = true;
        let mut supervisor = RelaySupervisor {
            records,
            next: 0,
            writable_waits: 0,
        };

        relay_capability_evidence(
            &mut system,
            &mut supervisor,
            PARENT_CHANNEL,
            CHILD_CHANNEL,
            DEADLINE,
        )
        .unwrap();

        assert_eq!(system.count, WRCAP1_EVENT_COUNT);
        assert_eq!(system.relayed, records);
        assert_eq!(supervisor.next, WRCAP1_EVENT_COUNT);
        assert_eq!(supervisor.writable_waits, 1);
    }

    #[test]
    fn malformed_record_stops_relay_before_later_facts() {
        let mut records = records();
        records[3][73] = b':';
        let mut system = RelaySystem::new();
        let mut supervisor = RelaySupervisor {
            records,
            next: 0,
            writable_waits: 0,
        };

        assert_eq!(
            relay_capability_evidence(
                &mut system,
                &mut supervisor,
                PARENT_CHANNEL,
                CHILD_CHANNEL,
                DEADLINE,
            ),
            Err(Init0Error::CapabilityEvidence)
        );
        assert_eq!(system.count, 3);
        assert_eq!(supervisor.next, 4);
    }

    fn records() -> [[u8; WRCAP1_RECORD_BYTES]; WRCAP1_EVENT_COUNT] {
        let mut transcript = EvidenceTranscript::new(0x0123_4567_89AB_CDEF).unwrap();
        for event in [
            event(EvidenceKind::ContentDelivery, 0, 0, 3, 1, 2),
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
                MEMORY_PAGE_BYTES,
                MEMORY_CHILD_RIGHTS_MASK,
            ),
            event(EvidenceKind::ChannelLifecycle, 1, 1, CHANNEL_TOKEN, 0xF, 2),
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
            transcript.push(event).unwrap();
        }
        let mut records = [[0_u8; WRCAP1_RECORD_BYTES]; WRCAP1_EVENT_COUNT];
        for (index, record) in records.iter_mut().enumerate() {
            *record = transcript.encoded(index).unwrap();
        }
        records
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

#[cfg(all(test, feature = "dw1b-preemption-integration"))]
mod dw1b_tests;
