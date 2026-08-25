#![no_std]
#![forbid(unsafe_code)]

//! Temporary WYR0 `init0` application contract.
//!
//! WYR0-G validates its one-time loader handoff, maps the delegated read-only bootfs just long
//! enough to select `bin/hello`, and launches that descendant only through `wyrmroot-loader`.
//! It reports READY to its primordial parent only after `hello` acknowledges its parent Channel
//! and exits normally with application code zero.

#[cfg(feature = "i-capability-integration")]
use deepwyrm_syscall::{
    DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_SIGNAL_WRITABLE, DW_STATUS_WOULD_BLOCK,
    DW_TASK_STATE_EXITED, DwSignals, DwTaskTerminationInfoV1, DwWaitItemV1,
};
use deepwyrm_syscall::{DwDeadline, DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights};
use wyrmroot_bootfs::archive::{Archive, LookupError, ParseError};
use wyrmroot_loader::{
    launch::{HEADER_BYTES, INIT0_BYTES, LaunchError, LaunchProfile, encode_ready, parse_init},
    process::{
        LoadAuthority, LoadError, LoadRequest, LoadStage, LoadedProcess, LoaderPlatform,
        load_process,
    },
};
#[cfg(feature = "i-capability-integration")]
use wyrmroot_runtime::validate_successful_exit;
use wyrmroot_runtime::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, CapabilityValidationError,
    ExitObservedReadinessError, ExitValidationError, InitCapability, LOADER_TASK_GROUP_EXPECTATION,
    MappingPlan, MappingPlanError, NativeError, ReceiveCounts, SELF_ROOT_EXPECTATION,
    SupervisionError, SupervisionPlatform, supervise_child, validate_bootstrap_channel,
    validate_init_capabilities_v2,
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

    /// Closes one caller-local handle.
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError>;
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
            cleanup_loaded_process(system, loader, loaded, terminal.is_none())
                .map_err(Init0Error::Cleanup)?;
            if let Some(error) = terminal.and_then(capability_terminal_error) {
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
        let terminate = matches!(
            &supervision,
            Err(error) if !error.process_exit_observed()
        );
        let loaded_cleanup = cleanup_loaded_process(system, loader, loaded, terminate);
        if let Err(cleanup) = loaded_cleanup {
            return Err(Init0Error::Cleanup(cleanup));
        }
        supervision.map_err(Init0Error::Supervision)?;
        Ok(message.transaction_id)
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

#[cfg(all(
    feature = "i2-stress-integration",
    feature = "i-capability-integration"
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
