#![no_std]
#![forbid(unsafe_code)]

//! Temporary WYR0 `init0` application contract.
//!
//! WYR0-G validates its one-time loader handoff, maps the delegated read-only bootfs just long
//! enough to select `bin/hello`, and launches that descendant only through `wyrmroot-loader`.
//! It reports READY to its primordial parent only after `hello` acknowledges its parent Channel
//! and exits normally with application code zero.

use deepwyrm_syscall::{DwDeadline, DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights};
use wyrmroot_bootfs::archive::{Archive, LookupError, ParseError};
use wyrmroot_loader::{
    launch::{HEADER_BYTES, INIT0_BYTES, LaunchError, LaunchProfile, encode_ready, parse_init},
    process::{
        LoadAuthority, LoadError, LoadRequest, LoadStage, LoadedProcess, LoaderPlatform,
        load_process,
    },
};
use wyrmroot_runtime::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, CapabilityValidationError,
    ExitObservedReadinessError, ExitValidationError, InitCapability, LOADER_TASK_GROUP_EXPECTATION,
    MappingPlan, MappingPlanError, NativeError, ReceiveCounts, SELF_ROOT_EXPECTATION,
    SupervisionError, SupervisionPlatform, supervise_child, validate_bootstrap_channel,
    validate_init_capabilities_v2,
};

/// The only bootfs path selected by the WYR0-G descendant smoke chain.
pub const HELLO_PATH: &[u8] = b"bin/hello";
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
                match load_hello(loader, authority, bootfs) {
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

fn bootfs_mapping_plan<System: Init0System>(
    system: &mut System,
    bootfs: DwHandle,
) -> Result<MappingPlan, Init0Error> {
    system
        .query_memory_object_size(bootfs)
        .map_err(Init0Error::Native)
        .and_then(|size| MappingPlan::for_bootfs(size).map_err(Init0Error::Mapping))
}

fn load_hello<Loader: LoaderPlatform<Error = NativeError>>(
    loader: &mut Loader,
    authority: LoadAuthority,
    bytes: &[u8],
) -> Result<LoadedProcess, Init0Error> {
    let archive = Archive::new(bytes).map_err(Init0Error::Bootfs)?;
    let entry = archive.lookup(HELLO_PATH).map_err(|error| match error {
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
            profile: LaunchProfile::Hello,
            transaction_id: HELLO_TRANSACTION_ID,
        },
    )
    .map_err(Init0Error::Loader)
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
