#![no_std]
#![forbid(unsafe_code)]

//! Primordial Wyrmroot bootstrap transaction shared by the native entry and host fixtures.

#[cfg(any(
    all(
        feature = "primordial-blocking-cleanup",
        feature = "primordial-user-exception"
    ),
    all(
        feature = "primordial-blocking-cleanup",
        feature = "primordial-invalid-return"
    ),
    all(
        feature = "primordial-user-exception",
        feature = "primordial-invalid-return"
    )
))]
compile_error!("primordial bootstrap behavior variants are mutually exclusive");

#[cfg(any(
    all(
        feature = "i0-negative-malformed-elf",
        any(
            feature = "primordial-blocking-cleanup",
            feature = "primordial-user-exception",
            feature = "primordial-invalid-return",
            feature = "i0-negative-malformed-startup",
            feature = "i0-negative-capability-count",
            feature = "i0-negative-capability-type",
            feature = "i0-negative-capability-rights"
        )
    ),
    all(
        feature = "i0-negative-malformed-startup",
        any(
            feature = "primordial-blocking-cleanup",
            feature = "primordial-user-exception",
            feature = "primordial-invalid-return",
            feature = "i0-negative-capability-count",
            feature = "i0-negative-capability-type",
            feature = "i0-negative-capability-rights"
        )
    ),
    all(
        feature = "i0-negative-capability-count",
        any(
            feature = "primordial-blocking-cleanup",
            feature = "primordial-user-exception",
            feature = "primordial-invalid-return",
            feature = "i0-negative-capability-type",
            feature = "i0-negative-capability-rights"
        )
    ),
    all(
        feature = "i0-negative-capability-type",
        any(
            feature = "primordial-blocking-cleanup",
            feature = "primordial-user-exception",
            feature = "primordial-invalid-return",
            feature = "i0-negative-capability-rights"
        )
    ),
    all(
        feature = "i0-negative-capability-rights",
        any(
            feature = "primordial-blocking-cleanup",
            feature = "primordial-user-exception",
            feature = "primordial-invalid-return"
        )
    )
))]
compile_error!(
    "I0 negative bootstrap variants are mutually exclusive with other bootstrap behavior variants"
);

#[cfg(all(
    feature = "loader-smoke-integration",
    any(
        feature = "i0-negative-malformed-elf",
        feature = "i0-negative-malformed-startup",
        feature = "i0-negative-capability-count",
        feature = "i0-negative-capability-type",
        feature = "i0-negative-capability-rights"
    )
))]
compile_error!(
    "the WYR0-E loader-smoke integration is mutually exclusive with I0 negative variants"
);

#[cfg(any(
    all(
        feature = "loader-smoke-integration",
        feature = "primordial-blocking-cleanup"
    ),
    all(
        feature = "loader-smoke-integration",
        feature = "primordial-user-exception"
    ),
    all(
        feature = "loader-smoke-integration",
        feature = "primordial-invalid-return"
    )
))]
compile_error!(
    "the WYR0-E loader-smoke integration is mutually exclusive with primordial behavior variants"
);

#[cfg(all(
    feature = "i-capability-integration",
    any(
        feature = "loader-smoke-integration",
        feature = "primordial-blocking-cleanup",
        feature = "primordial-user-exception",
        feature = "primordial-invalid-return",
        feature = "i0-negative-malformed-elf",
        feature = "i0-negative-malformed-startup",
        feature = "i0-negative-capability-count",
        feature = "i0-negative-capability-type",
        feature = "i0-negative-capability-rights"
    )
))]
compile_error!("the WYR0-I capability relay is mutually exclusive with other bootstrap variants");

#[cfg(feature = "i-capability-relay")]
use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_SIGNAL_WRITABLE,
    DW_STATUS_TIMED_OUT, DW_STATUS_WOULD_BLOCK,
};
use deepwyrm_syscall::{
    DW_SIGNAL_EXITED, DW_TASK_STATE_EXITED, DwDeadline, DwHandle, DwObjectType,
    DwReceivedHandleInfoV1, DwRights, DwSignals, DwWaitItemV1,
};
use wyrmroot_bootfs::archive::{Archive, LookupError, ParseError};
use wyrmroot_bootstrap_proto::{
    BOOTSTRAP_INIT_V2_SIZE, BOOTSTRAP_READY_V2_SIZE, BootstrapMessage, DecodeError, InitMessageV2,
    MAX_BOOTSTRAP_HANDLES, ReadyMessageV2, decode,
};
#[cfg(feature = "loader-smoke-integration")]
use wyrmroot_loader::process::load_process;
use wyrmroot_loader::{
    launch::LaunchProfile,
    process::{
        LoadAuthority, LoadError, LoadFault, LoadRequest, LoadStage, LoadedProcess, LoaderPlatform,
        load_process_with_fault,
    },
};
#[cfg(feature = "primordial-test-support")]
use wyrmroot_runtime::PrimordialTestError;
use wyrmroot_runtime::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, CapabilityValidationError,
    InitCapability, LOADER_TASK_GROUP_EXPECTATION, MappingPlan, MappingPlanError, NativeError,
    ReceiveCounts, SELF_ROOT_EXPECTATION, validate_bootstrap_channel,
    validate_init_capabilities_v2,
};
use wyrmroot_runtime::{
    SupervisionError, SupervisionPlatform, supervise_child, validate_successful_exit,
};

/// Canonical init executable required in the primordial bootfs.
pub const INIT0_PATH: &[u8] = b"system/init0";
/// Canonical smoke executable required in the primordial bootfs.
pub const HELLO_PATH: &[u8] = b"bin/hello";
/// E-only temporary native loader probe. This is not an init0 policy entry.
#[cfg(feature = "loader-smoke-integration")]
pub const LOADER_SMOKE_PATH: &[u8] = b"test/loader-smoke";
/// Distinct nonzero WRLP transaction identifier used by the temporary E-only child.
#[cfg(feature = "loader-smoke-integration")]
pub const LOADER_SMOKE_TRANSACTION_ID: u64 = 2;

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
#[derive(Debug, Eq, PartialEq)]
pub enum BootstrapError {
    /// A native Deepwyrm operation failed or returned malformed output.
    Native(NativeError),
    /// The startup Channel did not have its exact type and rights.
    BootstrapChannel(CapabilityValidationError),
    /// INIT bytes or handle counts violated the locked protocol.
    Protocol(DecodeError),
    /// A native receive result exceeded the caller-provided fixed protocol buffers.
    ReceiveCounts(ReceiveCounts),
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
    /// An explicitly selected primordial kernel-test behavior failed closed.
    #[cfg(feature = "primordial-test-support")]
    TestSupport(PrimordialTestError),
    /// The E-only loader transaction failed before it published the temporary child.
    Loader(LoadError<NativeError>),
    /// Temporary WYR0-E child readiness or completion did not satisfy the exact contract.
    Supervision(SupervisionError<NativeError>),
    /// Cleanup of an already-published temporary child failed.
    Cleanup(ChildCleanupError),
    /// A successful bootfs callback failed to retain the child it created.
    MissingLoadedProcess,
    /// The selector-gated WYR0-I controller evidence relay rejected an init0 datagram.
    #[cfg(feature = "i-capability-relay")]
    CapabilityRelay(Wrcap1RelayError),
}

impl BootstrapError {
    /// Returns a bounded native application exit code for live integration diagnostics.
    ///
    /// A descendant's nonzero exit code is preserved so the canonical serial completion record
    /// identifies the deepest failing WYR0 application. Other failures retain a bootstrap-owned
    /// prefix and a stable category or loader-stage suffix.
    #[must_use]
    pub fn exit_code(&self) -> u32 {
        const PREFIX: u32 = 0xB000_0000;
        match self {
            Self::Native(NativeError::Status(status)) => {
                PREFIX | 0x0001_0000 | status.0.unsigned_abs()
            }
            Self::Native(NativeError::Output(output)) => {
                PREFIX | 0x0002_0000 | native_output_code(*output)
            }
            Self::BootstrapChannel(_) => PREFIX | 0x02,
            Self::Protocol(_) => PREFIX | 0x03,
            Self::ReceiveCounts(_) => PREFIX | 0x04,
            Self::UnexpectedMessage => PREFIX | 0x05,
            Self::UnexpectedTransactionId => PREFIX | 0x06,
            Self::Capability(_) => PREFIX | 0x07,
            Self::Mapping(_) => PREFIX | 0x08,
            Self::Bootfs(_) => PREFIX | 0x09,
            Self::MissingRequiredEntry => PREFIX | 0x0A,
            Self::RequiredEntryNotExecutable => PREFIX | 0x0B,
            #[cfg(feature = "i-capability-relay")]
            Self::CapabilityRelay(error) => PREFIX | 0x0D00 | wrcap1_relay_error_code(error),
            #[cfg(feature = "primordial-test-support")]
            Self::TestSupport(_) => PREFIX | 0x0C,
            Self::Loader(LoadError::Platform {
                stage,
                cause,
                rollback_failed,
            }) => loader_platform_exit_code(*stage, *cause, *rollback_failed),
            Self::Loader(_) => PREFIX | 0x01FF,
            Self::Supervision(SupervisionError::Exit(
                wyrmroot_runtime::ExitValidationError::NonzeroApplicationCode(code),
            )) => *code,
            Self::Supervision(_) => PREFIX | 0x0200,
            Self::Cleanup(error) => cleanup_exit_code(*error),
            Self::MissingLoadedProcess => PREFIX | 0x0301,
        }
    }
}

#[cfg(feature = "i-capability-relay")]
const fn wrcap1_relay_error_code(error: &Wrcap1RelayError) -> u32 {
    match error {
        Wrcap1RelayError::UnboundedDeadline => 1,
        Wrcap1RelayError::TimedOut => 2,
        Wrcap1RelayError::PeerClosed => 3,
        Wrcap1RelayError::InvalidWaitResult => 4,
        Wrcap1RelayError::ReceiveWouldBlock => 5,
        Wrcap1RelayError::SendWouldBlock => 6,
        Wrcap1RelayError::CapabilityBearing => 7,
        Wrcap1RelayError::MalformedFraming => 8,
        Wrcap1RelayError::UnexpectedSequence => 9,
        Wrcap1RelayError::UnexpectedKind => 10,
        Wrcap1RelayError::Checksum => 11,
    }
}

/// The exact operation that failed while reclaiming a published child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildCleanupStage {
    /// Terminating a child whose successful exit was not proven.
    ProcessTerminate,
    /// Closing the retained parent endpoint of the child's launch channel.
    LaunchChannelClose,
    /// Closing the retained child Process handle.
    ProcessHandleClose,
}

/// An exact failure while reclaiming a published child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildCleanupError {
    /// The cleanup operation that failed.
    pub stage: ChildCleanupStage,
    /// The native status or malformed-output cause.
    pub cause: NativeError,
}

/// Encodes final child-cleanup failures without collapsing the operation or native cause.
///
/// The `0xB2` high byte is bootstrap-owned. Bits 23..16 identify the cleanup
/// stage, bit 15 distinguishes bounded native-output failures from native
/// status values, and the low 15 bits retain the native cause.
const fn cleanup_exit_code(error: ChildCleanupError) -> u32 {
    const PREFIX: u32 = 0xB200_0000;
    let stage = match error.stage {
        ChildCleanupStage::ProcessTerminate => 1,
        ChildCleanupStage::LaunchChannelClose => 2,
        ChildCleanupStage::ProcessHandleClose => 3,
    };
    let cause = match error.cause {
        NativeError::Status(status) => PREFIX | bounded_status_code(status.0.unsigned_abs()),
        NativeError::Output(output) => PREFIX | 0x8000 | native_output_code(output),
    };
    cause | (stage << 16)
}

/// Encodes a native loader-platform failure without losing its bounded cause.
///
/// The `0xB1` high byte is reserved for bootstrap loader-platform exits, separate from ordinary
/// bootstrap-owned categories. Bit 23 records failed rollback, bits 22..16 identify the loader
/// stage, bit 15 selects a bounded native-output cause, and bits 14..0 carry either that output
/// code or a saturating absolute native status value.
const fn loader_platform_exit_code(
    stage: LoadStage,
    cause: NativeError,
    rollback_failed: bool,
) -> u32 {
    const PREFIX: u32 = 0xB100_0000;
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

/// Executes the complete D2 bootstrap handshake without exiting the process.
pub fn run_bootstrap<System: BootstrapSystem>(
    system: &mut System,
    bootstrap_channel: DwHandle,
) -> Result<(), BootstrapError> {
    run_bootstrap_inner(system, bootstrap_channel, |_| Ok(()))
}

/// WYR0-F child transaction identifier for `system/init0`.
pub const INIT0_TRANSACTION_ID: u64 = 1;

/// Number of controller-originated WYR0-I capability evidence records.
#[cfg(feature = "i-capability-relay")]
pub const WRCAP1_RECORD_COUNT: usize = 15;
/// Canonical ordered WYR0-I controller evidence kinds for the relay.
#[cfg(feature = "i-capability-relay")]
pub const WRCAP1_KINDS: [u8; WRCAP1_RECORD_COUNT] = [
    0x01, 0x02, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x07, 0x08, 0x08, 0x08, 0x08, 0x09, 0x0A,
];
/// Exact fixed-width ASCII length of one `WRCAP1` evidence datagram.
#[cfg(feature = "i-capability-relay")]
pub const WRCAP1_RECORD_SIZE: usize = 117;

/// A capability-evidence relay datagram did not meet the bootstrap boundary contract.
#[cfg(feature = "i-capability-relay")]
#[derive(Debug, Eq, PartialEq)]
pub enum Wrcap1RelayError {
    /// The relay was given an unbounded deadline.
    UnboundedDeadline,
    /// The bounded receive wait elapsed before the next required record arrived.
    TimedOut,
    /// The child Channel closed before its next required record became readable.
    PeerClosed,
    /// A wait result did not select the requested Channel or its requested signals.
    InvalidWaitResult,
    /// A post-readable receive raced with draining and reported `WOULD_BLOCK`.
    ReceiveWouldBlock,
    /// A bounded relay send remained backpressured after every permitted retry.
    SendWouldBlock,
    /// The child attached one or more handles to an evidence datagram.
    CapabilityBearing,
    /// The record was not exact fixed-width, uppercase ASCII `WRCAP1` framing.
    MalformedFraming,
    /// The record sequence was not the contiguous expected value.
    UnexpectedSequence,
    /// The record kind was not the required canonical next kind.
    UnexpectedKind,
    /// The record's checksum did not authenticate its exact preceding byte sequence.
    Checksum,
}

/// Stable terminal detail for the test-only malformed-ELF variant.
pub const I0_NEGATIVE_MALFORMED_ELF_DETAIL: u32 = 0xB000_0401;
/// Stable terminal detail for the test-only malformed-startup variant.
pub const I0_NEGATIVE_MALFORMED_STARTUP_DETAIL: u32 = 0xB000_0402;
/// Stable terminal detail for the test-only malformed capability-count variant.
pub const I0_NEGATIVE_CAPABILITY_COUNT_DETAIL: u32 = 0xB000_0403;
/// Stable terminal detail for the test-only malformed capability-type variant.
pub const I0_NEGATIVE_CAPABILITY_TYPE_DETAIL: u32 = 0xB000_0404;
/// Stable terminal detail for the test-only malformed capability-rights variant.
pub const I0_NEGATIVE_CAPABILITY_RIGHTS_DETAIL: u32 = 0xB000_0405;

/// Returns the distinct terminal detail only after a selected I0 test fault
/// produced its exact expected failure.  `None` preserves the real diagnostic
/// for every unexpected error.
pub fn i0_negative_terminal_detail(fault: LoadFault, error: &BootstrapError) -> Option<u32> {
    use wyrmroot_runtime::{
        ExitValidationError, StartupError, SupervisionError, startup_error_exit_code,
    };

    match (fault, error) {
        (
            LoadFault::MalformedElf,
            BootstrapError::Loader(LoadError::Elf(wyrmroot_loader::elf::ElfError::BadMagic)),
        ) => Some(I0_NEGATIVE_MALFORMED_ELF_DETAIL),
        (
            LoadFault::MalformedStartup,
            BootstrapError::Supervision(SupervisionError::Exit(
                ExitValidationError::NonzeroApplicationCode(code),
            )),
        ) if *code == startup_error_exit_code(StartupError::StringPointerOutOfRange) => {
            Some(I0_NEGATIVE_MALFORMED_STARTUP_DETAIL)
        }
        (
            LoadFault::InitCapabilityCount,
            BootstrapError::Supervision(SupervisionError::Exit(
                ExitValidationError::NonzeroApplicationCode(0x1000_0307),
            )),
        ) => Some(I0_NEGATIVE_CAPABILITY_COUNT_DETAIL),
        (
            LoadFault::InitCapabilityType,
            BootstrapError::Supervision(SupervisionError::Exit(
                ExitValidationError::NonzeroApplicationCode(0x1000_0330),
            )),
        ) => Some(I0_NEGATIVE_CAPABILITY_TYPE_DETAIL),
        (
            LoadFault::InitCapabilityRights,
            BootstrapError::Supervision(SupervisionError::Exit(
                ExitValidationError::NonzeroApplicationCode(0x1000_0330),
            )),
        ) => Some(I0_NEGATIVE_CAPABILITY_RIGHTS_DETAIL),
        _ => None,
    }
}

/// Runs the WYR0-F primordial bootstrap transaction before primordial READY.
///
/// The bootstrap validates the existing G primordial handoff and the complete required bootfs
/// manifest, maps the bootfs only while constructing `system/init0`, then transfers only the
/// loader's locked Init0 capabilities.  It deliberately has no `hello` fallback or descendant
/// policy: that remains WYR0-G work.
pub fn run_init0_bootstrap<
    System: BootstrapSystem,
    Loader: LoaderPlatform<Error = NativeError>,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    loader: &mut Loader,
    supervisor: &mut Supervisor,
    bootstrap_channel: DwHandle,
    deadline: DwDeadline,
) -> Result<(), BootstrapError> {
    run_init0_bootstrap_with_fault_and_before_supervision(
        system,
        loader,
        supervisor,
        bootstrap_channel,
        deadline,
        LoadFault::None,
        |_, _, _, _, _| Ok(()),
    )
}

/// Runs the selector-gated WYR0-I bootstrap transaction.
///
/// Before ordinary WRLP supervision, this path relays the controller's fifteen exact, handle-free
/// WRCAP1 datagrams from init0's launch Channel to the primordial parent Channel. Bootstrap
/// validates only the transport boundary it owns and forwards each accepted byte slice unchanged;
/// the controller remains the sole evidence-record source and the host owns full semantic joins.
#[cfg(feature = "i-capability-relay")]
pub fn run_init0_capability_bootstrap<
    System: BootstrapSystem,
    Loader: LoaderPlatform<Error = NativeError>,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    loader: &mut Loader,
    supervisor: &mut Supervisor,
    bootstrap_channel: DwHandle,
    deadline: DwDeadline,
) -> Result<(), BootstrapError> {
    run_init0_bootstrap_with_fault_and_before_supervision(
        system,
        loader,
        supervisor,
        bootstrap_channel,
        deadline,
        LoadFault::None,
        relay_wrcap1_records,
    )
}

/// Runs the primordial `init0` transaction with one explicit test-only child
/// launch fault.  Ordinary callers must use [`run_init0_bootstrap`].
pub fn run_init0_bootstrap_with_fault<
    System: BootstrapSystem,
    Loader: LoaderPlatform<Error = NativeError>,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    loader: &mut Loader,
    supervisor: &mut Supervisor,
    bootstrap_channel: DwHandle,
    deadline: DwDeadline,
    fault: LoadFault,
) -> Result<(), BootstrapError> {
    run_init0_bootstrap_with_fault_and_before_supervision(
        system,
        loader,
        supervisor,
        bootstrap_channel,
        deadline,
        fault,
        |_, _, _, _, _| Ok(()),
    )
}

fn run_init0_bootstrap_with_fault_and_before_supervision<
    System: BootstrapSystem,
    Loader: LoaderPlatform<Error = NativeError>,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    loader: &mut Loader,
    supervisor: &mut Supervisor,
    bootstrap_channel: DwHandle,
    deadline: DwDeadline,
    fault: LoadFault,
    before_supervision: impl FnOnce(
        &mut System,
        &mut Supervisor,
        DwHandle,
        DwHandle,
        DwDeadline,
    ) -> Result<(), BootstrapError>,
) -> Result<(), BootstrapError> {
    let channel_info = system
        .query_capability_info(bootstrap_channel)
        .map_err(BootstrapError::Native)?;
    validate_bootstrap_channel(channel_info, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(BootstrapError::BootstrapChannel)?;

    let mut bytes = [0_u8; BOOTSTRAP_INIT_V2_SIZE];
    let mut handles = [DwReceivedHandleInfoV1::default(); MAX_BOOTSTRAP_HANDLES];
    let counts = system
        .receive_channel(bootstrap_channel, &mut bytes, &mut handles)
        .map_err(BootstrapError::Native)?;
    if counts.bytes > bytes.len() || counts.handles > handles.len() {
        return Err(BootstrapError::ReceiveCounts(counts));
    }

    let operation = (|| {
        let transaction_id =
            expected_primordial_transaction(&bytes[..counts.bytes], counts.handles)?;
        let authority = validated_load_authority(system, &handles[..counts.handles])?;
        let plan = bootfs_mapping_plan(system, authority.bootfs)?;
        let mut loaded = None;
        let mapped =
            system.with_bootfs_bytes(authority.parent_root, authority.bootfs, plan, |bootfs| {
                match load_init0(loader, authority, bootfs, fault) {
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
                    return Err(BootstrapError::Cleanup(cleanup));
                }
                return Err(BootstrapError::Native(error));
            }
            (Err(error), None) => return Err(BootstrapError::Native(error)),
            (Ok(Ok(())), None) => return Err(BootstrapError::MissingLoadedProcess),
        };
        if let Err(error) = before_supervision(
            system,
            supervisor,
            loaded.launch_channel,
            bootstrap_channel,
            deadline,
        ) {
            let terminal =
                observe_terminal_after_relay_failure(supervisor, loaded.process, deadline);
            let cleanup_exit =
                cleanup_supervised_process(system, loader, supervisor, loaded, terminal.is_none())
                    .map_err(BootstrapError::Cleanup)?;
            if let Some(info) = terminal.or(cleanup_exit) {
                validate_successful_exit(&info)
                    .map_err(|error| BootstrapError::Supervision(SupervisionError::Exit(error)))?;
            }
            return Err(error);
        }
        let supervision = supervise_child(
            supervisor,
            loaded.process,
            loaded.launch_channel,
            INIT0_TRANSACTION_ID,
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
                .map_err(BootstrapError::Cleanup)?;
        if let Some(info) = late_exit.or(cleanup_exit) {
            validate_successful_exit(&info)
                .map_err(|error| BootstrapError::Supervision(SupervisionError::Exit(error)))?;
        }
        supervision.map_err(BootstrapError::Supervision)?;
        Ok(transaction_id)
    })();
    let cleanup = close_received_handles(system, &handles[..counts.handles]);
    let transaction_id = operation?;
    cleanup?;
    send_primordial_ready(system, bootstrap_channel, transaction_id)
}

fn observe_terminal_after_relay_failure<Supervisor: SupervisionPlatform<Error = NativeError>>(
    supervisor: &mut Supervisor,
    process: DwHandle,
    deadline: DwDeadline,
) -> Option<deepwyrm_syscall::DwTaskTerminationInfoV1> {
    if let Ok(info) = supervisor.query_task_termination(process)
        && info.state == DW_TASK_STATE_EXITED
    {
        return Some(info);
    }
    let item = DwWaitItemV1 {
        handle: process,
        signals: DwSignals(DW_SIGNAL_EXITED.0),
    };
    let observed = supervisor
        .wait_many(core::slice::from_ref(&item), deadline)
        .ok()?;
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_EXITED.0 == 0 {
        return None;
    }
    supervisor
        .query_task_termination(process)
        .ok()
        .filter(|info| info.state == DW_TASK_STATE_EXITED)
}

#[cfg(feature = "i-capability-relay")]
fn relay_wrcap1_records<
    System: BootstrapSystem,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    supervisor: &mut Supervisor,
    launch_channel: DwHandle,
    primordial_parent_channel: DwHandle,
    deadline: DwDeadline,
) -> Result<(), BootstrapError> {
    if deadline == DW_DEADLINE_INFINITE {
        return Err(BootstrapError::CapabilityRelay(
            Wrcap1RelayError::UnboundedDeadline,
        ));
    }
    let mut bytes = [0_u8; WRCAP1_RECORD_SIZE];
    let mut handles = [];
    for (sequence, expected_kind) in WRCAP1_KINDS.into_iter().enumerate() {
        wait_for_wrcap1_record(supervisor, launch_channel, deadline)?;
        let counts = match system.receive_channel(launch_channel, &mut bytes, &mut handles) {
            Err(NativeError::Status(status)) if status == DW_STATUS_WOULD_BLOCK => {
                return Err(BootstrapError::CapabilityRelay(
                    Wrcap1RelayError::ReceiveWouldBlock,
                ));
            }
            Err(error) => return Err(BootstrapError::Native(error)),
            Ok(counts) => counts,
        };
        if counts.handles != 0 {
            return Err(BootstrapError::CapabilityRelay(
                Wrcap1RelayError::CapabilityBearing,
            ));
        }
        if counts.bytes > bytes.len() {
            return Err(BootstrapError::ReceiveCounts(counts));
        }
        let record = &bytes[..counts.bytes];
        validate_wrcap1_record(record, sequence as u32, expected_kind)
            .map_err(BootstrapError::CapabilityRelay)?;
        send_wrcap1_record_bounded(
            system,
            supervisor,
            primordial_parent_channel,
            record,
            deadline,
        )?;
    }
    Ok(())
}

#[cfg(feature = "i-capability-relay")]
fn send_wrcap1_record_bounded<
    System: BootstrapSystem,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    supervisor: &mut Supervisor,
    parent_channel: DwHandle,
    record: &[u8],
    deadline: DwDeadline,
) -> Result<(), BootstrapError> {
    for _ in 0..32 {
        match system.send_channel(parent_channel, record) {
            Ok(()) => return Ok(()),
            Err(NativeError::Status(status)) if status == DW_STATUS_WOULD_BLOCK => {
                let item = DwWaitItemV1 {
                    handle: parent_channel,
                    signals: DwSignals(DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
                };
                let observed = match supervisor.wait_many(core::slice::from_ref(&item), deadline) {
                    Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
                        return Err(BootstrapError::CapabilityRelay(Wrcap1RelayError::TimedOut));
                    }
                    Err(error) => return Err(BootstrapError::Native(error)),
                    Ok(observed) => observed,
                };
                if observed.index != 0 {
                    return Err(BootstrapError::CapabilityRelay(
                        Wrcap1RelayError::InvalidWaitResult,
                    ));
                }
                if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
                    return Err(BootstrapError::CapabilityRelay(
                        Wrcap1RelayError::PeerClosed,
                    ));
                }
                if observed.observed.0 & DW_SIGNAL_WRITABLE.0 == 0 {
                    return Err(BootstrapError::CapabilityRelay(
                        Wrcap1RelayError::InvalidWaitResult,
                    ));
                }
            }
            Err(error) => return Err(BootstrapError::Native(error)),
        }
    }
    Err(BootstrapError::CapabilityRelay(
        Wrcap1RelayError::SendWouldBlock,
    ))
}

#[cfg(feature = "i-capability-relay")]
fn wait_for_wrcap1_record<Supervisor: SupervisionPlatform<Error = NativeError>>(
    supervisor: &mut Supervisor,
    launch_channel: DwHandle,
    deadline: DwDeadline,
) -> Result<(), BootstrapError> {
    let item = DwWaitItemV1 {
        handle: launch_channel,
        signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    };
    let result = match supervisor.wait_many(core::slice::from_ref(&item), deadline) {
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
            return Err(BootstrapError::CapabilityRelay(Wrcap1RelayError::TimedOut));
        }
        Err(error) => return Err(BootstrapError::Native(error)),
        Ok(result) => result,
    };
    if result.index != 0 || result.observed.0 & item.signals.0 == 0 {
        return Err(BootstrapError::CapabilityRelay(
            Wrcap1RelayError::InvalidWaitResult,
        ));
    }
    if result.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(BootstrapError::CapabilityRelay(
            Wrcap1RelayError::PeerClosed,
        ));
    }
    Ok(())
}

#[cfg(feature = "i-capability-relay")]
fn validate_wrcap1_record(
    record: &[u8],
    expected_sequence: u32,
    expected_kind: u8,
) -> Result<(), Wrcap1RelayError> {
    const DELIMITERS: [usize; 10] = [6, 9, 26, 35, 38, 47, 56, 73, 90, 107];
    if record.len() != WRCAP1_RECORD_SIZE
        || record[..7] != *b"WRCAP1|"
        || record[7..9] != *b"01"
        || record[116] != b'\n'
        || DELIMITERS.iter().any(|&index| record[index] != b'|')
        || !record[10..26].iter().any(|&byte| byte != b'0')
        || !record[10..26]
            .iter()
            .chain(record[27..35].iter())
            .chain(record[36..38].iter())
            .chain(record[39..47].iter())
            .chain(record[48..56].iter())
            .chain(record[57..73].iter())
            .chain(record[74..90].iter())
            .chain(record[91..107].iter())
            .chain(record[108..116].iter())
            .all(|&byte| matches!(byte, b'0'..=b'9' | b'A'..=b'F'))
    {
        return Err(Wrcap1RelayError::MalformedFraming);
    }
    if parse_hex_u32(&record[27..35]) != Some(expected_sequence) {
        return Err(Wrcap1RelayError::UnexpectedSequence);
    }
    if parse_hex_u32(&record[36..38]) != Some(u32::from(expected_kind)) {
        return Err(Wrcap1RelayError::UnexpectedKind);
    }
    if parse_hex_u32(&record[108..116]) != Some(fnv1a32(&record[..108])) {
        return Err(Wrcap1RelayError::Checksum);
    }
    Ok(())
}

#[cfg(feature = "i-capability-relay")]
fn parse_hex_u32(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0_u32, |value, &byte| {
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'A'..=b'F' => u32::from(byte - b'A' + 10),
            _ => return None,
        };
        value.checked_mul(16)?.checked_add(digit)
    })
}

#[cfg(feature = "i-capability-relay")]
const fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5_u32;
    let mut index = 0;
    while index < bytes.len() {
        hash ^= bytes[index] as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        index += 1;
    }
    hash
}

/// Runs the WYR0-E-only loader-smoke transaction before primordial READY.
///
/// This path launches only `test/loader-smoke` with the handle-free `Hello` profile.  It neither
/// starts `system/init0` nor establishes an init policy; later WYR0 phases own that behavior.
/// The caller supplies separate platform adapters so bootfs mapping can remain borrowed only for
/// ELF construction while readiness and completion observation remain fully host-testable.
#[cfg(feature = "loader-smoke-integration")]
pub fn run_loader_smoke_bootstrap<
    System: BootstrapSystem,
    Loader: LoaderPlatform<Error = NativeError>,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    loader: &mut Loader,
    supervisor: &mut Supervisor,
    bootstrap_channel: DwHandle,
    deadline: DwDeadline,
) -> Result<(), BootstrapError> {
    let channel_info = system
        .query_capability_info(bootstrap_channel)
        .map_err(BootstrapError::Native)?;
    validate_bootstrap_channel(channel_info, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(BootstrapError::BootstrapChannel)?;

    let mut bytes = [0_u8; BOOTSTRAP_INIT_V2_SIZE];
    let mut handles = [DwReceivedHandleInfoV1::default(); MAX_BOOTSTRAP_HANDLES];
    let counts = system
        .receive_channel(bootstrap_channel, &mut bytes, &mut handles)
        .map_err(BootstrapError::Native)?;
    if counts.bytes > bytes.len() || counts.handles > handles.len() {
        return Err(BootstrapError::ReceiveCounts(counts));
    }

    let operation = (|| {
        let transaction_id =
            expected_primordial_transaction(&bytes[..counts.bytes], counts.handles)?;
        let authority = validated_load_authority(system, &handles[..counts.handles])?;
        let plan = bootfs_mapping_plan(system, authority.bootfs)?;
        let mut loaded = None;
        let mapped =
            system.with_bootfs_bytes(authority.parent_root, authority.bootfs, plan, |bootfs| {
                match load_loader_smoke(loader, authority, bootfs) {
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
                    return Err(BootstrapError::Cleanup(cleanup));
                }
                return Err(BootstrapError::Native(error));
            }
            (Err(error), None) => return Err(BootstrapError::Native(error)),
            (Ok(Ok(())), None) => return Err(BootstrapError::MissingLoadedProcess),
        };
        let supervision = supervise_child(
            supervisor,
            loaded.process,
            loaded.launch_channel,
            LOADER_SMOKE_TRANSACTION_ID,
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
                .map_err(BootstrapError::Cleanup)?;
        if let Some(info) = late_exit.or(cleanup_exit) {
            validate_successful_exit(&info)
                .map_err(|error| BootstrapError::Supervision(SupervisionError::Exit(error)))?;
        }
        supervision.map_err(BootstrapError::Supervision)?;
        Ok(transaction_id)
    })();
    let cleanup = close_received_handles(system, &handles[..counts.handles]);
    let transaction_id = operation?;
    cleanup?;
    send_primordial_ready(system, bootstrap_channel, transaction_id)
}

/// Executes the bootstrap transaction with one explicit test-only hook before READY and close.
#[cfg(feature = "primordial-test-support")]
pub fn run_bootstrap_with_before_ready<System: BootstrapSystem>(
    system: &mut System,
    bootstrap_channel: DwHandle,
    before_ready: impl FnOnce(DwHandle) -> Result<(), BootstrapError>,
) -> Result<(), BootstrapError> {
    run_bootstrap_inner(system, bootstrap_channel, before_ready)
}

fn run_bootstrap_inner<System: BootstrapSystem>(
    system: &mut System,
    bootstrap_channel: DwHandle,
    before_ready: impl FnOnce(DwHandle) -> Result<(), BootstrapError>,
) -> Result<(), BootstrapError> {
    let channel_info = system
        .query_capability_info(bootstrap_channel)
        .map_err(BootstrapError::Native)?;
    validate_bootstrap_channel(channel_info, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(BootstrapError::BootstrapChannel)?;

    let mut bytes = [0_u8; BOOTSTRAP_INIT_V2_SIZE];
    let mut handles = [DwReceivedHandleInfoV1::default(); MAX_BOOTSTRAP_HANDLES];
    let counts = system
        .receive_channel(bootstrap_channel, &mut bytes, &mut handles)
        .map_err(BootstrapError::Native)?;
    if counts.bytes > bytes.len() || counts.handles > handles.len() {
        return Err(BootstrapError::ReceiveCounts(counts));
    }

    let operation = (|| {
        let transaction_id =
            expected_primordial_transaction(&bytes[..counts.bytes], counts.handles)?;
        process_init(system, &handles[..counts.handles])?;
        Ok(transaction_id)
    })();
    let cleanup = close_received_handles(system, &handles[..counts.handles]);
    let transaction_id = operation?;
    cleanup?;
    before_ready(bootstrap_channel)?;

    send_primordial_ready(system, bootstrap_channel, transaction_id)
}

fn expected_primordial_transaction(
    bytes: &[u8],
    handle_count: usize,
) -> Result<u64, BootstrapError> {
    match decode(bytes, handle_count).map_err(BootstrapError::Protocol)? {
        BootstrapMessage::InitV2(message) => {
            if message.transaction_id != InitMessageV2::primordial().transaction_id {
                return Err(BootstrapError::UnexpectedTransactionId);
            }
            Ok(message.transaction_id)
        }
        _ => Err(BootstrapError::UnexpectedMessage),
    }
}

fn send_primordial_ready<System: BootstrapSystem>(
    system: &mut System,
    bootstrap_channel: DwHandle,
    transaction_id: u64,
) -> Result<(), BootstrapError> {
    let mut ready = [0_u8; BOOTSTRAP_READY_V2_SIZE];
    let ready_size = ReadyMessageV2 { transaction_id }
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
        received_capability(handles[2]),
    ];
    let fresh = [
        system
            .query_capability_info(handles[0].handle)
            .map_err(BootstrapError::Native)?,
        system
            .query_capability_info(handles[1].handle)
            .map_err(BootstrapError::Native)?,
        system
            .query_capability_info(handles[2].handle)
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
        InitCapability {
            received: received[2],
            fresh: fresh[2],
        },
    ];
    validate_init_capabilities_v2(
        &capabilities,
        SELF_ROOT_EXPECTATION,
        BOOTFS_EXPECTATION,
        LOADER_TASK_GROUP_EXPECTATION,
    )
    .map_err(BootstrapError::Capability)?;

    let logical_size = system
        .query_memory_object_size(handles[1].handle)
        .map_err(BootstrapError::Native)?;
    let plan = MappingPlan::for_bootfs(logical_size).map_err(BootstrapError::Mapping)?;
    system
        .with_bootfs_bytes(handles[0].handle, handles[1].handle, plan, validate_bootfs)
        .map_err(BootstrapError::Native)?
}

fn validated_load_authority<System: BootstrapSystem>(
    system: &mut System,
    handles: &[DwReceivedHandleInfoV1],
) -> Result<LoadAuthority, BootstrapError> {
    if handles.len() != MAX_BOOTSTRAP_HANDLES {
        return Err(BootstrapError::Capability(
            CapabilityValidationError::WrongInitCapabilityCount,
        ));
    }
    let received = [
        received_capability(handles[0]),
        received_capability(handles[1]),
        received_capability(handles[2]),
    ];
    let fresh = [
        system
            .query_capability_info(handles[0].handle)
            .map_err(BootstrapError::Native)?,
        system
            .query_capability_info(handles[1].handle)
            .map_err(BootstrapError::Native)?,
        system
            .query_capability_info(handles[2].handle)
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
        InitCapability {
            received: received[2],
            fresh: fresh[2],
        },
    ];
    validate_init_capabilities_v2(
        &capabilities,
        SELF_ROOT_EXPECTATION,
        BOOTFS_EXPECTATION,
        LOADER_TASK_GROUP_EXPECTATION,
    )
    .map_err(BootstrapError::Capability)?;
    Ok(LoadAuthority {
        parent_root: handles[0].handle,
        bootfs: handles[1].handle,
        task_group: handles[2].handle,
    })
}

fn bootfs_mapping_plan<System: BootstrapSystem>(
    system: &mut System,
    bootfs: DwHandle,
) -> Result<MappingPlan, BootstrapError> {
    system
        .query_memory_object_size(bootfs)
        .map_err(BootstrapError::Native)
        .and_then(|size| MappingPlan::for_bootfs(size).map_err(BootstrapError::Mapping))
}

fn load_init0<Loader: LoaderPlatform<Error = NativeError>>(
    loader: &mut Loader,
    authority: LoadAuthority,
    bytes: &[u8],
    fault: LoadFault,
) -> Result<LoadedProcess, BootstrapError> {
    validate_bootfs(bytes)?;
    let archive = Archive::new(bytes).map_err(BootstrapError::Bootfs)?;
    let entry = archive.lookup(INIT0_PATH).map_err(|error| match error {
        LookupError::NotFound | LookupError::InvalidPath(_) => BootstrapError::MissingRequiredEntry,
    })?;
    let display_path = entry
        .name_utf8()
        .map_err(|_| BootstrapError::MissingRequiredEntry)?;
    load_process_with_fault(
        loader,
        authority,
        LoadRequest {
            image: entry.data(),
            display_path,
            profile: LaunchProfile::Init0,
            transaction_id: INIT0_TRANSACTION_ID,
        },
        fault,
    )
    .map_err(BootstrapError::Loader)
}

#[cfg(feature = "loader-smoke-integration")]
fn load_loader_smoke<Loader: LoaderPlatform<Error = NativeError>>(
    loader: &mut Loader,
    authority: LoadAuthority,
    bytes: &[u8],
) -> Result<LoadedProcess, BootstrapError> {
    let archive = Archive::new(bytes).map_err(BootstrapError::Bootfs)?;
    let entry = archive
        .lookup(LOADER_SMOKE_PATH)
        .map_err(|error| match error {
            LookupError::NotFound | LookupError::InvalidPath(_) => {
                BootstrapError::MissingRequiredEntry
            }
        })?;
    if !entry.is_executable() || entry.data().is_empty() {
        return Err(BootstrapError::RequiredEntryNotExecutable);
    }
    let display_path = entry
        .name_utf8()
        .map_err(|_| BootstrapError::MissingRequiredEntry)?;
    load_process(
        loader,
        authority,
        LoadRequest {
            image: entry.data(),
            display_path,
            profile: LaunchProfile::Hello,
            transaction_id: LOADER_SMOKE_TRANSACTION_ID,
        },
    )
    .map_err(BootstrapError::Loader)
}

fn cleanup_loaded_process<System: BootstrapSystem, Loader: LoaderPlatform<Error = NativeError>>(
    system: &mut System,
    loader: &mut Loader,
    loaded: LoadedProcess,
    terminate: bool,
) -> Result<(), ChildCleanupError> {
    let mut first_error = None;
    if terminate && let Err(error) = loader.process_terminate(loaded.process) {
        first_error = Some(ChildCleanupError {
            stage: ChildCleanupStage::ProcessTerminate,
            cause: error,
        });
    }
    for (handle, stage) in [
        (loaded.launch_channel, ChildCleanupStage::LaunchChannelClose),
        (loaded.process, ChildCleanupStage::ProcessHandleClose),
    ] {
        if let Err(error) = system.close_handle(handle)
            && first_error.is_none()
        {
            first_error = Some(ChildCleanupError {
                stage,
                cause: error,
            });
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn cleanup_supervised_process<
    System: BootstrapSystem,
    Loader: LoaderPlatform<Error = NativeError>,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    loader: &mut Loader,
    supervisor: &mut Supervisor,
    loaded: LoadedProcess,
    terminate: bool,
) -> Result<Option<deepwyrm_syscall::DwTaskTerminationInfoV1>, ChildCleanupError> {
    let mut first_error = None;
    let mut observed_exit = None;
    if terminate && let Err(error) = loader.process_terminate(loaded.process) {
        observed_exit = supervisor
            .query_task_termination(loaded.process)
            .ok()
            .filter(|info| info.state == DW_TASK_STATE_EXITED);
        if observed_exit.is_none() {
            first_error = Some(ChildCleanupError {
                stage: ChildCleanupStage::ProcessTerminate,
                cause: error,
            });
        }
    }
    for (handle, stage) in [
        (loaded.launch_channel, ChildCleanupStage::LaunchChannelClose),
        (loaded.process, ChildCleanupStage::ProcessHandleClose),
    ] {
        if let Err(error) = system.close_handle(handle)
            && first_error.is_none()
        {
            first_error = Some(ChildCleanupError {
                stage,
                cause: error,
            });
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(observed_exit),
    }
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
