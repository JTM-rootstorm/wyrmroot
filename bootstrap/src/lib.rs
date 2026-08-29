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

mod wyr0_compat;

pub use wyr0_compat::{
    HELLO_PATH, I0_NEGATIVE_CAPABILITY_COUNT_DETAIL, I0_NEGATIVE_CAPABILITY_RIGHTS_DETAIL,
    I0_NEGATIVE_CAPABILITY_TYPE_DETAIL, I0_NEGATIVE_MALFORMED_ELF_DETAIL,
    I0_NEGATIVE_MALFORMED_STARTUP_DETAIL, INIT0_PATH, INIT0_TRANSACTION_ID,
    i0_negative_terminal_detail, run_init0_bootstrap, run_init0_bootstrap_with_fault,
};

/// Permanent supervisor path used by normal WYR1 media.
pub const SYSTEM_INIT_PATH: &[u8] = b"system/init";
/// Primordial-owned nonzero transaction for the permanent supervisor handoff.
pub const SYSTEM_INIT_TRANSACTION_ID: u64 = 0x5759_5231_0000_0001;
#[cfg(feature = "loader-smoke-integration")]
pub use wyr0_compat::{LOADER_SMOKE_PATH, LOADER_SMOKE_TRANSACTION_ID, run_loader_smoke_bootstrap};
#[cfg(feature = "i-capability-relay")]
pub use wyr0_compat::{
    WRCAP1_KINDS, WRCAP1_RECORD_COUNT, WRCAP1_RECORD_SIZE, Wrcap1RelayError,
    run_init0_capability_bootstrap,
};

use deepwyrm_syscall::{
    DW_TASK_STATE_EXITED, DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights,
    DwTaskTerminationInfoV1,
};
use wyrmroot_bootfs::archive::{Archive, LookupError, ParseError};
use wyrmroot_bootstrap_proto::{
    BOOTSTRAP_INIT_V2_SIZE, BOOTSTRAP_READY_V2_SIZE, BootstrapMessage, DecodeError, InitMessageV2,
    MAX_BOOTSTRAP_V2_HANDLES, ReadyMessageV2, decode,
};
use wyrmroot_loader::launch::{LaunchError, LaunchProfile};
use wyrmroot_loader::process::{
    LoadAuthority, LoadError, LoadRequest, LoadStage, LoadedProcess, LoaderPlatform,
};
#[cfg(feature = "primordial-test-support")]
use wyrmroot_runtime::PrimordialTestError;
use wyrmroot_runtime::await_child_ready_profile_observed;
use wyrmroot_runtime::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, CapabilityValidationError,
    InitCapability, LOADER_TASK_GROUP_EXPECTATION, MappingPlan, MappingPlanError, NativeError,
    ReceiveCounts, SELF_ROOT_EXPECTATION, validate_bootstrap_channel,
    validate_init_capabilities_v2,
};
use wyrmroot_runtime::{
    ExitObservedReadinessError, ExitValidationError, ObservedSupervisionError, SupervisionError,
    SupervisionPlatform, validate_successful_exit,
};

/// Launches exactly `/system/init`, accepts its operational WRLP 1.2 READY,
/// retires primordial authority, and reports READY to the kernel parent. The
/// permanent supervisor is deliberately not awaited to exit.
pub fn run_supervisor_bootstrap<
    System: BootstrapSystem,
    Loader: LoaderPlatform<Error = NativeError>,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    loader: &mut Loader,
    supervisor: &mut Supervisor,
    bootstrap_channel: DwHandle,
    deadline: deepwyrm_syscall::DwDeadline,
) -> Result<(), BootstrapError> {
    let channel_info = system
        .query_capability_info(bootstrap_channel)
        .map_err(BootstrapError::Native)?;
    validate_bootstrap_channel(channel_info, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(BootstrapError::BootstrapChannel)?;
    let mut bytes = [0; BOOTSTRAP_INIT_V2_SIZE];
    let mut handles = [DwReceivedHandleInfoV1::default(); MAX_BOOTSTRAP_V2_HANDLES];
    let counts = system
        .receive_channel(bootstrap_channel, &mut bytes, &mut handles)
        .map_err(BootstrapError::Native)?;
    if counts.bytes > bytes.len() || counts.handles > handles.len() {
        let initialized = core::cmp::min(counts.handles, handles.len());
        let handles_cleanup = close_received_handles(system, &handles[..initialized]);
        let channel_cleanup = system
            .close_handle(bootstrap_channel)
            .map_err(BootstrapError::Native);
        handles_cleanup?;
        channel_cleanup?;
        return Err(BootstrapError::ReceiveCounts(counts));
    }
    let operation = (|| {
        let message =
            decode(&bytes[..counts.bytes], counts.handles).map_err(BootstrapError::Protocol)?;
        let BootstrapMessage::InitV2(init) = message else {
            return Err(BootstrapError::UnexpectedMessage);
        };
        if init.transaction_id != 1 {
            return Err(BootstrapError::UnexpectedTransactionId);
        }
        let authority = validated_load_authority(system, &handles[..counts.handles])?;
        let plan = bootfs_mapping_plan(system, authority.bootfs)?;
        let mut loaded = None;
        system
            .with_bootfs_bytes(authority.parent_root, authority.bootfs, plan, |bootfs| {
                let archive = Archive::new(bootfs).map_err(BootstrapError::Bootfs)?;
                let entry = archive
                    .lookup(SYSTEM_INIT_PATH)
                    .map_err(|_| BootstrapError::MissingRequiredEntry)?;
                if !entry.is_executable() || entry.data().is_empty() {
                    return Err(BootstrapError::RequiredEntryNotExecutable);
                }
                let display_path = entry
                    .name_utf8()
                    .map_err(|_| BootstrapError::MissingRequiredEntry)?;
                loaded = Some(
                    wyrmroot_loader::process::load_process(
                        loader,
                        authority,
                        LoadRequest {
                            image: entry.data(),
                            display_path,
                            profile: LaunchProfile::Supervisor,
                            transaction_id: SYSTEM_INIT_TRANSACTION_ID,
                        },
                    )
                    .map_err(BootstrapError::Loader)?,
                );
                Ok(())
            })
            .map_err(BootstrapError::Native)??;
        let loaded = loaded.ok_or(BootstrapError::MissingLoadedProcess)?;
        let ready = await_child_ready_profile_observed(
            supervisor,
            loaded.process,
            loaded.launch_channel,
            LaunchProfile::Supervisor,
            SYSTEM_INIT_TRANSACTION_ID,
            deadline,
        );
        if let Err(error) = ready {
            let terminate = !error.process_exit_observed();
            cleanup_loaded_process(system, loader, loaded, terminate)
                .map_err(BootstrapError::Cleanup)?;
            return Err(match error {
                ObservedSupervisionError::Supervision(error) => BootstrapError::Supervision(error),
                error => BootstrapError::ObservedSupervision(error),
            });
        }
        // Closing primordial's observation handles does not terminate init;
        // init owns its delegated descendant TaskGroup and immutable bootfs.
        cleanup_loaded_process(system, loader, loaded, false).map_err(BootstrapError::Cleanup)?;
        Ok(init.transaction_id)
    })();
    let cleanup = close_received_handles(system, &handles[..counts.handles]);
    let transaction = operation?;
    cleanup?;
    send_primordial_ready(system, bootstrap_channel, transaction)
}

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
    /// Permanent supervisor readiness failed after retaining its exact terminal record.
    ObservedSupervision(ObservedSupervisionError<NativeError>),
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
            Self::Supervision(error) => supervision_exit_code(error),
            Self::ObservedSupervision(error) => observed_supervision_exit_code(error),
            Self::Cleanup(error) => cleanup_exit_code(*error),
            Self::MissingLoadedProcess => PREFIX | 0x0301,
        }
    }
}

/// Encodes a permanent supervisor's retained terminal record without widening
/// the native ABI or emitting an ad-hoc diagnostic channel.
///
/// The high byte identifies the bounded terminal-record format. Bits 23..22
/// classify the fault address as absent, lower-user-canonical,
/// upper-canonical, or noncanonical. Bits 21..18 and 17..14 retain saturated
/// termination-reason and exception-type values, bits 13..6 retain saturated
/// reason-specific detail, and the existing supervision category remains in
/// the low six bits consumed by selector diagnostics.
const fn observed_terminal_code(category: u32, info: &DwTaskTerminationInfoV1) -> u32 {
    const PREFIX: u32 = 0xB400_0000;
    let reason = bounded_u32(info.reason.0, 0xF);
    let exception_type = bounded_u32(info.exception_type.0, 0xF);
    let detail = bounded_u32(info.detail, 0xFF);
    PREFIX
        | (fault_address_class(info.fault_address) << 22)
        | (reason << 18)
        | (exception_type << 14)
        | (detail << 6)
        | category
}

const fn bounded_u32(value: u32, maximum: u32) -> u32 {
    if value > maximum { maximum } else { value }
}

const fn fault_address_class(address: u64) -> u32 {
    if address == 0 {
        0
    } else if address < 0x0000_8000_0000_0000 {
        1
    } else if address >= 0xFFFF_8000_0000_0000 {
        2
    } else {
        3
    }
}

const fn observed_exit_validation_code(
    error: &ExitValidationError,
    info: &DwTaskTerminationInfoV1,
) -> u32 {
    match error {
        ExitValidationError::InvalidEnvelope => observed_terminal_code(10, info),
        ExitValidationError::NotExited => observed_terminal_code(11, info),
        ExitValidationError::NotNormalExit => observed_terminal_code(12, info),
        ExitValidationError::NonzeroApplicationCode(code) => *code,
        ExitValidationError::NonzeroExceptionFields => observed_terminal_code(13, info),
    }
}

fn observed_terminal_readiness_code(
    info: &DwTaskTerminationInfoV1,
    readiness_category: u32,
) -> u32 {
    match validate_successful_exit(info) {
        Ok(()) => observed_terminal_code(readiness_category, info),
        Err(error) => observed_exit_validation_code(&error, info),
    }
}

fn observed_supervision_exit_code(error: &ObservedSupervisionError<NativeError>) -> u32 {
    match error {
        ObservedSupervisionError::Supervision(error) => supervision_exit_code(error),
        ObservedSupervisionError::ExitedBeforeReady(info) => {
            observed_terminal_readiness_code(info, 7)
        }
        ObservedSupervisionError::PeerClosedBeforeReady(info) => {
            observed_terminal_readiness_code(info, 8)
        }
        ObservedSupervisionError::Exit(error, info) => observed_exit_validation_code(error, info),
        ObservedSupervisionError::ExitObservedReadiness(error, info) => {
            let category = match error {
                ExitObservedReadinessError::Platform(_) => 14,
                ExitObservedReadinessError::InvalidWaitResult => 15,
                ExitObservedReadinessError::InvalidReadyReceive(_) => 16,
                ExitObservedReadinessError::Ready(_) => 17,
                ExitObservedReadinessError::DuplicateReady => 18,
            };
            observed_terminal_code(category, info)
        }
    }
}

/// Encodes the exact supervision stage in the low six bits so selector
/// diagnostics that retain only the bootstrap family and bounded category do
/// not collapse every READY failure to the old `0xB000_0200` value.
///
/// Bits 19..6 carry a bounded native, framing, or count detail. Bit 20 marks a
/// malformed native output rather than a native status. Descendant nonzero
/// application codes remain unchanged because they are already the most exact
/// available diagnosis.
const fn supervision_exit_code(error: &SupervisionError<NativeError>) -> u32 {
    const UNBOUNDED_DEADLINE: u32 = 1;
    const PLATFORM: u32 = 2;
    const EXIT_QUERY: u32 = 3;
    const INVALID_WAIT_RESULT: u32 = 4;
    const INVALID_READY_RECEIVE: u32 = 5;
    const READY: u32 = 6;
    const EXITED_BEFORE_READY: u32 = 7;
    const PEER_CLOSED_BEFORE_READY: u32 = 8;
    const DUPLICATE_READY: u32 = 9;
    const EXIT_INVALID_ENVELOPE: u32 = 10;
    const EXIT_NOT_EXITED: u32 = 11;
    const EXIT_NOT_NORMAL: u32 = 12;
    const EXIT_NONZERO_EXCEPTION: u32 = 13;
    const EXIT_DRAIN_PLATFORM: u32 = 14;
    const EXIT_DRAIN_INVALID_WAIT: u32 = 15;
    const EXIT_DRAIN_INVALID_RECEIVE: u32 = 16;
    const EXIT_DRAIN_READY: u32 = 17;
    const EXIT_DRAIN_DUPLICATE_READY: u32 = 18;

    match error {
        SupervisionError::UnboundedDeadline => supervision_code(UNBOUNDED_DEADLINE, 0),
        SupervisionError::Platform(error) => supervision_native_code(PLATFORM, *error),
        SupervisionError::ExitQuery(error) => supervision_native_code(EXIT_QUERY, *error),
        SupervisionError::InvalidWaitResult => supervision_code(INVALID_WAIT_RESULT, 0),
        SupervisionError::InvalidReadyReceive(counts) => {
            supervision_code(INVALID_READY_RECEIVE, receive_counts_detail(*counts))
        }
        SupervisionError::Ready(error) => supervision_code(READY, launch_error_code(*error)),
        SupervisionError::ExitedBeforeReady => supervision_code(EXITED_BEFORE_READY, 0),
        SupervisionError::PeerClosedBeforeReady => supervision_code(PEER_CLOSED_BEFORE_READY, 0),
        SupervisionError::DuplicateReady => supervision_code(DUPLICATE_READY, 0),
        SupervisionError::Exit(ExitValidationError::InvalidEnvelope) => {
            supervision_code(EXIT_INVALID_ENVELOPE, 0)
        }
        SupervisionError::Exit(ExitValidationError::NotExited) => {
            supervision_code(EXIT_NOT_EXITED, 0)
        }
        SupervisionError::Exit(ExitValidationError::NotNormalExit) => {
            supervision_code(EXIT_NOT_NORMAL, 0)
        }
        SupervisionError::Exit(ExitValidationError::NonzeroApplicationCode(code)) => *code,
        SupervisionError::Exit(ExitValidationError::NonzeroExceptionFields) => {
            supervision_code(EXIT_NONZERO_EXCEPTION, 0)
        }
        SupervisionError::ExitObservedReadiness(ExitObservedReadinessError::Platform(error)) => {
            supervision_native_code(EXIT_DRAIN_PLATFORM, *error)
        }
        SupervisionError::ExitObservedReadiness(ExitObservedReadinessError::InvalidWaitResult) => {
            supervision_code(EXIT_DRAIN_INVALID_WAIT, 0)
        }
        SupervisionError::ExitObservedReadiness(
            ExitObservedReadinessError::InvalidReadyReceive(counts),
        ) => supervision_code(EXIT_DRAIN_INVALID_RECEIVE, receive_counts_detail(*counts)),
        SupervisionError::ExitObservedReadiness(ExitObservedReadinessError::Ready(error)) => {
            supervision_code(EXIT_DRAIN_READY, launch_error_code(*error))
        }
        SupervisionError::ExitObservedReadiness(ExitObservedReadinessError::DuplicateReady) => {
            supervision_code(EXIT_DRAIN_DUPLICATE_READY, 0)
        }
    }
}

const fn supervision_code(category: u32, detail: u32) -> u32 {
    const PREFIX: u32 = 0xB020_0000;
    const DETAIL_MAX: u32 = 0x3FFF;
    let detail = if detail > DETAIL_MAX {
        DETAIL_MAX
    } else {
        detail
    };
    PREFIX | (detail << 6) | category
}

const fn supervision_native_code(category: u32, error: NativeError) -> u32 {
    const OUTPUT: u32 = 1 << 20;
    match error {
        NativeError::Status(status) => supervision_code(category, status.0.unsigned_abs()),
        NativeError::Output(output) => {
            supervision_code(category, native_output_code(output)) | OUTPUT
        }
    }
}

const fn receive_counts_detail(counts: ReceiveCounts) -> u32 {
    const COUNT_MAX: usize = 0x7F;
    let bytes = if counts.bytes > COUNT_MAX {
        COUNT_MAX
    } else {
        counts.bytes
    };
    let handles = if counts.handles > COUNT_MAX {
        COUNT_MAX
    } else {
        counts.handles
    };
    ((bytes as u32) << 7) | handles as u32
}

const fn launch_error_code(error: LaunchError) -> u32 {
    match error {
        LaunchError::BufferSize => 1,
        LaunchError::BadMagic => 2,
        LaunchError::BadVersion => 3,
        LaunchError::BadType => 4,
        LaunchError::NonzeroFlags => 5,
        LaunchError::BadTotalSize => 6,
        LaunchError::BadCapabilityCount => 7,
        LaunchError::ZeroTransaction => 8,
        LaunchError::TransactionMismatch => 9,
        LaunchError::NonzeroReserved => 10,
        LaunchError::BadCapabilityRole { index } => 0x100 | bounded_index(index),
        LaunchError::HandleCount => 11,
        LaunchError::HandleMetadata { index } => 0x200 | bounded_index(index),
        LaunchError::ProfileSpecificEncoderRequired => 0x300,
    }
}

const fn bounded_index(index: usize) -> u32 {
    if index > 0xFF { 0xFF } else { index as u32 }
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
    let mut handles = [DwReceivedHandleInfoV1::default(); MAX_BOOTSTRAP_V2_HANDLES];
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
    if handles.len() != MAX_BOOTSTRAP_V2_HANDLES {
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
    if handles.len() != MAX_BOOTSTRAP_V2_HANDLES {
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
