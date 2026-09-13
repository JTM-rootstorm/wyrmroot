//! Permanent WYR1-A supervisor policy and native startup boundary.
//!
//! The fixed controller composes `RestartSupervisor`; it does not implement a
//! dependency solver or copy restart-policy transitions.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(any(
    all(feature = "wyr1e-production", feature = "wyr1d-selector32"),
    all(feature = "wyr1e-production", feature = "dw1e3-selector31"),
    all(feature = "wyr1e-production", feature = "wyr1c6-selector29")
))]
compile_error!("WYR1-E production and selector-only init policies are mutually exclusive");

#[cfg(all(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
compile_error!("WYR1-E7 and E8 selector profiles are mutually exclusive");

use core::mem::MaybeUninit;

#[cfg(feature = "wyr1e-production")]
use wyrmroot_consoled as _;
#[cfg(test)]
use {wyrmroot_devmgr as _, wyrmroot_uart16550d as _};

pub mod evidence;
pub mod gate;
#[cfg(feature = "r1-selector34")]
pub mod r1_driver;
#[cfg(feature = "r1-selector34")]
pub mod r1_relay;
pub mod wyr1b;
pub mod wyr1b_gate;
mod wyr1b_job;
pub mod wyr1b_native;
#[cfg(feature = "wyr1c6-selector29")]
pub mod wyr1c6_gate;
pub mod wyr1c_native;
#[cfg(feature = "wyr1d-selector32")]
pub mod wyr1d_gate;
#[cfg(any(test, feature = "wyr1e-selector33"))]
mod wyr1e7_evidence;
#[cfg(any(test, feature = "wyr1e8-selector33"))]
mod wyr1e8_evidence;

use crate::evidence::{EvidenceError, EvidenceEvent, EvidenceLog};
use crate::gate::{GATE_CONFIG_PATH, GateConfig, GateConfigError, parse_gate_config};
use deepwyrm_syscall::{
    DW_SIGNAL_EXITED, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_STATUS_TIMED_OUT,
    DW_TASK_STATE_EXITED, DW_TERMINATION_AUTHORIZED, DW_TERMINATION_NORMAL_EXIT,
    DW_TERMINATION_TASK_GROUP_TEARDOWN, DwDeadline, DwHandle, DwHandleTransferV1, DwObjectType,
    DwReceivedHandleInfoV1, DwRights, DwTaskTerminationInfoV1, DwWaitItemV1, DwWaitResultV1,
};
use wyrmroot_bootfs::archive::{Archive, LookupError, ParseError};
use wyrmroot_loader::{
    launch::{
        HEADER_BYTES, LaunchProfile, RESOURCE_DOMAIN_CLAIM_RIGHTS, RESOURCE_DOMAIN_CUSTODY_RIGHTS,
        SUPERVISOR_BYTES, encode_ready_for_profile, parse_init,
    },
    process::{
        LoadAuthority, LoadError, LoadRequest, LoadedProcess, LoaderPlatform, ServiceLoadRequest,
        load_process, load_service_process,
    },
};
use wyrmroot_rrc_manifest::{
    Activation, DependencyKind, MANIFEST_PATH, Manifest, ParseError as ManifestParseError, RoleId,
    StartupProfile,
};
use wyrmroot_runtime::{
    AttemptFailure, CleanupDisposition, RestartState, RestartSupervisor, RestartTransitionError,
    TerminalDisposition, WYR0_I_SUPERVISION_POLICY,
};
use wyrmroot_runtime::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, CapabilityValidationError,
    InitCapability, LOADER_TASK_GROUP_EXPECTATION, MappingPlan, MappingPlanError, NativeError,
    ObservedSupervisionError, RESOURCE_DOMAIN_TASK_GROUP_EXPECTATION, ReceiveCounts,
    SELF_ROOT_EXPECTATION, SupervisionError, SupervisionPlatform,
    await_child_ready_profile_observed, supervise_ready_child_profile, validate_bootstrap_channel,
    validate_init_capabilities_v2, validate_init_capabilities_v3,
};

pub const SYSTEM_INIT_PATH: &str = "system/init";
pub const EARLY_ROLE_COUNT: usize = 2;
const EXPECTED_ROLE_PATHS: [(RoleId, &str); 5] = [
    (RoleId::Registryd, "system/registryd"),
    (RoleId::Devmgr, "system/devmgr"),
    (RoleId::Uart16550d, "system/uart16550d"),
    (RoleId::Consoled, "system/consoled"),
    (RoleId::Wyrmsh, "system/wyrmsh"),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemMode {
    Bootstrap,
    SupervisorOperational,
    ActivatingEarlyRoles,
    Normal,
    Degraded,
    Fatal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryResult {
    Recovered,
    Degraded,
    Fatal,
}

/// Process application status used when permanent init cannot safely continue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum InitApplicationStatus {
    /// Fatal bootstrap/supervision failure; platform recovery requires reboot.
    FatalRebootRequired = 0xAF01_0002,
}

#[must_use]
pub const fn fatal_application_status(_error: &InitError) -> InitApplicationStatus {
    InitApplicationStatus::FatalRebootRequired
}

/// E8-only record of the emergency dispatcher cleanup that followed an
/// initiating error. This is private diagnostic state, not protocol or
/// application-status ABI.
#[cfg(feature = "wyr1e8-selector33")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum E8EmergencyCleanup {
    NotRun,
    DisconnectFailed,
    Attempted {
        channel_close_failed: bool,
        owner_cleanup_failed: bool,
    },
}

#[cfg(feature = "wyr1e8-selector33")]
impl E8EmergencyCleanup {
    const fn failed(self) -> bool {
        match self {
            Self::NotRun => false,
            Self::DisconnectFailed => true,
            Self::Attempted {
                channel_close_failed,
                owner_cleanup_failed,
            } => channel_close_failed || owner_cleanup_failed,
        }
    }
}

/// E8-only operation that most narrowly returned an error during the bounded
/// recovery transition. These values are private diagnostic evidence,
/// not protocol or application-status ABI.
#[cfg(feature = "wyr1e8-selector33")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum E8FailureOperation {
    TriggerWait = 0x01,
    /// Explicit WRC8 response parsing, identity or post-receive lateness.
    Quiesced = 0x02,
    RequestRetire = 0x03,
    RetireDependents = 0x04,
    ReapDriver = 0x05,
    AcknowledgeReaped = 0x06,
    DriverRetired = 0x07,
    RebindPublication = 0x08,
    /// The action-live guard, including expiry after ordinary READY receipt.
    ActionDeadline = 0x09,
    /// Ordinary registry/devmgr recovery requested while an action is active.
    RecoveryFallback = 0x0a,
    RetireRegistry = 0x0b,
    LaunchRegistry = 0x0c,
    CommitRegistry = 0x0d,
    StartConsole = 0x0e,
}

#[cfg(feature = "wyr1e8-selector33")]
const fn e8_failure_kind(error: &InitError) -> u8 {
    match error {
        InitError::WrongActivationOrder => 0x01,
        InitError::Accounting | InitError::Wyr1BModel(_) => 0x02,
        InitError::Supervision => 0x03,
        InitError::Cleanup => 0x04,
        InitError::Native(_) => 0x05,
        InitError::WrongManifestProfile
        | InitError::ResourceIdentityMismatch
        | InitError::InvalidResourceHandle
        | InitError::Capability(_)
        | InitError::RegistryProtocol(_)
        | InitError::Wyr1BGateProtocol(_)
        | InitError::Wyr1BGateMismatch => 0x06,
        InitError::UnlaunchableRole
        | InitError::Bootfs(_)
        | InitError::MissingRetainedMaterial
        | InitError::NonExecutableRole
        | InitError::Manifest(_)
        | InitError::ArtifactIdentityMismatch(_)
        | InitError::Mapping(_)
        | InitError::Launch(_)
        | InitError::Loader(_) => 0x07,
        InitError::GateConfig(_)
        | InitError::Evidence(_)
        | InitError::Wyr1BGateConfig(_)
        | InitError::Wyr1BEvidence(_) => 0x08,
        #[cfg(feature = "wyr1b-test-evidence")]
        InitError::StartupMapping(_) | InitError::OrdinaryMapping(_) => 0x07,
        #[cfg(feature = "wyr1c6-selector29")]
        InitError::Wyr1C6GateConfig(_) => 0x08,
        InitError::E8Transition {
            initiating_kind,
            emergency_cleanup,
            ..
        } => {
            if emergency_cleanup.failed() {
                0x04
            } else {
                *initiating_kind
            }
        }
        InitError::MissingAttemptResources
        | InitError::ResourcesAlreadyInstalled
        | InitError::Restart(_)
        | InitError::ZeroBootGeneration => 0x0f,
    }
}

#[cfg(feature = "wyr1e8-selector33")]
pub(crate) fn e8_operation<T>(
    operation: E8FailureOperation,
    result: Result<T, InitError>,
) -> Result<T, InitError> {
    result.map_err(|error| match error {
        InitError::E8Transition { .. } => error,
        _ => InitError::E8Transition {
            operation: operation as u8,
            initiating_kind: e8_failure_kind(&error),
            emergency_cleanup: E8EmergencyCleanup::NotRun,
        },
    })
}

#[cfg(feature = "wyr1e8-selector33")]
pub(crate) fn e8_dispatch_failure(
    error: InitError,
    emergency_cleanup: E8EmergencyCleanup,
) -> InitError {
    match error {
        InitError::E8Transition {
            operation,
            initiating_kind,
            ..
        } => InitError::E8Transition {
            operation,
            initiating_kind,
            emergency_cleanup,
        },
        error => InitError::E8Transition {
            operation: 0x0f,
            initiating_kind: e8_failure_kind(&error),
            emergency_cleanup,
        },
    }
}

/// Application detail for a fatal resident tick. E8 records the narrow
/// operation that returned `Err` and its initiating kind. If the dispatcher's
/// emergency cleanup fails, the same operation is reported with existing kind
/// `04` while the initiating kind remains in the private carrier. Every other
/// build preserves the established coarse resident failure code.
#[must_use]
pub const fn resident_tick_failure_application_status(error: &InitError) -> u32 {
    #[cfg(feature = "wyr1e8-selector33")]
    {
        let (operation, kind) = match error {
            InitError::E8Transition {
                operation,
                initiating_kind,
                emergency_cleanup,
            } => (
                *operation,
                if emergency_cleanup.failed() {
                    0x04
                } else {
                    *initiating_kind
                },
            ),
            _ => (0x0f, e8_failure_kind(error)),
        };
        let operation = match operation {
            0x01..=0x0f => operation,
            _ => 0x0f,
        };
        let kind = match kind {
            0x01..=0x08 | 0x0f => kind,
            _ => 0x0f,
        };
        0xAF18_0000 | (operation as u32) << 8 | kind as u32
    }
    // Selector 34 keeps the category here for the same reason it keeps it at the
    // pre-READY boundary: a resident-tick failure that reports only 0xAF01_0006
    // cannot be told apart from any other fatal tick.
    #[cfg(feature = "r1-selector34")]
    {
        0xAF36_0000 | test_failure_category(error)
    }
    #[cfg(not(any(feature = "wyr1e8-selector33", feature = "r1-selector34")))]
    {
        let _ = error;
        0xAF01_0006
    }
}

/// Test-only application status that preserves the top-level init failure
/// category across the selector's process-exit boundary. These values are
/// diagnostic evidence, not part of the production application-status ABI.
#[cfg(any(
    feature = "wyr1-test-evidence",
    feature = "wyr1b-test-evidence",
    feature = "wyr1c6-selector29",
    feature = "r1-selector34"
))]
const fn test_failure_category(error: &InitError) -> u32 {
    match error {
        InitError::WrongManifestProfile => 0x01,
        InitError::UnlaunchableRole => 0x02,
        InitError::WrongActivationOrder => 0x03,
        InitError::MissingAttemptResources => 0x04,
        InitError::ResourcesAlreadyInstalled => 0x05,
        InitError::ResourceIdentityMismatch => 0x06,
        InitError::InvalidResourceHandle => 0x07,
        InitError::Restart(_) => 0x08,
        InitError::Bootfs(_) => 0x09,
        InitError::MissingRetainedMaterial => 0x0a,
        InitError::NonExecutableRole => 0x0b,
        InitError::Manifest(_) => 0x0c,
        InitError::ZeroBootGeneration => 0x0d,
        InitError::ArtifactIdentityMismatch(_) => 0x0e,
        InitError::Native(_) => 0x0f,
        InitError::Capability(_) => 0x10,
        InitError::Mapping(_) => 0x11,
        #[cfg(feature = "wyr1b-test-evidence")]
        InitError::StartupMapping(_) => 0x11,
        #[cfg(feature = "wyr1b-test-evidence")]
        InitError::OrdinaryMapping(_) => 0x11,
        InitError::Launch(_) => 0x12,
        InitError::Loader(_) => 0x13,
        InitError::Supervision => 0x14,
        InitError::Cleanup => 0x15,
        InitError::Accounting => 0x16,
        InitError::GateConfig(_) => 0x17,
        InitError::Evidence(_) => 0x18,
        InitError::Wyr1BGateConfig(_) => 0x19,
        InitError::RegistryProtocol(_) => 0x1a,
        InitError::Wyr1BGateProtocol(_) => 0x1b,
        InitError::Wyr1BGateMismatch => 0x1c,
        InitError::Wyr1BModel(_) => 0x1d,
        InitError::Wyr1BEvidence(_) => 0x1e,
        #[cfg(feature = "wyr1c6-selector29")]
        InitError::Wyr1C6GateConfig(_) => 0x1f,
        #[cfg(feature = "wyr1e8-selector33")]
        InitError::E8Transition { .. } => 0x20,
        #[cfg(feature = "r1-selector34")]
        InitError::R1Probe(failure) => failure.category(),
        #[cfg(feature = "r1-selector34")]
        InitError::R1Relay(_) => 0x25,
    }
}

/// Selector-29-only status preserving the pre-READY system-init failure
/// category across the primordial Process-exit boundary.
#[cfg(feature = "wyr1c6-selector29")]
#[must_use]
pub const fn wyr1c6_test_failure_application_status(error: &InitError) -> u32 {
    match error {
        InitError::Native(error) => 0xAF1D_0000 | wyrmroot_runtime::native_error_code(*error),
        _ => 0xAF1C_0000 | test_failure_category(error),
    }
}

#[cfg(feature = "wyr1-test-evidence")]
#[must_use]
pub const fn wyr1_test_failure_application_status(error: &InitError) -> u32 {
    0xAF11_0000 | test_failure_category(error)
}

/// Why card R1's probe never produced its terminal record, as precisely as the
/// driver could establish it.
///
/// Run 5 reported `Supervision` from two unrelated sites -- the READY handshake
/// and the report drain -- and both discarded the probe's own normal-exit code,
/// which is `PROBE_ERROR_BASE | ordinal` and names the exact startup check that
/// refused. That left the run proving the probe did not report and nothing about
/// why, which is the same cause-erasing shape the `0xAF34` bases were introduced
/// to remove, one layer further in. Each variant here is a distinct terminal
/// status, so a later run says which site failed and, when the kernel recorded
/// one, with which probe code.
#[cfg(feature = "r1-selector34")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R1ProbeFailure {
    /// The probe exited with its own nonzero application code, kept verbatim.
    ExitCode(u32),
    /// The READY handshake failed with no exact terminal record to attribute it
    /// to: a timeout, or a liveness failure the kernel could not resolve to an
    /// exit. The probe may still have been running.
    ReadyUnattributed,
    /// The probe stopped reporting before its terminal record and its task-state
    /// record carried no application code -- it had not exited normally, or had
    /// not exited at all and only closed its channel.
    DrainUnattributed,
    /// The probe stopped reporting and the task-state query itself refused, so
    /// no exit code could be read.
    DrainQueryFailed,
}

#[cfg(feature = "r1-selector34")]
impl R1ProbeFailure {
    /// Category byte for this failure, continuing `test_failure_category`'s
    /// sequence so each site is separable in the terminal status.
    const fn category(self) -> u32 {
        match self {
            // `ExitCode` never reaches a category: the status encoder gives it
            // its own base so the probe's full code survives. It is mapped here
            // only because `test_failure_category` is total over `InitError`.
            Self::ExitCode(_) => 0x21,
            Self::ReadyUnattributed => 0x22,
            Self::DrainUnattributed => 0x23,
            Self::DrainQueryFailed => 0x24,
        }
    }
}

/// Packs a relay refusal into sixteen bits, keeping the numbers that identify it.
///
/// Run 6 reported `0xAF340001` because the driver answered a refused record with
/// `InitError::WrongManifestProfile`, one of fourteen sites returning that value.
/// The refusal itself knows exactly what was wrong -- `OutOfOrder` carries the
/// expected and observed sequence numbers, `WrongTopology` the two counts that
/// disagreed -- and all of it was discarded at the boundary.
///
/// Layout: kind in the high nibble, its own numbers in the low twelve bits. Both
/// sequence numbers fit because the relay refuses anything past
/// `RELAY_CAPACITY` (64), and both topology counts fit because the gate's own
/// fields are bounded well below 64; each is saturated rather than truncated so a
/// wild value reads as at-the-limit instead of as a small one.
#[cfg(feature = "r1-selector34")]
const fn r1_relay_detail(error: &r1_relay::RelayError) -> u32 {
    use r1_relay::RelayError;

    const fn six(value: u64) -> u32 {
        if value > 0x3f { 0x3f } else { value as u32 }
    }

    match error {
        RelayError::Malformed(header) => 0x1000 | r1_relay_header_detail(header),
        RelayError::UnexpectedHandles => 0x2000,
        RelayError::WrongTopology {
            online_cpus,
            hog_count,
        } => 0x3000 | (six(*online_cpus as u64) << 6) | six(*hog_count as u64),
        RelayError::OutOfOrder { expected, observed } => {
            0x4000 | (six(*expected) << 6) | six(*observed)
        }
        RelayError::AfterTerminal => 0x5000,
        RelayError::Full => 0x6000,
    }
}

/// Ordinal of the header rejection behind a `Malformed` refusal.
///
/// Enumerated rather than cast so adding a `HeaderError` variant is a compile
/// error here instead of silently joining whichever ordinal it lands on.
#[cfg(feature = "r1-selector34")]
const fn r1_relay_header_detail(error: &wyrmroot_r1_saturation::record::HeaderError) -> u32 {
    use wyrmroot_r1_saturation::record::HeaderError;

    match error {
        HeaderError::WrongLength => 0x01,
        HeaderError::WrongMagic => 0x02,
        HeaderError::UnsupportedVersion => 0x03,
        HeaderError::SizeMismatch => 0x04,
        HeaderError::UnknownKind => 0x05,
        HeaderError::ZeroSequence => 0x06,
        HeaderError::ZeroNonce => 0x07,
    }
}

/// Selector-34-only status preserving the pre-READY system-init failure category
/// across the primordial Process-exit boundary.
///
/// Card R1's first two runs each died before the probe ran, and the second
/// reported only `FatalRebootRequired` -- one value standing for all thirty-two
/// `InitError` categories -- so the run proved the product had failed and
/// nothing about where. Deepwyrm reports selector 34's terminal application code
/// unsummarized, so every bit kept here reaches the host transcript intact.
///
/// `Native` keeps its own base because `native_error_code` needs a full sixteen
/// bits: collapsing it into the category byte would discard exactly the status
/// that identifies which syscall refused.
#[cfg(feature = "r1-selector34")]
#[must_use]
pub const fn r1_test_failure_application_status(error: &InitError) -> u32 {
    match error {
        InitError::Native(error) => 0xAF35_0000 | wyrmroot_runtime::native_error_code(*error),
        // The probe's own code, not a category: `PROBE_ERROR_BASE` occupies the
        // high half, so the low sixteen bits carry the ordinal that identifies
        // which of its startup checks refused.
        InitError::R1Probe(R1ProbeFailure::ExitCode(code)) => 0xAF37_0000 | (*code & 0xffff),
        // A refused record's own reason, for the same purpose: run 6 proved a
        // record had been refused and nothing about which check refused it.
        InitError::R1Relay(error) => 0xAF38_0000 | r1_relay_detail(error),
        _ => 0xAF34_0000 | test_failure_category(error),
    }
}

/// Coarse, bounded classification of the queried startup bootfs size.
#[cfg(feature = "wyr1b-test-evidence")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StartupBootfsSizeClass {
    Zero = 0,
    SmallNonzero = 1,
    Admitted = 2,
    OverMaximum = 3,
    GarbageHigh = 4,
}

/// Selector-27-only evidence for the initial bootfs mapping-plan failure.
#[cfg(feature = "wyr1b-test-evidence")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupMappingDiagnostic {
    error: MappingPlanError,
    size_class: StartupBootfsSizeClass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum MappingDiagnosticSite {
    RoleRemap = 1,
    JobDispatcher = 2,
    RegistryReplacement = 3,
}

/// Selector-27-only evidence for a post-startup bootfs mapping-plan failure.
#[cfg(feature = "wyr1b-test-evidence")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrdinaryMappingDiagnostic {
    site: MappingDiagnosticSite,
    error: MappingPlanError,
    size_class: StartupBootfsSizeClass,
}

#[cfg(feature = "wyr1b-test-evidence")]
const fn startup_bootfs_size_class(size: u64) -> StartupBootfsSizeClass {
    if size == 0 {
        StartupBootfsSizeClass::Zero
    } else if size < wyrmroot_runtime::PAGE_SIZE {
        StartupBootfsSizeClass::SmallNonzero
    } else if size <= wyrmroot_runtime::MAX_BOOTFS_LOGICAL_SIZE {
        StartupBootfsSizeClass::Admitted
    } else if size < (1_u64 << 63) {
        StartupBootfsSizeClass::OverMaximum
    } else {
        StartupBootfsSizeClass::GarbageHigh
    }
}

#[cfg(feature = "wyr1b-test-evidence")]
const fn mapping_failure_ordinal(
    site: u32,
    error: MappingPlanError,
    size_class: StartupBootfsSizeClass,
) -> u32 {
    let outcome = match (error, size_class) {
        (MappingPlanError::EmptyArchive, StartupBootfsSizeClass::Zero) => 0,
        (MappingPlanError::ArchiveTooLarge, StartupBootfsSizeClass::OverMaximum) => 1,
        (MappingPlanError::ArchiveTooLarge, StartupBootfsSizeClass::GarbageHigh) => 2,
        _ => 0x1f,
    };
    if outcome == 0x1f {
        outcome
    } else {
        site * 3 + outcome + 1
    }
}

/// Selector-27 test evidence keeps supplementary mapping detail in the byte
/// above the category. Its low five bits carry the claim-bearing ordinal that
/// survives primordial application-summary compression: three reachable
/// mapping outcomes for each of four ordered mapping sites produce `1..=12`.
#[cfg(feature = "wyr1b-test-evidence")]
#[must_use]
pub const fn wyr1b_test_failure_application_status(error: &InitError) -> u32 {
    let (detail, ordinal) = match error {
        InitError::StartupMapping(diagnostic) => {
            let variant = match diagnostic.error {
                MappingPlanError::EmptyArchive => 1,
                MappingPlanError::ArchiveTooLarge => 2,
                MappingPlanError::RoundingOverflow => 3,
            };
            (
                (variant << 4) | diagnostic.size_class as u32,
                mapping_failure_ordinal(0, diagnostic.error, diagnostic.size_class),
            )
        }
        InitError::OrdinaryMapping(diagnostic) => {
            let variant = match diagnostic.error {
                MappingPlanError::EmptyArchive => 1,
                MappingPlanError::ArchiveTooLarge => 2,
                MappingPlanError::RoundingOverflow => 3,
            };
            (
                ((diagnostic.site as u32) << 6) | (variant << 3) | diagnostic.size_class as u32,
                mapping_failure_ordinal(
                    diagnostic.site as u32,
                    diagnostic.error,
                    diagnostic.size_class,
                ),
            )
        }
        _ => (0, test_failure_category(error)),
    };
    0xAF11_0000 | (detail << 8) | ordinal
}

/// Boot-lifetime owner of the fixed supervisor state and primordial authority.
/// The immutable bootfs handle is retained and remapped narrowly for each load;
/// no borrowed mapping escapes a transition.
#[derive(Debug, Eq, PartialEq)]
pub struct ResidentSystemInit {
    controller: SystemInit,
    authority: LoadAuthority,
    result: RecoveryResult,
    active: [Option<ActiveNativeRole>; EARLY_ROLE_COUNT],
    evidence_finalized: bool,
    last_tick_ns: u64,
    wyr1b: Option<wyr1b_native::ResidentState>,
    wyr1b_evidence: Option<wyr1b_gate::EvidenceLog>,
    wyr1c: Option<wyr1c_native::ResidentState>,
}

/// Broad primordial resource-domain custody. It is intentionally not a field
/// of [`LoadAuthority`]: ordinary process construction must not manufacture
/// or absorb device-claim authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceDomainCustody {
    resource_domain: DwHandle,
}

impl ResourceDomainCustody {
    pub const fn new(resource_domain: DwHandle) -> Self {
        Self { resource_domain }
    }

    pub const fn handle(self) -> DwHandle {
        self.resource_domain
    }

    /// Models the only D5 reduction init may make for a devmgr-generation
    /// descendant. Membership is kernel-authoritative; this seam refuses to
    /// represent a claim capability for init itself or another outsider.
    pub fn devmgr_claim_authority(
        self,
        membership: ResourceDomainMembership,
    ) -> Result<ReducedResourceDomainAuthority, ResourceDomainCustodyError> {
        match membership {
            ResourceDomainMembership::InitOutsideDomain | ResourceDomainMembership::Unrelated => {
                Err(ResourceDomainCustodyError::OutsideResourceDomain)
            }
            ResourceDomainMembership::DevmgrGenerationDescendant => {
                Ok(ReducedResourceDomainAuthority {
                    resource_domain: self.resource_domain,
                    rights: RESOURCE_DOMAIN_CLAIM_RIGHTS,
                })
            }
        }
    }
}

/// D5 model membership relation. It records the kernel custody predicate but
/// does not implement a userspace claim syscall.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceDomainMembership {
    InitOutsideDomain,
    Unrelated,
    DevmgrGenerationDescendant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReducedResourceDomainAuthority {
    resource_domain: DwHandle,
    rights: DwRights,
}

impl ReducedResourceDomainAuthority {
    pub const fn handle(self) -> DwHandle {
        self.resource_domain
    }
    pub const fn rights(self) -> DwRights {
        self.rights
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceDomainCustodyError {
    OutsideResourceDomain,
}

/// Explicit broad-rights identity used by focused D5 model tests.
pub const RESOURCE_DOMAIN_CUSTODY_PROFILE_RIGHTS: DwRights = RESOURCE_DOMAIN_CUSTODY_RIGHTS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveNativeRole {
    role: RoleId,
    generation: u64,
    transaction_id: u64,
    loaded: LoadedProcess,
    task_group: DwHandle,
}

#[derive(Debug, Eq, PartialEq)]
struct ActivationState {
    controller: SystemInit,
    result: RecoveryResult,
    active: [Option<ActiveNativeRole>; EARLY_ROLE_COUNT],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RoleActivation {
    Ready(ActiveNativeRole),
    Degraded,
}

impl ResidentSystemInit {
    #[must_use]
    pub const fn result(&self) -> RecoveryResult {
        self.result
    }

    #[must_use]
    pub const fn controller(&self) -> &SystemInit {
        &self.controller
    }

    #[must_use]
    pub const fn authority(&self) -> LoadAuthority {
        self.authority
    }

    #[must_use]
    pub const fn evidence_finalized(&self) -> bool {
        self.evidence_finalized
    }

    /// Returns one completed selector-27 evidence record. Selector 25 and
    /// incomplete selector-27 attempts expose no WRB1 record.
    #[must_use]
    pub fn wyr1b_evidence_record(&self, index: usize) -> Option<&[u8; wyr1b_gate::RECORD_BYTES]> {
        self.wyr1b_evidence.as_ref()?.record_at(index)
    }

    /// Returns one completed selector-29 WRC6 record. Incomplete joins expose
    /// no record and therefore cannot be submitted as acceptance evidence.
    #[cfg(feature = "wyr1c6-selector29")]
    #[must_use]
    pub fn write_wyr1c6_evidence_record(
        &self,
        index: usize,
        output: &mut [u8; wyr1c6_gate::RECORD_BYTES],
    ) -> Option<()> {
        self.wyr1c
            .as_ref()?
            .c6_evidence
            .as_ref()?
            .encode_record_at(index, output)
    }

    /// Advances the permanent fixed-role control loop without inventing service
    /// manager policy. A zero-time probe keeps idle ticks nonblocking; once a
    /// role signal is pending, the exact terminal protocol is drained under the
    /// bounded cleanup deadline before the generation-owned transition occurs.
    pub fn control_tick<S, L, W>(
        &mut self,
        system: &mut S,
        loader: &mut L,
        waits: &mut W,
        now_ns: u64,
    ) -> Result<SystemMode, InitError>
    where
        S: InitPlatform,
        L: LoaderPlatform<Error = NativeError>,
        W: SupervisionPlatform<Error = NativeError>,
    {
        if now_ns < self.last_tick_ns {
            self.controller.fatal();
            self.result = RecoveryResult::Fatal;
            return Err(InitError::WrongActivationOrder);
        }
        self.last_tick_ns = now_ns;

        for index in 0..self.active.len() {
            let Some(active) = self.active[index] else {
                continue;
            };
            let poll_items = [
                DwWaitItemV1 {
                    handle: active.loaded.launch_channel,
                    signals: deepwyrm_syscall::DwSignals(
                        DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0,
                    ),
                },
                DwWaitItemV1 {
                    handle: active.loaded.process,
                    signals: DW_SIGNAL_EXITED,
                },
            ];
            let observed = match waits.wait_many(&poll_items, DwDeadline(now_ns)) {
                Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => continue,
                Err(error) => Err(ObservedSupervisionError::Supervision(
                    SupervisionError::Platform(error),
                )),
                Ok(_) => {
                    let observation_deadline = now_ns
                        .checked_add(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns)
                        .ok_or(InitError::Restart(
                            RestartTransitionError::ArithmeticOverflow,
                        ))?;
                    supervise_ready_child_profile(
                        waits,
                        active.loaded.process,
                        active.loaded.launch_channel,
                        LaunchProfile::EarlyBootStub,
                        active.transaction_id,
                        DwDeadline(observation_deadline),
                    )
                }
            };

            let (transition, terminate) = match observed {
                Ok(info) => (
                    AfterReadyTransition::Terminal(terminal_disposition(&info)),
                    false,
                ),
                Err(error) => (
                    classify_after_ready_observation(&error),
                    !error.process_exit_observed(),
                ),
            };
            let transitioned = match transition {
                AfterReadyTransition::Terminal(disposition) => self.controller.terminal(
                    active.role,
                    active.generation,
                    active.transaction_id,
                    now_ns,
                    disposition,
                ),
                AfterReadyTransition::Failure(failure) => self.controller.fail(
                    active.role,
                    active.generation,
                    active.transaction_id,
                    now_ns,
                    failure,
                ),
            };
            if let Err(error) = transitioned {
                return Err(cleanup_after_transition_error(
                    system,
                    waits,
                    &mut self.controller,
                    active.loaded,
                    active.task_group,
                    active.role,
                    error,
                ));
            }
            complete_native_cleanup(
                system,
                waits,
                &mut self.controller,
                active.loaded,
                active.task_group,
                terminate,
                active.role,
                active.generation,
                active.transaction_id,
                now_ns,
            )?;
            self.active[index] = None;

            if transition == AfterReadyTransition::Terminal(TerminalDisposition::NormalExit(0)) {
                continue;
            }
            if advance_or_degrade(
                system,
                &mut self.controller,
                active.role,
                active.transaction_id,
            )? {
                self.result = RecoveryResult::Degraded;
                continue;
            }
            match remap_and_activate_role(
                system,
                loader,
                waits,
                self.authority,
                &mut self.controller,
                active.role,
            )? {
                RoleActivation::Ready(replacement) => self.active[index] = Some(replacement),
                RoleActivation::Degraded => self.result = RecoveryResult::Degraded,
            }
        }

        if self.controller.mode() == SystemMode::Degraded {
            self.result = RecoveryResult::Degraded;
        }
        if !self.evidence_finalized && self.active.iter().all(Option::is_none) {
            self.controller.finalize_evidence(self.result)?;
            self.evidence_finalized = true;
        }
        Ok(self.controller.mode())
    }

    /// Product-dispatched resident loop. Selector 25 immediately delegates to
    /// the unchanged legacy loop and therefore performs zero WYR1-B platform
    /// operations.
    #[inline(always)]
    pub fn control_tick_product<S, L, W>(
        &mut self,
        system: &mut S,
        loader: &mut L,
        waits: &mut W,
        now_ns: u64,
    ) -> Result<SystemMode, InitError>
    where
        S: Wyr1BPlatform,
        L: LoaderPlatform<Error = NativeError>,
        W: SupervisionPlatform<Error = NativeError>,
    {
        if self.wyr1c.is_some() {
            wyr1c_native::control_tick(self, system, loader, waits, now_ns)
        } else if self.wyr1b.is_none() {
            self.control_tick(system, loader, waits, now_ns)
        } else {
            wyr1b_native::control_tick(self, system, loader, waits, now_ns)
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct AttemptResources {
    pub role: RoleId,
    pub generation: u64,
    pub transaction_id: u64,
    pub executable_identity: [u8; 32],
    pub startup_profile: StartupProfile,
    pub task_group: DwHandle,
    pub process: DwHandle,
    pub launch_channel: DwHandle,
    pub mappings: u8,
    pub reservation: AttemptReservation,
}

/// Affine token proving one fixed-role generation was reserved before child
/// publication. It is intentionally neither `Copy` nor `Clone`.
#[derive(Debug, Eq, PartialEq)]
pub struct AttemptReservation {
    role: RoleId,
    generation: u64,
    transaction_id: u64,
    nonce: u64,
    published: bool,
    released: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReservationSlot {
    last_generation: u64,
    transaction_id: u64,
    nonce: u64,
    outstanding: bool,
    published: bool,
}

impl ReservationSlot {
    const EMPTY: Self = Self {
        last_generation: 0,
        transaction_id: 0,
        nonce: 0,
        outstanding: false,
        published: false,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AttemptLedger {
    slots: [ReservationSlot; EARLY_ROLE_COUNT],
    next_nonce: u64,
}

impl AttemptLedger {
    const fn new() -> Self {
        Self {
            slots: [ReservationSlot::EMPTY; EARLY_ROLE_COUNT],
            next_nonce: 1,
        }
    }

    fn reserve(
        &mut self,
        index: usize,
        role: RoleId,
        generation: u64,
        transaction_id: u64,
    ) -> Result<AttemptReservation, InitError> {
        let slot = &mut self.slots[index];
        if generation == 0 || transaction_id == 0 || slot.outstanding {
            return Err(InitError::Accounting);
        }
        if generation <= slot.last_generation || self.next_nonce == 0 {
            return Err(InitError::Accounting);
        }
        let nonce = self.next_nonce;
        self.next_nonce = self
            .next_nonce
            .checked_add(1)
            .ok_or(InitError::Accounting)?;
        *slot = ReservationSlot {
            last_generation: generation,
            transaction_id,
            nonce,
            outstanding: true,
            published: false,
        };
        Ok(AttemptReservation {
            role,
            generation,
            transaction_id,
            nonce,
            published: false,
            released: false,
        })
    }

    fn publish(&mut self, token: &mut AttemptReservation) -> Result<(), InitError> {
        let index = role_index(token.role)?;
        let slot = &mut self.slots[index];
        validate_reservation(slot, token)?;
        if token.published || slot.published {
            return Err(InitError::Accounting);
        }
        token.published = true;
        slot.published = true;
        Ok(())
    }

    fn release(&mut self, token: &mut AttemptReservation) -> Result<(), InitError> {
        let index = role_index(token.role)?;
        let slot = &mut self.slots[index];
        validate_reservation(slot, token)?;
        token.released = true;
        slot.outstanding = false;
        slot.published = false;
        slot.transaction_id = 0;
        slot.nonce = 0;
        Ok(())
    }

    const fn outstanding(&self) -> usize {
        self.slots[0].outstanding as usize + self.slots[1].outstanding as usize
    }
}

fn validate_reservation(
    slot: &ReservationSlot,
    token: &AttemptReservation,
) -> Result<(), InitError> {
    if token.released
        || !slot.outstanding
        || slot.last_generation != token.generation
        || slot.transaction_id != token.transaction_id
        || slot.nonce != token.nonce
    {
        Err(InitError::Accounting)
    } else {
        Ok(())
    }
}

fn role_index(role: RoleId) -> Result<usize, InitError> {
    match role {
        RoleId::Registryd => Ok(0),
        RoleId::Devmgr => Ok(1),
        _ => Err(InitError::UnlaunchableRole),
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum InitError {
    WrongManifestProfile,
    UnlaunchableRole,
    WrongActivationOrder,
    MissingAttemptResources,
    ResourcesAlreadyInstalled,
    ResourceIdentityMismatch,
    InvalidResourceHandle,
    Restart(RestartTransitionError),
    Bootfs(ParseError),
    MissingRetainedMaterial,
    NonExecutableRole,
    Manifest(ManifestParseError),
    ZeroBootGeneration,
    ArtifactIdentityMismatch(RoleId),
    Native(NativeError),
    Capability(CapabilityValidationError),
    Mapping(MappingPlanError),
    #[cfg(feature = "wyr1b-test-evidence")]
    StartupMapping(StartupMappingDiagnostic),
    #[cfg(feature = "wyr1b-test-evidence")]
    OrdinaryMapping(OrdinaryMappingDiagnostic),
    Launch(wyrmroot_loader::launch::LaunchError),
    Loader(LoadError<NativeError>),
    Supervision,
    Cleanup,
    Accounting,
    GateConfig(GateConfigError),
    Evidence(EvidenceError),
    Wyr1BGateConfig(wyr1b_gate::GateError),
    RegistryProtocol(wyrmroot_registry_proto::Error),
    Wyr1BGateProtocol(wyrmroot_wyr1b_gate_proto::Error),
    Wyr1BGateMismatch,
    Wyr1BModel(wyr1b::JobError),
    Wyr1BEvidence(wyr1b_gate::GateError),
    #[cfg(feature = "wyr1c6-selector29")]
    Wyr1C6GateConfig(wyr1c6_gate::GateError),
    #[cfg(feature = "wyr1e8-selector33")]
    E8Transition {
        operation: u8,
        initiating_kind: u8,
        emergency_cleanup: E8EmergencyCleanup,
    },
    #[cfg(feature = "r1-selector34")]
    R1Probe(R1ProbeFailure),
    #[cfg(feature = "r1-selector34")]
    R1Relay(r1_relay::RelayError),
}

impl From<RestartTransitionError> for InitError {
    fn from(value: RestartTransitionError) -> Self {
        Self::Restart(value)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct RoleController {
    role: RoleId,
    executable_identity: [u8; 32],
    restart: RestartSupervisor,
    resources: Option<AttemptResources>,
}

impl RoleController {
    fn new(role: RoleId, identity: [u8; 32]) -> Result<Self, InitError> {
        Ok(Self {
            role,
            executable_identity: identity,
            restart: RestartSupervisor::new(WYR0_I_SUPERVISION_POLICY)?,
            resources: None,
        })
    }

    #[cfg(feature = "wyr1e8-selector33")]
    fn admit_recovery(
        &mut self,
        accounting: &AttemptLedger,
        generation: u64,
        transaction: u64,
        now: u64,
    ) -> Result<(), InitError> {
        let resources = self
            .resources
            .as_ref()
            .ok_or(InitError::MissingAttemptResources)?;
        if resources.generation != generation {
            return Err(RestartTransitionError::StaleGeneration.into());
        }
        if resources.transaction_id != transaction {
            return Err(RestartTransitionError::TransactionMismatch.into());
        }
        let reservation = &resources.reservation;
        let slot = &accounting.slots[role_index(self.role)?];
        validate_reservation(slot, reservation)?;
        if resources.role != self.role
            || reservation.role != self.role
            || reservation.generation != generation
            || reservation.transaction_id != transaction
            || !reservation.published
            || !slot.published
        {
            return Err(InitError::Accounting);
        }
        self.restart
            .admit_recovery(generation, transaction, now, AttemptFailure::WaitFailed)?;
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct SystemInit {
    mode: SystemMode,
    roles: [RoleController; EARLY_ROLE_COUNT],
    degraded_transitions: u8,
    activated: [bool; EARLY_ROLE_COUNT],
    accounting: AttemptLedger,
    gate: Option<GateConfig>,
    evidence: Option<EvidenceLog>,
    registry_startup_profile: StartupProfile,
    devmgr_startup_profile: StartupProfile,
}

impl SystemInit {
    /// Consumes an already product-validated WRRM manifest and binds exact
    /// executable identities to the two WYR1-A launchable roles.
    pub fn from_manifest(manifest: Manifest<'_>) -> Result<Self, InitError> {
        Self::from_manifest_with_profiles(
            manifest,
            StartupProfile::EarlyBootStub,
            StartupProfile::EarlyBootStub,
            StartupProfile::Retained,
        )
    }

    pub(crate) fn from_wyr1b_manifest(manifest: Manifest<'_>) -> Result<Self, InitError> {
        Self::from_manifest_with_profiles(
            manifest,
            StartupProfile::BootstrapRegistry,
            StartupProfile::EarlyBootStub,
            StartupProfile::Retained,
        )
    }

    #[cfg_attr(
        all(feature = "wyr1e-production", not(test)),
        allow(
            dead_code,
            reason = "retained for explicit historical-profile isolation in the E6 binary build"
        )
    )]
    pub(crate) fn from_wyr1c_manifest(manifest: Manifest<'_>) -> Result<Self, InitError> {
        Self::from_manifest_with_profiles(
            manifest,
            StartupProfile::BootstrapRegistry,
            StartupProfile::DeviceCoordinator,
            StartupProfile::Retained,
        )
    }

    #[cfg(feature = "wyr1e-production")]
    pub(crate) fn from_wyr1e_manifest(manifest: Manifest<'_>) -> Result<Self, InitError> {
        Self::from_manifest_with_profiles(
            manifest,
            StartupProfile::BootstrapRegistry,
            StartupProfile::DeviceCoordinator,
            StartupProfile::Wyrmsh,
        )
    }

    fn from_manifest_with_profiles(
        manifest: Manifest<'_>,
        registry_startup_profile: StartupProfile,
        devmgr_startup_profile: StartupProfile,
        wyrmsh_startup_profile: StartupProfile,
    ) -> Result<Self, InitError> {
        if manifest.role_count() != 5 {
            return Err(InitError::WrongManifestProfile);
        }
        for ((expected, expected_path), role) in
            EXPECTED_ROLE_PATHS.into_iter().zip(manifest.roles())
        {
            let expected_shape = if expected == RoleId::Registryd {
                (Activation::Early, registry_startup_profile)
            } else if expected == RoleId::Devmgr {
                (Activation::Early, devmgr_startup_profile)
            } else if expected == RoleId::Uart16550d {
                (Activation::DeviceBound, StartupProfile::Retained)
            } else if expected == RoleId::Wyrmsh {
                (Activation::ConsoleBound, wyrmsh_startup_profile)
            } else {
                (Activation::ConsoleBound, StartupProfile::Retained)
            };
            if role.id() != expected
                || role.path() != expected_path
                || !role.required()
                || !role.requires_ready()
                || (role.activation(), role.startup_profile()) != expected_shape
            {
                return Err(InitError::WrongManifestProfile);
            }
        }
        let mut ready_edges = 0u8;
        for edge in manifest.edges() {
            if edge.kind() != DependencyKind::RoleReady {
                continue;
            }
            let bit = match (edge.owner(), edge.target_role()) {
                (RoleId::Devmgr, Some(RoleId::Registryd)) => 1,
                (RoleId::Uart16550d, Some(RoleId::Devmgr)) => 2,
                (RoleId::Consoled, Some(RoleId::Uart16550d)) => 4,
                (RoleId::Wyrmsh, Some(RoleId::Consoled)) => 8,
                _ => return Err(InitError::WrongManifestProfile),
            };
            if ready_edges & bit != 0 {
                return Err(InitError::WrongManifestProfile);
            }
            ready_edges |= bit;
        }
        if ready_edges != 0x0f {
            return Err(InitError::WrongManifestProfile);
        }
        let registry = manifest
            .role(RoleId::Registryd)
            .ok_or(InitError::WrongManifestProfile)?;
        let devmgr = manifest
            .role(RoleId::Devmgr)
            .ok_or(InitError::WrongManifestProfile)?;
        Ok(Self {
            mode: SystemMode::Bootstrap,
            roles: [
                RoleController::new(RoleId::Registryd, *registry.executable_identity())?,
                RoleController::new(RoleId::Devmgr, *devmgr.executable_identity())?,
            ],
            degraded_transitions: 0,
            activated: [false; EARLY_ROLE_COUNT],
            accounting: AttemptLedger::new(),
            gate: None,
            evidence: None,
            registry_startup_profile,
            devmgr_startup_profile,
        })
    }

    #[must_use]
    pub const fn mode(&self) -> SystemMode {
        self.mode
    }
    #[must_use]
    pub const fn result(&self) -> Option<RecoveryResult> {
        match self.mode {
            SystemMode::Normal => Some(RecoveryResult::Recovered),
            SystemMode::Degraded => Some(RecoveryResult::Degraded),
            SystemMode::Fatal => Some(RecoveryResult::Fatal),
            _ => None,
        }
    }
    #[must_use]
    pub const fn degraded_transitions(&self) -> u8 {
        self.degraded_transitions
    }
    #[must_use]
    pub fn role_state(&self, role: RoleId) -> Option<RestartState> {
        self.index(role).map(|i| self.roles[i].restart.state())
    }

    #[cfg(feature = "wyr1c6-selector29")]
    #[must_use]
    pub const fn c6_startup_profiles_exclude_direct_device_authority(&self) -> bool {
        matches!(
            self.registry_startup_profile,
            StartupProfile::BootstrapRegistry
        ) && matches!(
            self.devmgr_startup_profile,
            StartupProfile::DeviceCoordinator
        )
    }

    #[cfg(feature = "wyr1c6-selector29")]
    #[must_use]
    pub fn role_failure_count(&self, role: RoleId) -> Option<usize> {
        self.index(role)
            .map(|index| self.roles[index].restart.history().len())
    }
    #[must_use]
    pub fn resources(&self, role: RoleId) -> Option<&AttemptResources> {
        self.index(role)
            .and_then(|i| self.roles[i].resources.as_ref())
    }

    pub fn reserve_attempt(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
    ) -> Result<AttemptReservation, InitError> {
        let index = role_index(role)?;
        self.accounting
            .reserve(index, role, generation, transaction)
    }

    pub fn abort_reservation(
        &mut self,
        mut reservation: AttemptReservation,
    ) -> Result<(), InitError> {
        self.accounting.release(&mut reservation)
    }

    #[must_use]
    pub const fn outstanding_reservations(&self) -> usize {
        self.accounting.outstanding()
    }

    #[must_use]
    pub const fn gate_config(&self) -> Option<GateConfig> {
        self.gate
    }

    #[must_use]
    pub fn evidence_line(&self, index: usize) -> Option<&[u8]> {
        self.evidence
            .as_ref()?
            .line(index)
            .map(|line| line.as_slice())
    }

    /// Marks manifest/closure/controller initialization complete. This is the
    /// exact state acknowledged by the supervisor READY to primordial.
    pub fn become_operational(&mut self) -> Result<(), InitError> {
        if self.mode != SystemMode::Bootstrap {
            return Err(InitError::WrongActivationOrder);
        }
        self.mode = SystemMode::SupervisorOperational;
        Ok(())
    }

    pub fn begin_registry(
        &mut self,
        now: u64,
        generation: u64,
        transaction: u64,
    ) -> Result<(), InitError> {
        if self.mode != SystemMode::SupervisorOperational {
            return Err(InitError::WrongActivationOrder);
        }
        self.roles[0].restart.begin(now, generation, transaction)?;
        self.mode = SystemMode::ActivatingEarlyRoles;
        Ok(())
    }

    pub fn install_attempt(&mut self, mut resources: AttemptResources) -> Result<(), InitError> {
        let index = self
            .index(resources.role)
            .ok_or(InitError::UnlaunchableRole)?;
        if resources.task_group.0 == 0
            || resources.process.0 == 0
            || resources.launch_channel.0 == 0
        {
            self.accounting.release(&mut resources.reservation)?;
            return Err(InitError::InvalidResourceHandle);
        }
        let expected_profile = match resources.role {
            RoleId::Registryd => self.registry_startup_profile,
            RoleId::Devmgr => self.devmgr_startup_profile,
            _ => return Err(InitError::UnlaunchableRole),
        };
        if resources.startup_profile != expected_profile
            || resources.executable_identity != self.roles[index].executable_identity
        {
            self.accounting.release(&mut resources.reservation)?;
            return Err(InitError::ResourceIdentityMismatch);
        }
        let RestartState::Starting {
            generation,
            transaction_id,
            ..
        } = self.roles[index].restart.state()
        else {
            self.accounting.release(&mut resources.reservation)?;
            return Err(InitError::WrongActivationOrder);
        };
        if (generation, transaction_id) != (resources.generation, resources.transaction_id) {
            self.accounting.release(&mut resources.reservation)?;
            return Err(InitError::ResourceIdentityMismatch);
        }
        if self.roles[index].resources.is_some() {
            self.accounting.release(&mut resources.reservation)?;
            return Err(InitError::ResourcesAlreadyInstalled);
        }
        if resources.reservation.role != resources.role
            || resources.reservation.generation != resources.generation
            || resources.reservation.transaction_id != resources.transaction_id
        {
            self.accounting.release(&mut resources.reservation)?;
            return Err(InitError::Accounting);
        }
        self.roles[index].resources = Some(resources);
        Ok(())
    }

    pub fn child_started(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
        now: u64,
    ) -> Result<(), InitError> {
        let index = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        if self.roles[index].resources.is_none() {
            return Err(InitError::MissingAttemptResources);
        }
        self.roles[index]
            .restart
            .child_started(generation, transaction, now)?;
        let resources = self.roles[index]
            .resources
            .as_mut()
            .ok_or(InitError::MissingAttemptResources)?;
        self.accounting.publish(&mut resources.reservation)?;
        Ok(())
    }

    pub fn ready(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
        now: u64,
    ) -> Result<(), InitError> {
        let index = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        self.roles[index]
            .restart
            .ready(generation, transaction, now)?;
        self.record_evidence(EvidenceEvent::Ready, role, generation, transaction, 0)?;
        self.activated[index] = true;
        match role {
            RoleId::Registryd if !self.activated[1] => {
                if self.mode != SystemMode::ActivatingEarlyRoles
                    && self.mode != SystemMode::Degraded
                {
                    return Err(InitError::WrongActivationOrder);
                }
                match self.roles[1].restart.state() {
                    RestartState::Stopped => self.roles[1].restart.begin(
                        now,
                        generation,
                        next_transaction(transaction)?,
                    )?,
                    RestartState::PermanentFailure { .. } if self.mode == SystemMode::Degraded => {}
                    _ => return Err(InitError::WrongActivationOrder),
                }
            }
            RoleId::Registryd if self.activated[1] => self.mode = SystemMode::Normal,
            RoleId::Devmgr if self.activated[0] => self.mode = SystemMode::Normal,
            _ => {}
        }
        Ok(())
    }

    pub fn fail(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
        now: u64,
        failure: AttemptFailure,
    ) -> Result<(), InitError> {
        self.controller_mut(role)?
            .restart
            .fail_attempt(generation, transaction, now, failure)?;
        Ok(())
    }

    /// Starts one explicitly admitted post-stability recovery episode without
    /// releasing the exact published owner's resources or accounting token.
    #[cfg(feature = "wyr1e8-selector33")]
    pub(crate) fn admit_recovery(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
        now: u64,
    ) -> Result<(), InitError> {
        let index = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        self.roles[index].admit_recovery(&self.accounting, generation, transaction, now)
    }

    pub fn ready_wait_failed(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
        now: u64,
        failure: AttemptFailure,
    ) -> Result<(), InitError> {
        let controller = self.controller_mut(role)?;
        if let RestartState::AwaitingReady { deadline_ns, .. } = controller.restart.state()
            && now >= deadline_ns
        {
            controller
                .restart
                .deadline_elapsed(generation, transaction, deadline_ns, now)?;
            return Ok(());
        }
        controller
            .restart
            .fail_attempt(generation, transaction, now, failure)?;
        Ok(())
    }

    pub fn terminal(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
        now: u64,
        disposition: TerminalDisposition,
    ) -> Result<(), InitError> {
        self.controller_mut(role)?
            .restart
            .terminal(generation, transaction, now, disposition)?;
        if self.mode == SystemMode::Normal && disposition != TerminalDisposition::NormalExit(0) {
            self.mode = SystemMode::ActivatingEarlyRoles;
        }
        Ok(())
    }

    pub fn cleanup_complete(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
        now: u64,
    ) -> Result<(), InitError> {
        let index = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        let controller = &mut self.roles[index];
        let had_resources = controller.resources.is_some();
        let unpublished = matches!(
            controller.restart.state(),
            RestartState::CleaningUp {
                action: wyrmroot_runtime::CleanupAction::CloseUnpublished,
                ..
            }
        );
        if controller.resources.is_none() && !unpublished {
            return Err(InitError::MissingAttemptResources);
        }
        controller
            .restart
            .cleanup_complete(generation, transaction, now)?;
        if let Some(mut resources) = controller.resources.take() {
            self.accounting.release(&mut resources.reservation)?;
        }
        if had_resources {
            let value = self.roles[index]
                .restart
                .history()
                .as_slice()
                .last()
                .and_then(|record| *record)
                .map(|record| reap_evidence_value(record.failure))
                .ok_or(InitError::Accounting)?;
            self.record_evidence(EvidenceEvent::Reap, role, generation, transaction, value)?;
        }
        self.update_permanent_failure(role)?;
        Ok(())
    }

    pub fn cleanup_failed(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
        now: u64,
    ) -> Result<(), InitError> {
        let controller = self.controller_mut(role)?;
        controller
            .restart
            .cleanup_failed(generation, transaction, now)?;
        self.update_permanent_failure(role)?;
        Ok(())
    }

    /// Retires an exact active role after its ordinary transition into
    /// `CleaningUp` failed but the caller has already attempted native owner
    /// release. Complete cleanup releases the installed accounting reservation
    /// exactly once; failed cleanup remains retained and blocks replacement.
    pub fn retire_active_fail_closed(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
        now: u64,
        failure: AttemptFailure,
        cleanup: CleanupDisposition,
    ) -> Result<(), InitError> {
        let index = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        if self.roles[index].resources.is_none() {
            return Err(InitError::MissingAttemptResources);
        }
        self.roles[index].restart.retire_active_fail_closed(
            generation,
            transaction,
            now,
            failure,
            cleanup,
        )?;
        if cleanup == CleanupDisposition::Complete {
            let mut resources = self.roles[index]
                .resources
                .take()
                .ok_or(InitError::MissingAttemptResources)?;
            self.accounting.release(&mut resources.reservation)?;
            self.record_evidence(
                EvidenceEvent::Reap,
                role,
                generation,
                transaction,
                reap_evidence_value(failure),
            )?;
        }
        self.update_permanent_failure(role)?;
        Ok(())
    }

    pub fn start_replacement(
        &mut self,
        role: RoleId,
        now: u64,
        generation: u64,
        transaction: u64,
    ) -> Result<(), InitError> {
        let previous = self
            .index(role)
            .and_then(|index| self.roles[index].restart.history().as_slice().last())
            .and_then(|record| *record)
            .map(|record| (record.generation, record.transaction_id))
            .ok_or(InitError::Accounting)?;
        self.controller_mut(role)?
            .restart
            .start_replacement(now, generation, transaction)?;
        self.record_evidence(
            EvidenceEvent::Restart,
            role,
            previous.0,
            previous.1,
            generation,
        )?;
        self.update_permanent_failure(role)?;
        Ok(())
    }

    pub fn fatal(&mut self) {
        self.mode = SystemMode::Fatal;
    }

    fn retire_attempt_after_fatal(&mut self, role: RoleId) -> Result<(), InitError> {
        let index = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        if let Some(mut resources) = self.roles[index].resources.take() {
            self.accounting.release(&mut resources.reservation)?;
        }
        self.fatal();
        Ok(())
    }

    fn update_permanent_failure(&mut self, role: RoleId) -> Result<(), InitError> {
        if self
            .role_state(role)
            .is_some_and(|state| matches!(state, RestartState::PermanentFailure { .. }))
            && self.mode != SystemMode::Degraded
        {
            self.mode = SystemMode::Degraded;
            self.degraded_transitions = self.degraded_transitions.saturating_add(1);
            let identity = self
                .index(role)
                .and_then(|index| self.roles[index].restart.history().as_slice().last())
                .and_then(|record| *record)
                .map(|record| (record.generation, record.transaction_id));
            if let Some((last_generation, last_transaction_id)) = identity {
                self.record_evidence(
                    EvidenceEvent::PermanentFailure,
                    role,
                    last_generation,
                    last_transaction_id,
                    1,
                )?;
            }
        }
        Ok(())
    }
    fn record_evidence(
        &mut self,
        event: EvidenceEvent,
        role: RoleId,
        generation: u64,
        transaction: u64,
        value: u64,
    ) -> Result<(), InitError> {
        if let Some(evidence) = &mut self.evidence {
            evidence
                .record(event, role as u32, generation, transaction, value)
                .map_err(InitError::Evidence)?;
        }
        Ok(())
    }

    fn finalize_evidence(&mut self, result: RecoveryResult) -> Result<(), InitError> {
        if let Some(evidence) = &mut self.evidence {
            match result {
                RecoveryResult::Recovered | RecoveryResult::Degraded => {}
                RecoveryResult::Fatal => return Ok(()),
            }
            evidence
                .record(EvidenceEvent::Terminal, 0, 0, 0, 0)
                .map_err(InitError::Evidence)?;
        }
        Ok(())
    }
    fn index(&self, role: RoleId) -> Option<usize> {
        match role {
            RoleId::Registryd => Some(0),
            RoleId::Devmgr => Some(1),
            _ => None,
        }
    }
    fn controller_mut(&mut self, role: RoleId) -> Result<&mut RoleController, InitError> {
        let i = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        Ok(&mut self.roles[i])
    }

    fn executable_identity(&self, role: RoleId) -> Result<[u8; 32], InitError> {
        let index = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        Ok(self.roles[index].executable_identity)
    }
}

/// Validates the runtime half of the selected-generation trust boundary.
///
/// Build tooling externally authenticates the bootfs/manifest receipts. Init
/// has no fourth startup authority with which to re-authenticate those
/// receipts; it validates the retained bytes it actually received, including
/// canonical WRRM form, the fixed product graph, and every role artifact hash.
pub fn validate_retained_bootfs(bytes: &[u8]) -> Result<SystemInit, InitError> {
    let archive = Archive::new(bytes).map_err(InitError::Bootfs)?;
    let manifest_entry = archive
        .lookup(MANIFEST_PATH.as_bytes())
        .map_err(map_lookup)?;
    let manifest_bytes = manifest_entry.data();
    let encoded_generation: [u8; 32] = manifest_bytes
        .get(48..80)
        .ok_or(InitError::Manifest(ManifestParseError::TruncatedHeader))?
        .try_into()
        .expect("checked WRRM generation slice");
    if encoded_generation == [0; 32] {
        return Err(InitError::ZeroBootGeneration);
    }
    let manifest = Manifest::parse_structural(manifest_bytes, &encoded_generation)
        .map_err(InitError::Manifest)?;
    let mut controller = SystemInit::from_manifest(manifest)?;
    for role in manifest.roles() {
        let entry = archive.lookup(role.path().as_bytes()).map_err(map_lookup)?;
        if !entry.is_executable() || entry.data().is_empty() {
            return Err(InitError::NonExecutableRole);
        }
        if wyrmroot_runtime::sha256::digest(entry.data()) != *role.executable_identity() {
            return Err(InitError::ArtifactIdentityMismatch(role.id()));
        }
    }
    // Init itself and all declared immutable dependencies must resolve from
    // the same retained archive. Their expected identities remain bound by
    // the external selected-generation receipt; hashing them again here would
    // produce an unauthenticated value with no independent comparison source.
    let init = archive
        .lookup(SYSTEM_INIT_PATH.as_bytes())
        .map_err(map_lookup)?;
    if !init.is_executable() || init.data().is_empty() {
        return Err(InitError::NonExecutableRole);
    }
    for edge in manifest.edges() {
        if let Some(path) = edge.target_path() {
            archive.lookup(path.as_bytes()).map_err(map_lookup)?;
        }
    }
    controller.gate = match archive.lookup(GATE_CONFIG_PATH.as_bytes()) {
        Ok(entry) => Some(parse_gate_config(entry.data()).map_err(InitError::GateConfig)?),
        Err(LookupError::NotFound) => None,
        Err(error) => return Err(map_lookup(error)),
    };
    controller.evidence = controller
        .gate
        .map(|config| EvidenceLog::new(config.nonce, config.scenario))
        .transpose()
        .map_err(InitError::Evidence)?;
    Ok(controller)
}

fn map_lookup(_: LookupError) -> InitError {
    InitError::MissingRetainedMaterial
}

/// Native operations owned by permanent init in addition to the reusable
/// loader and readiness platform boundaries.
pub trait InitPlatform {
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
    fn query_memory_object_size(&mut self, handle: DwHandle) -> Result<u64, NativeError>;
    fn with_bootfs_bytes<R>(
        &mut self,
        root: DwHandle,
        bootfs: DwHandle,
        plan: MappingPlan,
        use_bytes: impl for<'a> FnOnce(&mut Self, &'a [u8]) -> R,
    ) -> Result<R, NativeError>;
    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError>;
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError>;
    fn create_attempt_task_group(&mut self, parent: DwHandle) -> Result<DwHandle, NativeError>;
    fn terminate_task_group(&mut self, task_group: DwHandle) -> Result<(), NativeError>;
    fn now(&mut self) -> Result<u64, NativeError>;
    fn wait_until(&mut self, deadline_ns: u64) -> Result<(), NativeError>;
}

/// Accepts a timer signal or its finite wait timeout only after the active
/// monotonic clock proves the requested deadline has elapsed. The timeout is
/// a valid fallback wake for delay-only restart backoff; an early signal or
/// early timeout remains a malformed wait result.
pub fn validate_wait_until_completion(
    deadline_ns: u64,
    observed_now: u64,
    wait_result: Result<(), NativeError>,
) -> Result<(), NativeError> {
    match wait_result {
        Ok(()) => {
            if observed_now >= deadline_ns {
                Ok(())
            } else {
                Err(NativeError::Output(
                    wyrmroot_runtime::NativeOutputError::InvalidWaitResult,
                ))
            }
        }
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
            if observed_now >= deadline_ns {
                Ok(())
            } else {
                Err(NativeError::Output(
                    wyrmroot_runtime::NativeOutputError::InvalidWaitResult,
                ))
            }
        }
        Err(error) => Err(error),
    }
}

/// Selector-27-only native operations used by the WYR1-B controller.
///
/// The permanent selector-25 path remains bounded by [`InitPlatform`], so it
/// cannot create or transfer the additional registry service Channels.
pub trait Wyr1BPlatform: InitPlatform {
    fn channel_create(&mut self, rights: DwRights) -> Result<(DwHandle, DwHandle), NativeError>;
    fn send_channel_with_handles(
        &mut self,
        channel: DwHandle,
        bytes: &[u8],
        transfers: &[DwHandleTransferV1],
    ) -> Result<(), NativeError>;
    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, NativeError>;
    /// Creates one unpublished, immutable manifest object with the exact
    /// caller-requested staging rights. The native implementation confines
    /// its writable mapping to the runtime boundary; the loader separately
    /// reduces sender-only transfer authority at the child boundary.
    fn materialize_read_only_memory(
        &mut self,
        root: DwHandle,
        bytes: &[u8],
        rights: DwRights,
    ) -> Result<DwHandle, NativeError>;

    /// Sends one observer-only WRE1 record to the selector-33 kernel relay.
    #[cfg(feature = "wyr1e-selector33")]
    fn submit_wyr1e7_evidence(&mut self, _record: &[u8; 192]) -> Result<(), NativeError> {
        #[cfg(test)]
        return Ok(());
        #[cfg(not(test))]
        Err(NativeError::Output(
            wyrmroot_runtime::NativeOutputError::InvalidWaitResult,
        ))
    }

    /// Sends one observer-only WRE1 v1.1 record to the selector-33 relay.
    #[cfg(feature = "wyr1e8-selector33")]
    fn submit_wyr1e8_evidence(&mut self, _record: &[u8; 192]) -> Result<(), NativeError> {
        #[cfg(test)]
        return Ok(());
        #[cfg(not(test))]
        Err(NativeError::Output(
            wyrmroot_runtime::NativeOutputError::InvalidWaitResult,
        ))
    }
}

/// Runs the native selected-generation activation through NORMAL or DEGRADED.
/// The caller remains alive afterward as the permanent supervisor loop.
pub fn run_system_init<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootstrap_channel: DwHandle,
) -> Result<ResidentSystemInit, InitError>
where
    S: InitPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let (authority, activation) = receive_and_activate(
        system,
        bootstrap_channel,
        |system, authority, transaction_id, bootfs| {
            activate_retained_bootfs(
                system,
                loader,
                waits,
                authority,
                bootstrap_channel,
                transaction_id,
                bootfs,
            )
        },
    )?;
    Ok(ResidentSystemInit {
        controller: activation.controller,
        authority,
        result: activation.result,
        active: activation.active,
        evidence_finalized: false,
        last_tick_ns: system.now().map_err(InitError::Native)?,
        wyr1b: None,
        wyr1b_evidence: None,
        wyr1c: None,
    })
}

/// Selects the immutable product path, constructs one resident in place, and
/// transfers control without returning or copying the resident value.
/// Selector 25 remains the exact legacy path; only a canonical selector-27
/// gate admits the WYR1-B platform extension.
pub fn continue_system_init_product<S, L, W, R>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootstrap_channel: DwHandle,
    continuation: impl FnOnce(&mut ResidentSystemInit, &mut S, &mut L, &mut W) -> R,
) -> Result<R, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut slot = MaybeUninit::uninit();
    let resident =
        receive_and_activate_product_in_place(system, loader, waits, bootstrap_channel, &mut slot)?;
    resident.last_tick_ns = system.now().map_err(InitError::Native)?;
    Ok(continuation(resident, system, loader, waits))
}

/// Selects only the WYR1-C4 WRLP 1.7 four-capability supervisor product.
/// Historical product entry points remain exact three-capability WRLP 1.2.
pub fn continue_system_init_resource_product<S, L, W, R>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootstrap_channel: DwHandle,
    continuation: impl FnOnce(&mut ResidentSystemInit, &mut S, &mut L, &mut W) -> R,
) -> Result<R, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut slot = MaybeUninit::uninit();
    let resident = receive_and_activate_resource_product_in_place(
        system,
        loader,
        waits,
        bootstrap_channel,
        &mut slot,
    )?;
    resident.last_tick_ns = system.now().map_err(InitError::Native)?;
    Ok(continuation(resident, system, loader, waits))
}

fn receive_and_activate_resource_product_in_place<'a, S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootstrap_channel: DwHandle,
    slot: &'a mut MaybeUninit<ResidentSystemInit>,
) -> Result<&'a mut ResidentSystemInit, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let channel = system
        .query_capability_info(bootstrap_channel)
        .map_err(InitError::Native)?;
    validate_bootstrap_channel(channel, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(InitError::Capability)?;
    let mut init_bytes = [0; SUPERVISOR_BYTES + 8];
    let mut handles = [DwReceivedHandleInfoV1::default(); 4];
    let counts = system
        .receive_channel(bootstrap_channel, &mut init_bytes, &mut handles)
        .map_err(InitError::Native)?;
    if counts
        != (ReceiveCounts {
            bytes: init_bytes.len(),
            handles: handles.len(),
        })
    {
        let error = InitError::Launch(wyrmroot_loader::launch::LaunchError::HandleCount);
        close_malformed_startup(system, &handles, counts.handles, bootstrap_channel)?;
        return Err(error);
    }
    let startup = activate_received_resource_product_in_place(
        system,
        loader,
        waits,
        slot,
        bootstrap_channel,
        &init_bytes,
        &handles,
    );
    let resident = match startup {
        Ok(value) => value,
        Err(error) => {
            close_startup_failure(system, &handles, bootstrap_channel)?;
            return Err(error);
        }
    };
    system
        .close_handle(bootstrap_channel)
        .map_err(InitError::Native)?;
    Ok(resident)
}

#[allow(clippy::too_many_arguments)]
fn activate_received_resource_product_in_place<'a, S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    slot: &'a mut MaybeUninit<ResidentSystemInit>,
    bootstrap_channel: DwHandle,
    init_bytes: &[u8; SUPERVISOR_BYTES + 8],
    handles: &[DwReceivedHandleInfoV1; 4],
) -> Result<&'a mut ResidentSystemInit, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let parsed = parse_init(LaunchProfile::SupervisorResourceDomain, init_bytes, handles)
        .map_err(InitError::Launch)?;
    let capabilities = [
        fresh_capability(system, handles[0])?,
        fresh_capability(system, handles[1])?,
        fresh_capability(system, handles[2])?,
        fresh_capability(system, handles[3])?,
    ];
    validate_init_capabilities_v3(
        &capabilities,
        SELF_ROOT_EXPECTATION,
        BOOTFS_EXPECTATION,
        LOADER_TASK_GROUP_EXPECTATION,
        RESOURCE_DOMAIN_TASK_GROUP_EXPECTATION,
    )
    .map_err(InitError::Capability)?;
    let authority = LoadAuthority {
        parent_root: handles[0].handle,
        bootfs: handles[1].handle,
        task_group: handles[2].handle,
    };
    let custody = ResourceDomainCustody::new(handles[3].handle);
    let size = system
        .query_memory_object_size(authority.bootfs)
        .map_err(InitError::Native)?;
    let plan = MappingPlan::for_bootfs(size).map_err(|error| startup_mapping_error(error, size))?;
    system
        .with_bootfs_bytes(
            authority.parent_root,
            authority.bootfs,
            plan,
            |system, bootfs| {
                let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
                let marker = archive
                    .lookup(wyr1c_native::MARKER_PATH.as_bytes())
                    .map_err(map_lookup)?;
                if marker.data() != wyr1c_native::MARKER_BYTES {
                    return Err(InitError::WrongManifestProfile);
                }
                wyr1c_native::activate_in_place(
                    system,
                    loader,
                    waits,
                    slot,
                    authority,
                    Some(custody),
                    LaunchProfile::SupervisorResourceDomain,
                    bootstrap_channel,
                    parsed.transaction_id,
                    bootfs,
                )
            },
        )
        .map_err(InitError::Native)?
}

fn receive_and_activate_product_in_place<'a, S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    bootstrap_channel: DwHandle,
    slot: &'a mut MaybeUninit<ResidentSystemInit>,
) -> Result<&'a mut ResidentSystemInit, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let channel = system
        .query_capability_info(bootstrap_channel)
        .map_err(InitError::Native)?;
    validate_bootstrap_channel(channel, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(InitError::Capability)?;
    let mut init_bytes = [0; SUPERVISOR_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 3];
    let counts = system
        .receive_channel(bootstrap_channel, &mut init_bytes, &mut handles)
        .map_err(InitError::Native)?;
    if counts
        != (ReceiveCounts {
            bytes: SUPERVISOR_BYTES,
            handles: 3,
        })
    {
        let error = InitError::Launch(wyrmroot_loader::launch::LaunchError::HandleCount);
        close_malformed_startup(system, &handles, counts.handles, bootstrap_channel)?;
        return Err(error);
    }
    let startup = activate_received_product_in_place(
        system,
        loader,
        waits,
        slot,
        bootstrap_channel,
        &init_bytes,
        &handles,
    );
    let resident = match startup {
        Ok(value) => value,
        Err(error) => {
            close_startup_failure(system, &handles, bootstrap_channel)?;
            return Err(error);
        }
    };
    system
        .close_handle(bootstrap_channel)
        .map_err(InitError::Native)?;
    Ok(resident)
}

#[allow(clippy::too_many_arguments)]
fn activate_received_product_in_place<'a, S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    slot: &'a mut MaybeUninit<ResidentSystemInit>,
    bootstrap_channel: DwHandle,
    init_bytes: &[u8; SUPERVISOR_BYTES],
    handles: &[DwReceivedHandleInfoV1; 3],
) -> Result<&'a mut ResidentSystemInit, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let parsed =
        parse_init(LaunchProfile::Supervisor, init_bytes, handles).map_err(InitError::Launch)?;
    let capabilities = [
        fresh_capability(system, handles[0])?,
        fresh_capability(system, handles[1])?,
        fresh_capability(system, handles[2])?,
    ];
    validate_init_capabilities_v2(
        &capabilities,
        SELF_ROOT_EXPECTATION,
        BOOTFS_EXPECTATION,
        LOADER_TASK_GROUP_EXPECTATION,
    )
    .map_err(InitError::Capability)?;
    let authority = LoadAuthority {
        parent_root: handles[0].handle,
        bootfs: handles[1].handle,
        task_group: handles[2].handle,
    };
    let size = system
        .query_memory_object_size(authority.bootfs)
        .map_err(InitError::Native)?;
    let plan = MappingPlan::for_bootfs(size).map_err(|error| startup_mapping_error(error, size))?;
    system
        .with_bootfs_bytes(
            authority.parent_root,
            authority.bootfs,
            plan,
            |system, bootfs| {
                let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
                match archive.lookup(wyr1c_native::MARKER_PATH.as_bytes()) {
                    Ok(marker) if marker.data() == wyr1c_native::MARKER_BYTES => {
                        wyr1c_native::activate_in_place(
                            system,
                            loader,
                            waits,
                            slot,
                            authority,
                            None,
                            LaunchProfile::Supervisor,
                            bootstrap_channel,
                            parsed.transaction_id,
                            bootfs,
                        )
                    }
                    Ok(_) => Err(InitError::WrongManifestProfile),
                    Err(LookupError::NotFound) => {
                        match archive.lookup(wyr1b_gate::GATE_PATH.as_bytes()) {
                            Ok(_) => wyr1b_native::activate_in_place(
                                system,
                                loader,
                                waits,
                                slot,
                                authority,
                                bootstrap_channel,
                                parsed.transaction_id,
                                bootfs,
                            ),
                            Err(LookupError::NotFound) => activate_retained_bootfs_in_place(
                                system,
                                loader,
                                waits,
                                slot,
                                authority,
                                bootstrap_channel,
                                parsed.transaction_id,
                                bootfs,
                            ),
                            Err(error) => Err(map_lookup(error)),
                        }
                    }
                    Err(error) => Err(map_lookup(error)),
                }
            },
        )
        .map_err(InitError::Native)?
}

fn receive_and_activate<S, T>(
    system: &mut S,
    bootstrap_channel: DwHandle,
    activate: impl FnOnce(&mut S, LoadAuthority, u64, &[u8]) -> Result<T, InitError>,
) -> Result<(LoadAuthority, T), InitError>
where
    S: InitPlatform,
{
    let channel = system
        .query_capability_info(bootstrap_channel)
        .map_err(InitError::Native)?;
    validate_bootstrap_channel(channel, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(InitError::Capability)?;
    let mut init_bytes = [0; SUPERVISOR_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 3];
    let counts = system
        .receive_channel(bootstrap_channel, &mut init_bytes, &mut handles)
        .map_err(InitError::Native)?;
    if counts
        != (ReceiveCounts {
            bytes: SUPERVISOR_BYTES,
            handles: 3,
        })
    {
        let error = InitError::Launch(wyrmroot_loader::launch::LaunchError::HandleCount);
        close_malformed_startup(system, &handles, counts.handles, bootstrap_channel)?;
        return Err(error);
    }
    let startup = (|| {
        let parsed = parse_init(LaunchProfile::Supervisor, &init_bytes, &handles)
            .map_err(InitError::Launch)?;
        let capabilities = [
            fresh_capability(system, handles[0])?,
            fresh_capability(system, handles[1])?,
            fresh_capability(system, handles[2])?,
        ];
        validate_init_capabilities_v2(
            &capabilities,
            SELF_ROOT_EXPECTATION,
            BOOTFS_EXPECTATION,
            LOADER_TASK_GROUP_EXPECTATION,
        )
        .map_err(InitError::Capability)?;
        let authority = LoadAuthority {
            parent_root: handles[0].handle,
            bootfs: handles[1].handle,
            task_group: handles[2].handle,
        };
        let size = system
            .query_memory_object_size(authority.bootfs)
            .map_err(InitError::Native)?;
        let plan =
            MappingPlan::for_bootfs(size).map_err(|error| startup_mapping_error(error, size))?;
        let activation = system
            .with_bootfs_bytes(
                authority.parent_root,
                authority.bootfs,
                plan,
                |system, bootfs| activate(system, authority, parsed.transaction_id, bootfs),
            )
            .map_err(InitError::Native)??;
        Ok::<_, InitError>((authority, activation))
    })();
    let (authority, activation) = match startup {
        Ok(value) => value,
        Err(error) => {
            close_startup_failure(system, &handles, bootstrap_channel)?;
            return Err(error);
        }
    };
    system
        .close_handle(bootstrap_channel)
        .map_err(InitError::Native)?;
    Ok((authority, activation))
}

fn startup_mapping_error(error: MappingPlanError, size: u64) -> InitError {
    #[cfg(feature = "wyr1b-test-evidence")]
    {
        InitError::StartupMapping(StartupMappingDiagnostic {
            error,
            size_class: startup_bootfs_size_class(size),
        })
    }
    #[cfg(not(feature = "wyr1b-test-evidence"))]
    {
        let _ = size;
        InitError::Mapping(error)
    }
}

pub(crate) fn ordinary_mapping_error(
    site: MappingDiagnosticSite,
    error: MappingPlanError,
    size: u64,
) -> InitError {
    #[cfg(feature = "wyr1b-test-evidence")]
    {
        InitError::OrdinaryMapping(OrdinaryMappingDiagnostic {
            site,
            error,
            size_class: startup_bootfs_size_class(size),
        })
    }
    #[cfg(not(feature = "wyr1b-test-evidence"))]
    {
        let _ = (site, size);
        InitError::Mapping(error)
    }
}

fn close_startup_failure<S: InitPlatform>(
    system: &mut S,
    handles: &[DwReceivedHandleInfoV1],
    bootstrap_channel: DwHandle,
) -> Result<(), InitError> {
    let mut failed = false;
    for handle in handles {
        if handle.handle.0 != 0 {
            failed |= system.close_handle(handle.handle).is_err();
        }
    }
    failed |= system.close_handle(bootstrap_channel).is_err();
    if failed {
        Err(InitError::Cleanup)
    } else {
        Ok(())
    }
}

fn close_malformed_startup<S: InitPlatform>(
    system: &mut S,
    handles: &[DwReceivedHandleInfoV1],
    reported_handles: usize,
    bootstrap_channel: DwHandle,
) -> Result<(), InitError> {
    let initialized = core::cmp::min(reported_handles, handles.len());
    close_startup_failure(system, &handles[..initialized], bootstrap_channel)
}

fn activate_retained_bootfs<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootstrap_channel: DwHandle,
    parent_transaction: u64,
    bootfs: &[u8],
) -> Result<ActivationState, InitError>
where
    S: InitPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut controller = validate_retained_bootfs(bootfs)?;
    let mut active = [None; EARLY_ROLE_COUNT];
    let result = activate_retained_bootfs_state(
        system,
        loader,
        waits,
        authority,
        bootstrap_channel,
        parent_transaction,
        bootfs,
        &mut controller,
        &mut active,
    )?;
    Ok(ActivationState {
        controller,
        result,
        active,
    })
}

#[allow(clippy::too_many_arguments)]
fn activate_retained_bootfs_in_place<'a, S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    slot: &'a mut MaybeUninit<ResidentSystemInit>,
    authority: LoadAuthority,
    bootstrap_channel: DwHandle,
    parent_transaction: u64,
    bootfs: &[u8],
) -> Result<&'a mut ResidentSystemInit, InitError>
where
    S: InitPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let controller = validate_retained_bootfs(bootfs)?;
    let resident = slot.write(ResidentSystemInit {
        controller,
        authority,
        result: RecoveryResult::Degraded,
        active: [None; EARLY_ROLE_COUNT],
        evidence_finalized: false,
        last_tick_ns: 0,
        wyr1b: None,
        wyr1b_evidence: None,
        wyr1c: None,
    });
    resident.result = activate_retained_bootfs_state(
        system,
        loader,
        waits,
        authority,
        bootstrap_channel,
        parent_transaction,
        bootfs,
        &mut resident.controller,
        &mut resident.active,
    )?;
    Ok(resident)
}

#[allow(clippy::too_many_arguments)]
fn activate_retained_bootfs_state<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootstrap_channel: DwHandle,
    parent_transaction: u64,
    bootfs: &[u8],
    controller: &mut SystemInit,
    active: &mut [Option<ActiveNativeRole>; EARLY_ROLE_COUNT],
) -> Result<RecoveryResult, InitError>
where
    S: InitPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    controller.become_operational()?;
    let mut ready = [0; HEADER_BYTES];
    let ready_len =
        encode_ready_for_profile(LaunchProfile::Supervisor, parent_transaction, &mut ready)
            .map_err(InitError::Launch)?;
    system
        .send_channel(bootstrap_channel, &ready[..ready_len])
        .map_err(InitError::Native)?;
    let retire_now = system.now().map_err(InitError::Native)?;
    let retire_deadline = retire_now
        .checked_add(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns)
        .ok_or(InitError::Restart(
            RestartTransitionError::ArithmeticOverflow,
        ))?;
    let retire_item = DwWaitItemV1 {
        handle: bootstrap_channel,
        signals: DW_SIGNAL_PEER_CLOSED,
    };
    let retired = waits
        .wait_many(
            core::slice::from_ref(&retire_item),
            DwDeadline(retire_deadline),
        )
        .map_err(|_| InitError::Supervision)?;
    if retired.index != 0 || retired.observed.0 & DW_SIGNAL_PEER_CLOSED.0 == 0 {
        return Err(InitError::Supervision);
    }
    let now = system.now().map_err(InitError::Native)?;
    controller.begin_registry(now, 1, 0x1001)?;
    for role in [RoleId::Registryd, RoleId::Devmgr] {
        match activate_role_until_ready(system, controller, loader, waits, authority, bootfs, role)?
        {
            RoleActivation::Ready(attempt) => active[role_index(role)?] = Some(attempt),
            RoleActivation::Degraded => return Ok(RecoveryResult::Degraded),
        }
    }
    Ok(RecoveryResult::Recovered)
}

fn remap_and_activate_role<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    controller: &mut SystemInit,
    role: RoleId,
) -> Result<RoleActivation, InitError>
where
    S: InitPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let size = system
        .query_memory_object_size(authority.bootfs)
        .map_err(InitError::Native)?;
    let plan = MappingPlan::for_bootfs(size)
        .map_err(|error| ordinary_mapping_error(MappingDiagnosticSite::RoleRemap, error, size))?;
    system
        .with_bootfs_bytes(
            authority.parent_root,
            authority.bootfs,
            plan,
            |system, bootfs| {
                activate_role_until_ready(
                    system, controller, loader, waits, authority, bootfs, role,
                )
            },
        )
        .map_err(InitError::Native)?
}

#[allow(clippy::too_many_arguments)]
fn activate_role_until_ready<S, L, W>(
    system: &mut S,
    controller: &mut SystemInit,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootfs: &[u8],
    role: RoleId,
) -> Result<RoleActivation, InitError>
where
    S: InitPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    loop {
        let RestartState::Starting {
            generation,
            transaction_id,
            ..
        } = controller
            .role_state(role)
            .ok_or(InitError::WrongActivationOrder)?
        else {
            return Err(InitError::WrongActivationOrder);
        };
        let executable_identity = controller.executable_identity(role)?;
        let task_group = system
            .create_attempt_task_group(authority.task_group)
            .map_err(InitError::Native)?;
        let reservation = controller.reserve_attempt(role, generation, transaction_id)?;
        let role_authority = LoadAuthority {
            task_group,
            ..authority
        };
        let loaded = match load_role(
            loader,
            role_authority,
            bootfs,
            role,
            executable_identity,
            transaction_id,
        ) {
            Ok(value) => value,
            Err(error) => {
                let now = match system.now().map_err(InitError::Native) {
                    Ok(now) => now,
                    Err(clock_error) => {
                        let close_failed = system.close_handle(task_group).is_err();
                        let release_failed = controller.abort_reservation(reservation).is_err();
                        controller.fatal();
                        return Err(if close_failed || release_failed {
                            InitError::Cleanup
                        } else {
                            clock_error
                        });
                    }
                };
                if let Err(transition_error) = controller.fail(
                    role,
                    generation,
                    transaction_id,
                    now,
                    AttemptFailure::CreationFailed,
                ) {
                    let close_failed = system.close_handle(task_group).is_err();
                    let release_failed = controller.abort_reservation(reservation).is_err();
                    controller.fatal();
                    return Err(if close_failed || release_failed {
                        InitError::Cleanup
                    } else {
                        transition_error
                    });
                }
                let rollback_failed = matches!(
                    error,
                    InitError::Loader(LoadError::Platform {
                        rollback_failed: true,
                        ..
                    })
                );
                let close_failed = system.close_handle(task_group).is_err();
                if rollback_failed || close_failed {
                    let retired_at = now.checked_add(1).ok_or(InitError::Accounting)?;
                    controller.cleanup_failed(role, generation, transaction_id, retired_at)?;
                    controller.fatal();
                    return Err(error);
                }
                controller.abort_reservation(reservation)?;
                let retired_at = now.checked_add(1).ok_or(InitError::Accounting)?;
                controller.cleanup_complete(role, generation, transaction_id, retired_at)?;
                if advance_or_degrade(system, controller, role, transaction_id)? {
                    return Ok(RoleActivation::Degraded);
                }
                continue;
            }
        };
        let install = controller.install_attempt(AttemptResources {
            role,
            generation,
            transaction_id,
            executable_identity,
            startup_profile: StartupProfile::EarlyBootStub,
            task_group,
            process: loaded.process,
            launch_channel: loaded.launch_channel,
            mappings: 0,
            reservation,
        });
        if let Err(error) = install {
            controller.fatal();
            return match cleanup_loaded(system, waits, loaded, task_group, true) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(cleanup),
            };
        }
        let now = match system.now().map_err(InitError::Native) {
            Ok(now) => now,
            Err(error) => {
                return Err(cleanup_after_transition_error(
                    system, waits, controller, loaded, task_group, role, error,
                ));
            }
        };
        if let Err(error) = controller.child_started(role, generation, transaction_id, now) {
            return Err(cleanup_after_transition_error(
                system, waits, controller, loaded, task_group, role, error,
            ));
        }
        let deadline = match now.checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns) {
            Some(deadline) => DwDeadline(deadline),
            None => {
                return Err(cleanup_after_transition_error(
                    system,
                    waits,
                    controller,
                    loaded,
                    task_group,
                    role,
                    InitError::Restart(RestartTransitionError::ArithmeticOverflow),
                ));
            }
        };
        match await_child_ready_profile_observed(
            waits,
            loaded.process,
            loaded.launch_channel,
            LaunchProfile::EarlyBootStub,
            transaction_id,
            deadline,
        ) {
            Ok(()) => {
                let now = match system.now().map_err(InitError::Native) {
                    Ok(now) => now,
                    Err(error) => {
                        return Err(cleanup_after_transition_error(
                            system, waits, controller, loaded, task_group, role, error,
                        ));
                    }
                };
                if let Err(error) = controller.ready(role, generation, transaction_id, now) {
                    return Err(cleanup_after_transition_error(
                        system, waits, controller, loaded, task_group, role, error,
                    ));
                }
                return Ok(RoleActivation::Ready(ActiveNativeRole {
                    role,
                    generation,
                    transaction_id,
                    loaded,
                    task_group,
                }));
            }
            Err(error) => {
                let observed_transition = classify_after_ready_observation(&error);
                let now = match system.now().map_err(InitError::Native) {
                    Ok(now) => now,
                    Err(clock_error) => {
                        return Err(cleanup_after_transition_error(
                            system,
                            waits,
                            controller,
                            loaded,
                            task_group,
                            role,
                            clock_error,
                        ));
                    }
                };
                let transition = match observed_transition {
                    AfterReadyTransition::Terminal(disposition) => {
                        controller.terminal(role, generation, transaction_id, now, disposition)
                    }
                    AfterReadyTransition::Failure(failure) => {
                        controller.ready_wait_failed(role, generation, transaction_id, now, failure)
                    }
                };
                if let Err(transition_error) = transition {
                    return Err(cleanup_after_transition_error(
                        system,
                        waits,
                        controller,
                        loaded,
                        task_group,
                        role,
                        transition_error,
                    ));
                }
                complete_native_cleanup(
                    system,
                    waits,
                    controller,
                    loaded,
                    task_group,
                    !error.process_exit_observed(),
                    role,
                    generation,
                    transaction_id,
                    now,
                )?;
                if advance_or_degrade(system, controller, role, transaction_id)? {
                    return Ok(RoleActivation::Degraded);
                }
            }
        }
    }
}

fn fresh_capability<S: InitPlatform>(
    system: &mut S,
    info: DwReceivedHandleInfoV1,
) -> Result<InitCapability<DwObjectType, DwRights>, InitError> {
    Ok(InitCapability {
        received: CapabilityInfo {
            object_type: info.object_type,
            rights: info.rights,
        },
        fresh: system
            .query_capability_info(info.handle)
            .map_err(InitError::Native)?,
    })
}
fn load_role<L: LoaderPlatform<Error = NativeError>>(
    loader: &mut L,
    authority: LoadAuthority,
    bytes: &[u8],
    role: RoleId,
    expected_identity: [u8; 32],
    transaction_id: u64,
) -> Result<LoadedProcess, InitError> {
    let archive = Archive::new(bytes).map_err(InitError::Bootfs)?;
    let path = match role {
        RoleId::Registryd => "system/registryd",
        RoleId::Devmgr => "system/devmgr",
        _ => return Err(InitError::UnlaunchableRole),
    };
    let e = archive.lookup(path.as_bytes()).map_err(map_lookup)?;
    if wyrmroot_runtime::sha256::digest(e.data()) != expected_identity {
        return Err(InitError::ArtifactIdentityMismatch(role));
    }
    load_process(
        loader,
        authority,
        LoadRequest {
            image: e.data(),
            display_path: path,
            profile: LaunchProfile::EarlyBootStub,
            transaction_id,
        },
    )
    .map_err(InitError::Loader)
}
pub(crate) fn cleanup_loaded<S: InitPlatform, W: SupervisionPlatform<Error = NativeError>>(
    system: &mut S,
    waits: &mut W,
    loaded: LoadedProcess,
    task_group: DwHandle,
    terminate: bool,
) -> Result<(), InitError> {
    cleanup_loaded_before(system, waits, loaded, task_group, terminate, None)
}

pub(crate) fn cleanup_loaded_before<
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut S,
    waits: &mut W,
    loaded: LoadedProcess,
    task_group: DwHandle,
    terminate: bool,
    deadline_cap: Option<u64>,
) -> Result<(), InitError> {
    let mut failed = false;
    let observed_now = system.now();
    let cleanup_deadline = observed_now.ok().and_then(|now| {
        now.checked_add(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns)
            .map(|deadline| deadline_cap.map_or(deadline, |cap| deadline.min(cap)))
            .or(deadline_cap)
    });
    if deadline_cap.is_some() && observed_now.is_err() {
        failed = true;
    }
    if terminate && system.terminate_task_group(task_group).is_err() {
        // A termination request may race the child's own terminal transition.
        failed |= !matches!(
            waits.query_task_termination(loaded.process),
            Ok(info) if info.state == DW_TASK_STATE_EXITED
        );
    }
    let mut terminal = matches!(
        waits.query_task_termination(loaded.process),
        Ok(info) if info.state == DW_TASK_STATE_EXITED
    );
    let may_wait = match (observed_now, deadline_cap) {
        (Ok(now), Some(cap)) => now < cap,
        (Ok(_), None) => true,
        (Err(_), _) => false,
    };
    if !terminal
        && may_wait
        && let Some(deadline) = cleanup_deadline
    {
        let item = DwWaitItemV1 {
            handle: loaded.process,
            signals: DW_SIGNAL_EXITED,
        };
        terminal = matches!(
            waits.wait_many(core::slice::from_ref(&item), DwDeadline(deadline)),
            Ok(result) if result.index == 0 && result.observed.0 & DW_SIGNAL_EXITED.0 != 0
        ) && matches!(
            waits.query_task_termination(loaded.process),
            Ok(info) if info.state == DW_TASK_STATE_EXITED
        );
    }
    failed |= !terminal;
    for h in [loaded.launch_channel, loaded.process, task_group] {
        failed |= system.close_handle(h).is_err();
    }
    if failed {
        Err(InitError::Cleanup)
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn cleanup_after_transition_error<S: InitPlatform, W: SupervisionPlatform<Error = NativeError>>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    loaded: LoadedProcess,
    task_group: DwHandle,
    role: RoleId,
    transition_error: InitError,
) -> InitError {
    if cleanup_loaded(system, waits, loaded, task_group, true).is_err() {
        controller.fatal();
        return InitError::Cleanup;
    }
    match controller.retire_attempt_after_fatal(role) {
        Ok(()) => transition_error,
        Err(error) => {
            controller.fatal();
            error
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn complete_native_cleanup<S: InitPlatform, W: SupervisionPlatform<Error = NativeError>>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    loaded: LoadedProcess,
    task_group: DwHandle,
    terminate: bool,
    role: RoleId,
    generation: u64,
    transaction: u64,
    classified_at: u64,
) -> Result<u64, InitError> {
    match cleanup_loaded(system, waits, loaded, task_group, terminate) {
        Ok(()) => {
            let retired_at = classified_at.checked_add(1).ok_or(InitError::Accounting)?;
            match controller.cleanup_complete(role, generation, transaction, retired_at) {
                Ok(()) => Ok(retired_at),
                Err(error) => {
                    let retirement = controller.retire_attempt_after_fatal(role);
                    match retirement {
                        Ok(()) => Err(error),
                        Err(retirement_error) => Err(retirement_error),
                    }
                }
            }
        }
        Err(error) => {
            let classified = classified_at.checked_add(1).ok_or(InitError::Accounting)?;
            let transition = controller.cleanup_failed(role, generation, transaction, classified);
            controller.fatal();
            match transition {
                Ok(()) => Err(error),
                Err(_) => Err(InitError::Cleanup),
            }
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AfterReadyTransition {
    Terminal(TerminalDisposition),
    Failure(AttemptFailure),
}

fn classify_after_ready_observation(
    error: &ObservedSupervisionError<NativeError>,
) -> AfterReadyTransition {
    match error {
        ObservedSupervisionError::ExitedBeforeReady(info)
        | ObservedSupervisionError::PeerClosedBeforeReady(info)
        | ObservedSupervisionError::Exit(_, info) => {
            AfterReadyTransition::Terminal(terminal_disposition(info))
        }
        ObservedSupervisionError::ExitObservedReadiness(_, _) => {
            AfterReadyTransition::Failure(AttemptFailure::ReadinessFailedAfterExit)
        }
        ObservedSupervisionError::Supervision(error) => {
            let failure = match error {
                SupervisionError::Ready(_)
                | SupervisionError::InvalidReadyReceive(_)
                | SupervisionError::DuplicateReady => AttemptFailure::DuplicateReady,
                SupervisionError::ExitObservedReadiness(_) => {
                    AttemptFailure::ReadinessFailedAfterExit
                }
                SupervisionError::ExitQuery(_) | SupervisionError::Exit(_) => {
                    AttemptFailure::ExitQueryFailed
                }
                _ => AttemptFailure::WaitFailed,
            };
            AfterReadyTransition::Failure(failure)
        }
    }
}

fn terminal_disposition(info: &DwTaskTerminationInfoV1) -> TerminalDisposition {
    if info.reason == DW_TERMINATION_NORMAL_EXIT
        && info.exception_type.0 == 0
        && info.detail == 0
        && info.fault_address == 0
    {
        TerminalDisposition::NormalExit(info.application_code)
    } else if info.reason == DW_TERMINATION_TASK_GROUP_TEARDOWN
        && info.exception_type.0 == 0
        && info.detail == 0
        && info.fault_address == 0
    {
        TerminalDisposition::TaskGroupTeardown
    } else if info.reason == DW_TERMINATION_AUTHORIZED
        && info.exception_type.0 == 0
        && info.detail == 0
        && info.fault_address == 0
    {
        TerminalDisposition::AuthorizedTermination
    } else {
        TerminalDisposition::UnhandledException
    }
}
fn advance_or_degrade<S: InitPlatform>(
    system: &mut S,
    controller: &mut SystemInit,
    role: RoleId,
    transaction: u64,
) -> Result<bool, InitError> {
    match controller
        .role_state(role)
        .ok_or(InitError::WrongActivationOrder)?
    {
        RestartState::PermanentFailure { .. } => Ok(true),
        RestartState::Backoff {
            next_generation,
            deadline_ns,
            ..
        } => {
            let observed_now = wait_for_replacement(system, deadline_ns)?;
            controller.start_replacement(
                role,
                observed_now,
                next_generation,
                next_transaction(transaction)?,
            )?;
            Ok(matches!(controller.mode(), SystemMode::Degraded))
        }
        _ => Err(InitError::WrongActivationOrder),
    }
}

fn wait_for_replacement<S: InitPlatform>(
    system: &mut S,
    deadline_ns: u64,
) -> Result<u64, InitError> {
    system.wait_until(deadline_ns).map_err(InitError::Native)?;
    let observed_now = system.now().map_err(InitError::Native)?;
    if observed_now < deadline_ns {
        return Err(InitError::WrongActivationOrder);
    }
    Ok(observed_now)
}

fn next_transaction(transaction: u64) -> Result<u64, InitError> {
    transaction.checked_add(1).ok_or(InitError::Restart(
        RestartTransitionError::ArithmeticOverflow,
    ))
}

/// Distinguishes process existence from profile-aware READY validation.
pub fn observe_ready(
    bytes: &[u8],
    handles: usize,
    expected_transaction: u64,
) -> Result<(), AttemptFailure> {
    if handles != 0 || bytes.len() != wyrmroot_loader::launch::HEADER_BYTES {
        return Err(AttemptFailure::MalformedReady);
    }
    match wyrmroot_loader::launch::parse_ready_for_profile(
        wyrmroot_loader::launch::LaunchProfile::EarlyBootStub,
        bytes,
        expected_transaction,
    ) {
        Ok(()) => Ok(()),
        Err(wyrmroot_loader::launch::LaunchError::TransactionMismatch) => {
            Err(AttemptFailure::WrongTransactionReady)
        }
        Err(_) => Err(AttemptFailure::MalformedReady),
    }
}

/// Converts an exact Process result into the restart engine's typed terminal disposition.
#[must_use]
pub const fn normal_exit(code: u32) -> TerminalDisposition {
    TerminalDisposition::NormalExit(code)
}

pub const REAP_CLASS_NORMAL_EXIT: u32 = 1;
pub const REAP_CLASS_AUTHORIZED_TERMINATION: u32 = 2;
pub const REAP_CLASS_TASK_GROUP_TEARDOWN: u32 = 3;
pub const REAP_CLASS_UNHANDLED_EXCEPTION: u32 = 4;

#[must_use]
pub const fn reap_evidence_value(failure: AttemptFailure) -> u64 {
    let disposition = match failure {
        AttemptFailure::ExitBeforeReady(disposition)
        | AttemptFailure::ExitAfterReady(disposition) => disposition,
        AttemptFailure::MalformedReady
        | AttemptFailure::DuplicateReady
        | AttemptFailure::ReadinessFailedAfterExit
        | AttemptFailure::WrongTransactionReady
        | AttemptFailure::PeerClosedBeforeReady
        | AttemptFailure::WaitFailed
        | AttemptFailure::ReadyTimeout
        | AttemptFailure::Cancelled => TerminalDisposition::TaskGroupTeardown,
        AttemptFailure::ExitQueryFailed => TerminalDisposition::UnhandledException,
        AttemptFailure::CreationFailed | AttemptFailure::StartFailed => {
            TerminalDisposition::AuthorizedTermination
        }
    };
    match disposition {
        TerminalDisposition::NormalExit(code) => {
            ((REAP_CLASS_NORMAL_EXIT as u64) << 32) | code as u64
        }
        TerminalDisposition::AuthorizedTermination => {
            (REAP_CLASS_AUTHORIZED_TERMINATION as u64) << 32
        }
        TerminalDisposition::TaskGroupTeardown => (REAP_CLASS_TASK_GROUP_TEARDOWN as u64) << 32,
        TerminalDisposition::UnhandledException => (REAP_CLASS_UNHANDLED_EXCEPTION as u64) << 32,
    }
}

#[must_use]
pub const fn cleanup_is_permanent(state: RestartState) -> bool {
    matches!(
        state,
        RestartState::PermanentFailure {
            cleanup: CleanupDisposition::Failed,
            ..
        }
    )
}

#[cfg(test)]
mod native_cleanup_tests {
    use super::*;

    #[cfg(feature = "wyr1e-production")]
    #[test]
    fn e6_manifest_constructor_admits_only_the_production_shell_profile() {
        use wyrmroot_rrc_manifest::builder::{Builder, DependencySpec, RoleSpec};

        let boot_generation = [0x42; 32];
        let mut builder = Builder::new(boot_generation);
        for (id, path, activation, profile) in [
            (
                RoleId::Registryd,
                "system/registryd",
                Activation::Early,
                StartupProfile::BootstrapRegistry,
            ),
            (
                RoleId::Devmgr,
                "system/devmgr",
                Activation::Early,
                StartupProfile::DeviceCoordinator,
            ),
            (
                RoleId::Uart16550d,
                "system/uart16550d",
                Activation::DeviceBound,
                StartupProfile::Retained,
            ),
            (
                RoleId::Consoled,
                "system/consoled",
                Activation::ConsoleBound,
                StartupProfile::Retained,
            ),
            (
                RoleId::Wyrmsh,
                "system/wyrmsh",
                Activation::ConsoleBound,
                StartupProfile::Wyrmsh,
            ),
        ] {
            builder
                .add_role(RoleSpec {
                    id,
                    required: true,
                    requires_ready: true,
                    activation,
                    startup_profile: profile,
                    path,
                    justification: "fixed retained recovery closure",
                    executable_identity: [id as u8; 32],
                })
                .unwrap();
        }
        for (owner, target) in [
            (RoleId::Devmgr, RoleId::Registryd),
            (RoleId::Uart16550d, RoleId::Devmgr),
            (RoleId::Consoled, RoleId::Uart16550d),
            (RoleId::Wyrmsh, RoleId::Consoled),
        ] {
            builder
                .add_dependency(DependencySpec {
                    owner,
                    kind: DependencyKind::RoleReady,
                    target_role: Some(target),
                    target_path: None,
                })
                .unwrap();
        }
        let bytes = builder.build_structural().unwrap();
        let manifest = Manifest::parse_structural(&bytes, &boot_generation).unwrap();
        assert!(SystemInit::from_wyr1e_manifest(manifest).is_ok());
        assert_eq!(
            SystemInit::from_wyr1c_manifest(manifest),
            Err(InitError::WrongManifestProfile)
        );
    }

    #[test]
    fn resource_domain_custody_reduces_only_for_a_devmgr_descendant() {
        let custody = ResourceDomainCustody::new(DwHandle(44));
        assert_eq!(
            custody.devmgr_claim_authority(ResourceDomainMembership::InitOutsideDomain),
            Err(ResourceDomainCustodyError::OutsideResourceDomain)
        );
        assert_eq!(
            custody.devmgr_claim_authority(ResourceDomainMembership::Unrelated),
            Err(ResourceDomainCustodyError::OutsideResourceDomain)
        );
        let reduced = custody
            .devmgr_claim_authority(ResourceDomainMembership::DevmgrGenerationDescendant)
            .expect("devmgr descendant receives reduced claim authority");
        assert_eq!(reduced.handle(), DwHandle(44));
        assert_eq!(reduced.rights(), RESOURCE_DOMAIN_CLAIM_RIGHTS);
        assert_ne!(reduced.rights(), RESOURCE_DOMAIN_CUSTODY_PROFILE_RIGHTS);
    }
    use deepwyrm_syscall::{
        DW_TASK_STATE_EXITED, DW_TASK_TERMINATION_INFO_V1_SIZE, DW_WAIT_RESULT_V1_SIZE, DwStatus,
        DwTaskState, DwTaskTerminationInfoV1, DwWaitResultV1,
    };
    use wyrmroot_runtime::NativeOutputError;

    const FAILURE: NativeError = NativeError::Status(DwStatus(-1));

    struct MockNative {
        now: u64,
        terminate_fails: bool,
        close_failure: DwHandle,
        closed: [DwHandle; 4],
        close_count: usize,
        wake_now: Option<u64>,
        wyr1b_calls: usize,
    }

    impl MockNative {
        const fn new() -> Self {
            Self {
                now: 10,
                terminate_fails: false,
                close_failure: DwHandle(0),
                closed: [DwHandle(0); 4],
                close_count: 0,
                wake_now: None,
                wyr1b_calls: 0,
            }
        }
    }

    impl InitPlatform for MockNative {
        fn query_capability_info(
            &mut self,
            _handle: DwHandle,
        ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
            Err(FAILURE)
        }

        fn receive_channel(
            &mut self,
            _channel: DwHandle,
            _bytes: &mut [u8],
            _handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, NativeError> {
            Err(FAILURE)
        }

        fn query_memory_object_size(&mut self, _handle: DwHandle) -> Result<u64, NativeError> {
            Err(FAILURE)
        }

        fn with_bootfs_bytes<R>(
            &mut self,
            _root: DwHandle,
            _bootfs: DwHandle,
            _plan: MappingPlan,
            _use_bytes: impl for<'a> FnOnce(&mut Self, &'a [u8]) -> R,
        ) -> Result<R, NativeError> {
            Err(FAILURE)
        }

        fn send_channel(&mut self, _channel: DwHandle, _bytes: &[u8]) -> Result<(), NativeError> {
            Err(FAILURE)
        }

        fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
            self.closed[self.close_count] = handle;
            self.close_count += 1;
            if handle == self.close_failure {
                Err(FAILURE)
            } else {
                Ok(())
            }
        }

        fn create_attempt_task_group(
            &mut self,
            _parent: DwHandle,
        ) -> Result<DwHandle, NativeError> {
            Err(FAILURE)
        }

        fn terminate_task_group(&mut self, _task_group: DwHandle) -> Result<(), NativeError> {
            if self.terminate_fails {
                Err(FAILURE)
            } else {
                Ok(())
            }
        }

        fn now(&mut self) -> Result<u64, NativeError> {
            Ok(self.now)
        }

        fn wait_until(&mut self, _deadline_ns: u64) -> Result<(), NativeError> {
            match self.wake_now {
                Some(now) => {
                    self.now = now;
                    Ok(())
                }
                None => Err(FAILURE),
            }
        }
    }

    impl Wyr1BPlatform for MockNative {
        fn channel_create(
            &mut self,
            _rights: DwRights,
        ) -> Result<(DwHandle, DwHandle), NativeError> {
            self.wyr1b_calls += 1;
            Err(FAILURE)
        }

        fn send_channel_with_handles(
            &mut self,
            _channel: DwHandle,
            _bytes: &[u8],
            _transfers: &[DwHandleTransferV1],
        ) -> Result<(), NativeError> {
            self.wyr1b_calls += 1;
            Err(FAILURE)
        }

        fn wait_many(
            &mut self,
            _items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, NativeError> {
            self.wyr1b_calls += 1;
            Err(FAILURE)
        }

        fn materialize_read_only_memory(
            &mut self,
            _root: DwHandle,
            _bytes: &[u8],
            _rights: DwRights,
        ) -> Result<DwHandle, NativeError> {
            self.wyr1b_calls += 1;
            Err(FAILURE)
        }
    }

    struct MockWaits {
        query_count: u8,
        terminal_at: u8,
        wait_exited: bool,
    }

    struct DeadlineWaits {
        query_count: u8,
        wait_deadline: Option<DwDeadline>,
    }

    impl SupervisionPlatform for DeadlineWaits {
        type Error = NativeError;

        fn wait_many(
            &mut self,
            _items: &[DwWaitItemV1],
            deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, Self::Error> {
            self.wait_deadline = Some(deadline);
            Ok(DwWaitResultV1 {
                index: 0,
                observed: DW_SIGNAL_EXITED,
                ..DwWaitResultV1::default()
            })
        }

        fn receive_channel(
            &mut self,
            _channel: DwHandle,
            _bytes: &mut [u8],
            _handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, Self::Error> {
            Err(FAILURE)
        }

        fn query_task_termination(
            &mut self,
            _process: DwHandle,
        ) -> Result<DwTaskTerminationInfoV1, Self::Error> {
            self.query_count += 1;
            Ok(DwTaskTerminationInfoV1 {
                state: if self.query_count >= 2 {
                    DW_TASK_STATE_EXITED
                } else {
                    DwTaskState(0)
                },
                ..DwTaskTerminationInfoV1::default()
            })
        }
    }

    struct ResidentWaits {
        wait_count: u8,
    }

    impl SupervisionPlatform for ResidentWaits {
        type Error = NativeError;

        fn wait_many(
            &mut self,
            items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, Self::Error> {
            let result = match self.wait_count {
                0 | 1 => DwWaitResultV1 {
                    size: DW_WAIT_RESULT_V1_SIZE,
                    version: 1,
                    index: 0,
                    observed: DW_SIGNAL_PEER_CLOSED,
                    ..DwWaitResultV1::default()
                },
                2 => DwWaitResultV1 {
                    size: DW_WAIT_RESULT_V1_SIZE,
                    version: 1,
                    index: 0,
                    observed: DW_SIGNAL_EXITED,
                    ..DwWaitResultV1::default()
                },
                3 => return Err(NativeError::Status(DW_STATUS_TIMED_OUT)),
                _ => panic!("unexpected resident wait"),
            };
            if self.wait_count == 2 {
                assert_eq!(items.len(), 1);
            }
            self.wait_count += 1;
            Ok(result)
        }

        fn receive_channel(
            &mut self,
            _channel: DwHandle,
            _bytes: &mut [u8],
            _handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, Self::Error> {
            Err(FAILURE)
        }

        fn query_task_termination(
            &mut self,
            _process: DwHandle,
        ) -> Result<DwTaskTerminationInfoV1, Self::Error> {
            Ok(DwTaskTerminationInfoV1 {
                size: DW_TASK_TERMINATION_INFO_V1_SIZE,
                version: 1,
                state: DW_TASK_STATE_EXITED,
                reason: DW_TERMINATION_NORMAL_EXIT,
                ..DwTaskTerminationInfoV1::default()
            })
        }
    }

    impl SupervisionPlatform for MockWaits {
        type Error = NativeError;

        fn wait_many(
            &mut self,
            _items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, Self::Error> {
            if self.wait_exited {
                Ok(DwWaitResultV1 {
                    index: 0,
                    observed: DW_SIGNAL_EXITED,
                    ..DwWaitResultV1::default()
                })
            } else {
                Err(NativeError::Output(NativeOutputError::InvalidWaitResult))
            }
        }

        fn receive_channel(
            &mut self,
            _channel: DwHandle,
            _bytes: &mut [u8],
            _handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, Self::Error> {
            Err(FAILURE)
        }

        fn query_task_termination(
            &mut self,
            _process: DwHandle,
        ) -> Result<DwTaskTerminationInfoV1, Self::Error> {
            self.query_count += 1;
            Ok(DwTaskTerminationInfoV1 {
                state: if self.query_count >= self.terminal_at {
                    DW_TASK_STATE_EXITED
                } else {
                    DwTaskState(0)
                },
                ..DwTaskTerminationInfoV1::default()
            })
        }
    }

    const LOADED: LoadedProcess = LoadedProcess {
        process: DwHandle(20),
        launch_channel: DwHandle(30),
    };

    fn install_ready_attempt(
        controller: &mut SystemInit,
        role: RoleId,
        generation: u64,
        transaction_id: u64,
        handles: (u64, u64, u64),
        now: u64,
    ) -> ActiveNativeRole {
        let reservation = controller
            .reserve_attempt(role, generation, transaction_id)
            .unwrap();
        let loaded = LoadedProcess {
            process: DwHandle(handles.1),
            launch_channel: DwHandle(handles.2),
        };
        let task_group = DwHandle(handles.0);
        let executable_identity = controller.executable_identity(role).unwrap();
        controller
            .install_attempt(AttemptResources {
                role,
                generation,
                transaction_id,
                executable_identity,
                startup_profile: StartupProfile::EarlyBootStub,
                task_group,
                process: loaded.process,
                launch_channel: loaded.launch_channel,
                mappings: 0,
                reservation,
            })
            .unwrap();
        controller
            .child_started(role, generation, transaction_id, now)
            .unwrap();
        controller
            .ready(role, generation, transaction_id, now + 1)
            .unwrap();
        ActiveNativeRole {
            role,
            generation,
            transaction_id,
            loaded,
            task_group,
        }
    }

    fn ready_registry_controller() -> SystemInit {
        let mut controller = SystemInit {
            mode: SystemMode::Bootstrap,
            roles: [
                RoleController::new(RoleId::Registryd, [1; 32]).unwrap(),
                RoleController::new(RoleId::Devmgr, [2; 32]).unwrap(),
            ],
            degraded_transitions: 0,
            activated: [false; EARLY_ROLE_COUNT],
            accounting: AttemptLedger::new(),
            gate: None,
            evidence: None,
            registry_startup_profile: StartupProfile::EarlyBootStub,
            devmgr_startup_profile: StartupProfile::EarlyBootStub,
        };
        controller.become_operational().unwrap();
        controller.begin_registry(0, 1, 0x1001).unwrap();
        install_ready_attempt(
            &mut controller,
            RoleId::Registryd,
            1,
            0x1001,
            (10, 20, 30),
            1,
        );
        controller
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn admitted_recovery_keeps_owner_reserved_until_exact_cleanup() {
        let mut controller = ready_registry_controller();
        controller
            .admit_recovery(RoleId::Registryd, 1, 0x1001, 3_000_000_000)
            .unwrap();
        assert_eq!(controller.outstanding_reservations(), 1);
        assert!(controller.resources(RoleId::Registryd).is_some());
        let restart = controller.roles[0].restart;
        let accounting = controller.accounting;
        assert_eq!(
            controller.admit_recovery(RoleId::Registryd, 1, 0x1001, 3_000_000_001),
            Err(InitError::Restart(RestartTransitionError::InvalidState))
        );
        assert_eq!(controller.roles[0].restart, restart);
        assert_eq!(controller.accounting, accounting);
        assert_eq!(
            controller.cleanup_complete(RoleId::Registryd, 2, 0x1001, 3_000_000_001),
            Err(InitError::Restart(RestartTransitionError::StaleGeneration))
        );
        assert_eq!(controller.outstanding_reservations(), 1);
        controller
            .cleanup_complete(RoleId::Registryd, 1, 0x1001, 3_000_000_001)
            .unwrap();
        assert_eq!(controller.outstanding_reservations(), 0);
        assert!(controller.resources(RoleId::Registryd).is_none());
        assert_ne!(controller.mode(), SystemMode::Degraded);
        assert_eq!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::Backoff {
                next_attempt: 2,
                next_generation: 2,
                deadline_ns: 3_025_000_001,
            })
        );
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn recovery_admission_rejects_wrong_owner_and_invalid_clock_without_mutation() {
        for (role, generation, transaction, now, error) in [
            (
                RoleId::Consoled,
                1,
                0x1001,
                3_000_000_000,
                InitError::UnlaunchableRole,
            ),
            (
                RoleId::Registryd,
                2,
                0x1001,
                3_000_000_000,
                InitError::Restart(RestartTransitionError::StaleGeneration),
            ),
            (
                RoleId::Registryd,
                1,
                0x1002,
                3_000_000_000,
                InitError::Restart(RestartTransitionError::TransactionMismatch),
            ),
            (
                RoleId::Registryd,
                1,
                0x1001,
                0,
                InitError::Restart(RestartTransitionError::TimeRegression),
            ),
            (
                RoleId::Registryd,
                1,
                0x1001,
                u64::MAX,
                InitError::Restart(RestartTransitionError::ArithmeticOverflow),
            ),
        ] {
            let mut controller = ready_registry_controller();
            let unchanged = ready_registry_controller();
            assert_eq!(
                controller.admit_recovery(role, generation, transaction, now),
                Err(error)
            );
            assert_eq!(controller, unchanged);
        }
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn recovery_admission_requires_exact_published_resources_without_mutation() {
        let mutations: [fn(&mut SystemInit); 6] = [
            |controller| controller.roles[0].resources.as_mut().unwrap().role = RoleId::Devmgr,
            |controller| {
                controller.roles[0]
                    .resources
                    .as_mut()
                    .unwrap()
                    .reservation
                    .role = RoleId::Devmgr
            },
            |controller| {
                controller.roles[0]
                    .resources
                    .as_mut()
                    .unwrap()
                    .reservation
                    .published = false
            },
            |controller| {
                controller.roles[0]
                    .resources
                    .as_mut()
                    .unwrap()
                    .reservation
                    .released = true
            },
            |controller| controller.accounting.slots[0].published = false,
            |controller| controller.accounting.slots[0].nonce += 1,
        ];
        for mutate in mutations {
            let mut controller = ready_registry_controller();
            let mut unchanged = ready_registry_controller();
            mutate(&mut controller);
            mutate(&mut unchanged);
            assert_eq!(
                controller.admit_recovery(RoleId::Registryd, 1, 0x1001, 3_000_000_000),
                Err(InitError::Accounting)
            );
            assert_eq!(controller, unchanged);
        }
        let mut controller = ready_registry_controller();
        let retained = controller.roles[0].resources.take().unwrap();
        let restart = controller.roles[0].restart;
        let accounting = controller.accounting;
        assert_eq!(
            controller.admit_recovery(RoleId::Registryd, 1, 0x1001, 3_000_000_000),
            Err(InitError::MissingAttemptResources)
        );
        assert_eq!(controller.roles[0].restart, restart);
        assert_eq!(controller.accounting, accounting);
        controller.roles[0].resources = Some(retained);
        assert_eq!(controller, ready_registry_controller());
    }

    #[test]
    fn fail_closed_complete_retirement_releases_accounting_and_degrades() {
        let mut controller = ready_registry_controller();
        assert_eq!(controller.outstanding_reservations(), 1);

        controller
            .retire_active_fail_closed(
                RoleId::Registryd,
                1,
                0x1001,
                u64::MAX,
                AttemptFailure::WaitFailed,
                CleanupDisposition::Complete,
            )
            .unwrap();

        assert!(controller.resources(RoleId::Registryd).is_none());
        assert_eq!(controller.outstanding_reservations(), 0);
        assert_eq!(controller.mode(), SystemMode::Degraded);
        assert_eq!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::PermanentFailure {
                final_failure: AttemptFailure::WaitFailed,
                cleanup: CleanupDisposition::Complete,
            })
        );
    }

    #[test]
    fn fail_closed_retirement_is_identity_exact_and_failed_cleanup_stays_owned() {
        let mut controller = ready_registry_controller();
        let ready = controller.role_state(RoleId::Registryd);

        assert_eq!(
            controller.retire_active_fail_closed(
                RoleId::Registryd,
                1,
                0x1002,
                3,
                AttemptFailure::WaitFailed,
                CleanupDisposition::Complete,
            ),
            Err(InitError::Restart(
                RestartTransitionError::TransactionMismatch
            ))
        );
        assert_eq!(controller.role_state(RoleId::Registryd), ready);
        assert_eq!(controller.outstanding_reservations(), 1);

        controller
            .retire_active_fail_closed(
                RoleId::Registryd,
                1,
                0x1001,
                3,
                AttemptFailure::WaitFailed,
                CleanupDisposition::Failed,
            )
            .unwrap();
        assert!(controller.resources(RoleId::Registryd).is_some());
        assert_eq!(controller.outstanding_reservations(), 1);
        assert_eq!(controller.mode(), SystemMode::Degraded);
        assert!(matches!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::PermanentFailure {
                cleanup: CleanupDisposition::Failed,
                ..
            })
        ));
    }

    #[test]
    fn resident_drains_peer_close_to_clean_exit_without_dropping_other_role() {
        let mut controller = SystemInit {
            mode: SystemMode::Bootstrap,
            roles: [
                RoleController::new(RoleId::Registryd, [1; 32]).unwrap(),
                RoleController::new(RoleId::Devmgr, [2; 32]).unwrap(),
            ],
            degraded_transitions: 0,
            activated: [false; EARLY_ROLE_COUNT],
            accounting: AttemptLedger::new(),
            gate: None,
            evidence: None,
            registry_startup_profile: StartupProfile::EarlyBootStub,
            devmgr_startup_profile: StartupProfile::EarlyBootStub,
        };
        controller.become_operational().unwrap();
        controller.begin_registry(0, 1, 0x1001).unwrap();
        let registry = install_ready_attempt(
            &mut controller,
            RoleId::Registryd,
            1,
            0x1001,
            (10, 20, 30),
            1,
        );
        let devmgr =
            install_ready_attempt(&mut controller, RoleId::Devmgr, 1, 0x1002, (11, 21, 31), 3);
        let mut resident = ResidentSystemInit {
            controller,
            authority: LoadAuthority {
                parent_root: DwHandle(100),
                bootfs: DwHandle(101),
                task_group: DwHandle(102),
            },
            result: RecoveryResult::Recovered,
            active: [Some(registry), Some(devmgr)],
            evidence_finalized: false,
            last_tick_ns: 9,
            wyr1b: None,
            wyr1b_evidence: None,
            wyr1c: None,
        };
        let mut native = MockNative::new();
        let mut loader = wyrmroot_runtime::NativeLoaderPlatform;
        let mut waits = ResidentWaits { wait_count: 0 };

        assert_eq!(
            resident.control_tick_product(&mut native, &mut loader, &mut waits, 10),
            Ok(SystemMode::Normal)
        );
        assert_eq!(native.wyr1b_calls, 0);
        assert_eq!(resident.wyr1b_evidence_record(0), None);
        assert_eq!(resident.active, [None, Some(devmgr)]);
        assert_eq!(
            resident.controller.role_state(RoleId::Registryd),
            Some(RestartState::Stopped)
        );
        assert!(matches!(
            resident.controller.role_state(RoleId::Devmgr),
            Some(RestartState::Ready { .. })
        ));
        assert!(!resident.evidence_finalized());
        assert_eq!(
            &native.closed[..3],
            &[
                registry.loaded.launch_channel,
                registry.loaded.process,
                registry.task_group
            ]
        );
        assert_eq!(waits.wait_count, 3);
    }

    #[test]
    fn task_group_termination_race_reconciles_with_fresh_terminal_query() {
        let mut native = MockNative::new();
        native.terminate_fails = true;
        let mut waits = MockWaits {
            query_count: 0,
            terminal_at: 1,
            wait_exited: false,
        };
        assert_eq!(
            cleanup_loaded(&mut native, &mut waits, LOADED, DwHandle(10), true),
            Ok(())
        );
        assert_eq!(
            &native.closed[..3],
            &[DwHandle(30), DwHandle(20), DwHandle(10)]
        );
    }

    #[test]
    fn cleanup_closes_every_handle_after_individual_close_failure() {
        let mut native = MockNative::new();
        native.close_failure = DwHandle(20);
        let mut waits = MockWaits {
            query_count: 0,
            terminal_at: 1,
            wait_exited: false,
        };
        assert_eq!(
            cleanup_loaded(&mut native, &mut waits, LOADED, DwHandle(10), false),
            Err(InitError::Cleanup)
        );
        assert_eq!(native.close_count, 3);
        assert_eq!(
            &native.closed[..3],
            &[DwHandle(30), DwHandle(20), DwHandle(10)]
        );
    }

    #[test]
    fn cleanup_action_cap_uses_exact_deadline_and_starts_no_wait_at_expiry() {
        let mut before = MockNative::new();
        before.now = 199;
        let mut before_waits = DeadlineWaits {
            query_count: 0,
            wait_deadline: None,
        };
        assert_eq!(
            cleanup_loaded_before(
                &mut before,
                &mut before_waits,
                LOADED,
                DwHandle(10),
                true,
                Some(200),
            ),
            Ok(())
        );
        assert_eq!(before_waits.wait_deadline, Some(DwDeadline(200)));

        let mut expired = MockNative::new();
        expired.now = 200;
        let mut expired_waits = DeadlineWaits {
            query_count: 0,
            wait_deadline: None,
        };
        assert_eq!(
            cleanup_loaded_before(
                &mut expired,
                &mut expired_waits,
                LOADED,
                DwHandle(10),
                true,
                Some(200),
            ),
            Err(InitError::Cleanup)
        );
        assert_eq!(expired_waits.wait_deadline, None);
        assert_eq!(expired.close_count, 3);
    }

    #[test]
    fn cleanup_deadline_failure_is_visible_after_closing_all_handles() {
        let mut native = MockNative::new();
        let mut waits = MockWaits {
            query_count: 0,
            terminal_at: u8::MAX,
            wait_exited: false,
        };
        assert_eq!(
            cleanup_loaded(&mut native, &mut waits, LOADED, DwHandle(10), true),
            Err(InitError::Cleanup)
        );
        assert_eq!(native.close_count, 3);
    }

    #[test]
    fn oversized_startup_count_closes_every_initialized_handle_and_channel() {
        let handles = [
            DwReceivedHandleInfoV1 {
                handle: DwHandle(1),
                ..DwReceivedHandleInfoV1::default()
            },
            DwReceivedHandleInfoV1 {
                handle: DwHandle(2),
                ..DwReceivedHandleInfoV1::default()
            },
            DwReceivedHandleInfoV1 {
                handle: DwHandle(3),
                ..DwReceivedHandleInfoV1::default()
            },
        ];
        let mut native = MockNative::new();
        assert_eq!(
            close_malformed_startup(&mut native, &handles, usize::MAX, DwHandle(4)),
            Ok(())
        );
        assert_eq!(
            native.closed,
            [DwHandle(1), DwHandle(2), DwHandle(3), DwHandle(4)]
        );
    }

    #[test]
    fn replacement_uses_fresh_delayed_wake_and_rejects_early_wake() {
        let mut native = MockNative::new();
        native.wake_now = Some(125);
        assert_eq!(wait_for_replacement(&mut native, 100), Ok(125));
        native.wake_now = Some(99);
        assert_eq!(
            wait_for_replacement(&mut native, 100),
            Err(InitError::WrongActivationOrder)
        );
    }

    #[test]
    fn elapsed_wait_accepts_timeout_fallback_but_rejects_early_completion() {
        let timed_out = Err(NativeError::Status(DW_STATUS_TIMED_OUT));
        assert_eq!(validate_wait_until_completion(100, 100, Ok(())), Ok(()));
        assert_eq!(validate_wait_until_completion(100, 125, timed_out), Ok(()));
        assert_eq!(
            validate_wait_until_completion(100, 99, Ok(())),
            Err(NativeError::Output(NativeOutputError::InvalidWaitResult))
        );
        assert_eq!(
            validate_wait_until_completion(100, 99, timed_out),
            Err(NativeError::Output(NativeOutputError::InvalidWaitResult))
        );
    }

    #[test]
    fn replacement_transaction_overflow_is_structured() {
        assert_eq!(
            next_transaction(u64::MAX),
            Err(InitError::Restart(
                RestartTransitionError::ArithmeticOverflow
            ))
        );
    }

    #[test]
    fn exact_terminal_records_map_to_all_reap_classes() {
        let mut info = DwTaskTerminationInfoV1 {
            reason: DW_TERMINATION_NORMAL_EXIT,
            application_code: 0xA101_F001,
            ..DwTaskTerminationInfoV1::default()
        };
        assert_eq!(
            terminal_disposition(&info),
            TerminalDisposition::NormalExit(0xA101_F001)
        );
        info.reason = DW_TERMINATION_AUTHORIZED;
        info.application_code = 0;
        assert_eq!(
            terminal_disposition(&info),
            TerminalDisposition::AuthorizedTermination
        );
        info.reason = deepwyrm_syscall::DW_TERMINATION_UNHANDLED_EXCEPTION;
        info.exception_type = deepwyrm_syscall::DW_EXCEPTION_ILLEGAL_INSTRUCTION;
        assert_eq!(
            terminal_disposition(&info),
            TerminalDisposition::UnhandledException
        );
        info.reason = DW_TERMINATION_TASK_GROUP_TEARDOWN;
        info.exception_type = deepwyrm_syscall::DwExceptionType(0);
        assert_eq!(
            terminal_disposition(&info),
            TerminalDisposition::TaskGroupTeardown
        );
        assert_eq!(
            reap_evidence_value(AttemptFailure::ExitAfterReady(terminal_disposition(&info))),
            (REAP_CLASS_TASK_GROUP_TEARDOWN as u64) << 32
        );
        assert_eq!(
            reap_evidence_value(AttemptFailure::DuplicateReady),
            (REAP_CLASS_TASK_GROUP_TEARDOWN as u64) << 32
        );
    }

    #[test]
    fn after_ready_observation_uses_terminal_and_failure_owners_exactly() {
        let info = DwTaskTerminationInfoV1 {
            reason: DW_TERMINATION_NORMAL_EXIT,
            application_code: 7,
            ..DwTaskTerminationInfoV1::default()
        };
        let terminal: ObservedSupervisionError<NativeError> =
            ObservedSupervisionError::ExitedBeforeReady(info);
        assert_eq!(
            classify_after_ready_observation(&terminal),
            AfterReadyTransition::Terminal(TerminalDisposition::NormalExit(7))
        );

        let post_exit: ObservedSupervisionError<NativeError> =
            ObservedSupervisionError::ExitObservedReadiness(
                wyrmroot_runtime::ExitObservedReadinessError::DuplicateReady,
                info,
            );
        assert_eq!(
            classify_after_ready_observation(&post_exit),
            AfterReadyTransition::Failure(AttemptFailure::ReadinessFailedAfterExit)
        );

        let duplicate: ObservedSupervisionError<NativeError> =
            ObservedSupervisionError::Supervision(SupervisionError::DuplicateReady);
        assert_eq!(
            classify_after_ready_observation(&duplicate),
            AfterReadyTransition::Failure(AttemptFailure::DuplicateReady)
        );
    }

    #[test]
    fn initial_ready_exit_race_uses_the_terminal_transition() {
        let info = DwTaskTerminationInfoV1 {
            reason: DW_TERMINATION_NORMAL_EXIT,
            application_code: 0xA101_F001,
            ..DwTaskTerminationInfoV1::default()
        };
        let observed: ObservedSupervisionError<NativeError> =
            ObservedSupervisionError::ExitedBeforeReady(info);
        let AfterReadyTransition::Terminal(disposition) =
            classify_after_ready_observation(&observed)
        else {
            panic!("early terminal observation lost its terminal owner")
        };

        let mut supervisor = RestartSupervisor::new(WYR0_I_SUPERVISION_POLICY).unwrap();
        supervisor.begin(1, 1, 1).unwrap();
        supervisor.child_started(1, 1, 2).unwrap();
        supervisor.terminal(1, 1, 3, disposition).unwrap();
        assert!(matches!(
            supervisor.state(),
            RestartState::CleaningUp {
                failure: AttemptFailure::ExitBeforeReady(TerminalDisposition::NormalExit(
                    0xA101_F001
                )),
                action: wyrmroot_runtime::CleanupAction::CloseTerminal,
                ..
            }
        ));
    }

    #[test]
    fn after_ready_exit_race_enters_the_admitted_restart_transition() {
        let mut supervisor = RestartSupervisor::new(WYR0_I_SUPERVISION_POLICY).unwrap();
        supervisor.begin(1, 1, 1).unwrap();
        supervisor.child_started(1, 1, 2).unwrap();
        supervisor.ready(1, 1, 3).unwrap();
        let info = DwTaskTerminationInfoV1 {
            reason: DW_TERMINATION_NORMAL_EXIT,
            ..DwTaskTerminationInfoV1::default()
        };
        let observed: ObservedSupervisionError<NativeError> =
            ObservedSupervisionError::ExitedBeforeReady(info);
        let AfterReadyTransition::Terminal(disposition) =
            classify_after_ready_observation(&observed)
        else {
            panic!("terminal observation lost its terminal owner")
        };
        supervisor.terminal(1, 1, 4, disposition).unwrap();
        assert!(matches!(
            supervisor.state(),
            RestartState::CleaningUp {
                failure: AttemptFailure::ExitAfterReady(TerminalDisposition::NormalExit(0)),
                action: wyrmroot_runtime::CleanupAction::CloseTerminal,
                ..
            }
        ));
        supervisor.cleanup_complete(1, 1, 5).unwrap();
        assert_eq!(supervisor.state(), RestartState::Stopped);

        let mut drain_failure = RestartSupervisor::new(WYR0_I_SUPERVISION_POLICY).unwrap();
        drain_failure.begin(1, 1, 1).unwrap();
        drain_failure.child_started(1, 1, 2).unwrap();
        drain_failure.ready(1, 1, 3).unwrap();
        let observed: ObservedSupervisionError<NativeError> =
            ObservedSupervisionError::ExitObservedReadiness(
                wyrmroot_runtime::ExitObservedReadinessError::DuplicateReady,
                info,
            );
        let AfterReadyTransition::Failure(failure) = classify_after_ready_observation(&observed)
        else {
            panic!("post-exit readiness failure lost its failure owner")
        };
        drain_failure.fail_attempt(1, 1, 4, failure).unwrap();
        assert!(matches!(
            drain_failure.state(),
            RestartState::CleaningUp {
                failure: AttemptFailure::ReadinessFailedAfterExit,
                action: wyrmroot_runtime::CleanupAction::CloseTerminal,
                ..
            }
        ));
    }

    #[test]
    fn rollback_failure_maps_to_exact_fatal_reboot_status() {
        let error = InitError::Loader(LoadError::Platform {
            stage: wyrmroot_loader::process::LoadStage::ProcessCreate,
            cause: FAILURE,
            rollback_failed: true,
        });
        assert_eq!(
            fatal_application_status(&error),
            InitApplicationStatus::FatalRebootRequired
        );
        assert_eq!(fatal_application_status(&error) as u32, 0xAF01_0002);
    }

    #[test]
    fn resident_tick_failure_detail_preserves_the_selected_profile() {
        // Selector 34 keeps its category at this boundary too, so it is excluded
        // from the collapsing case rather than asserted to collapse: this test
        // predates that selector and only ran under features where it does.
        #[cfg(not(any(feature = "wyr1e8-selector33", feature = "r1-selector34")))]
        for error in [
            InitError::Accounting,
            InitError::Supervision,
            InitError::Cleanup,
            InitError::WrongActivationOrder,
        ] {
            assert_eq!(
                resident_tick_failure_application_status(&error),
                0xAF01_0006
            );
        }

        #[cfg(feature = "wyr1e8-selector33")]
        assert_eq!(
            resident_tick_failure_application_status(&InitError::Accounting),
            0xAF18_0F02
        );

        #[cfg(feature = "r1-selector34")]
        for error in [
            InitError::Accounting,
            InitError::Supervision,
            InitError::Cleanup,
            InitError::WrongActivationOrder,
        ] {
            assert_eq!(
                resident_tick_failure_application_status(&error),
                0xAF36_0000 | test_failure_category(&error)
            );
        }
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn e8_failure_detail_is_finite_unique_and_keeps_the_narrowest_operation() {
        for operation in [
            E8FailureOperation::TriggerWait,
            E8FailureOperation::Quiesced,
            E8FailureOperation::RequestRetire,
            E8FailureOperation::RetireDependents,
            E8FailureOperation::ReapDriver,
            E8FailureOperation::AcknowledgeReaped,
            E8FailureOperation::DriverRetired,
            E8FailureOperation::RebindPublication,
            E8FailureOperation::ActionDeadline,
            E8FailureOperation::RecoveryFallback,
            E8FailureOperation::RetireRegistry,
            E8FailureOperation::LaunchRegistry,
            E8FailureOperation::CommitRegistry,
            E8FailureOperation::StartConsole,
        ] {
            let error = e8_operation::<()>(operation, Err(InitError::Cleanup)).unwrap_err();
            assert_eq!(
                resident_tick_failure_application_status(&error),
                0xAF18_0004 | (operation as u32) << 8
            );
        }

        for (error, expected_kind) in [
            (InitError::WrongActivationOrder, 0x01),
            (InitError::Accounting, 0x02),
            (InitError::Supervision, 0x03),
            (InitError::Cleanup, 0x04),
            (
                InitError::Native(NativeError::Status(deepwyrm_syscall::DwStatus(-11))),
                0x05,
            ),
            (InitError::WrongManifestProfile, 0x06),
            (InitError::UnlaunchableRole, 0x07),
            (
                InitError::Evidence(evidence::EvidenceError::AlreadyTerminal),
                0x08,
            ),
            (InitError::ZeroBootGeneration, 0x0f),
        ] {
            let error =
                e8_operation::<()>(E8FailureOperation::TriggerWait, Err(error)).unwrap_err();
            assert_eq!(
                resident_tick_failure_application_status(&error),
                0xAF18_0100 | expected_kind
            );
        }

        let nested = e8_operation(
            E8FailureOperation::DriverRetired,
            e8_operation::<()>(
                E8FailureOperation::RebindPublication,
                Err(InitError::Cleanup),
            ),
        )
        .unwrap_err();
        assert_eq!(
            resident_tick_failure_application_status(&nested),
            0xAF18_0804
        );
        assert_eq!(
            resident_tick_failure_application_status(&InitError::E8Transition {
                operation: 0,
                initiating_kind: 0,
                emergency_cleanup: E8EmergencyCleanup::NotRun,
            }),
            0xAF18_0F0F
        );
        assert_eq!(
            e8_operation(E8FailureOperation::RequestRetire, Ok::<_, InitError>(7)),
            Ok(7)
        );
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn recovery_supervision_failures_keep_their_source_family() {
        for (operation, expected) in [
            (E8FailureOperation::Quiesced, 0xAF18_0203),
            (E8FailureOperation::ActionDeadline, 0xAF18_0903),
            (E8FailureOperation::RecoveryFallback, 0xAF18_0A03),
        ] {
            let initiating =
                e8_operation::<()>(operation, Err(InitError::Supervision)).unwrap_err();
            let nested = e8_operation::<()>(E8FailureOperation::RebindPublication, Err(initiating))
                .unwrap_err();
            let dispatched = e8_dispatch_failure(
                nested,
                E8EmergencyCleanup::Attempted {
                    channel_close_failed: false,
                    owner_cleanup_failed: false,
                },
            );
            assert_eq!(
                resident_tick_failure_application_status(&dispatched),
                expected
            );
            assert_eq!(e8_operation(operation, Ok::<_, InitError>(7)), Ok(7));
        }
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn registry_recovery_failures_keep_phase_and_nested_operations() {
        for (operation, expected) in [
            (E8FailureOperation::RetireDependents, 0xAF18_0404),
            (E8FailureOperation::RebindPublication, 0xAF18_0804),
            (E8FailureOperation::ActionDeadline, 0xAF18_0904),
            (E8FailureOperation::RetireRegistry, 0xAF18_0B04),
            (E8FailureOperation::LaunchRegistry, 0xAF18_0C04),
            (E8FailureOperation::CommitRegistry, 0xAF18_0D04),
            (E8FailureOperation::StartConsole, 0xAF18_0E04),
        ] {
            let error = e8_operation::<()>(operation, Err(InitError::Cleanup)).unwrap_err();
            assert_eq!(resident_tick_failure_application_status(&error), expected);
            let nested =
                e8_operation::<()>(E8FailureOperation::StartConsole, Err(error)).unwrap_err();
            assert_eq!(
                nested,
                InitError::E8Transition {
                    operation: operation as u8,
                    initiating_kind: 4,
                    emergency_cleanup: E8EmergencyCleanup::NotRun,
                }
            );
            let deadline = e8_operation::<()>(
                E8FailureOperation::ActionDeadline,
                Err(InitError::Supervision),
            )
            .unwrap_err();
            let nested_deadline = e8_operation::<()>(operation, Err(deadline)).unwrap_err();
            assert_eq!(
                resident_tick_failure_application_status(&nested_deadline),
                0xAF18_0903
            );
            assert_eq!(
                e8_operation(operation, Ok::<_, InitError>(Some(7))),
                Ok(Some(7))
            );
            assert_eq!(
                e8_operation(operation, Ok::<Option<u64>, InitError>(None)),
                Ok(None)
            );
        }
        for operation in [0, 0x10, u8::MAX] {
            let error = InitError::E8Transition {
                operation,
                initiating_kind: 4,
                emergency_cleanup: E8EmergencyCleanup::NotRun,
            };
            assert_eq!(
                resident_tick_failure_application_status(&error),
                0xAF18_0F04
            );
        }
        assert_eq!(
            resident_tick_failure_application_status(&InitError::Cleanup),
            0xAF18_0F04
        );
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn e8_dispatch_failure_keeps_initiating_detail_and_cleanup_outcome_separate() {
        let initiating = e8_operation::<()>(
            E8FailureOperation::Quiesced,
            Err(InitError::Native(NativeError::Status(
                deepwyrm_syscall::DwStatus(-11),
            ))),
        )
        .unwrap_err();
        let cleanup = E8EmergencyCleanup::Attempted {
            channel_close_failed: true,
            owner_cleanup_failed: false,
        };
        let joined = e8_dispatch_failure(initiating, cleanup);
        assert_eq!(
            joined,
            InitError::E8Transition {
                operation: E8FailureOperation::Quiesced as u8,
                initiating_kind: 0x05,
                emergency_cleanup: cleanup,
            }
        );
        assert_eq!(
            resident_tick_failure_application_status(&joined),
            0xAF18_0204
        );

        let completed = e8_dispatch_failure(
            InitError::Accounting,
            E8EmergencyCleanup::Attempted {
                channel_close_failed: false,
                owner_cleanup_failed: false,
            },
        );
        assert_eq!(
            resident_tick_failure_application_status(&completed),
            0xAF18_0F02
        );
        assert_eq!(
            e8_dispatch_failure(InitError::Accounting, E8EmergencyCleanup::DisconnectFailed),
            InitError::E8Transition {
                operation: 0x0f,
                initiating_kind: 0x02,
                emergency_cleanup: E8EmergencyCleanup::DisconnectFailed,
            }
        );
        let disconnect_failed =
            e8_dispatch_failure(InitError::Accounting, E8EmergencyCleanup::DisconnectFailed);
        assert_eq!(
            resident_tick_failure_application_status(&disconnect_failed),
            0xAF18_0F04
        );
    }

    #[cfg(feature = "wyr1c6-selector29")]
    #[test]
    fn wyr1c6_test_failure_status_preserves_pre_ready_category() {
        assert_eq!(
            wyr1c6_test_failure_application_status(&InitError::WrongManifestProfile),
            0xAF1C_0001
        );
        assert_eq!(
            wyr1c6_test_failure_application_status(&InitError::Capability(
                CapabilityValidationError::InvalidFreshCapability,
            )),
            0xAF1C_0010
        );
        assert_eq!(
            wyr1c6_test_failure_application_status(&InitError::Accounting),
            0xAF1C_0016
        );
        assert_eq!(
            wyr1c6_test_failure_application_status(&InitError::Native(NativeError::Status(
                deepwyrm_syscall::DwStatus(-11),
            ))),
            0xAF1D_000B
        );
    }

    #[cfg(feature = "wyr1-test-evidence")]
    #[test]
    fn wyr1_test_failure_status_preserves_top_level_category() {
        assert_eq!(
            wyr1_test_failure_application_status(&InitError::Cleanup),
            0xAF11_0015
        );
        assert_eq!(
            wyr1_test_failure_application_status(&InitError::Accounting),
            0xAF11_0016
        );
        assert_eq!(
            wyr1_test_failure_application_status(&InitError::WrongActivationOrder),
            0xAF11_0003
        );
    }

    #[cfg(feature = "wyr1b-test-evidence")]
    #[test]
    fn wyr1b_startup_mapping_status_encodes_variant_and_size_class() {
        let cases = [
            (0, 0xAF11_1001),
            (wyrmroot_runtime::MAX_BOOTFS_LOGICAL_SIZE + 1, 0xAF11_2302),
            (u64::MAX, 0xAF11_2403),
        ];
        for (size, expected) in cases {
            let error = MappingPlan::for_bootfs(size).unwrap_err();
            let status = wyr1b_test_failure_application_status(&startup_mapping_error(error, size));
            assert_eq!(status, expected);
        }
    }

    #[cfg(feature = "wyr1b-test-evidence")]
    #[test]
    fn startup_bootfs_size_classes_cover_stable_boundaries() {
        use wyrmroot_runtime::{MAX_BOOTFS_LOGICAL_SIZE, PAGE_SIZE};

        let cases = [
            (0, StartupBootfsSizeClass::Zero),
            (1, StartupBootfsSizeClass::SmallNonzero),
            (PAGE_SIZE - 1, StartupBootfsSizeClass::SmallNonzero),
            (PAGE_SIZE, StartupBootfsSizeClass::Admitted),
            (MAX_BOOTFS_LOGICAL_SIZE, StartupBootfsSizeClass::Admitted),
            (
                MAX_BOOTFS_LOGICAL_SIZE + 1,
                StartupBootfsSizeClass::OverMaximum,
            ),
            ((1_u64 << 63) - 1, StartupBootfsSizeClass::OverMaximum),
            (1_u64 << 63, StartupBootfsSizeClass::GarbageHigh),
            (u64::MAX, StartupBootfsSizeClass::GarbageHigh),
        ];
        for (size, expected) in cases {
            assert_eq!(startup_bootfs_size_class(size), expected);
        }
    }

    #[cfg(feature = "wyr1b-test-evidence")]
    #[test]
    fn ordinary_mapping_status_encodes_site_variant_and_size_class() {
        let sites = [
            MappingDiagnosticSite::RoleRemap,
            MappingDiagnosticSite::JobDispatcher,
            MappingDiagnosticSite::RegistryReplacement,
        ];
        let sizes = [0, wyrmroot_runtime::MAX_BOOTFS_LOGICAL_SIZE + 1, u64::MAX];
        for (site_index, site) in sites.into_iter().enumerate() {
            for (outcome_index, size) in sizes.into_iter().enumerate() {
                let error = MappingPlan::for_bootfs(size).unwrap_err();
                let expected_ordinal = 4 + (site_index as u32 * 3) + outcome_index as u32;
                let status = wyr1b_test_failure_application_status(&ordinary_mapping_error(
                    site, error, size,
                ));
                assert_eq!(status & 0x1f, expected_ordinal);
            }
        }
    }

    #[cfg(feature = "wyr1b-test-evidence")]
    #[test]
    fn mapping_ordinals_survive_kernel_application_summary_compression() {
        let sizes = [0, wyrmroot_runtime::MAX_BOOTFS_LOGICAL_SIZE + 1, u64::MAX];
        let mut statuses = [0_u32; 12];
        for (index, size) in sizes.into_iter().enumerate() {
            let error = MappingPlan::for_bootfs(size).unwrap_err();
            statuses[index] =
                wyr1b_test_failure_application_status(&startup_mapping_error(error, size));
        }
        for (site_index, site) in [
            MappingDiagnosticSite::RoleRemap,
            MappingDiagnosticSite::JobDispatcher,
            MappingDiagnosticSite::RegistryReplacement,
        ]
        .into_iter()
        .enumerate()
        {
            for (outcome_index, size) in sizes.into_iter().enumerate() {
                let error = MappingPlan::for_bootfs(size).unwrap_err();
                statuses[3 + site_index * 3 + outcome_index] =
                    wyr1b_test_failure_application_status(&ordinary_mapping_error(
                        site, error, size,
                    ));
            }
        }
        let mut seen = 0_u16;
        for (index, status) in statuses.into_iter().enumerate() {
            let ordinal = status & 0x1f;
            let expected = index as u32 + 1;
            assert_eq!(ordinal, expected);
            assert_eq!(0x20 | ordinal, 0x21 + index as u32);
            let bit = 1_u16 << ordinal;
            assert_eq!(seen & bit, 0);
            seen |= bit;
        }
        assert_eq!(seen, 0x1ffe);
    }

    #[cfg(feature = "wyr1b-test-evidence")]
    #[test]
    fn non_mapping_category_status_is_unchanged() {
        for (error, expected) in [
            (InitError::Cleanup, 0xAF11_0015),
            (InitError::Accounting, 0xAF11_0016),
        ] {
            assert_eq!(wyr1b_test_failure_application_status(&error), expected);
        }
    }

    #[test]
    fn resident_fits_locked_native_stack_partition() {
        extern crate std;
        use core::mem::size_of;

        std::println!("resident bytes: {}", size_of::<ResidentSystemInit>());

        // Selector 32 retains a JobV2 dispatcher alongside the device resident.
        // Reserve 40 KiB of the existing 108 KiB execution stack for residency;
        // this partition is a userspace budget, not a startup ABI limit.
        let resident_budget = if cfg!(any(
            feature = "wyr1d-selector32",
            feature = "wyr1e-production"
        )) {
            40
        } else {
            20
        };
        assert!(
            size_of::<ResidentSystemInit>() <= resident_budget * 1024,
            "resident bytes: {}",
            size_of::<ResidentSystemInit>()
        );
        assert_eq!(wyrmroot_loader::elf::STACK_BYTES, 128 * 1024);
        assert_eq!(wyrmroot_runtime::STARTUP_BLOCK_V2_SIZE, 20 * 1024);
        assert_eq!(
            wyrmroot_loader::elf::STACK_BYTES as usize - wyrmroot_runtime::STARTUP_BLOCK_V2_SIZE,
            108 * 1024
        );
    }
}

/// Guards the one property card R1's second run proved was missing: that a
/// selector-private evidence build reports *which* init failure it hit.
///
/// The status dispatch in `main.rs` selects on features, and its production arm
/// is a negated default. A new selector that does not name a status therefore
/// inherits `FatalRebootRequired` silently -- one value standing for all
/// thirty-two `InitError` categories -- and the defect stays invisible until a
/// run fails and proves nothing. This reads the crate's own manifest rather than
/// a hand-kept list, so the check cannot drift from the features that exist.
#[cfg(test)]
mod selector_status_coverage {
    /// Selectors that predate this rule and still collapse to
    /// `FatalRebootRequired` at the pre-READY boundary. They are accepted or
    /// frozen products: giving them a cause-preserving status changes their
    /// binaries and therefore their product identity, which is not card R1's to
    /// do. Recorded as debt so the check still fails closed for new work.
    const KNOWN_COLLAPSING: [&str; 4] = [
        "dw1e3-selector31",
        "wyr1d-selector32",
        "wyr1e-selector33",
        "wyr1e8-selector33",
    ];

    /// Features that switch on a runtime evidence surface but are never built
    /// as a selector on their own: they are composed into one that is. Selector
    /// 29 is `wyr1c6-production` plus `wyr1c6-test-evidence`, and the status is
    /// gated on the composed name, so the component must not be required to
    /// carry one itself.
    const COMPONENT_FEATURES: [&str; 1] = ["wyr1c6-test-evidence"];

    /// Selector features whose names predate the `*-selector<N>` convention.
    /// These are selectors 25 and 27, and both do name a status.
    const LEGACY_SELECTORS: [&str; 2] = ["wyr1-test-evidence", "wyr1b-test-evidence"];

    const MANIFEST: &str = include_str!("../Cargo.toml");
    const MAIN: &str = include_str!("main.rs");

    /// Just the pre-READY status dispatch, not all of `main.rs`.
    ///
    /// Scoping matters: every selector also appears in `main.rs` as a
    /// `#[cfg(feature = ...)] use ... as _;` line, so searching the whole file
    /// would let an import stand in for a status arm and this check would pass
    /// for a selector that still collapses.
    fn dispatch(main: &str) -> &str {
        let start = main
            .find("match result {")
            .expect("main dispatches on the init result");
        let rest = &main[start..];
        let end = rest
            .find("fn continue_resident")
            .expect("the dispatch ends before the resident hook");
        let region = &rest[..end];
        // If the dispatch moves, fail loudly rather than searching an empty
        // region and silently passing.
        assert!(
            region.contains("fatal_application_status"),
            "the status dispatch no longer looks like itself; re-anchor this check"
        );
        region
    }

    /// True when `dispatch` gates on exactly this feature name. Compares the
    /// whole name so `wyr1e-selector33` cannot be satisfied by
    /// `wyr1e8-selector33`.
    fn names_feature(dispatch: &str, selector: &str) -> bool {
        const NEEDLE: &str = "feature = \"";
        let mut rest = dispatch;
        while let Some(index) = rest.find(NEEDLE) {
            let after = &rest[index + NEEDLE.len()..];
            if let Some(end) = after.find('"')
                && &after[..end] == selector
            {
                return true;
            }
            rest = after;
        }
        false
    }

    /// True when the selector appears as a *positive* condition of this one-line
    /// `cfg`, rather than inside a `not(...)`.
    fn positively_gated(attribute: &str, selector: &str) -> bool {
        attribute
            .split("not(")
            .next()
            .is_some_and(|positive| names_feature(positive, selector))
    }

    /// True when the dispatch answers this selector by returning a status other
    /// than the coarse production one.
    ///
    /// Merely naming the selector is not enough, and this is the distinction the
    /// check turns on: the negated production arm lists every selector that must
    /// *not* reach `fatal_application_status`, so a selector can be named all
    /// over the dispatch and still collapse. What matters is that some arm
    /// positively gated on it returns something else.
    fn preserves_category(dispatch: &str, selector: &str) -> bool {
        let mut lines = dispatch.lines();
        while let Some(line) = lines.next() {
            let line = line.trim();
            if !line.starts_with("#[cfg(") || !positively_gated(line, selector) {
                continue;
            }
            for next in lines.by_ref() {
                let next = next.trim();
                if next.is_empty() || next.starts_with('#') || next.starts_with("//") {
                    continue;
                }
                return next.contains("return") && !next.contains("fatal_application_status");
            }
        }
        false
    }

    /// Visits every feature whose definition turns on a selector-private
    /// evidence surface in the runtime. That dependency feature is what makes a
    /// build selector-private, so it is the honest definition of "must preserve
    /// its failure category".
    fn for_each_evidence_selector(manifest: &str, mut visit: impl FnMut(&str)) {
        let features = manifest
            .split("[features]")
            .nth(1)
            .expect("system-init declares features");
        let features = features
            .split("\n[")
            .next()
            .expect("the features section ends");
        let mut name: Option<&str> = None;
        let mut evidence = false;
        for line in features.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((left, right)) = line.split_once('=') {
                if let Some(previous) = name
                    && evidence
                {
                    visit(previous);
                }
                name = Some(left.trim());
                evidence = right.contains("-test-evidence");
            } else if line.contains("-test-evidence") {
                evidence = true;
            }
        }
        if let Some(previous) = name
            && evidence
        {
            visit(previous);
        }
    }

    #[test]
    fn every_evidence_selector_either_preserves_its_category_or_is_recorded_debt() {
        let mut saw_selector_34 = false;
        for_each_evidence_selector(MANIFEST, |selector| {
            if selector == "r1-selector34" {
                saw_selector_34 = true;
            }
            if COMPONENT_FEATURES.contains(&selector) {
                return;
            }
            // Fail closed on a name that is neither a recognised selector
            // spelling nor a declared component, so a future feature cannot slip
            // past this check by being named something new.
            assert!(
                selector.contains("selector") || LEGACY_SELECTORS.contains(&selector),
                "{selector} enables a runtime evidence surface but is neither a \
                 *-selector<N> feature nor a declared component; classify it in \
                 COMPONENT_FEATURES or LEGACY_SELECTORS so this check keeps \
                 meaning something."
            );
            if KNOWN_COLLAPSING.contains(&selector) {
                return;
            }
            assert!(
                preserves_category(dispatch(MAIN), selector),
                "{selector} is a selector-private evidence build but names no \
                 failure status in main.rs, so every InitError would collapse to \
                 FatalRebootRequired. Add a status that preserves the category, \
                 or record it in KNOWN_COLLAPSING with the reason."
            );
        });
        // If this trips, the manifest parse stopped matching the manifest and
        // the check above proved nothing.
        assert!(
            saw_selector_34,
            "selector 34 was not seen as an evidence build"
        );
    }

    #[test]
    fn the_recorded_debt_is_real_and_not_stale() {
        for selector in KNOWN_COLLAPSING {
            assert!(
                MANIFEST.contains(selector),
                "{selector} is recorded as collapsing but no longer exists"
            );
            assert!(
                !preserves_category(dispatch(MAIN), selector),
                "{selector} now names a status in main.rs; remove it from \
                 KNOWN_COLLAPSING rather than leaving the debt recorded"
            );
        }
    }

    #[test]
    fn the_needle_match_is_exact_and_not_a_prefix() {
        let sample = "#[cfg(feature = \"wyr1e8-selector33\")]";
        assert!(names_feature(sample, "wyr1e8-selector33"));
        assert!(!names_feature(sample, "wyr1e-selector33"));
        assert!(!names_feature(sample, "wyr1e8"));
    }

    #[test]
    fn being_named_in_the_negated_production_arm_does_not_count() {
        // This is the shape that made an earlier version of this check pass for
        // a selector whose status arm had been deleted.
        let fallback = "\
#[cfg(not(any(\n\
    feature = \"wyr1-test-evidence\",\n\
    feature = \"r1-selector34\"\n\
)))]\n\
return fatal_application_status(&error) as u32;\n";
        assert!(!preserves_category(fallback, "r1-selector34"));

        let arm = "\
#[cfg(feature = \"r1-selector34\")]\n\
return r1_test_failure_application_status(&error);\n";
        assert!(preserves_category(arm, "r1-selector34"));

        // A selector excluded by a sibling arm's not(...) must not be credited
        // to that arm, but must still be credited to its own.
        let composed = "\
#[cfg(all(feature = \"wyr1-test-evidence\", not(feature = \"wyr1b-test-evidence\")))]\n\
return wyr1_test_failure_application_status(&error);\n";
        assert!(preserves_category(composed, "wyr1-test-evidence"));
        assert!(!preserves_category(composed, "wyr1b-test-evidence"));
    }
}

#[cfg(all(test, feature = "r1-selector34"))]
mod r1_failure_status_tests {
    use super::*;

    /// A refused record must reach the host as which refusal, with its numbers.
    ///
    /// Run 6's `0xAF340001` could have been any of six refusals at any of
    /// fourteen sites. These assertions are the difference between that and a
    /// status that names the check and the values that failed it.
    #[test]
    fn every_relay_refusal_keeps_its_own_numbers_and_stays_distinct() {
        use crate::r1_relay::RelayError;
        use wyrmroot_r1_saturation::record::HeaderError;

        let status = |error| r1_test_failure_application_status(&InitError::R1Relay(error));

        // The two refusals that carry numbers must carry them intact.
        assert_eq!(
            status(RelayError::OutOfOrder {
                expected: 3,
                observed: 7,
            }),
            0xAF38_40c7
        );
        assert_eq!(
            status(RelayError::WrongTopology {
                online_cpus: 1,
                hog_count: 3,
            }),
            0xAF38_3043
        );
        // Saturation, not truncation: a wild count must not read as a small one.
        assert_eq!(
            status(RelayError::OutOfOrder {
                expected: u64::MAX,
                observed: 64,
            }),
            0xAF38_4fff
        );

        let cases = [
            RelayError::Malformed(HeaderError::WrongLength),
            RelayError::Malformed(HeaderError::WrongMagic),
            RelayError::Malformed(HeaderError::UnsupportedVersion),
            RelayError::Malformed(HeaderError::SizeMismatch),
            RelayError::Malformed(HeaderError::UnknownKind),
            RelayError::Malformed(HeaderError::ZeroSequence),
            RelayError::Malformed(HeaderError::ZeroNonce),
            RelayError::UnexpectedHandles,
            RelayError::WrongTopology {
                online_cpus: 1,
                hog_count: 3,
            },
            RelayError::OutOfOrder {
                expected: 1,
                observed: 2,
            },
            RelayError::AfterTerminal,
            RelayError::Full,
        ];
        for (index, error) in cases.iter().enumerate() {
            let mine = status(*error);
            // No refusal may collide with another, nor with the category space
            // every other pre-READY failure reports through.
            assert_ne!(
                mine & 0xffff_0000,
                0xAF34_0000,
                "a relay refusal fell back into the collapsed category space"
            );
            for other in &cases[index + 1..] {
                assert_ne!(
                    mine,
                    status(*other),
                    "two relay refusals share one terminal status"
                );
            }
        }
    }

    #[test]
    fn every_category_survives_the_pre_ready_boundary_distinctly() {
        // The point of the status is that different failures read differently.
        // Two categories mapping to one value would put us back where run 2 was.
        let cases = [
            (InitError::WrongManifestProfile, 0xAF34_0001),
            (InitError::UnlaunchableRole, 0xAF34_0002),
            (InitError::WrongActivationOrder, 0xAF34_0003),
            (InitError::NonExecutableRole, 0xAF34_000b),
            (InitError::ZeroBootGeneration, 0xAF34_000d),
            (InitError::Supervision, 0xAF34_0014),
            (InitError::Cleanup, 0xAF34_0015),
            (InitError::Accounting, 0xAF34_0016),
        ];
        for (error, expected) in &cases {
            assert_eq!(
                r1_test_failure_application_status(error),
                *expected,
                "{error:?} lost its category"
            );
        }
        // Pairwise, so the check needs no allocation in this no_std crate.
        let mut outer = 0;
        while outer < cases.len() {
            let mut inner = outer + 1;
            while inner < cases.len() {
                assert_ne!(
                    r1_test_failure_application_status(&cases[outer].0),
                    r1_test_failure_application_status(&cases[inner].0),
                    "two categories collided"
                );
                inner += 1;
            }
            outer += 1;
        }
    }

    #[test]
    fn a_native_failure_keeps_the_status_that_says_which_syscall_refused() {
        // DW_STATUS_NO_RESOURCES is what run 1 turned on, so it is the case
        // worth pinning: the code must survive, not become a bare "native".
        let error = InitError::Native(NativeError::Status(deepwyrm_syscall::DwStatus(-13)));
        assert_eq!(r1_test_failure_application_status(&error), 0xAF35_000d);
        let output = InitError::Native(NativeError::Output(
            wyrmroot_runtime::NativeOutputError::InvalidChannelReceive,
        ));
        assert_eq!(r1_test_failure_application_status(&output), 0xAF35_8003);
    }

    #[test]
    fn the_r1_bases_cannot_be_confused_with_another_selectors() {
        // Deepwyrm reports selector 34's code unsummarized, so a base shared
        // with another selector would be genuinely ambiguous in a transcript.
        for existing in [
            0xAF01_0000_u32,
            0xAF11_0000,
            0xAF18_0000,
            0xAF1B_0000,
            0xAF1C_0000,
            0xAF1D_0000,
        ] {
            for mine in [0xAF34_0000_u32, 0xAF35_0000, 0xAF36_0000] {
                assert_ne!(existing, mine);
            }
        }
        // And the coarse production value must no longer be reachable here.
        assert_ne!(
            r1_test_failure_application_status(&InitError::Supervision),
            InitApplicationStatus::FatalRebootRequired as u32
        );
    }

    #[test]
    fn a_fatal_resident_tick_also_keeps_its_category() {
        assert_eq!(
            resident_tick_failure_application_status(&InitError::Supervision),
            0xAF36_0014
        );
        assert_ne!(
            resident_tick_failure_application_status(&InitError::Cleanup),
            0xAF01_0006
        );
    }
}

/// Guards what card R1's audit found after three runs: an artifact the product
/// stages but nothing consumes.
///
/// R1's bootfs carries the saturation probe and a `WRR1` gate describing it, and
/// neither had a reader anywhere in permanent init. Nothing failed a test,
/// because no test related what the product stages to what init looks up — so
/// the product booted, activated its role graph, and would have idled until the
/// host timeout with no evidence. That failure is indistinguishable from the A27
/// stall this card exists to investigate, which is what makes it worth a gate.
#[cfg(test)]
mod r1_composition_coverage {
    /// Paths R1 stages whose consumer is not written yet. Emptying this list was
    /// the definition of done for the selector-34 scenario driver: it must look
    /// the gate up, launch the probe, and relay the probe's records.
    ///
    /// It is now empty, and `r1_driver` is the consumer of both paths.
    const KNOWN_UNWIRED: [&str; 0] = [];

    /// Everything permanent init could plausibly look a path up from.
    /// `r1_driver.rs` joined this list with the driver it gates.
    const SOURCES: [&str; 4] = [
        include_str!("lib.rs"),
        include_str!("main.rs"),
        include_str!("r1_driver.rs"),
        include_str!("r1_relay.rs"),
    ];

    /// A path is consumed when some source names the bootfs constant that
    /// carries it, not only when a copy of the literal appears.
    ///
    /// The literal spelling stays accepted because that is what a wrong local
    /// copy would look like, and this gate should keep finding one; but a driver
    /// that correctly looks the path up through `wyrmroot_bootfs::r1` never
    /// contains the literal at all, so requiring it would have forced exactly
    /// the duplicated constant the archive builder exists to prevent.
    fn any_source_mentions(path: &str, constant: &str) -> bool {
        SOURCES
            .iter()
            .any(|source| source.contains(path) || source.contains(constant))
    }

    /// Each staged path with the constant permanent init must reach it through.
    const STAGED: [(&str, &str); 2] = [
        (wyrmroot_bootfs::r1::R1_PROBE_PATH, "R1_PROBE_PATH"),
        (wyrmroot_bootfs::r1::R1_GATE_PATH, "R1_GATE_PATH"),
    ];

    #[test]
    fn every_path_r1_stages_is_either_consumed_or_recorded_as_unwired() {
        for (path, constant) in STAGED {
            if KNOWN_UNWIRED.contains(&path) {
                continue;
            }
            assert!(
                any_source_mentions(path, constant),
                "{path} is staged in card R1's bootfs but permanent init never \
                 looks it up, so the product would boot and produce no evidence. \
                 Consume it, or record it in KNOWN_UNWIRED with the reason."
            );
        }
    }

    #[test]
    fn the_unwired_list_is_real_and_shrinks_rather_than_rots() {
        for path in KNOWN_UNWIRED {
            let constant = STAGED
                .iter()
                .find_map(|(staged, constant)| (*staged == path).then_some(*constant))
                .unwrap_or_default();
            assert!(
                !any_source_mentions(path, constant),
                "{path} now has a consumer in permanent init; remove it from \
                 KNOWN_UNWIRED so the gate starts protecting it"
            );
        }
        // The relay was the other half of the same gap: it existed, it was host
        // tested, and in the product nothing called it. The driver has now
        // landed, so the bound rises from "declaration only" to "declaration
        // plus exactly the driver's one call site": `r1_driver::drain` relays
        // each datagram, and a second caller would mean two places decide
        // custody of the same transcript, which is what this bound still
        // forbids. KNOWN_UNWIRED is empty, re-checked with this change.
        let called = SOURCES
            .iter()
            .filter(|source| source.contains("relay_one("))
            .count();
        assert!(
            called <= 2,
            "relay_one has more callers than its own module and the scenario \
             driver; two places now decide custody of one transcript"
        );
        assert!(
            SOURCES[2].contains("relay_one("),
            "the scenario driver no longer relays the probe's records, so a \
             running probe's transcript cannot reach the kernel collector"
        );
    }
}

/// Card R1's third repetition of one defect, gated instead of patched again.
///
/// Three runs of this card failed with a status that proved something had gone
/// wrong and nothing about where:
///
/// - run 2 (`0xAF010002`): `fatal_application_status(_error)` discarded its
///   argument, collapsing every `InitError` category into one value;
/// - run 5 (`0xAF340014`): two unrelated driver sites returned
///   `InitError::Supervision`, both discarding the probe's own exit code;
/// - run 6 (`0xAF340001`): `InitError::WrongManifestProfile`, returned from
///   fourteen sites in `r1_driver.rs` alone, one of which
///   (`Err(RelayFailure::Refused(_))`) threw away a `RelayError` carrying the
///   exact expected and observed sequence numbers.
///
/// Each of the first two was fixed correctly at its own site, and the next run
/// was undiagnosable anyway. `AGENTS.md` §1 requires that the third occurrence of
/// one failure class be classified rather than patched a third time, so this
/// module states the class as an invariant over the source of the terminal-status
/// path: **a cause that was carried to a boundary must not be dropped at it.**
///
/// The rules read source text for the same reason
/// `selector_class_membership.rs` does: the defect is an *absence* — a payload
/// that is never read — so nothing about a correct build fails, and no type can
/// express "this discard was not deliberate".
#[cfg(all(test, feature = "r1-selector34"))]
mod r1_cause_preservation {
    /// The files a selector-34 terminal status can be produced from. `lib.rs`
    /// carries the encoders, the other two the driver and its relay.
    const SOURCES: [(&str, &str); 3] = [
        ("r1_driver.rs", include_str!("r1_driver.rs")),
        ("r1_relay.rs", include_str!("r1_relay.rs")),
        ("lib.rs", include_str!("lib.rs")),
    ];

    /// Error types on this path whose variants carry a cause worth keeping.
    ///
    /// Curated rather than derived: the rule needs to know that discarding a
    /// `RelayFailure` loses `OutOfOrder { expected, observed }` while discarding
    /// a unit-like marker loses nothing. `the_curated_types_still_exist` fails if
    /// one is renamed out from under the list.
    const PAYLOAD_BEARING: [&str; 6] = [
        "RelayFailure",
        "RelayError",
        "ObservedSupervisionError",
        "SupervisionError",
        "LoadError",
        "ExitValidationError",
    ];

    /// Sites that drop a carried cause and are not yet fixed.
    ///
    /// Keyed on the exact trimmed source line so the entry rots visibly when the
    /// line changes, rather than drifting with line numbers. This list may
    /// **shrink and never grow**: a new discard is the fourth occurrence of the
    /// class, which is precisely what this module exists to refuse.
    ///
    /// Every entry is a live defect, not an exemption. Each would erase the cause
    /// of a future run exactly as runs 2, 5 and 6 did.
    const KNOWN_DISCARDS: [(&str, &str); 5] = [
        (
            ".map_err(|_| InitError::Supervision)?;",
            "lib.rs `activate_retained_bootfs_state`: the bootstrap-retirement \
             wait loses the native status of a refused or timed-out wait, and \
             reports selector 34's `0xAF340014` -- run 5's exact status -- from a \
             site earlier than the driver. Shared by every selector, so carrying \
             the cause changes other products' statuses and needs a \
             cross-selector pass rather than a local edit.",
        ),
        (
            ".map_err(|_| InitError::WrongManifestProfile)?;",
            "gate lookup: the bootfs error naming which entry is missing is lost",
        ),
        (
            ".map_err(|_| InitError::WrongManifestProfile)",
            "argv encoding: loses which field would not fit",
        ),
        (
            "let configuration = parse_gate(gate.data()).map_err(|_| InitError::WrongManifestProfile)?;",
            "gate parse: loses the WRR1 field that failed validation",
        ),
        (
            "system.close_handle(group).map_err(|_| InitError::Cleanup)?;",
            "teardown: loses the native status of the refused close",
        ),
    ];

    /// Payload-free `InitError` variants returned from more than one site in the
    /// driver, with the count at the time this gate was written.
    ///
    /// A payload-free variant returned from many sites is the run-6 defect
    /// directly: fourteen distinct causes arriving as `0xAF340001`. The counts
    /// may only fall.
    const KNOWN_COLLAPSING: [(&str, &str, usize); 2] = [
        (
            "WrongManifestProfile",
            "InitError::WrongManifestProfile",
            13,
        ),
        ("Cleanup", "InitError::Cleanup", 7),
    ];

    /// Variants that carry a cause the selector-34 encoder does not surface.
    ///
    /// `r1_test_failure_application_status` gives `Native` and `R1Probe` their
    /// own bases; every other payload-bearing variant reaches the host as a bare
    /// category, so the payload is carried the whole way and dropped at the last
    /// step. The counts may only fall.
    const KNOWN_UNSURFACED: [&str; 5] = [
        "InitError::Bootfs",
        "InitError::Mapping",
        "InitError::Loader",
        "InitError::RegistryProtocol",
        "InitError::Wyr1BModel",
    ];

    /// Lines that convert one error into another while discarding the original.
    ///
    /// Two forms, both taken from real defects on this card:
    /// `map_err(|_| …)` (runs 2 and 5) and a match arm that discards a
    /// payload-bearing variant and produces an `InitError` (run 6).
    fn discards_a_cause(line: &str) -> bool {
        let trimmed = line.trim();
        // Comments, and string literals -- which is what this module's own
        // fixtures and its KNOWN_DISCARDS entries are. Without the literal skip
        // the gate reports its own test data as defects, and a finding could be
        // silenced by editing a fixture rather than by fixing the code.
        if trimmed.starts_with("//") || trimmed.starts_with('"') {
            return false;
        }
        if trimmed.contains("map_err(|_|") {
            return true;
        }
        discards_a_binding(trimmed)
            && trimmed.contains("InitError::")
            && PAYLOAD_BEARING.iter().any(|name| trimmed.contains(name))
    }

    /// Whether a line binds a payload only to throw it away.
    ///
    /// Both spellings count. `(_)` is run 6's form; `(_error)` is run 2's -- the
    /// `fatal_application_status(_error)` that started this class, and which an
    /// earlier draft of this rule missed because it looked only for `(_)`. A
    /// leading underscore on a bound payload means the compiler was told to stop
    /// asking, which is the whole defect.
    fn discards_a_binding(line: &str) -> bool {
        let bytes = line.as_bytes();
        for (at, window) in bytes.windows(2).enumerate() {
            if window != b"(_" {
                continue;
            }
            match bytes.get(at + 2) {
                Some(b')') => return true,
                Some(next) if next.is_ascii_alphanumeric() || *next == b'_' => return true,
                _ => {}
            }
        }
        false
    }

    /// Source with its test modules removed.
    ///
    /// Tests legitimately construct and match errors they do not care about, and
    /// counting those would make the collapse budget meaningless. This module's
    /// own fixtures are the sharper reason: they quote real defect lines
    /// verbatim, so scanning them would report the gate's own test data as
    /// defects -- and would let someone silence a finding by editing a fixture.
    fn without_tests(source: &str) -> &str {
        // Only a trailing `mod tests` block is cut. Truncating at the first
        // `#[cfg(test)]` was tried and was wrong: `lib.rs` carries inline test
        // modules throughout, so it hid every real site below the first one --
        // including the `activate_retained_bootfs_state` discard this gate found.
        match source.find("\nmod tests {") {
            Some(at) => &source[..at],
            None => source,
        }
    }

    /// Every discarding line across the scanned sources, as an iterator: this
    /// crate is `no_std` with no allocator, so the scan cannot collect.
    /// This module's own marker in `lib.rs`. Everything from here down is the
    /// gate itself, whose detector literals and declared defect lines are not
    /// code under test.
    const SELF_MARKER: &str = "\nmod r1_cause_preservation {";

    /// `lib.rs` with this module removed.
    ///
    /// Skipping comments and quoted fixtures was not enough: the detector's own
    /// `contains("map_err(|_|")` sits mid-line in ordinary code and matched
    /// itself. A gate that reads the file it lives in has to excise itself, and
    /// `the_self_exclusion_is_real` fails if the marker stops matching.
    fn without_self(source: &str) -> &str {
        match source.find(SELF_MARKER) {
            Some(at) => &source[..at],
            None => source,
        }
    }

    fn offending_lines() -> impl Iterator<Item = (&'static str, &'static str)> {
        SOURCES.into_iter().flat_map(|(name, source)| {
            without_tests(without_self(source))
                .lines()
                .map(str::trim)
                .filter(|line| discards_a_cause(line))
                .map(move |line| (name, line))
        })
    }

    /// The rule itself, proven against the real defect rather than only against
    /// the current tree: if this ever stops firing on run 6's own line, the gate
    /// has been disabled whatever else it reports.
    #[test]
    fn the_rule_fires_on_the_defects_it_was_written_for() {
        for line in [
            "            Err(RelayFailure::Refused(_)) => return Err(InitError::WrongManifestProfile),",
            "        .map_err(|_| InitError::Supervision)",
            "            .map_err(|_| InitError::WrongManifestProfile)?;",
            "        ObservedSupervisionError::Supervision(_) => return Err(InitError::Supervision),",
            // Run 2's spelling: a bound payload silenced with a leading
            // underscore. An earlier draft of this rule missed it.
            "            Err(RelayFailure::Refused(_error)) => Err(InitError::WrongManifestProfile),",
            "        Err(LoadError::Native(_e)) => Err(InitError::WrongManifestProfile),",
        ] {
            assert!(
                discards_a_cause(line),
                "the cause-preservation rule does not fire on a known defect: {line}"
            );
        }
        // And it must not fire on the shapes that keep the cause, or the gate
        // would be unusable and would be switched off rather than obeyed.
        for line in [
            "        .map_err(InitError::Native)?;",
            "            .map_err(|error| InitError::R1Probe(probe_failure_before_ready(&error)))",
            "                    Ok(_) => R1ProbeFailure::DrainUnattributed,",
            "            // map_err(|_| InitError::Cleanup) is what this forbids",
        ] {
            assert!(
                !discards_a_cause(line),
                "the rule fires on a shape that preserves its cause: {line}"
            );
        }
    }

    #[test]
    fn no_new_site_drops_a_carried_cause() {
        // Self-check: the scan must actually be reading source. A rename or an
        // emptied include would otherwise make this pass by finding nothing.
        // Exact, not a lower bound. Keying the allowlist on line text means a
        // second copy of an allowed line would otherwise be admitted for free --
        // which is how a fourteen-site collapse grows one paste at a time. Too
        // few, and the scan has stopped reading the sources it names.
        let seen = offending_lines().count();
        assert_eq!(
            seen,
            KNOWN_DISCARDS.len(),
            "the scan found {seen} cause-discarding lines and {} are declared. \
             More means a new discard, or a second copy of a declared one; fewer \
             means the scan is no longer reading these sources, or a site was \
             fixed without shrinking KNOWN_DISCARDS",
            KNOWN_DISCARDS.len()
        );
        for (file, line) in offending_lines() {
            assert!(
                KNOWN_DISCARDS.iter().any(|(known, _)| *known == line),
                "{file} drops a carried cause at a site this gate does not know:\n  \
                 {line}\nThis is the fourth occurrence of card R1's recurring \
                 defect class. Carry the cause into the status instead of \
                 declaring it here."
            );
        }
    }

    #[test]
    fn the_discard_list_shrinks_rather_than_rots() {
        for (known, reason) in KNOWN_DISCARDS {
            assert!(
                offending_lines().any(|(_, line)| line == known),
                "KNOWN_DISCARDS still lists a site that no longer exists, so the \
                 list describes a tree that is gone: {known} ({reason})"
            );
            assert!(
                !reason.is_empty(),
                "every declared discard states what cause it loses"
            );
        }
    }

    #[test]
    fn the_self_exclusion_is_real() {
        let lib = include_str!("lib.rs");
        assert!(
            lib.contains(SELF_MARKER),
            "this module's own marker no longer matches, so the gate is either \
             scanning itself or excising the wrong region"
        );
        // The excision must remove this module and nothing above it: the
        // `activate_retained_bootfs_state` discard lives far earlier in the file
        // and must still be scanned. Losing it is how the first attempt at this
        // exclusion silently hid every real site in `lib.rs`.
        let scanned = without_self(lib);
        assert!(
            scanned.contains("fn activate_retained_bootfs_state"),
            "the self-exclusion cut away real code above this module"
        );
        assert!(
            !scanned.contains("fn discards_a_cause"),
            "the self-exclusion did not remove this module's own detector"
        );
    }

    #[test]
    fn the_curated_types_still_exist() {
        // The payload-bearing list is the rule's whole notion of "a cause worth
        // keeping". If a type is renamed and the list is not, the rule silently
        // narrows, which is how a gate stops gating without failing.
        for name in PAYLOAD_BEARING {
            assert!(
                SOURCES.iter().any(|(_, source)| source.contains(name)),
                "{name} is named in PAYLOAD_BEARING but appears in none of the \
                 sources, so the rule no longer recognises it"
            );
        }
    }

    #[test]
    fn the_collapse_budget_only_falls() {
        let driver = without_tests(include_str!("r1_driver.rs"));
        for (variant, pattern, recorded) in KNOWN_COLLAPSING {
            let count = driver.matches(pattern).count();
            assert!(
                count > 0,
                "{variant} is recorded as collapsing but is never returned; \
                 remove it from KNOWN_COLLAPSING"
            );
            assert!(
                count <= recorded,
                "{variant} is now returned from {count} driver sites, up from \
                 {recorded}. A payload-free variant returned from many sites is \
                 run 6's defect: fourteen causes arriving as one status. Give it \
                 a payload or reuse an existing site."
            );
        }
    }

    #[test]
    fn the_unsurfaced_list_names_real_variants() {
        let lib = include_str!("lib.rs");
        for variant in KNOWN_UNSURFACED {
            assert!(
                lib.contains(variant),
                "{variant} is recorded as carrying an unsurfaced cause but is not \
                 an InitError variant any more"
            );
        }
        // `Native` and `R1Probe` are the two the encoder does surface. If either
        // stopped being special-cased, every cause on this path would collapse
        // again and this list would be describing the wrong problem.
        for surfaced in [
            "InitError::Native(error) => 0xAF35_0000",
            "R1ProbeFailure::ExitCode(code)) => 0xAF37_0000",
            "InitError::R1Relay(error) => 0xAF38_0000",
        ] {
            assert!(
                lib.contains(surfaced),
                "the selector-34 encoder no longer surfaces a cause it used to: \
                 {surfaced}"
            );
        }
    }
}
