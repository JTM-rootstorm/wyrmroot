//! Permanent WYR1-A supervisor policy and native startup boundary.
//!
//! The fixed controller composes `RestartSupervisor`; it does not implement a
//! dependency solver or copy restart-policy transitions.

#![no_std]
#![forbid(unsafe_code)]

// The WYR1-E production product is the WYR1-C6 resource product plus the
// shell controller; every selector built on it inherits both. The manifest's
// feature lists say so, and these refuse a build in which one stopped doing so.
#[cfg(all(
    feature = "wyr1e-production",
    not(all(feature = "wyr1c6-production", feature = "wyr1e-shell-controller"))
))]
compile_error!("wyr1e-production must compose wyr1c6-production and wyr1e-shell-controller");

#[cfg(all(feature = "wyr1c6-production", not(feature = "wyr1c5-production")))]
compile_error!("wyr1c6-production must compose the wyr1c5-production resource product");

use core::mem::MaybeUninit;

#[cfg(feature = "wyr1e-production")]
use wyrmroot_consoled as _;
#[cfg(test)]
use {wyrmroot_devmgr as _, wyrmroot_uart16550d as _};

pub mod evidence;
pub mod gate;
mod launch_transaction;
pub mod resident_loop;
pub mod wyr1b;
pub mod wyr1b_gate;
mod wyr1b_job;
pub mod wyr1b_native;
pub mod wyr1c_native;

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

/// What the dispatcher's emergency cleanup did after an initiating error.
///
/// Private diagnostic state, not protocol or application-status ABI. Ordinary
/// supervision state since R7B-2: the selector was never what made a failed
/// cleanup worth reporting, it was only the one build that reported it.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmergencyCleanup {
    NotRun,
    DisconnectFailed,
    Attempted {
        channel_close_failed: bool,
        owner_cleanup_failed: bool,
    },
}

impl EmergencyCleanup {
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

/// The operation that most narrowly returned an error during a bounded
/// recovery transition. Private diagnostic evidence, not protocol or
/// application-status ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
#[allow(
    dead_code,
    reason = "the numbering is a reader's vocabulary, shared across products:               a build with no dependent-retirement or held-wait leg never               reports those operations, and gating the variants per feature               would put back the selector-shaped code R7B-2 removes"
)]
pub(crate) enum RecoveryOperation {
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
    // 0x0f is `UNATTRIBUTED_OPERATION`. Everything below it is a recovery
    // transition and everything above it is a startup step: F3A.6d could
    // locate its failure's site and its status but not the step it happened
    // in, because there was no value left to name one with.
    /// Receiving and validating the retained product before any role runs.
    ReceiveProduct = 0x10,
    /// Mapping the retained bootfs for in-place activation.
    MapRetainedBootfs = 0x11,
    /// The registry role's first launch, before any READY exists.
    ActivateRegistry = 0x12,
    /// The device manager's first launch.
    ActivateDevmgr = 0x13,
    /// The serial driver's first launch.
    ActivateUart = 0x14,
    /// The console role's first launch.
    ActivateConsole = 0x15,
    /// The shell's first launch.
    ActivateShell = 0x16,
    /// An ordinary resident tick after startup completed.
    ResidentTick = 0x17,
    /// A job request on a historical launch session. F3A.7j: the dispatcher's
    /// failures reached COM1 as `0x0f`, so a request that killed permanent
    /// init could not say whose session it came from.
    DispatchHistoricalJob = 0x18,
    /// A job request on the console's launch session.
    DispatchConsoleJob = 0x19,
    /// A job request on a shell's own job session.
    DispatchShellJob = 0x1a,
}

/// Reported when no operation claimed the failure: the error reached the tick
/// boundary without passing through `attribute_failure`.
///
/// Selector 34 encodes tick failures with `test_failure_category`'s 32-value
/// space instead, so the whole 8-kind fallback -- and this constant with it --
/// is compiled out there. Gated rather than `allow`ed: an unused constant under
/// one selector is a fact about which encoding that selector uses, and saying
/// so keeps `-D dead-code` meaningful instead of silencing it.
const UNATTRIBUTED_OPERATION: u8 = 0x0f;

/// One error's own diagnostic instance, or zero where it has nothing to add.
///
/// `failure_kind` answers "what class of thing went wrong" in four bits, which
/// is the caller's question under `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` §2.
/// This answers "which one", which is the reader's, and §3.3 requires it to
/// survive a diagnostic boundary -- a test-completion status is named there as
/// exactly such a boundary. Zero means the error carries no instance.
///
/// Kept across attribution in `RecoveryTransition::payload`, because
/// `attribute_failure` replaces the error it wraps: before F3A.6c the
/// innermost cause was reduced to four bits there, which is the collapse
/// contract §3.2 calls a debt to the reader.
const fn failure_instance(error: &InitError) -> u16 {
    match error {
        // `native_error_code` is the project's own canonical 16-bit encoding:
        // bit 15 distinguishes an output-contract failure from a kernel status
        // and the magnitude saturates below it.
        InitError::Native(error) => wyrmroot_runtime::native_error_code(*error) as u16,
        InitError::AbsentState(site) => *site as u16,
        InitError::RegistryAbandoned(reason) => *reason as u16,
        InitError::SessionShutdown(steps) => *steps as u16,
        InitError::LaunchProtocol(error) => *error as u16,
        // An attributed failure already carries the innermost instance.
        InitError::RecoveryTransition { payload, .. } => *payload,
        _ => 0,
    }
}

const fn failure_kind(error: &InitError) -> u8 {
    match error {
        InitError::WrongActivationOrder => 0x01,
        // A new kind rather than 0x01's: the payload namespaces are per-kind,
        // and sharing 0x01 would make a site number indistinguishable from a
        // native status magnitude. 0x09..=0x0e were unallocated.
        InitError::AbsentState(_) => 0x09,
        // Also its own kind, and for the same reason: the reason code shares
        // no namespace with a site number or a status magnitude. 0x0a..=0x0e
        // were unallocated.
        InitError::RegistryAbandoned(_) => 0x0a,
        // Its own kind for the same reason as the two above: the step mask
        // shares no namespace with a site number, a status magnitude or an
        // abandonment reason. 0x0b..=0x0e remain unallocated.
        InitError::SessionShutdown(_) => 0x0b,
        InitError::Accounting | InitError::Wyr1BModel(_) => 0x02,
        // The retirement wait kept `Supervision`'s meaning when it gained a
        // payload, so selector 33's kind is unchanged by that split. E8 must stay
        // byte-identical to the A27 baseline, and this is what keeps it so.
        InitError::Supervision | InitError::BootstrapRetirement(_) => 0x03,
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
        // A refused launch message is a protocol refusal, which is what 0x06
        // already names for the registry and gate protocols.
        InitError::LaunchProtocol(_) => 0x06,
        InitError::GateConfig(_)
        | InitError::Evidence(_)
        | InitError::Wyr1BGateConfig(_)
        | InitError::Wyr1BEvidence(_) => 0x08,
        InitError::RecoveryTransition {
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

/// Names the operation a failure came from, innermost wins.
///
/// An error that already carries an attribution keeps it, so wrapping an outer
/// step does not overwrite the narrow one that actually failed.
pub(crate) fn attribute_failure<T>(
    operation: RecoveryOperation,
    result: Result<T, InitError>,
) -> Result<T, InitError> {
    result.map_err(|error| match error {
        InitError::RecoveryTransition { .. } => error,
        _ => InitError::RecoveryTransition {
            operation: operation as u8,
            initiating_kind: failure_kind(&error),
            payload: failure_instance(&error),
            emergency_cleanup: EmergencyCleanup::NotRun,
        },
    })
}

pub(crate) fn dispatch_failure(error: InitError, emergency_cleanup: EmergencyCleanup) -> InitError {
    match error {
        InitError::RecoveryTransition {
            operation,
            initiating_kind,
            payload,
            ..
        } => InitError::RecoveryTransition {
            operation,
            initiating_kind,
            payload,
            emergency_cleanup,
        },
        error => InitError::RecoveryTransition {
            operation: 0x0f,
            initiating_kind: failure_kind(&error),
            payload: failure_instance(&error),
            emergency_cleanup,
        },
    }
}

/// Application detail for a fatal resident tick: `AF18SSKK`, where `SS` is the
/// narrow operation that returned `Err` and `KK` its initiating kind. If the
/// dispatcher's emergency cleanup fails, the same operation is reported with
/// kind `04` while the initiating kind stays in the private carrier.
///
/// R7B-2 made this every build's encoding. It used to be E8's alone, and every
/// other build returned the single constant `0xAF01_0006` -- which is the exact
/// reading that stalled A8: the transcript showed a fatal tick and the frozen
/// evidence could not say which operation produced it. That is the collapse
/// `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` §3.2 says owes an instance to the
/// reader's channel, and the process exit status is that channel here. E8's own
/// values are unchanged, so its transcripts stay byte-identical to the A27
/// baseline; `0xAF01_0006` is now unreachable, because operation `0x00` cannot
/// be produced, and so still reads unambiguously as a pre-R7B-2 build.
///
/// Selector 34 keeps its own category encoding: `test_failure_category` is a
/// 32-value space that R1's evidence is written against, not this 8-kind one.
#[must_use]
pub const fn resident_tick_failure_application_status(error: &InitError) -> u32 {
    {
        // Not a wildcard over `InitError` in the sense §3.4 forbids: every
        // variant but this one is named by `failure_kind`, whose match is
        // exhaustive, so a new variant still fails to compile rather than
        // inheriting an arm here.
        let (operation, kind) = match error {
            InitError::RecoveryTransition {
                operation,
                initiating_kind,
                emergency_cleanup,
                ..
            } => (
                *operation,
                if emergency_cleanup.failed() {
                    0x04
                } else {
                    *initiating_kind
                },
            ),
            unattributed => (UNATTRIBUTED_OPERATION, failure_kind(unattributed)),
        };
        // The operation field is eight bits wide at bits 15..8 and always was;
        // until F3A.6e the clamp admitted only four bits of values, which is
        // why the bring-up steps could not be named -- 0x01..=0x0e were all
        // allocated to recovery transitions and 0x0f is the sentinel. Values
        // above the sentinel are the bring-up operations, so every existing
        // status is unchanged and `0x0f` still means "nothing claimed this".
        let operation = match operation {
            0x01..=0xfe => operation,
            _ => UNATTRIBUTED_OPERATION,
        };
        let kind = match kind {
            0x01..=0x0b | 0x0f => kind,
            _ => 0x0f,
        };
        // Three kinds carry an instance, and a sixteen-bit word cannot hold the
        // operation nibble plus a sixteen-bit cause. Per
        // `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` §5 the encoding saturates
        // rather than wraps, and per §3.3 the instance survives: each gets its
        // own tag carrying the operation *and* its cause, in the same shape
        // `wyr1c6_test_failure_application_status` and selector 34's encoder
        // already use for a native status.
        //
        // Every other error keeps `0xAF18_<operation><kind>` byte for byte,
        // which is what holds E8's statuses identical to the A27 baseline.
        let instance = failure_instance(error) as u32;
        // Every instance-bearing tag uses one layout -- `operation` at bits
        // 15..8, the cause's own byte at 7..0 -- so a reader needs one rule
        // rather than one per tag. Eight bits is enough for all three causes:
        // `deepwyrm/abi/schema/status.toml` tops out at magnitude 16 and there
        // are eight `NativeOutputError` variants, so the native byte is
        // lossless across the whole ABI rather than merely usually. The
        // abandoned-registry reason is a small enumeration and needs far less.
        match kind {
            // Bit 7 keeps a malformed-output classification distinguishable
            // from a kernel status; the magnitude saturates at 0x7f, which no
            // status in the schema reaches.
            0x05 => {
                let magnitude = instance & 0x7fff;
                let saturated = if magnitude > 0x7f { 0x7f } else { magnitude };
                0xAF1E_0000
                    | (operation as u32) << 8
                    | if instance & 0x8000 != 0 { 0x80 } else { 0 }
                    | saturated
            }
            // An absent state slot, at the site that found it.
            0x09 => 0xAF1F_0000 | (operation as u32) << 8 | (instance & 0xff),
            // An abandoned registry, with the exit that abandoned it.
            0x0a => 0xAF21_0000 | (operation as u32) << 8 | (instance & 0xff),
            // A session shutdown, with the mask of steps that failed.
            0x0b => 0xAF22_0000 | (operation as u32) << 8 | (instance & 0xff),
            // Kind 0x06 is shared by three protocols, so the tag says which
            // one and the low byte carries the refusal. Only the launch
            // protocol carries an instance here; the other two reach the
            // reader as 0xAF18 and their class, unchanged.
            0x06 if matches!(error, InitError::LaunchProtocol(_)) => {
                0xAF20_0000 | (operation as u32) << 8 | (instance & 0xff)
            }
            _ => 0xAF18_0000 | (operation as u32) << 8 | kind as u32,
        }
    }
}

/// Decodes a tick-failure status back into operation, kind and instance.
///
/// In source and under test because the layout is a contract, not a comment:
/// four tags share one function and a reader holding a transcript needs to
/// know which one they are looking at.
///
/// Returns `None` for a word this encoder never produces.
#[must_use]
pub const fn decode_tick_failure(status: u32) -> Option<TickFailure> {
    match status >> 16 {
        0xAF18 => Some(TickFailure {
            operation: ((status >> 8) & 0xff) as u8,
            kind: (status & 0x0f) as u8,
            instance: 0,
            saturated: false,
        }),
        0xAF1E => Some(TickFailure {
            operation: ((status >> 8) & 0xff) as u8,
            kind: 0x05,
            instance: (status & 0x7f) as u16 | if status & 0x80 != 0 { 0x8000 } else { 0 },
            saturated: status & 0x7f == 0x7f,
        }),
        0xAF1F => Some(TickFailure {
            operation: ((status >> 8) & 0xff) as u8,
            kind: 0x09,
            instance: (status & 0xff) as u16,
            saturated: false,
        }),
        0xAF20 => Some(TickFailure {
            operation: ((status >> 8) & 0xff) as u8,
            kind: 0x06,
            instance: (status & 0xff) as u16,
            saturated: false,
        }),
        0xAF21 => Some(TickFailure {
            operation: ((status >> 8) & 0xff) as u8,
            kind: 0x0a,
            instance: (status & 0xff) as u16,
            saturated: false,
        }),
        0xAF22 => Some(TickFailure {
            operation: ((status >> 8) & 0xff) as u8,
            kind: 0x0b,
            instance: (status & 0xff) as u16,
            saturated: false,
        }),
        _ => None,
    }
}

/// One decoded tick-failure status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TickFailure {
    /// `RecoveryOperation`, or `0x0f` when nothing claimed the failure.
    pub operation: u8,
    /// `failure_kind`'s four-bit class.
    pub kind: u8,
    /// The cause's own value, or zero where the kind carries none.
    pub instance: u16,
    /// Whether `instance` reached its encoding's limit and may be larger.
    pub saturated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum MappingDiagnosticSite {
    RoleRemap = 1,
    JobDispatcher = 2,
    RegistryReplacement = 3,
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
    /// Whether the interactive session ended and nothing replaces it.
    ///
    /// F3A.7g. Permanent init's loop has no other way out: every exit from it
    /// is a failure status, because a supervisor that stops supervising was
    /// previously always a supervisor that broke. A console child that ends
    /// the session is the one case where there is nothing left to supervise,
    /// and this is how that reaches the loop.
    session_complete: bool,
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
    /// Whether the interactive session ended. Once true it stays true: there
    /// is no console generation after the one that ended the session.
    pub const fn session_complete(&self) -> bool {
        self.session_complete
    }

    #[cfg(feature = "wyr1e-production")]
    pub(crate) const fn observe_session_complete(&mut self) {
        self.session_complete = true;
    }

    pub const fn evidence_finalized(&self) -> bool {
        self.evidence_finalized
    }

    /// Returns one completed selector-27 evidence record. Selector 25 and
    /// incomplete selector-27 attempts expose no WRB1 record.
    #[must_use]
    pub fn wyr1b_evidence_record(&self, index: usize) -> Option<&[u8; wyr1b_gate::RECORD_BYTES]> {
        self.wyr1b_evidence.as_ref()?.record_at(index)
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
        // Attributed as an ordinary resident tick, so a failure here is
        // distinguishable from one during startup. `attribute_failure` keeps
        // an inner attribution, so a recovery transition that already named
        // itself is not overwritten by this outer one.
        let observed = if self.wyr1c.is_some() {
            wyr1c_native::control_tick(self, system, loader, waits, now_ns)
        } else if self.wyr1b.is_none() {
            self.control_tick(system, loader, waits, now_ns)
        } else {
            wyr1b_native::control_tick(self, system, loader, waits, now_ns)
        };
        attribute_failure(RecoveryOperation::ResidentTick, observed)
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
    Launch(wyrmroot_loader::launch::LaunchError),
    /// A launch-protocol message refused parsing, with the reason it refused.
    ///
    /// Both sites that parse one used to report `InitError::Accounting`, which
    /// was not merely a collapse under
    /// `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` §3.1 but the wrong class: a
    /// malformed request is a protocol refusal, and kind 0x02 sent a reader
    /// looking at resource accounting. Twenty-three distinct reasons reached
    /// that one value.
    LaunchProtocol(wyrmroot_launch_proto::Error),
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
    /// A bounded recovery transition failed, naming the operation it failed in.
    /// An expected state slot was absent, at the numbered site that found it.
    ///
    /// Every one of these used to be `WrongActivationOrder`, which is raised
    /// at roughly two hundred sites across six files and carries four bits.
    /// Two different meanings were sharing it: `return Err(..)` guards, which
    /// are genuine ordering violations, and `.ok_or(..)` on a state `Option`,
    /// which says some slot the caller expected to be populated was not. The
    /// second is now this, with a site number, so a transcript can say which
    /// slot.
    ///
    /// Sites are allocated in stable per-file ranges rather than one global
    /// sequence, so inserting one does not renumber the rest:
    ///
    /// | range | file |
    /// | --- | --- |
    /// | `0x01..=0x0f` | `lib.rs` |
    /// | `0x10..=0x7f` | `wyr1c_native.rs` |
    /// | `0x80..=0xbf` | `wyr1e_native.rs` |
    ///
    /// Within a file a site may also be a base or'd with a bounded mask, where
    /// one slot's absence is not the whole fact worth carrying.
    /// `wyr1e_native.rs` does this for `0xa0..=0xbf`; see
    /// `absent_owner_site`.
    ///
    /// `wyr1b_native.rs`, `wyr1d_native.rs` and the two evidence modules keep
    /// `WrongActivationOrder` deliberately: their sites belong to selectors
    /// whose failure statuses are pinned, and
    /// `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` requires E8's to stay identical to
    /// the A27 baseline. Converting them would move those words.
    AbsentState(u8),
    /// A registry recovery gave up without installing a replacement.
    ///
    /// F3A.6f: `recover_registry` empties `state.registry` and `state.binding`
    /// before it relaunches, and two of its exits used to `return Ok(())`
    /// having installed nothing -- leaving a state `wyr1e::poll` cannot
    /// tolerate, and reporting success. The `RecoveryResult::Degraded` those
    /// exits set is a running accumulator, not a verdict: the resident is
    /// *constructed* `Degraded`, so no reader can treat it as a stop signal.
    ///
    /// Under `wyr1e-production` abandoning the registry is therefore terminal,
    /// because almost everything `poll` does needs the registry's control
    /// channel and a system without one has nothing left to poll. Builds
    /// without that product keep the old `Ok`: nothing there reads the slot.
    ///
    /// The payload says which exit and what asked for the recovery, per
    /// `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` §6 -- the exits are
    /// indistinguishable from a status otherwise, because both used to return
    /// `Ok`, and F3A.6f could not say which one the smp profile took.
    ///
    /// The trigger is the high nibble and the exit the low one; see
    /// `wyr1c_native::abandoned`. F3A.6h added the trigger because the exit
    /// alone says the restart budget ran out without saying what kept
    /// spending it, and the callers are not interchangeable: a peer-closed
    /// control channel, a dead registryd process and a shell-side poisoning
    /// have different causes. The reported trigger is the final call's, which
    /// is the loss that exhausted the budget.
    RegistryAbandoned(u8),
    /// A session shutdown could not release everything it owns, as a mask of
    /// the steps that failed.
    ///
    /// F3A.7i. The first run of F3A.7g's teardown reported `0xAF18_1704` --
    /// an ordinary resident tick returning `Cleanup` -- and that was the whole
    /// of it. The teardown has five independent steps and deliberately runs
    /// all of them, so "something failed" is four bits covering thirty-one
    /// distinct outcomes, which is the collapse
    /// `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` 3.2 calls a debt to the reader.
    /// A mask is the honest shape here precisely *because* the steps are
    /// independent: reporting only the first failure would hide the rest, and
    /// the next run would be as blind as this one.
    ///
    /// Bit 0 the job dispatcher, 1 the driver, 2 devmgr, 3 the registry, 4 the
    /// early-role table. Zero is never reported: a shutdown with no failed
    /// step is a success.
    SessionShutdown(u8),
    RecoveryTransition {
        operation: u8,
        initiating_kind: u8,
        /// The innermost error's own diagnostic instance, kept across attribution.
        ///
        /// `attribute_failure` replaces the error it wraps with this variant,
        /// which used to mean the payload of the error that actually failed --
        /// a `DwStatus`, a parse error, a launcher code -- was discarded and
        /// only its four-bit kind survived. F3A.6b's transcripts said
        /// `InitError::Native(_)` and could not say which syscall.
        payload: u16,
        emergency_cleanup: EmergencyCleanup,
    },
    BootstrapRetirement(BootstrapRetirementFailure),
}

/// Why permanent init could not retire its bootstrap launch channel.
///
/// The retirement wait is reached by every selector through `run_system_init`,
/// and both of its failures reported a bare `InitError::Supervision` -- one value
/// shared with a hundred and five other sites across this crate. Card R1's run 5
/// reported exactly that (`0xAF340014`) and the site was not even among the two I
/// had identified; the cause-preservation gate found it. Each case here carries
/// what it knows, so the failure names itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapRetirementFailure {
    /// The wait for the bootstrap peer's close failed or timed out. The native
    /// status distinguishes those, and every neighbouring call in this function
    /// already preserves it.
    Wait(NativeError),
    /// The wait succeeded but selected the wrong input or lacked `PEER_CLOSED`,
    /// which is a different failure from the wait refusing: the kernel answered,
    /// and answered unexpectedly.
    WrongResult { index: u32, observed: u64 },
}

/// What init found on the probe's channel after a record went missing.
///
/// Run 9 refused sequence 7 while expecting 6, and the probe provably sent 6:
/// record 7 carries sequence 7, so `next_sequence` ran seven times, and it is
/// only ever consumed inside an emitter that immediately sends and propagates
/// failure. So the datagram was lost between a successful `send_channel` and
/// init's `receive_channel`, and the next question is not *whether* one was lost
/// but whether exactly one was.
///
/// `further` is how many more datagrams were queued behind the refused one, and
/// `highest_gap` whether any of those was itself out of sequence. One isolated
/// loss and a stream of losses are different defects, and the status has to tell
/// them apart or the next run repeats this one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayGapCensus {
    pub expected: u64,
    pub observed: u64,
    pub further: u32,
    pub further_gaps: u32,
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
    ///
    /// `RestartSupervisor::admit_recovery` in `wyrmroot-runtime` has always
    /// been ordinary, documented supervision. Only these two wrappers named a
    /// selector, so only they were removed at R7B-4.
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
        session_complete: false,
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
        session_complete: false,
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
        .map_err(|error| InitError::BootstrapRetirement(BootstrapRetirementFailure::Wait(error)))?;
    if retired.index != 0 || retired.observed.0 & DW_SIGNAL_PEER_CLOSED.0 == 0 {
        return Err(InitError::BootstrapRetirement(
            BootstrapRetirementFailure::WrongResult {
                index: retired.index,
                observed: retired.observed.0,
            },
        ));
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
            .ok_or(InitError::AbsentState(0x01))?
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
        .ok_or(InitError::AbsentState(0x02))?
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

    /// The other half of the same wiring: what `SessionComplete` makes the
    /// tick do. It is ordinary compiled code under `wyr1e-production`, but no
    /// host fixture reaches `control_tick` with a retired console, so the
    /// property is stated here rather than only compiled.
    ///
    /// Source text because `wyr1e_resident_step` is reached only through
    /// `control_tick`, which no host fake drives; scoped to that fn's body.
    #[test]
    fn a_complete_session_is_recorded_and_never_treated_as_a_recovery() {
        const NATIVE: &str = include_str!("wyr1c_native.rs");
        let step = NATIVE
            .find("fn wyr1e_resident_step<")
            .expect("the console/shell step moved");
        let step = &NATIVE[step..];
        let step = &step[..step.find("\n}\n").expect("the step never closes")];

        const CHECK: &str = "if outcome == wyr1e::PollOutcome::SessionComplete {";

        let handled = step
            .find(CHECK)
            .expect("the tick no longer recognises a completed session");
        let after = &step[handled + CHECK.len()..];
        let close = after
            .find("\n        }\n")
            .expect("the completed-session check never closes");
        let body = &after[..close];

        let retired = body
            .find("retire_for_session_shutdown(resident, system, waits)?;")
            .expect("a completed session is recognised but nothing is retired");
        let recorded = body
            .find("resident.observe_session_complete();")
            .expect("a completed session is recognised but not recorded");
        // Retiring first is the whole point. Recording completion and then
        // failing the teardown would report a finished system while its roles
        // were still running, which is the state the first F3A.7g run left
        // behind and could not explain.
        assert!(
            retired < recorded,
            "the roles must be retired before completion is recorded: \
             retire {retired}, record {recorded}"
        );
        assert!(
            body[recorded..].contains("return Ok(resident.controller.mode());"),
            "a recorded completion must leave the tick"
        );

        // The recovery dispatch maps every other outcome onto something to
        // rebuild out of the bootfs archive. Reaching it with a completed
        // session would relaunch the console the poll just retired.
        let dispatch = step
            .find("if outcome != wyr1e::PollOutcome::Stable {")
            .expect("the tick no longer dispatches recoveries");
        assert!(
            handled < dispatch,
            "a completed session must be answered before the recovery dispatch: \
             handled {handled}, dispatch {dispatch}"
        );
    }

    #[cfg(feature = "wyr1e-production")]
    #[test]
    fn e6_manifest_constructor_admits_only_the_production_shell_profile() {
        use wyrmroot_rrc_manifest::builder::{Builder, DependencySpec, RoleSpec};

        // The same five-role closure with the shell's startup profile varied.
        // The E6 constructor is additive: it admits only `Wyrmsh`, and the
        // historical WYR1-C constructor keeps admitting only `Retained`.
        let boot_generation = [0x42; 32];
        let build = |shell_profile: StartupProfile| {
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
                    shell_profile,
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
            builder.build_structural().unwrap()
        };
        let production = build(StartupProfile::Wyrmsh);
        let manifest = Manifest::parse_structural(&production, &boot_generation).unwrap();
        assert!(SystemInit::from_wyr1e_manifest(manifest).is_ok());
        assert_eq!(
            SystemInit::from_wyr1c_manifest(manifest),
            Err(InitError::WrongManifestProfile)
        );
        let historical = build(StartupProfile::Retained);
        let manifest = Manifest::parse_structural(&historical, &boot_generation).unwrap();
        assert!(SystemInit::from_wyr1c_manifest(manifest).is_ok());
        assert_eq!(
            SystemInit::from_wyr1e_manifest(manifest),
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
        wait_deadline: Option<u64>,
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
                wait_deadline: None,
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

        fn wait_until(&mut self, deadline_ns: u64) -> Result<(), NativeError> {
            self.wait_deadline = Some(deadline_ns);
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

    /// Two ready early roles under one resident. With `ResidentWaits`, the
    /// first legacy tick reaps the registry's peer close and succeeds.
    pub(crate) fn two_role_resident() -> (ResidentSystemInit, ActiveNativeRole, ActiveNativeRole) {
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
        let resident = ResidentSystemInit {
            controller,
            authority: LoadAuthority {
                parent_root: DwHandle(100),
                bootfs: DwHandle(101),
                task_group: DwHandle(102),
            },
            result: RecoveryResult::Recovered,
            active: [Some(registry), Some(devmgr)],
            evidence_finalized: false,
            session_complete: false,
            last_tick_ns: 9,
            wyr1b: None,
            wyr1b_evidence: None,
            wyr1c: None,
        };
        (resident, registry, devmgr)
    }

    #[test]
    fn resident_drains_peer_close_to_clean_exit_without_dropping_other_role() {
        let (mut resident, registry, devmgr) = two_role_resident();
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

    /// The resident loop's own platform for `MockNative`. Selectors 29 and 34
    /// drive their own scenario from the loop on every tick, which this fixture
    /// does not carry, so the loop tests below run in every other shape.
    impl resident_loop::ResidentLoopPlatform for MockNative {

    }

    /// F3A.7g, the last step: a completed session ends permanent init's
    /// process with success, on the tick that observed it.
    ///
    /// The tick runs first (the registry is reaped), and the check comes
    /// before the wait: `MockNative` fails any wait, so a loop that slept
    /// before checking, or checked only after a later tick, would report
    /// 0xAF01_0005 instead.
    #[test]
    fn permanent_init_leaves_its_loop_when_the_session_is_complete() {
        let (mut resident, _, _) = two_role_resident();
        resident.session_complete = true;
        let mut native = MockNative::new();
        let mut loader = wyrmroot_runtime::NativeLoaderPlatform;
        let mut waits = ResidentWaits { wait_count: 0 };

        assert_eq!(
            resident_loop::continue_resident(&mut resident, &mut native, &mut loader, &mut waits),
            0
        );
        assert_eq!(waits.wait_count, 3, "the tick ran before the loop returned");
    }

    /// The control for the test above: the same resident with its session
    /// still open does not leave the loop, and reaches the tick wait.
    #[test]
    fn an_open_session_keeps_permanent_init_in_its_loop() {
        let (mut resident, _, _) = two_role_resident();
        let mut native = MockNative::new();
        let mut loader = wyrmroot_runtime::NativeLoaderPlatform;
        let mut waits = ResidentWaits { wait_count: 0 };

        assert_eq!(
            resident_loop::continue_resident(&mut resident, &mut native, &mut loader, &mut waits),
            0xAF01_0005
        );
        assert_eq!(waits.wait_count, 3);
    }

    /// The loop sleeps one tick period past the tick's own instant. Products
    /// with resident handshakes (selectors 29, 31, 32 and production) tick at
    /// the supervision backoff, the rest once a second; the selectors' half
    /// is a build-time assertion beside `RESIDENT_TICK_NS`.
    #[test]
    fn the_resident_loop_waits_one_tick_period_past_the_tick() {
        let expected = if cfg!(feature = "wyr1e-production") {
            WYR0_I_SUPERVISION_POLICY.backoff_ns
        } else {
            1_000_000_000
        };
        assert_eq!(resident_loop::RESIDENT_TICK_NS, expected);

        let (mut resident, _, _) = two_role_resident();
        let mut native = MockNative::new();
        let mut loader = wyrmroot_runtime::NativeLoaderPlatform;
        let mut waits = ResidentWaits { wait_count: 0 };
        assert_eq!(
            resident_loop::continue_resident(&mut resident, &mut native, &mut loader, &mut waits),
            0xAF01_0005
        );
        assert_eq!(native.wait_deadline, Some(native.now + expected));
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

    /// F3A.6c: a native failure must say which native failure it was.
    ///
    /// The F3A campaign's transcripts reported `0xAF18_0F05` -- unattributed,
    /// kind 5, `InitError::Native(_)` -- and could not say which syscall
    /// returned what. `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` §3.3 requires
    /// the instance to survive a diagnostic boundary, so it now does: through
    /// attribution, into its own tag, and back out of the decoder.
    #[test]
    fn a_native_tick_failure_carries_its_own_status_through_attribution() {
        use deepwyrm_syscall::DwStatus;
        use wyrmroot_runtime::{NativeError, NativeOutputError};

        let native = InitError::Native(NativeError::Status(DwStatus(-7)));
        let decoded = decode_tick_failure(resident_tick_failure_application_status(&native))
            .expect("a native tick failure decodes");
        assert_eq!(
            (decoded.operation, decoded.kind, decoded.instance),
            (0x0f, 0x05, 7)
        );
        assert!(!decoded.saturated);

        // Attribution keeps the instance and replaces only the operation.
        // This is the collapse F3A.6c closed: `attribute_failure` used to
        // discard the error it wrapped and keep four bits of it.
        let attributed: Result<(), InitError> =
            attribute_failure(RecoveryOperation::StartConsole, Err(native));
        let decoded = decode_tick_failure(resident_tick_failure_application_status(
            &attributed.unwrap_err(),
        ))
        .expect("an attributed native tick failure decodes");
        assert_eq!(
            (decoded.operation, decoded.kind, decoded.instance),
            (0x0e, 0x05, 7)
        );

        // An output-contract failure stays distinguishable from a kernel
        // status, which is what the family bit is for.
        let output = InitError::Native(NativeError::Output(NativeOutputError::InvalidWaitResult));
        let decoded = decode_tick_failure(resident_tick_failure_application_status(&output))
            .expect("an output-contract failure decodes");
        assert_eq!(decoded.instance, 0x8006);

        // A magnitude beyond the field saturates and says so, rather than
        // aliasing a different small status: contract §5. Nothing in
        // `status.toml` reaches 0x7f -- it tops out at 16 -- so this is a
        // guard against a future status, not a live loss.
        let big = InitError::Native(NativeError::Status(DwStatus(-4096)));
        let decoded = decode_tick_failure(resident_tick_failure_application_status(&big))
            .expect("a large native status decodes");
        assert!(decoded.saturated);
        assert_eq!(decoded.instance, 0x7f);
    }

    /// F3A.6e: a startup step must be nameable, and every old value must not move.
    ///
    /// F3A.6d located its failure's site and its status and could not say
    /// which step it happened in, because `0x01..=0x0e` were all recovery
    /// transitions and `0x0f` is the sentinel. The field was always eight bits
    /// wide; only the clamp was four.
    #[test]
    fn an_abandoned_registry_names_the_exit_that_abandoned_it() {
        // F3A.6f's whole point: the two exits used to be indistinguishable
        // because both returned `Ok`. They must not collapse to one status.
        let budget: Result<(), InitError> = attribute_failure(
            RecoveryOperation::RetireRegistry,
            Err(InitError::RegistryAbandoned(0x01)),
        );
        let declined: Result<(), InitError> = attribute_failure(
            RecoveryOperation::LaunchRegistry,
            Err(InitError::RegistryAbandoned(0x02)),
        );
        let budget = resident_tick_failure_application_status(&budget.unwrap_err());
        let declined = resident_tick_failure_application_status(&declined.unwrap_err());
        assert_ne!(budget, declined);
        assert_eq!(budget >> 16, 0xAF21);
        assert_eq!(declined >> 16, 0xAF21);

        let decoded = decode_tick_failure(budget).expect("an abandoned registry decodes");
        assert_eq!(decoded.operation, RecoveryOperation::RetireRegistry as u8);
        assert_eq!(decoded.kind, 0x0a);
        assert_eq!(decoded.instance, 0x01);
        assert!(!decoded.saturated);
        let decoded = decode_tick_failure(declined).expect("an abandoned registry decodes");
        assert_eq!(decoded.operation, RecoveryOperation::LaunchRegistry as u8);
        assert_eq!(decoded.instance, 0x02);

        // Unattributed, the reason still survives: the tag is what carries it,
        // not the operation.
        let bare = resident_tick_failure_application_status(&InitError::RegistryAbandoned(0x02));
        assert_eq!(bare, 0xAF21_0F02);

        // F3A.6h. The same exit reached from two different triggers must not
        // read as one status, and a whole reason byte survives the encoder.
        use crate::wyr1c_native::abandoned;
        let control = InitError::RegistryAbandoned(abandoned::reason(
            abandoned::trigger::CONTROL_LOST,
            abandoned::phase::NONE,
        ));
        let exited = InitError::RegistryAbandoned(abandoned::reason(
            abandoned::trigger::EXITED,
            abandoned::phase::NONE,
        ));
        let control = resident_tick_failure_application_status(&control);
        let exited = resident_tick_failure_application_status(&exited);
        assert_ne!(control, exited);
        assert_eq!(control, 0xAF21_0F10);
        assert_eq!(exited, 0xAF21_0F20);

        // F3A.6j. One trigger and two phases must not read as one status
        // either: the phase is what distinguishes twenty poll sites.
        let deadline = InitError::RegistryAbandoned(abandoned::reason(
            abandoned::trigger::WYR1E_POLL,
            abandoned::phase::READY_DEADLINE_BEFORE_WAIT,
        ));
        let unmatched = InitError::RegistryAbandoned(abandoned::reason(
            abandoned::trigger::WYR1E_POLL,
            abandoned::phase::CONSOLE_EVENT_UNMATCHED,
        ));
        let deadline = resident_tick_failure_application_status(&deadline);
        let unmatched = resident_tick_failure_application_status(&unmatched);
        assert_ne!(deadline, unmatched);
        assert_eq!(deadline, 0xAF21_0F44);
        assert_eq!(unmatched, 0xAF21_0F4C);
        assert_eq!(
            decode_tick_failure(unmatched)
                .expect("an abandoned registry decodes")
                .instance,
            0x4c
        );

        // And the new kind does not disturb the tag every other error uses.
        assert_eq!(
            resident_tick_failure_application_status(&InitError::Cleanup) >> 16,
            0xAF18
        );
    }

    /// F3A.7i. The mask is the point: the shutdown runs all five steps, so a
    /// status that said only "a cleanup failed" -- which is what the first
    /// F3A.7g run reported, as `0xAF18_1704` -- covers thirty-one different
    /// outcomes and names none of them.
    #[test]
    fn a_session_shutdown_reports_every_step_that_failed_and_not_merely_that_one_did() {
        let status =
            |steps| resident_tick_failure_application_status(&InitError::SessionShutdown(steps));

        // Each step alone is its own status. Literals, not `1 << n`: the bit
        // positions are what a transcript is read with, and a test written in
        // terms of the shift would follow the shift if it moved.
        assert_eq!(status(0x01), 0xAF22_0F01);
        assert_eq!(status(0x02), 0xAF22_0F02);
        assert_eq!(status(0x04), 0xAF22_0F04);
        assert_eq!(status(0x08), 0xAF22_0F08);
        assert_eq!(status(0x10), 0xAF22_0F10);

        // And combinations stay distinguishable from their members, which is
        // the property a first-failure-only report does not have.
        assert_eq!(status(0x03), 0xAF22_0F03);
        assert_eq!(status(0x1f), 0xAF22_0F1F);
        assert_ne!(status(0x03), status(0x01));
        assert_ne!(status(0x03), status(0x02));

        // The tag is its own, so no other kind's reader can claim it.
        for other in [
            resident_tick_failure_application_status(&InitError::Cleanup),
            resident_tick_failure_application_status(&InitError::AbsentState(0x01)),
            resident_tick_failure_application_status(&InitError::RegistryAbandoned(0x01)),
        ] {
            assert_ne!(other >> 16, 0xAF22);
        }

        let decoded = decode_tick_failure(status(0x1f)).expect("a session shutdown decodes");
        assert_eq!(decoded.kind, 0x0b);
        assert_eq!(decoded.instance, 0x1f);
        assert!(!decoded.saturated);
        assert_eq!(decoded.operation, UNATTRIBUTED_OPERATION);
    }

    #[test]
    fn a_startup_operation_is_nameable_without_moving_any_recovery_value() {
        // Every startup operation round-trips above the sentinel.
        for operation in [
            RecoveryOperation::ReceiveProduct,
            RecoveryOperation::MapRetainedBootfs,
            RecoveryOperation::ActivateRegistry,
            RecoveryOperation::ActivateDevmgr,
            RecoveryOperation::ActivateUart,
            RecoveryOperation::ActivateConsole,
            RecoveryOperation::ActivateShell,
            RecoveryOperation::ResidentTick,
            RecoveryOperation::DispatchHistoricalJob,
            RecoveryOperation::DispatchConsoleJob,
            RecoveryOperation::DispatchShellJob,
        ] {
            assert!(operation as u8 > UNATTRIBUTED_OPERATION);
            let attributed: Result<(), InitError> =
                attribute_failure(operation, Err(InitError::AbsentState(0x8d)));
            let decoded = decode_tick_failure(resident_tick_failure_application_status(
                &attributed.unwrap_err(),
            ))
            .expect("a startup-attributed failure decodes");
            assert_eq!(decoded.operation, operation as u8);
            assert_eq!(decoded.instance, 0x8d);
        }

        // A recovery operation still encodes where it always did, and the
        // sentinel still means unattributed.
        let recovery: Result<(), InitError> =
            attribute_failure(RecoveryOperation::StartConsole, Err(InitError::Cleanup));
        assert_eq!(
            resident_tick_failure_application_status(&recovery.unwrap_err()),
            0xAF18_0E04
        );
        assert_eq!(
            resident_tick_failure_application_status(&InitError::Cleanup),
            0xAF18_0F04
        );
    }

    /// F3A.6c: a refused launch message must say why it was refused.
    ///
    /// Both sites that parse one reported `InitError::Accounting`, which was
    /// the wrong class as well as a collapse: twenty-three reasons arrived as
    /// kind 0x02, pointing a reader at resource accounting.
    #[test]
    fn a_refused_launch_message_carries_its_reason_and_the_right_class() {
        use wyrmroot_launch_proto::Error as LaunchProtocolError;

        let refused = InitError::LaunchProtocol(LaunchProtocolError::WrongHandleCount);
        let decoded = decode_tick_failure(resident_tick_failure_application_status(&refused))
            .expect("a refused launch message decodes");
        // 0x06 is the protocol-refusal class, not 0x02's accounting.
        assert_eq!(decoded.kind, 0x06);
        assert_eq!(
            decoded.instance,
            LaunchProtocolError::WrongHandleCount as u16
        );

        // Distinct reasons must not encode alike.
        let other = InitError::LaunchProtocol(LaunchProtocolError::InvalidUtf8);
        assert_ne!(
            resident_tick_failure_application_status(&refused),
            resident_tick_failure_application_status(&other)
        );

        // The other two protocols at kind 0x06 keep the unchanged encoding,
        // because neither carries an instance this word has room for.
        let registry = resident_tick_failure_application_status(&InitError::Wyr1BGateMismatch);
        assert_eq!(registry, 0xAF18_0F06);
    }

    /// F3A.6c: an absent state slot must say which slot.
    #[test]
    fn an_absent_state_tick_failure_carries_its_site() {
        let absent = InitError::AbsentState(0x42);
        let decoded = decode_tick_failure(resident_tick_failure_application_status(&absent))
            .expect("an absent-state tick failure decodes");
        assert_eq!(
            (decoded.operation, decoded.kind, decoded.instance),
            (0x0f, 0x09, 0x42)
        );

        let attributed: Result<(), InitError> =
            attribute_failure(RecoveryOperation::LaunchRegistry, Err(absent));
        let decoded = decode_tick_failure(resident_tick_failure_application_status(
            &attributed.unwrap_err(),
        ))
        .expect("an attributed absent-state failure decodes");
        assert_eq!(
            (decoded.operation, decoded.kind, decoded.instance),
            (0x0c, 0x09, 0x42)
        );

        // Two different sites must not encode alike, which is the whole point.
        assert_ne!(
            resident_tick_failure_application_status(&InitError::AbsentState(0x10)),
            resident_tick_failure_application_status(&InitError::AbsentState(0x11))
        );
    }

    #[test]
    fn resident_tick_failure_detail_preserves_the_selected_profile() {
        // Every other build reports the operation and the kind. Before R7B-2
        // only E8 did, and the rest returned 0xAF01_0006 for all four of these
        // -- one value standing for every fatal tick, which is the reading that
        // stalled A8.
        for (error, expected) in [
            (InitError::Accounting, 0xAF18_0F02),
            (InitError::Supervision, 0xAF18_0F03),
            (InitError::Cleanup, 0xAF18_0F04),
            (InitError::WrongActivationOrder, 0xAF18_0F01),
        ] {
            assert_eq!(resident_tick_failure_application_status(&error), expected);
        }

        // An attributed failure reports its operation in place of 0x0f, and a
        // failed emergency cleanup reports kind 04 while the initiating kind
        // stays in the private carrier rather than being lost.
        {
            assert_eq!(
                resident_tick_failure_application_status(&InitError::RecoveryTransition {
                    operation: RecoveryOperation::StartConsole as u8,
                    initiating_kind: 0x02,
                    payload: 0,
                    emergency_cleanup: EmergencyCleanup::NotRun,
                }),
                0xAF18_0E02
            );
            assert_eq!(
                resident_tick_failure_application_status(&InitError::RecoveryTransition {
                    operation: RecoveryOperation::StartConsole as u8,
                    initiating_kind: 0x02,
                    payload: 0,
                    emergency_cleanup: EmergencyCleanup::DisconnectFailed,
                }),
                0xAF18_0E04
            );
        }

        // 0xAF01_0006 is now unreachable: operation 0x00 cannot be produced, so
        // the old collapsed value still reads as a pre-R7B-2 build.
        for error in [
            InitError::Accounting,
            InitError::Supervision,
            InitError::Cleanup,
            InitError::WrongActivationOrder,
        ] {
            assert_ne!(
                resident_tick_failure_application_status(&error),
                0xAF01_0006
            );
        }
    }

    #[test]
    fn resident_fits_locked_native_stack_partition() {
        extern crate std;
        use core::mem::size_of;

        std::println!("resident bytes: {}", size_of::<ResidentSystemInit>());

        // The interactive product retains a JobV2 dispatcher alongside the
        // device resident. Reserve 40 KiB of the existing 108 KiB execution
        // stack for residency; this partition is a userspace budget, not a
        // startup ABI limit.
        let resident_budget = if cfg!(feature = "wyr1e-production") {
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
