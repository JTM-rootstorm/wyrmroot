//! Permanent WYR1-A supervisor policy and native startup boundary.
//!
//! The fixed controller composes `RestartSupervisor`; it does not implement a
//! dependency solver or copy restart-policy transitions.

#![no_std]
#![forbid(unsafe_code)]

use core::mem::MaybeUninit;

use wyrmroot_consoled as _;
#[cfg(test)]
use {wyrmroot_devmgr as _, wyrmroot_registryd as _, wyrmroot_uart16550d as _};

mod launch_transaction;
pub mod resident_loop;
pub(crate) mod wyr1b;
mod wyr1b_job;
pub(crate) mod wyr1b_native;
pub(crate) mod wyr1c_native;

use deepwyrm_syscall::{
    DW_SIGNAL_EXITED, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_STATUS_TIMED_OUT,
    DW_TASK_STATE_EXITED, DwDeadline, DwHandle, DwHandleTransferV1, DwObjectType,
    DwReceivedHandleInfoV1, DwRights, DwTaskTerminationInfoV1, DwWaitItemV1, DwWaitResultV1,
};
use wyrmroot_bootfs::archive::{Archive, LookupError, ParseError};
use wyrmroot_loader::{
    launch::{
        HEADER_BYTES, LaunchProfile, RESOURCE_DOMAIN_CLAIM_RIGHTS, SUPERVISOR_BYTES,
        encode_ready_for_profile, parse_init,
    },
    process::{
        LoadAuthority, LoadError, LoadedProcess, LoaderPlatform, ServiceLoadRequest,
        load_service_process,
    },
};
use wyrmroot_rrc_manifest::{
    Activation, DependencyKind, MANIFEST_PATH, Manifest, ParseError as ManifestParseError, RoleId,
    StartupProfile,
};
use wyrmroot_runtime::{
    AttemptFailure, CleanupDisposition, RestartState, RestartSupervisor, RestartTransitionError,
    WYR0_I_SUPERVISION_POLICY,
};
use wyrmroot_runtime::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, CapabilityValidationError,
    InitCapability, LOADER_TASK_GROUP_EXPECTATION, MappingPlan, MappingPlanError, NativeError,
    RESOURCE_DOMAIN_TASK_GROUP_EXPECTATION, ReceiveCounts, SELF_ROOT_EXPECTATION,
    SupervisionPlatform, await_child_ready_profile_observed, validate_bootstrap_channel,
    validate_init_capabilities_v3,
};

pub(crate) const SYSTEM_INIT_PATH: &str = "system/init";
pub(crate) const EARLY_ROLE_COUNT: usize = 2;
const EXPECTED_ROLE_PATHS: [(RoleId, &str); 5] = [
    (RoleId::Registryd, "system/registryd"),
    (RoleId::Devmgr, "system/devmgr"),
    (RoleId::Uart16550d, "system/uart16550d"),
    (RoleId::Consoled, "system/consoled"),
    (RoleId::Wyrmsh, "system/wyrmsh"),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SystemMode {
    Bootstrap,
    SupervisorOperational,
    ActivatingEarlyRoles,
    Normal,
    Degraded,
    Fatal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryResult {
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
        InitError::Supervision => 0x03,
        InitError::Cleanup => 0x04,
        InitError::Native(_) => 0x05,
        InitError::WrongManifestProfile
        | InitError::ResourceIdentityMismatch
        | InitError::InvalidResourceHandle
        | InitError::Capability(_)
        | InitError::RegistryProtocol(_) => 0x06,
        InitError::UnlaunchableRole
        | InitError::Bootfs(_)
        | InitError::MissingRetainedMaterial
        | InitError::NonExecutableRole
        | InitError::Manifest(_)
        | InitError::ArtifactIdentityMismatch(_)
        | InitError::Mapping(_)
        | InitError::Launch(_)
        | InitError::Loader(_) => 0x07,
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
pub(crate) const fn resident_tick_failure_application_status(error: &InitError) -> u32 {
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
            _ => 0xAF18_0000 | (operation as u32) << 8 | kind as u32,
        }
    }
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
    wyr1c: Option<wyr1c_native::ResidentState>,
}

/// Broad primordial resource-domain custody. It is intentionally not a field
/// of [`LoadAuthority`]: ordinary process construction must not manufacture
/// or absorb device-claim authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResourceDomainCustody {
    resource_domain: DwHandle,
}

impl ResourceDomainCustody {
    pub(crate) const fn new(resource_domain: DwHandle) -> Self {
        Self { resource_domain }
    }

    pub(crate) const fn handle(self) -> DwHandle {
        self.resource_domain
    }

    /// The one reduction init makes: claim authority for a devmgr-generation
    /// descendant. Membership is kernel-authoritative.
    pub(crate) const fn devmgr_claim_authority(self) -> ReducedResourceDomainAuthority {
        ReducedResourceDomainAuthority {
            resource_domain: self.resource_domain,
            rights: RESOURCE_DOMAIN_CLAIM_RIGHTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReducedResourceDomainAuthority {
    resource_domain: DwHandle,
    rights: DwRights,
}

impl ReducedResourceDomainAuthority {
    pub(crate) const fn handle(self) -> DwHandle {
        self.resource_domain
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveNativeRole {
    role: RoleId,
    generation: u64,
    transaction_id: u64,
    loaded: LoadedProcess,
    task_group: DwHandle,
}

impl ResidentSystemInit {
    #[must_use]
    /// Whether the interactive session ended. Once true it stays true: there
    /// is no console generation after the one that ended the session.
    pub(crate) const fn session_complete(&self) -> bool {
        self.session_complete
    }

    pub(crate) const fn observe_session_complete(&mut self) {
        self.session_complete = true;
    }

    /// Product-dispatched resident loop. Selector 25 immediately delegates to
    /// the unchanged legacy loop and therefore performs zero WYR1-B platform
    /// operations.
    #[inline(always)]
    pub(crate) fn control_tick_product<S, L, W>(
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
        let observed = wyr1c_native::control_tick(self, system, loader, waits, now_ns);
        attribute_failure(RecoveryOperation::ResidentTick, observed)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct AttemptResources {
    pub(crate) role: RoleId,
    pub(crate) generation: u64,
    pub(crate) transaction_id: u64,
    pub(crate) executable_identity: [u8; 32],
    pub(crate) startup_profile: StartupProfile,
    pub(crate) task_group: DwHandle,
    pub(crate) process: DwHandle,
    pub(crate) launch_channel: DwHandle,
    pub(crate) mappings: u8,
    pub(crate) reservation: AttemptReservation,
}

/// Affine token proving one fixed-role generation was reserved before child
/// publication. It is intentionally neither `Copy` nor `Clone`.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct AttemptReservation {
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
    Loader(LoadError<NativeError>),
    Supervision,
    Cleanup,
    Accounting,
    RegistryProtocol(wyrmroot_registry_proto::Error),
    Wyr1BModel(wyr1b::JobError),
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
pub(crate) struct SystemInit {
    mode: SystemMode,
    roles: [RoleController; EARLY_ROLE_COUNT],
    degraded_transitions: u8,
    activated: [bool; EARLY_ROLE_COUNT],
    accounting: AttemptLedger,
    registry_startup_profile: StartupProfile,
    devmgr_startup_profile: StartupProfile,
}

impl SystemInit {
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
            registry_startup_profile,
            devmgr_startup_profile,
        })
    }

    #[must_use]
    pub(crate) const fn mode(&self) -> SystemMode {
        self.mode
    }
    #[must_use]
    pub(crate) fn role_state(&self, role: RoleId) -> Option<RestartState> {
        self.index(role).map(|i| self.roles[i].restart.state())
    }

    #[must_use]
    pub(crate) fn resources(&self, role: RoleId) -> Option<&AttemptResources> {
        self.index(role)
            .and_then(|i| self.roles[i].resources.as_ref())
    }

    pub(crate) fn reserve_attempt(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
    ) -> Result<AttemptReservation, InitError> {
        let index = role_index(role)?;
        self.accounting
            .reserve(index, role, generation, transaction)
    }

    pub(crate) fn abort_reservation(
        &mut self,
        mut reservation: AttemptReservation,
    ) -> Result<(), InitError> {
        self.accounting.release(&mut reservation)
    }

    /// Marks manifest/closure/controller initialization complete. This is the
    /// exact state acknowledged by the supervisor READY to primordial.
    pub(crate) fn become_operational(&mut self) -> Result<(), InitError> {
        if self.mode != SystemMode::Bootstrap {
            return Err(InitError::WrongActivationOrder);
        }
        self.mode = SystemMode::SupervisorOperational;
        Ok(())
    }

    pub(crate) fn begin_registry(
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

    pub(crate) fn install_attempt(
        &mut self,
        mut resources: AttemptResources,
    ) -> Result<(), InitError> {
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

    pub(crate) fn child_started(
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

    pub(crate) fn ready(
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

    pub(crate) fn fail(
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

    pub(crate) fn ready_wait_failed(
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

    pub(crate) fn cleanup_complete(
        &mut self,
        role: RoleId,
        generation: u64,
        transaction: u64,
        now: u64,
    ) -> Result<(), InitError> {
        let index = self.index(role).ok_or(InitError::UnlaunchableRole)?;
        let controller = &mut self.roles[index];
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
        self.update_permanent_failure(role)?;
        Ok(())
    }

    pub(crate) fn cleanup_failed(
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
    pub(crate) fn retire_active_fail_closed(
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
        }
        self.update_permanent_failure(role)?;
        Ok(())
    }

    pub(crate) fn start_replacement(
        &mut self,
        role: RoleId,
        now: u64,
        generation: u64,
        transaction: u64,
    ) -> Result<(), InitError> {
        self.controller_mut(role)?
            .restart
            .start_replacement(now, generation, transaction)?;
        self.update_permanent_failure(role)?;
        Ok(())
    }

    pub(crate) fn fatal(&mut self) {
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
    let plan = MappingPlan::for_bootfs(size).map_err(InitError::Mapping)?;
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

    use deepwyrm_syscall::{
        DW_TASK_STATE_EXITED, DwStatus, DwTaskState, DwTaskTerminationInfoV1, DwWaitResultV1,
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

    /// The resident loop's own platform for `MockNative`. Selectors 29 and 34
    /// drive their own scenario from the loop on every tick, which this fixture
    /// does not carry, so the loop tests below run in every other shape.

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
        let resident_budget = if true { 40 } else { 20 };
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
