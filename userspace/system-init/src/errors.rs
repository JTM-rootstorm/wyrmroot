//! Init's failures: `InitError`, its attribution to an operation, and the
//! application status a failure leaves.

use crate::*;

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
    pub(crate) const fn failed(self) -> bool {
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
pub(crate) const UNATTRIBUTED_OPERATION: u8 = 0x0f;

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
pub(crate) const fn failure_instance(error: &InitError) -> u16 {
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

pub(crate) const fn failure_kind(error: &InitError) -> u8 {
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
        InitError::Accounting | InitError::Jobs(_) => 0x02,
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
    Jobs(crate::jobs::JobError),
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
    /// having installed nothing -- leaving a state `crate::poll` cannot
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
    /// `crate::abandoned`. F3A.6h added the trigger because the exit
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
