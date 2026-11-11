//! Permanent init: the product supervisor and its native startup boundary.
//!
//! The fixed controller composes `RestartSupervisor`; it does not implement a
//! dependency solver or copy restart-policy transitions.

#![no_std]
#![forbid(unsafe_code)]

use core::mem::MaybeUninit;

use wyrmroot_consoled as _;
#[cfg(test)]
use {wyrmroot_devmgr as _, wyrmroot_registryd as _, wyrmroot_uart16550d as _};

mod console;
mod controller;
mod errors;
mod job_dispatch;
mod job_launch;
mod job_sessions;
mod jobs;
pub use jobs::JOB_TASK_GROUP_LIMITS;
mod launch_transaction;
mod product;
mod recovery;
mod registry;
pub mod resident_loop;

// One crate-wide namespace for the resident supervisor's parts, which were a
// single module before they were split by responsibility.
use crate::controller::*;
pub use crate::errors::*;
use crate::{
    console::*, job_dispatch::*, job_launch::*, jobs::*, product::*, recovery::*, registry::*,
};

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

pub(crate) use wyrmroot_bootfs::paths::INIT_PATH as SYSTEM_INIT_PATH;
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
    product: Option<crate::ResidentState>,
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
        S: ResidentPlatform,
        L: LoaderPlatform<Error = NativeError>,
        W: SupervisionPlatform<Error = NativeError>,
    {
        // Attributed as an ordinary resident tick, so a failure here is
        // distinguishable from one during startup. `attribute_failure` keeps
        // an inner attribution, so a recovery transition that already named
        // itself is not overwritten by this outer one.
        let observed = crate::control_tick(self, system, loader, waits, now_ns);
        attribute_failure(RecoveryOperation::ResidentTick, observed)
    }
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
    /// Applies [`JOB_TASK_GROUP_LIMITS`] to a fresh job TaskGroup
    /// before anything runs in it (F4 DW1-F4-M1).
    fn limit_job_task_group(&mut self, task_group: DwHandle) -> Result<(), NativeError>;
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
pub trait ResidentPlatform: InitPlatform {
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
    S: ResidentPlatform,
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
    S: ResidentPlatform,
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
    S: ResidentPlatform,
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
                    .lookup(crate::MARKER_PATH.as_bytes())
                    .map_err(map_lookup)?;
                if marker.data() != crate::MARKER_BYTES {
                    return Err(InitError::WrongManifestProfile);
                }
                crate::activate_in_place(
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
        resident_calls: usize,
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
                resident_calls: 0,
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

        fn limit_job_task_group(&mut self, _task_group: DwHandle) -> Result<(), NativeError> {
            Ok(())
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

    impl ResidentPlatform for MockNative {
        fn channel_create(
            &mut self,
            _rights: DwRights,
        ) -> Result<(DwHandle, DwHandle), NativeError> {
            self.resident_calls += 1;
            Err(FAILURE)
        }

        fn send_channel_with_handles(
            &mut self,
            _channel: DwHandle,
            _bytes: &[u8],
            _transfers: &[DwHandleTransferV1],
        ) -> Result<(), NativeError> {
            self.resident_calls += 1;
            Err(FAILURE)
        }

        fn wait_many(
            &mut self,
            _items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, NativeError> {
            self.resident_calls += 1;
            Err(FAILURE)
        }

        fn materialize_read_only_memory(
            &mut self,
            _root: DwHandle,
            _bytes: &[u8],
            _rights: DwRights,
        ) -> Result<DwHandle, NativeError> {
            self.resident_calls += 1;
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
