//! Native selector-27 registry and dependent-peer controller.

use super::*;
use crate::launch_transaction::{
    LaunchResources, LaunchStage, LaunchToken, LaunchTransactionError,
};
use crate::wyr1b::{
    EndpointGrant, EndpointKind, JobError, JobResult as ControllerJobResult, LaunchChannelRelease,
    LaunchEngineError, PolicyView, PreparedJob, RegistryTopology, RequestTicket,
    commit_prepared_job, correlation_environment, observe_prepared_ready, prepare_reserved_job,
};
use crate::wyr1b_gate::{EvidenceLog, GATE_PATH, GateConfig, GateEvent, parse_config};
#[cfg(feature = "wyr1e8-selector33")]
use crate::wyr1b_job::PendingWait;
use crate::wyr1b_job::{JobDispatcher, LaunchSessionScope, SessionOwner};
use deepwyrm_syscall::{
    DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_INSPECT, DW_RIGHT_READ,
    DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DW_RIGHT_WRITE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE,
    DW_STATUS_NO_MEMORY, DW_STATUS_NO_RESOURCES, DW_TASK_STATE_EXITED, DW_TERMINATION_AUTHORIZED,
    DW_TERMINATION_NORMAL_EXIT, DW_TERMINATION_RESOURCE_POLICY, DW_TERMINATION_TASK_GROUP_TEARDOWN,
    DW_TERMINATION_UNHANDLED_EXCEPTION, DwHandleTransferV1, DwRights,
};
#[cfg(feature = "wyr1e8-selector33")]
use wyrmroot_device_proto::DriverLaunchRequest;
use wyrmroot_launch_proto::{
    ErrorCode as LaunchErrorCode, Message as LaunchMessage, MessageType as LaunchMessageType,
    Reservation as LaunchReservation, TerminationClassification, TerminationResult,
    encode_error as encode_launch_error, encode_job_list, encode_job_message, encode_job_result,
    encode_job_state, encode_shell_v1_accepted,
    encode_shell_v1_error as encode_shell_v1_error_reply, parse_message as parse_launch_message,
    parse_reservation_prefix, parse_shell_v1_request, parse_shell_v1_reservation_prefix,
};
use wyrmroot_loader::{
    launch::{CHILD_CHANNEL_RIGHTS, LaunchProfile},
    process::{WyrmshLoadRequest, load_wyrmsh_process},
};
use wyrmroot_registry_proto::{
    EnumerationScope, HEADER_BYTES as REGISTRY_HEADER_BYTES, Header as RegistryHeader,
    InstallClient, MAX_SERVICE_LIST_PAGES, Message as RegistryMessage,
    MessageType as RegistryMessageType, ProtocolVersion, SERVICE_LIST_PREFIX_BYTES,
    SERVICE_LIST_RECORD_BYTES, encode_empty as encode_registry_empty, encode_install_client,
    encode_install_publication, parse as parse_registry_message,
};
use wyrmroot_wyr1b_gate_proto::{
    Direction, ECHO_PROTOCOL_ID, ECHO_SERVICE_NAME, ECHO_VERSION_MAJOR, ECHO_VERSION_MINOR,
    MessageType as GateMessageType, RECORD_BYTES as GATE_RECORD_BYTES, Record as GateRecord,
    TEST_PRIVATE_PUBLISHER_ROLE_ID, encode as encode_gate_record, parse_for as parse_gate_record,
};

const REGISTRY_PATH: &str = "system/registryd";
const PUBLISHER_PATH: &str = "test/wyr1-b/publisher";
const CLIENT_PATH: &str = "test/wyr1-b/client";
const FIRST_PUBLICATION_ID: u64 = 0x1_0001;
const SECOND_PUBLICATION_ID: u64 = 0x1_0002;
const CLIENT_ID: u64 = 0x2_0001;
const INSTALL_PUBLICATION_TRANSACTION: u64 = 1;
const INSTALL_CLIENT_TRANSACTION: u64 = 3;
const CONTROLLER_CHANNEL_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_TRANSFER.0,
);
const WYRMSH_REGISTRY_DEADLINE_NS: u64 = 1_000_000_000;
#[allow(
    dead_code,
    reason = "used by the E3C controller feature and host matrix"
)]
const WYRMSH_FIRST_INSTALL_TRANSACTION: u64 = 0xE300_0001;
#[cfg(feature = "wyr1e8-selector33")]
const E8_DRIVER_TRIGGER_TOKEN_INDEX: u64 = 0x0102;
#[cfg(feature = "wyr1e8-selector33")]
const E8_REGISTRY_TRIGGER_TOKEN_INDEX: u64 = 0x0202;

#[allow(
    dead_code,
    reason = "used by the E3C controller feature and host matrix"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShellRegistryHealth {
    Healthy { generation: u64 },
    Poisoned { generation: u64 },
    Exhausted,
}

#[cfg(feature = "wyr1e8-selector33")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum E8RecoveryAction {
    Driver,
    Registry,
}

#[cfg(feature = "wyr1e8-selector33")]
impl E8RecoveryAction {
    fn control(self) -> wyrmroot_consoled::quiesce_control::Action {
        match self {
            Self::Driver => wyrmroot_consoled::quiesce_control::Action::Driver,
            Self::Registry => wyrmroot_consoled::quiesce_control::Action::Registry,
        }
    }
}

#[cfg(feature = "wyr1e8-selector33")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct E8TriggerIdentity {
    launch_transaction: u64,
    job_id: u64,
    action: E8RecoveryAction,
}

/// The only result a held WAIT may carry.
///
/// `hold_e8_wait` refuses anything else, so this is not a default: it is the
/// value the admission guard has already established by the time a barrier
/// exists. R7B-4 class D1c -- `E8HeldWait` used to store a copy, which could
/// only ever equal this.
#[cfg(feature = "wyr1e8-selector33")]
const E8_HELD_WAIT_RESULT: ControllerJobResult = ControllerJobResult {
    classification: TerminationClassification::NormalExit.as_u32(),
    application_code: 0,
    exception_class: 0,
    exception_detail: 0,
    exception_address: 0,
    cleanup_result: 0,
};

/// One shell WAIT held across a recovery episode, and the quiesce handshake
/// that holds it.
///
/// R7B-4 class D1c shrank this. It carried two fields that duplicated state
/// the product already owns: a `deadline`, which R7B-1 made ordinary episode
/// state on `ShellControllerState` and which every reader cross-checked
/// against `recovery_deadline()` because the copy could disagree; and a
/// `result`, which the admission guard pins to [`E8_HELD_WAIT_RESULT`] before
/// the barrier can exist at all. Both are read from their owners now, and the
/// consistency check that policed the deadline copy went with it.
///
/// What is left is not specialization to be removed. `pending` names the
/// parked reply -- parked in ordinary `pending_waits` storage, not here -- and
/// `identity` and `acknowledged` are the WRC8 quiesce handshake with consoled,
/// which is the scenario itself rather than machinery around it.
#[cfg(feature = "wyr1e8-selector33")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct E8HeldWait {
    pub(crate) pending: PendingWait,
    pub(crate) identity: wyrmroot_consoled::quiesce_control::Identity,
    acknowledged: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ShellControllerState {
    health: ShellRegistryHealth,
    next_install_transaction: u64,
    replacement_attempts: u16,
    last_console_generation: u64,
    last_status_generation: u64,
    last_child_generation: u64,
    /// The deadline of the recovery episode in flight, if one is.
    ///
    /// R7B-1. Every recovery leg's own deadline is capped by this one and
    /// every step refuses to proceed past it, so an episode cannot outlive its
    /// budget by accumulating individually-legal legs. Nothing in the product
    /// opens an episode yet, so product builds hold `None` here and behave
    /// exactly as the removed `not(wyr1e8-selector33)` arms did: no cap, no
    /// expiry. What was selector-specific was never the property, only the one
    /// caller that asks for it.
    recovery_deadline: Option<u64>,
    /// Whether a console child ended the interactive session.
    ///
    /// F3A.7g. `wyrmsh` exits with
    /// `wyrmroot_launch_proto::SHELL_SESSION_SHUTDOWN_STATUS` when it was
    /// asked to end the session rather than merely to end itself, and this is
    /// where that status stops being a number on a wire. It is latched at the
    /// WAIT reply -- the one place init has the child's terminal result in
    /// hand -- and read at the console process exit that follows, which is
    /// otherwise indistinguishable from a console that crashed and has to be
    /// relaunched.
    ///
    /// Set once and never cleared. A session that ended cannot be un-ended by
    /// a later generation, and there is no later generation: nothing replaces
    /// the console after this.
    session_shutdown: bool,
    #[cfg(feature = "wyr1e-selector33")]
    evidence: crate::wyr1e7_evidence::Observer,
    #[cfg(feature = "wyr1e8-selector33")]
    e8_evidence: crate::wyr1e8_evidence::Observer,
    #[cfg(feature = "wyr1e8-selector33")]
    e8_console_control: Option<DwHandle>,
    #[cfg(feature = "wyr1e8-selector33")]
    e8_trigger: Option<E8TriggerIdentity>,
    #[cfg(feature = "wyr1e8-selector33")]
    e8_held: Option<E8HeldWait>,
    /// Half of the final closure episode's READY join: the first
    /// `system/wyrmsh` generation having reached
    /// `JobDispatchOutcome::Launched`, as its generation and outer launch
    /// transaction. It is set once by the dispatcher that owns that join and
    /// is never cleared, so a later shell replacement cannot re-arm an
    /// episode. `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §5.4. The identity is
    /// the shell's bring-up READY evidence (F3A.7k); it grants nothing.
    #[cfg(feature = "wyr1f-closure")]
    wyr1f_shell_ready: Option<(u64, u64)>,
}

#[allow(
    dead_code,
    reason = "used by the E3C controller feature and host matrix"
)]
impl ShellControllerState {
    pub(crate) fn new(registry_generation: u64) -> Result<Self, InitError> {
        if registry_generation == 0 {
            return Err(InitError::Accounting);
        }
        Ok(Self {
            health: ShellRegistryHealth::Healthy {
                generation: registry_generation,
            },
            next_install_transaction: WYRMSH_FIRST_INSTALL_TRANSACTION,
            replacement_attempts: 0,
            last_console_generation: 0,
            last_status_generation: 0,
            last_child_generation: 0,
            recovery_deadline: None,
            session_shutdown: false,
            #[cfg(feature = "wyr1e-selector33")]
            evidence: crate::wyr1e7_evidence::Observer::new()?,
            #[cfg(feature = "wyr1e8-selector33")]
            e8_evidence: crate::wyr1e8_evidence::Observer::new()?,
            #[cfg(feature = "wyr1e8-selector33")]
            e8_console_control: None,
            #[cfg(feature = "wyr1e8-selector33")]
            e8_trigger: None,
            #[cfg(feature = "wyr1e8-selector33")]
            e8_held: None,
            #[cfg(feature = "wyr1f-closure")]
            wyr1f_shell_ready: None,
        })
    }

    /// Latches a console child's request to end the session.
    ///
    /// The caller has already established that the terminal result belongs to
    /// a `ConsoleLauncher` session and carries the shutdown status; this only
    /// remembers it.
    pub(crate) const fn observe_session_shutdown(&mut self) {
        self.session_shutdown = true;
    }

    #[must_use]
    pub(crate) const fn session_shutdown(&self) -> bool {
        self.session_shutdown
    }

    /// Records that a `system/wyrmsh` generation reached READY.
    ///
    /// Idempotent by construction, and never cleared: the join this feeds is
    /// "the first generation was READY", not "a generation is READY now", so
    /// a shell that exits and is replaced after DEGRADED cannot re-arm the
    /// episode.
    #[cfg(feature = "wyr1f-closure")]
    pub(crate) const fn observe_wyr1f_shell_ready(&mut self, generation: u64, transaction: u64) {
        if self.wyr1f_shell_ready.is_none() {
            self.wyr1f_shell_ready = Some((generation, transaction));
        }
    }

    /// The first READY generation's identity, once it exists.
    #[cfg(feature = "wyr1f-closure")]
    #[must_use]
    pub(crate) const fn wyr1f_shell_ready(&self) -> Option<(u64, u64)> {
        self.wyr1f_shell_ready
    }

    #[cfg(feature = "wyr1e-selector33")]
    pub(crate) fn observe_serial_for_e7(
        &mut self,
        publication_generation: u64,
        driver_attempt_generation: u64,
        supervisor_generation: u64,
    ) -> Result<(), InitError> {
        self.evidence.observe_serial(
            publication_generation,
            driver_attempt_generation,
            supervisor_generation,
        )
    }

    #[cfg(feature = "wyr1e-selector33")]
    fn submit_e7<S: Wyr1BPlatform>(
        system: &mut S,
        record: &[u8; crate::wyr1e7_evidence::RECORD_BYTES],
    ) -> Result<(), InitError> {
        system
            .submit_wyr1e7_evidence(record)
            .map_err(InitError::Native)
    }

    #[cfg(feature = "wyr1e-selector33")]
    fn record_e7_shell_ready<S: Wyr1BPlatform>(
        &mut self,
        system: &mut S,
        tuple: crate::wyr1e7_evidence::ShellTuple,
    ) -> Result<(), InitError> {
        #[cfg(test)]
        if !self.evidence.armed() {
            return Ok(());
        }
        self.evidence
            .shell_ready(tuple, |record| Self::submit_e7(system, record))
    }

    #[cfg(feature = "wyr1e-selector33")]
    fn record_e7_shell_jobs<S: Wyr1BPlatform>(
        &mut self,
        system: &mut S,
        request: &[u8],
        response: &[u8],
        handles: &[DwReceivedHandleInfoV1],
    ) -> Result<(), InitError> {
        #[cfg(test)]
        if !self.evidence.ready() {
            return Ok(());
        }
        self.evidence
            .shell_jobs_transaction(request, response, handles, |record| {
                Self::submit_e7(system, record)
            })
    }

    /// Records a shell-jobs launch whose reply was written on a later tick.
    ///
    /// R6B-2's counterpart to `record_e7_shell_jobs`. What it records is the
    /// same transaction; what it has instead of the request bytes is the
    /// `LaunchRequestFacts` taken while they existed.
    #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
    fn record_deferred_shell_jobs_launch<S: Wyr1BPlatform>(
        &mut self,
        system: &mut S,
        facts: crate::launch_request_facts::LaunchRequestFacts,
        response: &[u8],
    ) -> Result<(), InitError> {
        #[cfg(feature = "wyr1e-selector33")]
        {
            #[cfg(test)]
            if !self.evidence.ready() {
                return Ok(());
            }
            self.evidence
                .shell_jobs_launch_response(facts, response, |record| {
                    Self::submit_e7(system, record)
                })
        }
        #[cfg(feature = "wyr1e8-selector33")]
        {
            #[cfg(test)]
            if !self.e8_evidence.ready() {
                return Ok(());
            }
            let mut candidate = self.e8_evidence;
            candidate.shell_jobs_launch_response(facts, response, |record| {
                Self::submit_e8(system, record)
            })?;
            self.require_recovery_live(system)?;
            self.e8_evidence = candidate;
            Ok(())
        }
    }

    #[cfg(feature = "wyr1e-selector33")]
    fn record_e7_outer_response<S: Wyr1BPlatform>(
        &mut self,
        system: &mut S,
        request: &[u8],
        response: &[u8],
    ) -> Result<(), InitError> {
        #[cfg(test)]
        if !self.evidence.ready() {
            return Ok(());
        }
        self.evidence
            .observe_outer_response(request, response, |record| Self::submit_e7(system, record))
    }

    #[cfg(feature = "wyr1e8-selector33")]
    pub(crate) fn observe_serial_for_e8(
        &mut self,
        publication_generation: u64,
        request: DriverLaunchRequest,
    ) -> Result<(), InitError> {
        self.e8_evidence
            .observe_serial(crate::wyr1e8_evidence::SerialFacts {
                publication_generation,
                device_role_id: request.role_id.0,
                driver_attempt_generation: request.attempt_generation.0,
                driver_control_endpoint_id: request.endpoint.id.0,
                driver_control_endpoint_generation: request.endpoint.generation.0,
                driver_launch_transaction: request.transaction_id,
                supervisor_generation: request.supervisor_generation.0,
            })
    }

    #[cfg(feature = "wyr1e8-selector33")]
    fn submit_e8<S: Wyr1BPlatform>(
        system: &mut S,
        record: &[u8; crate::wyr1e8_evidence::RECORD_BYTES],
    ) -> Result<(), InitError> {
        system
            .submit_wyr1e8_evidence(record)
            .map_err(InitError::Native)
    }

    #[cfg(feature = "wyr1e8-selector33")]
    fn stage_e8_shell_ready<S: Wyr1BPlatform>(
        &mut self,
        system: &mut S,
        tuple: crate::wyr1e8_evidence::ShellTuple,
    ) -> Result<(), InitError> {
        #[cfg(test)]
        if !self.e8_evidence.armed() {
            return Ok(());
        }
        self.require_recovery_live(system)?;
        let ready_allowed = self.e8_ready_submission_allowed();
        let mut candidate = self.e8_evidence;
        if let Err(error) = candidate.stage_shell_tuple(tuple, |record| {
            if !ready_allowed {
                return Err(InitError::WrongActivationOrder);
            }
            Self::submit_e8(system, record)
        }) {
            self.e8_evidence.abort_staged_ready();
            return Err(error);
        }
        self.require_recovery_live(system)?;
        self.e8_evidence = candidate;
        self.finish_e8_action_if_ready(system)
    }

    #[cfg(feature = "wyr1e8-selector33")]
    pub(crate) fn observe_e8_serial_ready<S: Wyr1BPlatform>(
        &mut self,
        system: &mut S,
        ready: crate::wyr1e8_evidence::SerialReady,
    ) -> Result<(), InitError> {
        self.require_recovery_live(system)?;
        let ready_allowed = self.e8_ready_submission_allowed();
        let mut candidate = self.e8_evidence;
        if let Err(error) = candidate.observe_serial_ready(ready, |record| {
            if !ready_allowed {
                return Err(InitError::WrongActivationOrder);
            }
            Self::submit_e8(system, record)
        }) {
            self.e8_evidence.abort_staged_ready();
            return Err(error);
        }
        self.require_recovery_live(system)?;
        self.e8_evidence = candidate;
        self.finish_e8_action_if_ready(system)
    }

    #[cfg(feature = "wyr1e8-selector33")]
    fn e8_ready_submission_allowed(&self) -> bool {
        let Some(trigger) = self.e8_trigger else {
            return true;
        };
        let expected_stage = match trigger.action {
            E8RecoveryAction::Driver => 3,
            E8RecoveryAction::Registry => 4,
        };
        self.e8_evidence.stage() == expected_stage && self.e8_held.is_none()
    }

    #[cfg(feature = "wyr1e8-selector33")]
    pub(crate) const fn e8_shell_ready(&self) -> bool {
        self.e8_evidence.ready()
    }

    /// Whether an evidence tuple is written but not yet closed by its serial
    /// line.
    ///
    /// The shell-jobs dispatcher must not run while this holds: a tuple is two
    /// records that the protocol requires adjacent, and dispatching between
    /// them would interleave a third. This is an evidence-ordering obligation
    /// and nothing else.
    ///
    /// R7B-4 class D1e. Until now this reason shared a predicate,
    /// `job_dispatcher_poll_allowed`, with `e8_held.is_none()` -- a parked
    /// WAIT reply. Those are unrelated: one protects record adjacency, the
    /// other suppressed polling while a reply waited. R6C's argument is that a
    /// parked reply needs no such suppression, because the reply is parked in
    /// ordinary `pending_waits` storage and `e8_wait_is_held` already refuses
    /// to answer it twice. So that half is retired and this half is named for
    /// what it is. D1e's other two predicates were not retired with it: they
    /// are console-lifecycle ownership, which R6C's argument does not reach.
    #[cfg(feature = "wyr1e8-selector33")]
    pub(crate) const fn e8_tuple_waiting_for_serial(&self) -> bool {
        self.e8_evidence.tuple_waiting_for_serial()
    }

    #[cfg(feature = "wyr1e8-selector33")]
    pub(crate) const fn routine_console_relaunch_allowed(&self) -> bool {
        self.e8_trigger.is_none()
            && self.e8_held.is_none()
            && !self.e8_evidence.tuple_waiting_for_serial()
    }

    #[cfg(feature = "wyr1e8-selector33")]
    pub(crate) const fn recovery_owns_console_retirement(&self) -> bool {
        !self.routine_console_relaunch_allowed()
    }

    #[cfg(feature = "wyr1e8-selector33")]
    pub(crate) const fn e8_stage(&self) -> u32 {
        self.e8_evidence.stage()
    }

    #[cfg(feature = "wyr1e8-selector33")]
    fn record_e8_shell_jobs<S: Wyr1BPlatform>(
        &mut self,
        system: &mut S,
        request: &[u8],
        response: &[u8],
        handles: &[DwReceivedHandleInfoV1],
        accepted_deadline: Option<u64>,
    ) -> Result<(), InitError> {
        #[cfg(test)]
        if !self.e8_evidence.ready() {
            return Ok(());
        }
        let trigger = e8_trigger_from_transaction(
            self.e8_evidence.stage(),
            self.e8_evidence.nonce(),
            request,
            response,
            handles.len(),
        )?;
        match (trigger, accepted_deadline) {
            (Some(identity), Some(deadline))
                if deadline != 0
                    && self.e8_trigger == Some(identity)
                    && self.recovery_deadline == Some(deadline)
                    && self.e8_held.is_none() => {}
            (None, None) => {}
            _ => return Err(InitError::Accounting),
        }
        let mut candidate = self.e8_evidence;
        candidate.shell_jobs_transaction(request, response, handles, |record| {
            Self::submit_e8(system, record)
        })?;
        self.require_recovery_live(system)?;
        self.e8_evidence = candidate;
        Ok(())
    }

    #[cfg(feature = "wyr1e8-selector33")]
    fn install_e8_trigger_before_accept(
        &mut self,
        request: E8TriggerRequest,
        job_id: u64,
        deadline: u64,
    ) -> Result<(), InitError> {
        if deadline == 0 || self.e8_trigger.is_some() || self.e8_held.is_some() {
            return Err(InitError::Accounting);
        }
        self.e8_trigger = Some(E8TriggerIdentity {
            launch_transaction: request.reservation.transaction_id,
            job_id,
            action: request.action,
        });
        // The episode's budget and the trigger that opened it are set together
        // and cleared together, so no caller can observe one without the other.
        self.recovery_deadline = Some(deadline);
        Ok(())
    }

    #[cfg(feature = "wyr1e8-selector33")]
    fn classify_e8_trigger_launch(
        &self,
        reservation: LaunchReservation,
        launch: &wyrmroot_launch_proto::LaunchRequest<'_>,
        opens_episode: bool,
    ) -> Result<Option<E8TriggerRequest>, InitError> {
        let trigger = e8_trigger_from_launch(
            self.e8_evidence.stage(),
            self.e8_evidence.nonce(),
            reservation,
            launch,
            opens_episode,
        )?;
        if trigger.is_some() && (self.e8_trigger.is_some() || self.e8_held.is_some()) {
            return Err(InitError::Accounting);
        }
        Ok(trigger)
    }

    #[cfg(feature = "wyr1e8-selector33")]
    fn record_e8_outer_response<S: Wyr1BPlatform>(
        &mut self,
        system: &mut S,
        request: &[u8],
        response: &[u8],
    ) -> Result<(), InitError> {
        #[cfg(test)]
        if !self.e8_evidence.ready() {
            return Ok(());
        }
        self.e8_evidence
            .observe_outer_response(request, response, |record| Self::submit_e8(system, record))
    }

    #[cfg(feature = "wyr1e8-selector33")]
    pub(crate) fn set_e8_console_control(&mut self, control: DwHandle) -> Result<(), InitError> {
        if control.0 == 0 || self.e8_console_control.is_some() {
            return Err(InitError::WrongActivationOrder);
        }
        self.e8_console_control = Some(control);
        self.last_console_generation = 0;
        self.last_status_generation = 0;
        self.last_child_generation = 0;
        Ok(())
    }

    #[cfg(feature = "wyr1e8-selector33")]
    pub(crate) fn clear_e8_console_control(&mut self, control: DwHandle) -> Result<(), InitError> {
        if self.e8_console_control != Some(control) {
            return Err(InitError::WrongActivationOrder);
        }
        self.e8_console_control = None;
        Ok(())
    }

    #[cfg(feature = "wyr1e8-selector33")]
    fn hold_e8_wait<S: Wyr1BPlatform>(
        &mut self,
        system: &mut S,
        pending: PendingWait,
        result: ControllerJobResult,
    ) -> Result<bool, InitError> {
        let Some(trigger) = self.e8_trigger else {
            return Ok(false);
        };
        if pending.job_id != trigger.job_id {
            return Ok(false);
        }
        let expected_wait_transaction = trigger
            .launch_transaction
            .checked_add(1)
            .ok_or(InitError::Accounting)?;
        if self.e8_held.is_some()
            || pending.reservation.transaction_id != expected_wait_transaction
            || result != E8_HELD_WAIT_RESULT
        {
            return Err(InitError::Supervision);
        }
        let parsed =
            parse_launch_message(pending.request_bytes(), 0).map_err(|_| InitError::Accounting)?;
        if parsed.reservation != pending.reservation
            || !matches!(parsed.message, LaunchMessage::Wait { job_id } if job_id == trigger.job_id)
        {
            return Err(InitError::Accounting);
        }
        let tuple = self
            .e8_evidence
            .current_tuple()
            .ok_or(InitError::WrongActivationOrder)?;
        let identity = wyrmroot_consoled::quiesce_control::Identity {
            console_generation: tuple.console_generation,
            status_generation: tuple.status_generation,
            shell_generation: tuple.shell_generation,
            outer_shell_job: tuple.outer_job_id,
            trigger_job: trigger.job_id,
            trigger_wait_transaction: pending.reservation.transaction_id,
            action: trigger.action.control(),
            stage_nonce: self.e8_evidence.nonce(),
        };
        let now = system.now().map_err(InitError::Native)?;
        let deadline = self
            .recovery_deadline
            .ok_or(InitError::WrongActivationOrder)?;
        if now >= deadline {
            return Err(InitError::Supervision);
        }
        let bytes = wyrmroot_consoled::quiesce_control::encode(
            wyrmroot_consoled::quiesce_control::Message::Quiesce(identity),
        )
        .map_err(|_| InitError::Accounting)?;
        let control = self
            .e8_console_control
            .ok_or(InitError::WrongActivationOrder)?;
        self.e8_held = Some(E8HeldWait {
            pending,
            identity,
            acknowledged: false,
        });
        system
            .send_channel(control, &bytes)
            .map_err(InitError::Native)?;
        self.require_recovery_live(system)?;
        Ok(true)
    }

    #[cfg(feature = "wyr1e8-selector33")]
    fn e8_wait_is_held(&self, pending: PendingWait) -> Result<bool, InitError> {
        let Some(held) = self.e8_held else {
            return Ok(false);
        };
        if held.pending != pending {
            return Err(InitError::WrongActivationOrder);
        }
        Ok(true)
    }

    pub(crate) fn recovery_deadline_expired(&self, now: u64) -> bool {
        self.recovery_deadline
            .is_some_and(|deadline| now >= deadline)
    }

    #[cfg(feature = "wyr1e8-selector33")]
    pub(crate) fn accept_e8_quiesced(
        &mut self,
        identity: wyrmroot_consoled::quiesce_control::Identity,
        now: u64,
    ) -> Result<E8RecoveryAction, InitError> {
        let deadline = self
            .recovery_deadline
            .ok_or(InitError::WrongActivationOrder)?;
        let held = self
            .e8_held
            .as_mut()
            .ok_or(InitError::WrongActivationOrder)?;
        if identity != held.identity || held.acknowledged || now >= deadline {
            return Err(InitError::Supervision);
        }
        held.acknowledged = true;
        Ok(match identity.action {
            wyrmroot_consoled::quiesce_control::Action::Driver => E8RecoveryAction::Driver,
            wyrmroot_consoled::quiesce_control::Action::Registry => E8RecoveryAction::Registry,
        })
    }

    #[cfg(feature = "wyr1e8-selector33")]
    pub(crate) fn e8_held_for_action(
        &self,
        action: E8RecoveryAction,
    ) -> Result<E8HeldWait, InitError> {
        let held = self.e8_held.ok_or(InitError::WrongActivationOrder)?;
        let actual = match held.identity.action {
            wyrmroot_consoled::quiesce_control::Action::Driver => E8RecoveryAction::Driver,
            wyrmroot_consoled::quiesce_control::Action::Registry => E8RecoveryAction::Registry,
        };
        if actual != action || !held.acknowledged {
            return Err(InitError::WrongActivationOrder);
        }
        Ok(held)
    }

    #[cfg(feature = "wyr1e8-selector33")]
    pub(crate) fn consume_e8_held(&mut self, held: E8HeldWait) {
        debug_assert_eq!(self.e8_held, Some(held));
        self.e8_held = None;
    }

    /// Ends the episode: the trigger that opened it and the budget it was
    /// given are cleared together. Every site that abandons an episode goes
    /// through here, because clearing only one of the two would leave a
    /// deadline that no trigger owns -- and `recovery_deadline_expired` would
    /// then start failing legs for an episode that is over.
    #[cfg(feature = "wyr1e8-selector33")]
    fn close_recovery_episode(&mut self) {
        self.e8_trigger = None;
        self.recovery_deadline = None;
    }

    #[cfg(feature = "wyr1e8-selector33")]
    pub(crate) fn e8_pending_action(&self) -> Option<E8RecoveryAction> {
        self.e8_trigger.map(|trigger| trigger.action)
    }

    pub(crate) fn recovery_deadline(&self) -> Option<u64> {
        self.recovery_deadline
    }

    pub(crate) fn cap_recovery_deadline(&self, deadline: u64) -> u64 {
        self.recovery_deadline
            .map_or(deadline, |episode| deadline.min(episode))
    }

    pub(crate) fn require_recovery_live_at(&self, now: u64) -> Result<(), InitError> {
        if self.recovery_deadline_expired(now) {
            Err(InitError::Supervision)
        } else {
            Ok(())
        }
    }

    /// Reads the clock only when an episode is open, so a build with no
    /// episode pays no syscall for the check.
    pub(crate) fn require_recovery_live<S: Wyr1BPlatform>(
        &self,
        system: &mut S,
    ) -> Result<(), InitError> {
        if self.recovery_deadline.is_none() {
            return Ok(());
        }
        self.require_recovery_live_at(system.now().map_err(InitError::Native)?)
    }

    #[cfg(feature = "wyr1e8-selector33")]
    fn finish_e8_action_if_ready<S: Wyr1BPlatform>(
        &mut self,
        system: &mut S,
    ) -> Result<(), InitError> {
        let Some(trigger) = self.e8_trigger else {
            return Ok(());
        };
        self.require_recovery_live(system)?;
        if !self.e8_evidence.ready() {
            return Ok(());
        }
        let expected_stage = match trigger.action {
            E8RecoveryAction::Driver => 3,
            E8RecoveryAction::Registry => 4,
        };
        if self.e8_evidence.stage() != expected_stage || self.e8_held.is_some() {
            return Err(InitError::WrongActivationOrder);
        }
        self.require_recovery_live(system)?;
        self.close_recovery_episode();
        Ok(())
    }

    #[cfg(feature = "wyr1e8-selector33")]
    pub(crate) fn e8_driver_identity(
        &self,
        request: DriverLaunchRequest,
    ) -> Result<wyrmroot_device_proto::d5_controller::D5DriverIdentity, InitError> {
        let [
            role,
            bundle,
            attempt,
            endpoint,
            endpoint_generation,
            transaction,
            supervisor,
        ] = self
            .e8_evidence
            .current_serial_identity()
            .ok_or(InitError::WrongActivationOrder)?;
        if role != request.role_id.0
            || attempt != request.attempt_generation.0
            || endpoint != request.endpoint.id.0
            || endpoint_generation != request.endpoint.generation.0
            || transaction != request.transaction_id
            || supervisor != request.supervisor_generation.0
        {
            return Err(InitError::Accounting);
        }
        Ok(wyrmroot_device_proto::d5_controller::D5DriverIdentity {
            device_role_id: role,
            bundle_generation: bundle,
            driver_attempt_generation: attempt,
            driver_control_endpoint_id: endpoint,
            driver_control_endpoint_generation: endpoint_generation,
            launch_transaction_id: transaction,
        })
    }

    #[cfg(feature = "wyr1e8-selector33")]
    pub(crate) fn record_e8_forced_retired<S: Wyr1BPlatform>(
        &mut self,
        system: &mut S,
        held: E8HeldWait,
        result: TerminationResult,
    ) -> Result<(), InitError> {
        self.require_recovery_live(system)?;
        let mut candidate = self.e8_evidence;
        candidate.forced_retired(
            held.identity.trigger_wait_transaction,
            held.identity.trigger_job,
            result,
            |record| Self::submit_e8(system, record),
        )?;
        self.require_recovery_live(system)?;
        self.e8_evidence = candidate;
        Ok(())
    }

    pub(crate) const fn health(&self) -> ShellRegistryHealth {
        self.health
    }

    fn reserve_install_transaction(&mut self, generation: u64) -> Result<u64, InitError> {
        if self.health != (ShellRegistryHealth::Healthy { generation }) {
            return Err(InitError::Cleanup);
        }
        let transaction = self.next_install_transaction;
        self.next_install_transaction = transaction.checked_add(1).ok_or(InitError::Accounting)?;
        Ok(transaction)
    }

    fn reserve_shell_generation(
        &mut self,
        request: wyrmroot_launch_proto::ShellV1Request,
    ) -> Result<(), InitError> {
        if self.last_console_generation != 0
            && (request.console_generation < self.last_console_generation
                || request.status_generation <= self.last_status_generation
                || request.requested_child_generation <= self.last_child_generation)
        {
            return Err(InitError::Wyr1BModel(JobError::StaleGeneration));
        }
        self.last_console_generation = request.console_generation;
        self.last_status_generation = request.status_generation;
        self.last_child_generation = request.requested_child_generation;
        Ok(())
    }

    pub(crate) fn poison(&mut self, generation: u64) {
        if self.health == (ShellRegistryHealth::Healthy { generation }) {
            self.health = ShellRegistryHealth::Poisoned { generation };
        }
    }

    pub(crate) fn install_replacement(
        &mut self,
        topology: &mut RegistryTopology,
        generation: u64,
    ) -> Result<(), InitError> {
        self.reserve_replacement_generation(generation)?;
        topology
            .restart(generation)
            .map_err(InitError::Wyr1BModel)?;
        self.commit_replacement_generation(generation)
    }

    pub(crate) fn reserve_replacement_generation(
        &mut self,
        generation: u64,
    ) -> Result<(), InitError> {
        let ShellRegistryHealth::Poisoned {
            generation: previous,
        } = self.health
        else {
            return Err(InitError::WrongActivationOrder);
        };
        if generation <= previous {
            return Err(InitError::Accounting);
        }
        self.replacement_attempts = self
            .replacement_attempts
            .checked_add(1)
            .ok_or(InitError::Accounting)?;
        if self.replacement_attempts > u16::from(WYR0_I_SUPERVISION_POLICY.max_attempts) {
            self.health = ShellRegistryHealth::Exhausted;
            return Err(InitError::Cleanup);
        }
        Ok(())
    }

    pub(crate) fn commit_replacement_generation(
        &mut self,
        generation: u64,
    ) -> Result<(), InitError> {
        let ShellRegistryHealth::Poisoned {
            generation: previous,
        } = self.health
        else {
            return Err(InitError::WrongActivationOrder);
        };
        if generation <= previous {
            return Err(InitError::Accounting);
        }
        self.health = ShellRegistryHealth::Healthy { generation };
        self.next_install_transaction = WYRMSH_FIRST_INSTALL_TRANSACTION;
        Ok(())
    }
}

#[cfg(feature = "wyr1e8-selector33")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct E8TriggerRequest {
    reservation: LaunchReservation,
    action: E8RecoveryAction,
}

/// Classifies a launch the dispatcher has already parsed.
///
/// R7B-4 class D1b. The trigger check used to take raw request bytes and run
/// `parse_launch_message` over them a second time, on the ShellJobs dispatch
/// path, after the dispatcher had already parsed exactly those bytes. That
/// second parse is what made the check a sniff over every launch rather than a
/// comparison against a value already in hand. It takes the parsed launch now.
///
/// The episode still opens from a ShellJobs launch. Moving it off one entirely
/// is the rest of D1b and cannot be done here: the episode must be installed
/// before the launch is accepted, so whatever opens it has to carry the
/// launch's transaction, and every other source changes the E8 request wire or
/// the evidence sequence. That part owes a design decision, not a refactor.
#[cfg(feature = "wyr1e8-selector33")]
fn e8_trigger_from_launch(
    stage: u32,
    nonce: u64,
    reservation: LaunchReservation,
    launch: &wyrmroot_launch_proto::LaunchRequest<'_>,
    opens_episode: bool,
) -> Result<Option<E8TriggerRequest>, InitError> {
    if !opens_episode {
        return Ok(None);
    }
    if launch.stream_count != 3
        || launch.argc() != 3
        || launch.environment_count() != 0
        // argv0 naming the launched path is the general contract, not a fact
        // about this actor. Comparing it to `launch.path` says the same thing
        // without the dispatcher knowing which path that is.
        || launch.arg(0) != Some(launch.path)
    {
        return Err(InitError::Accounting);
    }
    let (action, token_index) = match (stage, launch.arg(1)) {
        (2, Some(wyrmroot_wyr1e_test_actors::RECOVERY_DRIVER_ACTION)) => {
            (E8RecoveryAction::Driver, E8_DRIVER_TRIGGER_TOKEN_INDEX)
        }
        (3, Some(wyrmroot_wyr1e_test_actors::RECOVERY_REGISTRY_ACTION)) => {
            (E8RecoveryAction::Registry, E8_REGISTRY_TRIGGER_TOKEN_INDEX)
        }
        _ => return Err(InitError::Accounting),
    };
    let expected_token = nonce ^ token_index;
    if expected_token == 0 || launch.arg(2).and_then(parse_e8_nonce) != Some(expected_token) {
        return Err(InitError::Accounting);
    }
    Ok(Some(E8TriggerRequest {
        reservation,
        action,
    }))
}

/// Byte-level entry point, for the evidence join that only ever has bytes.
///
/// `e8_trigger_from_transaction` reconstructs a trigger from a recorded
/// request/response pair, where no parsed launch survives. That is not the
/// dispatch path and parsing there costs nothing anyone is paying for.
#[cfg(feature = "wyr1e8-selector33")]
fn e8_trigger_from_request(
    stage: u32,
    nonce: u64,
    request: &[u8],
    handles: usize,
) -> Result<Option<E8TriggerRequest>, InitError> {
    let request = parse_launch_message(request, handles).map_err(|_| InitError::Accounting)?;
    let LaunchMessage::Launch(launch) = request.message else {
        return Ok(None);
    };
    e8_trigger_from_launch(
        stage,
        nonce,
        request.reservation,
        &launch,
        launch.path == wyrmroot_wyr1e_test_actors::RECOVERY_TRIGGER_PATH,
    )
}

#[cfg(feature = "wyr1e8-selector33")]
fn e8_trigger_from_transaction(
    stage: u32,
    nonce: u64,
    request: &[u8],
    response: &[u8],
    handles: usize,
) -> Result<Option<E8TriggerIdentity>, InitError> {
    let Some(trigger) = e8_trigger_from_request(stage, nonce, request, handles)? else {
        return Ok(None);
    };
    let response = parse_launch_message(response, 0).map_err(|_| InitError::Accounting)?;
    let LaunchMessage::LaunchAccepted { job_id } = response.message else {
        return Err(InitError::Accounting);
    };
    if response.reservation != trigger.reservation || job_id == 0 {
        return Err(InitError::Accounting);
    }
    Ok(Some(E8TriggerIdentity {
        launch_transaction: trigger.reservation.transaction_id,
        job_id,
        action: trigger.action,
    }))
}

#[cfg(feature = "wyr1e8-selector33")]
fn parse_e8_nonce(text: &str) -> Option<u64> {
    if text.len() != 16
        || !text
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(byte))
    {
        return None;
    }
    let value = u64::from_str_radix(text, 16).ok()?;
    (value != 0).then_some(value)
}

pub(crate) struct ShellLaunchContext<'a> {
    pub(crate) registry_control: DwHandle,
    pub(crate) topology: &'a mut RegistryTopology,
    pub(crate) state: &'a mut ShellControllerState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InstalledPeer {
    pub grant: EndpointGrant,
    pub loaded: LoadedProcess,
    pub task_group: DwHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JobDispatcherPollOutcome {
    Stable,
    SessionClosed {
        grant: EndpointGrant,
        scope: LaunchSessionScope,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RegistryNativeAttempt {
    pub active: ActiveNativeRole,
    pub control_channel: DwHandle,
    ready_at: u64,
}

#[cfg(all(test, feature = "wyr1e-production"))]
pub(crate) const fn registry_native_attempt_for_fixture(
    active: ActiveNativeRole,
    control_channel: DwHandle,
    ready_at: u64,
) -> RegistryNativeAttempt {
    RegistryNativeAttempt {
        active,
        control_channel,
        ready_at,
    }
}

#[derive(Debug, Eq, PartialEq)]
enum PeerLaunchError {
    PreInstall(InitError),
    InstallCommitted(InitError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerLaunchStage {
    Archive,
    ArtifactLookup,
    ArtifactValidation,
    Grant,
    Correlation,
    TaskGroup,
    ChannelPair,
    InstallMove,
    PeerCapability,
    Load,
    Clock,
    Deadline,
    Ready,
}

const fn peer_launch_error(stage: PeerLaunchStage, error: InitError) -> PeerLaunchError {
    match stage {
        PeerLaunchStage::Archive
        | PeerLaunchStage::ArtifactLookup
        | PeerLaunchStage::ArtifactValidation
        | PeerLaunchStage::Grant
        | PeerLaunchStage::Correlation
        | PeerLaunchStage::TaskGroup
        | PeerLaunchStage::ChannelPair
        | PeerLaunchStage::InstallMove => PeerLaunchError::PreInstall(error),
        PeerLaunchStage::PeerCapability
        | PeerLaunchStage::Load
        | PeerLaunchStage::Clock
        | PeerLaunchStage::Deadline
        | PeerLaunchStage::Ready => PeerLaunchError::InstallCommitted(error),
    }
}

fn retry_preinstall_once<T>(
    mut attempt: impl FnMut() -> Result<T, PeerLaunchError>,
) -> Result<T, PeerLaunchError> {
    match attempt() {
        Err(PeerLaunchError::PreInstall(InitError::Cleanup)) => {
            Err(PeerLaunchError::PreInstall(InitError::Cleanup))
        }
        Err(PeerLaunchError::PreInstall(_)) => attempt(),
        result => result,
    }
}

#[derive(Debug, Eq, PartialEq)]
enum GateRunError {
    PreInstall(InitError),
    CleanupFailed(InitError),
    InstallCommitted {
        error: InitError,
        cleanup_failed: bool,
    },
}

fn classify_gate_run_error(
    install_committed: bool,
    cleanup_failed: bool,
    error: InitError,
) -> GateRunError {
    if install_committed {
        GateRunError::InstallCommitted {
            error,
            cleanup_failed,
        }
    } else if cleanup_failed {
        GateRunError::CleanupFailed(InitError::Cleanup)
    } else {
        GateRunError::PreInstall(error)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct StagedChannelPair {
    first: Option<DwHandle>,
    second: Option<DwHandle>,
}

impl StagedChannelPair {
    const fn new(first: DwHandle, second: DwHandle) -> Self {
        Self {
            first: Some(first),
            second: Some(second),
        }
    }

    fn first(&self) -> Result<DwHandle, InitError> {
        self.first.ok_or(InitError::Accounting)
    }

    fn second(&self) -> Result<DwHandle, InitError> {
        self.second.ok_or(InitError::Accounting)
    }

    fn commit_first_move(&mut self) -> Result<(), InitError> {
        self.first.take().map(|_| ()).ok_or(InitError::Accounting)
    }

    fn commit_second_move(&mut self) -> Result<(), InitError> {
        self.second.take().map(|_| ()).ok_or(InitError::Accounting)
    }

    fn take_first(&mut self) -> Result<DwHandle, InitError> {
        self.first.take().ok_or(InitError::Accounting)
    }

    fn cleanup<S: InitPlatform>(&mut self, system: &mut S) -> bool {
        let mut failed = false;
        for slot in [&mut self.second, &mut self.first] {
            if let Some(handle) = slot.take() {
                failed |= system.close_handle(handle).is_err();
            }
        }
        !failed
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ResidentState {
    pub registry_control: DwHandle,
    pub topology: Option<RegistryTopology>,
    pub gate: GateConfig,
    pub jobs: JobDispatcher,
}

/// Validates the selector-27 retained product without weakening the selector-25
/// profile parser.
pub(crate) fn validate_retained_bootfs(
    bytes: &[u8],
) -> Result<(SystemInit, GateConfig), InitError> {
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
    let controller = SystemInit::from_wyr1b_manifest(manifest)?;
    for role in manifest.roles() {
        let entry = archive.lookup(role.path().as_bytes()).map_err(map_lookup)?;
        if !entry.is_executable() || entry.data().is_empty() {
            return Err(InitError::NonExecutableRole);
        }
        if wyrmroot_runtime::sha256::digest(entry.data()) != *role.executable_identity() {
            return Err(InitError::ArtifactIdentityMismatch(role.id()));
        }
    }
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
    let gate = archive.lookup(GATE_PATH.as_bytes()).map_err(map_lookup)?;
    let gate = parse_config(gate.data()).map_err(InitError::Wyr1BGateConfig)?;
    Ok((controller, gate))
}

/// Validates the C1 retained closure while preserving the selector-27 gate's
/// separate marker/configuration contract.
///
/// The returned UART identity comes from the validated WRRM. Retained roles
/// intentionally remain outside [`SystemInit`]'s early-role launch API.
pub(crate) fn validate_retained_bootfs_c1(
    bytes: &[u8],
) -> Result<(SystemInit, [u8; 32]), InitError> {
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
    let uart_identity = *manifest
        .role(RoleId::Uart16550d)
        .ok_or(InitError::WrongManifestProfile)?
        .executable_identity();
    #[cfg(feature = "wyr1e-production")]
    let controller = SystemInit::from_wyr1e_manifest(manifest)?;
    #[cfg(not(feature = "wyr1e-production"))]
    let controller = SystemInit::from_wyr1c_manifest(manifest)?;
    for role in manifest.roles() {
        let entry = archive.lookup(role.path().as_bytes()).map_err(map_lookup)?;
        if !entry.is_executable() || entry.data().is_empty() {
            return Err(InitError::NonExecutableRole);
        }
        if wyrmroot_runtime::sha256::digest(entry.data()) != *role.executable_identity() {
            return Err(InitError::ArtifactIdentityMismatch(role.id()));
        }
    }
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
    Ok((controller, uart_identity))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn activate_in_place<'a, S, L, W>(
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
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let resident = initialize_resident_in_place(slot, authority, bootfs)?;
    activate_resident(
        system,
        loader,
        waits,
        resident,
        authority,
        bootstrap_channel,
        parent_transaction,
        bootfs,
    )?;
    Ok(resident)
}

fn initialize_resident_in_place<'a>(
    slot: &'a mut MaybeUninit<ResidentSystemInit>,
    authority: LoadAuthority,
    bootfs: &[u8],
) -> Result<&'a mut ResidentSystemInit, InitError> {
    let (controller, gate) = validate_retained_bootfs(bootfs)?;
    #[cfg(feature = "wyr1f-closure")]
    let wyr1f = crate::wyr1f_closure::ClosureEpisode::new(controller.gate_config());
    Ok(slot.write(ResidentSystemInit {
        controller,
        authority,
        result: RecoveryResult::Degraded,
        active: [None; EARLY_ROLE_COUNT],
        evidence_finalized: false,
        session_complete: false,
        last_tick_ns: 0,
        wyr1b: Some(ResidentState {
            registry_control: DwHandle(0),
            topology: None,
            gate,
            jobs: JobDispatcher::new(),
        }),
        wyr1b_evidence: None,
        wyr1c: None,
        #[cfg(feature = "wyr1f-closure")]
        wyr1f,
    }))
}

#[allow(clippy::too_many_arguments)]
fn activate_resident<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    resident: &mut ResidentSystemInit,
    authority: LoadAuthority,
    bootstrap_channel: DwHandle,
    parent_transaction: u64,
    bootfs: &[u8],
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let ResidentSystemInit {
        controller,
        result,
        active,
        wyr1b,
        wyr1b_evidence,
        ..
    } = resident;
    let state = wyr1b.as_mut().ok_or(InitError::Accounting)?;
    let gate = state.gate;
    controller.become_operational()?;
    let mut ready = [0u8; HEADER_BYTES];
    let ready_len =
        encode_ready_for_profile(LaunchProfile::Supervisor, parent_transaction, &mut ready)
            .map_err(InitError::Launch)?;
    system
        .send_channel(bootstrap_channel, &ready[..ready_len])
        .map_err(InitError::Native)?;
    let retire_deadline = system
        .now()
        .map_err(InitError::Native)?
        .checked_add(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns)
        .ok_or(InitError::Accounting)?;
    let retired = waits
        .wait_many(
            core::slice::from_ref(&DwWaitItemV1 {
                handle: bootstrap_channel,
                signals: DW_SIGNAL_PEER_CLOSED,
            }),
            DwDeadline(retire_deadline),
        )
        .map_err(|_| InitError::Supervision)?;
    if retired.index != 0 || retired.observed.0 & DW_SIGNAL_PEER_CLOSED.0 == 0 {
        return Err(InitError::Supervision);
    }
    controller.begin_registry(system.now().map_err(InitError::Native)?, 1, 0x1001)?;
    let Some(registry) =
        launch_registry_until_ready(system, loader, waits, controller, authority, bootfs)?
    else {
        return Ok(());
    };
    let (mut registry, mut topology) =
        establish_registry_topology(system, waits, controller, registry)?;
    let (devmgr, activation_result) = match activate_role_until_ready(
        system,
        controller,
        loader,
        waits,
        authority,
        bootfs,
        RoleId::Devmgr,
    )? {
        RoleActivation::Ready(active) => (Some(active), RecoveryResult::Recovered),
        RoleActivation::Degraded => (None, RecoveryResult::Degraded),
    };
    *result = activation_result;
    loop {
        match run_registry_gate(
            system,
            loader,
            waits,
            authority,
            bootfs,
            registry,
            &mut topology,
            gate,
            &mut state.jobs,
        ) {
            Ok(evidence) => {
                *active = [Some(registry.active), devmgr];
                state.registry_control = registry.control_channel;
                state.topology = Some(topology);
                *wyr1b_evidence = Some(evidence);
                return Ok(());
            }
            Err(GateRunError::PreInstall(_error)) => {
                *result = RecoveryResult::Degraded;
                *active = [Some(registry.active), devmgr];
                state.registry_control = registry.control_channel;
                state.topology = Some(topology);
                return Ok(());
            }
            Err(GateRunError::CleanupFailed(_)) => {
                let _ = poison_registry_generation(system, waits, controller, registry, true)?;
                *result = RecoveryResult::Degraded;
                *active = [None, devmgr];
                state.topology = Some(topology);
                return Ok(());
            }
            Err(GateRunError::InstallCommitted {
                error: _,
                cleanup_failed,
            }) => {
                if poison_registry_generation(system, waits, controller, registry, cleanup_failed)?
                {
                    *result = RecoveryResult::Degraded;
                    *active = [None, devmgr];
                    state.topology = Some(topology);
                    return Ok(());
                }
                let Some(replacement) = launch_registry_until_ready(
                    system, loader, waits, controller, authority, bootfs,
                )?
                else {
                    *result = RecoveryResult::Degraded;
                    *active = [None, devmgr];
                    state.topology = Some(topology);
                    return Ok(());
                };
                registry = restart_topology_or_poison(
                    system,
                    waits,
                    controller,
                    &mut topology,
                    replacement,
                )?;
            }
        }
    }
}

fn gate_record(
    message_type: GateMessageType,
    gate: GateConfig,
    grant: EndpointGrant,
    object: EndpointGrant,
    operation_id: u64,
) -> GateRecord {
    GateRecord {
        message_type,
        nonce: gate.nonce,
        registry_generation: grant.registry_generation,
        actor_id: grant.endpoint_id,
        actor_generation: grant.endpoint_generation,
        object_id: object.endpoint_id,
        object_generation: object.endpoint_generation,
        operation_id,
        value: 0,
    }
}

fn send_gate<S: InitPlatform>(
    system: &mut S,
    channel: DwHandle,
    record: GateRecord,
) -> Result<(), InitError> {
    let mut bytes = [0u8; GATE_RECORD_BYTES];
    encode_gate_record(record, &mut bytes).map_err(InitError::Wyr1BGateProtocol)?;
    system
        .send_channel(channel, &bytes)
        .map_err(InitError::Native)
}

fn receive_gate<S: Wyr1BPlatform>(
    system: &mut S,
    channel: DwHandle,
    deadline: DwDeadline,
) -> Result<GateRecord, InitError> {
    let item = DwWaitItemV1 {
        handle: channel,
        signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    };
    let observed = system
        .wait_many(core::slice::from_ref(&item), deadline)
        .map_err(InitError::Native)?;
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(InitError::Supervision);
    }
    let mut bytes = [0u8; GATE_RECORD_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = system
        .receive_channel(channel, &mut bytes, &mut handles)
        .map_err(InitError::Native)?;
    if counts.bytes != GATE_RECORD_BYTES || counts.handles != 0 {
        if counts.handles != 0 && handles[0].handle.0 != 0 {
            system
                .close_handle(handles[0].handle)
                .map_err(|_| InitError::Cleanup)?;
        }
        return Err(InitError::Wyr1BGateProtocol(
            wyrmroot_wyr1b_gate_proto::Error::WrongSize,
        ));
    }
    parse_gate_record(&bytes, Direction::ChildToInit).map_err(InitError::Wyr1BGateProtocol)
}

fn expect_gate(actual: GateRecord, expected: GateRecord) -> Result<(), InitError> {
    if actual == expected {
        Ok(())
    } else {
        Err(InitError::Wyr1BGateMismatch)
    }
}

fn install_publication<S: Wyr1BPlatform>(
    system: &mut S,
    control: DwHandle,
    grant: EndpointGrant,
    registry_endpoint: DwHandle,
    operation: u64,
) -> Result<(), InitError> {
    let mut bytes = [0u8; 256];
    let publication_id = match operation {
        1 => FIRST_PUBLICATION_ID,
        2 => SECOND_PUBLICATION_ID,
        _ => return Err(InitError::Wyr1BGateMismatch),
    };
    let transaction_id = INSTALL_PUBLICATION_TRANSACTION
        .checked_add(operation - 1)
        .ok_or(InitError::Accounting)?;
    let size = encode_install_publication(
        RegistryHeader {
            message_type: RegistryMessageType::InstallPublication,
            registry_generation: grant.registry_generation,
            endpoint_id: 0,
            endpoint_generation: 0,
            transaction_id,
        },
        grant.endpoint_id,
        grant.endpoint_generation,
        TEST_PRIVATE_PUBLISHER_ROLE_ID,
        publication_id,
        operation,
        ECHO_PROTOCOL_ID,
        &[ProtocolVersion {
            major: ECHO_VERSION_MAJOR,
            minor: ECHO_VERSION_MINOR,
        }],
        ECHO_SERVICE_NAME,
        &mut bytes,
    )
    .map_err(InitError::RegistryProtocol)?;
    move_endpoint(system, control, &bytes[..size], registry_endpoint)
}

pub(crate) fn install_client<S: Wyr1BPlatform>(
    system: &mut S,
    control: DwHandle,
    grant: EndpointGrant,
    registry_endpoint: DwHandle,
    client_id: u64,
) -> Result<(), InitError> {
    let mut bytes = [0u8; 104];
    let size = encode_install_client(
        RegistryHeader {
            message_type: RegistryMessageType::InstallClient,
            registry_generation: grant.registry_generation,
            endpoint_id: 0,
            endpoint_generation: 0,
            transaction_id: INSTALL_CLIENT_TRANSACTION,
        },
        InstallClient {
            endpoint_id: grant.endpoint_id,
            endpoint_generation: grant.endpoint_generation,
            client_id,
            client_generation: grant.role_generation,
            scope: EnumerationScope::None,
        },
        &mut bytes,
    )
    .map_err(InitError::RegistryProtocol)?;
    move_endpoint(system, control, &bytes[..size], registry_endpoint)
}

fn install_wyrmsh_registry_client<S: Wyr1BPlatform>(
    system: &mut S,
    control: DwHandle,
    grant: EndpointGrant,
    registry_endpoint: DwHandle,
    transaction_id: u64,
) -> Result<(), InitError> {
    let mut bytes = [0_u8; 104];
    let size = encode_install_client(
        RegistryHeader {
            message_type: RegistryMessageType::InstallClient,
            registry_generation: grant.registry_generation,
            endpoint_id: 0,
            endpoint_generation: 0,
            transaction_id,
        },
        InstallClient {
            endpoint_id: grant.endpoint_id,
            endpoint_generation: grant.endpoint_generation,
            // Registry client IDs cannot repeat within a registry generation,
            // even when a replacement consoled restarts its local counters.
            // The reserved init transaction survives that console replacement.
            client_id: transaction_id,
            client_generation: grant.role_generation,
            scope: EnumerationScope::BootstrapMetadata,
        },
        &mut bytes,
    )
    .map_err(InitError::RegistryProtocol)?;
    move_endpoint(system, control, &bytes[..size], registry_endpoint)
}

fn preflight_wyrmsh_registry<S: Wyr1BPlatform>(
    system: &mut S,
    client: DwHandle,
    grant: EndpointGrant,
    deadline_cap: Option<u64>,
) -> Result<(), InitError> {
    let now = system.now().map_err(InitError::Native)?;
    if deadline_cap.is_some_and(|deadline| now >= deadline) {
        return Err(InitError::Supervision);
    }
    let header = RegistryHeader {
        message_type: RegistryMessageType::Enumerate,
        registry_generation: grant.registry_generation,
        endpoint_id: grant.endpoint_id,
        endpoint_generation: grant.endpoint_generation,
        transaction_id: 1,
    };
    let mut request = [0_u8; REGISTRY_HEADER_BYTES];
    let request_size =
        encode_registry_empty(header, &mut request).map_err(InitError::RegistryProtocol)?;
    system
        .send_channel(client, &request[..request_size])
        .map_err(InitError::Native)?;
    let deadline = DwDeadline(
        now.checked_add(WYRMSH_REGISTRY_DEADLINE_NS)
            .map(|deadline| deadline_cap.map_or(deadline, |cap| deadline.min(cap)))
            .or(deadline_cap)
            .ok_or(InitError::Accounting)?,
    );
    let mut expected_page = 0_u16;
    let mut expected_page_count = None;
    let mut expected_total = None;
    let mut observed_total = 0_u16;
    let mut previous_name = [0_u8; wyrmroot_registry_proto::MAX_SERVICE_NAME_BYTES];
    let mut previous_name_len = 0_usize;
    loop {
        let observed = system
            .wait_many(
                core::slice::from_ref(&DwWaitItemV1 {
                    handle: client,
                    signals: deepwyrm_syscall::DwSignals(
                        DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0,
                    ),
                }),
                deadline,
            )
            .map_err(InitError::Native)?;
        if deadline_cap.is_some_and(|deadline| system.now().map_or(true, |now| now >= deadline)) {
            return Err(InitError::Supervision);
        }
        if observed.index != 0
            || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0
            || observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0
        {
            return Err(InitError::Supervision);
        }
        let mut bytes = [0_u8;
            SERVICE_LIST_PREFIX_BYTES
                + wyrmroot_registry_proto::MAX_SERVICE_LIST_RECORDS * SERVICE_LIST_RECORD_BYTES];
        let mut handles = [DwReceivedHandleInfoV1::default(); 1];
        let counts = system
            .receive_channel(client, &mut bytes, &mut handles)
            .map_err(InitError::Native)?;
        if counts.bytes > bytes.len() || counts.handles != 0 {
            if counts.handles != 0 && handles[0].handle.0 != 0 {
                system
                    .close_handle(handles[0].handle)
                    .map_err(|_| InitError::Cleanup)?;
            }
            return Err(InitError::RegistryProtocol(
                wyrmroot_registry_proto::Error::WrongHandleCount,
            ));
        }
        let parsed = parse_registry_message(&bytes[..counts.bytes], counts.handles)
            .map_err(InitError::RegistryProtocol)?;
        if parsed.header.registry_generation != grant.registry_generation
            || parsed.header.endpoint_id != grant.endpoint_id
            || parsed.header.endpoint_generation != grant.endpoint_generation
            || parsed.header.transaction_id != 1
        {
            return Err(InitError::ResourceIdentityMismatch);
        }
        let RegistryMessage::ServiceList(page) = parsed.message else {
            return Err(InitError::WrongManifestProfile);
        };
        if page.page_index != expected_page
            || expected_page_count.is_some_and(|count| count != page.page_count)
            || expected_total.is_some_and(|count| count != page.total_count)
        {
            return Err(InitError::WrongManifestProfile);
        }
        expected_page_count = Some(page.page_count);
        expected_total = Some(page.total_count);
        for index in 0..usize::from(page.record_count) {
            let record = page.record(index).ok_or(InitError::WrongManifestProfile)?;
            if previous_name_len != 0 && previous_name[..previous_name_len] >= *record.service_name
            {
                return Err(InitError::WrongManifestProfile);
            }
            previous_name[..record.service_name.len()].copy_from_slice(record.service_name);
            previous_name_len = record.service_name.len();
        }
        observed_total = observed_total
            .checked_add(page.record_count)
            .ok_or(InitError::Accounting)?;
        expected_page = expected_page.checked_add(1).ok_or(InitError::Accounting)?;
        if expected_page == page.page_count {
            if observed_total != page.total_count {
                return Err(InitError::WrongManifestProfile);
            }
            return Ok(());
        }
        if usize::from(expected_page) >= MAX_SERVICE_LIST_PAGES {
            return Err(InitError::WrongManifestProfile);
        }
    }
}

fn move_endpoint<S: Wyr1BPlatform>(
    system: &mut S,
    control: DwHandle,
    bytes: &[u8],
    endpoint: DwHandle,
) -> Result<(), InitError> {
    validate_controller_channel(system, endpoint)?;
    let transfer = DwHandleTransferV1 {
        handle: endpoint,
        requested_rights: CHILD_CHANNEL_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    system
        .send_channel_with_handles(control, bytes, core::slice::from_ref(&transfer))
        .map_err(InitError::Native)
}

fn validate_controller_channel<S: InitPlatform>(
    system: &mut S,
    handle: DwHandle,
) -> Result<(), InitError> {
    let info = system
        .query_capability_info(handle)
        .map_err(InitError::Native)?;
    if info.object_type != DW_OBJECT_TYPE_CHANNEL || info.rights != CONTROLLER_CHANNEL_RIGHTS {
        return Err(InitError::ResourceIdentityMismatch);
    }
    Ok(())
}

pub(crate) fn create_controller_channel_pair<S: Wyr1BPlatform>(
    system: &mut S,
) -> Result<(DwHandle, DwHandle), InitError> {
    system
        .channel_create(CONTROLLER_CHANNEL_RIGHTS)
        .map_err(InitError::Native)
}

fn launch_registry<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    controller: &mut SystemInit,
    authority: LoadAuthority,
    bootfs: &[u8],
    deadline_cap: Option<u64>,
) -> Result<RegistryNativeAttempt, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    if let Some(deadline) = deadline_cap {
        let now = system.now().map_err(InitError::Native)?;
        if now >= deadline {
            return Err(InitError::Supervision);
        }
    }
    let RestartState::Starting {
        generation,
        transaction_id,
        ..
    } = controller
        .role_state(RoleId::Registryd)
        .ok_or(InitError::WrongActivationOrder)?
    else {
        return Err(InitError::WrongActivationOrder);
    };
    let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
    let image = archive
        .lookup(REGISTRY_PATH.as_bytes())
        .map_err(map_lookup)?;
    let executable_identity = controller.executable_identity(RoleId::Registryd)?;
    if !image.is_executable()
        || wyrmroot_runtime::sha256::digest(image.data()) != executable_identity
    {
        return Err(InitError::ArtifactIdentityMismatch(RoleId::Registryd));
    }
    if let Some(deadline) = deadline_cap {
        let now = system.now().map_err(InitError::Native)?;
        if now >= deadline {
            return Err(InitError::Supervision);
        }
    }
    let task_group = system
        .create_attempt_task_group(authority.task_group)
        .map_err(InitError::Native)?;
    let reservation =
        match controller.reserve_attempt(RoleId::Registryd, generation, transaction_id) {
            Ok(reservation) => reservation,
            Err(error) => {
                return Err(if system.close_handle(task_group).is_err() {
                    InitError::Cleanup
                } else {
                    error
                });
            }
        };
    let mut channels = match create_controller_channel_pair(system) {
        Ok((first, second)) => StagedChannelPair::new(first, second),
        Err(error) => {
            let close_failed = system.close_handle(task_group).is_err();
            let release_failed = controller.abort_reservation(reservation).is_err();
            return Err(if close_failed || release_failed {
                InitError::Cleanup
            } else {
                error
            });
        }
    };
    let child_control = channels.second()?;
    if let Err(error) = validate_controller_channel(system, child_control) {
        let mut failed = !channels.cleanup(system);
        failed |= system.close_handle(task_group).is_err();
        failed |= controller.abort_reservation(reservation).is_err();
        return Err(if failed { InitError::Cleanup } else { error });
    }
    let loaded = match load_service_process(
        loader,
        LoadAuthority {
            task_group,
            ..authority
        },
        ServiceLoadRequest {
            image: image.data(),
            display_path: REGISTRY_PATH,
            profile: LaunchProfile::BootstrapRegistry,
            service_channel: child_control,
            correlation: None,
            transaction_id,
        },
    ) {
        Ok(loaded) => loaded,
        Err(failure) => {
            if failure.service_channel_consumed {
                channels.commit_second_move()?;
            }
            let control_failed = !channels.cleanup(system);
            let group_failed = system.close_handle(task_group).is_err();
            let release_failed = controller.abort_reservation(reservation).is_err();
            return Err(if control_failed || group_failed || release_failed {
                InitError::Cleanup
            } else {
                InitError::Loader(failure.error)
            });
        }
    };
    channels.commit_second_move()?;
    let started_at = match system.now().map_err(InitError::Native) {
        Ok(now) => now,
        Err(error) => {
            let mut failed =
                cleanup_loaded_before(system, waits, loaded, task_group, true, deadline_cap)
                    .is_err();
            failed |= !channels.cleanup(system);
            failed |= controller.abort_reservation(reservation).is_err();
            return Err(if failed { InitError::Cleanup } else { error });
        }
    };
    if deadline_cap.is_some_and(|deadline| started_at >= deadline) {
        let mut failed =
            cleanup_loaded_before(system, waits, loaded, task_group, true, deadline_cap).is_err();
        failed |= !channels.cleanup(system);
        failed |= controller.abort_reservation(reservation).is_err();
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Supervision
        });
    }
    let deadline = match started_at.checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns) {
        Some(deadline) => deadline_cap.map_or(deadline, |cap| deadline.min(cap)),
        None => {
            let mut failed =
                cleanup_loaded_before(system, waits, loaded, task_group, true, deadline_cap)
                    .is_err();
            failed |= !channels.cleanup(system);
            failed |= controller.abort_reservation(reservation).is_err();
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Accounting
            });
        }
    };
    let resources = AttemptResources {
        role: RoleId::Registryd,
        generation,
        transaction_id,
        executable_identity,
        startup_profile: StartupProfile::BootstrapRegistry,
        task_group,
        process: loaded.process,
        launch_channel: loaded.launch_channel,
        mappings: 0,
        reservation,
    };
    if let Err(error) = controller.install_attempt(resources) {
        let cleanup = cleanup_loaded_before(system, waits, loaded, task_group, true, deadline_cap);
        let control_failed = !channels.cleanup(system);
        return Err(if cleanup.is_err() || control_failed {
            InitError::Cleanup
        } else {
            error
        });
    }
    let control_channel = channels.take_first()?;
    if let Err(error) =
        controller.child_started(RoleId::Registryd, generation, transaction_id, started_at)
    {
        return Err(reconcile_failed_registry_launch(
            system,
            waits,
            controller,
            loaded,
            task_group,
            control_channel,
            generation,
            transaction_id,
            started_at,
            AttemptFailure::CreationFailed,
            error,
            deadline_cap,
        ));
    }
    if let Err(_error) = await_child_ready_profile_observed(
        waits,
        loaded.process,
        loaded.launch_channel,
        LaunchProfile::BootstrapRegistry,
        transaction_id,
        DwDeadline(deadline),
    ) {
        return Err(reconcile_failed_registry_launch(
            system,
            waits,
            controller,
            loaded,
            task_group,
            control_channel,
            generation,
            transaction_id,
            started_at,
            AttemptFailure::WaitFailed,
            InitError::Supervision,
            deadline_cap,
        ));
    }
    let ready_at = match system.now().map_err(InitError::Native) {
        Ok(now) => now,
        Err(error) => {
            return Err(reconcile_failed_registry_launch(
                system,
                waits,
                controller,
                loaded,
                task_group,
                control_channel,
                generation,
                transaction_id,
                started_at,
                AttemptFailure::WaitFailed,
                error,
                deadline_cap,
            ));
        }
    };
    if deadline_cap.is_some_and(|deadline| ready_at >= deadline) {
        return Err(reconcile_failed_registry_launch(
            system,
            waits,
            controller,
            loaded,
            task_group,
            control_channel,
            generation,
            transaction_id,
            ready_at,
            AttemptFailure::WaitFailed,
            InitError::Supervision,
            deadline_cap,
        ));
    }
    if let Err(error) = controller.ready(RoleId::Registryd, generation, transaction_id, ready_at) {
        return Err(reconcile_failed_registry_launch(
            system,
            waits,
            controller,
            loaded,
            task_group,
            control_channel,
            generation,
            transaction_id,
            ready_at,
            AttemptFailure::WaitFailed,
            error,
            deadline_cap,
        ));
    }
    let installed_generation = match controller
        .resources(RoleId::Registryd)
        .map(|resources| resources.generation)
    {
        Some(generation) => generation,
        None => {
            return Err(reconcile_failed_registry_launch(
                system,
                waits,
                controller,
                loaded,
                task_group,
                control_channel,
                generation,
                transaction_id,
                ready_at,
                AttemptFailure::WaitFailed,
                InitError::MissingAttemptResources,
                deadline_cap,
            ));
        }
    };
    if installed_generation != generation {
        return Err(reconcile_failed_registry_launch(
            system,
            waits,
            controller,
            loaded,
            task_group,
            control_channel,
            generation,
            transaction_id,
            ready_at,
            AttemptFailure::WaitFailed,
            InitError::ResourceIdentityMismatch,
            deadline_cap,
        ));
    }
    Ok(RegistryNativeAttempt {
        active: ActiveNativeRole {
            role: RoleId::Registryd,
            generation,
            transaction_id,
            loaded,
            task_group,
        },
        control_channel,
        ready_at,
    })
}

pub(crate) fn establish_registry_topology<S, W>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    registry: RegistryNativeAttempt,
) -> Result<(RegistryNativeAttempt, RegistryTopology), InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    match RegistryTopology::new(registry.active.generation).map_err(InitError::Wyr1BModel) {
        Ok(topology) => Ok((registry, topology)),
        Err(error) => Err(reconcile_failed_registry_launch(
            system,
            waits,
            controller,
            registry.active.loaded,
            registry.active.task_group,
            registry.control_channel,
            registry.active.generation,
            registry.active.transaction_id,
            registry.ready_at,
            AttemptFailure::WaitFailed,
            error,
            None,
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn reconcile_failed_registry_launch<
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    loaded: LoadedProcess,
    task_group: DwHandle,
    control_channel: DwHandle,
    generation: u64,
    transaction_id: u64,
    classified_at: u64,
    failure: AttemptFailure,
    original: InitError,
    deadline_cap: Option<u64>,
) -> InitError {
    let transition = match controller.role_state(RoleId::Registryd) {
        Some(RestartState::Starting { .. }) | Some(RestartState::Ready { .. }) => controller.fail(
            RoleId::Registryd,
            generation,
            transaction_id,
            classified_at,
            failure,
        ),
        Some(RestartState::AwaitingReady { .. }) => controller.ready_wait_failed(
            RoleId::Registryd,
            generation,
            transaction_id,
            classified_at,
            failure,
        ),
        _ => Err(InitError::WrongActivationOrder),
    };
    if transition.is_err() {
        let _ = cleanup_loaded_before(system, waits, loaded, task_group, true, deadline_cap);
        let _ = system.close_handle(control_channel);
        controller.fatal();
        return InitError::Cleanup;
    }
    let cleanup_failed =
        cleanup_loaded_before(system, waits, loaded, task_group, true, deadline_cap).is_err()
            | system.close_handle(control_channel).is_err();
    let completed_at = match system.now() {
        Ok(value) => value,
        Err(_) => {
            controller.fatal();
            return InitError::Cleanup;
        }
    };
    let retired_at = match classified_at.checked_add(1) {
        Some(value) => value.max(completed_at),
        None => {
            controller.fatal();
            return InitError::Accounting;
        }
    };
    if cleanup_failed {
        let _ =
            controller.cleanup_failed(RoleId::Registryd, generation, transaction_id, retired_at);
        return InitError::Cleanup;
    }
    match controller.cleanup_complete(RoleId::Registryd, generation, transaction_id, retired_at) {
        Ok(()) => original,
        Err(_) => {
            controller.fatal();
            InitError::Cleanup
        }
    }
}

pub(crate) fn launch_registry_until_ready<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    controller: &mut SystemInit,
    authority: LoadAuthority,
    bootfs: &[u8],
) -> Result<Option<RegistryNativeAttempt>, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    launch_registry_until_ready_inner(system, loader, waits, controller, authority, bootfs, None)
}

/// The deadline-capped launch, matching the eight other `_before` helpers that
/// were already ordinary. R7B-4 took the selector gate off and the argument to
/// `Option<u64>`: with no episode open the cap is `None` and this is the plain
/// launch, which is what the `not(selector)` call site used to spell by hand.
#[allow(clippy::too_many_arguments)]
pub(crate) fn launch_registry_until_ready_before<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    controller: &mut SystemInit,
    authority: LoadAuthority,
    bootfs: &[u8],
    deadline_cap: Option<u64>,
) -> Result<Option<RegistryNativeAttempt>, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    launch_registry_until_ready_inner(
        system,
        loader,
        waits,
        controller,
        authority,
        bootfs,
        deadline_cap,
    )
}

#[allow(clippy::too_many_arguments)]
fn launch_registry_until_ready_inner<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    controller: &mut SystemInit,
    authority: LoadAuthority,
    bootfs: &[u8],
    deadline_cap: Option<u64>,
) -> Result<Option<RegistryNativeAttempt>, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    loop {
        let attempt_transaction = match controller
            .role_state(RoleId::Registryd)
            .ok_or(InitError::WrongActivationOrder)?
        {
            RestartState::Starting { transaction_id, .. } => transaction_id,
            _ => return Err(InitError::WrongActivationOrder),
        };
        let attempt_time = system.now().map_err(InitError::Native)?;
        if deadline_cap.is_some_and(|deadline| attempt_time >= deadline) {
            return Err(InitError::Supervision);
        }
        match launch_registry(
            system,
            loader,
            waits,
            controller,
            authority,
            bootfs,
            deadline_cap,
        ) {
            Ok(value) => return Ok(Some(value)),
            Err(error) => {
                let now = attempt_time;
                let state = controller
                    .role_state(RoleId::Registryd)
                    .ok_or(InitError::WrongActivationOrder)?;
                let (generation, transaction_id) = match state {
                    RestartState::Starting {
                        generation,
                        transaction_id,
                        ..
                    } => (generation, transaction_id),
                    RestartState::Backoff { .. } => {
                        if advance_registry_or_exhausted_with_cap(
                            system,
                            controller,
                            attempt_transaction,
                            deadline_cap,
                        )? {
                            return Ok(None);
                        }
                        continue;
                    }
                    RestartState::PermanentFailure { .. } => return Ok(None),
                    _ => return Err(InitError::WrongActivationOrder),
                };
                controller.fail(
                    RoleId::Registryd,
                    generation,
                    transaction_id,
                    now,
                    AttemptFailure::CreationFailed,
                )?;
                let retired_at = now.checked_add(1).ok_or(InitError::Accounting)?;
                if error == InitError::Cleanup {
                    controller.cleanup_failed(
                        RoleId::Registryd,
                        generation,
                        transaction_id,
                        retired_at,
                    )?;
                    return Ok(None);
                }
                controller.cleanup_complete(
                    RoleId::Registryd,
                    generation,
                    transaction_id,
                    retired_at,
                )?;
                if advance_registry_or_exhausted_with_cap(
                    system,
                    controller,
                    transaction_id,
                    deadline_cap,
                )? {
                    return Ok(None);
                }
            }
        }
    }
}

pub(crate) fn poison_registry_generation<S, W>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    registry: RegistryNativeAttempt,
    dependent_cleanup_failed: bool,
) -> Result<bool, InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    poison_registry_generation_before(
        system,
        waits,
        controller,
        registry,
        dependent_cleanup_failed,
        None,
    )
}

pub(crate) fn poison_registry_generation_before<S, W>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    registry: RegistryNativeAttempt,
    dependent_cleanup_failed: bool,
    deadline_cap: Option<u64>,
) -> Result<bool, InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    retire_registry_generation(
        system,
        waits,
        controller,
        registry,
        dependent_cleanup_failed,
        deadline_cap,
        RegistryRetirement::Failure,
    )
}

pub(crate) fn retire_registry_for_recovery_before<S, W>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    registry: RegistryNativeAttempt,
    deadline_cap: Option<u64>,
) -> Result<bool, InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    retire_registry_generation(
        system,
        waits,
        controller,
        registry,
        false,
        deadline_cap,
        RegistryRetirement::CoordinatedRecovery,
    )
}

enum RegistryRetirement {
    Failure,
    /// Retire a published, healthy owner as part of an admitted recovery
    /// episode, keeping its accounting token. Only reachable while an episode
    /// is open, so a build that opens none never selects it.
    CoordinatedRecovery,
}

fn retire_registry_generation<S, W>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    registry: RegistryNativeAttempt,
    dependent_cleanup_failed: bool,
    deadline_cap: Option<u64>,
    retirement: RegistryRetirement,
) -> Result<bool, InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let observed_now = system.now().map_err(InitError::Native);
    let (transition_now, transition) = match observed_now {
        Ok(now) => (
            Some(now),
            match retirement {
                RegistryRetirement::Failure => controller.fail(
                    RoleId::Registryd,
                    registry.active.generation,
                    registry.active.transaction_id,
                    now,
                    AttemptFailure::WaitFailed,
                ),
                RegistryRetirement::CoordinatedRecovery
                    if deadline_cap.is_some_and(|deadline| now < deadline) =>
                {
                    controller.admit_recovery(
                        RoleId::Registryd,
                        registry.active.generation,
                        registry.active.transaction_id,
                        now,
                    )
                }
                RegistryRetirement::CoordinatedRecovery => Err(InitError::Supervision),
            },
        ),
        Err(error) => (None, Err(error)),
    };
    let native_cleanup_failed = cleanup_loaded_before(
        system,
        waits,
        registry.active.loaded,
        registry.active.task_group,
        true,
        deadline_cap,
    )
    .is_err()
        | system.close_handle(registry.control_channel).is_err()
        | dependent_cleanup_failed;

    let now = match transition {
        Ok(()) => transition_now.ok_or(InitError::Accounting)?,
        Err(error) => {
            let identity_mismatch = matches!(
                error,
                InitError::Restart(RestartTransitionError::StaleGeneration)
                    | InitError::Restart(RestartTransitionError::TransactionMismatch)
            );
            let retirement = if identity_mismatch || transition_now.is_none() {
                controller.retire_attempt_after_fatal(RoleId::Registryd)
            } else {
                controller.retire_active_fail_closed(
                    RoleId::Registryd,
                    registry.active.generation,
                    registry.active.transaction_id,
                    transition_now.ok_or(InitError::Accounting)?,
                    AttemptFailure::WaitFailed,
                    if native_cleanup_failed {
                        CleanupDisposition::Failed
                    } else {
                        CleanupDisposition::Complete
                    },
                )
            };
            if retirement.is_err() {
                let _ = controller.retire_attempt_after_fatal(RoleId::Registryd);
            }
            return Err(if native_cleanup_failed || retirement.is_err() {
                InitError::Cleanup
            } else {
                // Preserve the original transition error after complete native
                // cleanup; its exact type explains why fail()->CleaningUp did
                // not commit while the role is now truthfully permanent.
                error
            });
        }
    };
    let completed_at = system.now().map_err(InitError::Native)?;
    let retired_at = now
        .checked_add(1)
        .map_or(completed_at, |minimum| minimum.max(completed_at));
    let deadline_expired = deadline_cap.is_some_and(|deadline| completed_at >= deadline);
    let cleanup_must_fail = native_cleanup_failed || retired_at == now;
    if cleanup_must_fail {
        if controller
            .cleanup_failed(
                RoleId::Registryd,
                registry.active.generation,
                registry.active.transaction_id,
                retired_at,
            )
            .is_err()
        {
            let _ = controller.retire_attempt_after_fatal(RoleId::Registryd);
            return Err(InitError::Cleanup);
        }
        return if retired_at == now && !native_cleanup_failed {
            Err(InitError::Accounting)
        } else {
            Ok(true)
        };
    }
    if let Err(error) = controller.cleanup_complete(
        RoleId::Registryd,
        registry.active.generation,
        registry.active.transaction_id,
        retired_at,
    ) {
        let _ = controller.retire_attempt_after_fatal(RoleId::Registryd);
        return Err(error);
    }
    if deadline_expired {
        return Err(InitError::Supervision);
    }
    advance_registry_or_exhausted_with_cap(
        system,
        controller,
        registry.active.transaction_id,
        deadline_cap,
    )
}

pub(crate) fn restart_topology_or_poison<S, W>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    topology: &mut RegistryTopology,
    registry: RegistryNativeAttempt,
) -> Result<RegistryNativeAttempt, InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    restart_topology_or_poison_before(system, waits, controller, topology, registry, None)
}

pub(crate) fn restart_topology_or_poison_before<S, W>(
    system: &mut S,
    waits: &mut W,
    controller: &mut SystemInit,
    topology: &mut RegistryTopology,
    registry: RegistryNativeAttempt,
    deadline_cap: Option<u64>,
) -> Result<RegistryNativeAttempt, InitError>
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    if deadline_cap.is_some_and(|deadline| system.now().map_or(true, |now| now >= deadline)) {
        let cleanup = poison_registry_generation_before(
            system,
            waits,
            controller,
            registry,
            false,
            deadline_cap,
        );
        return match cleanup {
            Err(InitError::Cleanup) => Err(InitError::Cleanup),
            Err(error) => Err(error),
            Ok(_) => Err(InitError::Supervision),
        };
    }
    if let Err(error) = topology
        .restart(registry.active.generation)
        .map_err(InitError::Wyr1BModel)
    {
        let _ = poison_registry_generation_before(
            system,
            waits,
            controller,
            registry,
            false,
            deadline_cap,
        )?;
        return Err(error);
    }
    if deadline_cap.is_some_and(|deadline| system.now().map_or(true, |now| now >= deadline)) {
        let _ = poison_registry_generation_before(
            system,
            waits,
            controller,
            registry,
            false,
            deadline_cap,
        )?;
        return Err(InitError::Supervision);
    }
    Ok(registry)
}

fn advance_registry_or_exhausted<S: InitPlatform>(
    system: &mut S,
    controller: &mut SystemInit,
    transaction_id: u64,
) -> Result<bool, InitError> {
    let _ = advance_or_degrade(system, controller, RoleId::Registryd, transaction_id)?;
    Ok(matches!(
        controller
            .role_state(RoleId::Registryd)
            .ok_or(InitError::WrongActivationOrder)?,
        RestartState::PermanentFailure { .. }
    ))
}

fn advance_registry_or_exhausted_with_cap<S: InitPlatform>(
    system: &mut S,
    controller: &mut SystemInit,
    transaction_id: u64,
    deadline_cap: Option<u64>,
) -> Result<bool, InitError> {
    let Some(action_deadline) = deadline_cap else {
        return advance_registry_or_exhausted(system, controller, transaction_id);
    };
    match controller
        .role_state(RoleId::Registryd)
        .ok_or(InitError::WrongActivationOrder)?
    {
        RestartState::PermanentFailure { .. } => Ok(true),
        RestartState::Backoff {
            next_generation,
            deadline_ns,
            ..
        } => {
            let wait_deadline = deadline_ns.min(action_deadline);
            system
                .wait_until(wait_deadline)
                .map_err(InitError::Native)?;
            let observed_now = system.now().map_err(InitError::Native)?;
            if observed_now < wait_deadline {
                return Err(InitError::WrongActivationOrder);
            }
            if observed_now >= action_deadline {
                return Err(InitError::Supervision);
            }
            controller.start_replacement(
                RoleId::Registryd,
                observed_now,
                next_generation,
                next_transaction(transaction_id)?,
            )?;
            Ok(matches!(controller.mode(), SystemMode::Degraded))
        }
        _ => Err(InitError::WrongActivationOrder),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerKind {
    Publisher {
        operation: u64,
    },
    Client {
        path: &'static str,
        role_generation: u64,
        transaction_id: u64,
        client_id: u64,
    },
}

#[allow(clippy::too_many_arguments)]
fn launch_peer<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootfs: &[u8],
    registry_control: DwHandle,
    topology: &mut RegistryTopology,
    kind: PeerKind,
) -> Result<InstalledPeer, PeerLaunchError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let (endpoint_kind, role_generation, path, profile, transaction_id) = match kind {
        PeerKind::Publisher { operation } => (
            EndpointKind::Publication,
            operation,
            PUBLISHER_PATH,
            LaunchProfile::BootstrapService,
            0x2000 + operation,
        ),
        PeerKind::Client {
            path,
            role_generation,
            transaction_id,
            client_id: _,
        } => (
            EndpointKind::RegistryClient,
            role_generation,
            path,
            LaunchProfile::RegistryClient,
            transaction_id,
        ),
    };
    let archive = Archive::new(bootfs)
        .map_err(|error| peer_launch_error(PeerLaunchStage::Archive, InitError::Bootfs(error)))?;
    let image = archive
        .lookup(path.as_bytes())
        .map_err(|error| peer_launch_error(PeerLaunchStage::ArtifactLookup, map_lookup(error)))?;
    if !image.is_executable() || image.data().is_empty() {
        return Err(peer_launch_error(
            PeerLaunchStage::ArtifactValidation,
            InitError::NonExecutableRole,
        ));
    }
    let grant = topology
        .issue(role_generation, endpoint_kind)
        .map_err(|error| peer_launch_error(PeerLaunchStage::Grant, InitError::Wyr1BModel(error)))?;
    let correlation = correlation_environment(grant).map_err(|error| {
        peer_launch_error(PeerLaunchStage::Correlation, InitError::Wyr1BModel(error))
    })?;
    let task_group = system
        .create_attempt_task_group(authority.task_group)
        .map_err(|error| peer_launch_error(PeerLaunchStage::TaskGroup, InitError::Native(error)))?;
    let mut channels = match create_controller_channel_pair(system) {
        Ok((first, second)) => StagedChannelPair::new(first, second),
        Err(error) => {
            return Err(peer_launch_error(
                PeerLaunchStage::ChannelPair,
                if system.close_handle(task_group).is_err() {
                    InitError::Cleanup
                } else {
                    error
                },
            ));
        }
    };
    let registry_endpoint = channels.first().map_err(PeerLaunchError::PreInstall)?;
    let install = match kind {
        PeerKind::Publisher { operation } => install_publication(
            system,
            registry_control,
            grant,
            registry_endpoint,
            operation,
        ),
        PeerKind::Client { client_id, .. } => install_client(
            system,
            registry_control,
            grant,
            registry_endpoint,
            client_id,
        ),
    };
    if let Err(error) = install {
        let mut failed = !channels.cleanup(system);
        failed |= system.close_handle(task_group).is_err();
        return Err(peer_launch_error(
            PeerLaunchStage::InstallMove,
            if failed { InitError::Cleanup } else { error },
        ));
    }
    channels
        .commit_first_move()
        .map_err(PeerLaunchError::InstallCommitted)?;
    // A successful install MOVE transfers the registry endpoint. Any later
    // failure poisons this registry generation; init must not retry against it.
    let peer_endpoint = channels
        .second()
        .map_err(PeerLaunchError::InstallCommitted)?;
    if let Err(error) = validate_controller_channel(system, peer_endpoint) {
        let failed = !channels.cleanup(system) | system.close_handle(task_group).is_err();
        return Err(peer_launch_error(
            PeerLaunchStage::PeerCapability,
            if failed { InitError::Cleanup } else { error },
        ));
    }
    let loaded = match load_service_process(
        loader,
        LoadAuthority {
            task_group,
            ..authority
        },
        ServiceLoadRequest {
            image: image.data(),
            display_path: path,
            profile,
            service_channel: peer_endpoint,
            correlation: Some(&correlation),
            transaction_id,
        },
    ) {
        Ok(loaded) => loaded,
        Err(failure) => {
            if failure.service_channel_consumed {
                channels
                    .commit_second_move()
                    .map_err(PeerLaunchError::InstallCommitted)?;
            }
            let close_failed = !channels.cleanup(system) | system.close_handle(task_group).is_err();
            return Err(peer_launch_error(
                PeerLaunchStage::Load,
                if close_failed {
                    InitError::Cleanup
                } else {
                    InitError::Loader(failure.error)
                },
            ));
        }
    };
    channels
        .commit_second_move()
        .map_err(PeerLaunchError::InstallCommitted)?;
    let now = match system.now().map_err(InitError::Native) {
        Ok(now) => now,
        Err(error) => {
            let cleanup = cleanup_loaded(system, waits, loaded, task_group, true);
            return Err(peer_launch_error(
                PeerLaunchStage::Clock,
                if cleanup.is_err() {
                    InitError::Cleanup
                } else {
                    error
                },
            ));
        }
    };
    let deadline = match now.checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns) {
        Some(deadline) => deadline,
        None => {
            let cleanup = cleanup_loaded(system, waits, loaded, task_group, true);
            return Err(peer_launch_error(
                PeerLaunchStage::Deadline,
                if cleanup.is_err() {
                    InitError::Cleanup
                } else {
                    InitError::Accounting
                },
            ));
        }
    };
    if await_child_ready_profile_observed(
        waits,
        loaded.process,
        loaded.launch_channel,
        profile,
        transaction_id,
        DwDeadline(deadline),
    )
    .is_err()
    {
        return Err(peer_launch_error(
            PeerLaunchStage::Ready,
            if cleanup_loaded(system, waits, loaded, task_group, true).is_err() {
                InitError::Cleanup
            } else {
                InitError::Supervision
            },
        ));
    }
    Ok(InstalledPeer {
        grant,
        loaded,
        task_group,
    })
}

#[cfg(feature = "dw1e3-selector31")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn launch_registry_client_actor<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootfs: &[u8],
    registry_control: DwHandle,
    topology: &mut RegistryTopology,
    path: &'static str,
    role_generation: u64,
    transaction_id: u64,
    client_id: u64,
) -> Result<InstalledPeer, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    launch_peer(
        system,
        loader,
        waits,
        authority,
        bootfs,
        registry_control,
        topology,
        PeerKind::Client {
            path,
            role_generation,
            transaction_id,
            client_id,
        },
    )
    .map_err(|error| match error {
        PeerLaunchError::PreInstall(error) | PeerLaunchError::InstallCommitted(error) => error,
    })
}

fn configure_publisher<S: InitPlatform>(
    system: &mut S,
    gate: GateConfig,
    publisher: InstalledPeer,
    client: InstalledPeer,
    operation: u64,
) -> Result<GateRecord, InitError> {
    let record = gate_record(
        GateMessageType::ConfigurePublisher,
        gate,
        publisher.grant,
        client.grant,
        operation,
    );
    send_gate(system, publisher.loaded.launch_channel, record)?;
    Ok(record)
}

fn configure_client<S: InitPlatform>(
    system: &mut S,
    gate: GateConfig,
    client: InstalledPeer,
    publisher: InstalledPeer,
    operation: u64,
) -> Result<GateRecord, InitError> {
    let record = gate_record(
        GateMessageType::ConfigureRegistryClient,
        gate,
        client.grant,
        publisher.grant,
        operation,
    );
    send_gate(system, client.loaded.launch_channel, record)?;
    Ok(record)
}

fn report_deadline<S: InitPlatform>(system: &mut S) -> Result<DwDeadline, InitError> {
    Ok(DwDeadline(
        system
            .now()
            .map_err(InitError::Native)?
            .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .ok_or(InitError::Accounting)?,
    ))
}

fn expect_report<S: Wyr1BPlatform>(
    system: &mut S,
    peer: InstalledPeer,
    configured: GateRecord,
    message_type: GateMessageType,
) -> Result<GateRecord, InitError> {
    let expected = GateRecord {
        message_type,
        ..configured
    };
    let deadline = report_deadline(system)?;
    let actual = receive_gate(system, peer.loaded.launch_channel, deadline)?;
    expect_gate(actual, expected)?;
    Ok(actual)
}

fn expect_challenge_report<S: Wyr1BPlatform>(
    system: &mut S,
    peer: InstalledPeer,
    configured: GateRecord,
    message_type: GateMessageType,
) -> Result<GateRecord, InitError> {
    let deadline = report_deadline(system)?;
    let actual = receive_gate(system, peer.loaded.launch_channel, deadline)?;
    if actual.message_type != message_type
        || actual.nonce != configured.nonce
        || actual.registry_generation != configured.registry_generation
        || actual.actor_id != configured.actor_id
        || actual.actor_generation != configured.actor_generation
        || actual.object_id != configured.object_id
        || actual.object_generation != configured.object_generation
        || actual.operation_id != configured.operation_id
    {
        return Err(InitError::Wyr1BGateMismatch);
    }
    Ok(actual)
}

fn done_record(gate: GateConfig, peer: InstalledPeer, operation_id: u64) -> GateRecord {
    GateRecord {
        message_type: GateMessageType::Done,
        nonce: gate.nonce,
        registry_generation: peer.grant.registry_generation,
        actor_id: peer.grant.endpoint_id,
        actor_generation: peer.grant.endpoint_generation,
        object_id: 0,
        object_generation: 0,
        operation_id,
        value: 0,
    }
}

fn complete_direct_exchange<S: Wyr1BPlatform>(
    system: &mut S,
    publisher: InstalledPeer,
    client: InstalledPeer,
    publisher_config: GateRecord,
    client_config: GateRecord,
) -> Result<u64, InitError> {
    let echoed =
        expect_challenge_report(system, publisher, publisher_config, GateMessageType::Echoed)?;
    let exchanged =
        expect_challenge_report(system, client, client_config, GateMessageType::Exchanged)?;
    if echoed.value != exchanged.value {
        return Err(InitError::Wyr1BGateMismatch);
    }
    Ok(echoed.value)
}

#[allow(clippy::too_many_arguments)]
fn launch_launch_client<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootfs: &[u8],
    topology: &mut RegistryTopology,
    jobs: &mut JobDispatcher,
    operation: u64,
) -> Result<InstalledPeer, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
    let image = archive.lookup(CLIENT_PATH.as_bytes()).map_err(map_lookup)?;
    if !image.is_executable() || image.data().is_empty() {
        return Err(InitError::NonExecutableRole);
    }
    let grant = topology
        .issue(operation, EndpointKind::LaunchSession)
        .map_err(InitError::Wyr1BModel)?;
    let task_group = system
        .create_attempt_task_group(authority.task_group)
        .map_err(InitError::Native)?;
    let mut channels = match create_controller_channel_pair(system) {
        Ok((controller, child)) => StagedChannelPair::new(controller, child),
        Err(error) => {
            return Err(if system.close_handle(task_group).is_err() {
                InitError::Cleanup
            } else {
                error
            });
        }
    };
    let child = channels.second()?;
    let transaction_id = 0x4000_u64
        .checked_add(grant.endpoint_id)
        .ok_or(InitError::Accounting)?;
    let loaded = match load_service_process(
        loader,
        LoadAuthority {
            task_group,
            ..authority
        },
        ServiceLoadRequest {
            image: image.data(),
            display_path: CLIENT_PATH,
            profile: LaunchProfile::LaunchClient,
            service_channel: child,
            correlation: None,
            transaction_id,
        },
    ) {
        Ok(loaded) => loaded,
        Err(failure) => {
            if failure.service_channel_consumed {
                channels.commit_second_move()?;
            }
            let failed = !channels.cleanup(system) | system.close_handle(task_group).is_err();
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Loader(failure.error)
            });
        }
    };
    channels.commit_second_move()?;
    let deadline = report_deadline(system)?;
    if await_child_ready_profile_observed(
        waits,
        loaded.process,
        loaded.launch_channel,
        LaunchProfile::LaunchClient,
        transaction_id,
        deadline,
    )
    .is_err()
    {
        let failed = cleanup_loaded(system, waits, loaded, task_group, true).is_err()
            | !channels.cleanup(system);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Supervision
        });
    }
    let session = channels.take_first()?;
    if let Err(error) = jobs.install_session(grant, session) {
        let failed = system.close_handle(session).is_err()
            | cleanup_loaded(system, waits, loaded, task_group, true).is_err();
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(error)
        });
    }
    if let Err(error) = jobs.attach_session_owner(
        grant,
        SessionOwner {
            process: loaded.process,
            launch_channel: loaded.launch_channel,
            task_group,
        },
    ) {
        let disconnected = jobs.disconnect_session(grant);
        let failed = disconnected.map_or(true, |channel| system.close_handle(channel).is_err())
            | cleanup_loaded(system, waits, loaded, task_group, true).is_err();
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(error)
        });
    }
    Ok(InstalledPeer {
        grant,
        loaded,
        task_group,
    })
}

fn wait_session_readable<S: Wyr1BPlatform>(
    system: &mut S,
    session: DwHandle,
) -> Result<(), InitError> {
    let deadline = report_deadline(system)?;
    let result = system
        .wait_many(
            core::slice::from_ref(&DwWaitItemV1 {
                handle: session,
                signals: deepwyrm_syscall::DwSignals(
                    DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0,
                ),
            }),
            deadline,
        )
        .map_err(InitError::Native)?;
    if result.index != 0 || result.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(InitError::Supervision);
    }
    Ok(())
}

fn close_received_reverse<S: InitPlatform>(
    system: &mut S,
    handles: &[DwReceivedHandleInfoV1],
    count: usize,
) -> bool {
    let mut failed = false;
    for handle in handles[..count.min(handles.len())].iter().rev() {
        failed |= system.close_handle(handle.handle).is_err();
    }
    failed
}

fn launch_engine_error(error: LaunchEngineError<NativeError>) -> InitError {
    match error {
        LaunchEngineError::Job(error) => InitError::Wyr1BModel(error),
        LaunchEngineError::Validation {
            error,
            abort_failed,
            cleanup_failed,
        } => {
            if abort_failed || cleanup_failed {
                InitError::Cleanup
            } else {
                InitError::Wyr1BModel(error)
            }
        }
        LaunchEngineError::Loader {
            error,
            abort_failed,
            cleanup_failed,
            ..
        } => {
            if abort_failed || cleanup_failed {
                InitError::Cleanup
            } else {
                InitError::Loader(error)
            }
        }
        LaunchEngineError::Publication { error, .. } => InitError::Wyr1BModel(error),
    }
}

#[allow(clippy::too_many_arguments)]
fn publish_launch_accepted<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    reservation: LaunchReservation,
    loaded: crate::wyr1b::LoadedJob,
    release: LaunchChannelRelease,
    #[cfg(feature = "wyr1e8-selector33")] e8_acceptance: Option<(
        &mut ShellControllerState,
        E8TriggerRequest,
    )>,
) -> Result<(LaunchChannelRelease, SentLaunchAccepted), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut response = [0_u8; 88];
    let size = encode_job_message(
        reservation,
        LaunchMessageType::LaunchAccepted,
        loaded.job_id,
        &mut response,
    )
    .map_err(|_| InitError::Accounting)?;
    #[cfg(feature = "wyr1e8-selector33")]
    let e8_deadline = if e8_acceptance.is_some() {
        let deadline = system.now().map_err(InitError::Native).and_then(|now| {
            now.checked_add(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns)
                .ok_or(InitError::Accounting)
        });
        match deadline {
            Ok(deadline) if deadline != u64::MAX => Some(deadline),
            Ok(_) => {
                jobs.jobs.restore_launch_channel(release);
                let cleanup_failed =
                    force_cleanup_job_before(system, waits, jobs, loaded, None).is_err();
                return Err(if cleanup_failed {
                    InitError::Cleanup
                } else {
                    InitError::Accounting
                });
            }
            Err(error) => {
                jobs.jobs.restore_launch_channel(release);
                let cleanup_failed =
                    force_cleanup_job_before(system, waits, jobs, loaded, None).is_err();
                return Err(if cleanup_failed {
                    InitError::Cleanup
                } else {
                    error
                });
            }
        }
    } else {
        None
    };
    #[cfg(feature = "wyr1e8-selector33")]
    let mut e8_owner = None;
    #[cfg(feature = "wyr1e8-selector33")]
    if let (Some((state, trigger)), Some(deadline)) = (e8_acceptance, e8_deadline) {
        state.install_e8_trigger_before_accept(trigger, loaded.job_id, deadline)?;
        e8_owner = Some(state);
    }
    if let Err(error) = system.send_channel(session, &response[..size]) {
        #[cfg(feature = "wyr1e8-selector33")]
        if let Some(state) = e8_owner {
            state.close_recovery_episode();
        }
        jobs.jobs.restore_launch_channel(release);
        let cleanup_failed = force_cleanup_job_before(
            system,
            waits,
            jobs,
            loaded,
            #[cfg(feature = "wyr1e8-selector33")]
            e8_deadline,
            #[cfg(not(feature = "wyr1e8-selector33"))]
            None,
        )
        .is_err();
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            InitError::Native(error)
        });
    }
    Ok((
        release,
        SentLaunchAccepted {
            #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
            bytes: response,
            #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
            len: size,
            #[cfg(feature = "wyr1e8-selector33")]
            e8_deadline,
        },
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SentLaunchAccepted {
    #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
    bytes: [u8; 88],
    #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
    len: usize,
    #[cfg(feature = "wyr1e8-selector33")]
    e8_deadline: Option<u64>,
}

impl SentLaunchAccepted {
    #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    #[cfg(not(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33")))]
    fn as_bytes(&self) -> &[u8] {
        &[]
    }
}

fn force_cleanup_job<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    loaded: crate::wyr1b::LoadedJob,
) -> Result<TerminationResult, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    force_cleanup_job_before(system, waits, jobs, loaded, None)
}

fn force_cleanup_job_before<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    loaded: crate::wyr1b::LoadedJob,
    deadline_cap: Option<u64>,
) -> Result<TerminationResult, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    if let Some(resources) = jobs
        .jobs
        .forced_termination_resources(loaded.job_id)
        .map_err(InitError::Wyr1BModel)?
    {
        if system
            .terminate_task_group(DwHandle(resources.task_group))
            .is_err()
        {
            jobs.jobs
                .record_cleanup_bits(loaded.job_id, 1 << 0)
                .map_err(InitError::Wyr1BModel)?;
        } else {
            jobs.jobs
                .commit_forced_termination(loaded.job_id, resources)
                .map_err(InitError::Wyr1BModel)?;
        }
    }
    let result = reap_job_before(system, waits, jobs, loaded, deadline_cap)?;
    if result.cleanup_result != 0 {
        Err(InitError::Cleanup)
    } else {
        Ok(result)
    }
}

fn rollback_prepared_job<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    prepared: crate::wyr1b::PreparedJob,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    force_cleanup_job(
        system,
        waits,
        jobs,
        crate::wyr1b::LoadedJob {
            job_id: prepared.job_id(),
            loaded: prepared.loaded,
            task_group: prepared.task_group,
        },
    )
    .map(|_| ())
}

/// Runs a launch end to end in one frame.
///
/// Retained by reset card R6B for the callers that genuinely need the launch
/// complete when the call returns -- `receive_and_accept_job`, and through it
/// `run_job_gate`'s owner and orphan launches, which use the returned
/// `LoadedJob`'s handles on the next line. Those are one-shot bring-up paths
/// with no event loop to return to.
///
/// The resident dispatcher does not use this. It calls
/// `construct_reserved_launch` and lets the poll finish the launch later,
/// which is the whole point of the card: §3's invariant 6 requires that one
/// child failing to reach READY not block unrelated control traffic.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn accept_reserved_launch<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: &PolicyView<'_>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    reservation: LaunchReservation,
    request_ticket: RequestTicket,
    request: wyrmroot_launch_proto::LaunchRequest<'_>,
    received: &[DwReceivedHandleInfoV1],
    handle_count: usize,
    #[cfg(feature = "wyr1e8-selector33")] e8_acceptance: Option<(
        &mut ShellControllerState,
        E8TriggerRequest,
    )>,
) -> Result<(crate::wyr1b::LoadedJob, SentLaunchAccepted), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let constructed = construct_reserved_launch(
        system,
        loader,
        waits,
        authority,
        policy,
        jobs,
        session,
        reservation,
        request_ticket,
        request,
        received,
        handle_count,
    )?;
    finish_constructed_launch(
        system,
        waits,
        jobs,
        constructed,
        #[cfg(feature = "wyr1e8-selector33")]
        e8_acceptance,
    )
}

/// Validates, reserves, loads and arms the READY deadline, and stops there.
///
/// Everything up to and including `report_deadline` is work the request's own
/// frame has to do: it consumes the moved stream handles and the borrowed
/// request, neither of which outlives the dispatch. What it returns is the
/// small record the observation needs afterwards.
#[allow(clippy::too_many_arguments)]
fn construct_reserved_launch<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: &PolicyView<'_>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    reservation: LaunchReservation,
    request_ticket: RequestTicket,
    request: wyrmroot_launch_proto::LaunchRequest<'_>,
    received: &[DwReceivedHandleInfoV1],
    handle_count: usize,
) -> Result<ConstructedLaunch, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    for info in &received[..handle_count] {
        if let Err(error) = validate_controller_channel(system, info.handle) {
            let failed = close_received_reverse(system, received, handle_count);
            return Err(if failed { InitError::Cleanup } else { error });
        }
    }
    let ticket = match jobs.jobs.begin_reserved_launch(request_ticket) {
        Ok(ticket) => ticket,
        Err(error) => {
            let failed = close_received_reverse(system, received, handle_count);
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Wyr1BModel(error)
            });
        }
    };
    let streams = [received[0].handle, received[1].handle, received[2].handle];
    let streams = &streams[..handle_count];
    let task_group = match system.create_attempt_task_group(authority.task_group) {
        Ok(task_group) => task_group,
        Err(error) => {
            return Err(
                if close_received_reverse(system, received, handle_count)
                    | jobs.jobs.abort_launch(ticket).is_err()
                {
                    InitError::Cleanup
                } else {
                    InitError::Native(error)
                },
            );
        }
    };
    let prepared = match prepare_reserved_job(
        &mut jobs.jobs,
        policy,
        loader,
        authority,
        task_group.0,
        reservation,
        ticket,
        request,
        streams,
    ) {
        Ok(prepared) => prepared,
        Err(LaunchEngineError::Publication {
            error,
            ticket,
            loaded,
            task_group,
        }) => {
            let cleanup_failed =
                cleanup_loaded(system, waits, loaded, DwHandle(task_group), true).is_err();
            let abort_failed = jobs.jobs.abort_launch(ticket).is_err();
            return Err(if cleanup_failed || abort_failed {
                InitError::Cleanup
            } else {
                InitError::Wyr1BModel(error)
            });
        }
        Err(error) => {
            let mapped = launch_engine_error(error);
            return Err(if system.close_handle(task_group).is_err() {
                InitError::Cleanup
            } else {
                mapped
            });
        }
    };
    let deadline = match report_deadline(system) {
        Ok(deadline) => deadline,
        Err(error) => {
            return Err(
                if rollback_prepared_job(system, waits, jobs, prepared).is_err() {
                    InitError::Cleanup
                } else {
                    error
                },
            );
        }
    };
    Ok(ConstructedLaunch {
        prepared,
        deadline,
        session,
        reservation,
    })
}

/// A launch whose child exists and whose READY has not been observed yet.
///
/// Reset plan §7: this is the boundary between `Constructed` and
/// `AwaitingReady`. Everything in it is a fact the observation and the
/// publication still need, and every one of them used to be a local of
/// `accept_reserved_launch`'s frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConstructedLaunch {
    prepared: PreparedJob,
    deadline: DwDeadline,
    session: DwHandle,
    reservation: LaunchReservation,
}

/// Observes the exact READY and publishes, or rolls the launch back.
///
/// Split out of `accept_reserved_launch` by reset card R6B. It is the half
/// that may not run in the frame that read the request: `observe_prepared_ready`
/// blocks until the child answers or `deadline` expires, and §3's invariant 6
/// says that wait must not hold the resident dispatcher. R6B moves the call
/// site; the sequence inside is unchanged.
#[allow(clippy::too_many_arguments)]
fn finish_constructed_launch<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    constructed: ConstructedLaunch,
    #[cfg(feature = "wyr1e8-selector33")] e8_acceptance: Option<(
        &mut ShellControllerState,
        E8TriggerRequest,
    )>,
) -> Result<(crate::wyr1b::LoadedJob, SentLaunchAccepted), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let ConstructedLaunch {
        prepared,
        deadline,
        session,
        reservation,
    } = constructed;
    let observation = observe_prepared_ready(waits, &prepared, deadline);
    if observation.is_err() {
        return Err(
            if rollback_prepared_job(system, waits, jobs, prepared).is_err() {
                InitError::Cleanup
            } else {
                InitError::Supervision
            },
        );
    }
    let observation = observation.expect("checked exact READY observation");
    let loaded = match commit_prepared_job(&mut jobs.jobs, prepared, observation) {
        Ok(loaded) => loaded,
        Err(error) => {
            return Err(
                if rollback_prepared_job(system, waits, jobs, prepared).is_err() {
                    InitError::Cleanup
                } else {
                    InitError::Wyr1BModel(error)
                },
            );
        }
    };
    let release = jobs
        .jobs
        .release_launch_channel(loaded.job_id, loaded.loaded.launch_channel.0)
        .map_err(InitError::Wyr1BModel)?;
    let (release, sent_response) = publish_launch_accepted(
        system,
        waits,
        jobs,
        session,
        reservation,
        loaded,
        release,
        #[cfg(feature = "wyr1e8-selector33")]
        e8_acceptance,
    )?;
    if system.close_handle(loaded.loaded.launch_channel).is_err() {
        jobs.jobs.restore_launch_channel(release);
        jobs.jobs
            .record_cleanup_bits(loaded.job_id, 1 << 2)
            .map_err(InitError::Wyr1BModel)?;
        if system
            .terminate_task_group(DwHandle(loaded.task_group))
            .is_err()
        {
            jobs.jobs
                .record_cleanup_bits(loaded.job_id, 1 << 0)
                .map_err(InitError::Wyr1BModel)?;
        } else {
            let resources = jobs
                .jobs
                .forced_termination_resources(loaded.job_id)
                .map_err(InitError::Wyr1BModel)?
                .ok_or(InitError::Accounting)?;
            jobs.jobs
                .commit_forced_termination(loaded.job_id, resources)
                .map_err(InitError::Wyr1BModel)?;
        }
        let loaded = jobs
            .jobs
            .loaded_job(loaded.job_id)
            .map_err(InitError::Wyr1BModel)?;
        return Ok((loaded, sent_response));
    }
    // The accepted job's retained resources are now owned by the model, which
    // recorded the released launch Channel. Returning the pre-release snapshot
    // would hand callers a closed launch-Channel handle to close again.
    let loaded = jobs
        .jobs
        .loaded_job(loaded.job_id)
        .map_err(InitError::Wyr1BModel)?;
    Ok((loaded, sent_response))
}

#[allow(clippy::too_many_arguments)]
fn receive_and_accept_job<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: &PolicyView<'_>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
) -> Result<crate::wyr1b::LoadedJob, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    wait_session_readable(system, session)?;
    match dispatch_one_job_request(
        system,
        loader,
        waits,
        authority,
        Some(policy),
        jobs,
        session,
        grant,
        LaunchPublication::Immediate,
    )? {
        JobDispatchOutcome::Launched(loaded) => Ok(loaded),
        JobDispatchOutcome::Responded => Err(InitError::Wyr1BModel(JobError::WrongState)),
        // Unreachable by construction: this caller asked for
        // `LaunchPublication::Immediate` precisely because it uses the job's
        // handles on the next line and has no event loop to be handed a token
        // instead. Refused rather than unwrapped, so a future caller that
        // changes the mode without changing the use gets an error instead of a
        // panic.
        JobDispatchOutcome::Constructed => Err(InitError::Wyr1BModel(JobError::WrongState)),
    }
}

fn classify_termination(
    info: &DwTaskTerminationInfoV1,
) -> Result<TerminationClassification, InitError> {
    Ok(if info.reason == DW_TERMINATION_NORMAL_EXIT {
        TerminationClassification::NormalExit
    } else if info.reason == DW_TERMINATION_AUTHORIZED {
        TerminationClassification::Authorized
    } else if info.reason == DW_TERMINATION_UNHANDLED_EXCEPTION {
        TerminationClassification::UnhandledException
    } else if info.reason == DW_TERMINATION_RESOURCE_POLICY {
        TerminationClassification::ResourcePolicy
    } else if info.reason == DW_TERMINATION_TASK_GROUP_TEARDOWN {
        TerminationClassification::TaskGroupTeardown
    } else {
        return Err(InitError::Supervision);
    })
}

/// Bounded preterminal observation rounds allowed for one child Process exit.
///
/// A scripted controller may close a child's launch Channel and reap immediately,
/// so the child can still be pre-exit when the first observation runs. Each round
/// is one `WYR0_I_SUPERVISION_POLICY.ready_timeout_ns` wait followed by a fresh
/// level-triggered task-state query, which keeps the total bound explicit and
/// removes the dependence on a single wait observing the exact EXITED transition.
const JOB_EXIT_OBSERVATION_ROUNDS: u16 = WYR0_I_SUPERVISION_POLICY.max_attempts as u16;

/// Observes one child Process reaching its level-triggered EXITED state within
/// the bounded round budget above. `Err(())` means the caller must record
/// cleanup bit 1 and leave the job retained for a later cleanup attempt.
fn await_job_exit<S, W>(
    system: &mut S,
    waits: &mut W,
    process: DwHandle,
    deadline_cap: Option<u64>,
) -> Result<DwTaskTerminationInfoV1, ()>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut info = waits.query_task_termination(process).map_err(|_| ())?;
    let mut round = 0_u16;
    while info.state != DW_TASK_STATE_EXITED {
        if round == JOB_EXIT_OBSERVATION_ROUNDS {
            return Err(());
        }
        round += 1;
        let now = system.now().map_err(|_| ())?;
        if deadline_cap.is_some_and(|cap| now >= cap) {
            return Err(());
        }
        let deadline = now
            .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .map(|deadline| deadline_cap.map_or(deadline, |cap| deadline.min(cap)))
            .or(deadline_cap)
            .map(DwDeadline)
            .ok_or(())?;
        match waits.wait_many(
            core::slice::from_ref(&DwWaitItemV1 {
                handle: process,
                signals: DW_SIGNAL_EXITED,
            }),
            deadline,
        ) {
            Ok(_) => {}
            // A round that expires without the exit signal is not yet a cleanup
            // failure: the child may simply not have been scheduled. Any other
            // native wait failure stays fatal for this attempt.
            Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {}
            Err(_) => return Err(()),
        }
        info = waits.query_task_termination(process).map_err(|_| ())?;
        if deadline_cap.is_some() {
            let now = system.now().map_err(|_| ())?;
            if now >= deadline_cap.ok_or(())? {
                return Err(());
            }
        }
    }
    Ok(info)
}

fn reap_job<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    loaded: crate::wyr1b::LoadedJob,
) -> Result<TerminationResult, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    reap_job_before(system, waits, jobs, loaded, None)
}

fn reap_job_before<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    loaded: crate::wyr1b::LoadedJob,
    deadline_cap: Option<u64>,
) -> Result<TerminationResult, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let terminal = match jobs
        .jobs
        .terminal_result(loaded.job_id)
        .map_err(InitError::Wyr1BModel)?
    {
        Some(terminal) => terminal,
        None => {
            if loaded.loaded.process.0 == 0 {
                return Err(InitError::Accounting);
            }
            let info = match await_job_exit(system, waits, loaded.loaded.process, deadline_cap) {
                Ok(info) => info,
                Err(()) => {
                    jobs.jobs
                        .record_cleanup_bits(loaded.job_id, 1 << 1)
                        .map_err(InitError::Wyr1BModel)?;
                    return Err(InitError::Cleanup);
                }
            };
            ControllerJobResult {
                classification: classify_termination(&info)?.as_u32(),
                application_code: info.application_code,
                exception_class: info.exception_type.0,
                exception_detail: info.detail,
                exception_address: info.fault_address,
                cleanup_result: 0,
            }
        }
    };
    let mut closed_mask = 0_u32;
    let mut failed_bits = 0_u32;
    if loaded.loaded.launch_channel.0 != 0 {
        if system.close_handle(loaded.loaded.launch_channel).is_err() {
            failed_bits |= 1 << 2;
        } else {
            closed_mask |= 1 << 2;
        }
    }
    if loaded.loaded.process.0 != 0 {
        if system.close_handle(loaded.loaded.process).is_err() {
            failed_bits |= 1 << 3;
        } else {
            closed_mask |= 1 << 3;
        }
    }
    if loaded.task_group != 0 {
        if system.close_handle(DwHandle(loaded.task_group)).is_err() {
            failed_bits |= 1 << 4;
        } else {
            closed_mask |= 1 << 4;
        }
    }
    let completed = jobs
        .jobs
        .apply_cleanup_progress(loaded.job_id, terminal, closed_mask, failed_bits)
        .map_err(InitError::Wyr1BModel)?;
    let Some(completed) = completed else {
        return Err(InitError::Cleanup);
    };
    jobs.jobs.reclaim_closed_sessions();
    controller_result_to_wire(completed)
}

const fn job_error_code(error: JobError) -> LaunchErrorCode {
    match error {
        JobError::TransactionReplay => LaunchErrorCode::TransactionReplay,
        JobError::UnknownConnection
        | JobError::ClosedConnection
        | JobError::StaleGeneration
        | JobError::DuplicateConnection
        | JobError::ZeroIdentity => LaunchErrorCode::StaleOrUnknownSession,
        JobError::ForeignJob | JobError::UnknownJob => LaunchErrorCode::ForeignOrUnknownJob,
        JobError::Capacity | JobError::ArithmeticOverflow => LaunchErrorCode::Capacity,
        JobError::Policy(_)
        | JobError::PolicyMissing
        | JobError::PolicyExecutable
        | JobError::Bootfs(_)
        | JobError::BootGenerationMismatch
        | JobError::ArtifactNotExecutable
        | JobError::ArtifactIdentityMismatch
        | JobError::StreamPolicy => LaunchErrorCode::PolicyRejected,
        JobError::WrongState | JobError::ResourceIdentity => LaunchErrorCode::InvalidState,
    }
}

/// A native failure during a launch, as the launch protocol's own vocabulary.
///
/// F3A.6n. `ErrorCode::Capacity` exists and was unreachable from the case it
/// describes. It is produced only by `job_error_code` from
/// `JobError::Capacity`, which is the *shell's own job table* filling up; a
/// **kernel** resource exhaustion arrived as `InitError::Native(status)` and
/// was reported as `LoaderFailure`. So "the loader broke" and "the system is
/// full" were the same word on the wire, and a reader could not tell a
/// defective artifact from a full machine.
///
/// `NO_MEMORY` and `NO_RESOURCES` are the kernel's two exhaustion statuses
/// (`deepwyrm/abi/schema/status.toml`, values -12 and -13). They are capacity
/// by any reading. Everything else native -- including an output-contract
/// fault, which is our own ABI handling and not the machine's limits -- keeps
/// `LoaderFailure`.
///
/// This is a §3.1 collapse and it stays one: `ErrorCode` is a bare
/// `#[repr(u32)]` enum with no payload, so the exact status cannot ride the
/// reply. Its own doc comment says Deepwyrm statuses "remain available only in
/// a terminal `JOB_RESULT`" -- an escape hatch a *refused* launch never has,
/// because no job is created. Until an out-of-band channel carries it per
/// §4.2, distinguishing the two classes is the whole improvement available
/// here, and it is the one the reader needs first.
const fn native_launch_error_code(error: NativeError) -> LaunchErrorCode {
    match error {
        NativeError::Status(status)
            if status.0 == DW_STATUS_NO_MEMORY.0 || status.0 == DW_STATUS_NO_RESOURCES.0 =>
        {
            LaunchErrorCode::Capacity
        }
        NativeError::Status(_) | NativeError::Output(_) => LaunchErrorCode::LoaderFailure,
    }
}

const fn launch_error_code(error: &InitError) -> LaunchErrorCode {
    match error {
        InitError::Wyr1BModel(error) => job_error_code(*error),
        InitError::Native(error) => native_launch_error_code(*error),
        // A load that failed *inside a platform stage* carries the kernel's
        // own cause, and that is where a handle- or memory-table exhaustion
        // during a launch actually surfaces -- not as a bare
        // `InitError::Native`. Reading only the outer variant would have left
        // the exhaustion case still answering `loader-failure`, which is the
        // mistake this change exists to correct.
        InitError::Loader(wyrmroot_loader::process::LoadError::Platform { cause, .. }) => {
            native_launch_error_code(*cause)
        }
        // The rest of `LoadError` genuinely names the loader or the artifact:
        // a malformed ELF, a bad startup block, a refused launch message.
        // `tools/e7_vm.py` pins `loader-failure` for a malformed ELF, and this
        // is the arm that keeps that answer.
        //
        // `Supervision` keeps the code rather than moving to a more accurate
        // one: nothing has been observed reaching it on this path, and moving
        // a code nothing has seen fire is churn with a conformance risk
        // attached.
        InitError::Loader(_) | InitError::Supervision => LaunchErrorCode::LoaderFailure,
        InitError::Cleanup | InitError::Accounting => LaunchErrorCode::CleanupFailure,
        _ => LaunchErrorCode::PolicyRejected,
    }
}

/// The shell launch path's mapping.
///
/// F3A.6n. The default arm used to be `LoaderFailure`, which is why the F
/// campaign's refused `spawn bin/cpu-hog` said `loader-failure` and meant
/// nothing: every `InitError` that was not `Wyr1BModel`, `Cleanup` or
/// `Accounting` claimed the loader had failed, including errors with no
/// relation to it. `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` §3.4 forbids a
/// wildcard over an error type at a status boundary and the compiler enforces
/// it -- but this is a *protocol reply* boundary, which that rule does not
/// reach, so the shape survived here.
///
/// Defaulting to a *specific* claim is the defect, not the defaulting. The
/// arms that can name their fault now do, by sharing `launch_error_code`'s
/// vocabulary, and what remains unclassified defaults to `PolicyRejected` --
/// "this request was refused" -- which claims nothing about where the fault
/// was. That is the honest answer for an error this function cannot attribute.
const fn shell_launch_error_code(error: &InitError) -> LaunchErrorCode {
    launch_error_code(error)
}

fn send_job_error<S: InitPlatform>(
    system: &mut S,
    session: DwHandle,
    reservation: LaunchReservation,
    code: LaunchErrorCode,
) -> Result<(), InitError> {
    let mut response = [0_u8; 88];
    let size =
        encode_launch_error(reservation, code, &mut response).map_err(|_| InitError::Accounting)?;
    system
        .send_channel(session, &response[..size])
        .map_err(InitError::Native)
}

/// Constructs the child, parks the transaction, and returns to the event loop.
///
/// Reset card R6B-2, and the whole of what it changes. The one-frame path is
/// `accept_reserved_launch`, which runs `construct_reserved_launch` and
/// `finish_constructed_launch` back to back; this runs only the first and
/// leaves the second to `finish_deferred_launch` on a later tick. Everything
/// the second half will need is written into the arena before this returns,
/// because the request buffer, the moved handles and the bootfs mapping all die
/// with this frame.
///
/// Failures before the child exists are answered here, exactly as they were:
/// the request bytes are still in hand, so the error reply and its evidence
/// record are unchanged. The one new failure is parking itself, and it is the
/// dangerous one -- a constructed child whose transaction never reached the
/// arena is a child nothing owns. It is rolled back before the reply, by the
/// same `rollback_prepared_job` the synchronous path uses.
#[allow(clippy::too_many_arguments)]
fn defer_reserved_launch<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: &PolicyView<'_>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
    scope: LaunchSessionScope,
    reservation: LaunchReservation,
    request_ticket: RequestTicket,
    request: wyrmroot_launch_proto::LaunchRequest<'_>,
    moved: &[DwReceivedHandleInfoV1],
    observed: &[DwReceivedHandleInfoV1],
    handle_count: usize,
    request_bytes: &[u8],
    mut state: Option<&mut ShellControllerState>,
    #[cfg(feature = "wyr1e8-selector33")] e8_trigger: Option<E8TriggerRequest>,
) -> Result<JobDispatchOutcome, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    // Taken before anything is constructed. If the request cannot yield the
    // facts the join will want, that is a property of the bytes, and finding it
    // out after a child exists would mean tearing one down to report it.
    #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
    let facts = match crate::launch_request_facts::LaunchRequestFacts::of(request_bytes, observed) {
        Ok(facts) => facts,
        Err(error) => {
            if close_received_reverse(system, moved, handle_count) {
                return Err(InitError::Cleanup);
            }
            send_observed_job_error(
                system,
                session,
                reservation,
                launch_error_code(&error),
                scope,
                state.as_deref_mut(),
                request_bytes,
                observed,
            )?;
            return Ok(JobDispatchOutcome::Responded);
        }
    };
    let constructed = match construct_reserved_launch(
        system,
        loader,
        waits,
        authority,
        policy,
        jobs,
        session,
        reservation,
        request_ticket,
        request,
        moved,
        handle_count,
    ) {
        Ok(constructed) => constructed,
        Err(error) => {
            send_observed_job_error(
                system,
                session,
                reservation,
                launch_error_code(&error),
                scope,
                state.as_deref_mut(),
                request_bytes,
                observed,
            )?;
            return if error == InitError::Cleanup {
                Err(error)
            } else {
                Ok(JobDispatchOutcome::Responded)
            };
        }
    };
    if let Err(error) = park_constructed_launch(
        jobs,
        grant,
        scope,
        constructed,
        #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
        facts,
        #[cfg(feature = "wyr1e8-selector33")]
        e8_trigger.map(|trigger| trigger.action),
    ) {
        let cleanup_failed =
            rollback_prepared_job(system, waits, jobs, constructed.prepared).is_err();
        send_observed_job_error(
            system,
            session,
            reservation,
            launch_error_code(&error),
            scope,
            state,
            request_bytes,
            observed,
        )?;
        return Err(if cleanup_failed {
            InitError::Cleanup
        } else {
            error
        });
    }
    Ok(JobDispatchOutcome::Constructed)
}

/// Writes one constructed launch into the arena and leaves it `AwaitingReady`.
///
/// Every stage edge is taken explicitly rather than assigned, so the arena's
/// own graph gets to refuse a sequence the dispatcher should not be producing.
fn park_constructed_launch(
    jobs: &mut JobDispatcher,
    grant: EndpointGrant,
    scope: LaunchSessionScope,
    constructed: ConstructedLaunch,
    #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
    facts: crate::launch_request_facts::LaunchRequestFacts,
    #[cfg(feature = "wyr1e8-selector33")] trigger_action: Option<E8RecoveryAction>,
) -> Result<(), InitError> {
    let token = jobs
        .launches
        .open(grant, constructed.session, scope, constructed.reservation)
        .map_err(launch_transaction_error)?;
    let record = || -> Result<(), LaunchTransactionError> {
        jobs.launches
            .attach_job(token, constructed.prepared.job_id())?;
        jobs.launches.advance(token, LaunchStage::Constructed)?;
        jobs.launches.attach_resources(
            token,
            constructed.prepared.profile(),
            LaunchResources {
                process: constructed.prepared.loaded.process,
                launch_channel: constructed.prepared.loaded.launch_channel,
                task_group: DwHandle(constructed.prepared.task_group),
            },
        )?;
        jobs.launches
            .arm_ready_deadline(token, constructed.deadline)?;
        #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
        jobs.launches.attach_request_facts(token, facts)?;
        #[cfg(feature = "wyr1e8-selector33")]
        if let Some(action) = trigger_action {
            jobs.launches.attach_trigger_action(token, action)?;
        }
        jobs.launches.advance(token, LaunchStage::AwaitingReady)
    }();
    if let Err(error) = record {
        // The slot exists but does not describe the child. Empty it so it
        // cannot be mistaken for one that owns handles, and let the caller
        // roll the child back.
        let _ = jobs.launches.take_resources(token);
        let _ = jobs.launches.advance(token, LaunchStage::Failing);
        let _ = jobs.launches.advance(token, LaunchStage::Cleanup);
        let _ = jobs.launches.advance(token, LaunchStage::Complete);
        let _ = jobs.launches.close(token);
        return Err(launch_transaction_error(error));
    }
    Ok(())
}

/// The arena's refusals are accounting errors: every one of them means the
/// dispatcher asked for a transition its own sequence should have made
/// impossible.
fn launch_transaction_error(error: LaunchTransactionError) -> InitError {
    match error {
        LaunchTransactionError::Capacity => InitError::Wyr1BModel(JobError::Capacity),
        LaunchTransactionError::SessionBusy => InitError::Wyr1BModel(JobError::WrongState),
        _ => InitError::Accounting,
    }
}

#[allow(clippy::too_many_arguments)]
fn observe_e7_response<S: Wyr1BPlatform>(
    system: &mut S,
    scope: LaunchSessionScope,
    state: Option<&mut ShellControllerState>,
    request: &[u8],
    response: &[u8],
    handles: &[DwReceivedHandleInfoV1],
    #[cfg(feature = "wyr1e8-selector33")] accepted_deadline: Option<u64>,
) -> Result<(), InitError> {
    #[cfg(feature = "wyr1e-selector33")]
    {
        let Some(state) = state else {
            #[cfg(test)]
            return Ok(());
            #[cfg(not(test))]
            return Err(InitError::WrongActivationOrder);
        };
        match scope {
            LaunchSessionScope::ShellJobs => {
                state.record_e7_shell_jobs(system, request, response, handles)
            }
            LaunchSessionScope::ConsoleLauncher => {
                if !handles.is_empty() {
                    return Err(InitError::Accounting);
                }
                state.record_e7_outer_response(system, request, response)
            }
            LaunchSessionScope::Historical => Ok(()),
        }
    }
    #[cfg(feature = "wyr1e8-selector33")]
    {
        let Some(state) = state else {
            #[cfg(test)]
            return Ok(());
            #[cfg(not(test))]
            return Err(InitError::WrongActivationOrder);
        };
        match scope {
            LaunchSessionScope::ShellJobs => {
                state.record_e8_shell_jobs(system, request, response, handles, accepted_deadline)
            }
            LaunchSessionScope::ConsoleLauncher => {
                if !handles.is_empty() {
                    return Err(InitError::Accounting);
                }
                state.record_e8_outer_response(system, request, response)
            }
            LaunchSessionScope::Historical => Ok(()),
        }
    }
    #[cfg(not(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33")))]
    {
        let _ = (system, scope, state, request, response, handles);
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn send_observed_job_error<S: Wyr1BPlatform>(
    system: &mut S,
    session: DwHandle,
    reservation: LaunchReservation,
    code: LaunchErrorCode,
    scope: LaunchSessionScope,
    state: Option<&mut ShellControllerState>,
    request: &[u8],
    handles: &[DwReceivedHandleInfoV1],
) -> Result<(), InitError> {
    let mut response = [0_u8; 88];
    let size =
        encode_launch_error(reservation, code, &mut response).map_err(|_| InitError::Accounting)?;
    system
        .send_channel(session, &response[..size])
        .map_err(InitError::Native)?;
    observe_e7_response(
        system,
        scope,
        state,
        request,
        &response[..size],
        handles,
        #[cfg(feature = "wyr1e8-selector33")]
        None,
    )
}

fn send_shell_v1_error<S: InitPlatform>(
    system: &mut S,
    session: DwHandle,
    reservation: LaunchReservation,
    code: LaunchErrorCode,
) -> Result<(), InitError> {
    let mut response = [0_u8; wyrmroot_launch_proto::SHELL_V1_REPLY_BYTES];
    let size = encode_shell_v1_error_reply(reservation, code, &mut response)
        .map_err(|_| InitError::Accounting)?;
    system
        .send_channel(session, &response[..size])
        .map_err(InitError::Native)
}

fn controller_result_to_wire(result: ControllerJobResult) -> Result<TerminationResult, InitError> {
    let classification = match result.classification {
        1 => TerminationClassification::NormalExit,
        2 => TerminationClassification::Authorized,
        3 => TerminationClassification::UnhandledException,
        4 => TerminationClassification::ResourcePolicy,
        5 => TerminationClassification::TaskGroupTeardown,
        _ => return Err(InitError::Accounting),
    };
    Ok(TerminationResult {
        classification,
        application_code: result.application_code,
        exception_class: result.exception_class,
        exception_detail: result.exception_detail,
        exception_address: result.exception_address,
        cleanup_result: result.cleanup_result,
    })
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn dispatch_reserved_operation<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
    reservation: LaunchReservation,
    ticket: RequestTicket,
    message: LaunchMessage<'_>,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut request = [0u8; 56];
    let request_size = match &message {
        LaunchMessage::Wait { job_id } => {
            encode_job_message(reservation, LaunchMessageType::Wait, *job_id, &mut request)
                .map_err(|_| InitError::Accounting)?
        }
        _ => 0,
    };
    dispatch_reserved_operation_observed(
        system,
        waits,
        jobs,
        session,
        grant,
        reservation,
        ticket,
        message,
        &request[..request_size],
        LaunchSessionScope::Historical,
        None,
    )
}

#[allow(clippy::too_many_arguments, clippy::needless_option_as_deref)]
fn dispatch_reserved_operation_observed<S, W>(
    system: &mut S,
    _waits: &mut W,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
    reservation: LaunchReservation,
    ticket: RequestTicket,
    message: LaunchMessage<'_>,
    request_bytes: &[u8],
    scope: LaunchSessionScope,
    mut evidence: Option<&mut ShellControllerState>,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut response = [0_u8; 320];
    let result: Result<Option<usize>, JobError> = match message {
        LaunchMessage::Query { job_id } => {
            jobs.jobs
                .query_reserved(ticket, job_id)
                .and_then(|snapshot| {
                    let phase = match snapshot.phase {
                        crate::wyr1b::JobPhase::Running => wyrmroot_launch_proto::JobPhase::Running,
                        crate::wyr1b::JobPhase::Terminating => {
                            wyrmroot_launch_proto::JobPhase::Terminating
                        }
                        crate::wyr1b::JobPhase::Reserved => return Err(JobError::WrongState),
                    };
                    encode_job_state(reservation, job_id, phase, &mut response)
                        .map(Some)
                        .map_err(|_| JobError::WrongState)
                })
        }
        LaunchMessage::Wait { job_id } => (|| -> Result<Option<usize>, JobError> {
            match jobs.jobs.result_reserved(ticket, job_id) {
                Ok(controller) => {
                    #[cfg(feature = "wyr1e8-selector33")]
                    if scope == LaunchSessionScope::ShellJobs
                        && evidence.as_deref().is_some_and(|state| {
                            state
                                .e8_trigger
                                .is_some_and(|trigger| trigger.job_id == job_id)
                        })
                    {
                        // Completion before WAIT admission must use the same
                        // retained barrier as completion after admission.
                        jobs.install_pending_wait(grant, reservation, job_id, request_bytes)?;
                        return Ok(None);
                    }
                    let terminal =
                        controller_result_to_wire(controller).map_err(|_| JobError::WrongState)?;
                    observe_session_shutdown_result(scope, evidence.as_deref_mut(), terminal);
                    encode_job_result(reservation, job_id, terminal, &mut response)
                        .map(Some)
                        .map_err(|_| JobError::WrongState)
                }
                Err(JobError::UnknownJob) => {
                    jobs.jobs.query_reserved(ticket, job_id)?;
                    jobs.install_pending_wait(grant, reservation, job_id, request_bytes)?;
                    Ok(None)
                }
                Err(error) => Err(error),
            }
        })(),
        LaunchMessage::Terminate { job_id } => {
            let resources = match jobs.jobs.authorize_terminate_reserved(ticket, job_id) {
                Ok(resources) => resources,
                Err(error) => {
                    return send_observed_job_error(
                        system,
                        session,
                        reservation,
                        job_error_code(error),
                        scope,
                        evidence.as_deref_mut(),
                        request_bytes,
                        &[],
                    );
                }
            };
            if system
                .terminate_task_group(DwHandle(resources.task_group))
                .is_err()
            {
                jobs.jobs
                    .record_cleanup_bits(job_id, 1 << 0)
                    .map_err(InitError::Wyr1BModel)?;
                return send_observed_job_error(
                    system,
                    session,
                    reservation,
                    LaunchErrorCode::CleanupFailure,
                    scope,
                    evidence.as_deref_mut(),
                    request_bytes,
                    &[],
                );
            }
            jobs.jobs
                .commit_terminate(job_id, resources)
                .and_then(|()| {
                    encode_job_message(
                        reservation,
                        LaunchMessageType::TerminationAccepted,
                        job_id,
                        &mut response,
                    )
                    .map(Some)
                    .map_err(|_| JobError::WrongState)
                })
        }
        LaunchMessage::ListJobs => {
            let mut ids = [0_u64; wyrmroot_launch_proto::MAX_LIVE_JOBS];
            jobs.jobs.list_reserved(ticket, &mut ids).and_then(|count| {
                encode_job_list(reservation, &ids[..count], &mut response)
                    .map(Some)
                    .map_err(|_| JobError::WrongState)
            })
        }
        LaunchMessage::CloseJob { job_id } => {
            jobs.jobs.close_job_reserved(ticket, job_id).and_then(|()| {
                jobs.drop_job_waits(grant, job_id);
                encode_job_message(
                    reservation,
                    LaunchMessageType::Closed,
                    job_id,
                    &mut response,
                )
                .map(Some)
                .map_err(|_| JobError::WrongState)
            })
        }
        LaunchMessage::Cancel {
            target_transaction_id,
        } => {
            if jobs
                .cancel_pending_wait(grant, target_transaction_id)
                .is_none()
            {
                return send_observed_job_error(
                    system,
                    session,
                    reservation,
                    LaunchErrorCode::CancellationUnavailable,
                    scope,
                    evidence.as_deref_mut(),
                    request_bytes,
                    &[],
                );
            }
            encode_job_message(
                reservation,
                LaunchMessageType::Cancelled,
                target_transaction_id,
                &mut response,
            )
            .map(Some)
            .map_err(|_| JobError::WrongState)
        }
        _ => Err(JobError::WrongState),
    };
    match result {
        Ok(Some(size)) => {
            system
                .send_channel(session, &response[..size])
                .map_err(InitError::Native)?;
            observe_e7_response(
                system,
                scope,
                evidence.as_deref_mut(),
                request_bytes,
                &response[..size],
                &[],
                #[cfg(feature = "wyr1e8-selector33")]
                None,
            )
        }
        Ok(None) => Ok(()),
        Err(error) => send_observed_job_error(
            system,
            session,
            reservation,
            job_error_code(error),
            scope,
            evidence,
            request_bytes,
            &[],
        ),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JobDispatchOutcome {
    Responded,
    Launched(crate::wyr1b::LoadedJob),
    /// The child exists and its READY deadline is armed, but nothing has been
    /// published yet. Reset card R6B-2: the transaction is in the arena and the
    /// dispatcher has gone back to the event loop.
    Constructed,
}

/// Whether a launch's reply is written in the frame that read the request.
///
/// Reset card R6B-2. §3's invariant 6 says one child failing to reach READY
/// must not block the supervisor from servicing unrelated traffic, and a stack
/// frame was the reason it did: `observe_prepared_ready` blocks in the middle
/// of the dispatch. `Deferred` parks the constructed launch in the arena and
/// returns, so the wait happens on a later tick with the request buffer and the
/// bootfs mapping already released.
///
/// `Immediate` is not a transitional shim. `receive_and_accept_job` and the
/// launch gates use the returned job's handles on the next line and have no
/// event loop to return to; for them the frame *is* the lifetime. Only the
/// resident dispatcher defers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LaunchPublication {
    Immediate,
    Deferred,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JobWireVersion {
    Legacy,
    ShellV1,
}

fn close_shell_session_for_job<S: InitPlatform>(
    system: &mut S,
    jobs: &mut JobDispatcher,
    job_id: u64,
) -> Result<(), InitError> {
    let Some(grant) = jobs.shell_session_for_outer_job(job_id) else {
        return Ok(());
    };
    let disconnected = jobs
        .disconnect_owned_session(grant)
        .map_err(InitError::Wyr1BModel)?;
    if disconnected.owner.is_some()
        || disconnected.outer_job != Some(job_id)
        || system.close_handle(disconnected.channel).is_err()
    {
        return Err(InitError::Cleanup);
    }
    Ok(())
}

fn cleanup_shell_before_publication<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    loaded: crate::wyr1b::LoadedJob,
) -> Result<TerminationResult, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    cleanup_shell_before_publication_before(system, waits, jobs, loaded, None)
}

fn cleanup_shell_before_publication_before<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    loaded: crate::wyr1b::LoadedJob,
    deadline_cap: Option<u64>,
) -> Result<TerminationResult, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let cleanup = force_cleanup_job_before(system, waits, jobs, loaded, deadline_cap);
    let session_cleanup = close_shell_session_for_job(system, jobs, loaded.job_id);
    match (cleanup, session_cleanup) {
        (Ok(result), Ok(())) => Ok(result),
        _ => Err(InitError::Cleanup),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AcceptedShell {
    loaded: crate::wyr1b::LoadedJob,
    request: wyrmroot_launch_proto::ShellV1Request,
    registry_grant: EndpointGrant,
    shell_grant: EndpointGrant,
}

#[allow(clippy::too_many_arguments)]
fn accept_reserved_shell<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: &PolicyView<'_>,
    jobs: &mut JobDispatcher,
    reservation: LaunchReservation,
    request_ticket: RequestTicket,
    request: wyrmroot_launch_proto::ShellV1Request,
    received: &[DwReceivedHandleInfoV1],
    context: &mut ShellLaunchContext<'_>,
) -> Result<AcceptedShell, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    #[cfg(feature = "wyr1e8-selector33")]
    context.state.require_recovery_live(system)?;
    if jobs.has_shell_session() {
        let failed = close_received_reverse(system, received, received.len());
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(JobError::Capacity)
        });
    }
    let image = match policy.authorize_wyrmsh() {
        Ok(image) => image,
        Err(error) => {
            let failed = close_received_reverse(system, received, received.len());
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Wyr1BModel(error)
            });
        }
    };
    let ticket = match jobs.jobs.begin_reserved_launch(request_ticket) {
        Ok(ticket) => ticket,
        Err(error) => {
            let failed = close_received_reverse(system, received, received.len());
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Wyr1BModel(error)
            });
        }
    };
    if let Err(error) = context.state.reserve_shell_generation(request) {
        let failed = close_received_reverse(system, received, received.len())
            | jobs.jobs.abort_launch(ticket).is_err();
        return Err(if failed { InitError::Cleanup } else { error });
    }
    let group = match system.create_attempt_task_group(authority.task_group) {
        Ok(group) => group,
        Err(error) => {
            let failed = close_received_reverse(system, received, received.len())
                | jobs.jobs.abort_launch(ticket).is_err();
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Native(error)
            });
        }
    };
    let install_transaction = match context
        .state
        .reserve_install_transaction(context.topology.generation())
    {
        Ok(transaction) => transaction,
        Err(error) => {
            let failed = close_received_reverse(system, received, received.len())
                | system.close_handle(group).is_err()
                | jobs.jobs.abort_launch(ticket).is_err();
            return Err(if failed { InitError::Cleanup } else { error });
        }
    };
    let registry_grant = match context.topology.issue(
        request.requested_child_generation,
        EndpointKind::RegistryClient,
    ) {
        Ok(grant) => grant,
        Err(error) => {
            let failed = close_received_reverse(system, received, received.len())
                | system.close_handle(group).is_err()
                | jobs.jobs.abort_launch(ticket).is_err();
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Wyr1BModel(error)
            });
        }
    };
    let (registry_server, registry_client) = match create_controller_channel_pair(system) {
        Ok(pair) => pair,
        Err(error) => {
            let failed = close_received_reverse(system, received, received.len())
                | system.close_handle(group).is_err()
                | jobs.jobs.abort_launch(ticket).is_err();
            return Err(if failed { InitError::Cleanup } else { error });
        }
    };
    if let Err(error) = install_wyrmsh_registry_client(
        system,
        context.registry_control,
        registry_grant,
        registry_server,
        install_transaction,
    ) {
        let failed = close_received_reverse(system, received, received.len())
            | system.close_handle(registry_server).is_err()
            | system.close_handle(registry_client).is_err()
            | system.close_handle(group).is_err()
            | jobs.jobs.abort_launch(ticket).is_err();
        return Err(if failed { InitError::Cleanup } else { error });
    }
    let fail_after_install = |system: &mut S,
                              jobs: &mut JobDispatcher,
                              context: &mut ShellLaunchContext<'_>,
                              original: InitError,
                              close_client: bool|
     -> InitError {
        context.state.poison(registry_grant.registry_generation);
        let failed = close_received_reverse(system, received, received.len())
            | (close_client && system.close_handle(registry_client).is_err())
            | system.close_handle(group).is_err()
            | jobs.jobs.abort_launch(ticket).is_err();
        if failed { InitError::Cleanup } else { original }
    };
    if let Err(error) = preflight_wyrmsh_registry(
        system,
        registry_client,
        registry_grant,
        #[cfg(feature = "wyr1e8-selector33")]
        context.state.recovery_deadline(),
        #[cfg(not(feature = "wyr1e8-selector33"))]
        None,
    ) {
        return Err(fail_after_install(system, jobs, context, error, true));
    }
    let shell_grant = match context.topology.issue(
        request.requested_child_generation,
        EndpointKind::LaunchSession,
    ) {
        Ok(grant) => grant,
        Err(error) => {
            return Err(fail_after_install(
                system,
                jobs,
                context,
                InitError::Wyr1BModel(error),
                true,
            ));
        }
    };
    let (shell_controller, shell_child) = match create_controller_channel_pair(system) {
        Ok(pair) => pair,
        Err(error) => {
            return Err(fail_after_install(system, jobs, context, error, true));
        }
    };
    if let Err(error) = jobs.install_scoped_session(
        shell_grant,
        shell_controller,
        crate::wyr1b_job::LaunchSessionScope::ShellJobs,
    ) {
        let failed = system.close_handle(shell_controller).is_err()
            | system.close_handle(shell_child).is_err();
        return Err(fail_after_install(
            system,
            jobs,
            context,
            if failed {
                InitError::Cleanup
            } else {
                InitError::Wyr1BModel(error)
            },
            true,
        ));
    }
    let loaded = match load_wyrmsh_process(
        loader,
        LoadAuthority {
            task_group: group,
            ..authority
        },
        WyrmshLoadRequest {
            image,
            stdin: received[0].handle,
            stdout: received[1].handle,
            stderr: received[2].handle,
            console_status: received[3].handle,
            registry_client,
            launch_session: shell_child,
            registry_generation: registry_grant.registry_generation,
            registry_endpoint_id: registry_grant.endpoint_id,
            registry_endpoint_generation: registry_grant.endpoint_generation,
            launch_connection_id: shell_grant.endpoint_id,
            launch_connection_generation: shell_grant.endpoint_generation,
            console_generation: request.console_generation,
            status_generation: request.status_generation,
            child_generation: request.requested_child_generation,
            outer_launch_transaction: reservation.transaction_id,
            transaction_id: install_transaction,
        },
    ) {
        Ok(loaded) => loaded,
        Err(failure) => {
            let disconnected = jobs.disconnect_session(shell_grant);
            let mut failed =
                disconnected.map_or(true, |channel| system.close_handle(channel).is_err());
            if !failure.stdin_consumed {
                failed |= close_received_reverse(system, received, received.len());
                failed |= system.close_handle(registry_client).is_err();
                failed |= system.close_handle(shell_child).is_err();
            }
            failed |= system.close_handle(group).is_err();
            failed |= jobs.jobs.abort_launch(ticket).is_err();
            context.state.poison(registry_grant.registry_generation);
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Loader(failure.error)
            });
        }
    };
    if let Err(error) =
        jobs.jobs
            .stage_launch(ticket, loaded.process.0, group.0, loaded.launch_channel.0)
    {
        let failed = cleanup_loaded(system, waits, loaded, group, true).is_err()
            | jobs
                .disconnect_session(shell_grant)
                .map_or(true, |channel| system.close_handle(channel).is_err())
            | jobs.jobs.abort_launch(ticket).is_err();
        context.state.poison(registry_grant.registry_generation);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(error)
        });
    }
    let loaded_job = crate::wyr1b::LoadedJob {
        job_id: ticket.job_id(),
        loaded,
        task_group: group.0,
    };
    if let Err(error) = jobs.attach_outer_job(shell_grant, loaded_job.job_id) {
        let failed = force_cleanup_job(system, waits, jobs, loaded_job).is_err()
            | jobs
                .disconnect_session(shell_grant)
                .map_or(true, |channel| system.close_handle(channel).is_err());
        context.state.poison(registry_grant.registry_generation);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(error)
        });
    }
    let ready_deadline = match report_deadline(system) {
        Ok(deadline) => {
            #[cfg(feature = "wyr1e8-selector33")]
            let deadline = DwDeadline(context.state.cap_recovery_deadline(deadline.0));
            deadline
        }
        Err(error) => {
            let failed = cleanup_shell_before_publication(system, waits, jobs, loaded_job).is_err();
            context.state.poison(registry_grant.registry_generation);
            return Err(if failed { InitError::Cleanup } else { error });
        }
    };
    let exact_ready = await_child_ready_profile_observed(
        waits,
        loaded.process,
        loaded.launch_channel,
        LaunchProfile::Wyrmsh,
        install_transaction,
        ready_deadline,
    )
    .is_ok();
    let running = waits
        .query_task_termination(loaded.process)
        .is_ok_and(|info| info.state == deepwyrm_syscall::DW_TASK_STATE_RUNNING);
    if !exact_ready || !running {
        let failed = cleanup_shell_before_publication(system, waits, jobs, loaded_job).is_err();
        context.state.poison(registry_grant.registry_generation);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Supervision
        });
    }
    #[cfg(feature = "wyr1e8-selector33")]
    if let Err(error) = context.state.require_recovery_live(system) {
        let failed = cleanup_shell_before_publication(system, waits, jobs, loaded_job).is_err();
        context.state.poison(registry_grant.registry_generation);
        return Err(if failed { InitError::Cleanup } else { error });
    }
    if let Err(error) =
        jobs.jobs
            .commit_launch(ticket, loaded.process.0, group.0, loaded.launch_channel.0)
    {
        let failed = cleanup_shell_before_publication(system, waits, jobs, loaded_job).is_err();
        context.state.poison(registry_grant.registry_generation);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(error)
        });
    }
    Ok(AcceptedShell {
        loaded: loaded_job,
        request,
        registry_grant,
        shell_grant,
    })
}

fn send_versioned_job_error<S: InitPlatform>(
    system: &mut S,
    session: DwHandle,
    reservation: LaunchReservation,
    version: JobWireVersion,
    code: LaunchErrorCode,
) -> Result<(), InitError> {
    match version {
        JobWireVersion::Legacy => send_job_error(system, session, reservation, code),
        JobWireVersion::ShellV1 => send_shell_v1_error(system, session, reservation, code),
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_one_job_request<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: Option<&PolicyView<'_>>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
    publication: LaunchPublication,
) -> Result<JobDispatchOutcome, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    dispatch_one_job_request_inner(
        system,
        loader,
        waits,
        authority,
        policy,
        jobs,
        session,
        grant,
        None,
        publication,
    )
}

#[allow(clippy::too_many_arguments)]
#[allow(
    dead_code,
    reason = "E6 wires this E3C adapter into the selected resident product"
)]
fn dispatch_one_job_request_with_shell<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: Option<&PolicyView<'_>>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
    shell: &mut ShellLaunchContext<'_>,
    publication: LaunchPublication,
) -> Result<JobDispatchOutcome, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    dispatch_one_job_request_inner(
        system,
        loader,
        waits,
        authority,
        policy,
        jobs,
        session,
        grant,
        Some(shell),
        publication,
    )
}

#[allow(clippy::too_many_arguments)]
fn dispatch_one_job_request_inner<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: Option<&PolicyView<'_>>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
    mut shell: Option<&mut ShellLaunchContext<'_>>,
    publication: LaunchPublication,
) -> Result<JobDispatchOutcome, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let scope = jobs.session_scope(grant).map_err(InitError::Wyr1BModel)?;
    let legacy_handle_limit = wyrmroot_launch_proto::STREAM_COUNT;
    let mut bytes = [0_u8; wyrmroot_launch_proto::MAX_LAUNCH_MESSAGE_BYTES];
    let mut received =
        [DwReceivedHandleInfoV1::default(); wyrmroot_launch_proto::SHELL_V1_HANDLE_COUNT];
    let counts = system
        .receive_channel(session, &mut bytes, &mut received)
        .map_err(InitError::Native)?;
    if counts.bytes > bytes.len() || counts.handles > received.len() {
        let failed = close_received_reverse(system, &received, counts.handles);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(JobError::StreamPolicy)
        });
    }
    let (version, reservation) = match parse_reservation_prefix(&bytes[..counts.bytes]) {
        Ok(reservation) => (JobWireVersion::Legacy, reservation),
        Err(_) => match parse_shell_v1_reservation_prefix(&bytes[..counts.bytes]) {
            Ok(reservation) => (JobWireVersion::ShellV1, reservation),
            Err(_) => {
                let failed = close_received_reverse(system, &received, counts.handles);
                return Err(if failed {
                    InitError::Cleanup
                } else if counts.handles > legacy_handle_limit {
                    InitError::Wyr1BModel(JobError::StreamPolicy)
                } else {
                    InitError::Wyr1BModel(JobError::WrongState)
                });
            }
        },
    };
    if version == JobWireVersion::Legacy && counts.handles > legacy_handle_limit {
        let failed = close_received_reverse(system, &received, counts.handles);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(JobError::StreamPolicy)
        });
    }
    if reservation.connection_id != grant.endpoint_id
        || reservation.generation != grant.endpoint_generation
    {
        let failed = close_received_reverse(system, &received, counts.handles);
        if failed {
            return Err(InitError::Cleanup);
        }
        send_versioned_job_error(
            system,
            session,
            reservation,
            version,
            LaunchErrorCode::StaleOrUnknownSession,
        )?;
        return Ok(JobDispatchOutcome::Responded);
    }
    let request_ticket = match jobs.jobs.reserve_request(reservation) {
        Ok(ticket) => ticket,
        Err(error) => {
            let failed = close_received_reverse(system, &received, counts.handles);
            if failed {
                return Err(InitError::Cleanup);
            }
            send_versioned_job_error(system, session, reservation, version, job_error_code(error))?;
            return Ok(JobDispatchOutcome::Responded);
        }
    };
    if version == JobWireVersion::ShellV1 {
        let parsed_shell = match parse_shell_v1_request(&bytes[..counts.bytes], counts.handles) {
            Ok(parsed) => parsed,
            Err(_) => {
                let failed = close_received_reverse(system, &received, counts.handles);
                if failed {
                    return Err(InitError::Cleanup);
                }
                send_shell_v1_error(
                    system,
                    session,
                    reservation,
                    LaunchErrorCode::MalformedRequest,
                )?;
                return Ok(JobDispatchOutcome::Responded);
            }
        };
        if !scope.admits_shell_v1() {
            if close_received_reverse(system, &received, counts.handles) {
                return Err(InitError::Cleanup);
            }
            send_shell_v1_error(
                system,
                session,
                reservation,
                LaunchErrorCode::PolicyRejected,
            )?;
            return Ok(JobDispatchOutcome::Responded);
        }
        for info in &received[..counts.handles] {
            if let Err(error) = validate_controller_channel(system, info.handle) {
                if close_received_reverse(system, &received, counts.handles) {
                    return Err(InitError::Cleanup);
                }
                send_shell_v1_error(system, session, reservation, launch_error_code(&error))?;
                return Ok(JobDispatchOutcome::Responded);
            }
        }
        let (Some(policy), Some(shell)) = (policy, shell.as_deref_mut()) else {
            if close_received_reverse(system, &received, counts.handles) {
                return Err(InitError::Cleanup);
            }
            send_shell_v1_error(system, session, reservation, LaunchErrorCode::LoaderFailure)?;
            return Ok(JobDispatchOutcome::Responded);
        };
        let accepted = match accept_reserved_shell(
            system,
            loader,
            waits,
            authority,
            policy,
            jobs,
            reservation,
            request_ticket,
            parsed_shell.request,
            &received[..counts.handles],
            shell,
        ) {
            Ok(accepted) => accepted,
            Err(error) => {
                let response = send_shell_v1_error(
                    system,
                    session,
                    reservation,
                    shell_launch_error_code(&error),
                );
                return if error == InitError::Cleanup {
                    Err(error)
                } else {
                    response?;
                    Ok(JobDispatchOutcome::Responded)
                };
            }
        };
        #[cfg(feature = "wyr1e8-selector33")]
        if let Err(error) = shell.state.require_recovery_live(system) {
            shell.state.poison(shell.topology.generation());
            return Err(
                if cleanup_shell_before_publication(system, waits, jobs, accepted.loaded).is_err() {
                    InitError::Cleanup
                } else {
                    error
                },
            );
        }
        let loaded = accepted.loaded;
        let release = jobs
            .jobs
            .release_launch_channel(loaded.job_id, loaded.loaded.launch_channel.0)
            .map_err(InitError::Wyr1BModel)?;
        let mut response = [0_u8; wyrmroot_launch_proto::SHELL_V1_REPLY_BYTES];
        let response_size = encode_shell_v1_accepted(reservation, loaded.job_id, &mut response)
            .map_err(|_| InitError::Accounting)?;
        if let Err(error) = system.send_channel(session, &response[..response_size]) {
            jobs.jobs.restore_launch_channel(release);
            shell.state.poison(shell.topology.generation());
            return Err(
                if cleanup_shell_before_publication(system, waits, jobs, loaded).is_err() {
                    InitError::Cleanup
                } else {
                    InitError::Native(error)
                },
            );
        }
        #[cfg(feature = "wyr1e8-selector33")]
        if let Err(error) = shell.state.require_recovery_live(system) {
            jobs.jobs.restore_launch_channel(release);
            shell.state.poison(shell.topology.generation());
            return Err(
                if cleanup_shell_before_publication(system, waits, jobs, loaded).is_err() {
                    InitError::Cleanup
                } else {
                    error
                },
            );
        }
        if system.close_handle(loaded.loaded.launch_channel).is_err() {
            jobs.jobs.restore_launch_channel(release);
            jobs.jobs
                .record_cleanup_bits(loaded.job_id, 1 << 2)
                .map_err(InitError::Wyr1BModel)?;
            shell.state.poison(shell.topology.generation());
            let _ = cleanup_shell_before_publication(system, waits, jobs, loaded);
            return Err(InitError::Cleanup);
        }
        #[cfg(feature = "wyr1e-selector33")]
        shell.state.record_e7_shell_ready(
            system,
            crate::wyr1e7_evidence::ShellTuple {
                console_generation: accepted.request.console_generation,
                status_generation: accepted.request.status_generation,
                shell_generation: accepted.request.requested_child_generation,
                outer_launch_transaction: reservation.transaction_id,
                outer_job_id: loaded.job_id,
                registry_generation: accepted.registry_grant.registry_generation,
                registry_endpoint_id: accepted.registry_grant.endpoint_id,
                registry_endpoint_generation: accepted.registry_grant.endpoint_generation,
                shell_jobs_connection_id: accepted.shell_grant.endpoint_id,
                shell_jobs_generation: accepted.shell_grant.endpoint_generation,
            },
        )?;
        #[cfg(feature = "wyr1f-closure")]
        shell.state.observe_wyr1f_shell_ready(
            accepted.request.requested_child_generation,
            reservation.transaction_id,
        );
        #[cfg(feature = "wyr1e8-selector33")]
        shell.state.stage_e8_shell_ready(
            system,
            crate::wyr1e8_evidence::ShellTuple {
                console_generation: accepted.request.console_generation,
                status_generation: accepted.request.status_generation,
                shell_generation: accepted.request.requested_child_generation,
                outer_launch_transaction: reservation.transaction_id,
                outer_job_id: loaded.job_id,
                registry_generation: accepted.registry_grant.registry_generation,
                registry_endpoint_id: accepted.registry_grant.endpoint_id,
                registry_endpoint_generation: accepted.registry_grant.endpoint_generation,
                shell_jobs_connection_id: accepted.shell_grant.endpoint_id,
                shell_jobs_generation: accepted.shell_grant.endpoint_generation,
            },
        )?;
        return Ok(JobDispatchOutcome::Launched(
            jobs.jobs
                .loaded_job(loaded.job_id)
                .map_err(InitError::Wyr1BModel)?,
        ));
    }
    let parsed = match parse_launch_message(&bytes[..counts.bytes], counts.handles) {
        Ok(parsed) => parsed,
        Err(_) => {
            let failed = close_received_reverse(system, &received, counts.handles);
            if failed {
                return Err(InitError::Cleanup);
            }
            send_job_error(
                system,
                session,
                reservation,
                LaunchErrorCode::MalformedRequest,
            )?;
            return Ok(JobDispatchOutcome::Responded);
        }
    };
    match parsed.message {
        LaunchMessage::Launch(request) => {
            if !scope.admits_legacy_launch(request.path) {
                if close_received_reverse(system, &received, counts.handles) {
                    return Err(InitError::Cleanup);
                }
                send_observed_job_error(
                    system,
                    session,
                    reservation,
                    LaunchErrorCode::PolicyRejected,
                    scope,
                    shell.as_deref_mut().map(|context| &mut *context.state),
                    &bytes[..counts.bytes],
                    &received[..counts.handles],
                )?;
                return Ok(JobDispatchOutcome::Responded);
            }
            let Some(policy) = policy else {
                if close_received_reverse(system, &received, counts.handles) {
                    return Err(InitError::Cleanup);
                }
                send_observed_job_error(
                    system,
                    session,
                    reservation,
                    LaunchErrorCode::PolicyRejected,
                    scope,
                    shell.as_deref_mut().map(|context| &mut *context.state),
                    &bytes[..counts.bytes],
                    &received[..counts.handles],
                )?;
                return Ok(JobDispatchOutcome::Responded);
            };
            #[cfg(feature = "wyr1e8-selector33")]
            let e8_trigger = if scope == LaunchSessionScope::ShellJobs {
                let state = shell
                    .as_deref()
                    .map(|context| &*context.state)
                    .ok_or(InitError::WrongActivationOrder)?;
                // R7B-4 class D1b. The dispatcher no longer knows which path
                // opens a recovery episode; the policy that admitted the launch
                // says so, by the profile it gave that path.
                let opens_episode = policy.opens_recovery_episode(request.path);
                match state.classify_e8_trigger_launch(reservation, &request, opens_episode) {
                    Ok(trigger) => trigger,
                    Err(error) => {
                        let failed = close_received_reverse(system, &received, counts.handles);
                        return Err(if failed { InitError::Cleanup } else { error });
                    }
                }
            } else {
                None
            };
            if publication == LaunchPublication::Deferred {
                return defer_reserved_launch(
                    system,
                    loader,
                    waits,
                    authority,
                    policy,
                    jobs,
                    session,
                    grant,
                    scope,
                    reservation,
                    request_ticket,
                    request,
                    &received[..legacy_handle_limit],
                    &received[..counts.handles],
                    counts.handles,
                    &bytes[..counts.bytes],
                    shell.as_deref_mut().map(|context| &mut *context.state),
                    #[cfg(feature = "wyr1e8-selector33")]
                    e8_trigger,
                );
            }
            match accept_reserved_launch(
                system,
                loader,
                waits,
                authority,
                policy,
                jobs,
                session,
                reservation,
                request_ticket,
                request,
                &received[..legacy_handle_limit],
                counts.handles,
                #[cfg(feature = "wyr1e8-selector33")]
                match e8_trigger {
                    Some(trigger) => Some((
                        shell
                            .as_deref_mut()
                            .map(|context| &mut *context.state)
                            .ok_or(InitError::WrongActivationOrder)?,
                        trigger,
                    )),
                    None => None,
                },
            ) {
                Ok((loaded, response)) => {
                    observe_e7_response(
                        system,
                        scope,
                        shell.as_deref_mut().map(|context| &mut *context.state),
                        &bytes[..counts.bytes],
                        response.as_bytes(),
                        &received[..counts.handles],
                        #[cfg(feature = "wyr1e8-selector33")]
                        response.e8_deadline,
                    )?;
                    Ok(JobDispatchOutcome::Launched(loaded))
                }
                Err(error) => {
                    send_observed_job_error(
                        system,
                        session,
                        reservation,
                        launch_error_code(&error),
                        scope,
                        shell.as_deref_mut().map(|context| &mut *context.state),
                        &bytes[..counts.bytes],
                        &received[..counts.handles],
                    )?;
                    if error == InitError::Cleanup {
                        Err(error)
                    } else {
                        Ok(JobDispatchOutcome::Responded)
                    }
                }
            }
        }
        message => {
            if close_received_reverse(system, &received, counts.handles) {
                return Err(InitError::Cleanup);
            }
            dispatch_reserved_operation_observed(
                system,
                waits,
                jobs,
                session,
                grant,
                reservation,
                request_ticket,
                message,
                &bytes[..counts.bytes],
                scope,
                shell.map(|context| &mut *context.state),
            )?;
            Ok(JobDispatchOutcome::Responded)
        }
    }
}

/// Rolls back the launch a departing session left parked, if it left one.
///
/// Reset card R6C's cancel edge. A session that peer-closes, or that is
/// disconnected by the tick's emergency cleanup, may have a transaction still
/// sitting at `AwaitingReady`: its child is constructed and unpublished, and the
/// only names for that child's Process, launch Channel and TaskGroup are in the
/// arena slot. Disconnecting the session without this would close the Channel
/// the slot recorded and leave the child to be collected at its deadline --
/// bounded, but by then the reply would be attempted on a closed handle and the
/// resources would have sat for the whole budget.
///
/// Nothing is sent. The peer that would have received `LAUNCH_ACCEPTED` or
/// `ERROR` is exactly the peer that has gone.
fn cancel_parked_launch<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    grant: EndpointGrant,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let Some(token) = jobs.launches.session_transaction(grant) else {
        return Ok(());
    };
    if jobs
        .launches
        .stage(token)
        .map_err(launch_transaction_error)?
        != LaunchStage::AwaitingReady
    {
        // Every other open stage is reached and left inside one call. A
        // transaction found in one here would mean a launch was parked at a
        // stage nothing polls, which is an accounting fault rather than a
        // cancel.
        return Err(InitError::Accounting);
    }
    let reservation = jobs
        .launches
        .response_envelope(token)
        .map_err(launch_transaction_error)?
        .1;
    let job_id = jobs
        .launches
        .job_id(token)
        .map_err(launch_transaction_error)?;
    let profile = jobs
        .launches
        .profile(token)
        .map_err(launch_transaction_error)?
        .ok_or(InitError::Accounting)?;
    let prepared = jobs
        .jobs
        .staged_job(
            grant.endpoint_id,
            grant.endpoint_generation,
            job_id,
            reservation.transaction_id,
            profile,
        )
        .map_err(InitError::Wyr1BModel)?;
    jobs.launches
        .take_resources(token)
        .map_err(launch_transaction_error)?;
    let cleanup_failed = rollback_prepared_job(system, waits, jobs, prepared).is_err();
    close_deferred_launch(jobs, token, false)?;
    if cleanup_failed {
        return Err(InitError::Cleanup);
    }
    Ok(())
}

/// Whether a parked launch has anything to say yet.
///
/// Reset card R6C. `finish_deferred_launch` ends in `observe_prepared_ready`,
/// which waits on the child's launch Channel and Process until one of them
/// signals or the READY deadline expires. R6B-2 moved that wait to a tick of
/// its own; it did not stop it being a wait, so a child that never answers
/// still held the tick that went to finish it.
///
/// This is the gate. It polls the same two handles the observation will wait
/// on, with an already-passed deadline, so it cannot block:
///
/// - something signalled that the observation can act on without waiting again
///   -- a READY message, or the child's exit -- so the launch is finished now;
/// - nothing signalled and the budget is spent, so the launch is failed here
///   without observing at all. Handing the spent deadline back to
///   `observe_prepared_ready` and letting its own `wait_many` time out would
///   reach the same disposition in production, but by way of a second clock --
///   the one the wait sees rather than the one the loop measured against. One
///   clock decides, and it is this one;
/// - nothing signalled and there is budget left, so the launch stays parked and
///   the tick goes on to the sessions.
///
/// READY is checked before expiry deliberately. A child that signalled in the
/// same instant its deadline passed is published, exactly as the one-frame
/// `wait_many` would have published it -- the deadline bounds how long the
/// supervisor waits, not how late an answer may be.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParkedLaunch {
    /// Silent, with budget left. Stays parked.
    Waiting,
    /// Its Channel or its Process said something. Finish it.
    Signalled,
    /// Silent, and out of budget. Fail it.
    Expired,
}

fn parked_launch_disposition<S: Wyr1BPlatform>(
    system: &mut S,
    jobs: &JobDispatcher,
    token: LaunchToken,
    now_ns: u64,
) -> Result<ParkedLaunch, InitError> {
    let resources = jobs
        .launches
        .resources(token)
        .map_err(launch_transaction_error)?
        .ok_or(InitError::Accounting)?;
    let deadline = jobs
        .launches
        .ready_deadline(token)
        .map_err(launch_transaction_error)?
        .ok_or(InitError::Accounting)?;
    // R6D. `PEER_CLOSED` is deliberately not asked for, and this is the whole
    // reason the gate is a signal set rather than "did anything happen".
    //
    // `await_child_ready_profile_observed` branches on what its own wait
    // selects. `READABLE` is the READY message, which it receives and parses;
    // `EXITED` is the early-exit record, which it queries and returns. Both
    // finish without waiting again. But a launch Channel that is `PEER_CLOSED`
    // and *not* `READABLE` sends it into a second `wait_many` for the Process's
    // `EXITED`, and that one is bounded only by the launch's own deadline. A
    // child that dropped its end of the Channel and then declined to die would
    // hold the tick for the whole budget -- one failing child blocking every
    // other launch client, which is exactly what R6D has to refute.
    //
    // So a peer-closed-but-silent child is left parked. Its Channel stays
    // closed, so the condition is level-triggered and every later tick sees it
    // again; it leaves through `Expired` when the budget runs out, by the same
    // door as a child that said nothing at all. What is lost is the terminal
    // record `PeerClosedBeforeReady` would have carried, and only when the
    // Process outlives its Channel by the whole budget.
    let items = [
        DwWaitItemV1 {
            handle: resources.launch_channel,
            signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0),
        },
        DwWaitItemV1 {
            handle: resources.process,
            signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_EXITED.0),
        },
    ];
    match system.wait_many(&items, DwDeadline(now_ns)) {
        Ok(_) => Ok(ParkedLaunch::Signalled),
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
            if now_ns >= deadline.0 {
                Ok(ParkedLaunch::Expired)
            } else {
                Ok(ParkedLaunch::Waiting)
            }
        }
        Err(error) => Err(InitError::Native(error)),
    }
}

/// Runs the half of a launch that was left parked, on a tick of its own.
///
/// Reset card R6B-2. This is `finish_constructed_launch` with its inputs read
/// back out of the arena instead of off the frame that constructed them, and
/// with the evidence record finished from the digests taken then. The sequence
/// inside `finish_constructed_launch` is untouched, including every rollback.
///
/// The prepared job is not stored; it is asked for. `JobController::staged_job`
/// rebuilds it from the model's own record of the job, which is why a slot can
/// be resolved a tick later without the arena holding a `LaunchTicket` that
/// names a job-table position the model may have reused. The handles the model
/// hands back are checked against the ones the arena recorded, because two
/// records of the same child disagreeing is exactly the state neither of them
/// could detect alone.
fn finish_deferred_launch<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    token: LaunchToken,
    mut shell: Option<&mut ShellLaunchContext<'_>>,
    disposition: ParkedLaunch,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    // A build with no evidence surface and no recovery trigger has nothing to
    // ask the shell context for; it still takes one, because the caller is the
    // same poll loop in every build.
    #[cfg(not(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33")))]
    let _ = &mut shell;
    let (session, reservation) = jobs
        .launches
        .response_envelope(token)
        .map_err(launch_transaction_error)?;
    let grant = jobs
        .launches
        .grant(token)
        .map_err(launch_transaction_error)?;
    let job_id = jobs
        .launches
        .job_id(token)
        .map_err(launch_transaction_error)?;
    let deadline = jobs
        .launches
        .ready_deadline(token)
        .map_err(launch_transaction_error)?
        .ok_or(InitError::Accounting)?;
    let profile = jobs
        .launches
        .profile(token)
        .map_err(launch_transaction_error)?
        .ok_or(InitError::Accounting)?;
    let recorded = jobs
        .launches
        .resources(token)
        .map_err(launch_transaction_error)?
        .ok_or(InitError::Accounting)?;
    #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
    let facts = jobs
        .launches
        .request_facts(token)
        .map_err(launch_transaction_error)?
        .ok_or(InitError::Accounting)?;
    #[cfg(feature = "wyr1e8-selector33")]
    let trigger_action = jobs
        .launches
        .trigger_action(token)
        .map_err(launch_transaction_error)?;
    let prepared = jobs
        .jobs
        .staged_job(
            grant.endpoint_id,
            grant.endpoint_generation,
            job_id,
            reservation.transaction_id,
            profile,
        )
        .map_err(InitError::Wyr1BModel)?;
    if prepared.loaded.process != recorded.process
        || prepared.loaded.launch_channel != recorded.launch_channel
        || prepared.task_group != recorded.task_group.0
    {
        return Err(InitError::Accounting);
    }
    // The transaction stops owning the handles here. Whichever way the rest of
    // this goes -- published, or rolled back -- they are accounted for by the
    // model or closed by the rollback, and a slot that still claimed them could
    // not be closed at all.
    jobs.launches
        .take_resources(token)
        .map_err(launch_transaction_error)?;
    let constructed = ConstructedLaunch {
        prepared,
        deadline,
        session,
        reservation,
    };
    #[cfg(feature = "wyr1e8-selector33")]
    let acceptance = match (trigger_action, shell.as_deref_mut()) {
        (Some(action), Some(context)) => Some((
            &mut *context.state,
            E8TriggerRequest {
                reservation,
                action,
            },
        )),
        (Some(_), None) => return Err(InitError::WrongActivationOrder),
        (None, _) => None,
    };
    let outcome = match disposition {
        ParkedLaunch::Signalled => finish_constructed_launch(
            system,
            waits,
            jobs,
            constructed,
            #[cfg(feature = "wyr1e8-selector33")]
            acceptance,
        ),
        // Out of budget, and nothing to observe. This is the disposition the
        // one-frame path reached when its `wait_many` hit the deadline, and the
        // rollback is the same one: the child is not published, and whether the
        // teardown itself failed is what decides between `Cleanup` and
        // `Supervision`.
        ParkedLaunch::Waiting | ParkedLaunch::Expired => {
            #[cfg(feature = "wyr1e8-selector33")]
            let _ = acceptance;
            Err(
                if rollback_prepared_job(system, waits, jobs, constructed.prepared).is_err() {
                    InitError::Cleanup
                } else {
                    InitError::Supervision
                },
            )
        }
    };
    #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
    let scope = jobs
        .launches
        .scope(token)
        .map_err(launch_transaction_error)?;
    let published = match outcome {
        Ok((_, response)) => {
            #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
            let recorded = observe_deferred_launch_response(
                system,
                scope,
                shell.as_deref_mut().map(|context| &mut *context.state),
                facts,
                response.as_bytes(),
            );
            #[cfg(not(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33")))]
            let recorded = {
                let _ = &response;
                Ok(())
            };
            recorded
        }
        Err(error) => {
            // Best-effort, and deliberately not `?`. The reply is owed to a
            // session that may already be gone -- peer close, or an emergency
            // disconnect elsewhere in the tick, closes the Channel this slot
            // recorded, and sending on a closed handle fails. What is *not*
            // best-effort is emptying the slot below: a transaction left open
            // here would be handed back by `awaiting_ready_from` on every
            // subsequent tick, for ever, holding a child nothing else can name.
            let reply = send_deferred_launch_error(
                system,
                session,
                reservation,
                launch_error_code(&error),
                #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
                scope,
                #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
                shell.map(|context| &mut *context.state),
                #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
                facts,
            );
            Err(match reply {
                Ok(()) => error,
                // A failed reply does not relabel the launch's own failure, for
                // the same reason `LaunchTransactions::fail` keeps the first
                // disposition: the caller asked why the launch failed, not what
                // went wrong telling it.
                Err(InitError::Cleanup) => InitError::Cleanup,
                Err(_) => error,
            })
        }
    };
    close_deferred_launch(jobs, token, published.is_ok())?;
    // One launch failing is not the tick failing. The one-frame path answered a
    // failed launch with an `ERROR` reply and returned `Responded`, and only a
    // failed *cleanup* escalated -- because a cleanup that did not happen means
    // resources nobody can name, while a child that missed READY has already
    // been rolled back by the time we get here. R6C keeps that split: a launch
    // that never answers must not take down the supervisor, which is most of
    // what R6D has to prove.
    match published {
        Ok(()) => Ok(()),
        Err(InitError::Cleanup) => Err(InitError::Cleanup),
        Err(_) => Ok(()),
    }
}

/// Walks the parked transaction out of the arena by the same door every
/// transaction leaves by: a disposition, then `Cleanup`, then `Complete`.
fn close_deferred_launch(
    jobs: &mut JobDispatcher,
    token: LaunchToken,
    published: bool,
) -> Result<(), InitError> {
    let disposition = if published {
        LaunchStage::Published
    } else {
        LaunchStage::Failing
    };
    jobs.launches
        .advance(token, disposition)
        .map_err(launch_transaction_error)?;
    jobs.launches
        .advance(token, LaunchStage::Cleanup)
        .map_err(launch_transaction_error)?;
    jobs.launches
        .advance(token, LaunchStage::Complete)
        .map_err(launch_transaction_error)?;
    jobs.launches
        .close(token)
        .map(|_| ())
        .map_err(launch_transaction_error)
}

/// Records the transaction whose request bytes are gone.
///
/// The counterpart of `observe_e7_response` for a deferred reply. Only
/// `ShellJobs` carries a launch transaction record; a console-launcher reply is
/// an outer response, which is recorded against the request and is never
/// deferred.
#[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
fn observe_deferred_launch_response<S: Wyr1BPlatform>(
    system: &mut S,
    scope: LaunchSessionScope,
    state: Option<&mut ShellControllerState>,
    facts: crate::launch_request_facts::LaunchRequestFacts,
    response: &[u8],
) -> Result<(), InitError> {
    if scope != LaunchSessionScope::ShellJobs {
        return Ok(());
    }
    let Some(state) = state else {
        #[cfg(test)]
        return Ok(());
        #[cfg(not(test))]
        return Err(InitError::WrongActivationOrder);
    };
    state.record_deferred_shell_jobs_launch(system, facts, response)
}

/// Sends the error reply a deferred launch owes its session, and records it.
fn send_deferred_launch_error<S: Wyr1BPlatform>(
    system: &mut S,
    session: DwHandle,
    reservation: LaunchReservation,
    code: LaunchErrorCode,
    #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
    scope: LaunchSessionScope,
    #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))] state: Option<
        &mut ShellControllerState,
    >,
    #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
    facts: crate::launch_request_facts::LaunchRequestFacts,
) -> Result<(), InitError> {
    let mut response = [0_u8; 88];
    let size =
        encode_launch_error(reservation, code, &mut response).map_err(|_| InitError::Accounting)?;
    system
        .send_channel(session, &response[..size])
        .map_err(InitError::Native)?;
    #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
    observe_deferred_launch_response(system, scope, state, facts, &response[..size])?;
    Ok(())
}

#[inline(always)]
pub(crate) fn poll_job_dispatcher<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    jobs: &mut JobDispatcher,
    now_ns: u64,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    poll_job_dispatcher_inner(system, loader, waits, authority, jobs, now_ns, None).map(|_| ())
}

/// E3C adapter for the selected console controller. The caller supplies the
/// current registry generation and poison state; request bytes cannot select
/// either authority.
#[cfg(feature = "wyr1e-shell-controller")]
#[allow(
    dead_code,
    clippy::too_many_arguments,
    reason = "E6 wires this E3C adapter into the selected resident product"
)]
pub(crate) fn poll_job_dispatcher_with_shell<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    jobs: &mut JobDispatcher,
    now_ns: u64,
    shell: &mut ShellLaunchContext<'_>,
) -> Result<JobDispatcherPollOutcome, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    poll_job_dispatcher_inner(system, loader, waits, authority, jobs, now_ns, Some(shell))
}

#[allow(clippy::too_many_arguments)]
fn poll_job_dispatcher_inner<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    jobs: &mut JobDispatcher,
    now_ns: u64,
    mut shell: Option<&mut ShellLaunchContext<'_>>,
) -> Result<JobDispatcherPollOutcome, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut outcome = JobDispatcherPollOutcome::Stable;
    // Reset cards R6B-2 and R6C. A launch parked by a previous tick is looked at
    // before any new request is read -- the child is already alive and its READY
    // deadline is already running, so it has the older claim -- but it is only
    // *finished* if its own handles say something has happened, or if its budget
    // has run out. R6B-2 moved the blocking observation off the frame that read
    // the request; R6C is what stops it blocking the tick as well.
    //
    // The tick does not end here either way. A parked child that is still
    // silent costs one non-blocking poll of two handles, and the session poll
    // below runs regardless, which is the property R6D has to prove: a child
    // that never answers cannot take a session's turn.
    //
    // The cursor moves past the slot it looked at, so a silent child cannot
    // starve the one behind it.
    if let Some(token) = jobs.launches.awaiting_ready_from(jobs.launch_cursor) {
        jobs.launch_cursor = token.slot().wrapping_add(1);
        match parked_launch_disposition(system, jobs, token, now_ns)? {
            ParkedLaunch::Waiting => {}
            disposition => finish_deferred_launch(
                system,
                waits,
                jobs,
                token,
                shell.as_deref_mut(),
                disposition,
            )?,
        }
    }
    if let Some((grant, session)) = jobs.next_session() {
        let item = DwWaitItemV1 {
            handle: session,
            signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        };
        match system.wait_many(core::slice::from_ref(&item), DwDeadline(now_ns)) {
            Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {}
            Err(error) => return Err(InitError::Native(error)),
            Ok(observed) if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 => {
                // Read before the dispatch, which may disconnect the session.
                let scope = jobs.session_scope(grant).map_err(InitError::Wyr1BModel)?;
                let size = system
                    .query_memory_object_size(authority.bootfs)
                    .map_err(InitError::Native)?;
                let plan = MappingPlan::for_bootfs(size).map_err(|error| {
                    ordinary_mapping_error(MappingDiagnosticSite::JobDispatcher, error, size)
                })?;
                let dispatched = system
                    .with_bootfs_bytes(
                        authority.parent_root,
                        authority.bootfs,
                        plan,
                        |system, bootfs| {
                            let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
                            let manifest = archive
                                .lookup(MANIFEST_PATH.as_bytes())
                                .map_err(map_lookup)?;
                            let boot_generation: [u8; 32] = manifest
                                .data()
                                .get(48..80)
                                .ok_or(InitError::Accounting)?
                                .try_into()
                                .map_err(|_| InitError::Accounting)?;
                            let policy = PolicyView::from_bootfs(archive, boot_generation)
                                .map_err(InitError::Wyr1BModel)?;
                            if let Some(shell) = shell.as_deref_mut() {
                                dispatch_one_job_request_with_shell(
                                    system,
                                    loader,
                                    waits,
                                    authority,
                                    Some(&policy),
                                    jobs,
                                    session,
                                    grant,
                                    shell,
                                    LaunchPublication::Deferred,
                                )
                            } else {
                                dispatch_one_job_request(
                                    system,
                                    loader,
                                    waits,
                                    authority,
                                    Some(&policy),
                                    jobs,
                                    session,
                                    grant,
                                    LaunchPublication::Deferred,
                                )
                            }
                        },
                    )
                    .map_err(InitError::Native)?;
                if let Err(dispatch_error) = dispatched {
                    // R6C. Whatever this session had in flight goes with it.
                    let cancel_failed = cancel_parked_launch(system, waits, jobs, grant).is_err();
                    // Both arms ran the same emergency cleanup; only one said
                    // which half of it failed. The other collapsed to a bare
                    // `Cleanup`, losing the initiating error entirely -- the
                    // collapse `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` 3.2 says
                    // owes an instance. One arm now, and the reported kind is
                    // unchanged: a failed cleanup still reports kind 04.
                    let disconnected = jobs.disconnect_owned_session(grant);
                    let emergency_cleanup = match disconnected {
                        Ok(session) => {
                            let channel_close_failed =
                                system.close_handle(session.channel).is_err();
                            let owner_cleanup_failed =
                                cleanup_session_owner(system, waits, session.owner, true);
                            EmergencyCleanup::Attempted {
                                channel_close_failed,
                                owner_cleanup_failed,
                            }
                        }
                        Err(_) => EmergencyCleanup::DisconnectFailed,
                    };
                    let emergency_cleanup = match emergency_cleanup {
                        EmergencyCleanup::Attempted {
                            channel_close_failed,
                            owner_cleanup_failed,
                        } => EmergencyCleanup::Attempted {
                            channel_close_failed,
                            owner_cleanup_failed: owner_cleanup_failed | cancel_failed,
                        },
                        other => other,
                    };
                    // F3A.7j. Named by the session's scope, so a failed
                    // request says whose it was; `attribute_failure` keeps
                    // an operation the error already carries.
                    let operation = match scope {
                        LaunchSessionScope::Historical => RecoveryOperation::DispatchHistoricalJob,
                        LaunchSessionScope::ConsoleLauncher => {
                            RecoveryOperation::DispatchConsoleJob
                        }
                        LaunchSessionScope::ShellJobs => RecoveryOperation::DispatchShellJob,
                    };
                    let attributed =
                        attribute_failure(operation, Err::<(), _>(dispatch_error)).unwrap_err();
                    return Err(dispatch_failure(attributed, emergency_cleanup));
                }
            }
            Ok(observed) if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 => {
                let scope = jobs.session_scope(grant).map_err(InitError::Wyr1BModel)?;
                #[cfg(feature = "wyr1e8-selector33")]
                let defer_console_retirement = scope == LaunchSessionScope::ConsoleLauncher
                    && shell
                        .as_deref()
                        .is_some_and(|context| context.state.recovery_owns_console_retirement());
                #[cfg(not(feature = "wyr1e8-selector33"))]
                let defer_console_retirement = false;
                // When recovery owns this session and its process as one
                // coordinated retirement, observe peer close without consuming
                // either owner ahead of that join.
                if !defer_console_retirement {
                    // R6C's cancel. The peer that asked for this launch is gone
                    // before it was told the child exists, so nothing owns the
                    // child and nothing is owed a reply. Rolling it back here
                    // rather than leaving it to its deadline means the session's
                    // resources and its child's go in one step -- and means the
                    // slot is not still holding a Channel this branch is about
                    // to close.
                    cancel_parked_launch(system, waits, jobs, grant)?;
                    let outer = if scope == crate::wyr1b_job::LaunchSessionScope::ConsoleLauncher {
                        jobs.jobs
                            .loaded_job_for_owner(grant.endpoint_id, grant.endpoint_generation)
                            .map_err(InitError::Wyr1BModel)?
                    } else {
                        None
                    };
                    let disconnected = jobs
                        .disconnect_owned_session(grant)
                        .map_err(InitError::Wyr1BModel)?;
                    let mut failed = system.close_handle(disconnected.channel).is_err()
                        | cleanup_session_owner(system, waits, disconnected.owner, true)
                        | disconnected.outer_job.is_some_and(|job_id| {
                            let loaded = jobs.jobs.loaded_job(job_id);
                            loaded.map_or(true, |loaded| {
                                force_cleanup_job(system, waits, jobs, loaded).is_err()
                            })
                        });
                    if let Some(outer) = outer {
                        failed |=
                            cleanup_shell_before_publication(system, waits, jobs, outer).is_err();
                    }
                    if failed {
                        return Err(InitError::Cleanup);
                    }
                    outcome = JobDispatcherPollOutcome::SessionClosed { grant, scope };
                }
            }
            Ok(_) => return Err(InitError::Supervision),
        }
    }
    if let Some(loaded) = jobs.next_cleanup_job() {
        let terminal_staged = jobs
            .jobs
            .terminal_result(loaded.job_id)
            .map_err(InitError::Wyr1BModel)?
            .is_some();
        let exited = if terminal_staged {
            true
        } else if loaded.loaded.process.0 == 0 {
            return Err(InitError::Accounting);
        } else {
            match waits.query_task_termination(loaded.loaded.process) {
                Ok(info) => info.state == DW_TASK_STATE_EXITED,
                Err(_) => {
                    jobs.jobs
                        .record_cleanup_bits(loaded.job_id, 1 << 1)
                        .map_err(InitError::Wyr1BModel)?;
                    return Err(InitError::Cleanup);
                }
            }
        };
        if exited {
            let result = reap_job(system, waits, jobs, loaded)?;
            let nested = close_shell_session_for_job(system, jobs, loaded.job_id);
            if result.cleanup_result != 0 || nested.is_err() {
                return Err(InitError::Cleanup);
            }
        }
    }
    if let Some(shell) = shell {
        service_pending_wait_inner(system, waits, jobs, Some(&mut *shell.state))?;
    } else {
        service_pending_wait(system, waits, jobs)?;
    }
    Ok(outcome)
}

/// Latches a console child's session shutdown, at either WAIT reply.
///
/// F3A.7g. Both replies encode the same terminal result and both are reached
/// for the same child, so the fact is read once, here, rather than at two
/// sites that could drift apart.
///
/// The scope is what makes this specific. A `ConsoleLauncher` session belongs
/// to `consoled`, which launches exactly one child -- its shell -- so any
/// terminal result crossing it is that shell's. A `ShellJobs` session belongs
/// to the shell itself, and the jobs *it* launches are ordinary user programs
/// whose exit codes it prints; one of those happening to exit with the same
/// value must not end the session.
fn observe_session_shutdown_result(
    scope: LaunchSessionScope,
    state: Option<&mut ShellControllerState>,
    terminal: wyrmroot_launch_proto::TerminationResult,
) {
    if scope != LaunchSessionScope::ConsoleLauncher
        || terminal.classification != wyrmroot_launch_proto::TerminationClassification::NormalExit
        || terminal.application_code != wyrmroot_launch_proto::SHELL_SESSION_SHUTDOWN_STATUS
    {
        return;
    }
    if let Some(state) = state {
        state.observe_session_shutdown();
    }
}

fn service_pending_wait<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    service_pending_wait_inner(system, waits, jobs, None)
}

#[allow(unused_mut)]
fn service_pending_wait_inner<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    mut evidence: Option<&mut ShellControllerState>,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let Some(pending) = jobs.next_pending_wait() else {
        return Ok(());
    };
    let scope = jobs
        .session_scope(pending.grant)
        .map_err(InitError::Wyr1BModel)?;
    let result = match jobs.jobs.result_for_owner(
        pending.reservation.connection_id,
        pending.reservation.generation,
        pending.job_id,
    ) {
        Ok(result) => result,
        Err(JobError::UnknownJob) => return Ok(()),
        Err(error) => return Err(InitError::Wyr1BModel(error)),
    };
    let session = jobs
        .session_handle(pending.grant)
        .map_err(InitError::Wyr1BModel)?;
    // The held-wait barrier itself is R7A class D1 and still selector-only;
    // only the attribution around it became ordinary.
    #[cfg(feature = "wyr1e8-selector33")]
    if scope == LaunchSessionScope::ShellJobs {
        let state = evidence
            .as_deref_mut()
            .ok_or(InitError::WrongActivationOrder)?;
        if attribute_failure(
            RecoveryOperation::TriggerWait,
            state.e8_wait_is_held(pending),
        )? || attribute_failure(
            RecoveryOperation::TriggerWait,
            state.hold_e8_wait(system, pending, result),
        )? {
            return Ok(());
        }
    }
    let terminal = controller_result_to_wire(result)?;
    observe_session_shutdown_result(scope, evidence.as_deref_mut(), terminal);
    let mut response = [0_u8; 88];
    let size = encode_job_result(pending.reservation, pending.job_id, terminal, &mut response)
        .map_err(|_| InitError::Accounting)?;
    if let Err(error) = system.send_channel(session, &response[..size]) {
        jobs.finish_pending_wait(pending)
            .map_err(InitError::Wyr1BModel)?;
        let disconnected = jobs
            .disconnect_owned_session(pending.grant)
            .map_err(InitError::Wyr1BModel)?;
        let failed = system.close_handle(disconnected.channel).is_err()
            | cleanup_session_owner(system, waits, disconnected.owner, true);
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Native(error)
        });
    }
    #[cfg(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33"))]
    let request = pending.request_bytes();
    #[cfg(not(any(feature = "wyr1e-selector33", feature = "wyr1e8-selector33")))]
    let request = &[];
    observe_e7_response(
        system,
        scope,
        evidence,
        request,
        &response[..size],
        &[],
        #[cfg(feature = "wyr1e8-selector33")]
        None,
    )?;
    jobs.finish_pending_wait(pending)
        .map_err(InitError::Wyr1BModel)
}

fn cleanup_session_owner<S, W>(
    system: &mut S,
    waits: &mut W,
    owner: Option<SessionOwner>,
    terminate: bool,
) -> bool
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    cleanup_session_owner_before(system, waits, owner, terminate, None)
}

fn cleanup_session_owner_before<S, W>(
    system: &mut S,
    waits: &mut W,
    owner: Option<SessionOwner>,
    terminate: bool,
    deadline_cap: Option<u64>,
) -> bool
where
    S: InitPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    owner.is_some_and(|owner| {
        cleanup_loaded_before(
            system,
            waits,
            LoadedProcess {
                process: owner.process,
                launch_channel: owner.launch_channel,
            },
            owner.task_group,
            terminate,
            deadline_cap,
        )
        .is_err()
    })
}

/// Retires one product consoled generation and its foreground shell while
/// preserving already-published background jobs as invisible controller-owned
/// orphans. The caller retains the dispatcher so those jobs can still reap.
#[cfg(feature = "wyr1e-production")]
pub(crate) fn retire_console_product<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    peer: InstalledPeer,
    terminate: bool,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    retire_console_product_inner(system, waits, jobs, peer, terminate, None).map(|_| ())
}

// Called only from the held-wait retirement branch, which is class D1c and
// still the selector's. Signature matches the `_before` family regardless.
#[cfg(feature = "wyr1e8-selector33")]
pub(crate) fn retire_console_product_with_result<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    peer: InstalledPeer,
    terminate: bool,
) -> Result<Option<TerminationResult>, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    retire_console_product_inner(system, waits, jobs, peer, terminate, None)
}

#[cfg(feature = "wyr1e8-selector33")]
pub(crate) fn retire_console_product_with_result_before<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    peer: InstalledPeer,
    terminate: bool,
    deadline_cap: Option<u64>,
) -> Result<Option<TerminationResult>, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    retire_console_product_inner(system, waits, jobs, peer, terminate, deadline_cap)
}

#[cfg(feature = "wyr1e8-selector33")]
pub(crate) fn finish_e8_dependent_retirement<S: Wyr1BPlatform>(
    system: &mut S,
    jobs: &mut JobDispatcher,
    shell: &mut ShellControllerState,
    held: E8HeldWait,
    result: TerminationResult,
) -> Result<(), InitError> {
    shell.require_recovery_live_at(system.now().map_err(InitError::Native)?)?;
    jobs.remove_barrier_result(held.pending, E8_HELD_WAIT_RESULT)
        .map_err(InitError::Wyr1BModel)?;
    shell.require_recovery_live_at(system.now().map_err(InitError::Native)?)?;
    shell.record_e8_forced_retired(system, held, result)?;
    shell.consume_e8_held(held);
    Ok(())
}

#[cfg(feature = "wyr1e-production")]
fn retire_console_product_inner<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    peer: InstalledPeer,
    terminate: bool,
    deadline_cap: Option<u64>,
) -> Result<Option<TerminationResult>, InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let outer = jobs
        .jobs
        .loaded_job_for_owner(peer.grant.endpoint_id, peer.grant.endpoint_generation)
        .map_err(InitError::Wyr1BModel)?;
    let disconnected = jobs
        .disconnect_owned_session(peer.grant)
        .map_err(InitError::Wyr1BModel)?;
    let expected_owner = SessionOwner {
        process: peer.loaded.process,
        launch_channel: peer.loaded.launch_channel,
        task_group: peer.task_group,
    };
    // Accounting disagreement must not short-circuit cleanup of resources we
    // still own. Preserve the mismatch as a cleanup failure after attempting
    // every independent close in this generation.
    let owner_mismatch = disconnected.owner != Some(expected_owner);
    let outer_mismatch = disconnected.outer_job.is_some();
    let channel_close_failed = system.close_handle(disconnected.channel).is_err();
    let owner_cleanup_failed =
        cleanup_session_owner_before(system, waits, disconnected.owner, terminate, deadline_cap);
    let mut failed = owner_mismatch | outer_mismatch | channel_close_failed | owner_cleanup_failed;
    let outer_result = match outer {
        Some(outer) => {
            match cleanup_shell_before_publication_before(system, waits, jobs, outer, deadline_cap)
            {
                Ok(result) => Some(result),
                Err(_) => {
                    failed = true;
                    None
                }
            }
        }
        None => None,
    };
    if failed {
        Err(InitError::Cleanup)
    } else {
        Ok(outer_result)
    }
}

pub(crate) fn drain_job_dispatcher<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut sessions = [None; crate::wyr1b_job::MAX_SESSIONS];
    let session_count = jobs.drain_sessions(&mut sessions);
    let mut failed = false;
    for session in sessions[..session_count].iter().rev().flatten().copied() {
        failed |= system.close_handle(session.channel).is_err()
            | cleanup_session_owner(system, waits, session.owner, true);
    }
    let job_count = jobs.jobs.live_jobs();
    for _ in 0..job_count {
        let Some(loaded) = jobs.next_cleanup_job() else {
            break;
        };
        if let Some(resources) = jobs
            .jobs
            .forced_termination_resources(loaded.job_id)
            .map_err(InitError::Wyr1BModel)?
        {
            if system
                .terminate_task_group(DwHandle(resources.task_group))
                .is_err()
            {
                jobs.jobs
                    .record_cleanup_bits(loaded.job_id, 1 << 0)
                    .map_err(InitError::Wyr1BModel)?;
                failed = true;
            } else {
                jobs.jobs
                    .commit_forced_termination(loaded.job_id, resources)
                    .map_err(InitError::Wyr1BModel)?;
            }
        }
        match reap_job(system, waits, jobs, loaded) {
            Ok(result) => failed |= result.cleanup_result != 0,
            Err(_) => failed = true,
        }
    }
    if jobs.jobs.live_jobs() != 0 || failed {
        Err(InitError::Cleanup)
    } else {
        Ok(())
    }
}

fn close_launch_client<S, W>(
    system: &mut S,
    waits: &mut W,
    jobs: &mut JobDispatcher,
    peer: InstalledPeer,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    let session = jobs
        .session_handle(peer.grant)
        .map_err(InitError::Wyr1BModel)?;
    let deadline = report_deadline(system)?;
    let result = system
        .wait_many(
            core::slice::from_ref(&DwWaitItemV1 {
                handle: session,
                signals: DW_SIGNAL_PEER_CLOSED,
            }),
            deadline,
        )
        .map_err(InitError::Native)?;
    if result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 == 0 {
        return Err(InitError::Supervision);
    }
    let disconnected = jobs
        .disconnect_owned_session(peer.grant)
        .map_err(InitError::Wyr1BModel)?;
    let expected_owner = SessionOwner {
        process: peer.loaded.process,
        launch_channel: peer.loaded.launch_channel,
        task_group: peer.task_group,
    };
    if disconnected.owner != Some(expected_owner) {
        return Err(InitError::Accounting);
    }
    let failed = system.close_handle(disconnected.channel).is_err()
        | cleanup_session_owner(system, waits, disconnected.owner, false);
    if failed {
        Err(InitError::Cleanup)
    } else {
        Ok(())
    }
}

fn launch_gate_record(
    message_type: GateMessageType,
    gate: GateConfig,
    actor: EndpointGrant,
    object_id: u64,
    object_generation: u64,
    operation_id: u64,
) -> GateRecord {
    GateRecord {
        message_type,
        nonce: gate.nonce,
        registry_generation: actor.registry_generation,
        actor_id: actor.endpoint_id,
        actor_generation: actor.endpoint_generation,
        object_id,
        object_generation,
        operation_id,
        value: 0,
    }
}

fn expect_launch_report<S: Wyr1BPlatform>(
    system: &mut S,
    peer: InstalledPeer,
    expected: GateRecord,
) -> Result<(), InitError> {
    let deadline = report_deadline(system)?;
    let actual = receive_gate(system, peer.loaded.launch_channel, deadline)?;
    expect_gate(actual, expected)
}

#[allow(clippy::too_many_arguments)]
fn dispatch_owner_wait_then_poll<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    policy: Option<&PolicyView<'_>>,
    jobs: &mut JobDispatcher,
    session: DwHandle,
    grant: EndpointGrant,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    if dispatch_one_job_request(
        system,
        loader,
        waits,
        authority,
        policy,
        jobs,
        session,
        grant,
        LaunchPublication::Immediate,
    )? != JobDispatchOutcome::Responded
    {
        return Err(InitError::Wyr1BModel(JobError::WrongState));
    }
    let poll_now = system.now().map_err(InitError::Native)?;
    poll_job_dispatcher(system, loader, waits, authority, jobs, poll_now)
}

fn record_owner_job_reap(
    evidence: &mut EvidenceLog,
    owner: EndpointGrant,
    job_id: u64,
    result: ControllerJobResult,
) -> Result<(), InitError> {
    if result.classification != TerminationClassification::NormalExit.as_u32()
        || result.application_code != 0
        || result.cleanup_result != 0
    {
        return Err(InitError::Wyr1BGateMismatch);
    }
    evidence
        .record(GateEvent::JobExitZero, job_id, owner.endpoint_generation, 0)
        .map_err(InitError::Wyr1BEvidence)?;
    evidence
        .record(
            GateEvent::JobReaped,
            job_id,
            owner.endpoint_generation,
            owner.endpoint_id,
        )
        .map_err(InitError::Wyr1BEvidence)
}

#[allow(clippy::too_many_arguments)]
fn run_job_gate<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootfs: &[u8],
    topology: &mut RegistryTopology,
    gate: GateConfig,
    jobs: &mut JobDispatcher,
    evidence: &mut EvidenceLog,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
    let manifest = archive
        .lookup(MANIFEST_PATH.as_bytes())
        .map_err(map_lookup)?;
    let boot_generation: [u8; 32] = manifest
        .data()
        .get(48..80)
        .ok_or(InitError::Accounting)?
        .try_into()
        .map_err(|_| InitError::Accounting)?;
    let policy =
        PolicyView::from_bootfs(archive, boot_generation).map_err(InitError::Wyr1BModel)?;

    let owner = launch_launch_client(system, loader, waits, authority, bootfs, topology, jobs, 3)?;
    let (_, owner_session) = jobs.next_session().ok_or(InitError::Accounting)?;
    let owner_config = launch_gate_record(
        GateMessageType::ConfigureLaunchOwner,
        gate,
        owner.grant,
        0,
        0,
        3,
    );
    send_gate(system, owner.loaded.launch_channel, owner_config)?;
    let owner_job = receive_and_accept_job(
        system,
        loader,
        waits,
        authority,
        &policy,
        jobs,
        owner_session,
        owner.grant,
    )?;
    expect_launch_report(
        system,
        owner,
        launch_gate_record(
            GateMessageType::JobAccepted,
            gate,
            owner.grant,
            owner_job.job_id,
            owner.grant.endpoint_generation,
            3,
        ),
    )?;
    evidence
        .record(
            GateEvent::JobAccepted,
            owner_job.job_id,
            owner.grant.endpoint_generation,
            owner.grant.endpoint_id,
        )
        .map_err(InitError::Wyr1BEvidence)?;
    wait_session_readable(system, owner_session)?;
    dispatch_owner_wait_then_poll(
        system,
        loader,
        waits,
        authority,
        Some(&policy),
        jobs,
        owner_session,
        owner.grant,
    )?;
    let job_id = owner_job.job_id;
    expect_launch_report(
        system,
        owner,
        launch_gate_record(
            GateMessageType::JobResult,
            gate,
            owner.grant,
            job_id,
            owner.grant.endpoint_generation,
            3,
        ),
    )?;
    let owner_result = jobs
        .jobs
        .result_for_owner(
            owner.grant.endpoint_id,
            owner.grant.endpoint_generation,
            job_id,
        )
        .map_err(InitError::Wyr1BModel)?;
    record_owner_job_reap(&mut *evidence, owner.grant, job_id, owner_result)?;
    close_launch_client(system, waits, jobs, owner)?;

    let foreign =
        launch_launch_client(system, loader, waits, authority, bootfs, topology, jobs, 4)?;
    let (_, foreign_session) = jobs.next_session().ok_or(InitError::Accounting)?;
    let foreign_config = launch_gate_record(
        GateMessageType::ConfigureLaunchForeign,
        gate,
        foreign.grant,
        owner.grant.endpoint_id,
        owner.grant.endpoint_generation,
        4,
    );
    send_gate(system, foreign.loaded.launch_channel, foreign_config)?;
    let probe = launch_gate_record(
        GateMessageType::ProbeForeign,
        gate,
        foreign.grant,
        job_id,
        owner.grant.endpoint_generation,
        4,
    );
    send_gate(system, foreign.loaded.launch_channel, probe)?;
    wait_session_readable(system, foreign_session)?;
    if dispatch_one_job_request(
        system,
        loader,
        waits,
        authority,
        Some(&policy),
        jobs,
        foreign_session,
        foreign.grant,
        LaunchPublication::Immediate,
    )? != JobDispatchOutcome::Responded
    {
        return Err(InitError::Wyr1BModel(JobError::WrongState));
    }
    expect_launch_report(
        system,
        foreign,
        launch_gate_record(
            GateMessageType::ForeignRejected,
            gate,
            foreign.grant,
            job_id,
            owner.grant.endpoint_generation,
            4,
        ),
    )?;
    evidence
        .record(
            GateEvent::ForeignRejected,
            foreign.grant.endpoint_id,
            foreign.grant.endpoint_generation,
            job_id,
        )
        .map_err(InitError::Wyr1BEvidence)?;
    close_launch_client(system, waits, jobs, foreign)?;

    let orphan = launch_launch_client(system, loader, waits, authority, bootfs, topology, jobs, 5)?;
    let (_, orphan_session) = jobs.next_session().ok_or(InitError::Accounting)?;
    let orphan_config = launch_gate_record(
        GateMessageType::ConfigureLaunchOwner,
        gate,
        orphan.grant,
        0,
        0,
        5,
    );
    send_gate(system, orphan.loaded.launch_channel, orphan_config)?;
    let orphan_job = receive_and_accept_job(
        system,
        loader,
        waits,
        authority,
        &policy,
        jobs,
        orphan_session,
        orphan.grant,
    )?;
    expect_launch_report(
        system,
        orphan,
        launch_gate_record(
            GateMessageType::OrphanDisconnecting,
            gate,
            orphan.grant,
            orphan_job.job_id,
            orphan.grant.endpoint_generation,
            5,
        ),
    )?;
    close_launch_client(system, waits, jobs, orphan)?;
    let orphan_result = reap_job(system, waits, jobs, orphan_job)?;
    if orphan_result.cleanup_result != 0 {
        return Err(InitError::Cleanup);
    }
    evidence
        .record(
            GateEvent::OrphanReaped,
            orphan_job.job_id,
            orphan.grant.endpoint_generation,
            orphan.grant.endpoint_id,
        )
        .map_err(InitError::Wyr1BEvidence)?;
    jobs.jobs.reclaim_closed_sessions();
    if jobs.session_count() != 0 || jobs.jobs.live_jobs() != 0 || jobs.jobs.orphan_jobs() != 0 {
        return Err(InitError::Accounting);
    }
    evidence.finish().map_err(InitError::Wyr1BEvidence)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_registry_gate<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootfs: &[u8],
    registry: RegistryNativeAttempt,
    topology: &mut RegistryTopology,
    gate: GateConfig,
    jobs: &mut JobDispatcher,
) -> Result<EvidenceLog, GateRunError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let mut publisher1 = None;
    let mut publisher2 = None;
    let mut client = None;
    let mut install_committed = false;
    let mut evidence = EvidenceLog::new(gate.nonce)
        .map_err(|error| GateRunError::PreInstall(InitError::Wyr1BEvidence(error)))?;
    let outcome: Result<(), InitError> = (|| {
        if registry.active.role != RoleId::Registryd || registry.active.generation == 0 {
            return Err(InitError::Wyr1BGateMismatch);
        }
        evidence
            .record(
                GateEvent::RegistryReady,
                RoleId::Registryd as u64,
                registry.active.generation,
                registry.active.transaction_id,
            )
            .map_err(InitError::Wyr1BEvidence)?;
        macro_rules! launch {
            ($slot:ident, $kind:expr) => {{
                match retry_preinstall_once(|| {
                    launch_peer(
                        system,
                        loader,
                        waits,
                        authority,
                        bootfs,
                        registry.control_channel,
                        topology,
                        $kind,
                    )
                }) {
                    Ok(peer) => {
                        install_committed = true;
                        $slot = Some(peer);
                    }
                    Err(PeerLaunchError::PreInstall(error)) => return Err(error),
                    Err(PeerLaunchError::InstallCommitted(error)) => {
                        install_committed = true;
                        return Err(error);
                    }
                }
            }};
        }

        launch!(publisher1, PeerKind::Publisher { operation: 1 });
        launch!(
            client,
            PeerKind::Client {
                path: CLIENT_PATH,
                role_generation: 1,
                transaction_id: 0x3001,
                client_id: CLIENT_ID,
            }
        );
        let first = publisher1.ok_or(InitError::Accounting)?;
        let client_peer = client.ok_or(InitError::Accounting)?;
        let publisher1_config = configure_publisher(system, gate, first, client_peer, 1)?;
        if first.grant.registry_generation != registry.active.generation {
            return Err(InitError::Wyr1BGateMismatch);
        }
        evidence
            .record(
                GateEvent::PublisherReady,
                first.grant.endpoint_id,
                first.grant.endpoint_generation,
                first.grant.role_generation,
            )
            .map_err(InitError::Wyr1BEvidence)?;
        expect_report(system, first, publisher1_config, GateMessageType::Published)?;
        let client1_config = configure_client(system, gate, client_peer, first, 1)?;
        if client_peer.grant.registry_generation != registry.active.generation {
            return Err(InitError::Wyr1BGateMismatch);
        }
        evidence
            .record(
                GateEvent::ClientReady,
                client_peer.grant.endpoint_id,
                client_peer.grant.endpoint_generation,
                client_peer.grant.role_generation,
            )
            .map_err(InitError::Wyr1BEvidence)?;
        evidence
            .record(
                GateEvent::Published,
                first.grant.endpoint_id,
                first.grant.endpoint_generation,
                first.grant.role_generation,
            )
            .map_err(InitError::Wyr1BEvidence)?;
        expect_report(
            system,
            client_peer,
            client1_config,
            GateMessageType::Connected,
        )?;
        evidence
            .record(
                GateEvent::Connected,
                client_peer.grant.endpoint_id,
                client_peer.grant.endpoint_generation,
                first.grant.endpoint_id,
            )
            .map_err(InitError::Wyr1BEvidence)?;
        let challenge = complete_direct_exchange(
            system,
            first,
            client_peer,
            publisher1_config,
            client1_config,
        )?;
        evidence
            .record(
                GateEvent::DirectExchange,
                client_peer.grant.endpoint_id,
                client_peer.grant.endpoint_generation,
                challenge,
            )
            .map_err(InitError::Wyr1BEvidence)?;

        let retire = gate_record(
            GateMessageType::Retire,
            gate,
            first.grant,
            client_peer.grant,
            1,
        );
        send_gate(system, first.loaded.launch_channel, retire)?;
        expect_report(system, first, retire, GateMessageType::Retired)?;
        evidence
            .record(
                GateEvent::Retired,
                first.grant.endpoint_id,
                first.grant.endpoint_generation,
                first.grant.role_generation,
            )
            .map_err(InitError::Wyr1BEvidence)?;

        launch!(publisher2, PeerKind::Publisher { operation: 2 });
        let second = publisher2.ok_or(InitError::Accounting)?;
        let publisher2_config = configure_publisher(system, gate, second, client_peer, 2)?;
        expect_report(
            system,
            second,
            publisher2_config,
            GateMessageType::Published,
        )?;
        let client2_config = configure_client(system, gate, client_peer, second, 2)?;
        expect_report(
            system,
            client_peer,
            client2_config,
            GateMessageType::Connected,
        )?;
        let _ = complete_direct_exchange(
            system,
            second,
            client_peer,
            publisher2_config,
            client2_config,
        )?;

        let stale = gate_record(
            GateMessageType::ProbeStale,
            gate,
            first.grant,
            second.grant,
            2,
        );
        send_gate(system, first.loaded.launch_channel, stale)?;
        expect_report(system, first, stale, GateMessageType::StaleRejected)?;
        evidence
            .record(
                GateEvent::StaleRejected,
                first.grant.endpoint_id,
                first.grant.endpoint_generation,
                second.grant.endpoint_id,
            )
            .map_err(InitError::Wyr1BEvidence)?;
        send_gate(
            system,
            first.loaded.launch_channel,
            done_record(gate, first, 2),
        )?;
        send_gate(
            system,
            second.loaded.launch_channel,
            done_record(gate, second, 2),
        )?;
        send_gate(
            system,
            client_peer.loaded.launch_channel,
            done_record(gate, client_peer, 2),
        )?;

        let first = publisher1.take().ok_or(InitError::Accounting)?;
        cleanup_loaded(system, waits, first.loaded, first.task_group, false)?;
        let second = publisher2.take().ok_or(InitError::Accounting)?;
        cleanup_loaded(system, waits, second.loaded, second.task_group, false)?;
        let client_peer = client.take().ok_or(InitError::Accounting)?;
        cleanup_loaded(
            system,
            waits,
            client_peer.loaded,
            client_peer.task_group,
            false,
        )?;
        run_job_gate(
            system,
            loader,
            waits,
            authority,
            bootfs,
            topology,
            gate,
            jobs,
            &mut evidence,
        )?;
        Ok(())
    })();
    if let Err(error) = outcome {
        let mut cleanup_failed =
            error == InitError::Cleanup || drain_job_dispatcher(system, waits, jobs).is_err();
        for slot in [&mut publisher2, &mut client, &mut publisher1] {
            if let Some(peer) = slot.take() {
                cleanup_failed |=
                    cleanup_loaded(system, waits, peer.loaded, peer.task_group, true).is_err();
            }
        }
        return Err(classify_gate_run_error(
            install_committed,
            cleanup_failed,
            error,
        ));
    }
    Ok(evidence)
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn run_registry_replacement_gate<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    bootfs: &[u8],
    registry: RegistryNativeAttempt,
    topology: &mut RegistryTopology,
    gate: GateConfig,
    jobs: &mut JobDispatcher,
) -> ReplacementGateOutcome
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    match run_registry_gate(
        system, loader, waits, authority, bootfs, registry, topology, gate, jobs,
    ) {
        Ok(_) => ReplacementGateOutcome::Complete,
        Err(GateRunError::PreInstall(_)) => ReplacementGateOutcome::PreInstall,
        Err(GateRunError::CleanupFailed(_)) => ReplacementGateOutcome::CleanupFailed,
        Err(GateRunError::InstallCommitted {
            error: _,
            cleanup_failed,
        }) => ReplacementGateOutcome::InstallCommitted { cleanup_failed },
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplacementGateOutcome {
    Complete,
    PreInstall,
    CleanupFailed,
    InstallCommitted { cleanup_failed: bool },
}

#[allow(clippy::too_many_arguments)]
fn launch_registry_replacement_with_gate<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    controller: &mut SystemInit,
    authority: LoadAuthority,
    bootfs: &[u8],
    topology: &mut RegistryTopology,
    gate: GateConfig,
    jobs: &mut JobDispatcher,
) -> Result<Option<(RegistryNativeAttempt, bool)>, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    loop {
        let Some(registry) =
            launch_registry_until_ready(system, loader, waits, controller, authority, bootfs)?
        else {
            return Ok(None);
        };
        let registry = restart_topology_or_poison(system, waits, controller, topology, registry)?;
        match run_registry_replacement_gate(
            system, loader, waits, authority, bootfs, registry, topology, gate, jobs,
        ) {
            ReplacementGateOutcome::Complete => return Ok(Some((registry, true))),
            ReplacementGateOutcome::PreInstall => return Ok(Some((registry, false))),
            ReplacementGateOutcome::CleanupFailed => {
                let _ = poison_registry_generation(system, waits, controller, registry, true)?;
                return Ok(None);
            }
            ReplacementGateOutcome::InstallCommitted { cleanup_failed } => {
                if poison_registry_generation(system, waits, controller, registry, cleanup_failed)?
                {
                    return Ok(None);
                }
            }
        }
    }
}

pub(crate) fn control_tick<S, L, W>(
    resident: &mut ResidentSystemInit,
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
    if now_ns < resident.last_tick_ns {
        resident.controller.fatal();
        resident.result = RecoveryResult::Fatal;
        return Err(InitError::WrongActivationOrder);
    }
    resident.last_tick_ns = now_ns;
    let ResidentSystemInit {
        controller,
        authority,
        result,
        active: active_roles,
        wyr1b,
        ..
    } = resident;
    let state = wyr1b.as_mut().ok_or(InitError::WrongActivationOrder)?;
    for active_slot in active_roles.iter_mut() {
        let Some(active) = *active_slot else {
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
        let profile = if active.role == RoleId::Registryd {
            LaunchProfile::BootstrapRegistry
        } else {
            LaunchProfile::EarlyBootStub
        };
        let observed = match waits.wait_many(&poll_items, DwDeadline(now_ns)) {
            Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => continue,
            Err(error) => Err(ObservedSupervisionError::Supervision(
                SupervisionError::Platform(error),
            )),
            Ok(_) => {
                let deadline = now_ns
                    .checked_add(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns)
                    .ok_or(InitError::Accounting)?;
                supervise_ready_child_profile(
                    waits,
                    active.loaded.process,
                    active.loaded.launch_channel,
                    profile,
                    active.transaction_id,
                    DwDeadline(deadline),
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
        match transition {
            AfterReadyTransition::Terminal(disposition) => controller.terminal(
                active.role,
                active.generation,
                active.transaction_id,
                now_ns,
                disposition,
            )?,
            AfterReadyTransition::Failure(failure) => controller.fail(
                active.role,
                active.generation,
                active.transaction_id,
                now_ns,
                failure,
            )?,
        }
        if active.role == RoleId::Devmgr {
            complete_native_cleanup(
                system,
                waits,
                controller,
                active.loaded,
                active.task_group,
                terminate,
                active.role,
                active.generation,
                active.transaction_id,
                now_ns,
            )?;
            *active_slot = None;
            if transition == AfterReadyTransition::Terminal(TerminalDisposition::NormalExit(0)) {
                continue;
            }
            if advance_or_degrade(system, controller, active.role, active.transaction_id)? {
                *result = RecoveryResult::Degraded;
                continue;
            }
            match remap_and_activate_role(
                system,
                loader,
                waits,
                *authority,
                controller,
                active.role,
            )? {
                RoleActivation::Ready(replacement) => *active_slot = Some(replacement),
                RoleActivation::Degraded => *result = RecoveryResult::Degraded,
            }
            continue;
        }

        let cleanup_failed = drain_job_dispatcher(system, waits, &mut state.jobs).is_err()
            | cleanup_loaded(system, waits, active.loaded, active.task_group, terminate).is_err()
            | system.close_handle(state.registry_control).is_err();
        *active_slot = None;
        state.registry_control = DwHandle(0);
        let retired_at = now_ns.checked_add(1).ok_or(InitError::Accounting)?;
        if cleanup_failed {
            controller.cleanup_failed(
                RoleId::Registryd,
                active.generation,
                active.transaction_id,
                retired_at,
            )?;
            *result = RecoveryResult::Degraded;
            continue;
        }
        controller.cleanup_complete(
            RoleId::Registryd,
            active.generation,
            active.transaction_id,
            retired_at,
        )?;
        if advance_registry_or_exhausted(system, controller, active.transaction_id)? {
            *result = RecoveryResult::Degraded;
            continue;
        }
        let size = system
            .query_memory_object_size(authority.bootfs)
            .map_err(InitError::Native)?;
        let plan = MappingPlan::for_bootfs(size).map_err(|error| {
            ordinary_mapping_error(MappingDiagnosticSite::RegistryReplacement, error, size)
        })?;
        let replacement = system
            .with_bootfs_bytes(
                authority.parent_root,
                authority.bootfs,
                plan,
                |system, bootfs| {
                    launch_registry_replacement_with_gate(
                        system,
                        loader,
                        waits,
                        controller,
                        *authority,
                        bootfs,
                        state
                            .topology
                            .as_mut()
                            .ok_or(InitError::WrongActivationOrder)?,
                        state.gate,
                        &mut state.jobs,
                    )
                },
            )
            .map_err(InitError::Native)??;
        if let Some((replacement, gate_complete)) = replacement {
            state.registry_control = replacement.control_channel;
            *active_slot = Some(replacement.active);
            if !gate_complete {
                *result = RecoveryResult::Degraded;
            }
        } else {
            *result = RecoveryResult::Degraded;
        }
    }
    poll_job_dispatcher(system, loader, waits, *authority, &mut state.jobs, now_ns)?;
    if controller.mode() == SystemMode::Degraded {
        *result = RecoveryResult::Degraded;
    }
    Ok(controller.mode())
}

#[cfg(test)]
#[path = "../../consoled/src/stream_transfer.rs"]
mod consoled_stream_transfer;

#[cfg(test)]
mod tests {

    /// F3A.7g. The latch is what turns a shell's exit status into the end of
    /// a session, so each of the three things it insists on is checked
    /// against the case it excludes, not merely against the case it admits.
    #[test]
    fn only_a_console_child_exiting_normally_with_the_shutdown_status_ends_the_session() {
        use wyrmroot_launch_proto::{TerminationClassification, TerminationResult};

        const SHUTDOWN: u32 = 0x5344_0001;

        // The literal, not the constant under test: the shell writes this
        // value from its own side of the wire, and a test written in terms of
        // `SHELL_SESSION_SHUTDOWN_STATUS` would follow the constant if it
        // moved and leave the two halves silently disagreeing.
        assert_eq!(
            wyrmroot_launch_proto::SHELL_SESSION_SHUTDOWN_STATUS,
            SHUTDOWN
        );

        let result = |classification, application_code| TerminationResult {
            classification,
            application_code,
            exception_class: 0,
            exception_detail: 0,
            exception_address: 0,
            cleanup_result: 0,
        };
        let latched = |scope, terminal| {
            let mut state = ShellControllerState::new(7).unwrap();
            observe_session_shutdown_result(scope, Some(&mut state), terminal);
            state.session_shutdown()
        };

        let shutdown = result(TerminationClassification::NormalExit, SHUTDOWN);
        assert!(latched(LaunchSessionScope::ConsoleLauncher, shutdown));

        // A shell's own job exiting with the same number is a user program's
        // exit code, which the shell prints. It is not a request to end the
        // session, and no session it could end is on that channel.
        assert!(!latched(LaunchSessionScope::ShellJobs, shutdown));
        assert!(!latched(LaunchSessionScope::Historical, shutdown));

        // `application_code` is only the application's own word when the
        // application exited normally. Every other classification carries
        // whatever the kernel left in the field.
        for classification in [
            TerminationClassification::Authorized,
            TerminationClassification::UnhandledException,
            TerminationClassification::ResourcePolicy,
            TerminationClassification::TaskGroupTeardown,
        ] {
            assert!(!latched(
                LaunchSessionScope::ConsoleLauncher,
                result(classification, SHUTDOWN)
            ));
        }

        // Neighbouring codes, including the ordinary clean exit that row 12's
        // `exit` produces, leave the session running.
        for code in [0, 1, SHUTDOWN - 1, SHUTDOWN + 1, 0x5344_0000] {
            assert!(!latched(
                LaunchSessionScope::ConsoleLauncher,
                result(TerminationClassification::NormalExit, code)
            ));
        }
    }

    /// F3A.6n. `ErrorCode::Capacity` was unreachable from the case it names,
    /// and `loader-failure` was the answer to a full machine.
    #[test]
    fn a_kernel_exhaustion_is_capacity_and_only_the_loader_is_a_loader_failure() {
        use deepwyrm_syscall::DwStatus;

        // The two kernel exhaustion statuses reach the code that describes
        // them, on both launch paths.
        for status in [DW_STATUS_NO_MEMORY, DW_STATUS_NO_RESOURCES] {
            let error = InitError::Native(NativeError::Status(status));
            assert_eq!(launch_error_code(&error), LaunchErrorCode::Capacity);
            assert_eq!(shell_launch_error_code(&error), LaunchErrorCode::Capacity);
        }

        // Any other native failure is not capacity. An output-contract fault
        // is our own ABI handling, not the machine's limits.
        let other = InitError::Native(NativeError::Status(DwStatus(-5)));
        assert_eq!(launch_error_code(&other), LaunchErrorCode::LoaderFailure);
        let output = InitError::Native(NativeError::Output(
            wyrmroot_runtime::NativeOutputError::InvalidChannelReceive,
        ));
        assert_eq!(launch_error_code(&output), LaunchErrorCode::LoaderFailure);

        // A malformed ELF keeps `loader-failure`, because `tools/e7_vm.py`
        // pins exactly that answer for `run test/wyr1-e/malformed-elf`.
        assert_eq!(
            launch_error_code(&InitError::Loader(
                wyrmroot_loader::process::LoadError::Elf(wyrmroot_loader::elf::ElfError::BadMagic)
            )),
            LaunchErrorCode::LoaderFailure
        );

        // But an exhaustion inside a platform stage of the same load is
        // capacity, which is where this actually bites: the kernel's cause is
        // nested in `LoadError::Platform`, not in a bare `InitError::Native`.
        assert_eq!(
            launch_error_code(&InitError::Loader(
                wyrmroot_loader::process::LoadError::Platform {
                    stage: wyrmroot_loader::process::LoadStage::ChannelCreate,
                    cause: NativeError::Status(DW_STATUS_NO_RESOURCES),
                    rollback_failed: false,
                }
            )),
            LaunchErrorCode::Capacity
        );

        // And the shell path no longer defaults to claiming the loader failed.
        // An unclassified error says the request was refused, which claims
        // nothing about where the fault was.
        assert_eq!(
            shell_launch_error_code(&InitError::WrongActivationOrder),
            LaunchErrorCode::PolicyRejected
        );
        assert_ne!(
            shell_launch_error_code(&InitError::WrongActivationOrder),
            LaunchErrorCode::LoaderFailure
        );

        // The shell job table filling up is still its own code, unchanged:
        // that is what `Capacity` already meant and it must not be confused
        // with the kernel's exhaustion above.
        assert_eq!(
            shell_launch_error_code(&InitError::Wyr1BModel(JobError::Capacity)),
            LaunchErrorCode::Capacity
        );
    }
    extern crate alloc;

    use super::*;
    use crate::wyr1b_job::LaunchSessionScope;
    use alloc::{vec, vec::Vec};
    use deepwyrm_syscall::{DwMemoryProtection, DwStatus, DwWaitResultV1};
    use wyrmroot_bootfs::builder::{Builder as BootfsBuilder, FileMode};
    use wyrmroot_bootfs::launch_policy::{
        LAUNCH_POLICY_PATH, LaunchPolicyEntry, WYRMSH_PATH, WYRMSH_PROFILE_ID,
        encode as encode_launch_policy, encode_wyrmsh as encode_wyrmsh_policy,
    };
    use wyrmroot_loader::process::{ParentMapping, ProcessCreateRequest, ProcessCreateResult};
    use wyrmroot_registry_proto::{
        Message, ProtocolVersion as RegistryProtocolVersion, ServiceListRecord,
        encode_service_list, parse,
    };
    use wyrmroot_registryd::service::{
        ChannelRights as RegistryChannelRights, ProbeSignals as RegistryProbeSignals,
        ReceiveCounts as RegistryReceiveCounts, ReceivedHandle as RegistryReceivedHandle,
        Transport as RegistryTransport, WaitEvent as RegistryWaitEvent,
    };

    const FAILURE: NativeError = NativeError::Status(DwStatus(-1));
    const WYRMSH_CONSOLE_STATUS_LOST: u32 = 0x5745_0104;

    struct MockPlatform {
        sent: [u8; 256],
        sent_len: usize,
        transfer: DwHandleTransferV1,
        fresh_rights: DwRights,
        queried: [DwHandle; 4],
        query_count: usize,
        created_rights: DwRights,
        closed: [DwHandle; 8],
        close_count: usize,
        fail_close: Option<DwHandle>,
        now: Option<u64>,
        terminate_count: usize,
        fail_terminate: bool,
        allow_wait: bool,
        session_poll_timeout: bool,
        task_group: Option<DwHandle>,
        fail_send: bool,
        inbound: [u8; 256],
        inbound_len: usize,
        inbound_handles: [DwReceivedHandleInfoV1; 16],
        inbound_handle_count: usize,
        bootfs: Option<Vec<u8>>,
        session_poll_readable: bool,
        /// Reports the session's peer as gone, for R6C's cancel edge.
        session_poll_peer_closed: bool,
        /// What R6C's parked-launch poll should see, when a test has a parked
        /// launch at all.
        ///
        /// A poll of a parked child is the only wait on this platform that asks
        /// for `EXITED`, so it is distinguishable from the session poll without
        /// the mock having to know which handle is which. `None` means the test
        /// has no opinion and the child poll answers the same way the session
        /// poll does, which is what every test written before R6C expects.
        child_poll_readable: Option<bool>,
        /// The signals the last parked-child poll asked about, for R6D.
        child_poll_signals: Vec<u64>,
        /// Which session Channel the last reply went to, so a test with two
        /// launch clients can say which one was answered.
        last_sent_channel: Option<DwHandle>,
    }

    #[derive(Default)]
    struct ShellPlatform {
        inbound: Vec<(DwHandle, Vec<u8>, Vec<DwReceivedHandleInfoV1>)>,
        inbound_cursor: usize,
        sent: Vec<(DwHandle, Vec<u8>)>,
        moved: Vec<(DwHandle, Vec<u8>, DwHandleTransferV1)>,
        closed: Vec<DwHandle>,
        terminated_task_groups: Vec<DwHandle>,
        next_channel: u64,
        session_readable: bool,
        session_peer_closed: bool,
        fail_move: bool,
        fail_send_on: Option<DwHandle>,
        now: u64,
        fail_now: bool,
        allow_wait_until: bool,
        bootfs: Option<Vec<u8>>,
        #[cfg(feature = "wyr1e-selector33")]
        evidence: Vec<[u8; crate::wyr1e7_evidence::RECORD_BYTES]>,
        #[cfg(feature = "wyr1e-selector33")]
        fail_evidence: bool,
        #[cfg(feature = "wyr1e8-selector33")]
        e8_evidence: Vec<[u8; crate::wyr1e8_evidence::RECORD_BYTES]>,
        #[cfg(feature = "wyr1e8-selector33")]
        now_after_e8_evidence: Option<u64>,
        #[cfg(feature = "wyr1e8-selector33")]
        now_after_send_on: Option<(DwHandle, u64)>,
    }

    impl ShellPlatform {
        fn new() -> Self {
            Self {
                next_channel: 100,
                session_readable: true,
                now: 10,
                ..Self::default()
            }
        }

        fn push(&mut self, channel: DwHandle, bytes: Vec<u8>, handles: &[DwHandle]) {
            self.inbound.push((
                channel,
                bytes,
                handles
                    .iter()
                    .copied()
                    .map(|handle| DwReceivedHandleInfoV1 {
                        handle,
                        object_type: DW_OBJECT_TYPE_CHANNEL,
                        rights: CONTROLLER_CHANNEL_RIGHTS,
                        ..DwReceivedHandleInfoV1::default()
                    })
                    .collect(),
            ));
        }
    }

    impl InitPlatform for ShellPlatform {
        fn query_capability_info(
            &mut self,
            _handle: DwHandle,
        ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
            Ok(CapabilityInfo {
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: CONTROLLER_CHANNEL_RIGHTS,
            })
        }

        fn receive_channel(
            &mut self,
            channel: DwHandle,
            bytes: &mut [u8],
            handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, NativeError> {
            let (expected_channel, source, source_handles) =
                self.inbound.get(self.inbound_cursor).ok_or(FAILURE)?;
            if *expected_channel != channel
                || source.len() > bytes.len()
                || source_handles.len() > handles.len()
            {
                return Err(FAILURE);
            }
            bytes[..source.len()].copy_from_slice(source);
            handles[..source_handles.len()].copy_from_slice(source_handles);
            self.inbound_cursor += 1;
            Ok(ReceiveCounts {
                bytes: source.len(),
                handles: source_handles.len(),
            })
        }

        fn query_memory_object_size(&mut self, _handle: DwHandle) -> Result<u64, NativeError> {
            u64::try_from(self.bootfs.as_ref().ok_or(FAILURE)?.len()).map_err(|_| FAILURE)
        }

        fn with_bootfs_bytes<R>(
            &mut self,
            _root: DwHandle,
            _bootfs: DwHandle,
            _plan: MappingPlan,
            use_bytes: impl for<'a> FnOnce(&mut Self, &'a [u8]) -> R,
        ) -> Result<R, NativeError> {
            let bootfs = self.bootfs.take().ok_or(FAILURE)?;
            let result = use_bytes(self, &bootfs);
            self.bootfs = Some(bootfs);
            Ok(result)
        }

        fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
            if self.fail_send_on == Some(channel) {
                return Err(FAILURE);
            }
            self.sent.push((channel, bytes.to_vec()));
            #[cfg(feature = "wyr1e8-selector33")]
            if let Some((target, now)) = self.now_after_send_on
                && target == channel
            {
                self.now = now;
            }
            Ok(())
        }

        fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
            self.closed.push(handle);
            Ok(())
        }

        fn create_attempt_task_group(
            &mut self,
            _parent: DwHandle,
        ) -> Result<DwHandle, NativeError> {
            Ok(DwHandle(300))
        }

        fn terminate_task_group(&mut self, task_group: DwHandle) -> Result<(), NativeError> {
            self.terminated_task_groups.push(task_group);
            Ok(())
        }

        fn now(&mut self) -> Result<u64, NativeError> {
            if self.fail_now {
                Err(FAILURE)
            } else {
                Ok(self.now)
            }
        }

        fn wait_until(&mut self, deadline_ns: u64) -> Result<(), NativeError> {
            if self.allow_wait_until {
                self.now = deadline_ns;
                Ok(())
            } else {
                Err(FAILURE)
            }
        }
    }

    impl Wyr1BPlatform for ShellPlatform {
        fn channel_create(
            &mut self,
            rights: DwRights,
        ) -> Result<(DwHandle, DwHandle), NativeError> {
            assert_eq!(rights, CONTROLLER_CHANNEL_RIGHTS);
            let first = DwHandle(self.next_channel);
            let second = DwHandle(self.next_channel + 1);
            self.next_channel += 2;
            Ok((first, second))
        }

        fn send_channel_with_handles(
            &mut self,
            channel: DwHandle,
            bytes: &[u8],
            transfers: &[DwHandleTransferV1],
        ) -> Result<(), NativeError> {
            if transfers.len() != 1 {
                return Err(FAILURE);
            }
            if self.fail_move {
                return Err(FAILURE);
            }
            self.moved.push((channel, bytes.to_vec(), transfers[0]));
            Ok(())
        }

        fn wait_many(
            &mut self,
            _items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, NativeError> {
            if self.session_readable {
                Ok(DwWaitResultV1 {
                    index: 0,
                    observed: DW_SIGNAL_READABLE,
                    ..DwWaitResultV1::default()
                })
            } else if self.session_peer_closed {
                Ok(DwWaitResultV1 {
                    index: 0,
                    observed: DW_SIGNAL_PEER_CLOSED,
                    ..DwWaitResultV1::default()
                })
            } else {
                Err(NativeError::Status(DW_STATUS_TIMED_OUT))
            }
        }

        fn materialize_read_only_memory(
            &mut self,
            _root: DwHandle,
            _bytes: &[u8],
            _rights: DwRights,
        ) -> Result<DwHandle, NativeError> {
            Err(FAILURE)
        }

        #[cfg(feature = "wyr1e-selector33")]
        fn submit_wyr1e7_evidence(
            &mut self,
            record: &[u8; crate::wyr1e7_evidence::RECORD_BYTES],
        ) -> Result<(), NativeError> {
            if self.fail_evidence {
                return Err(FAILURE);
            }
            self.evidence.push(*record);
            Ok(())
        }

        #[cfg(feature = "wyr1e8-selector33")]
        fn submit_wyr1e8_evidence(
            &mut self,
            record: &[u8; crate::wyr1e8_evidence::RECORD_BYTES],
        ) -> Result<(), NativeError> {
            self.e8_evidence.push(*record);
            if let Some(now) = self.now_after_e8_evidence {
                self.now = now;
            }
            Ok(())
        }
    }

    struct ShellWaits {
        transaction: u64,
        exited: bool,
        exit_after_running_check: bool,
        query_count: usize,
    }

    impl SupervisionPlatform for ShellWaits {
        type Error = NativeError;

        fn wait_many(
            &mut self,
            _items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, Self::Error> {
            Ok(DwWaitResultV1 {
                index: 0,
                observed: if self.exited {
                    DW_SIGNAL_EXITED
                } else {
                    DW_SIGNAL_READABLE
                },
                ..DwWaitResultV1::default()
            })
        }

        fn receive_channel(
            &mut self,
            _channel: DwHandle,
            bytes: &mut [u8],
            _handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, Self::Error> {
            let size = wyrmroot_loader::launch::encode_ready_for_profile(
                LaunchProfile::Wyrmsh,
                self.transaction,
                bytes,
            )
            .map_err(|_| FAILURE)?;
            Ok(ReceiveCounts {
                bytes: size,
                handles: 0,
            })
        }

        fn query_task_termination(
            &mut self,
            _process: DwHandle,
        ) -> Result<DwTaskTerminationInfoV1, Self::Error> {
            let exited = self.exited || (self.exit_after_running_check && self.query_count != 0);
            self.query_count += 1;
            Ok(DwTaskTerminationInfoV1 {
                state: if exited {
                    DW_TASK_STATE_EXITED
                } else {
                    deepwyrm_syscall::DW_TASK_STATE_RUNNING
                },
                reason: DW_TERMINATION_NORMAL_EXIT,
                ..DwTaskTerminationInfoV1::default()
            })
        }
    }

    impl MockPlatform {
        fn new() -> Self {
            Self {
                sent: [0; 256],
                sent_len: 0,
                transfer: DwHandleTransferV1::default(),
                fresh_rights: CONTROLLER_CHANNEL_RIGHTS,
                queried: [DwHandle(0); 4],
                query_count: 0,
                created_rights: DwRights(0),
                closed: [DwHandle(0); 8],
                close_count: 0,
                fail_close: None,
                now: None,
                terminate_count: 0,
                fail_terminate: false,
                allow_wait: false,
                session_poll_timeout: false,
                task_group: None,
                fail_send: true,
                inbound: [0; 256],
                inbound_len: 0,
                inbound_handles: [DwReceivedHandleInfoV1::default(); 16],
                inbound_handle_count: 0,
                bootfs: None,
                session_poll_readable: false,
                session_poll_peer_closed: false,
                child_poll_readable: None,
                child_poll_signals: Vec::new(),
                last_sent_channel: None,
            }
        }
    }

    struct InitSendLoader {
        next: u64,
        closed: [DwHandle; 32],
        close_count: usize,
        transferred_service: Option<DwHandle>,
        sent_init: Vec<u8>,
        sent_transfers: Vec<DwHandleTransferV1>,
        fail_init: bool,
    }

    impl InitSendLoader {
        const fn new() -> Self {
            Self {
                next: 0x1000,
                closed: [DwHandle(0); 32],
                close_count: 0,
                transferred_service: None,
                sent_init: Vec::new(),
                sent_transfers: Vec::new(),
                fail_init: true,
            }
        }

        fn handle(&mut self) -> DwHandle {
            let handle = DwHandle(self.next);
            self.next += 1;
            handle
        }

        fn close_count(&self, handle: DwHandle) -> usize {
            self.closed[..self.close_count]
                .iter()
                .filter(|closed| **closed == handle)
                .count()
        }
    }

    impl LoaderPlatform for InitSendLoader {
        type Error = NativeError;

        fn channel_create(
            &mut self,
            _rights: DwRights,
        ) -> Result<(DwHandle, DwHandle), Self::Error> {
            Ok((self.handle(), self.handle()))
        }

        fn duplicate(
            &mut self,
            _handle: DwHandle,
            _rights: DwRights,
        ) -> Result<DwHandle, Self::Error> {
            Ok(self.handle())
        }

        fn close(&mut self, handle: DwHandle) -> Result<(), Self::Error> {
            self.closed[self.close_count] = handle;
            self.close_count += 1;
            Ok(())
        }

        fn process_create(
            &mut self,
            _request: ProcessCreateRequest,
        ) -> Result<ProcessCreateResult, Self::Error> {
            Ok(ProcessCreateResult {
                process: self.handle(),
                root: self.handle(),
                child_bootstrap: self.handle(),
            })
        }

        fn memory_create(
            &mut self,
            _bytes: u64,
            _rights: DwRights,
        ) -> Result<DwHandle, Self::Error> {
            Ok(self.handle())
        }

        fn materialize_parent(
            &mut self,
            _parent_root: DwHandle,
            memory: DwHandle,
            object_size: u64,
            _destination_offset: u64,
            _source: &[u8],
        ) -> Result<ParentMapping, Self::Error> {
            Ok(ParentMapping {
                address: 0x6000_0000 + memory.0 * 0x10_0000,
                bytes: object_size,
            })
        }

        fn materialize_parent_with(
            &mut self,
            _parent_root: DwHandle,
            memory: DwHandle,
            object_size: u64,
            _destination_offset: u64,
            destination_size: usize,
            materialize: impl FnOnce(&mut [u8]),
        ) -> Result<ParentMapping, Self::Error> {
            let mut destination = vec![0; destination_size];
            materialize(&mut destination);
            Ok(ParentMapping {
                address: 0x6000_0000 + memory.0 * 0x10_0000,
                bytes: object_size,
            })
        }

        fn unmap_parent(
            &mut self,
            _parent_root: DwHandle,
            _mapping: ParentMapping,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn map_child(
            &mut self,
            _child_root: DwHandle,
            _memory: DwHandle,
            _address: u64,
            _bytes: u64,
            _protection: DwMemoryProtection,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn unmap_child(
            &mut self,
            _child_root: DwHandle,
            _address: u64,
            _bytes: u64,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn thread_create(
            &mut self,
            _process: DwHandle,
            _rights: DwRights,
        ) -> Result<DwHandle, Self::Error> {
            Ok(self.handle())
        }

        fn send_init(
            &mut self,
            _channel: DwHandle,
            bytes: &[u8],
            transfers: &[DwHandleTransferV1],
        ) -> Result<(), Self::Error> {
            self.transferred_service = transfers.last().map(|transfer| transfer.handle);
            self.sent_init = bytes.to_vec();
            self.sent_transfers = transfers.to_vec();
            if self.fail_init { Err(FAILURE) } else { Ok(()) }
        }

        fn thread_start(
            &mut self,
            _thread: DwHandle,
            _entry: u64,
            _stack_pointer: u64,
            _child_bootstrap: DwHandle,
            _startup_abi: u64,
        ) -> Result<(), Self::Error> {
            if self.fail_init {
                panic!("failed INIT must prevent thread start")
            }
            Ok(())
        }

        fn thread_terminate(&mut self, _thread: DwHandle) -> Result<(), Self::Error> {
            Ok(())
        }

        fn process_terminate(&mut self, _process: DwHandle) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn executable() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x2000];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x400000_u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&0x1000_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&0x400000_u64.to_le_bytes());
        bytes[88..96].copy_from_slice(&0x400000_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&16_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&32_u64.to_le_bytes());
        bytes[112..120].copy_from_slice(&4096_u64.to_le_bytes());
        bytes
    }

    fn service_bootfs(path: &str, image: &[u8]) -> Vec<u8> {
        let mut builder = BootfsBuilder::new();
        builder
            .add(path.as_bytes(), image, FileMode::Executable)
            .unwrap();
        builder.build().unwrap()
    }

    fn job_policy_bootfs(image: &[u8]) -> (Vec<u8>, [u8; 32]) {
        let generation = [0x44; 32];
        let mut manifest = [0_u8; 80];
        manifest[48..80].copy_from_slice(&generation);
        let entry = LaunchPolicyEntry {
            path: "bin/hello",
            content_sha256: wyrmroot_runtime::sha256::digest(image),
            startup_abi: 2,
            profile_id: 1,
            allow_no_streams: true,
            allow_three_streams: true,
        };
        let mut policy = [0_u8; 512];
        let policy_size = encode_launch_policy(generation, &[entry], &mut policy).unwrap();
        let mut builder = BootfsBuilder::new();
        builder
            .add(b"bin/hello", image, FileMode::Executable)
            .unwrap();
        builder
            .add(
                LAUNCH_POLICY_PATH.as_bytes(),
                &policy[..policy_size],
                FileMode::ReadOnly,
            )
            .unwrap();
        builder
            .add(MANIFEST_PATH.as_bytes(), &manifest, FileMode::ReadOnly)
            .unwrap();
        (builder.build().unwrap(), generation)
    }

    fn wyrmsh_policy_bootfs(image: &[u8]) -> (Vec<u8>, [u8; 32]) {
        let generation = [0x45; 32];
        let mut manifest = [0_u8; 80];
        manifest[48..80].copy_from_slice(&generation);
        let entry = LaunchPolicyEntry {
            path: WYRMSH_PATH,
            content_sha256: wyrmroot_runtime::sha256::digest(image),
            startup_abi: 2,
            profile_id: WYRMSH_PROFILE_ID,
            allow_no_streams: false,
            allow_three_streams: true,
        };
        let mut policy = [0_u8; 512];
        let policy_size = encode_wyrmsh_policy(generation, &[entry], &mut policy).unwrap();
        let mut builder = BootfsBuilder::new();
        builder
            .add(WYRMSH_PATH.as_bytes(), image, FileMode::Executable)
            .unwrap();
        builder
            .add(
                LAUNCH_POLICY_PATH.as_bytes(),
                &policy[..policy_size],
                FileMode::ReadOnly,
            )
            .unwrap();
        builder
            .add(MANIFEST_PATH.as_bytes(), &manifest, FileMode::ReadOnly)
            .unwrap();
        (builder.build().unwrap(), generation)
    }

    fn shell_request(
        reservation: LaunchReservation,
        child_generation: u64,
    ) -> (Vec<u8>, [DwHandle; 4]) {
        let mut bytes = [0_u8; wyrmroot_launch_proto::SHELL_V1_REQUEST_BYTES];
        let size = wyrmroot_launch_proto::encode_shell_v1_request(
            reservation,
            wyrmroot_launch_proto::ShellV1Request {
                console_generation: 2,
                status_generation: child_generation - 1,
                requested_child_generation: child_generation,
            },
            &mut bytes,
        )
        .unwrap();
        (
            bytes[..size].to_vec(),
            [DwHandle(500), DwHandle(501), DwHandle(502), DwHandle(503)],
        )
    }

    fn empty_service_page(grant: EndpointGrant) -> Vec<u8> {
        let mut bytes = [0_u8; SERVICE_LIST_PREFIX_BYTES];
        let size = encode_service_list(
            RegistryHeader {
                message_type: RegistryMessageType::ServiceList,
                registry_generation: grant.registry_generation,
                endpoint_id: grant.endpoint_id,
                endpoint_generation: grant.endpoint_generation,
                transaction_id: 1,
            },
            0,
            1,
            0,
            &[],
            &mut bytes,
        )
        .unwrap();
        bytes[..size].to_vec()
    }

    fn starting_registry(image: &[u8]) -> SystemInit {
        let mut controller = SystemInit {
            mode: SystemMode::Bootstrap,
            roles: [
                RoleController::new(RoleId::Registryd, wyrmroot_runtime::sha256::digest(image))
                    .unwrap(),
                RoleController::new(RoleId::Devmgr, [2; 32]).unwrap(),
            ],
            degraded_transitions: 0,
            activated: [false; EARLY_ROLE_COUNT],
            accounting: AttemptLedger::new(),
            gate: None,
            evidence: None,
            registry_startup_profile: StartupProfile::BootstrapRegistry,
            devmgr_startup_profile: StartupProfile::EarlyBootStub,
        };
        controller.become_operational().unwrap();
        controller.begin_registry(0, 1, 0x1001).unwrap();
        controller
    }

    impl InitPlatform for MockPlatform {
        fn query_capability_info(
            &mut self,
            handle: DwHandle,
        ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
            self.queried[self.query_count] = handle;
            self.query_count += 1;
            Ok(CapabilityInfo {
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: self.fresh_rights,
            })
        }
        fn receive_channel(
            &mut self,
            _channel: DwHandle,
            bytes: &mut [u8],
            handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, NativeError> {
            if self.inbound_len == 0 {
                return Err(FAILURE);
            }
            if self.inbound_len > bytes.len() || self.inbound_handle_count > handles.len() {
                return Err(FAILURE);
            }
            bytes[..self.inbound_len].copy_from_slice(&self.inbound[..self.inbound_len]);
            handles[..self.inbound_handle_count]
                .copy_from_slice(&self.inbound_handles[..self.inbound_handle_count]);
            let bytes = self.inbound_len;
            let handles = self.inbound_handle_count;
            self.inbound_len = 0;
            self.inbound_handle_count = 0;
            Ok(ReceiveCounts { bytes, handles })
        }
        fn query_memory_object_size(&mut self, _handle: DwHandle) -> Result<u64, NativeError> {
            self.bootfs
                .as_ref()
                .map(|bootfs| bootfs.len() as u64)
                .ok_or(FAILURE)
        }
        fn with_bootfs_bytes<R>(
            &mut self,
            _root: DwHandle,
            _bootfs: DwHandle,
            _plan: MappingPlan,
            use_bytes: impl for<'a> FnOnce(&mut Self, &'a [u8]) -> R,
        ) -> Result<R, NativeError> {
            let bootfs = self.bootfs.take().ok_or(FAILURE)?;
            let result = use_bytes(self, &bootfs);
            self.bootfs = Some(bootfs);
            Ok(result)
        }
        fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
            if self.fail_send {
                return Err(FAILURE);
            }
            self.sent[..bytes.len()].copy_from_slice(bytes);
            self.sent_len = bytes.len();
            self.last_sent_channel = Some(channel);
            Ok(())
        }
        fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
            self.closed[self.close_count] = handle;
            self.close_count += 1;
            if self.fail_close == Some(handle) {
                Err(FAILURE)
            } else {
                Ok(())
            }
        }
        fn create_attempt_task_group(
            &mut self,
            _parent: DwHandle,
        ) -> Result<DwHandle, NativeError> {
            self.task_group.ok_or(FAILURE)
        }
        fn terminate_task_group(&mut self, _task_group: DwHandle) -> Result<(), NativeError> {
            self.terminate_count += 1;
            if self.fail_terminate {
                Err(FAILURE)
            } else {
                Ok(())
            }
        }
        fn now(&mut self) -> Result<u64, NativeError> {
            self.now.ok_or(FAILURE)
        }
        fn wait_until(&mut self, deadline_ns: u64) -> Result<(), NativeError> {
            if self.allow_wait {
                self.now = Some(deadline_ns);
                Ok(())
            } else {
                Err(FAILURE)
            }
        }
    }

    struct TerminalWaits;

    impl SupervisionPlatform for TerminalWaits {
        type Error = NativeError;

        fn wait_many(
            &mut self,
            _items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, Self::Error> {
            Err(FAILURE)
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
                state: DW_TASK_STATE_EXITED,
                reason: DW_TERMINATION_NORMAL_EXIT,
                ..DwTaskTerminationInfoV1::default()
            })
        }
    }

    /// Drives one complete `JobV2` acceptance: the child publishes exact READY
    /// for the reserved transaction and stays running until the caller marks it
    /// exited, exactly like the live post-READY release wait.
    struct AcceptedJobV2Waits {
        transaction_id: u64,
        profile: LaunchProfile,
        exited: bool,
        console_status_lost_process: Option<DwHandle>,
        running_process: Option<DwHandle>,
    }

    impl SupervisionPlatform for AcceptedJobV2Waits {
        type Error = NativeError;

        fn wait_many(
            &mut self,
            _items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, Self::Error> {
            Ok(DwWaitResultV1 {
                index: 0,
                observed: DW_SIGNAL_READABLE,
                ..DwWaitResultV1::default()
            })
        }

        fn receive_channel(
            &mut self,
            _channel: DwHandle,
            bytes: &mut [u8],
            _handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, Self::Error> {
            let size = wyrmroot_loader::launch::encode_ready_for_profile(
                self.profile,
                self.transaction_id,
                bytes,
            )
            .map_err(|_| FAILURE)?;
            Ok(ReceiveCounts {
                bytes: size,
                handles: 0,
            })
        }

        fn query_task_termination(
            &mut self,
            process: DwHandle,
        ) -> Result<DwTaskTerminationInfoV1, Self::Error> {
            let status_lost = self.console_status_lost_process == Some(process);
            let running = self.running_process == Some(process);
            Ok(DwTaskTerminationInfoV1 {
                state: if running {
                    deepwyrm_syscall::DW_TASK_STATE_RUNNING
                } else if self.exited || status_lost {
                    DW_TASK_STATE_EXITED
                } else {
                    deepwyrm_syscall::DW_TASK_STATE_RUNNING
                },
                reason: DW_TERMINATION_NORMAL_EXIT,
                application_code: if status_lost {
                    WYRMSH_CONSOLE_STATUS_LOST
                } else {
                    0
                },
                ..DwTaskTerminationInfoV1::default()
            })
        }
    }

    /// Models the live rapid-close scheduling gap: the controller reaps
    /// immediately after releasing the launch Channel, so the child Process is
    /// still pre-exit and each bounded observation round expires before the
    /// child is scheduled.
    struct ScheduledExitWaits {
        waits: usize,
        exit_after_waits: usize,
    }

    impl SupervisionPlatform for ScheduledExitWaits {
        type Error = NativeError;

        fn wait_many(
            &mut self,
            _items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, Self::Error> {
            self.waits += 1;
            Err(NativeError::Status(DW_STATUS_TIMED_OUT))
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
                state: if self.waits >= self.exit_after_waits {
                    DW_TASK_STATE_EXITED
                } else {
                    deepwyrm_syscall::DW_TASK_STATE_RUNNING
                },
                reason: DW_TERMINATION_NORMAL_EXIT,
                ..DwTaskTerminationInfoV1::default()
            })
        }
    }

    struct WaitFailureThenTerminal {
        query_count: usize,
    }

    impl SupervisionPlatform for WaitFailureThenTerminal {
        type Error = NativeError;

        fn wait_many(
            &mut self,
            _items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, Self::Error> {
            Err(FAILURE)
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
                state: if self.query_count == 1 {
                    deepwyrm_syscall::DW_TASK_STATE_RUNNING
                } else {
                    DW_TASK_STATE_EXITED
                },
                reason: DW_TERMINATION_NORMAL_EXIT,
                ..DwTaskTerminationInfoV1::default()
            })
        }
    }

    impl Wyr1BPlatform for MockPlatform {
        fn channel_create(
            &mut self,
            rights: DwRights,
        ) -> Result<(DwHandle, DwHandle), NativeError> {
            self.created_rights = rights;
            Ok((DwHandle(20), DwHandle(21)))
        }
        fn send_channel_with_handles(
            &mut self,
            _channel: DwHandle,
            bytes: &[u8],
            transfers: &[DwHandleTransferV1],
        ) -> Result<(), NativeError> {
            assert_eq!(transfers.len(), 1);
            self.sent[..bytes.len()].copy_from_slice(bytes);
            self.sent_len = bytes.len();
            self.transfer = transfers[0];
            Ok(())
        }
        fn wait_many(
            &mut self,
            items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, NativeError> {
            let child_poll = items
                .iter()
                .any(|item| item.signals.0 & DW_SIGNAL_EXITED.0 != 0);
            if child_poll {
                self.child_poll_signals = items.iter().map(|item| item.signals.0).collect();
            }
            if let (true, Some(readable)) = (child_poll, self.child_poll_readable) {
                return if readable {
                    Ok(DwWaitResultV1 {
                        index: 0,
                        observed: DW_SIGNAL_READABLE,
                        ..DwWaitResultV1::default()
                    })
                } else {
                    Err(NativeError::Status(DW_STATUS_TIMED_OUT))
                };
            }
            if self.session_poll_peer_closed {
                Ok(DwWaitResultV1 {
                    index: 0,
                    observed: DW_SIGNAL_PEER_CLOSED,
                    ..DwWaitResultV1::default()
                })
            } else if self.session_poll_readable {
                Ok(DwWaitResultV1 {
                    index: 0,
                    observed: DW_SIGNAL_READABLE,
                    ..DwWaitResultV1::default()
                })
            } else if self.session_poll_timeout {
                Err(NativeError::Status(DW_STATUS_TIMED_OUT))
            } else {
                Err(FAILURE)
            }
        }

        fn materialize_read_only_memory(
            &mut self,
            _root: DwHandle,
            _bytes: &[u8],
            _rights: DwRights,
        ) -> Result<DwHandle, NativeError> {
            Ok(DwHandle(0x7fff))
        }
    }

    fn grant(kind: EndpointKind, endpoint_id: u64, role_generation: u64) -> EndpointGrant {
        EndpointGrant {
            registry_generation: 7,
            endpoint_id,
            endpoint_generation: 3,
            role_generation,
            kind,
        }
    }

    fn reservation(transaction_id: u64) -> LaunchReservation {
        LaunchReservation {
            connection_id: 1,
            generation: 3,
            transaction_id,
        }
    }

    #[cfg(feature = "wyr1e-selector33")]
    fn selector33_ready_state(
        platform: &mut ShellPlatform,
        shell_jobs: EndpointGrant,
        outer_job_id: u64,
    ) -> ShellControllerState {
        let mut state = ShellControllerState::new(6).unwrap();
        state.observe_serial_for_e7(11, 12, 13).unwrap();
        state
            .record_e7_shell_ready(
                platform,
                crate::wyr1e7_evidence::ShellTuple {
                    console_generation: 1,
                    status_generation: 2,
                    shell_generation: 3,
                    outer_launch_transaction: 4,
                    outer_job_id,
                    registry_generation: 6,
                    registry_endpoint_id: 7,
                    registry_endpoint_generation: 8,
                    shell_jobs_connection_id: shell_jobs.endpoint_id,
                    shell_jobs_generation: shell_jobs.endpoint_generation,
                },
            )
            .unwrap();
        state
    }

    fn evidence_through_job_accepted(
        gate: GateConfig,
        owner: EndpointGrant,
        job_id: u64,
    ) -> EvidenceLog {
        let publisher1 = grant(EndpointKind::Publication, 10, 1);
        let client = grant(EndpointKind::RegistryClient, 11, 1);
        let publisher2 = grant(EndpointKind::Publication, 12, 2);
        let mut evidence = EvidenceLog::new(gate.nonce).unwrap();
        for (event, subject, generation, value) in [
            (GateEvent::RegistryReady, RoleId::Registryd as u64, 7, 1),
            (
                GateEvent::PublisherReady,
                publisher1.endpoint_id,
                publisher1.endpoint_generation,
                publisher1.role_generation,
            ),
            (
                GateEvent::ClientReady,
                client.endpoint_id,
                client.endpoint_generation,
                client.role_generation,
            ),
            (
                GateEvent::Published,
                publisher1.endpoint_id,
                publisher1.endpoint_generation,
                publisher1.role_generation,
            ),
            (
                GateEvent::Connected,
                client.endpoint_id,
                client.endpoint_generation,
                publisher1.endpoint_id,
            ),
            (
                GateEvent::DirectExchange,
                client.endpoint_id,
                client.endpoint_generation,
                gate.nonce,
            ),
            (
                GateEvent::Retired,
                publisher1.endpoint_id,
                publisher1.endpoint_generation,
                publisher1.role_generation,
            ),
            (
                GateEvent::StaleRejected,
                publisher1.endpoint_id,
                publisher1.endpoint_generation,
                publisher2.endpoint_id,
            ),
            (
                GateEvent::JobAccepted,
                job_id,
                owner.endpoint_generation,
                owner.endpoint_id,
            ),
        ] {
            evidence.record(event, subject, generation, value).unwrap();
        }
        evidence
    }

    fn resident_with_wyr1b_evidence(evidence: EvidenceLog) -> ResidentSystemInit {
        let (controller, _) = ready_registry();
        ResidentSystemInit {
            controller,
            authority: LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            result: RecoveryResult::Recovered,
            active: [None; EARLY_ROLE_COUNT],
            evidence_finalized: false,
            session_complete: false,
            last_tick_ns: 0,
            wyr1b: None,
            wyr1b_evidence: Some(evidence),
            wyr1c: None,
            #[cfg(feature = "wyr1f-closure")]
            wyr1f: crate::wyr1f_closure::ClosureEpisode::new(None),
        }
    }

    #[test]
    fn native_gate_report_failure_exposes_no_partial_evidence() {
        let gate = GateConfig { nonce: 0x27 };
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        let mut evidence = EvidenceLog::new(gate.nonce).unwrap();
        evidence
            .record(GateEvent::RegistryReady, RoleId::Registryd as u64, 7, 1)
            .unwrap();
        let expected = launch_gate_record(
            GateMessageType::JobResult,
            gate,
            owner,
            1,
            owner.endpoint_generation,
            3,
        );
        let mut mismatched = expected;
        mismatched.value = 1;

        assert_eq!(
            expect_gate(mismatched, expected),
            Err(InitError::Wyr1BGateMismatch)
        );
        assert_eq!(evidence.recorded_events(), 1);
        let resident = resident_with_wyr1b_evidence(evidence);
        for index in 0..crate::wyr1b_gate::EVIDENCE_RECORDS {
            assert_eq!(resident.wyr1b_evidence_record(index), None);
        }
    }

    #[test]
    fn native_gate_mock_exposes_only_complete_clean_reap_transcript() {
        let gate = GateConfig { nonce: 0x27 };
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        let mut jobs = JobDispatcher::new();
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();
        let mut platform = MockPlatform::new();
        let mut waits = TerminalWaits;
        let result = reap_job(&mut platform, &mut waits, &mut jobs, loaded).unwrap();
        assert_eq!(result.classification, TerminationClassification::NormalExit);
        assert_eq!(result.application_code, 0);
        assert_eq!(result.cleanup_result, 0);

        let mut evidence = evidence_through_job_accepted(gate, owner, launch.job_id);
        let owner_result = jobs
            .jobs
            .result_for_owner(owner.endpoint_id, owner.endpoint_generation, launch.job_id)
            .unwrap();
        record_owner_job_reap(&mut evidence, owner, launch.job_id, owner_result).unwrap();
        evidence
            .record(
                GateEvent::ForeignRejected,
                launch.job_id,
                owner.endpoint_generation,
                2,
            )
            .unwrap();
        evidence
            .record(
                GateEvent::OrphanReaped,
                launch.job_id + 1,
                owner.endpoint_generation,
                3,
            )
            .unwrap();
        evidence.finish().unwrap();

        let resident = resident_with_wyr1b_evidence(evidence);
        let expected_events = [
            GateEvent::RegistryReady,
            GateEvent::PublisherReady,
            GateEvent::ClientReady,
            GateEvent::Published,
            GateEvent::Connected,
            GateEvent::DirectExchange,
            GateEvent::Retired,
            GateEvent::StaleRejected,
            GateEvent::JobAccepted,
            GateEvent::JobExitZero,
            GateEvent::JobReaped,
            GateEvent::ForeignRejected,
            GateEvent::OrphanReaped,
            GateEvent::Terminal,
        ];
        for (sequence, event) in expected_events.into_iter().enumerate() {
            let record = resident.wyr1b_evidence_record(sequence).unwrap();
            assert_eq!(
                u64::from_str_radix(core::str::from_utf8(&record[25..33]).unwrap(), 16),
                Ok(sequence as u64)
            );
            assert_eq!(
                u64::from_str_radix(core::str::from_utf8(&record[34..36]).unwrap(), 16),
                Ok(event as u64)
            );
        }
        assert_eq!(resident.wyr1b_evidence_record(expected_events.len()), None);
    }

    #[test]
    fn native_gate_cleanup_failure_records_neither_job_terminal_event() {
        let gate = GateConfig { nonce: 0x27 };
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        let mut jobs = JobDispatcher::new();
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();
        let mut platform = MockPlatform::new();
        platform.fail_close = Some(DwHandle(103));
        let mut waits = TerminalWaits;
        let mut evidence = evidence_through_job_accepted(gate, owner, launch.job_id);

        assert_eq!(
            reap_job(&mut platform, &mut waits, &mut jobs, loaded),
            Err(InitError::Cleanup)
        );
        assert_eq!(evidence.recorded_events(), 9);
        assert_eq!(
            resident_with_wyr1b_evidence(evidence).wyr1b_evidence_record(0),
            None
        );

        platform.fail_close = None;
        let retained = jobs.jobs.loaded_job(launch.job_id).unwrap();
        let result = reap_job(&mut platform, &mut waits, &mut jobs, retained).unwrap();
        assert_ne!(result.cleanup_result, 0);
        let owner_result = jobs
            .jobs
            .result_for_owner(owner.endpoint_id, owner.endpoint_generation, launch.job_id)
            .unwrap();
        assert_eq!(
            record_owner_job_reap(&mut evidence, owner, launch.job_id, owner_result),
            Err(InitError::Wyr1BGateMismatch)
        );
        assert_eq!(evidence.recorded_events(), 9);
        let resident = resident_with_wyr1b_evidence(evidence);
        for index in 0..crate::wyr1b_gate::EVIDENCE_RECORDS {
            assert_eq!(resident.wyr1b_evidence_record(index), None);
        }
    }

    #[test]
    fn native_dispatcher_executes_every_nonlaunch_operation_and_rejects_replay() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();

        let query_ticket = jobs.jobs.reserve_request(reservation(2)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(2),
            query_ticket,
            LaunchMessage::Query {
                job_id: launch.job_id,
            },
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::JobState {
                phase: wyrmroot_launch_proto::JobPhase::Running,
                ..
            }
        ));

        let list_ticket = jobs.jobs.reserve_request(reservation(3)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(3),
            list_ticket,
            LaunchMessage::ListJobs,
        )
        .unwrap();
        let listed = parse_launch_message(&platform.sent[..platform.sent_len], 0).unwrap();
        assert!(
            matches!(listed.message, LaunchMessage::JobList(ids) if ids.get(0) == Some(launch.job_id))
        );

        let terminate_ticket = jobs.jobs.reserve_request(reservation(4)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(4),
            terminate_ticket,
            LaunchMessage::Terminate {
                job_id: launch.job_id,
            },
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::TerminationAccepted { job_id } if job_id == launch.job_id
        ));
        assert_eq!(platform.terminate_count, 1);

        let sent_before_wait = platform.sent_len;
        let wait_ticket = jobs.jobs.reserve_request(reservation(5)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(5),
            wait_ticket,
            LaunchMessage::Wait {
                job_id: launch.job_id,
            },
        )
        .unwrap();
        assert_eq!(platform.sent_len, sent_before_wait);
        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();
        reap_job(&mut platform, &mut waits, &mut jobs, loaded).unwrap();
        service_pending_wait(&mut platform, &mut waits, &mut jobs).unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::JobResult { job_id, .. } if job_id == launch.job_id
        ));

        let close_ticket = jobs.jobs.reserve_request(reservation(6)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(6),
            close_ticket,
            LaunchMessage::CloseJob {
                job_id: launch.job_id,
            },
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Closed { job_id } if job_id == launch.job_id
        ));

        let cancel_ticket = jobs.jobs.reserve_request(reservation(7)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(7),
            cancel_ticket,
            LaunchMessage::Cancel {
                target_transaction_id: 1,
            },
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error {
                code: LaunchErrorCode::CancellationUnavailable
            }
        ));
        assert_eq!(
            jobs.jobs.reserve_request(reservation(7)),
            Err(JobError::TransactionReplay)
        );

        let foreign_grant = grant(EndpointKind::LaunchSession, 2, 1);
        jobs.install_session(foreign_grant, DwHandle(91)).unwrap();
        let foreign = LaunchReservation {
            connection_id: 2,
            generation: 3,
            transaction_id: 1,
        };
        let foreign_ticket = jobs.jobs.reserve_request(foreign).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(91),
            foreign_grant,
            foreign,
            foreign_ticket,
            LaunchMessage::Query {
                job_id: launch.job_id,
            },
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error {
                code: LaunchErrorCode::ForeignOrUnknownJob
            }
        ));
    }

    #[test]
    fn production_owner_wait_tick_emits_result_before_gate_report_can_continue() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        platform.now = Some(10);
        platform.session_poll_timeout = true;
        let mut waits = TerminalWaits;
        let mut loader = InitSendLoader::new();
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
        platform.inbound_len = encode_job_message(
            reservation(2),
            LaunchMessageType::Wait,
            launch.job_id,
            &mut platform.inbound,
        )
        .unwrap();

        dispatch_owner_wait_then_poll(
            &mut platform,
            &mut loader,
            &mut waits,
            LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            None,
            &mut jobs,
            DwHandle(90),
            owner,
        )
        .unwrap();

        let response = parse_launch_message(&platform.sent[..platform.sent_len], 0).unwrap();
        assert_eq!(response.reservation, reservation(2));
        assert!(matches!(
            response.message,
            LaunchMessage::JobResult { job_id, .. } if job_id == launch.job_id
        ));
    }

    fn poll_malformed_dispatch_with_emergency_cleanup(
        fail_channel_close: bool,
        attach_owner: bool,
    ) -> (InitError, MockPlatform) {
        let image = executable();
        let (bootfs, _) = job_policy_bootfs(&image);
        let mut platform = MockPlatform::new();
        platform.bootfs = Some(bootfs);
        platform.session_poll_readable = true;
        platform.inbound[0] = 0;
        platform.inbound_len = 1;
        platform.now = Some(1);
        if fail_channel_close {
            platform.fail_close = Some(DwHandle(90));
        }
        let mut loader = InitSendLoader::new();
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        if attach_owner {
            jobs.attach_session_owner(
                owner,
                SessionOwner {
                    process: DwHandle(101),
                    launch_channel: DwHandle(102),
                    task_group: DwHandle(103),
                },
            )
            .unwrap();
        }
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        let result = if attach_owner {
            let mut waits = ScheduledExitWaits {
                waits: 0,
                exit_after_waits: usize::MAX,
            };
            poll_job_dispatcher(
                &mut platform,
                &mut loader,
                &mut waits,
                authority,
                &mut jobs,
                10,
            )
        } else {
            let mut waits = TerminalWaits;
            poll_job_dispatcher(
                &mut platform,
                &mut loader,
                &mut waits,
                authority,
                &mut jobs,
                10,
            )
        };
        assert_eq!(jobs.session_count(), 0);
        assert_eq!(jobs.jobs.live_jobs(), 0);
        (result.unwrap_err(), platform)
    }

    /// Asserts the resident tick status in the builds that encode it this way.
    ///
    /// `resident_tick_failure_application_status` forks on selector 34, which
    /// encodes a tick failure with `test_failure_category`'s 32-value space
    /// instead of the operation/kind pair these constants are written in. The
    /// `InitError` each caller asserts immediately above is selector-
    /// independent and is checked in every build; only the encoding of it is
    /// not, so only the encoding is gated.
    fn assert_tick_status(error: &InitError, expected: u32) {
        #[cfg(not(feature = "r1-selector34"))]
        assert_eq!(resident_tick_failure_application_status(error), expected);
        #[cfg(feature = "r1-selector34")]
        let _ = (error, expected);
    }

    #[test]
    fn dispatch_failure_with_completed_cleanup_reports_the_initiating_error() {
        let (error, platform) = poll_malformed_dispatch_with_emergency_cleanup(false, false);
        assert_eq!(
            error,
            InitError::RecoveryTransition {
                operation: RecoveryOperation::DispatchHistoricalJob as u8,
                initiating_kind: 0x02,
                payload: 0,
                emergency_cleanup: EmergencyCleanup::Attempted {
                    channel_close_failed: false,
                    owner_cleanup_failed: false,
                },
            }
        );
        assert_tick_status(&error, 0xAF18_1802);
        assert_eq!(&platform.closed[..platform.close_count], &[DwHandle(90)]);
        assert_eq!(platform.terminate_count, 0);
    }

    #[test]
    fn dispatch_failure_records_channel_cleanup_failure_separately() {
        let (error, platform) = poll_malformed_dispatch_with_emergency_cleanup(true, false);
        assert_eq!(
            error,
            InitError::RecoveryTransition {
                operation: RecoveryOperation::DispatchHistoricalJob as u8,
                initiating_kind: 0x02,
                payload: 0,
                emergency_cleanup: EmergencyCleanup::Attempted {
                    channel_close_failed: true,
                    owner_cleanup_failed: false,
                },
            }
        );
        assert_tick_status(&error, 0xAF18_1804);
        assert_eq!(&platform.closed[..platform.close_count], &[DwHandle(90)]);
        assert_eq!(platform.terminate_count, 0);
    }

    #[test]
    fn dispatch_failure_records_owner_cleanup_failure_separately() {
        let (error, platform) = poll_malformed_dispatch_with_emergency_cleanup(false, true);
        assert_eq!(
            error,
            InitError::RecoveryTransition {
                operation: RecoveryOperation::DispatchHistoricalJob as u8,
                initiating_kind: 0x02,
                payload: 0,
                emergency_cleanup: EmergencyCleanup::Attempted {
                    channel_close_failed: false,
                    owner_cleanup_failed: true,
                },
            }
        );
        assert_tick_status(&error, 0xAF18_1804);
        assert_eq!(
            &platform.closed[..platform.close_count],
            &[DwHandle(90), DwHandle(102), DwHandle(101), DwHandle(103)]
        );
        assert_eq!(platform.terminate_count, 1);
    }

    #[test]
    fn dispatch_failure_records_both_cleanup_legs_without_a_second_error() {
        let (error, platform) = poll_malformed_dispatch_with_emergency_cleanup(true, true);
        assert_eq!(
            error,
            InitError::RecoveryTransition {
                operation: RecoveryOperation::DispatchHistoricalJob as u8,
                initiating_kind: 0x02,
                payload: 0,
                emergency_cleanup: EmergencyCleanup::Attempted {
                    channel_close_failed: true,
                    owner_cleanup_failed: true,
                },
            }
        );
        assert_tick_status(&error, 0xAF18_1804);
        assert_eq!(
            &platform.closed[..platform.close_count],
            &[DwHandle(90), DwHandle(102), DwHandle(101), DwHandle(103)]
        );
        assert_eq!(platform.terminate_count, 1);
    }

    #[test]
    fn resident_poll_disconnects_but_preserves_received_move_cleanup_failure() {
        let image = executable();
        let (bootfs, _) = job_policy_bootfs(&image);
        let mut platform = MockPlatform::new();
        platform.bootfs = Some(bootfs);
        platform.fail_close = Some(DwHandle(500));
        platform.session_poll_readable = true;
        platform.inbound_len = encode_job_message(
            reservation(1),
            LaunchMessageType::Query,
            7,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_handles[0] = DwReceivedHandleInfoV1 {
            handle: DwHandle(500),
            ..DwReceivedHandleInfoV1::default()
        };
        platform.inbound_handle_count = 1;
        let mut loader = InitSendLoader::new();
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();

        let result = poll_job_dispatcher(
            &mut platform,
            &mut loader,
            &mut waits,
            LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            &mut jobs,
            10,
        );
        // R7B-2: every build reports which half of the emergency cleanup ran
        // and what it did. This used to collapse to a bare `Cleanup` outside
        // the selector, which said a cleanup happened and nothing about what
        // provoked it.
        assert_eq!(
            result,
            Err(InitError::RecoveryTransition {
                operation: RecoveryOperation::DispatchHistoricalJob as u8,
                initiating_kind: 0x04,
                payload: 0,
                emergency_cleanup: EmergencyCleanup::Attempted {
                    channel_close_failed: false,
                    owner_cleanup_failed: false,
                },
            })
        );
        assert_eq!(jobs.session_count(), 0);
        assert_eq!(
            &platform.closed[..platform.close_count],
            &[DwHandle(500), DwHandle(90)]
        );
    }

    #[test]
    fn native_receive_reserves_before_malformed_and_replay_responses() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        let mut waits = TerminalWaits;
        let mut loader = InitSendLoader::new();
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };

        let size = encode_job_message(
            reservation(2),
            LaunchMessageType::Query,
            launch.job_id,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_len = size;
        assert_eq!(
            dispatch_one_job_request(
                &mut platform,
                &mut loader,
                &mut waits,
                authority,
                None,
                &mut jobs,
                DwHandle(90),
                owner,
                LaunchPublication::Immediate,
            ),
            Ok(JobDispatchOutcome::Responded)
        );
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::JobState { job_id, .. } if job_id == launch.job_id
        ));

        let replay = encode_job_message(
            reservation(2),
            LaunchMessageType::Query,
            launch.job_id,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_len = replay;
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            None,
            &mut jobs,
            DwHandle(90),
            owner,
            LaunchPublication::Immediate,
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error {
                code: LaunchErrorCode::TransactionReplay
            }
        ));

        encode_job_message(
            reservation(3),
            LaunchMessageType::Query,
            launch.job_id,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_len = wyrmroot_launch_proto::HEADER_BYTES;
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            None,
            &mut jobs,
            DwHandle(90),
            owner,
            LaunchPublication::Immediate,
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error {
                code: LaunchErrorCode::MalformedRequest
            }
        ));
        assert_eq!(
            jobs.jobs.reserve_request(reservation(3)),
            Err(JobError::TransactionReplay)
        );
    }

    #[test]
    fn rejected_launch_emits_stable_error_keeps_session_and_replays() {
        let image = executable();
        let (bootfs, generation) = job_policy_bootfs(&image);
        let archive = Archive::new(&bootfs).unwrap();
        let policy = PolicyView::from_bootfs(archive, generation).unwrap();
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        platform.task_group = Some(DwHandle(77));
        let mut waits = TerminalWaits;
        let mut loader = InitSendLoader::new();
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        let size = wyrmroot_launch_proto::encode_launch(
            reservation(1),
            "bin/missing",
            &["bin/missing"],
            &[],
            false,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_len = size;
        assert_eq!(
            dispatch_one_job_request(
                &mut platform,
                &mut loader,
                &mut waits,
                authority,
                Some(&policy),
                &mut jobs,
                DwHandle(90),
                owner,
                LaunchPublication::Immediate,
            ),
            Ok(JobDispatchOutcome::Responded)
        );
        let rejected = parse_launch_message(&platform.sent[..platform.sent_len], 0).unwrap();
        assert_eq!(
            rejected.message,
            LaunchMessage::Error {
                code: LaunchErrorCode::PolicyRejected,
            }
        );
        assert_eq!(jobs.session_count(), 1);
        assert_eq!(jobs.jobs.live_jobs(), 0);

        let replay = wyrmroot_launch_proto::encode_launch(
            reservation(1),
            "bin/missing",
            &["bin/missing"],
            &[],
            false,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_len = replay;
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            Some(&policy),
            &mut jobs,
            DwHandle(90),
            owner,
            LaunchPublication::Immediate,
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error {
                code: LaunchErrorCode::TransactionReplay
            }
        ));
        assert_eq!(jobs.session_count(), 1);

        platform.inbound_len = wyrmroot_launch_proto::encode_launch(
            reservation(2),
            "bin/hello",
            &["bin/hello"],
            &[],
            false,
            &mut platform.inbound,
        )
        .unwrap();
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            None,
            &mut jobs,
            DwHandle(90),
            owner,
            LaunchPublication::Immediate,
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error {
                code: LaunchErrorCode::PolicyRejected
            }
        ));
        platform.inbound_len = wyrmroot_launch_proto::encode_launch(
            reservation(2),
            "bin/hello",
            &["bin/hello"],
            &[],
            false,
            &mut platform.inbound,
        )
        .unwrap();
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            Some(&policy),
            &mut jobs,
            DwHandle(90),
            owner,
            LaunchPublication::Immediate,
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error {
                code: LaunchErrorCode::TransactionReplay
            }
        ));
        assert_eq!(jobs.jobs.live_jobs(), 0);
        assert_eq!(jobs.session_count(), 1);
    }

    #[cfg(feature = "wyr1e-selector33")]
    #[test]
    fn selector33_records_only_successfully_sent_actual_shelljobs_replies() {
        let mut platform = ShellPlatform::new();
        let mut loader = InitSendLoader::new();
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        let grant = grant(EndpointKind::LaunchSession, 9, 3);
        let session = DwHandle(90);
        jobs.install_scoped_session(grant, session, LaunchSessionScope::ShellJobs)
            .unwrap();
        let mut topology = RegistryTopology::new(6).unwrap();
        let mut state = ShellControllerState::new(6).unwrap();
        state.observe_serial_for_e7(11, 12, 13).unwrap();
        state
            .record_e7_shell_ready(
                &mut platform,
                crate::wyr1e7_evidence::ShellTuple {
                    console_generation: 1,
                    status_generation: 2,
                    shell_generation: 3,
                    outer_launch_transaction: 4,
                    outer_job_id: 5,
                    registry_generation: 6,
                    registry_endpoint_id: 7,
                    registry_endpoint_generation: 8,
                    shell_jobs_connection_id: grant.endpoint_id,
                    shell_jobs_generation: grant.endpoint_generation,
                },
            )
            .unwrap();
        let reservation = LaunchReservation {
            connection_id: grant.endpoint_id,
            generation: grant.endpoint_generation,
            transaction_id: 20,
        };
        let mut request = [0u8; wyrmroot_launch_proto::HEADER_BYTES];
        let size = wyrmroot_launch_proto::encode_list_jobs(reservation, &mut request).unwrap();
        platform.push(session, request[..size].to_vec(), &[]);
        let mut context = ShellLaunchContext {
            registry_control: DwHandle(70),
            topology: &mut topology,
            state: &mut state,
        };
        dispatch_one_job_request_with_shell(
            &mut platform,
            &mut loader,
            &mut waits,
            LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            None,
            &mut jobs,
            session,
            grant,
            &mut context,
            LaunchPublication::Immediate,
        )
        .unwrap();
        assert_eq!(platform.evidence.len(), 2);
        assert_eq!(
            u32::from_le_bytes(platform.evidence[1][8..12].try_into().unwrap()),
            2
        );
        assert_eq!(
            u32::from_le_bytes(platform.evidence[1][128..132].try_into().unwrap()),
            9
        );
        assert_eq!(
            u32::from_le_bytes(platform.evidence[1][132..136].try_into().unwrap()),
            10
        );

        let failed_reservation = LaunchReservation {
            transaction_id: 21,
            ..reservation
        };
        let failed_size =
            wyrmroot_launch_proto::encode_list_jobs(failed_reservation, &mut request).unwrap();
        platform.push(session, request[..failed_size].to_vec(), &[]);
        platform.fail_send_on = Some(session);
        assert!(
            dispatch_one_job_request_with_shell(
                &mut platform,
                &mut loader,
                &mut waits,
                LoadAuthority {
                    parent_root: DwHandle(1),
                    bootfs: DwHandle(2),
                    task_group: DwHandle(3),
                },
                None,
                &mut jobs,
                session,
                grant,
                &mut context,
                LaunchPublication::Immediate,
            )
            .is_err()
        );
        assert_eq!(platform.evidence.len(), 2);

        platform.fail_send_on = None;
        platform.fail_evidence = true;
        let relay_failure = LaunchReservation {
            transaction_id: 22,
            ..reservation
        };
        let relay_failure_size =
            wyrmroot_launch_proto::encode_list_jobs(relay_failure, &mut request).unwrap();
        platform.push(session, request[..relay_failure_size].to_vec(), &[]);
        assert!(
            dispatch_one_job_request_with_shell(
                &mut platform,
                &mut loader,
                &mut waits,
                LoadAuthority {
                    parent_root: DwHandle(1),
                    bootfs: DwHandle(2),
                    task_group: DwHandle(3),
                },
                None,
                &mut jobs,
                session,
                grant,
                &mut context,
                LaunchPublication::Immediate,
            )
            .is_err()
        );
        assert_eq!(platform.evidence.len(), 2);
    }

    #[cfg(feature = "wyr1e-selector33")]
    #[test]
    fn selector33_launch_observer_uses_the_successfully_sent_reply_buffer() {
        let grant = grant(EndpointKind::LaunchSession, 9, 3);
        let session = DwHandle(90);
        let reservation = LaunchReservation {
            connection_id: grant.endpoint_id,
            generation: grant.endpoint_generation,
            transaction_id: 20,
        };
        let mut request = [0u8; 128];
        let request_size = wyrmroot_launch_proto::encode_launch(
            reservation,
            "bin/hello",
            &["bin/hello"],
            &[],
            false,
            &mut request,
        )
        .unwrap();
        let mut platform = ShellPlatform::new();
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        jobs.install_scoped_session(grant, session, LaunchSessionScope::ShellJobs)
            .unwrap();
        let launch = jobs.jobs.begin_launch(reservation).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();
        let release = jobs
            .jobs
            .release_launch_channel(launch.job_id, 103)
            .unwrap();
        let (_, sent) = publish_launch_accepted(
            &mut platform,
            &mut waits,
            &mut jobs,
            session,
            reservation,
            loaded,
            release,
            #[cfg(feature = "wyr1e8-selector33")]
            false,
        )
        .unwrap();
        assert_eq!(sent.as_bytes(), platform.sent[0].1.as_slice());

        let mut state = ShellControllerState::new(6).unwrap();
        state.observe_serial_for_e7(11, 12, 13).unwrap();
        state
            .record_e7_shell_ready(
                &mut platform,
                crate::wyr1e7_evidence::ShellTuple {
                    console_generation: 1,
                    status_generation: 2,
                    shell_generation: 3,
                    outer_launch_transaction: 4,
                    outer_job_id: 5,
                    registry_generation: 6,
                    registry_endpoint_id: 7,
                    registry_endpoint_generation: 8,
                    shell_jobs_connection_id: grant.endpoint_id,
                    shell_jobs_generation: grant.endpoint_generation,
                },
            )
            .unwrap();
        observe_e7_response(
            &mut platform,
            LaunchSessionScope::ShellJobs,
            Some(&mut state),
            &request[..request_size],
            sent.as_bytes(),
            &[],
            #[cfg(feature = "wyr1e8-selector33")]
            None,
        )
        .unwrap();
        assert_eq!(platform.evidence.len(), 2);

        let failed_reservation = LaunchReservation {
            transaction_id: 21,
            ..reservation
        };
        let failed = jobs.jobs.begin_launch(failed_reservation).unwrap();
        jobs.jobs.commit_launch(failed, 201, 202, 203).unwrap();
        let failed_loaded = jobs.jobs.loaded_job(failed.job_id).unwrap();
        let failed_release = jobs
            .jobs
            .release_launch_channel(failed.job_id, 203)
            .unwrap();
        platform.fail_send_on = Some(session);
        assert!(
            publish_launch_accepted(
                &mut platform,
                &mut waits,
                &mut jobs,
                session,
                failed_reservation,
                failed_loaded,
                failed_release,
                #[cfg(feature = "wyr1e8-selector33")]
                false,
            )
            .is_err()
        );
        assert_eq!(platform.sent.len(), 1);
        assert_eq!(platform.evidence.len(), 2);
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn e8_trigger_acceptance_establishes_one_checked_deadline_before_reply() {
        let grant = grant(EndpointKind::LaunchSession, 9, 3);
        let session = DwHandle(90);
        let reservation = LaunchReservation {
            connection_id: grant.endpoint_id,
            generation: grant.endpoint_generation,
            transaction_id: 20,
        };
        let mut platform = ShellPlatform::new();
        platform.now = 25;
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        jobs.install_scoped_session(grant, session, LaunchSessionScope::ShellJobs)
            .unwrap();
        let launch = jobs.jobs.begin_launch(reservation).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();
        let release = jobs
            .jobs
            .release_launch_channel(launch.job_id, 103)
            .unwrap();
        let mut state = ShellControllerState::new(1).unwrap();
        let trigger = E8TriggerRequest {
            reservation,
            action: E8RecoveryAction::Driver,
        };

        let (_, sent) = publish_launch_accepted(
            &mut platform,
            &mut waits,
            &mut jobs,
            session,
            reservation,
            loaded,
            release,
            Some((&mut state, trigger)),
        )
        .unwrap();
        assert_eq!(
            sent.e8_deadline,
            Some(25 + WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns)
        );
        assert_eq!(platform.sent.len(), 1);
        assert_eq!(state.recovery_deadline(), sent.e8_deadline);
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn e8_trigger_deadline_overflow_fails_before_accepted_reply() {
        let grant = grant(EndpointKind::LaunchSession, 9, 3);
        let session = DwHandle(90);
        let reservation = LaunchReservation {
            connection_id: grant.endpoint_id,
            generation: grant.endpoint_generation,
            transaction_id: 20,
        };
        let mut platform = ShellPlatform::new();
        platform.now = u64::MAX - WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns + 1;
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        jobs.install_scoped_session(grant, session, LaunchSessionScope::ShellJobs)
            .unwrap();
        let launch = jobs.jobs.begin_launch(reservation).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();
        let release = jobs
            .jobs
            .release_launch_channel(launch.job_id, 103)
            .unwrap();
        let mut state = ShellControllerState::new(1).unwrap();
        let trigger = E8TriggerRequest {
            reservation,
            action: E8RecoveryAction::Driver,
        };

        assert_eq!(
            publish_launch_accepted(
                &mut platform,
                &mut waits,
                &mut jobs,
                session,
                reservation,
                loaded,
                release,
                Some((&mut state, trigger)),
            ),
            Err(InitError::Accounting)
        );
        assert!(platform.sent.is_empty());
        assert_eq!(jobs.jobs.live_jobs(), 0);
    }

    #[cfg(feature = "wyr1e-selector33")]
    #[test]
    fn selector33_terminal_follows_pending_wait_reap_and_committed_close() {
        let mut platform = ShellPlatform::new();
        let mut loader = InitSendLoader::new();
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        let grant = grant(EndpointKind::LaunchSession, 30, 31);
        let session = DwHandle(90);
        jobs.install_scoped_session(grant, session, LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        let launched = jobs
            .jobs
            .begin_launch(LaunchReservation {
                connection_id: grant.endpoint_id,
                generation: grant.endpoint_generation,
                transaction_id: 1,
            })
            .unwrap();
        jobs.jobs.commit_launch(launched, 101, 102, 103).unwrap();
        let mut topology = RegistryTopology::new(6).unwrap();
        let mut state = ShellControllerState::new(6).unwrap();
        state.observe_serial_for_e7(11, 12, 13).unwrap();
        state
            .record_e7_shell_ready(
                &mut platform,
                crate::wyr1e7_evidence::ShellTuple {
                    console_generation: 1,
                    status_generation: 2,
                    shell_generation: 3,
                    outer_launch_transaction: 4,
                    outer_job_id: launched.job_id,
                    registry_generation: 6,
                    registry_endpoint_id: 7,
                    registry_endpoint_generation: 8,
                    shell_jobs_connection_id: 9,
                    shell_jobs_generation: 10,
                },
            )
            .unwrap();
        let mut context = ShellLaunchContext {
            registry_control: DwHandle(70),
            topology: &mut topology,
            state: &mut state,
        };
        let wait_reservation = LaunchReservation {
            connection_id: grant.endpoint_id,
            generation: grant.endpoint_generation,
            transaction_id: 40,
        };
        let mut wait_request = [0u8; 56];
        let wait_size = encode_job_message(
            wait_reservation,
            LaunchMessageType::Wait,
            launched.job_id,
            &mut wait_request,
        )
        .unwrap();
        platform.push(session, wait_request[..wait_size].to_vec(), &[]);
        dispatch_one_job_request_with_shell(
            &mut platform,
            &mut loader,
            &mut waits,
            LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            None,
            &mut jobs,
            session,
            grant,
            &mut context,
            LaunchPublication::Immediate,
        )
        .unwrap();
        assert_eq!(platform.evidence.len(), 1);
        assert!(platform.sent.is_empty());

        let loaded = jobs.jobs.loaded_job(launched.job_id).unwrap();
        reap_job(&mut platform, &mut waits, &mut jobs, loaded).unwrap();
        service_pending_wait_inner(
            &mut platform,
            &mut waits,
            &mut jobs,
            Some(&mut *context.state),
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[0].1, 0).unwrap().message,
            LaunchMessage::JobResult { job_id, .. } if job_id == launched.job_id
        ));

        let close_reservation = LaunchReservation {
            transaction_id: 41,
            ..wait_reservation
        };
        let mut close_request = [0u8; 56];
        let close_size = encode_job_message(
            close_reservation,
            LaunchMessageType::CloseJob,
            launched.job_id,
            &mut close_request,
        )
        .unwrap();
        platform.push(session, close_request[..close_size].to_vec(), &[]);
        dispatch_one_job_request_with_shell(
            &mut platform,
            &mut loader,
            &mut waits,
            LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            None,
            &mut jobs,
            session,
            grant,
            &mut context,
            LaunchPublication::Immediate,
        )
        .unwrap();
        assert_eq!(platform.evidence.len(), 3);
        assert_eq!(
            u32::from_le_bytes(platform.evidence[1][8..12].try_into().unwrap()),
            3
        );
        assert_eq!(
            u64::from_le_bytes(platform.evidence[1][112..120].try_into().unwrap()),
            41
        );
        assert_eq!(
            u32::from_le_bytes(platform.evidence[2][8..12].try_into().unwrap()),
            255
        );
        assert_eq!(
            jobs.jobs.result(
                LaunchReservation {
                    connection_id: grant.endpoint_id,
                    generation: grant.endpoint_generation,
                    transaction_id: 42,
                },
                launched.job_id,
            ),
            Err(JobError::UnknownJob)
        );
    }

    #[cfg(feature = "wyr1e-selector33")]
    #[test]
    fn selector33_failed_pending_result_and_close_reply_emit_no_terminal() {
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        let shell_jobs = grant(EndpointKind::LaunchSession, 9, 3);

        {
            let mut platform = ShellPlatform::new();
            let mut loader = InitSendLoader::new();
            let mut waits = TerminalWaits;
            let mut jobs = JobDispatcher::new();
            let grant = grant(EndpointKind::LaunchSession, 30, 31);
            let session = DwHandle(90);
            jobs.install_scoped_session(grant, session, LaunchSessionScope::ConsoleLauncher)
                .unwrap();
            let launch = jobs
                .jobs
                .begin_launch(LaunchReservation {
                    connection_id: grant.endpoint_id,
                    generation: grant.endpoint_generation,
                    transaction_id: 1,
                })
                .unwrap();
            jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
            let mut topology = RegistryTopology::new(6).unwrap();
            let mut state = selector33_ready_state(&mut platform, shell_jobs, launch.job_id);
            let mut context = ShellLaunchContext {
                registry_control: DwHandle(70),
                topology: &mut topology,
                state: &mut state,
            };
            let reservation = LaunchReservation {
                connection_id: grant.endpoint_id,
                generation: grant.endpoint_generation,
                transaction_id: 40,
            };
            let mut request = [0u8; 56];
            let size = encode_job_message(
                reservation,
                LaunchMessageType::Wait,
                launch.job_id,
                &mut request,
            )
            .unwrap();
            platform.push(session, request[..size].to_vec(), &[]);
            dispatch_one_job_request_with_shell(
                &mut platform,
                &mut loader,
                &mut waits,
                authority,
                None,
                &mut jobs,
                session,
                grant,
                &mut context,
                LaunchPublication::Immediate,
            )
            .unwrap();
            let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();
            reap_job(&mut platform, &mut waits, &mut jobs, loaded).unwrap();
            platform.fail_send_on = Some(session);
            assert!(
                service_pending_wait_inner(
                    &mut platform,
                    &mut waits,
                    &mut jobs,
                    Some(&mut *context.state),
                )
                .is_err()
            );
            assert!(platform.sent.is_empty());
            assert_eq!(platform.evidence.len(), 1);
        }

        {
            let mut platform = ShellPlatform::new();
            let mut loader = InitSendLoader::new();
            let mut waits = TerminalWaits;
            let mut jobs = JobDispatcher::new();
            let grant = grant(EndpointKind::LaunchSession, 30, 31);
            let session = DwHandle(90);
            jobs.install_scoped_session(grant, session, LaunchSessionScope::ConsoleLauncher)
                .unwrap();
            let launch = jobs
                .jobs
                .begin_launch(LaunchReservation {
                    connection_id: grant.endpoint_id,
                    generation: grant.endpoint_generation,
                    transaction_id: 1,
                })
                .unwrap();
            jobs.jobs.commit_launch(launch, 201, 202, 203).unwrap();
            let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();
            reap_job(&mut platform, &mut waits, &mut jobs, loaded).unwrap();
            let mut topology = RegistryTopology::new(6).unwrap();
            let mut state = selector33_ready_state(&mut platform, shell_jobs, launch.job_id);
            let mut context = ShellLaunchContext {
                registry_control: DwHandle(70),
                topology: &mut topology,
                state: &mut state,
            };

            for (transaction_id, kind) in [
                (40, LaunchMessageType::Wait),
                (41, LaunchMessageType::CloseJob),
            ] {
                let reservation = LaunchReservation {
                    connection_id: grant.endpoint_id,
                    generation: grant.endpoint_generation,
                    transaction_id,
                };
                let mut request = [0u8; 56];
                let size =
                    encode_job_message(reservation, kind, launch.job_id, &mut request).unwrap();
                platform.push(session, request[..size].to_vec(), &[]);
                if kind == LaunchMessageType::CloseJob {
                    platform.fail_send_on = Some(session);
                }
                let result = dispatch_one_job_request_with_shell(
                    &mut platform,
                    &mut loader,
                    &mut waits,
                    authority,
                    None,
                    &mut jobs,
                    session,
                    grant,
                    &mut context,
                    LaunchPublication::Immediate,
                );
                if kind == LaunchMessageType::Wait {
                    result.unwrap();
                } else {
                    assert!(result.is_err());
                }
            }
            assert_eq!(platform.sent.len(), 1);
            assert!(matches!(
                parse_launch_message(&platform.sent[0].1, 0).unwrap().message,
                LaunchMessage::JobResult { job_id, .. } if job_id == launch.job_id
            ));
            assert_eq!(platform.evidence.len(), 1);
        }
    }

    #[test]
    fn console_shell_v1_admission_cleans_handles_and_stops_at_e3c_boundary() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        let mut waits = TerminalWaits;
        let mut loader = InitSendLoader::new();
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_scoped_session(owner, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        let request = wyrmroot_launch_proto::ShellV1Request {
            console_generation: 2,
            status_generation: 3,
            requested_child_generation: 4,
        };

        platform.inbound_len = wyrmroot_launch_proto::encode_shell_v1_request(
            reservation(1),
            request,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_handle_count = 4;
        for (index, info) in platform.inbound_handles[..4].iter_mut().enumerate() {
            info.handle = DwHandle(41 + index as u64);
        }
        assert_eq!(
            dispatch_one_job_request(
                &mut platform,
                &mut loader,
                &mut waits,
                authority,
                None,
                &mut jobs,
                DwHandle(90),
                owner,
                LaunchPublication::Immediate,
            ),
            Ok(JobDispatchOutcome::Responded)
        );
        assert_eq!(
            platform.closed[..4],
            [DwHandle(44), DwHandle(43), DwHandle(42), DwHandle(41)]
        );
        assert_eq!(
            platform.queried,
            [DwHandle(41), DwHandle(42), DwHandle(43), DwHandle(44)]
        );
        assert_eq!(platform.query_count, 4);
        assert_eq!(
            CONTROLLER_CHANNEL_RIGHTS.0 & deepwyrm_syscall::DW_RIGHT_DUPLICATE.0,
            0
        );
        assert_eq!(
            wyrmroot_launch_proto::parse_shell_v1_reply(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .reply,
            wyrmroot_launch_proto::ShellV1Reply::Error {
                code: LaunchErrorCode::LoaderFailure,
            }
        );
        assert_eq!(jobs.jobs.live_jobs(), 0);

        platform.inbound_len = wyrmroot_launch_proto::encode_shell_v1_request(
            reservation(1),
            request,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_handle_count = 4;
        for (index, info) in platform.inbound_handles[..4].iter_mut().enumerate() {
            info.handle = DwHandle(51 + index as u64);
        }
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            None,
            &mut jobs,
            DwHandle(90),
            owner,
            LaunchPublication::Immediate,
        )
        .unwrap();
        assert_eq!(
            platform.closed[4..8],
            [DwHandle(54), DwHandle(53), DwHandle(52), DwHandle(51)]
        );
        assert_eq!(
            wyrmroot_launch_proto::parse_shell_v1_reply(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .reply,
            wyrmroot_launch_proto::ShellV1Reply::Error {
                code: LaunchErrorCode::TransactionReplay,
            }
        );
    }

    #[test]
    fn e3c_shell_transaction_installs_preflights_loads_and_publishes() {
        let image = executable();
        let (bootfs, generation) = wyrmsh_policy_bootfs(&image);
        let archive = Archive::new(&bootfs).unwrap();
        let policy = PolicyView::from_bootfs(archive, generation).unwrap();
        assert_eq!(
            policy.authorize(WYRMSH_PATH, 3),
            Err(JobError::PolicyMissing)
        );
        assert_eq!(policy.authorize_wyrmsh(), Ok(image.as_slice()));

        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        let reservation = LaunchReservation {
            connection_id: owner.endpoint_id,
            generation: owner.endpoint_generation,
            transaction_id: 11,
        };
        let (request, handles) = shell_request(reservation, 4);
        let registry_grant = EndpointGrant {
            registry_generation: 7,
            endpoint_id: 1,
            endpoint_generation: 1,
            role_generation: 4,
            kind: EndpointKind::RegistryClient,
        };
        let mut platform = ShellPlatform::new();
        platform.push(DwHandle(90), request, &handles);
        platform.push(DwHandle(101), empty_service_page(registry_grant), &[]);
        let mut loader = InitSendLoader::new();
        loader.fail_init = false;
        let mut waits = ShellWaits {
            transaction: WYRMSH_FIRST_INSTALL_TRANSACTION,
            exited: false,
            exit_after_running_check: false,
            query_count: 0,
        };
        let mut jobs = JobDispatcher::new();
        jobs.install_scoped_session(owner, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        let mut topology = RegistryTopology::new(7).unwrap();
        let mut state = ShellControllerState::new(7).unwrap();
        let mut context = ShellLaunchContext {
            registry_control: DwHandle(70),
            topology: &mut topology,
            state: &mut state,
        };

        let outcome = dispatch_one_job_request_with_shell(
            &mut platform,
            &mut loader,
            &mut waits,
            LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            Some(&policy),
            &mut jobs,
            DwHandle(90),
            owner,
            &mut context,
            LaunchPublication::Immediate,
        )
        .unwrap();
        let JobDispatchOutcome::Launched(loaded) = outcome else {
            panic!("E3C shell must reach publication")
        };
        assert_eq!(loaded.job_id, 1);
        assert_eq!(jobs.session_count(), 2);
        assert_eq!(
            state.health(),
            ShellRegistryHealth::Healthy { generation: 7 }
        );

        assert_eq!(platform.moved.len(), 1);
        let (control, install, transfer) = &platform.moved[0];
        assert_eq!(*control, DwHandle(70));
        assert_eq!(transfer.handle, DwHandle(100));
        assert_eq!(transfer.operation, DW_HANDLE_TRANSFER_MOVE);
        let installed = parse(install, 1).unwrap();
        assert_eq!(
            installed.header.transaction_id,
            WYRMSH_FIRST_INSTALL_TRANSACTION
        );
        assert!(matches!(
            installed.message,
            RegistryMessage::InstallClient(InstallClient {
                endpoint_id: 1,
                endpoint_generation: 1,
                client_id: WYRMSH_FIRST_INSTALL_TRANSACTION,
                client_generation: 4,
                scope: EnumerationScope::BootstrapMetadata,
            })
        ));
        let enumerate = platform
            .sent
            .iter()
            .find(|(channel, _)| *channel == DwHandle(101))
            .unwrap();
        assert!(matches!(
            parse(&enumerate.1, 0).unwrap().message,
            RegistryMessage::Enumerate
        ));
        let accepted = platform
            .sent
            .iter()
            .find(|(channel, _)| *channel == DwHandle(90))
            .unwrap();
        assert!(matches!(
            wyrmroot_launch_proto::parse_shell_v1_reply(&accepted.1, 0)
                .unwrap()
                .reply,
            wyrmroot_launch_proto::ShellV1Reply::LaunchAccepted { job_id: 1 }
        ));

        assert_eq!(loader.sent_transfers.len(), 6);
        assert_eq!(
            loader
                .sent_transfers
                .iter()
                .map(|transfer| transfer.handle)
                .collect::<Vec<_>>(),
            [
                DwHandle(500),
                DwHandle(501),
                DwHandle(502),
                DwHandle(503),
                DwHandle(101),
                DwHandle(103),
            ]
        );
        let received: Vec<_> = loader
            .sent_transfers
            .iter()
            .map(|transfer| DwReceivedHandleInfoV1 {
                handle: transfer.handle,
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: transfer.requested_rights,
                ..DwReceivedHandleInfoV1::default()
            })
            .collect();
        let init =
            wyrmroot_loader::launch::parse_wyrmsh_init(&loader.sent_init, &received).unwrap();
        assert_eq!(init.registry_generation, 7);
        assert_eq!(init.registry_endpoint_id, 1);
        assert_eq!(init.launch_connection_id, 2);
        assert_eq!(init.console_generation, 2);
        assert_eq!(init.status_generation, 3);
        assert_eq!(init.child_generation, 4);
        assert_eq!(init.outer_launch_transaction, 11);
        assert_eq!(init.transaction_id, WYRMSH_FIRST_INSTALL_TRANSACTION);

        let first_shell = EndpointGrant {
            registry_generation: 7,
            endpoint_id: 2,
            endpoint_generation: 1,
            role_generation: 4,
            kind: EndpointKind::LaunchSession,
        };
        let orphan_ticket = jobs
            .jobs
            .begin_launch(LaunchReservation {
                connection_id: first_shell.endpoint_id,
                generation: first_shell.endpoint_generation,
                transaction_id: 2,
            })
            .unwrap();
        jobs.jobs
            .commit_launch(orphan_ticket, 801, 802, 803)
            .unwrap();
        platform.session_readable = false;
        waits.exited = true;
        poll_job_dispatcher(
            &mut platform,
            &mut loader,
            &mut waits,
            LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            &mut jobs,
            20,
        )
        .unwrap();
        assert_eq!(jobs.session_count(), 1);
        assert!(!jobs.has_shell_session());
        assert_eq!(jobs.jobs.orphan_jobs(), 1);

        let replacement_reservation = LaunchReservation {
            transaction_id: 12,
            ..reservation
        };
        let (replacement_request, replacement_handles) = shell_request(replacement_reservation, 5);
        let replacement_registry = EndpointGrant {
            registry_generation: 7,
            endpoint_id: 3,
            endpoint_generation: 1,
            role_generation: 5,
            kind: EndpointKind::RegistryClient,
        };
        platform.push(DwHandle(90), replacement_request, &replacement_handles);
        platform.push(DwHandle(105), empty_service_page(replacement_registry), &[]);
        platform.session_readable = true;
        waits.transaction = WYRMSH_FIRST_INSTALL_TRANSACTION + 1;
        waits.exited = false;
        let mut replacement_context = ShellLaunchContext {
            registry_control: DwHandle(70),
            topology: &mut topology,
            state: &mut state,
        };
        let replacement = dispatch_one_job_request_with_shell(
            &mut platform,
            &mut loader,
            &mut waits,
            LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            Some(&policy),
            &mut jobs,
            DwHandle(90),
            owner,
            &mut replacement_context,
            LaunchPublication::Immediate,
        )
        .unwrap();
        assert!(matches!(replacement, JobDispatchOutcome::Launched(_)));
        assert_eq!(jobs.session_count(), 2);
        assert_eq!(jobs.jobs.orphan_jobs(), 1);
        let replacement_init = wyrmroot_loader::launch::parse_wyrmsh_init(
            &loader.sent_init,
            &loader
                .sent_transfers
                .iter()
                .map(|transfer| DwReceivedHandleInfoV1 {
                    handle: transfer.handle,
                    object_type: DW_OBJECT_TYPE_CHANNEL,
                    rights: transfer.requested_rights,
                    ..DwReceivedHandleInfoV1::default()
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(replacement_init.registry_endpoint_id, 3);
        assert_eq!(replacement_init.launch_connection_id, 4);
        assert_eq!(replacement_init.status_generation, 4);
        assert_eq!(replacement_init.child_generation, 5);
        assert_eq!(replacement_init.outer_launch_transaction, 12);
        assert_eq!(
            replacement_init.transaction_id,
            WYRMSH_FIRST_INSTALL_TRANSACTION + 1
        );
        let replacement_install = parse(&platform.moved[1].1, 1).unwrap();
        assert!(matches!(
            replacement_install.message,
            RegistryMessage::InstallClient(InstallClient {
                endpoint_id: 3,
                endpoint_generation: 1,
                client_id,
                client_generation: 5,
                scope: EnumerationScope::BootstrapMetadata,
            }) if client_id == WYRMSH_FIRST_INSTALL_TRANSACTION + 1
        ));
    }

    #[cfg(feature = "wyr1e-shell-controller")]
    #[test]
    fn e3c_controller_feature_runs_the_transport_injected_poll_adapter() {
        let image = executable();
        let (bootfs, _) = wyrmsh_policy_bootfs(&image);
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        let reservation = LaunchReservation {
            connection_id: owner.endpoint_id,
            generation: owner.endpoint_generation,
            transaction_id: 11,
        };
        let (request, handles) = shell_request(reservation, 4);
        let registry_grant = EndpointGrant {
            registry_generation: 7,
            endpoint_id: 1,
            endpoint_generation: 1,
            role_generation: 4,
            kind: EndpointKind::RegistryClient,
        };
        let mut platform = ShellPlatform::new();
        platform.bootfs = Some(bootfs);
        platform.push(DwHandle(90), request, &handles);
        platform.push(DwHandle(101), empty_service_page(registry_grant), &[]);
        let mut loader = InitSendLoader::new();
        loader.fail_init = false;
        let mut waits = ShellWaits {
            transaction: WYRMSH_FIRST_INSTALL_TRANSACTION,
            exited: false,
            exit_after_running_check: false,
            query_count: 0,
        };
        let mut jobs = JobDispatcher::new();
        jobs.install_scoped_session(owner, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        let mut topology = RegistryTopology::new(7).unwrap();
        let mut state = ShellControllerState::new(7).unwrap();
        let mut context = ShellLaunchContext {
            registry_control: DwHandle(70),
            topology: &mut topology,
            state: &mut state,
        };

        poll_job_dispatcher_with_shell(
            &mut platform,
            &mut loader,
            &mut waits,
            LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            &mut jobs,
            10,
            &mut context,
        )
        .unwrap();

        assert_eq!(jobs.jobs.live_jobs(), 1);
        assert_eq!(jobs.session_count(), 2);
        assert_eq!(platform.inbound_cursor, 2);
        assert!(platform.sent.iter().any(|(channel, bytes)| {
            *channel == DwHandle(90)
                && matches!(
                    wyrmroot_launch_proto::parse_shell_v1_reply(bytes, 0)
                        .unwrap()
                        .reply,
                    wyrmroot_launch_proto::ShellV1Reply::LaunchAccepted { job_id: 1 }
                )
        }));
    }

    #[test]
    fn e3c_post_install_preflight_failure_poison_is_finite_and_cleans_custody() {
        let image = executable();
        let (bootfs, generation) = wyrmsh_policy_bootfs(&image);
        let policy = PolicyView::from_bootfs(Archive::new(&bootfs).unwrap(), generation).unwrap();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        let reservation = LaunchReservation {
            connection_id: owner.endpoint_id,
            generation: owner.endpoint_generation,
            transaction_id: 12,
        };
        let (request, handles) = shell_request(reservation, 4);
        let stale = EndpointGrant {
            registry_generation: 7,
            endpoint_id: 9,
            endpoint_generation: 1,
            role_generation: 4,
            kind: EndpointKind::RegistryClient,
        };
        let mut platform = ShellPlatform::new();
        platform.push(DwHandle(90), request, &handles);
        platform.push(DwHandle(101), empty_service_page(stale), &[]);
        let mut loader = InitSendLoader::new();
        let mut waits = ShellWaits {
            transaction: WYRMSH_FIRST_INSTALL_TRANSACTION,
            exited: false,
            exit_after_running_check: false,
            query_count: 0,
        };
        let mut jobs = JobDispatcher::new();
        jobs.install_scoped_session(owner, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        let mut topology = RegistryTopology::new(7).unwrap();
        let mut state = ShellControllerState::new(7).unwrap();
        let mut context = ShellLaunchContext {
            registry_control: DwHandle(70),
            topology: &mut topology,
            state: &mut state,
        };
        assert_eq!(
            dispatch_one_job_request_with_shell(
                &mut platform,
                &mut loader,
                &mut waits,
                LoadAuthority {
                    parent_root: DwHandle(1),
                    bootfs: DwHandle(2),
                    task_group: DwHandle(3),
                },
                Some(&policy),
                &mut jobs,
                DwHandle(90),
                owner,
                &mut context,
                LaunchPublication::Immediate,
            ),
            Ok(JobDispatchOutcome::Responded)
        );
        assert_eq!(
            state.health(),
            ShellRegistryHealth::Poisoned { generation: 7 }
        );
        assert_eq!(jobs.session_count(), 1);
        assert_eq!(jobs.jobs.live_jobs(), 0);
        for handle in [
            DwHandle(101),
            DwHandle(503),
            DwHandle(502),
            DwHandle(501),
            DwHandle(500),
            DwHandle(300),
        ] {
            assert_eq!(
                platform
                    .closed
                    .iter()
                    .filter(|closed| **closed == handle)
                    .count(),
                1,
                "handle {handle:?}"
            );
        }
        assert!(!platform.closed.contains(&DwHandle(100)));
        assert_eq!(
            state.install_replacement(&mut topology, 7),
            Err(InitError::Accounting)
        );
        state.install_replacement(&mut topology, 8).unwrap();
        assert_eq!(
            state.health(),
            ShellRegistryHealth::Healthy { generation: 8 }
        );
        assert_eq!(topology.generation(), 8);
    }

    #[test]
    fn e3c_registry_install_move_failure_is_precommit_and_keeps_registry_healthy() {
        let image = executable();
        let (bootfs, generation) = wyrmsh_policy_bootfs(&image);
        let policy = PolicyView::from_bootfs(Archive::new(&bootfs).unwrap(), generation).unwrap();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        let reservation = LaunchReservation {
            connection_id: owner.endpoint_id,
            generation: owner.endpoint_generation,
            transaction_id: 13,
        };
        let (request, handles) = shell_request(reservation, 4);
        let mut platform = ShellPlatform::new();
        platform.fail_move = true;
        platform.push(DwHandle(90), request, &handles);
        let mut loader = InitSendLoader::new();
        let mut waits = ShellWaits {
            transaction: WYRMSH_FIRST_INSTALL_TRANSACTION,
            exited: false,
            exit_after_running_check: false,
            query_count: 0,
        };
        let mut jobs = JobDispatcher::new();
        jobs.install_scoped_session(owner, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        let mut topology = RegistryTopology::new(7).unwrap();
        let mut state = ShellControllerState::new(7).unwrap();
        let mut context = ShellLaunchContext {
            registry_control: DwHandle(70),
            topology: &mut topology,
            state: &mut state,
        };

        assert_eq!(
            dispatch_one_job_request_with_shell(
                &mut platform,
                &mut loader,
                &mut waits,
                LoadAuthority {
                    parent_root: DwHandle(1),
                    bootfs: DwHandle(2),
                    task_group: DwHandle(3),
                },
                Some(&policy),
                &mut jobs,
                DwHandle(90),
                owner,
                &mut context,
                LaunchPublication::Immediate,
            ),
            Ok(JobDispatchOutcome::Responded)
        );
        assert_eq!(
            state.health(),
            ShellRegistryHealth::Healthy { generation: 7 }
        );
        assert!(platform.moved.is_empty());
        assert_eq!(jobs.jobs.live_jobs(), 0);
        assert_eq!(jobs.session_count(), 1);
        for handle in [
            DwHandle(101),
            DwHandle(100),
            DwHandle(300),
            DwHandle(503),
            DwHandle(502),
            DwHandle(501),
            DwHandle(500),
        ] {
            assert_eq!(
                platform
                    .closed
                    .iter()
                    .filter(|closed| **closed == handle)
                    .count(),
                1,
                "handle {handle:?}"
            );
        }
        let reply = platform
            .sent
            .iter()
            .find(|(channel, _)| *channel == DwHandle(90))
            .unwrap();
        assert_eq!(
            wyrmroot_launch_proto::parse_shell_v1_reply(&reply.1, 0)
                .unwrap()
                .reply,
            wyrmroot_launch_proto::ShellV1Reply::Error {
                code: LaunchErrorCode::LoaderFailure,
            }
        );
    }

    #[test]
    fn e3c_post_install_loader_failure_poison_cleans_unpublished_shell() {
        let image = executable();
        let (bootfs, generation) = wyrmsh_policy_bootfs(&image);
        let policy = PolicyView::from_bootfs(Archive::new(&bootfs).unwrap(), generation).unwrap();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        let reservation = LaunchReservation {
            connection_id: owner.endpoint_id,
            generation: owner.endpoint_generation,
            transaction_id: 14,
        };
        let (request, handles) = shell_request(reservation, 4);
        let registry_grant = EndpointGrant {
            registry_generation: 7,
            endpoint_id: 1,
            endpoint_generation: 1,
            role_generation: 4,
            kind: EndpointKind::RegistryClient,
        };
        let mut platform = ShellPlatform::new();
        platform.push(DwHandle(90), request, &handles);
        platform.push(DwHandle(101), empty_service_page(registry_grant), &[]);
        let mut loader = InitSendLoader::new();
        let mut waits = ShellWaits {
            transaction: WYRMSH_FIRST_INSTALL_TRANSACTION,
            exited: false,
            exit_after_running_check: false,
            query_count: 0,
        };
        let mut jobs = JobDispatcher::new();
        jobs.install_scoped_session(owner, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        let mut topology = RegistryTopology::new(7).unwrap();
        let mut state = ShellControllerState::new(7).unwrap();
        let mut context = ShellLaunchContext {
            registry_control: DwHandle(70),
            topology: &mut topology,
            state: &mut state,
        };

        assert_eq!(
            dispatch_one_job_request_with_shell(
                &mut platform,
                &mut loader,
                &mut waits,
                LoadAuthority {
                    parent_root: DwHandle(1),
                    bootfs: DwHandle(2),
                    task_group: DwHandle(3),
                },
                Some(&policy),
                &mut jobs,
                DwHandle(90),
                owner,
                &mut context,
                LaunchPublication::Immediate,
            ),
            Ok(JobDispatchOutcome::Responded)
        );
        assert_eq!(
            state.health(),
            ShellRegistryHealth::Poisoned { generation: 7 }
        );
        assert_eq!(jobs.jobs.live_jobs(), 0);
        assert_eq!(jobs.session_count(), 1);
        assert!(!jobs.has_shell_session());
        let reply = platform
            .sent
            .iter()
            .find(|(channel, _)| *channel == DwHandle(90))
            .unwrap();
        assert_eq!(
            wyrmroot_launch_proto::parse_shell_v1_reply(&reply.1, 0)
                .unwrap()
                .reply,
            wyrmroot_launch_proto::ShellV1Reply::Error {
                code: LaunchErrorCode::LoaderFailure,
            }
        );
    }

    #[test]
    fn e3c_wrong_ready_correlation_tears_down_before_publication() {
        let image = executable();
        let (bootfs, generation) = wyrmsh_policy_bootfs(&image);
        let policy = PolicyView::from_bootfs(Archive::new(&bootfs).unwrap(), generation).unwrap();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        let reservation = LaunchReservation {
            connection_id: owner.endpoint_id,
            generation: owner.endpoint_generation,
            transaction_id: 15,
        };
        let (request, handles) = shell_request(reservation, 4);
        let registry_grant = EndpointGrant {
            registry_generation: 7,
            endpoint_id: 1,
            endpoint_generation: 1,
            role_generation: 4,
            kind: EndpointKind::RegistryClient,
        };
        let mut platform = ShellPlatform::new();
        platform.push(DwHandle(90), request, &handles);
        platform.push(DwHandle(101), empty_service_page(registry_grant), &[]);
        let mut loader = InitSendLoader::new();
        loader.fail_init = false;
        let mut waits = ShellWaits {
            transaction: WYRMSH_FIRST_INSTALL_TRANSACTION + 1,
            exited: false,
            exit_after_running_check: true,
            query_count: 0,
        };
        let mut jobs = JobDispatcher::new();
        jobs.install_scoped_session(owner, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        let mut topology = RegistryTopology::new(7).unwrap();
        let mut state = ShellControllerState::new(7).unwrap();
        let mut context = ShellLaunchContext {
            registry_control: DwHandle(70),
            topology: &mut topology,
            state: &mut state,
        };

        assert_eq!(
            dispatch_one_job_request_with_shell(
                &mut platform,
                &mut loader,
                &mut waits,
                LoadAuthority {
                    parent_root: DwHandle(1),
                    bootfs: DwHandle(2),
                    task_group: DwHandle(3),
                },
                Some(&policy),
                &mut jobs,
                DwHandle(90),
                owner,
                &mut context,
                LaunchPublication::Immediate,
            ),
            Ok(JobDispatchOutcome::Responded)
        );
        assert_eq!(
            state.health(),
            ShellRegistryHealth::Poisoned { generation: 7 }
        );
        assert_eq!(jobs.jobs.live_jobs(), 0);
        assert_eq!(jobs.session_count(), 1);
        assert!(!jobs.has_shell_session());
        let reply = platform
            .sent
            .iter()
            .find(|(channel, _)| *channel == DwHandle(90))
            .unwrap();
        assert_eq!(
            wyrmroot_launch_proto::parse_shell_v1_reply(&reply.1, 0)
                .unwrap()
                .reply,
            wyrmroot_launch_proto::ShellV1Reply::Error {
                code: LaunchErrorCode::LoaderFailure,
            }
        );
    }

    #[test]
    fn e3c_accepted_reply_loss_tears_down_shell_and_poisons_registry() {
        let image = executable();
        let (bootfs, generation) = wyrmsh_policy_bootfs(&image);
        let policy = PolicyView::from_bootfs(Archive::new(&bootfs).unwrap(), generation).unwrap();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        let reservation = LaunchReservation {
            connection_id: owner.endpoint_id,
            generation: owner.endpoint_generation,
            transaction_id: 16,
        };
        let (request, handles) = shell_request(reservation, 4);
        let registry_grant = EndpointGrant {
            registry_generation: 7,
            endpoint_id: 1,
            endpoint_generation: 1,
            role_generation: 4,
            kind: EndpointKind::RegistryClient,
        };
        let mut platform = ShellPlatform::new();
        platform.fail_send_on = Some(DwHandle(90));
        platform.push(DwHandle(90), request, &handles);
        platform.push(DwHandle(101), empty_service_page(registry_grant), &[]);
        let mut loader = InitSendLoader::new();
        loader.fail_init = false;
        let mut waits = ShellWaits {
            transaction: WYRMSH_FIRST_INSTALL_TRANSACTION,
            exited: false,
            exit_after_running_check: true,
            query_count: 0,
        };
        let mut jobs = JobDispatcher::new();
        jobs.install_scoped_session(owner, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        let mut topology = RegistryTopology::new(7).unwrap();
        let mut state = ShellControllerState::new(7).unwrap();
        let mut context = ShellLaunchContext {
            registry_control: DwHandle(70),
            topology: &mut topology,
            state: &mut state,
        };

        assert!(matches!(
            dispatch_one_job_request_with_shell(
                &mut platform,
                &mut loader,
                &mut waits,
                LoadAuthority {
                    parent_root: DwHandle(1),
                    bootfs: DwHandle(2),
                    task_group: DwHandle(3),
                },
                Some(&policy),
                &mut jobs,
                DwHandle(90),
                owner,
                &mut context,
                LaunchPublication::Immediate,
            ),
            Err(InitError::Native(_))
        ));
        assert_eq!(
            state.health(),
            ShellRegistryHealth::Poisoned { generation: 7 }
        );
        assert_eq!(jobs.jobs.live_jobs(), 0);
        assert_eq!(jobs.session_count(), 1);
        assert!(!jobs.has_shell_session());
    }

    #[test]
    fn e3c_registry_replacement_ladder_exhausts_after_bounded_attempts() {
        let mut topology = RegistryTopology::new(1).unwrap();
        let mut state = ShellControllerState::new(1).unwrap();
        let mut generation = 1_u64;
        for _ in 0..WYR0_I_SUPERVISION_POLICY.max_attempts {
            state.poison(generation);
            generation += 1;
            state
                .install_replacement(&mut topology, generation)
                .unwrap();
        }
        state.poison(generation);
        assert_eq!(
            state.install_replacement(&mut topology, generation + 1),
            Err(InitError::Cleanup)
        );
        assert_eq!(state.health(), ShellRegistryHealth::Exhausted);
        assert_eq!(topology.generation(), generation);
    }

    #[cfg(feature = "wyr1e-production")]
    #[test]
    fn e6_console_accounting_mismatch_still_closes_every_owned_resource() {
        let grant = grant(EndpointKind::LaunchSession, 1, 1);
        let actual_owner = SessionOwner {
            process: DwHandle(201),
            launch_channel: DwHandle(202),
            task_group: DwHandle(203),
        };
        let mut jobs = JobDispatcher::new();
        jobs.install_scoped_session(grant, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        jobs.attach_session_owner(grant, actual_owner).unwrap();
        let mismatched_peer = InstalledPeer {
            grant,
            loaded: LoadedProcess {
                process: DwHandle(101),
                launch_channel: DwHandle(102),
            },
            task_group: DwHandle(103),
        };
        let mut platform = MockPlatform::new();
        let mut waits = TerminalWaits;

        assert_eq!(
            retire_console_product(&mut platform, &mut waits, &mut jobs, mismatched_peer, false,),
            Err(InitError::Cleanup)
        );
        assert_eq!(jobs.session_count(), 0);
        assert_eq!(
            &platform.closed[..platform.close_count],
            &[
                DwHandle(90),
                actual_owner.launch_channel,
                actual_owner.process,
                actual_owner.task_group,
            ]
        );
    }

    #[cfg(feature = "wyr1e-production")]
    #[test]
    fn e6_console_retirement_orphans_background_jobs_without_draining_them() {
        let console = grant(EndpointKind::LaunchSession, 1, 1);
        let shell_jobs = grant(EndpointKind::LaunchSession, 2, 2);
        let console_owner = SessionOwner {
            process: DwHandle(201),
            launch_channel: DwHandle(202),
            task_group: DwHandle(203),
        };
        let mut jobs = JobDispatcher::new();
        jobs.install_scoped_session(console, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        jobs.attach_session_owner(console, console_owner).unwrap();

        let outer = jobs
            .jobs
            .begin_launch(LaunchReservation {
                connection_id: console.endpoint_id,
                generation: console.endpoint_generation,
                transaction_id: 1,
            })
            .unwrap();
        jobs.jobs.commit_launch(outer, 301, 302, 303).unwrap();
        jobs.install_scoped_session(shell_jobs, DwHandle(91), LaunchSessionScope::ShellJobs)
            .unwrap();
        jobs.attach_outer_job(shell_jobs, outer.job_id).unwrap();
        let background = jobs
            .jobs
            .begin_launch(LaunchReservation {
                connection_id: shell_jobs.endpoint_id,
                generation: shell_jobs.endpoint_generation,
                transaction_id: 1,
            })
            .unwrap();
        jobs.jobs.commit_launch(background, 401, 402, 403).unwrap();

        let mut platform = MockPlatform::new();
        let mut waits = TerminalWaits;
        retire_console_product(
            &mut platform,
            &mut waits,
            &mut jobs,
            InstalledPeer {
                grant: console,
                loaded: LoadedProcess {
                    process: console_owner.process,
                    launch_channel: console_owner.launch_channel,
                },
                task_group: console_owner.task_group,
            },
            true,
        )
        .unwrap();

        assert_eq!(jobs.session_count(), 0);
        assert_eq!(jobs.jobs.live_jobs(), 1);
        assert_eq!(jobs.jobs.orphan_jobs(), 1);
        assert_eq!(
            jobs.jobs.loaded_job(background.job_id).unwrap().loaded,
            LoadedProcess {
                process: DwHandle(401),
                launch_channel: DwHandle(403),
            }
        );
        for retained in [DwHandle(401), DwHandle(402), DwHandle(403)] {
            assert!(!platform.closed[..platform.close_count].contains(&retained));
        }
        for retired in [
            DwHandle(90),
            DwHandle(91),
            console_owner.launch_channel,
            console_owner.process,
            console_owner.task_group,
            DwHandle(301),
            DwHandle(302),
            DwHandle(303),
        ] {
            assert!(platform.closed[..platform.close_count].contains(&retired));
        }
    }

    #[test]
    fn e3c_shell_identity_namespaces_are_independently_fresh() {
        let mut state = ShellControllerState::new(1).unwrap();
        state
            .reserve_shell_generation(wyrmroot_launch_proto::ShellV1Request {
                console_generation: 2,
                status_generation: 3,
                requested_child_generation: 4,
            })
            .unwrap();
        assert_eq!(
            state.reserve_shell_generation(wyrmroot_launch_proto::ShellV1Request {
                console_generation: 3,
                status_generation: 3,
                requested_child_generation: 5,
            }),
            Err(InitError::Wyr1BModel(JobError::StaleGeneration))
        );
        assert_eq!(
            state.reserve_shell_generation(wyrmroot_launch_proto::ShellV1Request {
                console_generation: 3,
                status_generation: 4,
                requested_child_generation: 4,
            }),
            Err(InitError::Wyr1BModel(JobError::StaleGeneration))
        );
        state
            .reserve_shell_generation(wyrmroot_launch_proto::ShellV1Request {
                console_generation: 2,
                status_generation: 4,
                requested_child_generation: 5,
            })
            .unwrap();
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn e8_generation_restart_requires_a_fresh_authenticated_console_owner() {
        let mut state = ShellControllerState::new(1).unwrap();
        let local_first = wyrmroot_launch_proto::ShellV1Request {
            console_generation: 1,
            status_generation: 2,
            requested_child_generation: 3,
        };
        state.set_e8_console_control(DwHandle(10)).unwrap();
        state.reserve_shell_generation(local_first).unwrap();
        assert_eq!(
            state.reserve_shell_generation(local_first),
            Err(InitError::Wyr1BModel(JobError::StaleGeneration))
        );

        let before_stale_owner = state;
        assert_eq!(
            state.set_e8_console_control(DwHandle(11)),
            Err(InitError::WrongActivationOrder)
        );
        assert_eq!(state, before_stale_owner);
        assert_eq!(
            state.clear_e8_console_control(DwHandle(11)),
            Err(InitError::WrongActivationOrder)
        );
        assert_eq!(state, before_stale_owner);

        state.clear_e8_console_control(DwHandle(10)).unwrap();
        state.set_e8_console_control(DwHandle(20)).unwrap();
        state.reserve_shell_generation(local_first).unwrap();
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn shell_registry_clients_stay_fresh_when_console_generations_restart() {
        let mut state = ShellControllerState::new(7).unwrap();
        let mut topology = RegistryTopology::new(7).unwrap();
        let mut platform = ShellPlatform::new();
        let local_first = wyrmroot_launch_proto::ShellV1Request {
            console_generation: 1,
            status_generation: 3,
            requested_child_generation: 2,
        };
        let mut installed = Vec::new();
        for control in [DwHandle(10), DwHandle(20)] {
            state.set_e8_console_control(control).unwrap();
            state.reserve_shell_generation(local_first).unwrap();
            let transaction = state.reserve_install_transaction(7).unwrap();
            let grant = topology
                .issue(
                    local_first.requested_child_generation,
                    EndpointKind::RegistryClient,
                )
                .unwrap();
            let (server, client) = create_controller_channel_pair(&mut platform).unwrap();
            install_wyrmsh_registry_client(&mut platform, DwHandle(70), grant, server, transaction)
                .unwrap();
            let message = parse(&platform.moved.last().unwrap().1, 1).unwrap();
            let RegistryMessage::InstallClient(install) = message.message else {
                panic!("shell must install a registry client")
            };
            assert_eq!(message.header.registry_generation, 7);
            assert_eq!(
                install.client_generation,
                local_first.requested_child_generation
            );
            assert_eq!(install.scope, EnumerationScope::BootstrapMetadata);
            installed.push((message.header.transaction_id, install));
            assert_eq!(
                state.reserve_shell_generation(local_first),
                Err(InitError::Wyr1BModel(JobError::StaleGeneration))
            );
            platform.close_handle(client).unwrap();
            state.clear_e8_console_control(control).unwrap();
        }
        assert_ne!(installed[0].1.endpoint_id, installed[1].1.endpoint_id);
        assert_ne!(installed[0].1.client_id, installed[1].1.client_id);
        for (index, (transaction, install)) in installed.iter().enumerate() {
            assert_eq!(
                *transaction,
                WYRMSH_FIRST_INSTALL_TRANSACTION + index as u64
            );
            assert_eq!(install.client_id, *transaction);
        }
        assert_eq!(
            state.health(),
            ShellRegistryHealth::Healthy { generation: 7 }
        );
    }

    #[test]
    fn shell_registry_install_identity_resets_only_with_a_new_registry() {
        let mut state = ShellControllerState::new(7).unwrap();
        let mut topology = RegistryTopology::new(7).unwrap();
        assert_eq!(
            state.reserve_install_transaction(7),
            Ok(WYRMSH_FIRST_INSTALL_TRANSACTION)
        );
        assert_eq!(
            state.reserve_install_transaction(8),
            Err(InitError::Cleanup)
        );
        assert_eq!(
            state.reserve_install_transaction(7),
            Ok(WYRMSH_FIRST_INSTALL_TRANSACTION + 1)
        );
        state.next_install_transaction = u64::MAX;
        assert_eq!(
            state.reserve_install_transaction(7),
            Err(InitError::Accounting)
        );
        assert_eq!(state.next_install_transaction, u64::MAX);
        state.poison(7);
        assert_eq!(
            state.reserve_install_transaction(7),
            Err(InitError::Cleanup)
        );
        assert_eq!(
            state.install_replacement(&mut topology, 7),
            Err(InitError::Accounting)
        );
        assert_eq!(state.next_install_transaction, u64::MAX);
        state.install_replacement(&mut topology, 8).unwrap();
        assert_eq!(
            state.reserve_install_transaction(7),
            Err(InitError::Cleanup)
        );
        assert_eq!(
            state.reserve_install_transaction(8),
            Ok(WYRMSH_FIRST_INSTALL_TRANSACTION)
        );
    }

    #[cfg(feature = "wyr1e8-selector33")]
    fn e8_state_for_held_wait(launch_transaction: u64) -> ShellControllerState {
        let mut state = ShellControllerState::new(7).unwrap();
        let tuple = crate::wyr1e8_evidence::ShellTuple {
            console_generation: 1,
            status_generation: 2,
            shell_generation: 3,
            outer_launch_transaction: 4,
            outer_job_id: 5,
            registry_generation: 7,
            registry_endpoint_id: 8,
            registry_endpoint_generation: 9,
            shell_jobs_connection_id: 1,
            shell_jobs_generation: 3,
        };
        state
            .e8_evidence
            .observe_serial(crate::wyr1e8_evidence::SerialFacts {
                publication_generation: 10,
                device_role_id: 11,
                driver_attempt_generation: 12,
                driver_control_endpoint_id: 13,
                driver_control_endpoint_generation: 14,
                driver_launch_transaction: 15,
                supervisor_generation: 16,
            })
            .unwrap();
        state
            .e8_evidence
            .stage_shell_tuple(tuple, |_| Ok(()))
            .unwrap();
        state
            .e8_evidence
            .observe_serial_ready(
                crate::wyr1e8_evidence::SerialReady {
                    console_generation: tuple.console_generation,
                    status_generation: tuple.status_generation,
                    shell_generation: tuple.shell_generation,
                    attach_transaction: 17,
                    stream_generation: 18,
                    bundle_generation: 19,
                },
                |_| Ok(()),
            )
            .unwrap();
        state.set_e8_console_control(DwHandle(20)).unwrap();
        state.e8_trigger = Some(E8TriggerIdentity {
            launch_transaction,
            job_id: 12,
            action: E8RecoveryAction::Driver,
        });
        state.recovery_deadline = Some(200);
        state
    }

    #[cfg(feature = "wyr1e8-selector33")]
    fn e8_pending_wait(transaction_id: u64) -> PendingWait {
        let reservation = reservation(transaction_id);
        let mut request = [0_u8; 56];
        let request_len =
            encode_job_message(reservation, LaunchMessageType::Wait, 12, &mut request).unwrap();
        let mut jobs = JobDispatcher::new();
        jobs.install_pending_wait(
            grant(EndpointKind::LaunchSession, 1, 1),
            reservation,
            12,
            &request[..request_len],
        )
        .unwrap();
        jobs.next_pending_wait().unwrap()
    }

    #[cfg(feature = "wyr1e8-selector33")]
    const fn e8_normal_result() -> ControllerJobResult {
        ControllerJobResult {
            classification: TerminationClassification::NormalExit.as_u32(),
            application_code: 0,
            exception_class: 0,
            exception_detail: 0,
            exception_address: 0,
            cleanup_result: 0,
        }
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn completed_trigger_wait_still_enters_the_quiescence_barrier() {
        for action in [E8RecoveryAction::Driver, E8RecoveryAction::Registry] {
            let mut platform = ShellPlatform::new();
            let mut waits = TerminalWaits;
            let mut jobs = JobDispatcher::new();
            let owner = grant(EndpointKind::LaunchSession, 1, 1);
            let session = DwHandle(90);
            jobs.install_scoped_session(owner, session, LaunchSessionScope::ShellJobs)
                .unwrap();
            let launched = jobs.jobs.begin_launch(reservation(40)).unwrap();
            jobs.jobs.commit_launch(launched, 101, 102, 103).unwrap();
            let loaded = jobs.jobs.loaded_job(launched.job_id).unwrap();
            reap_job(&mut platform, &mut waits, &mut jobs, loaded).unwrap();
            let mut state = e8_state_for_held_wait(40);
            let trigger = state.e8_trigger.as_mut().unwrap();
            trigger.job_id = launched.job_id;
            trigger.action = action;
            let deadline = state.recovery_deadline.unwrap();
            let wait = reservation(41);
            let ticket = jobs.jobs.reserve_request(wait).unwrap();
            let mut request = [0u8; 56];
            let size =
                encode_job_message(wait, LaunchMessageType::Wait, launched.job_id, &mut request)
                    .unwrap();
            dispatch_reserved_operation_observed(
                &mut platform,
                &mut waits,
                &mut jobs,
                session,
                owner,
                wait,
                ticket,
                LaunchMessage::Wait {
                    job_id: launched.job_id,
                },
                &request[..size],
                LaunchSessionScope::ShellJobs,
                Some(&mut state),
            )
            .unwrap();
            assert!(
                platform.sent.is_empty(),
                "completed trigger result stays held"
            );
            service_pending_wait_inner(&mut platform, &mut waits, &mut jobs, Some(&mut state))
                .unwrap();
            let held = state.e8_held.unwrap();
            assert_eq!(held.pending.reservation, wait);
            // D1c: the barrier no longer copies these. The deadline is read
            // from the episode that owns it, and the result is the one the
            // admission guard admits -- asserting the copies matched was only
            // ever asserting that copying worked.
            assert_eq!(state.recovery_deadline(), Some(deadline));
            assert_eq!(E8_HELD_WAIT_RESULT, e8_normal_result());
            assert_eq!(platform.sent.len(), 1);
            assert_eq!(platform.sent[0].0, DwHandle(20));
            assert_eq!(
                wyrmroot_consoled::quiesce_control::parse(&platform.sent[0].1),
                Ok(wyrmroot_consoled::quiesce_control::Message::Quiesce(
                    held.identity
                ))
            );
            service_pending_wait_inner(&mut platform, &mut waits, &mut jobs, Some(&mut state))
                .unwrap();
            assert_eq!(
                platform.sent.len(),
                1,
                "held WAIT sends neither reply nor duplicate request"
            );
        }
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn e8_held_wait_requires_the_exact_launch_successor() {
        let mut adjacent = e8_state_for_held_wait(40);
        let mut adjacent_platform = MockPlatform::new();
        adjacent_platform.fail_send = false;
        adjacent_platform.now = Some(100);
        assert_eq!(
            adjacent.hold_e8_wait(
                &mut adjacent_platform,
                e8_pending_wait(41),
                e8_normal_result(),
            ),
            Ok(true)
        );
        assert_eq!(
            wyrmroot_consoled::quiesce_control::parse(
                &adjacent_platform.sent[..adjacent_platform.sent_len]
            ),
            Ok(wyrmroot_consoled::quiesce_control::Message::Quiesce(
                adjacent.e8_held.unwrap().identity
            ))
        );
        assert_eq!(
            adjacent.e8_held.unwrap().identity.trigger_wait_transaction,
            41
        );

        let mut gap = e8_state_for_held_wait(40);
        let mut gap_platform = MockPlatform::new();
        gap_platform.fail_send = false;
        gap_platform.now = Some(100);
        assert_eq!(
            gap.hold_e8_wait(&mut gap_platform, e8_pending_wait(42), e8_normal_result()),
            Err(InitError::Supervision)
        );
        assert_eq!(gap.e8_held, None);
        assert_eq!(gap_platform.sent_len, 0);

        let mut overflow = e8_state_for_held_wait(u64::MAX);
        let mut overflow_platform = MockPlatform::new();
        overflow_platform.fail_send = false;
        overflow_platform.now = Some(100);
        assert_eq!(
            overflow.hold_e8_wait(
                &mut overflow_platform,
                e8_pending_wait(u64::MAX),
                e8_normal_result(),
            ),
            Err(InitError::Accounting)
        );
        assert_eq!(overflow.e8_held, None);
        assert_eq!(overflow_platform.sent_len, 0);
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn e8_quiesce_send_crossing_deadline_keeps_the_held_owner() {
        let mut state = e8_state_for_held_wait(40);
        let mut platform = ShellPlatform::new();
        platform.now = 199;
        platform.now_after_send_on = Some((DwHandle(20), 200));

        assert_eq!(
            state.hold_e8_wait(&mut platform, e8_pending_wait(41), e8_normal_result()),
            Err(InitError::Supervision)
        );
        assert!(state.e8_held.is_some());
        assert_eq!(state.recovery_deadline(), Some(200));
        assert_eq!(platform.sent.len(), 1);
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn e8_action_keeps_its_deadline_across_preheld_held_and_recovery_states() {
        let mut state = e8_state_for_held_wait(40);
        assert_eq!(state.recovery_deadline(), Some(200));
        // The dispatcher admission is asserted at each step below and never
        // changes: R7B-4's D1e retired the held-wait suppression, so parking a
        // WAIT no longer stops the shell-jobs dispatcher. Console relaunch
        // stays suppressed throughout, because that predicate is episode
        // ownership and was deliberately left alone.
        assert!(!state.e8_tuple_waiting_for_serial());
        assert!(!state.routine_console_relaunch_allowed());
        assert!(!state.recovery_deadline_expired(199));
        assert!(state.recovery_deadline_expired(200));
        assert_eq!(
            state.require_recovery_live_at(200),
            Err(InitError::Supervision)
        );
        assert_eq!(state.cap_recovery_deadline(250), 200);

        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        platform.now = Some(199);
        assert_eq!(
            state.hold_e8_wait(&mut platform, e8_pending_wait(41), e8_normal_result()),
            Ok(true)
        );
        let held = state.e8_held.unwrap();
        assert!(!state.e8_tuple_waiting_for_serial());
        assert!(!state.routine_console_relaunch_allowed());
        assert_eq!(state.recovery_deadline(), Some(200));
        assert_eq!(
            state.e8_held_for_action(E8RecoveryAction::Registry),
            Err(InitError::WrongActivationOrder)
        );
        assert_eq!(state.e8_held, Some(held));
        assert_eq!(
            state.accept_e8_quiesced(held.identity, 199),
            Ok(E8RecoveryAction::Driver)
        );
        assert!(!state.e8_tuple_waiting_for_serial());
        assert!(!state.routine_console_relaunch_allowed());
        let taken = state.e8_held_for_action(E8RecoveryAction::Driver).unwrap();
        assert_eq!(state.recovery_deadline(), Some(200));
        state.consume_e8_held(taken);
        assert!(!state.e8_tuple_waiting_for_serial());
        assert!(!state.routine_console_relaunch_allowed());
        assert_eq!(state.recovery_deadline(), Some(200));
        assert_eq!(state.e8_pending_action(), Some(E8RecoveryAction::Driver));

        let mut delayed = e8_state_for_held_wait(40);
        let mut delayed_platform = MockPlatform::new();
        delayed_platform.fail_send = false;
        delayed_platform.now = Some(200);
        assert_eq!(
            delayed.hold_e8_wait(
                &mut delayed_platform,
                e8_pending_wait(41),
                e8_normal_result(),
            ),
            Err(InitError::Supervision)
        );
        assert_eq!(delayed.recovery_deadline(), Some(200));
        assert_eq!(delayed.e8_held, None);
        assert_eq!(delayed_platform.sent_len, 0);
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn e8_ready_evidence_crossing_deadline_retains_the_pending_action() {
        let mut state = e8_state_for_held_wait(40);
        state.close_recovery_episode();
        let mut platform = ShellPlatform::new();

        let wait = reservation(30);
        let mut wait_request = [0u8; 56];
        let wait_request_len =
            encode_job_message(wait, LaunchMessageType::Wait, 5, &mut wait_request).unwrap();
        let mut wait_response = [0u8; 88];
        let wait_response_len = encode_job_result(
            wait,
            5,
            TerminationResult {
                classification: TerminationClassification::NormalExit,
                application_code: 0,
                exception_class: 0,
                exception_detail: 0,
                exception_address: 0,
                cleanup_result: 0,
            },
            &mut wait_response,
        )
        .unwrap();
        state
            .record_e8_outer_response(
                &mut platform,
                &wait_request[..wait_request_len],
                &wait_response[..wait_response_len],
            )
            .unwrap();

        let close = reservation(31);
        let mut close_request = [0u8; 56];
        let close_request_len =
            encode_job_message(close, LaunchMessageType::CloseJob, 5, &mut close_request).unwrap();
        let mut close_response = [0u8; 56];
        let close_response_len =
            encode_job_message(close, LaunchMessageType::Closed, 5, &mut close_response).unwrap();
        state
            .record_e8_outer_response(
                &mut platform,
                &close_request[..close_request_len],
                &close_response[..close_response_len],
            )
            .unwrap();
        assert_eq!(state.e8_stage(), 2);

        let stage_two_tuple = crate::wyr1e8_evidence::ShellTuple {
            console_generation: 1,
            status_generation: 3,
            shell_generation: 4,
            outer_launch_transaction: 6,
            outer_job_id: 7,
            registry_generation: 7,
            registry_endpoint_id: 10,
            registry_endpoint_generation: 11,
            shell_jobs_connection_id: 12,
            shell_jobs_generation: 13,
        };
        state
            .stage_e8_shell_ready(&mut platform, stage_two_tuple)
            .unwrap();
        state
            .observe_e8_serial_ready(
                &mut platform,
                crate::wyr1e8_evidence::SerialReady {
                    console_generation: stage_two_tuple.console_generation,
                    status_generation: stage_two_tuple.status_generation,
                    shell_generation: stage_two_tuple.shell_generation,
                    attach_transaction: 17,
                    stream_generation: 18,
                    bundle_generation: 19,
                },
            )
            .unwrap();
        state.e8_trigger = Some(E8TriggerIdentity {
            launch_transaction: 40,
            job_id: 12,
            action: E8RecoveryAction::Driver,
        });
        state.recovery_deadline = Some(200);
        platform.now = 199;
        state
            .hold_e8_wait(&mut platform, e8_pending_wait(41), e8_normal_result())
            .unwrap();
        let held = state.e8_held.unwrap();
        state.accept_e8_quiesced(held.identity, 199).unwrap();
        let held = state.e8_held_for_action(E8RecoveryAction::Driver).unwrap();

        state
            .record_e8_forced_retired(
                &mut platform,
                held,
                TerminationResult {
                    classification: TerminationClassification::TaskGroupTeardown,
                    application_code: 0,
                    exception_class: 0,
                    exception_detail: 0,
                    exception_address: 0,
                    cleanup_result: 0,
                },
            )
            .unwrap();

        let tuple = crate::wyr1e8_evidence::ShellTuple {
            console_generation: 2,
            status_generation: 4,
            shell_generation: 5,
            outer_launch_transaction: 8,
            outer_job_id: 9,
            registry_generation: 7,
            registry_endpoint_id: 14,
            registry_endpoint_generation: 15,
            shell_jobs_connection_id: 16,
            shell_jobs_generation: 17,
        };
        let fresh_serial = crate::wyr1e8_evidence::SerialFacts {
            publication_generation: 20,
            device_role_id: 11,
            driver_attempt_generation: 21,
            driver_control_endpoint_id: 22,
            driver_control_endpoint_generation: 23,
            driver_launch_transaction: 24,
            supervisor_generation: 16,
        };
        let ready = crate::wyr1e8_evidence::SerialReady {
            console_generation: tuple.console_generation,
            status_generation: tuple.status_generation,
            shell_generation: tuple.shell_generation,
            attach_transaction: 25,
            stream_generation: 26,
            bundle_generation: 19,
        };

        // Even a relation-valid replacement cannot publish READY while the
        // exact held barrier still owns the transition. Rejection also clears
        // the controller's staged tuple and serial facts.
        let evidence_count = platform.e8_evidence.len();
        state.e8_evidence.observe_serial(fresh_serial).unwrap();
        state.stage_e8_shell_ready(&mut platform, tuple).unwrap();
        assert_eq!(
            state.observe_e8_serial_ready(&mut platform, ready),
            Err(InitError::WrongActivationOrder)
        );
        assert_eq!(platform.e8_evidence.len(), evidence_count);
        assert!(!state.e8_tuple_waiting_for_serial());
        assert!(!state.e8_shell_ready());

        state.consume_e8_held(held);
        state.e8_evidence.observe_serial(fresh_serial).unwrap();
        state.stage_e8_shell_ready(&mut platform, tuple).unwrap();
        platform.now_after_e8_evidence = Some(200);
        assert_eq!(
            state.observe_e8_serial_ready(&mut platform, ready),
            Err(InitError::Supervision)
        );
        assert_eq!(state.recovery_deadline(), Some(200));
        assert_eq!(state.e8_pending_action(), Some(E8RecoveryAction::Driver));
        assert_eq!(state.e8_stage(), 3);
        assert!(state.e8_tuple_waiting_for_serial());
        assert!(!state.e8_shell_ready());
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn e8_registry_backoff_stops_at_the_action_deadline_without_replacement() {
        let (mut controller, registry) = ready_registry();
        controller
            .fail(
                RoleId::Registryd,
                registry.active.generation,
                registry.active.transaction_id,
                10,
                AttemptFailure::WaitFailed,
            )
            .unwrap();
        controller
            .cleanup_complete(
                RoleId::Registryd,
                registry.active.generation,
                registry.active.transaction_id,
                11,
            )
            .unwrap();
        let RestartState::Backoff { deadline_ns, .. } =
            controller.role_state(RoleId::Registryd).unwrap()
        else {
            panic!("registry failure must enter backoff")
        };
        let action_deadline = deadline_ns.checked_sub(1).unwrap();
        let mut platform = MockPlatform::new();
        platform.now = Some(action_deadline - 1);
        platform.allow_wait = true;

        assert_eq!(
            advance_registry_or_exhausted_with_cap(
                &mut platform,
                &mut controller,
                registry.active.transaction_id,
                Some(action_deadline),
            ),
            Err(InitError::Supervision)
        );
        assert_eq!(platform.now, Some(action_deadline));
        assert!(matches!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::Backoff { .. })
        ));
    }

    #[test]
    fn e3c_shelljobs_peer_loss_forces_its_correlated_outer_shell() {
        let console = grant(EndpointKind::LaunchSession, 1, 1);
        let shell = EndpointGrant {
            registry_generation: 7,
            endpoint_id: 2,
            endpoint_generation: 1,
            role_generation: 4,
            kind: EndpointKind::LaunchSession,
        };
        let mut jobs = JobDispatcher::new();
        jobs.install_scoped_session(console, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        jobs.install_scoped_session(shell, DwHandle(91), LaunchSessionScope::ShellJobs)
            .unwrap();
        let ticket = jobs
            .jobs
            .begin_launch(LaunchReservation {
                connection_id: console.endpoint_id,
                generation: console.endpoint_generation,
                transaction_id: 1,
            })
            .unwrap();
        jobs.jobs.commit_launch(ticket, 700, 701, 702).unwrap();
        jobs.attach_outer_job(shell, ticket.job_id()).unwrap();
        assert_eq!(jobs.next_session(), Some((console, DwHandle(90))));

        let mut platform = ShellPlatform::new();
        platform.session_readable = false;
        platform.session_peer_closed = true;
        let mut loader = InitSendLoader::new();
        let mut waits = ShellWaits {
            transaction: 1,
            exited: true,
            exit_after_running_check: false,
            query_count: 0,
        };
        poll_job_dispatcher(
            &mut platform,
            &mut loader,
            &mut waits,
            LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            &mut jobs,
            10,
        )
        .unwrap();
        assert_eq!(jobs.session_count(), 1);
        assert_eq!(jobs.jobs.live_jobs(), 0);
        assert!(!jobs.has_shell_session());
        assert_eq!(
            platform
                .closed
                .iter()
                .filter(|handle| **handle == DwHandle(91))
                .count(),
            1
        );
    }

    #[cfg(feature = "wyr1e-shell-controller")]
    #[test]
    fn e3c_console_peer_loss_reports_exact_closed_session_after_owner_cleanup() {
        let console = grant(EndpointKind::LaunchSession, 1, 1);
        let mut jobs = JobDispatcher::new();
        jobs.install_scoped_session(console, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        jobs.attach_session_owner(
            console,
            SessionOwner {
                process: DwHandle(91),
                launch_channel: DwHandle(92),
                task_group: DwHandle(93),
            },
        )
        .unwrap();

        let mut platform = ShellPlatform::new();
        platform.session_readable = false;
        platform.session_peer_closed = true;
        let mut loader = InitSendLoader::new();
        let mut waits = ShellWaits {
            transaction: 1,
            exited: true,
            exit_after_running_check: false,
            query_count: 0,
        };
        let mut topology = RegistryTopology::new(7).unwrap();
        let mut shell_state = ShellControllerState::new(7).unwrap();
        let mut context = ShellLaunchContext {
            registry_control: DwHandle(70),
            topology: &mut topology,
            state: &mut shell_state,
        };

        let outcome = poll_job_dispatcher_with_shell(
            &mut platform,
            &mut loader,
            &mut waits,
            LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            &mut jobs,
            10,
            &mut context,
        )
        .unwrap();

        assert_eq!(
            outcome,
            JobDispatcherPollOutcome::SessionClosed {
                grant: console,
                scope: LaunchSessionScope::ConsoleLauncher,
            }
        );
        assert_eq!(jobs.session_count(), 0);
        for handle in [DwHandle(90), DwHandle(91), DwHandle(92)] {
            assert_eq!(
                platform
                    .closed
                    .iter()
                    .filter(|closed| **closed == handle)
                    .count(),
                1
            );
        }
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn active_recovery_defers_console_peer_loss_to_coordinated_retirement() {
        let console = grant(EndpointKind::LaunchSession, 1, 1);
        let owner = SessionOwner {
            process: DwHandle(91),
            launch_channel: DwHandle(92),
            task_group: DwHandle(93),
        };
        let mut jobs = JobDispatcher::new();
        jobs.install_scoped_session(console, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        jobs.attach_session_owner(console, owner).unwrap();

        let mut platform = ShellPlatform::new();
        platform.session_readable = false;
        platform.session_peer_closed = true;
        let mut loader = InitSendLoader::new();
        let mut waits = ShellWaits {
            transaction: 1,
            exited: true,
            exit_after_running_check: false,
            query_count: 0,
        };
        let mut topology = RegistryTopology::new(7).unwrap();
        let mut shell_state = e8_state_for_held_wait(40);
        let mut context = ShellLaunchContext {
            registry_control: DwHandle(70),
            topology: &mut topology,
            state: &mut shell_state,
        };

        let outcome = poll_job_dispatcher_with_shell(
            &mut platform,
            &mut loader,
            &mut waits,
            LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            &mut jobs,
            10,
            &mut context,
        )
        .unwrap();

        assert_eq!(outcome, JobDispatcherPollOutcome::Stable);
        assert_eq!(jobs.session_count(), 1);
        assert!(platform.closed.is_empty());
        assert!(platform.terminated_task_groups.is_empty());
        let disconnected = jobs.disconnect_owned_session(console).unwrap();
        assert_eq!(disconnected.channel, DwHandle(90));
        assert_eq!(disconnected.owner, Some(owner));
        assert_eq!(disconnected.outer_job, None);
    }

    /// A host transport for the real registry service.
    ///
    /// Reset card R7C. `preflight_wyrmsh_registry` consumes `ServiceList` pages
    /// that only Registryd produces, and the test below used to author them:
    /// two pages the fixture paged, counted and ordered itself, which is
    /// section 12's "hand-authoring a cross-component producer reply so a
    /// fixture matches the consumer". The pages the consumer now drains come
    /// out of `wyrmroot_registryd::service::RegistryService::step`, driven over
    /// the wire the same way the resident drives it.
    #[derive(Default)]
    struct RegistryHost {
        /// Frames waiting for the service, oldest first.
        inbound: Vec<(u64, Vec<u8>, Vec<u64>)>,
        /// Frames the service wrote, in order.
        sent: Vec<(u64, Vec<u8>)>,
    }

    impl RegistryHost {
        fn push(&mut self, channel: u64, bytes: Vec<u8>, handles: Vec<u64>) {
            self.inbound.push((channel, bytes, handles));
        }
    }

    impl RegistryTransport for RegistryHost {
        type Error = ();

        fn wait(
            &mut self,
            control: u64,
            endpoints: &[wyrmroot_registryd::InstalledEndpoint],
        ) -> Result<RegistryWaitEvent, Self::Error> {
            let channel = self.inbound.first().ok_or(())?.0;
            Ok(RegistryWaitEvent {
                endpoint_index: if channel == control {
                    None
                } else {
                    Some(
                        endpoints
                            .iter()
                            .position(|endpoint| endpoint.handle == channel)
                            .ok_or(())?,
                    )
                },
                readable: true,
                peer_closed: false,
            })
        }

        fn probe(
            &mut self,
            _endpoint: wyrmroot_registryd::InstalledEndpoint,
        ) -> Result<RegistryProbeSignals, Self::Error> {
            Ok(RegistryProbeSignals::default())
        }

        fn receive(
            &mut self,
            channel: u64,
            bytes: &mut [u8],
            handles: &mut [RegistryReceivedHandle],
        ) -> Result<RegistryReceiveCounts, Self::Error> {
            let index = self
                .inbound
                .iter()
                .position(|(queued, _, _)| *queued == channel)
                .ok_or(())?;
            let (_, frame, moved) = self.inbound.remove(index);
            bytes
                .get_mut(..frame.len())
                .ok_or(())?
                .copy_from_slice(&frame);
            for (slot, handle) in handles.iter_mut().zip(moved.iter()) {
                *slot = RegistryReceivedHandle {
                    handle: *handle,
                    metadata_is_channel: true,
                    metadata_rights: 0,
                };
            }
            Ok(RegistryReceiveCounts {
                bytes: frame.len(),
                handles: moved.len(),
            })
        }

        fn validate_channel(
            &mut self,
            _handle: RegistryReceivedHandle,
            _rights: RegistryChannelRights,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn send(&mut self, channel: u64, bytes: &[u8]) -> Result<(), Self::Error> {
            self.sent.push((channel, bytes.to_vec()));
            Ok(())
        }

        fn send_move(
            &mut self,
            channel: u64,
            bytes: &[u8],
            _moved_handle: u64,
            _reduced_rights: RegistryChannelRights,
        ) -> Result<(), Self::Error> {
            self.sent.push((channel, bytes.to_vec()));
            Ok(())
        }

        fn close(&mut self, _handle: u64) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    /// Publishes `names` through the real registry service and returns the
    /// `ServiceList` pages it writes for one bootstrap-metadata enumeration.
    fn actual_service_list_pages(grant: EndpointGrant, names: &[&[u8]]) -> Vec<Vec<u8>> {
        const CONTROL: u64 = 1;
        const CLIENT_CHANNEL: u64 = 900;
        let versions = [wyrmroot_registry_proto::ProtocolVersion { major: 1, minor: 0 }];
        let mut host = RegistryHost::default();
        let mut service = wyrmroot_registryd::service::RegistryService::new(CONTROL);
        for (index, name) in names.iter().enumerate() {
            let endpoint_id = 20 + index as u64;
            let channel = 200 + index as u64;
            // Control-channel installs are supervisor-scoped: the header
            // carries no endpoint, the payload names the one being installed.
            let header = RegistryHeader {
                message_type: RegistryMessageType::InstallPublication,
                registry_generation: grant.registry_generation,
                endpoint_id: 0,
                endpoint_generation: 0,
                transaction_id: 1,
            };
            let mut bytes = [0_u8; 416];
            let size = encode_install_publication(
                header,
                endpoint_id,
                1,
                RoleId::Registryd as u32,
                30 + index as u64,
                1,
                10 + index as u64,
                &versions,
                name,
                &mut bytes,
            )
            .unwrap();
            host.push(CONTROL, bytes[..size].to_vec(), vec![channel]);
            service.step(&mut host).unwrap();
            let mut publish = [0_u8; REGISTRY_HEADER_BYTES];
            let publish_size = encode_registry_empty(
                RegistryHeader {
                    message_type: RegistryMessageType::Publish,
                    endpoint_id,
                    endpoint_generation: 1,
                    transaction_id: 2,
                    ..header
                },
                &mut publish,
            )
            .unwrap();
            host.push(channel, publish[..publish_size].to_vec(), Vec::new());
            service.step(&mut host).unwrap();
        }
        let mut install = [0_u8; 416];
        let install_size = encode_install_client(
            RegistryHeader {
                message_type: RegistryMessageType::InstallClient,
                registry_generation: grant.registry_generation,
                endpoint_id: 0,
                endpoint_generation: 0,
                transaction_id: 1,
            },
            wyrmroot_registry_proto::InstallClient {
                endpoint_id: grant.endpoint_id,
                endpoint_generation: grant.endpoint_generation,
                client_id: 50,
                client_generation: 1,
                scope: wyrmroot_registry_proto::EnumerationScope::BootstrapMetadata,
            },
            &mut install,
        )
        .unwrap();
        host.push(
            CONTROL,
            install[..install_size].to_vec(),
            vec![CLIENT_CHANNEL],
        );
        service.step(&mut host).unwrap();
        let mut enumerate = [0_u8; REGISTRY_HEADER_BYTES];
        let enumerate_size = encode_registry_empty(
            RegistryHeader {
                message_type: RegistryMessageType::Enumerate,
                registry_generation: grant.registry_generation,
                endpoint_id: grant.endpoint_id,
                endpoint_generation: grant.endpoint_generation,
                transaction_id: 1,
            },
            &mut enumerate,
        )
        .unwrap();
        host.push(
            CLIENT_CHANNEL,
            enumerate[..enumerate_size].to_vec(),
            Vec::new(),
        );
        service.step(&mut host).unwrap();
        host.sent
            .iter()
            .filter(|(channel, _)| *channel == CLIENT_CHANNEL)
            .map(|(_, bytes)| bytes.clone())
            .collect()
    }

    #[test]
    fn e3c_registry_preflight_drains_every_canonical_page() {
        /// Only the refusal leg still authors a page: the real registry cannot
        /// emit a noncanonical one, and refusing one is exactly what this
        /// consumer owes.
        fn page(grant: EndpointGrant, page_index: u16, names: &[&[u8]]) -> Vec<u8> {
            let versions = [
                RegistryProtocolVersion { major: 1, minor: 0 },
                RegistryProtocolVersion::default(),
                RegistryProtocolVersion::default(),
                RegistryProtocolVersion::default(),
            ];
            let records: Vec<_> = names
                .iter()
                .enumerate()
                .map(|(index, name)| ServiceListRecord {
                    protocol_id: 10 + usize::from(page_index) as u64 * 2 + index as u64,
                    service_generation: 1,
                    versions,
                    version_count: 1,
                    service_name: name,
                })
                .collect();
            let mut bytes = [0_u8;
                SERVICE_LIST_PREFIX_BYTES
                    + wyrmroot_registry_proto::MAX_SERVICE_LIST_RECORDS * SERVICE_LIST_RECORD_BYTES];
            let size = encode_service_list(
                RegistryHeader {
                    message_type: RegistryMessageType::ServiceList,
                    registry_generation: grant.registry_generation,
                    endpoint_id: grant.endpoint_id,
                    endpoint_generation: grant.endpoint_generation,
                    transaction_id: 1,
                },
                page_index,
                2,
                3,
                &records,
                &mut bytes,
            )
            .unwrap();
            bytes[..size].to_vec()
        }

        let grant = EndpointGrant {
            registry_generation: 7,
            endpoint_id: 4,
            endpoint_generation: 1,
            role_generation: 9,
            kind: EndpointKind::RegistryClient,
        };
        let pages = actual_service_list_pages(grant, &[b"alpha", b"beta", b"gamma"]);
        assert_eq!(
            pages.len(),
            2,
            "the real registry pages three services in two"
        );
        let mut platform = ShellPlatform::new();
        for page in pages {
            platform.push(DwHandle(101), page, &[]);
        }
        preflight_wyrmsh_registry(&mut platform, DwHandle(101), grant, None).unwrap();
        assert_eq!(platform.inbound_cursor, 2);

        let mut noncanonical = ShellPlatform::new();
        noncanonical.push(DwHandle(101), page(grant, 0, &[b"alpha", b"beta"]), &[]);
        noncanonical.push(DwHandle(101), page(grant, 1, &[b"aardvark"]), &[]);
        assert_eq!(
            preflight_wyrmsh_registry(&mut noncanonical, DwHandle(101), grant, None),
            Err(InitError::WrongManifestProfile)
        );
    }

    #[test]
    fn malformed_shell_v1_is_cleaned_and_its_fresh_transaction_replays() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        let mut waits = TerminalWaits;
        let mut loader = InitSendLoader::new();
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_scoped_session(owner, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        let request = wyrmroot_launch_proto::ShellV1Request {
            console_generation: 2,
            status_generation: 3,
            requested_child_generation: 4,
        };
        platform.inbound_len = wyrmroot_launch_proto::encode_shell_v1_request(
            reservation(1),
            request,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound[112] ^= 1;
        platform.inbound_handle_count = 4;
        for (index, info) in platform.inbound_handles[..4].iter_mut().enumerate() {
            info.handle = DwHandle(41 + index as u64);
        }
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            None,
            &mut jobs,
            DwHandle(90),
            owner,
            LaunchPublication::Immediate,
        )
        .unwrap();
        assert_eq!(
            wyrmroot_launch_proto::parse_shell_v1_reply(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .reply,
            wyrmroot_launch_proto::ShellV1Reply::Error {
                code: LaunchErrorCode::MalformedRequest,
            }
        );
        assert_eq!(platform.close_count, 4);
        assert_eq!(platform.query_count, 0);

        platform.inbound_len = wyrmroot_launch_proto::encode_shell_v1_request(
            reservation(1),
            request,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_handle_count = 4;
        for (index, info) in platform.inbound_handles[..4].iter_mut().enumerate() {
            info.handle = DwHandle(51 + index as u64);
        }
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            None,
            &mut jobs,
            DwHandle(90),
            owner,
            LaunchPublication::Immediate,
        )
        .unwrap();
        assert_eq!(
            wyrmroot_launch_proto::parse_shell_v1_reply(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .reply,
            wyrmroot_launch_proto::ShellV1Reply::Error {
                code: LaunchErrorCode::TransactionReplay,
            }
        );
        assert_eq!(platform.close_count, 8);
        assert_eq!(platform.query_count, 0);
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn coherent_old_shell_v1_epoch_cannot_mutate_current_controller_or_observer() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        let mut waits = TerminalWaits;
        let mut loader = InitSendLoader::new();
        let mut jobs = JobDispatcher::new();
        let current = grant(EndpointKind::LaunchSession, 2, 2);
        jobs.install_scoped_session(current, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        let old_reservation = reservation(41);
        platform.inbound_len = wyrmroot_launch_proto::encode_shell_v1_request(
            old_reservation,
            wyrmroot_launch_proto::ShellV1Request {
                console_generation: 11,
                status_generation: 12,
                requested_child_generation: 13,
            },
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_handle_count = 4;
        for (index, info) in platform.inbound_handles[..4].iter_mut().enumerate() {
            info.handle = DwHandle(51 + index as u64);
        }
        let mut topology = RegistryTopology::new(7).unwrap();
        let mut state = ShellControllerState::new(7).unwrap();
        let state_before = state;
        let topology_before = topology;
        let mut shell = ShellLaunchContext {
            registry_control: DwHandle(80),
            topology: &mut topology,
            state: &mut state,
        };

        assert_eq!(
            dispatch_one_job_request_with_shell(
                &mut platform,
                &mut loader,
                &mut waits,
                LoadAuthority {
                    parent_root: DwHandle(1),
                    bootfs: DwHandle(2),
                    task_group: DwHandle(3),
                },
                None,
                &mut jobs,
                DwHandle(90),
                current,
                &mut shell,
                LaunchPublication::Immediate,
            ),
            Ok(JobDispatchOutcome::Responded)
        );
        assert_eq!(*shell.state, state_before);
        assert_eq!(*shell.topology, topology_before);
        assert_eq!(jobs.session_count(), 1);
        assert_eq!(jobs.jobs.live_jobs(), 0);
        assert_eq!(jobs.jobs.completed_results(), 0);
        assert_eq!(platform.query_count, 0);
        assert_eq!(platform.close_count, 4);
        assert_eq!(
            platform.closed[..4],
            [DwHandle(54), DwHandle(53), DwHandle(52), DwHandle(51)]
        );
        assert_eq!(
            wyrmroot_launch_proto::parse_shell_v1_reply(&platform.sent[..platform.sent_len], 0,)
                .unwrap()
                .reply,
            wyrmroot_launch_proto::ShellV1Reply::Error {
                code: LaunchErrorCode::StaleOrUnknownSession,
            }
        );
        assert!(
            jobs.jobs
                .reserve_request(LaunchReservation {
                    connection_id: current.endpoint_id,
                    generation: current.endpoint_generation,
                    transaction_id: old_reservation.transaction_id,
                })
                .is_ok()
        );
    }

    #[cfg(feature = "wyr1e8-selector33")]
    fn classify_e8_trigger_for_test(
        stage: u32,
        action: &str,
        token: &str,
    ) -> Result<Option<E8TriggerIdentity>, InitError> {
        let reservation = LaunchReservation {
            connection_id: 9,
            generation: 10,
            transaction_id: 11,
        };
        let mut request = [0u8; wyrmroot_launch_proto::MAX_LAUNCH_MESSAGE_BYTES];
        let request_len = wyrmroot_launch_proto::encode_launch(
            reservation,
            wyrmroot_wyr1e_test_actors::RECOVERY_TRIGGER_PATH,
            &[
                wyrmroot_wyr1e_test_actors::RECOVERY_TRIGGER_PATH,
                action,
                token,
            ],
            &[],
            true,
            &mut request,
        )
        .unwrap();
        let mut response = [0u8; 56];
        let response_len = encode_job_message(
            reservation,
            LaunchMessageType::LaunchAccepted,
            12,
            &mut response,
        )
        .unwrap();
        e8_trigger_from_transaction(
            stage,
            0x1122_3344_5566_7788,
            &request[..request_len],
            &response[..response_len],
            3,
        )
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn e8_recovery_trigger_requires_exact_stage_derived_token() {
        for (stage, action, token, expected) in [
            (
                2,
                wyrmroot_wyr1e_test_actors::RECOVERY_DRIVER_ACTION,
                "112233445566768A",
                E8RecoveryAction::Driver,
            ),
            (
                3,
                wyrmroot_wyr1e_test_actors::RECOVERY_REGISTRY_ACTION,
                "112233445566758A",
                E8RecoveryAction::Registry,
            ),
        ] {
            assert_eq!(
                classify_e8_trigger_for_test(stage, action, token),
                Ok(Some(E8TriggerIdentity {
                    launch_transaction: 11,
                    job_id: 12,
                    action: expected,
                }))
            );
            for rejected in [
                "1122334455667788",
                "112233445566768B",
                "112233445566758B",
                "112233445566768a",
            ] {
                assert_eq!(
                    classify_e8_trigger_for_test(stage, action, rejected),
                    Err(InitError::Accounting)
                );
            }
        }
        assert_eq!(
            classify_e8_trigger_for_test(
                2,
                wyrmroot_wyr1e_test_actors::RECOVERY_REGISTRY_ACTION,
                "112233445566758A",
            ),
            Err(InitError::Accounting)
        );
        assert_eq!(
            classify_e8_trigger_for_test(
                3,
                wyrmroot_wyr1e_test_actors::RECOVERY_DRIVER_ACTION,
                "112233445566768A",
            ),
            Err(InitError::Accounting)
        );
    }

    #[test]
    fn shell_v1_receive_failure_retains_uncommitted_sender_handles() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        let mut waits = TerminalWaits;
        let mut loader = InitSendLoader::new();
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_scoped_session(owner, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        platform.inbound_len = wyrmroot_launch_proto::encode_shell_v1_request(
            reservation(1),
            wyrmroot_launch_proto::ShellV1Request {
                console_generation: 2,
                status_generation: 3,
                requested_child_generation: 4,
            },
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_handle_count = 5;
        for (index, info) in platform.inbound_handles[..5].iter_mut().enumerate() {
            info.handle = DwHandle(41 + index as u64);
        }

        assert_eq!(
            dispatch_one_job_request(
                &mut platform,
                &mut loader,
                &mut waits,
                authority,
                None,
                &mut jobs,
                DwHandle(90),
                owner,
                LaunchPublication::Immediate,
            ),
            Err(InitError::Native(FAILURE))
        );
        assert_eq!(platform.inbound_handle_count, 5);
        assert_eq!(platform.close_count, 0);
        assert_eq!(platform.sent_len, 0);
    }

    #[test]
    fn shell_v1_rejects_duplicate_rights_after_committed_move_cleanup() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        platform.fresh_rights =
            DwRights(CONTROLLER_CHANNEL_RIGHTS.0 | deepwyrm_syscall::DW_RIGHT_DUPLICATE.0);
        let mut waits = TerminalWaits;
        let mut loader = InitSendLoader::new();
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_scoped_session(owner, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        platform.inbound_len = wyrmroot_launch_proto::encode_shell_v1_request(
            reservation(1),
            wyrmroot_launch_proto::ShellV1Request {
                console_generation: 2,
                status_generation: 3,
                requested_child_generation: 4,
            },
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_handle_count = 4;
        for (index, info) in platform.inbound_handles[..4].iter_mut().enumerate() {
            info.handle = DwHandle(41 + index as u64);
        }
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            LoadAuthority {
                parent_root: DwHandle(1),
                bootfs: DwHandle(2),
                task_group: DwHandle(3),
            },
            None,
            &mut jobs,
            DwHandle(90),
            owner,
            LaunchPublication::Immediate,
        )
        .unwrap();
        assert_eq!(platform.query_count, 1);
        assert_eq!(platform.close_count, 4);
        assert_eq!(
            wyrmroot_launch_proto::parse_shell_v1_reply(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .reply,
            wyrmroot_launch_proto::ShellV1Reply::Error {
                code: LaunchErrorCode::PolicyRejected,
            }
        );
    }

    #[test]
    fn launch_session_scopes_reject_crossed_protocols_without_fallback() {
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        for scope in [
            LaunchSessionScope::Historical,
            LaunchSessionScope::ShellJobs,
        ] {
            let mut platform = MockPlatform::new();
            platform.fail_send = false;
            let mut waits = TerminalWaits;
            let mut loader = InitSendLoader::new();
            let mut jobs = JobDispatcher::new();
            let owner = grant(EndpointKind::LaunchSession, 1, 1);
            jobs.install_scoped_session(owner, DwHandle(90), scope)
                .unwrap();
            platform.inbound_len = wyrmroot_launch_proto::encode_shell_v1_request(
                reservation(1),
                wyrmroot_launch_proto::ShellV1Request {
                    console_generation: 2,
                    status_generation: 3,
                    requested_child_generation: 4,
                },
                &mut platform.inbound,
            )
            .unwrap();
            platform.inbound_handle_count = 4;
            dispatch_one_job_request(
                &mut platform,
                &mut loader,
                &mut waits,
                authority,
                None,
                &mut jobs,
                DwHandle(90),
                owner,
                LaunchPublication::Immediate,
            )
            .unwrap();
            assert_eq!(
                wyrmroot_launch_proto::parse_shell_v1_reply(&platform.sent[..platform.sent_len], 0)
                    .unwrap()
                    .reply,
                wyrmroot_launch_proto::ShellV1Reply::Error {
                    code: LaunchErrorCode::PolicyRejected,
                }
            );
        }

        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        let mut waits = TerminalWaits;
        let mut loader = InitSendLoader::new();
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_scoped_session(owner, DwHandle(90), LaunchSessionScope::ConsoleLauncher)
            .unwrap();
        platform.inbound_len = wyrmroot_launch_proto::encode_launch(
            reservation(1),
            "bin/hello",
            &["bin/hello"],
            &[],
            false,
            &mut platform.inbound,
        )
        .unwrap();
        dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            None,
            &mut jobs,
            DwHandle(90),
            owner,
            LaunchPublication::Immediate,
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error {
                code: LaunchErrorCode::PolicyRejected
            }
        ));
    }

    #[test]
    fn scoped_sessions_keep_minor_zero_job_operations() {
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        for scope in [
            LaunchSessionScope::ConsoleLauncher,
            LaunchSessionScope::ShellJobs,
        ] {
            let mut platform = MockPlatform::new();
            platform.fail_send = false;
            let mut waits = TerminalWaits;
            let mut loader = InitSendLoader::new();
            let mut jobs = JobDispatcher::new();
            let owner = grant(EndpointKind::LaunchSession, 1, 1);
            jobs.install_scoped_session(owner, DwHandle(90), scope)
                .unwrap();
            platform.inbound[..wyrmroot_launch_proto::HEADER_BYTES].fill(0);
            wyrmroot_launch_proto::encode(reservation(1), &mut platform.inbound).unwrap();
            platform.inbound[40..44]
                .copy_from_slice(&(LaunchMessageType::ListJobs as u32).to_le_bytes());
            platform.inbound_len = wyrmroot_launch_proto::HEADER_BYTES;
            dispatch_one_job_request(
                &mut platform,
                &mut loader,
                &mut waits,
                authority,
                None,
                &mut jobs,
                DwHandle(90),
                owner,
                LaunchPublication::Immediate,
            )
            .unwrap();
            assert!(matches!(
                parse_launch_message(&platform.sent[..platform.sent_len], 0)
                    .unwrap()
                    .message,
                LaunchMessage::JobList(ids) if ids.is_empty()
            ));
        }
    }

    #[test]
    fn post_load_deadline_failure_rolls_back_invisibly_and_keeps_session() {
        let image = executable();
        let (bootfs, generation) = job_policy_bootfs(&image);
        let archive = Archive::new(&bootfs).unwrap();
        let policy = PolicyView::from_bootfs(archive, generation).unwrap();
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        platform.task_group = Some(DwHandle(77));
        let mut waits = TerminalWaits;
        let mut loader = InitSendLoader::new();
        loader.fail_init = false;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        let size = wyrmroot_launch_proto::encode_launch(
            reservation(1),
            "bin/hello",
            &["bin/hello"],
            &[],
            false,
            &mut platform.inbound,
        )
        .unwrap();
        platform.inbound_len = size;
        assert_eq!(
            dispatch_one_job_request(
                &mut platform,
                &mut loader,
                &mut waits,
                authority,
                Some(&policy),
                &mut jobs,
                DwHandle(90),
                owner,
                LaunchPublication::Immediate,
            ),
            Ok(JobDispatchOutcome::Responded)
        );
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error {
                code: LaunchErrorCode::LoaderFailure
            }
        ));
        assert_eq!(platform.terminate_count, 1);
        assert_eq!(jobs.jobs.live_jobs(), 0);
        assert_eq!(jobs.jobs.completed_results(), 0);
        assert_eq!(jobs.session_count(), 1);
        assert_eq!(
            jobs.jobs.result(reservation(2), 1),
            Err(JobError::UnknownJob)
        );
    }

    #[test]
    fn failed_launch_accepted_send_terminates_reaps_and_closes_once() {
        let mut platform = MockPlatform::new();
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let ticket = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(ticket, 101, 102, 103).unwrap();
        let loaded = jobs.jobs.loaded_job(ticket.job_id).unwrap();
        let release = jobs
            .jobs
            .release_launch_channel(ticket.job_id, 103)
            .unwrap();

        assert_eq!(
            publish_launch_accepted(
                &mut platform,
                &mut waits,
                &mut jobs,
                DwHandle(90),
                reservation(1),
                loaded,
                release,
                #[cfg(feature = "wyr1e8-selector33")]
                None,
            ),
            Err(InitError::Native(FAILURE))
        );
        assert_eq!(platform.terminate_count, 1);
        assert_eq!(jobs.jobs.live_jobs(), 0);
        assert_eq!(
            &platform.closed[..platform.close_count],
            &[DwHandle(103), DwHandle(101), DwHandle(102)]
        );
    }

    #[test]
    fn cancelled_wait_then_reap_terminate_reports_invalid_state_and_preserves_result() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();

        let wait_ticket = jobs.jobs.reserve_request(reservation(2)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(2),
            wait_ticket,
            LaunchMessage::Wait {
                job_id: launch.job_id,
            },
        )
        .unwrap();
        assert_eq!(platform.sent_len, 0);

        let cancel_ticket = jobs.jobs.reserve_request(reservation(3)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(3),
            cancel_ticket,
            LaunchMessage::Cancel {
                target_transaction_id: 2,
            },
        )
        .unwrap();
        let cancelled = platform.sent;
        let cancelled_len = platform.sent_len;
        assert!(matches!(
            parse_launch_message(&cancelled[..cancelled_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Cancelled {
                target_transaction_id: 2
            }
        ));

        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();
        reap_job(&mut platform, &mut waits, &mut jobs, loaded).unwrap();
        service_pending_wait(&mut platform, &mut waits, &mut jobs).unwrap();
        assert_eq!(platform.sent_len, cancelled_len);
        assert_eq!(&platform.sent[..cancelled_len], &cancelled[..cancelled_len]);

        for (transaction, message) in [
            (
                4,
                LaunchMessage::Terminate {
                    job_id: launch.job_id,
                },
            ),
            (
                5,
                LaunchMessage::Wait {
                    job_id: launch.job_id,
                },
            ),
            (
                6,
                LaunchMessage::CloseJob {
                    job_id: launch.job_id,
                },
            ),
        ] {
            let request = reservation(transaction);
            let ticket = jobs.jobs.reserve_request(request).unwrap();
            dispatch_reserved_operation(
                &mut platform,
                &mut waits,
                &mut jobs,
                DwHandle(90),
                owner,
                request,
                ticket,
                message,
            )
            .unwrap();
            let response = parse_launch_message(&platform.sent[..platform.sent_len], 0).unwrap();
            assert_eq!(response.reservation, request);
            match transaction {
                4 => assert_eq!(
                    response.message,
                    LaunchMessage::Error {
                        code: LaunchErrorCode::InvalidState
                    }
                ),
                5 => assert_eq!(
                    response.message,
                    LaunchMessage::JobResult {
                        job_id: launch.job_id,
                        result: TerminationResult {
                            classification: TerminationClassification::NormalExit,
                            application_code: 0,
                            exception_class: 0,
                            exception_detail: 0,
                            exception_address: 0,
                            cleanup_result: 0,
                        },
                    }
                ),
                6 => assert_eq!(
                    response.message,
                    LaunchMessage::Closed {
                        job_id: launch.job_id
                    }
                ),
                _ => unreachable!(),
            }
        }
        assert_eq!(platform.terminate_count, 0);
        assert_eq!(platform.close_count, 3);
        assert_eq!(
            jobs.jobs.result(reservation(7), launch.job_id),
            Err(JobError::UnknownJob)
        );
        assert_eq!(
            jobs.jobs.terminate(reservation(8), launch.job_id),
            Err(JobError::UnknownJob)
        );
    }

    #[test]
    fn terminate_during_staged_terminal_cleanup_never_calls_native_termination() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
        let terminal = ControllerJobResult {
            classification: 1,
            application_code: 0,
            exception_class: 0,
            exception_detail: 0,
            exception_address: 0,
            cleanup_result: 0,
        };
        assert_eq!(
            jobs.jobs
                .apply_cleanup_progress(launch.job_id, terminal, 1 << 3, 0),
            Ok(None)
        );
        let before = jobs.jobs.loaded_job(launch.job_id).unwrap();
        let ticket = jobs.jobs.reserve_request(reservation(2)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(2),
            ticket,
            LaunchMessage::Terminate {
                job_id: launch.job_id,
            },
        )
        .unwrap();
        assert_eq!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error {
                code: LaunchErrorCode::InvalidState
            }
        );
        assert_eq!(platform.terminate_count, 0);
        assert_eq!(jobs.jobs.loaded_job(launch.job_id), Ok(before));
        assert_eq!(jobs.jobs.terminal_result(launch.job_id), Ok(Some(terminal)));
    }

    #[test]
    fn close_and_disconnect_drop_waits_but_jobs_reap_naturally() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
        let wait_ticket = jobs.jobs.reserve_request(reservation(2)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(2),
            wait_ticket,
            LaunchMessage::Wait {
                job_id: launch.job_id,
            },
        )
        .unwrap();
        let close_ticket = jobs.jobs.reserve_request(reservation(3)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(3),
            close_ticket,
            LaunchMessage::CloseJob {
                job_id: launch.job_id,
            },
        )
        .unwrap();
        let closed = platform.sent;
        let closed_len = platform.sent_len;
        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();
        reap_job(&mut platform, &mut waits, &mut jobs, loaded).unwrap();
        service_pending_wait(&mut platform, &mut waits, &mut jobs).unwrap();
        assert_eq!(&platform.sent[..closed_len], &closed[..closed_len]);
        assert_eq!(platform.terminate_count, 0);

        let second = grant(EndpointKind::LaunchSession, 2, 1);
        jobs.install_session(second, DwHandle(91)).unwrap();
        let second_reservation = |transaction_id| LaunchReservation {
            connection_id: 2,
            generation: 3,
            transaction_id,
        };
        let launch2 = jobs.jobs.begin_launch(second_reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch2, 201, 202, 203).unwrap();
        let wait2 = jobs.jobs.reserve_request(second_reservation(2)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(91),
            second,
            second_reservation(2),
            wait2,
            LaunchMessage::Wait {
                job_id: launch2.job_id,
            },
        )
        .unwrap();
        jobs.disconnect_owned_session(second).unwrap();
        let sent_before_reap = platform.sent;
        let sent_before_reap_len = platform.sent_len;
        let loaded2 = jobs.jobs.loaded_job(launch2.job_id).unwrap();
        reap_job(&mut platform, &mut waits, &mut jobs, loaded2).unwrap();
        service_pending_wait(&mut platform, &mut waits, &mut jobs).unwrap();
        assert_eq!(platform.sent_len, sent_before_reap_len);
        assert_eq!(
            &platform.sent[..sent_before_reap_len],
            &sent_before_reap[..sent_before_reap_len]
        );
        assert_eq!(platform.terminate_count, 0);
    }

    #[test]
    fn close_failure_retries_only_retained_handle_and_keeps_sticky_result_bit() {
        let mut platform = MockPlatform::new();
        platform.fail_close = Some(DwHandle(103));
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();
        assert_eq!(
            reap_job(&mut platform, &mut waits, &mut jobs, loaded),
            Err(InitError::Cleanup)
        );
        assert_eq!(jobs.jobs.live_jobs(), 1);
        assert_eq!(jobs.jobs.completed_results(), 0);
        assert_eq!(
            &platform.closed[..platform.close_count],
            &[DwHandle(103), DwHandle(101), DwHandle(102)]
        );

        platform.fail_close = None;
        let retained = jobs.jobs.loaded_job(launch.job_id).unwrap();
        assert_eq!(retained.loaded.process, DwHandle(0));
        assert_eq!(retained.task_group, 0);
        assert_eq!(retained.loaded.launch_channel, DwHandle(103));
        let result = reap_job(&mut platform, &mut waits, &mut jobs, retained).unwrap();
        assert_eq!(result.cleanup_result, 1 << 2);
        assert_eq!(jobs.jobs.live_jobs(), 0);
        assert_eq!(platform.closed[platform.close_count - 1], DwHandle(103));
    }

    #[test]
    fn terminate_failure_keeps_running_phase_and_records_cleanup_bit_zero() {
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        platform.fail_terminate = true;
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();

        let terminate = jobs.jobs.reserve_request(reservation(2)).unwrap();
        dispatch_reserved_operation(
            &mut platform,
            &mut waits,
            &mut jobs,
            DwHandle(90),
            owner,
            reservation(2),
            terminate,
            LaunchMessage::Terminate {
                job_id: launch.job_id,
            },
        )
        .unwrap();
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error {
                code: LaunchErrorCode::CleanupFailure
            }
        ));
        assert_eq!(platform.terminate_count, 1);
        assert_eq!(
            jobs.jobs
                .query(reservation(3), launch.job_id)
                .unwrap()
                .phase,
            crate::wyr1b::JobPhase::Running
        );

        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();
        let result = reap_job(&mut platform, &mut waits, &mut jobs, loaded).unwrap();
        assert_eq!(result.cleanup_result, 1 << 0);
    }

    #[test]
    fn wait_failure_records_cleanup_bit_one_without_closing_before_terminal() {
        let mut platform = MockPlatform::new();
        platform.now = Some(1);
        let mut waits = WaitFailureThenTerminal { query_count: 0 };
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();

        assert_eq!(
            reap_job(&mut platform, &mut waits, &mut jobs, loaded),
            Err(InitError::Cleanup)
        );
        assert_eq!(platform.close_count, 0);
        assert_eq!(jobs.jobs.live_jobs(), 1);

        let retained = jobs.jobs.loaded_job(launch.job_id).unwrap();
        let result = reap_job(&mut platform, &mut waits, &mut jobs, retained).unwrap();
        assert_eq!(result.cleanup_result, 1 << 1);
        assert_eq!(jobs.jobs.live_jobs(), 0);
    }

    /// Reset card R6B-2's property, stated as a sequence rather than a
    /// signature: the poll that reads a launch does not publish it.
    ///
    /// This is the test the card exists for. Before it, the whole launch --
    /// construction, the blocking READY observation, and the reply -- ran in
    /// the frame that read the request, which is what §3's invariant 6 forbids.
    /// After it, the first poll returns with the child alive, the transaction
    /// parked in the arena and nothing on the wire; a later poll finds the
    /// parked transaction and finishes it. Both halves are asserted, because
    /// only publishing late is the property, and a version that never published
    /// at all would satisfy the first half alone.
    #[test]
    fn a_deferred_launch_publishes_on_a_later_poll_than_the_one_that_read_it() {
        let image = executable();
        let (bootfs, _) = job_policy_bootfs(&image);
        let mut platform = MockPlatform::new();
        platform.bootfs = Some(bootfs);
        platform.fail_send = false;
        platform.now = Some(1);
        platform.task_group = Some(DwHandle(77));
        platform.session_poll_readable = true;
        let mut waits = AcceptedJobV2Waits {
            transaction_id: reservation(1).transaction_id,
            profile: LaunchProfile::JobV2,
            exited: false,
            console_status_lost_process: None,
            running_process: None,
        };
        let mut loader = InitSendLoader::new();
        loader.fail_init = false;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        platform.inbound_len = wyrmroot_launch_proto::encode_launch(
            reservation(1),
            "bin/hello",
            &["bin/hello"],
            &[],
            false,
            &mut platform.inbound,
        )
        .unwrap();

        poll_job_dispatcher(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            &mut jobs,
            10,
        )
        .unwrap();

        assert_eq!(
            jobs.launches.open_count(),
            1,
            "the launch must be parked in the arena, not on the frame that read it"
        );
        assert_eq!(
            platform.sent_len, 0,
            "nothing may be published before the READY observation"
        );
        // The child is real -- construction ran -- and the model counts it.
        // What has not happened is publication: the owner has been told
        // nothing, which is the whole of what the deferral moves.
        assert_eq!(jobs.jobs.live_jobs(), 1);
        // Recorded rather than asserted: `loaded_job` answers for a job that
        // is staged but not committed, so a parked transaction's child is
        // reachable by id. That was true inside the one frame too and had no
        // window to be observed in; deferring gives it one. Nothing on the
        // resident path reaps by id today, and `job_transaction` is the arena's
        // answer for when R6C drives cleanup and cancel from ordinary dispatch.
        assert!(jobs.launches.job_transaction(1).is_some());

        // The session has nothing more to say; the child does. R6C makes those
        // two separate questions, so the next tick finishes the launch without
        // reading anything from the session.
        platform.session_poll_readable = false;
        platform.session_poll_timeout = true;
        platform.child_poll_readable = Some(true);

        poll_job_dispatcher(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            &mut jobs,
            11,
        )
        .unwrap();

        assert_eq!(
            jobs.launches.open_count(),
            0,
            "a published transaction leaves the arena"
        );
        assert_eq!(jobs.jobs.live_jobs(), 1);
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::LaunchAccepted { job_id } if job_id != 0
        ));
    }

    /// Builds the state the two R6C tests below start from: one launch read,
    /// constructed and parked, with nothing published.
    fn park_one_launch(
        platform: &mut MockPlatform,
        loader: &mut InitSendLoader,
        waits: &mut AcceptedJobV2Waits,
        jobs: &mut JobDispatcher,
        owner: EndpointGrant,
        authority: LoadAuthority,
    ) {
        platform.inbound_len = wyrmroot_launch_proto::encode_launch(
            reservation(1),
            "bin/hello",
            &["bin/hello"],
            &[],
            false,
            &mut platform.inbound,
        )
        .unwrap();
        poll_job_dispatcher(platform, loader, waits, authority, jobs, 10).unwrap();
        assert_eq!(jobs.launches.open_count(), 1);
        assert_eq!(platform.sent_len, 0);
        let _ = owner;
    }

    /// Reset card R6C, and the half of R6D that can be proved without a guest:
    /// a child that never answers does not take the session's turn.
    ///
    /// Before R6C the tick that went to finish a parked launch waited inside
    /// `observe_prepared_ready` until the child answered or its deadline
    /// expired, and every session on the dispatcher waited with it. Now a
    /// silent child costs one non-blocking poll of two handles and the session
    /// is serviced in the same tick. The assertion is that the session's
    /// request was answered while the launch was still parked -- which is only
    /// possible if finishing the launch did not block.
    #[test]
    fn a_child_that_never_answers_does_not_take_the_sessions_turn() {
        let image = executable();
        let (bootfs, _) = job_policy_bootfs(&image);
        let mut platform = MockPlatform::new();
        platform.bootfs = Some(bootfs);
        platform.fail_send = false;
        platform.now = Some(1);
        platform.task_group = Some(DwHandle(77));
        platform.session_poll_readable = true;
        let mut waits = AcceptedJobV2Waits {
            transaction_id: reservation(1).transaction_id,
            profile: LaunchProfile::JobV2,
            exited: false,
            console_status_lost_process: None,
            running_process: None,
        };
        let mut loader = InitSendLoader::new();
        loader.fail_init = false;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        park_one_launch(
            &mut platform,
            &mut loader,
            &mut waits,
            &mut jobs,
            owner,
            authority,
        );

        // The child stays silent. The session asks an unrelated question.
        platform.child_poll_readable = Some(false);
        platform.inbound_len = encode_job_message(
            reservation(2),
            LaunchMessageType::Query,
            1,
            &mut platform.inbound,
        )
        .unwrap();

        poll_job_dispatcher(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            &mut jobs,
            11,
        )
        .unwrap();

        assert_eq!(
            jobs.launches.open_count(),
            1,
            "a silent child stays parked rather than being failed early"
        );
        assert!(
            platform.sent_len > 0,
            "the session must be answered in the same tick the silent child was polled"
        );
        // §9 requires every reply to echo its request's envelope, so the
        // reservation is what says *which* request was answered. It is the
        // session's second one, not the parked launch's first.
        assert_eq!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .reservation,
            reservation(2)
        );
    }

    /// Reset card R6D, the part that needed a second launch client to say
    /// anything at all.
    ///
    /// R6C proved a silent child does not cost *its own* session its turn. That
    /// is the weaker reading: the same session could be serviced because the
    /// dispatcher happened to come back to it. R6D's claim is about other
    /// clients, so this has two installed sessions and asserts that the one
    /// without a parked launch is the one answered, while the other's child is
    /// still in flight.
    #[test]
    fn a_parked_child_does_not_cost_a_different_launch_client_its_turn() {
        let image = executable();
        let (bootfs, _) = job_policy_bootfs(&image);
        let mut platform = MockPlatform::new();
        platform.bootfs = Some(bootfs);
        platform.fail_send = false;
        platform.now = Some(1);
        platform.task_group = Some(DwHandle(77));
        platform.session_poll_readable = true;
        let mut waits = AcceptedJobV2Waits {
            transaction_id: reservation(1).transaction_id,
            profile: LaunchProfile::JobV2,
            exited: false,
            console_status_lost_process: None,
            running_process: None,
        };
        let mut loader = InitSendLoader::new();
        loader.fail_init = false;
        let mut jobs = JobDispatcher::new();
        let first = grant(EndpointKind::LaunchSession, 1, 1);
        let second = grant(EndpointKind::LaunchSession, 2, 1);
        jobs.install_session(first, DwHandle(90)).unwrap();
        jobs.install_session(second, DwHandle(91)).unwrap();
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        park_one_launch(
            &mut platform,
            &mut loader,
            &mut waits,
            &mut jobs,
            first,
            authority,
        );
        assert_eq!(
            jobs.launches.open_count(),
            1,
            "the first client's launch is in flight"
        );

        // The first client's child says nothing. The second client asks an
        // unrelated question, on its own session.
        platform.child_poll_readable = Some(false);
        platform.inbound_len = encode_job_message(
            LaunchReservation {
                connection_id: second.endpoint_id,
                generation: second.endpoint_generation,
                transaction_id: 1,
            },
            LaunchMessageType::Query,
            1,
            &mut platform.inbound,
        )
        .unwrap();

        poll_job_dispatcher(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            &mut jobs,
            11,
        )
        .unwrap();

        assert_eq!(
            jobs.launches.open_count(),
            1,
            "the first client's child is still in flight"
        );
        assert_eq!(
            platform.last_sent_channel,
            Some(DwHandle(91)),
            "the second client's session is the one that was answered"
        );
    }

    /// Reset card R6D, and the reason the parked-child poll asks for the
    /// signals it does rather than for anything at all.
    ///
    /// `await_child_ready_profile_observed` finishes without waiting again on
    /// exactly two of its branches: `READABLE`, where it receives and parses the
    /// READY message, and `EXITED`, where it queries the terminal record. A
    /// launch Channel that is `PEER_CLOSED` and not `READABLE` takes the third
    /// branch, which waits for the Process's `EXITED` under the launch's own
    /// deadline -- so a child that dropped its Channel and then declined to die
    /// would hold the tick for the whole budget.
    ///
    /// Asking for `PEER_CLOSED` here would therefore hand the observation
    /// exactly the case it cannot answer promptly. This pins the omission,
    /// because nothing else about the code would look wrong if it came back.
    #[test]
    fn the_parked_child_poll_asks_only_for_signals_it_can_act_on_at_once() {
        let image = executable();
        let (bootfs, _) = job_policy_bootfs(&image);
        let mut platform = MockPlatform::new();
        platform.bootfs = Some(bootfs);
        platform.fail_send = false;
        platform.now = Some(1);
        platform.task_group = Some(DwHandle(77));
        platform.session_poll_readable = true;
        let mut waits = AcceptedJobV2Waits {
            transaction_id: reservation(1).transaction_id,
            profile: LaunchProfile::JobV2,
            exited: false,
            console_status_lost_process: None,
            running_process: None,
        };
        let mut loader = InitSendLoader::new();
        loader.fail_init = false;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        park_one_launch(
            &mut platform,
            &mut loader,
            &mut waits,
            &mut jobs,
            owner,
            authority,
        );

        platform.child_poll_readable = Some(false);
        platform.session_poll_readable = false;
        platform.session_poll_timeout = true;
        poll_job_dispatcher(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            &mut jobs,
            11,
        )
        .unwrap();

        assert_eq!(
            platform.child_poll_signals,
            vec![DW_SIGNAL_READABLE.0, DW_SIGNAL_EXITED.0],
            "the Channel is polled for READY and the Process for exit, and \
             PEER_CLOSED is not asked for on either"
        );
    }

    /// Reset card R6C's cancel edge, and the hole that made it necessary.
    ///
    /// R6B-2 was safe here by accident: the poll returned as soon as it had
    /// finished a parked launch, so a session could never be disconnected while
    /// one of its launches was in flight. R6C stops the launch branch ending
    /// the tick -- which is the whole point, a silent child must not cost the
    /// session its turn -- and that made the case reachable. The session's peer
    /// closes, the branch closes the Channel the slot recorded, and the slot is
    /// left holding a child whose only names are in it.
    ///
    /// So the peer close cancels it. Nothing is sent: the peer that would have
    /// been told is the one that left.
    #[test]
    fn a_session_that_leaves_takes_its_parked_launch_with_it() {
        let image = executable();
        let (bootfs, _) = job_policy_bootfs(&image);
        let mut platform = MockPlatform::new();
        platform.bootfs = Some(bootfs);
        platform.fail_send = false;
        platform.now = Some(1);
        platform.task_group = Some(DwHandle(77));
        platform.session_poll_readable = true;
        let mut waits = AcceptedJobV2Waits {
            transaction_id: reservation(1).transaction_id,
            profile: LaunchProfile::JobV2,
            exited: false,
            console_status_lost_process: None,
            running_process: None,
        };
        let mut loader = InitSendLoader::new();
        loader.fail_init = false;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        park_one_launch(
            &mut platform,
            &mut loader,
            &mut waits,
            &mut jobs,
            owner,
            authority,
        );

        platform.child_poll_readable = Some(false);
        platform.session_poll_readable = false;
        platform.session_poll_peer_closed = true;
        waits.exited = true;
        let sent_before = platform.sent_len;

        poll_job_dispatcher(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            &mut jobs,
            11,
        )
        .unwrap();

        assert_eq!(
            jobs.launches.open_count(),
            0,
            "the departing session's transaction must not outlive it"
        );
        assert_eq!(
            jobs.jobs.live_jobs(),
            0,
            "its unpublished child must be rolled back, not left to its deadline"
        );
        assert_eq!(jobs.session_count(), 0);
        assert_eq!(
            platform.sent_len, sent_before,
            "nothing is owed to a peer that has gone"
        );
    }

    /// The other half: a child that never answers is failed when its budget
    /// runs out, and failing it does not fail the tick.
    ///
    /// The one-frame path answered a failed launch with an `ERROR` reply and
    /// carried on; only a failed cleanup escalated. A deferred launch that
    /// misses READY has to behave the same way, or one child that never starts
    /// would take down the supervisor -- which is the failure R6 exists to
    /// remove, reintroduced one card later.
    #[test]
    fn a_parked_launch_past_its_budget_fails_itself_and_not_the_tick() {
        let image = executable();
        let (bootfs, _) = job_policy_bootfs(&image);
        let mut platform = MockPlatform::new();
        platform.bootfs = Some(bootfs);
        platform.fail_send = false;
        platform.now = Some(1);
        platform.task_group = Some(DwHandle(77));
        platform.session_poll_readable = true;
        let mut waits = AcceptedJobV2Waits {
            transaction_id: reservation(1).transaction_id,
            profile: LaunchProfile::JobV2,
            exited: false,
            console_status_lost_process: None,
            running_process: None,
        };
        let mut loader = InitSendLoader::new();
        loader.fail_init = false;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        park_one_launch(
            &mut platform,
            &mut loader,
            &mut waits,
            &mut jobs,
            owner,
            authority,
        );
        let deadline = jobs
            .launches
            .ready_deadline(jobs.launches.job_transaction(1).unwrap())
            .unwrap()
            .unwrap();

        platform.child_poll_readable = Some(false);
        platform.session_poll_readable = false;
        platform.session_poll_timeout = true;
        // The rollback terminates the child and reaps it; a torn-down child has
        // exited by the time its terminal record is read.
        waits.exited = true;

        poll_job_dispatcher(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            &mut jobs,
            deadline.0,
        )
        .expect("a launch that misses its budget must not fail the tick");

        assert_eq!(
            jobs.launches.open_count(),
            0,
            "an expired transaction leaves the arena"
        );
        assert_eq!(jobs.jobs.live_jobs(), 0, "its child is rolled back");
        assert!(matches!(
            parse_launch_message(&platform.sent[..platform.sent_len], 0)
                .unwrap()
                .message,
            LaunchMessage::Error { .. }
        ));
    }

    #[test]
    fn accepted_launch_hands_back_released_state_so_a_scripted_orphan_reap_closes_once() {
        let image = executable();
        let (bootfs, generation) = job_policy_bootfs(&image);
        let archive = Archive::new(&bootfs).unwrap();
        let policy = PolicyView::from_bootfs(archive, generation).unwrap();
        let mut platform = MockPlatform::new();
        platform.fail_send = false;
        platform.now = Some(1);
        platform.task_group = Some(DwHandle(77));
        let mut waits = AcceptedJobV2Waits {
            transaction_id: reservation(1).transaction_id,
            profile: LaunchProfile::JobV2,
            exited: false,
            console_status_lost_process: None,
            running_process: None,
        };
        let mut loader = InitSendLoader::new();
        loader.fail_init = false;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };
        platform.inbound_len = wyrmroot_launch_proto::encode_launch(
            reservation(1),
            "bin/hello",
            &["bin/hello"],
            &[],
            false,
            &mut platform.inbound,
        )
        .unwrap();

        let JobDispatchOutcome::Launched(accepted) = dispatch_one_job_request(
            &mut platform,
            &mut loader,
            &mut waits,
            authority,
            Some(&policy),
            &mut jobs,
            DwHandle(90),
            owner,
            LaunchPublication::Immediate,
        )
        .unwrap() else {
            panic!("an accepted launch must report its loaded job");
        };

        // The controller released and closed its launch-Channel endpoint before
        // returning, so the value handed to a scripted orphan reap must not
        // still name that handle.
        assert_eq!(accepted.loaded.launch_channel, DwHandle(0));
        assert_eq!(platform.close_count, 1);
        let released = platform.closed[0];
        assert_ne!(released, DwHandle(0));

        waits.exited = true;
        let result = reap_job(&mut platform, &mut waits, &mut jobs, accepted).unwrap();
        assert_eq!(result.cleanup_result, 0);
        assert_eq!(
            platform.closed[1..platform.close_count]
                .iter()
                .filter(|handle| **handle == released)
                .count(),
            0
        );
        assert_eq!(jobs.jobs.live_jobs(), 0);
    }

    #[test]
    fn late_scheduled_child_exit_is_reaped_within_the_bounded_round_budget() {
        let mut platform = MockPlatform::new();
        platform.now = Some(1);
        let mut waits = ScheduledExitWaits {
            waits: 0,
            exit_after_waits: usize::from(WYR0_I_SUPERVISION_POLICY.max_attempts),
        };
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();

        let result = reap_job(&mut platform, &mut waits, &mut jobs, loaded).unwrap();
        assert_eq!(result.cleanup_result, 0);
        assert_eq!(
            waits.waits,
            usize::from(WYR0_I_SUPERVISION_POLICY.max_attempts)
        );
        assert_eq!(jobs.jobs.live_jobs(), 0);
    }

    #[test]
    fn unscheduled_child_exit_fails_closed_after_the_bounded_round_budget() {
        let mut platform = MockPlatform::new();
        platform.now = Some(1);
        let mut waits = ScheduledExitWaits {
            waits: 0,
            exit_after_waits: usize::MAX,
        };
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();
        let loaded = jobs.jobs.loaded_job(launch.job_id).unwrap();

        assert_eq!(
            reap_job(&mut platform, &mut waits, &mut jobs, loaded),
            Err(InitError::Cleanup)
        );
        assert_eq!(waits.waits, usize::from(JOB_EXIT_OBSERVATION_ROUNDS));
        assert_eq!(platform.close_count, 0);
        assert_eq!(jobs.jobs.live_jobs(), 1);

        let mut terminal = TerminalWaits;
        let retained = jobs.jobs.loaded_job(launch.job_id).unwrap();
        let result = reap_job(&mut platform, &mut terminal, &mut jobs, retained).unwrap();
        assert_eq!(result.cleanup_result, 1 << 1);
        assert_eq!(jobs.jobs.live_jobs(), 0);
    }

    #[test]
    fn released_launch_channel_is_never_closed_again_by_a_scripted_orphan_reap() {
        let mut platform = MockPlatform::new();
        platform.now = Some(1);
        let mut waits = ScheduledExitWaits {
            waits: 0,
            exit_after_waits: 1,
        };
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();

        // Exactly the accepted-launch tail: stage the release, then close the
        // controller endpoint once.
        let snapshot = jobs.jobs.loaded_job(launch.job_id).unwrap();
        assert_eq!(snapshot.loaded.launch_channel, DwHandle(103));
        jobs.jobs
            .release_launch_channel(launch.job_id, 103)
            .unwrap();
        platform
            .close_handle(snapshot.loaded.launch_channel)
            .unwrap();

        // The value `accept_reserved_launch` hands back to a scripted orphan
        // caller must be the released model state, not the stale snapshot.
        let accepted = jobs.jobs.loaded_job(launch.job_id).unwrap();
        assert_eq!(accepted.loaded.launch_channel, DwHandle(0));
        assert_eq!(accepted.loaded.process, DwHandle(101));
        assert_eq!(accepted.task_group, 102);

        let result = reap_job(&mut platform, &mut waits, &mut jobs, accepted).unwrap();
        assert_eq!(result.cleanup_result, 0);
        assert_eq!(
            &platform.closed[..platform.close_count],
            &[DwHandle(103), DwHandle(101), DwHandle(102)]
        );
        assert_eq!(jobs.jobs.live_jobs(), 0);
    }

    #[test]
    fn registry_drain_propagates_sticky_cleanup_and_retries_only_once_per_tick() {
        let mut platform = MockPlatform::new();
        platform.fail_close = Some(DwHandle(103));
        let mut waits = TerminalWaits;
        let mut jobs = JobDispatcher::new();
        let owner = grant(EndpointKind::LaunchSession, 1, 1);
        jobs.install_session(owner, DwHandle(90)).unwrap();
        let launch = jobs.jobs.begin_launch(reservation(1)).unwrap();
        jobs.jobs.commit_launch(launch, 101, 102, 103).unwrap();

        assert_eq!(
            drain_job_dispatcher(&mut platform, &mut waits, &mut jobs),
            Err(InitError::Cleanup)
        );
        assert_eq!(jobs.jobs.live_jobs(), 1);
        assert_eq!(
            &platform.closed[..platform.close_count],
            &[DwHandle(90), DwHandle(103), DwHandle(101), DwHandle(102)]
        );

        platform.fail_close = None;
        assert_eq!(
            drain_job_dispatcher(&mut platform, &mut waits, &mut jobs),
            Err(InitError::Cleanup)
        );
        assert_eq!(jobs.jobs.live_jobs(), 0);
        assert_eq!(platform.closed[platform.close_count - 1], DwHandle(103));
    }

    fn ready_registry() -> (SystemInit, RegistryNativeAttempt) {
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
            registry_startup_profile: StartupProfile::BootstrapRegistry,
            devmgr_startup_profile: StartupProfile::EarlyBootStub,
        };
        controller.become_operational().unwrap();
        controller.begin_registry(0, 1, 0x1001).unwrap();
        let reservation = controller
            .reserve_attempt(RoleId::Registryd, 1, 0x1001)
            .unwrap();
        let loaded = LoadedProcess {
            process: DwHandle(31),
            launch_channel: DwHandle(32),
        };
        let task_group = DwHandle(30);
        controller
            .install_attempt(AttemptResources {
                role: RoleId::Registryd,
                generation: 1,
                transaction_id: 0x1001,
                executable_identity: [1; 32],
                startup_profile: StartupProfile::BootstrapRegistry,
                task_group,
                process: loaded.process,
                launch_channel: loaded.launch_channel,
                mappings: 0,
                reservation,
            })
            .unwrap();
        controller
            .child_started(RoleId::Registryd, 1, 0x1001, 1)
            .unwrap();
        controller.ready(RoleId::Registryd, 1, 0x1001, 2).unwrap();
        (
            controller,
            RegistryNativeAttempt {
                active: ActiveNativeRole {
                    role: RoleId::Registryd,
                    generation: 1,
                    transaction_id: 0x1001,
                    loaded,
                    task_group,
                },
                control_channel: DwHandle(33),
                ready_at: 2,
            },
        )
    }

    #[test]
    fn registry_init_send_failure_is_closed_once_by_controller() {
        let image = executable();
        let bootfs = service_bootfs(REGISTRY_PATH, &image);
        let mut controller = starting_registry(&image);
        let mut platform = MockPlatform::new();
        platform.task_group = Some(DwHandle(22));
        let mut loader = InitSendLoader::new();
        let mut waits = TerminalWaits;
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };

        assert!(matches!(
            launch_registry(
                &mut platform,
                &mut loader,
                &mut waits,
                &mut controller,
                authority,
                &bootfs,
                None,
            ),
            Err(InitError::Loader(LoadError::Platform {
                stage: wyrmroot_loader::process::LoadStage::InitSend,
                rollback_failed: false,
                ..
            }))
        ));
        assert_eq!(loader.transferred_service, Some(DwHandle(21)));
        assert_eq!(loader.close_count(DwHandle(21)), 0);
        assert_eq!(
            platform.closed[..platform.close_count]
                .iter()
                .filter(|handle| **handle == DwHandle(21))
                .count(),
            1
        );
        assert_eq!(
            platform.closed[..platform.close_count],
            [DwHandle(21), DwHandle(20), DwHandle(22)]
        );
        assert_eq!(controller.outstanding_reservations(), 0);
    }

    #[test]
    fn peer_init_send_failure_is_closed_once_after_registry_install() {
        let image = executable();
        let bootfs = service_bootfs(PUBLISHER_PATH, &image);
        let mut topology = RegistryTopology::new(7).unwrap();
        let mut platform = MockPlatform::new();
        platform.task_group = Some(DwHandle(22));
        let mut loader = InitSendLoader::new();
        let mut waits = TerminalWaits;
        let authority = LoadAuthority {
            parent_root: DwHandle(1),
            bootfs: DwHandle(2),
            task_group: DwHandle(3),
        };

        assert!(matches!(
            launch_peer(
                &mut platform,
                &mut loader,
                &mut waits,
                authority,
                &bootfs,
                DwHandle(10),
                &mut topology,
                PeerKind::Publisher { operation: 1 },
            ),
            Err(PeerLaunchError::InstallCommitted(InitError::Loader(
                LoadError::Platform {
                    stage: wyrmroot_loader::process::LoadStage::InitSend,
                    rollback_failed: false,
                    ..
                }
            )))
        ));
        assert_eq!(loader.transferred_service, Some(DwHandle(21)));
        assert_eq!(loader.close_count(DwHandle(21)), 0);
        assert_eq!(
            platform.closed[..platform.close_count]
                .iter()
                .filter(|handle| **handle == DwHandle(21))
                .count(),
            1
        );
        assert_eq!(
            platform.closed[..platform.close_count],
            [DwHandle(21), DwHandle(22)]
        );
        assert!(!platform.closed[..platform.close_count].contains(&DwHandle(20)));
    }

    #[test]
    fn poison_consumes_every_native_owner_when_clock_transition_cannot_start() {
        let (mut controller, registry) = ready_registry();
        let mut platform = MockPlatform::new();
        let mut waits = TerminalWaits;

        assert_eq!(
            poison_registry_generation(&mut platform, &mut waits, &mut controller, registry, false,),
            Err(InitError::Native(FAILURE))
        );
        assert_eq!(platform.terminate_count, 1);
        assert_eq!(
            platform.closed[..platform.close_count],
            [DwHandle(32), DwHandle(31), DwHandle(30), DwHandle(33)]
        );
        assert!(controller.resources(RoleId::Registryd).is_none());
        assert_eq!(controller.mode(), SystemMode::Fatal);
    }

    #[test]
    fn poison_transition_rejection_still_consumes_native_owners_and_retires_fatal() {
        let (mut controller, mut registry) = ready_registry();
        registry.active.transaction_id += 1;
        let mut platform = MockPlatform::new();
        platform.now = Some(3);
        let mut waits = TerminalWaits;

        assert_eq!(
            poison_registry_generation(&mut platform, &mut waits, &mut controller, registry, false,),
            Err(InitError::Restart(
                RestartTransitionError::TransactionMismatch
            ))
        );
        assert_eq!(platform.terminate_count, 1);
        assert_eq!(
            platform.closed[..platform.close_count],
            [DwHandle(32), DwHandle(31), DwHandle(30), DwHandle(33)]
        );
        assert!(controller.resources(RoleId::Registryd).is_none());
        assert_eq!(controller.mode(), SystemMode::Fatal);
        assert!(!matches!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::CleaningUp { .. })
        ));
    }

    #[test]
    fn poison_timestamp_overflow_records_failure_without_stranding_cleanup() {
        let (mut controller, registry) = ready_registry();
        let mut platform = MockPlatform::new();
        platform.now = Some(u64::MAX);
        let mut waits = TerminalWaits;

        assert_eq!(
            poison_registry_generation(&mut platform, &mut waits, &mut controller, registry, false,),
            Err(InitError::Restart(
                RestartTransitionError::ArithmeticOverflow
            ))
        );
        assert_eq!(platform.terminate_count, 1);
        assert_eq!(
            platform.closed[..platform.close_count],
            [DwHandle(32), DwHandle(31), DwHandle(30), DwHandle(33)]
        );
        assert_eq!(controller.outstanding_reservations(), 0);
        assert!(controller.resources(RoleId::Registryd).is_none());
        assert_eq!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::PermanentFailure {
                final_failure: AttemptFailure::WaitFailed,
                cleanup: CleanupDisposition::Complete,
            })
        );
        assert_eq!(controller.mode(), SystemMode::Degraded);
        assert!(!matches!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::CleaningUp { .. })
        ));
    }

    #[test]
    fn poison_timestamp_overflow_preserves_cleanup_failure_precedence() {
        let (mut controller, registry) = ready_registry();
        let mut platform = MockPlatform::new();
        platform.now = Some(u64::MAX);
        platform.fail_close = Some(registry.control_channel);
        let mut waits = TerminalWaits;

        assert_eq!(
            poison_registry_generation(&mut platform, &mut waits, &mut controller, registry, false,),
            Err(InitError::Cleanup)
        );
        assert_eq!(platform.terminate_count, 1);
        assert_eq!(
            platform.closed[..platform.close_count],
            [DwHandle(32), DwHandle(31), DwHandle(30), DwHandle(33)]
        );
        assert!(controller.resources(RoleId::Registryd).is_some());
        assert_eq!(controller.outstanding_reservations(), 1);
        assert_eq!(controller.mode(), SystemMode::Degraded);
        assert_eq!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::PermanentFailure {
                final_failure: AttemptFailure::WaitFailed,
                cleanup: CleanupDisposition::Failed,
            })
        );
    }

    #[test]
    fn poison_cleanup_failure_is_permanent_and_blocks_replacement() {
        let (mut controller, registry) = ready_registry();
        let mut platform = MockPlatform::new();
        platform.now = Some(3);
        platform.fail_close = Some(registry.control_channel);
        let mut waits = TerminalWaits;

        assert_eq!(
            poison_registry_generation(&mut platform, &mut waits, &mut controller, registry, true,),
            Ok(true)
        );
        assert!(matches!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::PermanentFailure { .. })
        ));
        assert_eq!(controller.mode(), SystemMode::Degraded);
        assert!(
            controller
                .start_replacement(RoleId::Registryd, 4, 2, 0x1002)
                .is_err()
        );
    }

    #[test]
    fn poison_complete_cleanup_admits_exact_next_registry_generation() {
        let (mut controller, registry) = ready_registry();
        let mut platform = MockPlatform::new();
        platform.now = Some(3);
        platform.allow_wait = true;
        let mut waits = TerminalWaits;

        assert_eq!(
            poison_registry_generation(&mut platform, &mut waits, &mut controller, registry, false,),
            Ok(false)
        );
        assert!(matches!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::Starting {
                generation: 2,
                transaction_id: 0x1002,
                ..
            })
        ));
    }

    #[test]
    fn ordinary_aged_registry_cleanup_remains_permanent_after_startup_window() {
        let (mut controller, registry) = ready_registry();
        let mut platform = MockPlatform::new();
        platform.now = Some(3_000_000_000);
        platform.allow_wait = true;
        let mut waits = TerminalWaits;
        assert_eq!(
            poison_registry_generation_before(
                &mut platform,
                &mut waits,
                &mut controller,
                registry,
                false,
                Some(4_000_000_000),
            ),
            Ok(true)
        );
        assert_eq!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::PermanentFailure {
                final_failure: AttemptFailure::WaitFailed,
                cleanup: CleanupDisposition::Complete,
            })
        );
        assert_eq!(controller.outstanding_reservations(), 0);
        assert_eq!(controller.mode(), SystemMode::Degraded);
        assert_eq!(platform.now, Some(3_000_000_000));
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn admitted_aged_registry_cleanup_advances_only_after_exact_retirement_and_backoff() {
        let (mut controller, registry) = ready_registry();
        let mut platform = MockPlatform::new();
        platform.now = Some(3_000_000_000);
        platform.allow_wait = true;
        let mut waits = TerminalWaits;
        assert_eq!(
            retire_registry_for_recovery_before(
                &mut platform,
                &mut waits,
                &mut controller,
                registry,
                Some(4_000_000_000),
            ),
            Ok(false)
        );
        assert_eq!(platform.terminate_count, 1);
        assert_eq!(
            platform.closed[..platform.close_count],
            [DwHandle(32), DwHandle(31), DwHandle(30), DwHandle(33)]
        );
        assert_eq!(controller.outstanding_reservations(), 0);
        assert!(controller.resources(RoleId::Registryd).is_none());
        assert_eq!(platform.now, Some(3_025_000_001));
        assert_eq!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::Starting {
                attempt: 2,
                generation: 2,
                transaction_id: 0x1002,
                deadline_ns: 4_025_000_001,
            })
        );
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn admitted_registry_cleanup_failure_keeps_accounting_and_forbids_replacement() {
        let (mut controller, registry) = ready_registry();
        let mut platform = MockPlatform::new();
        platform.now = Some(3_000_000_000);
        platform.fail_close = Some(registry.control_channel);
        let mut waits = TerminalWaits;
        assert_eq!(
            retire_registry_for_recovery_before(
                &mut platform,
                &mut waits,
                &mut controller,
                registry,
                Some(4_000_000_000),
            ),
            Ok(true)
        );
        assert_eq!(controller.outstanding_reservations(), 1);
        assert!(controller.resources(RoleId::Registryd).is_some());
        assert_eq!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::PermanentFailure {
                final_failure: AttemptFailure::WaitFailed,
                cleanup: CleanupDisposition::Failed,
            })
        );
        assert_eq!(platform.close_count, 4);
        assert_eq!(platform.now, Some(3_000_000_000));
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn recovery_episode_does_not_extend_the_existing_action_cap() {
        for deadline in [3_000_000_000, 3_025_000_001] {
            let (mut controller, registry) = ready_registry();
            let mut platform = MockPlatform::new();
            platform.now = Some(3_000_000_000);
            platform.allow_wait = true;
            let mut waits = TerminalWaits;
            assert_eq!(
                retire_registry_for_recovery_before(
                    &mut platform,
                    &mut waits,
                    &mut controller,
                    registry,
                    Some(deadline),
                ),
                Err(InitError::Supervision)
            );
            assert!(!matches!(
                controller.role_state(RoleId::Registryd),
                Some(RestartState::Starting { .. })
            ));
            assert_eq!(controller.outstanding_reservations(), 0);
            assert_eq!(platform.close_count, 4);
            assert_eq!(platform.now, Some(deadline));
        }
    }

    #[test]
    fn rejected_topology_restart_cleans_the_newly_ready_registry() {
        let (mut controller, registry) = ready_registry();
        let mut topology = RegistryTopology::new(2).unwrap();
        let mut platform = MockPlatform::new();
        platform.now = Some(3);
        platform.allow_wait = true;
        let mut waits = TerminalWaits;

        assert_eq!(
            restart_topology_or_poison(
                &mut platform,
                &mut waits,
                &mut controller,
                &mut topology,
                registry,
            ),
            Err(InitError::Wyr1BModel(
                crate::wyr1b::JobError::StaleGeneration
            ))
        );
        assert_eq!(platform.terminate_count, 1);
        assert_eq!(
            platform.closed[..platform.close_count],
            [DwHandle(32), DwHandle(31), DwHandle(30), DwHandle(33)]
        );
        assert!(controller.resources(RoleId::Registryd).is_none());
    }

    #[cfg(feature = "wyr1e8-selector33")]
    #[test]
    fn expired_topology_handoff_cleans_owned_registry_without_restart() {
        let (mut controller, registry) = ready_registry();
        let mut topology = RegistryTopology::new(1).unwrap();
        let mut platform = MockPlatform::new();
        platform.now = Some(200);
        let mut waits = TerminalWaits;

        assert_eq!(
            restart_topology_or_poison_before(
                &mut platform,
                &mut waits,
                &mut controller,
                &mut topology,
                registry,
                Some(200),
            ),
            Err(InitError::Supervision)
        );
        assert_eq!(topology.generation(), 1);
        assert_eq!(platform.terminate_count, 1);
        assert_eq!(
            &platform.closed[..platform.close_count],
            &[DwHandle(32), DwHandle(31), DwHandle(30), DwHandle(33)]
        );
        assert!(controller.resources(RoleId::Registryd).is_none());
        assert!(matches!(
            controller.role_state(RoleId::Registryd),
            Some(RestartState::Backoff { .. })
        ));
    }

    #[test]
    fn publication_install_moves_exact_endpoint_and_keeps_logical_id_distinct() {
        let publication = grant(EndpointKind::Publication, 41, 9);
        let mut platform = MockPlatform::new();
        install_publication(&mut platform, DwHandle(10), publication, DwHandle(11), 1).unwrap();
        assert_eq!(platform.transfer.handle, DwHandle(11));
        assert_eq!(platform.transfer.operation, DW_HANDLE_TRANSFER_MOVE);
        assert_eq!(platform.transfer.requested_rights, CHILD_CHANNEL_RIGHTS);
        assert_eq!(platform.queried[..platform.query_count], [DwHandle(11)]);
        let parsed = parse(&platform.sent[..platform.sent_len], 1).unwrap();
        let Message::InstallPublication(install) = parsed.message else {
            panic!("wrong install type")
        };
        assert_eq!(install.endpoint_id, publication.endpoint_id);
        assert_eq!(install.endpoint_generation, publication.endpoint_generation);
        assert_eq!(install.publication_id, FIRST_PUBLICATION_ID);
        assert_ne!(install.publication_id, install.endpoint_id);
    }

    #[test]
    fn consoled_stream_descriptors_survive_init_then_reduce_at_actual_loader_move() {
        use deepwyrm_syscall::DW_RIGHT_DUPLICATE;
        use wyrmroot_loader::launch::{CHILD_CHANNEL_TRANSFER_RIGHTS, parse_init};
        use wyrmroot_loader::process::{JobLoadRequest, load_job_process};

        let streams = [DwHandle(0x901), DwHandle(0x902), DwHandle(0x903)];
        let mut platform = MockPlatform::new();
        for stream in streams {
            let transfer = consoled_stream_transfer::move_transfer(stream);
            assert_eq!(transfer.handle, stream);
            assert_eq!(transfer.operation, DW_HANDLE_TRANSFER_MOVE);
            assert_eq!(transfer.requested_rights, CHILD_CHANNEL_TRANSFER_RIGHTS);
            assert_eq!(transfer.requested_rights.0 & DW_RIGHT_DUPLICATE.0, 0);
            assert_eq!((transfer.reserved0, transfer.reserved), (0, [0; 2]));
            // Query the authority delivered by the actual first-hop descriptor.
            platform.fresh_rights = transfer.requested_rights;
            validate_controller_channel(&mut platform, stream).unwrap();
        }
        assert_eq!(platform.queried[..platform.query_count], streams);

        let image = executable();
        let mut loader = InitSendLoader::new();
        loader.fail_init = false;
        load_job_process(
            &mut loader,
            LoadAuthority {
                parent_root: DwHandle(1),
                task_group: DwHandle(2),
                bootfs: DwHandle(3),
            },
            JobLoadRequest {
                image: &image,
                policy_path: "bin/console-echo",
                argv: &["bin/console-echo"],
                environment: &[],
                streams: &streams,
                transaction_id: 0xd500,
            },
        )
        .unwrap();
        assert_eq!(loader.sent_transfers.len(), 3);
        let mut received = [DwReceivedHandleInfoV1::default(); 3];
        for (index, transfer) in loader.sent_transfers.iter().enumerate() {
            assert_eq!(transfer.handle, streams[index]);
            assert_eq!(transfer.operation, DW_HANDLE_TRANSFER_MOVE);
            assert_eq!(transfer.requested_rights, CHILD_CHANNEL_RIGHTS);
            assert_eq!(
                transfer.requested_rights.0 & (DW_RIGHT_TRANSFER.0 | DW_RIGHT_DUPLICATE.0),
                0
            );
            received[index] = DwReceivedHandleInfoV1 {
                handle: transfer.handle,
                rights: transfer.requested_rights,
                object_type: DW_OBJECT_TYPE_CHANNEL,
                ..DwReceivedHandleInfoV1::default()
            };
        }
        parse_init(LaunchProfile::JobV2Streams, &loader.sent_init, &received).unwrap();
    }

    #[test]
    fn consoled_stream_ingress_rejects_early_reduction_and_duplicate_authority() {
        use deepwyrm_syscall::DW_RIGHT_DUPLICATE;

        let transfer = consoled_stream_transfer::move_transfer(DwHandle(0x901));
        for rights in [
            DwRights(transfer.requested_rights.0 & !DW_RIGHT_TRANSFER.0),
            DwRights(transfer.requested_rights.0 | DW_RIGHT_DUPLICATE.0),
        ] {
            let mut platform = MockPlatform::new();
            platform.fresh_rights = rights;
            assert_eq!(
                validate_controller_channel(&mut platform, transfer.handle),
                Err(InitError::ResourceIdentityMismatch)
            );
            assert_eq!(platform.query_count, 1);
        }
    }

    #[test]
    fn controller_pairs_are_broad_and_move_reduces_only_in_descriptor() {
        let mut platform = MockPlatform::new();
        assert_eq!(
            create_controller_channel_pair(&mut platform),
            Ok((DwHandle(20), DwHandle(21)))
        );
        assert_eq!(platform.created_rights, CONTROLLER_CHANNEL_RIGHTS);

        let client = grant(EndpointKind::RegistryClient, 44, 5);
        let client_id = CLIENT_ID + 1;
        install_client(&mut platform, DwHandle(10), client, DwHandle(20), client_id).unwrap();
        assert_eq!(platform.queried[0], DwHandle(20));
        assert_eq!(platform.transfer.requested_rights, CHILD_CHANNEL_RIGHTS);
        assert_ne!(CONTROLLER_CHANNEL_RIGHTS, CHILD_CHANNEL_RIGHTS);
        let parsed = parse(&platform.sent[..platform.sent_len], 1).unwrap();
        let Message::InstallClient(install) = parsed.message else {
            panic!("wrong install type")
        };
        assert_eq!(install.client_id, client_id);
    }

    #[test]
    fn staged_channel_cleanup_is_affine_and_reverse_ordered() {
        let mut platform = MockPlatform::new();
        let mut owner = StagedChannelPair::new(DwHandle(20), DwHandle(21));
        assert!(owner.cleanup(&mut platform));
        assert!(owner.cleanup(&mut platform));
        assert_eq!(
            platform.closed[..platform.close_count],
            [DwHandle(21), DwHandle(20)]
        );
    }

    #[test]
    fn committed_move_is_never_closed_by_local_rollback() {
        let mut platform = MockPlatform::new();
        let mut owner = StagedChannelPair::new(DwHandle(20), DwHandle(21));
        owner.commit_first_move().unwrap();
        assert!(owner.cleanup(&mut platform));
        assert_eq!(platform.closed[..platform.close_count], [DwHandle(21)]);
    }

    #[test]
    fn install_boundary_classification_is_exact_and_cleanup_sticky() {
        assert_eq!(
            classify_gate_run_error(false, false, InitError::Native(FAILURE)),
            GateRunError::PreInstall(InitError::Native(FAILURE))
        );
        assert_eq!(
            classify_gate_run_error(false, true, InitError::Native(FAILURE)),
            GateRunError::CleanupFailed(InitError::Cleanup)
        );
        assert_eq!(
            classify_gate_run_error(true, true, InitError::Native(FAILURE)),
            GateRunError::InstallCommitted {
                error: InitError::Native(FAILURE),
                cleanup_failed: true,
            }
        );
    }

    #[test]
    fn every_peer_fault_stage_stays_on_its_exact_install_side() {
        for stage in [
            PeerLaunchStage::Archive,
            PeerLaunchStage::ArtifactLookup,
            PeerLaunchStage::ArtifactValidation,
            PeerLaunchStage::Grant,
            PeerLaunchStage::Correlation,
            PeerLaunchStage::TaskGroup,
            PeerLaunchStage::ChannelPair,
            PeerLaunchStage::InstallMove,
        ] {
            assert!(matches!(
                peer_launch_error(stage, InitError::Native(FAILURE)),
                PeerLaunchError::PreInstall(InitError::Native(FAILURE))
            ));
        }
        for stage in [
            PeerLaunchStage::PeerCapability,
            PeerLaunchStage::Load,
            PeerLaunchStage::Clock,
            PeerLaunchStage::Deadline,
            PeerLaunchStage::Ready,
        ] {
            assert!(matches!(
                peer_launch_error(stage, InitError::Native(FAILURE)),
                PeerLaunchError::InstallCommitted(InitError::Native(FAILURE))
            ));
        }
    }

    #[test]
    fn preinstall_retry_executes_once_but_cleanup_failure_is_sticky() {
        let mut recoverable_calls = 0;
        let recovered = retry_preinstall_once(|| {
            recoverable_calls += 1;
            if recoverable_calls == 1 {
                Err(PeerLaunchError::PreInstall(InitError::Native(FAILURE)))
            } else {
                Ok(7_u8)
            }
        });
        assert_eq!(recovered, Ok(7));
        assert_eq!(recoverable_calls, 2);

        let mut cleanup_calls = 0;
        let blocked = retry_preinstall_once(|| {
            cleanup_calls += 1;
            Err::<u8, _>(PeerLaunchError::PreInstall(InitError::Cleanup))
        });
        assert_eq!(
            blocked,
            Err(PeerLaunchError::PreInstall(InitError::Cleanup))
        );
        assert_eq!(cleanup_calls, 1);
    }

    #[test]
    fn move_rejects_stale_source_rights_before_atomic_send() {
        let mut platform = MockPlatform::new();
        platform.fresh_rights = CHILD_CHANNEL_RIGHTS;
        let client = grant(EndpointKind::RegistryClient, 44, 5);
        assert_eq!(
            install_client(&mut platform, DwHandle(10), client, DwHandle(20), CLIENT_ID,),
            Err(InitError::ResourceIdentityMismatch)
        );
        assert_eq!(platform.sent_len, 0);
        assert_eq!(platform.queried[..platform.query_count], [DwHandle(20)]);
    }

    #[test]
    fn gate_actor_uses_installed_endpoint_generation_not_role_generation() {
        let publisher = grant(EndpointKind::Publication, 41, 99);
        let client = grant(EndpointKind::RegistryClient, 42, 77);
        let record = gate_record(
            GateMessageType::ConfigurePublisher,
            GateConfig { nonce: 1 },
            publisher,
            client,
            1,
        );
        assert_eq!((record.actor_id, record.actor_generation), (41, 3));
        assert_ne!(record.actor_generation, publisher.role_generation);
    }

    #[test]
    fn stale_gate_report_is_rejected_without_advancing_state() {
        let publisher = grant(EndpointKind::Publication, 41, 99);
        let client = grant(EndpointKind::RegistryClient, 42, 77);
        let expected = gate_record(
            GateMessageType::Published,
            GateConfig { nonce: 1 },
            publisher,
            client,
            2,
        );
        let stale = GateRecord {
            operation_id: 1,
            ..expected
        };
        assert_eq!(
            expect_gate(stale, expected),
            Err(InitError::Wyr1BGateMismatch)
        );
    }

    /// The declared closure episode, on the production recovery path.
    ///
    /// `DW1_WYR1_FINAL_CLOSURE_CONTRACT.md` §5.4 and §11 item 4. This is the
    /// slice's central claim: the episode reaches `DEGRADED_RECOVERY` with the
    /// driver and the console still owned, which is what makes `status`,
    /// `services` and controlled shell exit/restart possible afterwards.
    /// Before the §5.3.1 narrowing this test could not pass -- `recover_devmgr`
    /// retired both before it knew devmgr would not come back.
    #[cfg(feature = "wyr1f-closure")]
    #[test]
    fn the_declared_episode_degrades_with_the_console_and_driver_retained() {
        let image = executable();
        let generation = [0x47; 32];
        let mut manifest = [0u8; 80];
        manifest[48..80].copy_from_slice(&generation);
        let mut builder = BootfsBuilder::new();
        builder
            .add(MANIFEST_PATH.as_bytes(), &manifest, FileMode::ReadOnly)
            .unwrap();
        builder
            .add(b"system/devmgr", &image, FileMode::Executable)
            .unwrap();
        // The replacement loop reads the device manifest before its first
        // attempt, whether or not the episode then refuses that attempt.
        builder
            .add(
                crate::wyr1c_native::DEVICE_MANIFEST_PATH.as_bytes(),
                &[0u8; 16],
                FileMode::ReadOnly,
            )
            .unwrap();
        let bootfs = builder.build().unwrap();
        let mut platform = ShellPlatform::new();
        platform.allow_wait_until = true;
        platform.bootfs = Some(bootfs.clone());
        let mut loader = InitSendLoader::new();
        loader.fail_init = false;
        let mut waits = AcceptedJobV2Waits {
            transaction_id: 0xE8B5_0002,
            profile: LaunchProfile::EarlyBootStub,
            exited: true,
            console_status_lost_process: None,
            running_process: None,
        };
        let console = InstalledPeer {
            grant: EndpointGrant {
                registry_generation: 1,
                endpoint_id: 21,
                endpoint_generation: 1,
                role_generation: 1,
                kind: EndpointKind::LaunchSession,
            },
            loaded: LoadedProcess {
                process: DwHandle(0xF1B0_0001),
                launch_channel: DwHandle(0xF1B0_0002),
            },
            task_group: DwHandle(0xF1B0_0003),
        };
        let driver_request = crate::wyr1c_native::wyr1f_fixture_driver_request();
        // Deliver the trigger eight times. A second episode, a re-armed one, or
        // a reset retry budget would all show up as a different outcome.
        let outcome = crate::wyr1c_native::exercise_wyr1f_degraded_episode(
            &mut platform,
            &mut loader,
            &mut waits,
            &bootfs,
            wyrmroot_runtime::sha256::digest(&image),
            1,
            console,
            driver_request,
            8,
        )
        .expect("the declared episode must reach a terminal supervisor result");

        assert_eq!(outcome.mode, crate::SystemMode::Degraded);
        assert_eq!(outcome.result, crate::RecoveryResult::Degraded);
        // Exactly one transition and one authoritative record, not eight.
        assert_eq!(outcome.degraded_transitions, 1);
        assert_eq!(outcome.permanent_failure_records, 1);
        assert!(matches!(
            outcome.devmgr_state,
            Some(RestartState::PermanentFailure { .. })
        ));
        // The dependency-preservation rule: both survive the episode.
        assert_eq!(outcome.console, Some(console), "console retained");
        assert!(outcome.driver_retained, "driver retained");
        // DEGRADED is a trustworthy substrate, not FATAL.
        assert_ne!(outcome.mode, crate::SystemMode::Fatal);
        // The episode is closed: ordinary activation is no longer refused, so
        // nothing the shell does afterwards re-enters it.
        assert!(!outcome.refuses_activation);
    }

    /// The product's own registry recovery, with nothing E8 about it.
    ///
    /// Reset card R7E. Before this test the only host test that reached
    /// `recover_registry` was the E8 producer fixture, and it could only reach
    /// it by launching an actor at a magic path with a matching nonce through a
    /// live ShellJobs session. The ordinary path -- no episode open, so
    /// `recovery_deadline` answers `None` and none of the selector's episode
    /// arithmetic runs -- had no coverage in the tree. That is what blocked
    /// R7B-4's D1b: the sniff could not be removed while it was the only way
    /// any test reached recovery at all.
    #[cfg(feature = "wyr1e-production")]
    #[test]
    fn ordinary_registry_recovery_needs_no_shell_no_trigger_and_no_barrier() {
        let image = executable();
        // The retained closure the relaunch looks up: the registry executable
        // and the manifest that names its generation.
        let generation = [0x47; 32];
        let mut manifest = [0u8; 80];
        manifest[48..80].copy_from_slice(&generation);
        let entry = LaunchPolicyEntry {
            path: "bin/hello",
            content_sha256: wyrmroot_runtime::sha256::digest(&image),
            startup_abi: 2,
            profile_id: 1,
            allow_no_streams: true,
            allow_three_streams: true,
        };
        let mut policy = [0u8; 512];
        let policy_len = encode_launch_policy(generation, &[entry], &mut policy).unwrap();
        let mut builder = BootfsBuilder::new();
        builder
            .add(b"bin/hello", &image, FileMode::Executable)
            .unwrap();
        builder
            .add(
                LAUNCH_POLICY_PATH.as_bytes(),
                &policy[..policy_len],
                FileMode::ReadOnly,
            )
            .unwrap();
        builder
            .add(MANIFEST_PATH.as_bytes(), &manifest, FileMode::ReadOnly)
            .unwrap();
        builder
            .add(b"system/registryd", &image, FileMode::Executable)
            .unwrap();
        let bootfs = builder.build().unwrap();
        let mut platform = ShellPlatform::new();
        platform.allow_wait_until = true;
        platform.bootfs = Some(bootfs.clone());
        let mut loader = InitSendLoader::new();
        loader.fail_init = false;
        // The replacement's launch transaction is the successor of the one the
        // fixture's live registry holds, so the child's exact READY is for it.
        let mut waits = AcceptedJobV2Waits {
            transaction_id: 0xE8B5_0002,
            profile: LaunchProfile::BootstrapRegistry,
            exited: true,
            console_status_lost_process: None,
            running_process: None,
        };
        // Devmgr's two answers: it reports waiting for a registry, then
        // acknowledges the fresh binding. Both are ordinary controller frames;
        // nothing about them is E8.
        let devmgr_control = crate::wyr1c_native::E8_REGISTRY_FIXTURE_DEVMGR_CONTROL;
        let mut waiting = [0u8; wyrmroot_device_proto::controller::STATUS_BYTES];
        wyrmroot_device_proto::controller::encode(
            wyrmroot_device_proto::controller::ControllerMessage::Status {
                supervisor_generation: wyrmroot_device_proto::coordinator::SupervisorGeneration(1),
                binding: None,
                transaction_id: 9,
                status:
                    wyrmroot_device_proto::controller::StatusCode::OperationalWaitingForRegistry,
                attempt_generation: None,
            },
            &mut waiting,
        )
        .unwrap();
        platform.push(devmgr_control, waiting.to_vec(), &[]);
        let mut rebound = [0u8; wyrmroot_device_proto::controller::STATUS_BYTES];
        wyrmroot_device_proto::controller::encode(
            wyrmroot_device_proto::controller::ControllerMessage::Status {
                supervisor_generation: wyrmroot_device_proto::coordinator::SupervisorGeneration(1),
                binding: Some(wyrmroot_device_proto::RegistryBinding {
                    generation: wyrmroot_device_proto::coordinator::RegistryGeneration(2),
                    endpoint: wyrmroot_device_proto::coordinator::RegistryEndpoint {
                        id: wyrmroot_device_proto::coordinator::RegistryEndpointId(1),
                        generation: wyrmroot_device_proto::coordinator::RegistryEndpointGeneration(
                            1,
                        ),
                    },
                }),
                transaction_id: 10,
                status: wyrmroot_device_proto::controller::StatusCode::OperationalResourceOwned,
                attempt_generation: None,
            },
            &mut rebound,
        )
        .unwrap();
        platform.push(devmgr_control, rebound.to_vec(), &[]);
        let (result, generation, role) = crate::wyr1c_native::exercise_ordinary_registry_recovery(
            &mut platform,
            &mut loader,
            &mut waits,
            &bootfs,
            wyrmroot_runtime::sha256::digest(&image),
            1,
        )
        .expect("the product's ordinary registry recovery must complete");
        assert_eq!(result, crate::RecoveryResult::Recovered);
        assert!(
            generation > 1,
            "recovery must restart the topology on a fresh registry generation"
        );
        // The replacement is the role's second attempt at its second
        // generation, which is what distinguishes a real relaunch from a
        // recovery that merely reported success.
        assert!(
            matches!(
                role,
                Some(RestartState::Ready {
                    attempt: 2,
                    generation: 2,
                    ..
                })
            ),
            "the replacement registry must be live: {role:?}"
        );
        // The bootfs deliberately omits `system/devmgr`: if the publication
        // rebind ever fails, the fall into `recover_devmgr_after_error` is
        // loud instead of letting devmgr recovery quietly stand in for the
        // registry recovery under test.
    }

    #[cfg(feature = "wyr1e8-selector33")]
    mod e8_producer_fixture {
        include!("wyr1e8_producer_fixture.rs");
    }
}
