//! Selector-33 WRE1 v1.1 evidence for staged shell recovery.

#![cfg_attr(test, allow(dead_code))]

use deepwyrm_syscall::DwReceivedHandleInfoV1;
use wyrmroot_launch_proto::{
    Message, MessageType, Reservation, TerminationClassification, TerminationResult, parse_message,
};

use crate::InitError;

pub(crate) const RECORD_BYTES: usize = 192;
const MAGIC: [u8; 4] = *b"WRE1";
const MAJOR: u16 = 1;
const MINOR: u16 = 1;
const TYPE_SHELL_READY: u32 = 1;
const TYPE_SHELLJOBS_TRANSACTION: u32 = 2;
const TYPE_SHELL_RETIRED: u32 = 3;
const TYPE_TERMINAL: u32 = 255;
const ERROR_OUTCOME_BIT: u32 = 0x8000_0000;
const MAX_RECORDS: u64 = 128;
const READY_DIGEST_DOMAIN: &[u8] = b"WRE1-READY-V1.1\0";
const RETIRED_DIGEST_DOMAIN: &[u8] = b"WRE1-RETIRED-V1.1\0";
const STATUS_LOST: u32 = 0x5745_0104;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ShellTuple {
    pub(crate) console_generation: u64,
    pub(crate) status_generation: u64,
    pub(crate) shell_generation: u64,
    pub(crate) outer_launch_transaction: u64,
    pub(crate) outer_job_id: u64,
    pub(crate) registry_generation: u64,
    pub(crate) registry_endpoint_id: u64,
    pub(crate) registry_endpoint_generation: u64,
    pub(crate) shell_jobs_connection_id: u64,
    pub(crate) shell_jobs_generation: u64,
}

impl ShellTuple {
    const fn valid(self) -> bool {
        self.console_generation != 0
            && self.status_generation != 0
            && self.shell_generation != 0
            && self.outer_launch_transaction != 0
            && self.outer_job_id != 0
            && self.registry_generation != 0
            && self.registry_endpoint_id != 0
            && self.registry_endpoint_generation != 0
            && self.shell_jobs_connection_id != 0
            && self.shell_jobs_generation != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SerialReady {
    pub(crate) console_generation: u64,
    pub(crate) status_generation: u64,
    pub(crate) shell_generation: u64,
    pub(crate) attach_transaction: u64,
    pub(crate) stream_generation: u64,
    pub(crate) bundle_generation: u64,
}

impl SerialReady {
    const fn valid(self) -> bool {
        self.console_generation != 0
            && self.status_generation != 0
            && self.shell_generation != 0
            && self.attach_transaction != 0
            && self.stream_generation != 0
            && self.bundle_generation != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SerialFacts {
    pub(crate) publication_generation: u64,
    pub(crate) device_role_id: u64,
    pub(crate) driver_attempt_generation: u64,
    pub(crate) driver_control_endpoint_id: u64,
    pub(crate) driver_control_endpoint_generation: u64,
    pub(crate) driver_launch_transaction: u64,
    pub(crate) supervisor_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReadyState {
    tuple: ShellTuple,
    serial: SerialFacts,
    ready: SerialReady,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Observer {
    nonce: u64,
    next_sequence: u64,
    stage: u32,
    serial: Option<SerialFacts>,
    pending_tuple: Option<ShellTuple>,
    pending_ready: Option<SerialReady>,
    current: Option<ReadyState>,
    previous: Option<ReadyState>,
    outer_result: Option<TerminationResult>,
    terminal: bool,
}

impl Observer {
    pub(crate) fn new() -> Result<Self, InitError> {
        Ok(Self {
            nonce: embedded_nonce().ok_or(InitError::Accounting)?,
            next_sequence: 1,
            stage: 1,
            serial: None,
            pending_tuple: None,
            pending_ready: None,
            current: None,
            previous: None,
            outer_result: None,
            terminal: false,
        })
    }

    pub(crate) fn observe_serial(&mut self, serial: SerialFacts) -> Result<(), InitError> {
        if serial.publication_generation == 0
            || serial.device_role_id == 0
            || serial.driver_attempt_generation == 0
            || serial.driver_control_endpoint_id == 0
            || serial.driver_control_endpoint_generation == 0
            || serial.driver_launch_transaction == 0
            || serial.supervisor_generation == 0
            || self.serial.is_some()
            || self.current.is_some()
            || self.terminal
        {
            return Err(InitError::Accounting);
        }
        self.serial = Some(serial);
        Ok(())
    }

    pub(crate) fn stage_shell_tuple(
        &mut self,
        tuple: ShellTuple,
        submit: impl FnOnce(&[u8; RECORD_BYTES]) -> Result<(), InitError>,
    ) -> Result<(), InitError> {
        if !tuple.valid()
            || self.pending_tuple.is_some()
            || self.current.is_some()
            || self.terminal
            || self
                .previous
                .is_some_and(|previous| previous.tuple == tuple)
        {
            return Err(InitError::Accounting);
        }
        self.pending_tuple = Some(tuple);
        self.maybe_ready(submit)
    }

    pub(crate) fn observe_serial_ready(
        &mut self,
        ready: SerialReady,
        submit: impl FnOnce(&[u8; RECORD_BYTES]) -> Result<(), InitError>,
    ) -> Result<(), InitError> {
        if !ready.valid()
            || self.pending_ready.is_some()
            || self.current.is_some()
            || self.terminal
            || self
                .previous
                .is_some_and(|previous| previous.ready == ready)
        {
            return Err(InitError::Accounting);
        }
        self.pending_ready = Some(ready);
        self.maybe_ready(submit)
    }

    fn maybe_ready(
        &mut self,
        submit: impl FnOnce(&[u8; RECORD_BYTES]) -> Result<(), InitError>,
    ) -> Result<(), InitError> {
        let (Some(tuple), Some(ready), Some(serial)) =
            (self.pending_tuple, self.pending_ready, self.serial)
        else {
            return Ok(());
        };
        if (
            tuple.console_generation,
            tuple.status_generation,
            tuple.shell_generation,
        ) != (
            ready.console_generation,
            ready.status_generation,
            ready.shell_generation,
        ) {
            self.pending_tuple = None;
            self.pending_ready = None;
            return Err(InitError::Accounting);
        }
        let next = ReadyState {
            tuple,
            serial,
            ready,
        };
        if let Some(previous) = self.previous {
            if let Err(error) = validate_transition(self.stage, previous, next) {
                self.pending_tuple = None;
                self.pending_ready = None;
                self.serial = None;
                return Err(error);
            }
        } else if self.stage != 1 {
            self.pending_tuple = None;
            self.pending_ready = None;
            return Err(InitError::WrongActivationOrder);
        }
        self.current = Some(next);
        self.pending_tuple = None;
        self.pending_ready = None;
        let mut record = self.record(
            TYPE_SHELL_READY,
            ready.attach_transaction,
            ready.stream_generation,
            self.stage,
            0,
            [
                serial.publication_generation,
                serial.driver_attempt_generation,
                serial.supervisor_generation,
            ],
        )?;
        semantic_digest(READY_DIGEST_DOMAIN, &mut record);
        submit(&record)?;
        self.advance()
    }

    pub(crate) const fn ready(&self) -> bool {
        self.current.is_some()
    }

    #[cfg(test)]
    pub(crate) const fn armed(&self) -> bool {
        self.serial.is_some()
    }

    pub(crate) const fn tuple_waiting_for_serial(&self) -> bool {
        self.pending_tuple.is_some()
    }

    pub(crate) fn abort_staged_ready(&mut self) {
        self.serial = None;
        self.pending_tuple = None;
        self.pending_ready = None;
    }

    pub(crate) const fn stage(&self) -> u32 {
        self.stage
    }

    pub(crate) const fn nonce(&self) -> u64 {
        self.nonce
    }

    pub(crate) const fn current_tuple(&self) -> Option<ShellTuple> {
        match self.current {
            Some(state) => Some(state.tuple),
            None => None,
        }
    }

    pub(crate) const fn current_serial_identity(&self) -> Option<[u64; 7]> {
        match self.current {
            Some(state) => Some([
                state.serial.device_role_id,
                state.ready.bundle_generation,
                state.serial.driver_attempt_generation,
                state.serial.driver_control_endpoint_id,
                state.serial.driver_control_endpoint_generation,
                state.serial.driver_launch_transaction,
                state.serial.supervisor_generation,
            ]),
            None => None,
        }
    }

    /// Records a launch transaction whose reply was written on a later tick.
    ///
    /// Reset card R6B-2. The one-frame path is [`Self::shell_jobs_transaction`]
    /// and this records the same thing about the same launch; what differs is
    /// only that the request bytes are gone by now, replaced by the
    /// [`LaunchRequestFacts`] taken while they were in hand. The reservation the
    /// response has to echo is checked against the request's exactly as
    /// `classify` checks it, and the digest is finished from the same preimage.
    ///
    /// A launch answers `LAUNCH_ACCEPTED` or `ERROR`; nothing else can reach
    /// here, because a deferred reply is written by the publication half and
    /// those are the only two things it sends.
    pub(crate) fn shell_jobs_launch_response(
        &mut self,
        facts: crate::launch_request_facts::LaunchRequestFacts,
        response: &[u8],
        submit: impl FnOnce(&[u8; RECORD_BYTES]) -> Result<(), InitError>,
    ) -> Result<(), InitError> {
        if !self.ready() {
            return Err(InitError::WrongActivationOrder);
        }
        let (transaction, job, kind, outcome, values) =
            classify_launch_response(facts.reservation(), response)?;
        let mut record =
            self.record(kind_record_type(), transaction, job, kind, outcome, values)?;
        record[160..192].copy_from_slice(&facts.combine(response));
        submit(&record)?;
        self.advance()
    }

    pub(crate) fn shell_jobs_transaction(
        &mut self,
        request: &[u8],
        response: &[u8],
        handles: &[DwReceivedHandleInfoV1],
        submit: impl FnOnce(&[u8; RECORD_BYTES]) -> Result<(), InitError>,
    ) -> Result<(), InitError> {
        if !self.ready() {
            return Err(InitError::WrongActivationOrder);
        }
        let (transaction, job, kind, outcome, values) = classify(request, response, handles.len())?;
        let digest = transaction_digest(request, response, handles)?;
        let mut record =
            self.record(kind_record_type(), transaction, job, kind, outcome, values)?;
        record[160..192].copy_from_slice(&digest);
        submit(&record)?;
        self.advance()
    }

    pub(crate) fn observe_outer_response(
        &mut self,
        request: &[u8],
        response: &[u8],
        mut submit: impl FnMut(&[u8; RECORD_BYTES]) -> Result<(), InitError>,
    ) -> Result<(), InitError> {
        let parsed_request = parse_message(request, 0).map_err(|_| InitError::Accounting)?;
        let parsed_response = parse_message(response, 0).map_err(|_| InitError::Accounting)?;
        let tuple = self.current.ok_or(InitError::WrongActivationOrder)?.tuple;
        if parsed_request.reservation != parsed_response.reservation {
            return Err(InitError::Accounting);
        }
        match (parsed_request.message, parsed_response.message) {
            (Message::Wait { job_id: requested }, Message::JobResult { job_id, result })
                if requested == tuple.outer_job_id && job_id == requested =>
            {
                self.outer_result = Some(result);
                Ok(())
            }
            (Message::CloseJob { job_id: requested }, Message::Closed { job_id })
                if requested == tuple.outer_job_id && job_id == requested =>
            {
                self.finish_clean(parsed_request.reservation.transaction_id, &mut submit)
            }
            _ => Ok(()),
        }
    }

    fn finish_clean(
        &mut self,
        close_transaction: u64,
        submit: &mut impl FnMut(&[u8; RECORD_BYTES]) -> Result<(), InitError>,
    ) -> Result<(), InitError> {
        let result = self.outer_result.ok_or(InitError::WrongActivationOrder)?;
        if !normal_zero(result) || !matches!(self.stage, 1 | 4) {
            return Err(InitError::Supervision);
        }
        let cause = if self.stage == 1 { 1 } else { 4 };
        self.emit_retired(
            close_transaction,
            self.current.unwrap().tuple.outer_job_id,
            cause,
            result,
            submit,
        )?;
        if cause == 4 {
            let terminal = self.record(TYPE_TERMINAL, 0, 0, 0, 0, [0; 3])?;
            submit(&terminal)?;
            self.advance()?;
            self.terminal = true;
        } else {
            self.stage = 2;
        }
        Ok(())
    }

    pub(crate) fn forced_retired(
        &mut self,
        wait_transaction: u64,
        trigger_job: u64,
        result: TerminationResult,
        mut submit: impl FnMut(&[u8; RECORD_BYTES]) -> Result<(), InitError>,
    ) -> Result<(), InitError> {
        if wait_transaction == 0
            || trigger_job == 0
            || !matches!(self.stage, 2 | 3)
            || !forced_result(result)
        {
            return Err(InitError::Supervision);
        }
        let cause = self.stage;
        self.emit_retired(wait_transaction, trigger_job, cause, result, &mut submit)?;
        self.stage += 1;
        Ok(())
    }

    fn emit_retired(
        &mut self,
        auxiliary_0: u64,
        auxiliary_1: u64,
        cause: u32,
        result: TerminationResult,
        submit: &mut impl FnMut(&[u8; RECORD_BYTES]) -> Result<(), InitError>,
    ) -> Result<(), InitError> {
        let current = self.current.ok_or(InitError::WrongActivationOrder)?;
        let mut record = self.record(
            TYPE_SHELL_RETIRED,
            auxiliary_0,
            auxiliary_1,
            cause,
            result.classification.as_u32(),
            result_values(result),
        )?;
        semantic_digest(RETIRED_DIGEST_DOMAIN, &mut record);
        submit(&record)?;
        self.advance()?;
        self.current = None;
        self.previous = Some(current);
        self.serial = (cause == 1).then_some(current.serial);
        self.outer_result = None;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        self,
        record_type: u32,
        auxiliary_0: u64,
        auxiliary_1: u64,
        protocol_kind: u32,
        outcome_class: u32,
        values: [u64; 3],
    ) -> Result<[u8; RECORD_BYTES], InitError> {
        if self.next_sequence == 0 || self.next_sequence > MAX_RECORDS || self.terminal {
            return Err(InitError::Accounting);
        }
        let tuple = self
            .current
            .map(|state| state.tuple)
            .or_else(|| self.previous.map(|state| state.tuple))
            .ok_or(InitError::WrongActivationOrder)?;
        let mut out = [0u8; RECORD_BYTES];
        out[0..4].copy_from_slice(&MAGIC);
        put_u16(&mut out, 4, MAJOR);
        put_u16(&mut out, 6, MINOR);
        put_u32(&mut out, 8, record_type);
        put_u32(&mut out, 12, RECORD_BYTES as u32);
        put_u64(&mut out, 16, self.next_sequence);
        put_u64(&mut out, 24, self.nonce);
        for (offset, value) in [
            (32, tuple.console_generation),
            (40, tuple.status_generation),
            (48, tuple.shell_generation),
            (56, tuple.outer_launch_transaction),
            (64, tuple.outer_job_id),
            (72, tuple.registry_generation),
            (80, tuple.registry_endpoint_id),
            (88, tuple.registry_endpoint_generation),
            (96, tuple.shell_jobs_connection_id),
            (104, tuple.shell_jobs_generation),
            (112, auxiliary_0),
            (120, auxiliary_1),
            (136, values[0]),
            (144, values[1]),
            (152, values[2]),
        ] {
            put_u64(&mut out, offset, value);
        }
        put_u32(&mut out, 128, protocol_kind);
        put_u32(&mut out, 132, outcome_class);
        Ok(out)
    }

    fn advance(&mut self) -> Result<(), InitError> {
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(InitError::Accounting)?;
        Ok(())
    }
}

const fn kind_record_type() -> u32 {
    TYPE_SHELLJOBS_TRANSACTION
}

fn validate_transition(stage: u32, old: ReadyState, new: ReadyState) -> Result<(), InitError> {
    let fresh_shell = old.tuple.outer_launch_transaction != new.tuple.outer_launch_transaction
        && old.tuple.outer_job_id != new.tuple.outer_job_id
        && (
            old.tuple.shell_jobs_connection_id,
            old.tuple.shell_jobs_generation,
        ) != (
            new.tuple.shell_jobs_connection_id,
            new.tuple.shell_jobs_generation,
        )
        && (
            old.tuple.registry_endpoint_id,
            old.tuple.registry_endpoint_generation,
        ) != (
            new.tuple.registry_endpoint_id,
            new.tuple.registry_endpoint_generation,
        );
    let valid = match stage {
        2 => {
            fresh_shell
                && old.tuple.registry_generation == new.tuple.registry_generation
                && old.tuple.console_generation == new.tuple.console_generation
                && old.tuple.status_generation != new.tuple.status_generation
                && old.tuple.shell_generation != new.tuple.shell_generation
                && old.serial == new.serial
                && old.ready.attach_transaction == new.ready.attach_transaction
                && old.ready.stream_generation == new.ready.stream_generation
                && old.ready.bundle_generation == new.ready.bundle_generation
        }
        3 => {
            // System-init and the healthy devmgr persist across this leg, so
            // their publication, attempt, launch, attach, and stream allocators
            // are monotonic. Consoled-owned counters are intentionally absent.
            fresh_shell
                && old.tuple.registry_generation == new.tuple.registry_generation
                && new.serial.publication_generation > old.serial.publication_generation
                && new.serial.device_role_id == old.serial.device_role_id
                && new.serial.driver_attempt_generation > old.serial.driver_attempt_generation
                && (
                    new.serial.driver_control_endpoint_id,
                    new.serial.driver_control_endpoint_generation,
                ) != (
                    old.serial.driver_control_endpoint_id,
                    old.serial.driver_control_endpoint_generation,
                )
                && new.serial.driver_launch_transaction > old.serial.driver_launch_transaction
                && new.serial.supervisor_generation == old.serial.supervisor_generation
                && new.ready.attach_transaction > old.ready.attach_transaction
                && new.ready.stream_generation > old.ready.stream_generation
                && new.ready.bundle_generation == old.ready.bundle_generation
        }
        4 => {
            // Registry replacement retains the healthy driver and supervisor,
            // but reissues every registry/publication/raw/shell authority from
            // the strictly newer topology. Consoled-local counters may restart.
            fresh_shell
                && new.tuple.registry_generation > old.tuple.registry_generation
                && new.serial.publication_generation > old.serial.publication_generation
                && new.serial.device_role_id == old.serial.device_role_id
                && new.serial.driver_attempt_generation == old.serial.driver_attempt_generation
                && new.serial.driver_control_endpoint_id == old.serial.driver_control_endpoint_id
                && new.serial.driver_control_endpoint_generation
                    == old.serial.driver_control_endpoint_generation
                && new.serial.driver_launch_transaction == old.serial.driver_launch_transaction
                && new.serial.supervisor_generation == old.serial.supervisor_generation
                && new.ready.attach_transaction > old.ready.attach_transaction
                && new.ready.stream_generation > old.ready.stream_generation
                && old.ready.bundle_generation == new.ready.bundle_generation
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(InitError::Accounting)
    }
}

fn normal_zero(result: TerminationResult) -> bool {
    result.classification == TerminationClassification::NormalExit
        && result.application_code == 0
        && result.exception_class == 0
        && result.exception_detail == 0
        && result.exception_address == 0
        && result.cleanup_result == 0
}

fn forced_result(result: TerminationResult) -> bool {
    let zero_tail = result.exception_class == 0
        && result.exception_detail == 0
        && result.exception_address == 0
        && result.cleanup_result == 0;
    zero_tail
        && ((result.classification == TerminationClassification::TaskGroupTeardown
            && result.application_code == 0)
            || (result.classification == TerminationClassification::NormalExit
                && result.application_code == STATUS_LOST))
}

/// The response half of [`classify`], for a launch whose request is gone.
///
/// Reset card R6B-2. Every request-derived value `classify` would compute is
/// either carried in the facts or constant for a launch: the kind is `Launch`,
/// and the requested job id -- which an `ERROR` reply reports back -- is zero.
fn classify_launch_response(
    reservation: Reservation,
    response: &[u8],
) -> Result<(u64, u64, u32, u32, [u64; 3]), InitError> {
    let response = parse_message(response, 0).map_err(|_| InitError::Accounting)?;
    if response.reservation != reservation {
        return Err(InitError::Accounting);
    }
    let (job, outcome) = match response.message {
        Message::LaunchAccepted { job_id } if job_id != 0 => {
            (job_id, MessageType::LaunchAccepted as u32)
        }
        Message::Error { code } => (0, ERROR_OUTCOME_BIT | code.as_u32()),
        _ => return Err(InitError::Accounting),
    };
    Ok((
        reservation.transaction_id,
        job,
        MessageType::Launch as u32,
        outcome,
        [0; 3],
    ))
}

fn classify(
    request: &[u8],
    response: &[u8],
    request_handles: usize,
) -> Result<(u64, u64, u32, u32, [u64; 3]), InitError> {
    let request = parse_message(request, request_handles).map_err(|_| InitError::Accounting)?;
    let response = parse_message(response, 0).map_err(|_| InitError::Accounting)?;
    if request.reservation != response.reservation {
        return Err(InitError::Accounting);
    }
    let (kind, requested_job) = match request.message {
        Message::Launch(_) => (MessageType::Launch, 0),
        Message::Wait { job_id } => (MessageType::Wait, job_id),
        Message::Terminate { job_id } => (MessageType::Terminate, job_id),
        Message::ListJobs => (MessageType::ListJobs, 0),
        Message::CloseJob { job_id } => (MessageType::CloseJob, job_id),
        _ => return Err(InitError::Accounting),
    };
    let (job, outcome, values) = match response.message {
        Message::LaunchAccepted { job_id } if kind == MessageType::Launch && job_id != 0 => {
            (job_id, MessageType::LaunchAccepted as u32, [0; 3])
        }
        Message::JobResult { job_id, result }
            if kind == MessageType::Wait && job_id == requested_job =>
        {
            (
                job_id,
                MessageType::JobResult as u32 | result.classification.as_u32() << 16,
                result_values(result),
            )
        }
        Message::TerminationAccepted { job_id }
            if kind == MessageType::Terminate && job_id == requested_job =>
        {
            (job_id, MessageType::TerminationAccepted as u32, [0; 3])
        }
        Message::JobList(ids) if kind == MessageType::ListJobs => {
            (0, MessageType::JobList as u32, [ids.len() as u64, 0, 0])
        }
        Message::Closed { job_id } if kind == MessageType::CloseJob && job_id == requested_job => {
            (job_id, MessageType::Closed as u32, [0; 3])
        }
        Message::Error { code } => (requested_job, ERROR_OUTCOME_BIT | code.as_u32(), [0; 3]),
        _ => return Err(InitError::Accounting),
    };
    Ok((
        request.reservation.transaction_id,
        job,
        kind as u32,
        outcome,
        values,
    ))
}

fn result_values(result: TerminationResult) -> [u64; 3] {
    [
        u64::from(result.application_code) | u64::from(result.exception_class) << 32,
        u64::from(result.exception_detail) | u64::from(result.cleanup_result) << 32,
        result.exception_address,
    ]
}

fn transaction_digest(
    request: &[u8],
    response: &[u8],
    handles: &[DwReceivedHandleInfoV1],
) -> Result<[u8; 32], InitError> {
    crate::launch_request_facts::transaction_digest(request, response, handles)
}

fn semantic_digest(domain: &[u8], record: &mut [u8; RECORD_BYTES]) {
    let mut preimage = [0u8; 180];
    preimage[..domain.len()].copy_from_slice(domain);
    preimage[domain.len()..domain.len() + 160].copy_from_slice(&record[..160]);
    let digest = wyrmroot_runtime::sha256::digest(&preimage[..domain.len() + 160]);
    record[160..192].copy_from_slice(&digest);
}

#[cfg(test)]
fn embedded_nonce() -> Option<u64> {
    Some(0x1122_3344_5566_7788)
}

#[cfg(not(test))]
fn embedded_nonce() -> Option<u64> {
    parse_nonce(option_env!("WYRMROOT_WYR1E8_EVIDENCE_NONCE")?)
}

fn parse_nonce(text: &str) -> Option<u64> {
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

fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrmroot_launch_proto::{Reservation, encode_job_message};

    fn tuple(seed: u64) -> ShellTuple {
        ShellTuple {
            console_generation: seed,
            status_generation: seed + 1,
            shell_generation: seed + 2,
            outer_launch_transaction: seed + 3,
            outer_job_id: seed + 4,
            registry_generation: seed + 5,
            registry_endpoint_id: seed + 6,
            registry_endpoint_generation: seed + 7,
            shell_jobs_connection_id: seed + 8,
            shell_jobs_generation: seed + 9,
        }
    }

    fn serial(seed: u64) -> [u64; 7] {
        [
            seed,
            seed + 1,
            seed + 2,
            seed + 3,
            seed + 4,
            seed + 5,
            seed + 6,
        ]
    }

    fn observe_serial(observer: &mut Observer, values: [u64; 7]) {
        observer
            .observe_serial(SerialFacts {
                publication_generation: values[0],
                device_role_id: values[1],
                driver_attempt_generation: values[2],
                driver_control_endpoint_id: values[3],
                driver_control_endpoint_generation: values[4],
                driver_launch_transaction: values[5],
                supervisor_generation: values[6],
            })
            .unwrap();
    }

    fn ready(tuple: ShellTuple, attach: u64, stream: u64, bundle: u64) -> SerialReady {
        SerialReady {
            console_generation: tuple.console_generation,
            status_generation: tuple.status_generation,
            shell_generation: tuple.shell_generation,
            attach_transaction: attach,
            stream_generation: stream,
            bundle_generation: bundle,
        }
    }

    fn finish_clean(
        observer: &mut Observer,
        tuple: ShellTuple,
        transaction: u64,
        mut submit: impl FnMut(&[u8; RECORD_BYTES]) -> Result<(), InitError>,
    ) {
        let reservation = Reservation {
            connection_id: 900,
            generation: 901,
            transaction_id: transaction,
        };
        let mut request = [0u8; 56];
        let request_len = encode_job_message(
            reservation,
            MessageType::Wait,
            tuple.outer_job_id,
            &mut request,
        )
        .unwrap();
        let result = TerminationResult {
            classification: TerminationClassification::NormalExit,
            application_code: 0,
            exception_class: 0,
            exception_detail: 0,
            exception_address: 0,
            cleanup_result: 0,
        };
        let mut response = [0u8; 88];
        let response_len = wyrmroot_launch_proto::encode_job_result(
            reservation,
            tuple.outer_job_id,
            result,
            &mut response,
        )
        .unwrap();
        observer
            .observe_outer_response(&request[..request_len], &response[..response_len], |_| {
                Ok(())
            })
            .unwrap();
        let close_reservation = Reservation {
            transaction_id: transaction + 1,
            ..reservation
        };
        let mut close = [0u8; 56];
        let close_len = encode_job_message(
            close_reservation,
            MessageType::CloseJob,
            tuple.outer_job_id,
            &mut close,
        )
        .unwrap();
        let mut closed = [0u8; 56];
        let closed_len = encode_job_message(
            close_reservation,
            MessageType::Closed,
            tuple.outer_job_id,
            &mut closed,
        )
        .unwrap();
        observer
            .observe_outer_response(&close[..close_len], &closed[..closed_len], |record| {
                submit(record)
            })
            .unwrap();
    }

    #[test]
    fn tuple_and_serial_fact_join_in_either_arrival_order() {
        let mut first = Observer::new().unwrap();
        observe_serial(&mut first, [20, 30, 21, 31, 32, 33, 22]);
        first.stage_shell_tuple(tuple(1), |_| Ok(())).unwrap();
        assert!(!first.ready());
        let ready = SerialReady {
            console_generation: 1,
            status_generation: 2,
            shell_generation: 3,
            attach_transaction: 23,
            stream_generation: 24,
            bundle_generation: 25,
        };
        first.observe_serial_ready(ready, |_| Ok(())).unwrap();
        assert!(first.ready());

        let mut second = Observer::new().unwrap();
        observe_serial(&mut second, [20, 30, 21, 31, 32, 33, 22]);
        second.observe_serial_ready(ready, |_| Ok(())).unwrap();
        assert!(!second.ready());
        second.stage_shell_tuple(tuple(1), |_| Ok(())).unwrap();
        assert!(second.ready());
    }

    #[test]
    fn forced_result_set_is_exact() {
        let base = TerminationResult {
            classification: TerminationClassification::TaskGroupTeardown,
            application_code: 0,
            exception_class: 0,
            exception_detail: 0,
            exception_address: 0,
            cleanup_result: 0,
        };
        assert!(forced_result(base));
        assert!(forced_result(TerminationResult {
            classification: TerminationClassification::NormalExit,
            application_code: STATUS_LOST,
            ..base
        }));
        assert!(!forced_result(TerminationResult {
            classification: TerminationClassification::NormalExit,
            application_code: 0x5745_0106,
            ..base
        }));
        assert!(!forced_result(TerminationResult {
            classification: TerminationClassification::NormalExit,
            application_code: 0x5745_0105,
            ..base
        }));
        assert!(!forced_result(TerminationResult {
            cleanup_result: 1,
            ..base
        }));
    }

    #[test]
    fn driver_replacement_checks_every_persistent_owner_relation() {
        let old_tuple = tuple(100);
        let old = ReadyState {
            tuple: old_tuple,
            serial: SerialFacts {
                publication_generation: 300,
                device_role_id: 301,
                driver_attempt_generation: 302,
                driver_control_endpoint_id: 303,
                driver_control_endpoint_generation: 304,
                driver_launch_transaction: 305,
                supervisor_generation: 306,
            },
            ready: ready(old_tuple, 400, 401, 402),
        };
        let new_tuple = ShellTuple {
            console_generation: 1,
            status_generation: 1,
            shell_generation: 1,
            outer_launch_transaction: 203,
            outer_job_id: 204,
            registry_generation: old_tuple.registry_generation,
            registry_endpoint_id: 206,
            registry_endpoint_generation: 207,
            shell_jobs_connection_id: 208,
            shell_jobs_generation: 209,
        };
        let next = ReadyState {
            tuple: new_tuple,
            serial: SerialFacts {
                publication_generation: 500,
                device_role_id: old.serial.device_role_id,
                driver_attempt_generation: 502,
                driver_control_endpoint_id: 503,
                driver_control_endpoint_generation: 504,
                driver_launch_transaction: 505,
                supervisor_generation: old.serial.supervisor_generation,
            },
            ready: ready(new_tuple, 600, 601, old.ready.bundle_generation),
        };
        assert_eq!(validate_transition(3, old, next), Ok(()));

        let mut invalid = [next; 10];
        invalid[0].tuple.registry_generation = old.tuple.registry_generation + 1;
        invalid[1].serial.publication_generation = old.serial.publication_generation;
        invalid[2].serial.device_role_id = old.serial.device_role_id + 1;
        invalid[3].serial.driver_attempt_generation = old.serial.driver_attempt_generation;
        invalid[4].serial.driver_control_endpoint_id = old.serial.driver_control_endpoint_id;
        invalid[4].serial.driver_control_endpoint_generation =
            old.serial.driver_control_endpoint_generation;
        invalid[5].serial.driver_launch_transaction = old.serial.driver_launch_transaction;
        invalid[6].serial.supervisor_generation = old.serial.supervisor_generation + 1;
        invalid[7].ready.attach_transaction = old.ready.attach_transaction;
        invalid[8].ready.stream_generation = old.ready.stream_generation;
        invalid[9].ready.bundle_generation = old.ready.bundle_generation + 1;
        for candidate in invalid {
            assert_eq!(
                validate_transition(3, old, candidate),
                Err(InitError::Accounting)
            );
        }
    }

    #[test]
    fn registry_replacement_retains_driver_and_refreshes_every_reissued_owner() {
        let old_tuple = tuple(100);
        let old = ReadyState {
            tuple: old_tuple,
            serial: SerialFacts {
                publication_generation: 300,
                device_role_id: 301,
                driver_attempt_generation: 302,
                driver_control_endpoint_id: 303,
                driver_control_endpoint_generation: 304,
                driver_launch_transaction: 305,
                supervisor_generation: 306,
            },
            ready: ready(old_tuple, 400, 401, 402),
        };
        let new_tuple = ShellTuple {
            console_generation: 1,
            status_generation: 1,
            shell_generation: 1,
            outer_launch_transaction: 203,
            outer_job_id: 204,
            registry_generation: old_tuple.registry_generation + 1,
            registry_endpoint_id: 206,
            registry_endpoint_generation: 207,
            shell_jobs_connection_id: 208,
            shell_jobs_generation: 209,
        };
        let next = ReadyState {
            tuple: new_tuple,
            serial: SerialFacts {
                publication_generation: 500,
                ..old.serial
            },
            ready: ready(new_tuple, 600, 601, old.ready.bundle_generation),
        };
        assert_eq!(validate_transition(4, old, next), Ok(()));

        let mut invalid = [next; 11];
        invalid[0].tuple.registry_generation = old.tuple.registry_generation;
        invalid[1].serial.publication_generation = old.serial.publication_generation;
        invalid[2].serial.device_role_id = old.serial.device_role_id + 1;
        invalid[3].serial.driver_attempt_generation = old.serial.driver_attempt_generation + 1;
        invalid[4].serial.driver_control_endpoint_id = old.serial.driver_control_endpoint_id + 1;
        invalid[5].serial.driver_control_endpoint_generation =
            old.serial.driver_control_endpoint_generation + 1;
        invalid[6].serial.driver_launch_transaction = old.serial.driver_launch_transaction + 1;
        invalid[7].serial.supervisor_generation = old.serial.supervisor_generation + 1;
        invalid[8].ready.attach_transaction = old.ready.attach_transaction;
        invalid[9].ready.stream_generation = old.ready.stream_generation;
        invalid[10].ready.bundle_generation = old.ready.bundle_generation + 1;
        for candidate in invalid {
            assert_eq!(
                validate_transition(4, old, candidate),
                Err(InitError::Accounting)
            );
        }
    }

    fn forced_zero() -> TerminationResult {
        TerminationResult {
            classification: TerminationClassification::TaskGroupTeardown,
            application_code: 0,
            exception_class: 0,
            exception_detail: 0,
            exception_address: 0,
            cleanup_result: 0,
        }
    }

    fn assert_retired_epoch_replay_is_inert(
        observer: &mut Observer,
        retired_tuple: ShellTuple,
        retired_ready: SerialReady,
    ) {
        let before = *observer;
        assert_eq!(
            observer.stage_shell_tuple(retired_tuple, |_| Ok(())),
            Err(InitError::Accounting)
        );
        assert_eq!(*observer, before);
        assert_eq!(
            observer.observe_serial_ready(retired_ready, |_| Ok(())),
            Err(InitError::Accounting)
        );
        assert_eq!(*observer, before);
    }

    #[test]
    fn retired_epochs_and_consistently_wrong_replacements_cannot_mutate_observer_state() {
        let mut observer = Observer::new().unwrap();
        let s1 = tuple(1);
        let s1_ready = ready(s1, 200, 201, 202);
        observe_serial(&mut observer, serial(100));
        observer.stage_shell_tuple(s1, |_| Ok(())).unwrap();
        observer.observe_serial_ready(s1_ready, |_| Ok(())).unwrap();
        finish_clean(&mut observer, s1, 300, |_| Ok(()));
        assert_retired_epoch_replay_is_inert(&mut observer, s1, s1_ready);

        let consistently_wrong = tuple(1_000);
        let consistently_wrong_ready = ready(consistently_wrong, 1_200, 1_201, 1_202);
        let before = observer;
        observer
            .stage_shell_tuple(consistently_wrong, |_| Ok(()))
            .unwrap();
        assert_eq!(
            observer.observe_serial_ready(consistently_wrong_ready, |_| Ok(())),
            Err(InitError::Accounting)
        );
        let mut after_reject = before;
        after_reject.serial = None;
        assert_eq!(observer, after_reject);
        observe_serial(&mut observer, serial(1_100));
        observer
            .observe_serial_ready(consistently_wrong_ready, |_| Ok(()))
            .unwrap();
        assert_eq!(
            observer.stage_shell_tuple(consistently_wrong, |_| Ok(())),
            Err(InitError::Accounting)
        );
        assert_eq!(observer, after_reject);

        let s2 = ShellTuple {
            console_generation: s1.console_generation,
            status_generation: 20,
            shell_generation: 21,
            outer_launch_transaction: 22,
            outer_job_id: 23,
            registry_generation: s1.registry_generation,
            registry_endpoint_id: 24,
            registry_endpoint_generation: 25,
            shell_jobs_connection_id: 26,
            shell_jobs_generation: 27,
        };
        let s2_ready = ready(s2, 200, 201, 202);
        observe_serial(&mut observer, serial(100));
        observer.stage_shell_tuple(s2, |_| Ok(())).unwrap();
        observer.observe_serial_ready(s2_ready, |_| Ok(())).unwrap();
        observer
            .forced_retired(310, 311, forced_zero(), |_| Ok(()))
            .unwrap();
        assert_retired_epoch_replay_is_inert(&mut observer, s2, s2_ready);

        let s3 = ShellTuple {
            console_generation: 1,
            status_generation: 2,
            shell_generation: 3,
            outer_launch_transaction: 32,
            outer_job_id: 33,
            registry_generation: s2.registry_generation,
            registry_endpoint_id: 34,
            registry_endpoint_generation: 35,
            shell_jobs_connection_id: 36,
            shell_jobs_generation: 37,
        };
        let s3_ready = ready(s3, 500, 501, 202);
        observe_serial(&mut observer, [400, 101, 402, 403, 404, 405, 106]);
        observer.stage_shell_tuple(s3, |_| Ok(())).unwrap();
        observer.observe_serial_ready(s3_ready, |_| Ok(())).unwrap();
        observer
            .forced_retired(510, 511, forced_zero(), |_| Ok(()))
            .unwrap();
        assert_retired_epoch_replay_is_inert(&mut observer, s3, s3_ready);
    }

    #[test]
    fn clean_replacement_requires_fresh_status_and_shell_generations() {
        for reuse_status in [true, false] {
            let mut observer = Observer::new().unwrap();
            let s1 = tuple(1);
            observe_serial(&mut observer, serial(100));
            observer.stage_shell_tuple(s1, |_| Ok(())).unwrap();
            observer
                .observe_serial_ready(ready(s1, 200, 201, 202), |_| Ok(()))
                .unwrap();
            finish_clean(&mut observer, s1, 300, |_| Ok(()));

            let mut invalid = ShellTuple {
                console_generation: s1.console_generation,
                status_generation: 20,
                shell_generation: 21,
                outer_launch_transaction: 22,
                outer_job_id: 23,
                registry_generation: s1.registry_generation,
                registry_endpoint_id: 24,
                registry_endpoint_generation: 25,
                shell_jobs_connection_id: 26,
                shell_jobs_generation: 27,
            };
            if reuse_status {
                invalid.status_generation = s1.status_generation;
            } else {
                invalid.shell_generation = s1.shell_generation;
            }
            let invalid_ready = ready(invalid, 200, 201, 202);
            observer.stage_shell_tuple(invalid, |_| Ok(())).unwrap();
            assert_eq!(
                observer.observe_serial_ready(invalid_ready, |_| Ok(())),
                Err(InitError::Accounting)
            );
            assert!(!observer.ready());
            assert!(!observer.tuple_waiting_for_serial());
        }
    }

    #[test]
    fn clean_s1_to_s2_reuses_exact_serial_without_reobservation() {
        let mut observer = Observer::new().unwrap();
        let s1 = tuple(1);
        let retained_serial = serial(100);
        observe_serial(&mut observer, retained_serial);
        observer.stage_shell_tuple(s1, |_| Ok(())).unwrap();
        observer
            .observe_serial_ready(ready(s1, 200, 201, 202), |_| Ok(()))
            .unwrap();
        finish_clean(&mut observer, s1, 300, |_| Ok(()));

        let s2 = ShellTuple {
            console_generation: s1.console_generation,
            status_generation: 20,
            shell_generation: 21,
            outer_launch_transaction: 22,
            outer_job_id: 23,
            registry_generation: s1.registry_generation,
            registry_endpoint_id: 24,
            registry_endpoint_generation: 25,
            shell_jobs_connection_id: 26,
            shell_jobs_generation: 27,
        };
        let mut ready_records = 0usize;
        observer.stage_shell_tuple(s2, |_| Ok(())).unwrap();
        observer
            .observe_serial_ready(ready(s2, 200, 201, 202), |record| {
                assert_eq!(
                    u32::from_le_bytes(record[8..12].try_into().unwrap()),
                    TYPE_SHELL_READY
                );
                assert_eq!(u32::from_le_bytes(record[128..132].try_into().unwrap()), 2);
                ready_records += 1;
                Ok(())
            })
            .unwrap();

        assert!(
            observer.ready(),
            "S2 must publish READY from retained serial facts"
        );
        assert!(!observer.tuple_waiting_for_serial());
        assert_eq!(ready_records, 1);
        let before_redundant_observation = observer;
        assert_eq!(
            observer.observe_serial(SerialFacts {
                publication_generation: retained_serial[0],
                device_role_id: retained_serial[1],
                driver_attempt_generation: retained_serial[2],
                driver_control_endpoint_id: retained_serial[3],
                driver_control_endpoint_generation: retained_serial[4],
                driver_launch_transaction: retained_serial[5],
                supervisor_generation: retained_serial[6],
            }),
            Err(InitError::Accounting)
        );
        assert_eq!(observer, before_redundant_observation);
    }

    #[test]
    fn four_shell_epochs_require_exact_clean_and_forced_retirement_order() {
        let mut observer = Observer::new().unwrap();
        let mut records = [[0u8; RECORD_BYTES]; 9];
        let mut count = 0usize;

        let s1 = tuple(1);
        observe_serial(&mut observer, serial(100));
        observer.stage_shell_tuple(s1, |_| Ok(())).unwrap();
        observer
            .observe_serial_ready(ready(s1, 200, 201, 202), |record| {
                records[count] = *record;
                count += 1;
                Ok(())
            })
            .unwrap();
        finish_clean(&mut observer, s1, 300, |record| {
            records[count] = *record;
            count += 1;
            Ok(())
        });

        let s2 = ShellTuple {
            console_generation: s1.console_generation,
            status_generation: 20,
            shell_generation: 21,
            outer_launch_transaction: 22,
            outer_job_id: 23,
            registry_generation: s1.registry_generation,
            registry_endpoint_id: 24,
            registry_endpoint_generation: 25,
            shell_jobs_connection_id: 26,
            shell_jobs_generation: 27,
        };
        observer.stage_shell_tuple(s2, |_| Ok(())).unwrap();
        observer
            .observe_serial_ready(ready(s2, 200, 201, 202), |record| {
                records[count] = *record;
                count += 1;
                Ok(())
            })
            .unwrap();
        observer
            .forced_retired(
                310,
                311,
                TerminationResult {
                    classification: TerminationClassification::TaskGroupTeardown,
                    application_code: 0,
                    exception_class: 0,
                    exception_detail: 0,
                    exception_address: 0,
                    cleanup_result: 0,
                },
                |record| {
                    records[count] = *record;
                    count += 1;
                    Ok(())
                },
            )
            .unwrap();
        assert!(!observer.armed());

        let s3 = ShellTuple {
            console_generation: 1,
            status_generation: 2,
            shell_generation: 3,
            outer_launch_transaction: 32,
            outer_job_id: 33,
            registry_generation: s2.registry_generation,
            registry_endpoint_id: 34,
            registry_endpoint_generation: 35,
            shell_jobs_connection_id: 36,
            shell_jobs_generation: 37,
        };
        let s3_serial = [400, 101, 402, 403, 404, 405, 106];
        observe_serial(&mut observer, s3_serial);
        observer.stage_shell_tuple(s3, |_| Ok(())).unwrap();
        observer
            .observe_serial_ready(ready(s3, 500, 501, 202), |record| {
                records[count] = *record;
                count += 1;
                Ok(())
            })
            .unwrap();
        observer
            .forced_retired(
                510,
                511,
                TerminationResult {
                    classification: TerminationClassification::NormalExit,
                    application_code: STATUS_LOST,
                    exception_class: 0,
                    exception_detail: 0,
                    exception_address: 0,
                    cleanup_result: 0,
                },
                |record| {
                    records[count] = *record;
                    count += 1;
                    Ok(())
                },
            )
            .unwrap();
        assert!(!observer.armed());

        let s4 = ShellTuple {
            console_generation: 1,
            status_generation: 2,
            shell_generation: 3,
            outer_launch_transaction: 42,
            outer_job_id: 43,
            registry_generation: 1_000,
            registry_endpoint_id: 45,
            registry_endpoint_generation: 46,
            shell_jobs_connection_id: 47,
            shell_jobs_generation: 48,
        };
        let mut s4_serial = s3_serial;
        s4_serial[0] = 600;
        observe_serial(&mut observer, s4_serial);
        observer.stage_shell_tuple(s4, |_| Ok(())).unwrap();
        observer
            .observe_serial_ready(ready(s4, 700, 701, 202), |record| {
                records[count] = *record;
                count += 1;
                Ok(())
            })
            .unwrap();
        finish_clean(&mut observer, s4, 710, |record| {
            records[count] = *record;
            count += 1;
            Ok(())
        });

        assert_eq!(count, 9);
        let kinds: [u32; 9] =
            records.map(|record| u32::from_le_bytes(record[8..12].try_into().unwrap()));
        assert_eq!(
            kinds,
            [
                TYPE_SHELL_READY,
                TYPE_SHELL_RETIRED,
                TYPE_SHELL_READY,
                TYPE_SHELL_RETIRED,
                TYPE_SHELL_READY,
                TYPE_SHELL_RETIRED,
                TYPE_SHELL_READY,
                TYPE_SHELL_RETIRED,
                TYPE_TERMINAL,
            ]
        );
        assert_eq!(
            u32::from_le_bytes(records[3][128..132].try_into().unwrap()),
            2
        );
        assert_eq!(
            u32::from_le_bytes(records[5][128..132].try_into().unwrap()),
            3
        );
        assert_eq!(
            u32::from_le_bytes(records[7][128..132].try_into().unwrap()),
            4
        );
        assert!(observer.terminal);
        assert!(!observer.armed());
    }
}
