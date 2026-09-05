// SPDX-License-Identifier: GPL-3.0-or-later

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_DUPLICATE,
    DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_SIGNAL_WRITABLE, DW_STATUS_PEER_CLOSED,
    DW_STATUS_TIMED_OUT, DW_STATUS_WOULD_BLOCK, DwDeadline, DwHandle, DwHandleTransferV1,
    DwReceivedHandleInfoV1, DwSignals,
};
use wyrmroot_launch_proto::{
    ErrorCode, MAX_ARGV, MAX_LAUNCH_MESSAGE_BYTES, Message, MessageType, ParsedMessage,
    Reservation, TerminationClassification, TerminationResult, encode_job_message, encode_launch,
};
use wyrmroot_loader::launch::{CHILD_CHANNEL_RIGHTS, CHILD_CHANNEL_TRANSFER_RIGHTS};
use wyrmroot_runtime::{NativeError, NativeInput, NativeOutput, StreamEndpoint, StreamError};
use wyrmroot_wyrmsh_core::Arguments;

use crate::inspection::{STATUS_TIMEOUT_NS, TransactionIds};
use crate::{
    Controls, EndpointRole, NativeOperation, ReceiveBudget, ShellError, ShellIdentity,
    WyrmshSystem, classify_health, control_deadline, ensure_before_control_deadline, health_items,
    native, poll_health, receive_control, send_control, wait_item, write_stderr, write_stdout,
};

/// The controller exposes up to 32 live jobs and a separate 32-result ring.
/// The client keeps every returned ID until authoritative close/foreign reply.
pub(crate) const MAX_VISIBLE_JOBS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JobState {
    Reserved,
    Active,
    Terminating,
    Completed(TerminationResult),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry {
    id: u64,
    state: JobState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Slot(usize);

pub(crate) struct JobTable {
    entries: [Option<Entry>; MAX_VISIBLE_JOBS],
}

impl JobTable {
    pub(crate) const fn new() -> Self {
        Self {
            entries: [None; MAX_VISIBLE_JOBS],
        }
    }

    pub(crate) fn reserve(&mut self) -> Option<Slot> {
        let index = self.entries.iter().position(Option::is_none)?;
        self.entries[index] = Some(Entry {
            id: 0,
            state: JobState::Reserved,
        });
        Some(Slot(index))
    }

    pub(crate) fn abort(&mut self, slot: Slot) {
        if matches!(
            self.entries.get(slot.0),
            Some(Some(Entry {
                state: JobState::Reserved,
                ..
            }))
        ) {
            self.entries[slot.0] = None;
        }
    }

    pub(crate) fn publish(&mut self, slot: Slot, id: u64) -> bool {
        if id == 0
            || self.entries.iter().flatten().any(|entry| entry.id == id)
            || !matches!(
                self.entries.get(slot.0),
                Some(Some(Entry {
                    state: JobState::Reserved,
                    ..
                }))
            )
        {
            return false;
        }
        self.entries[slot.0] = Some(Entry {
            id,
            state: JobState::Active,
        });
        true
    }

    pub(crate) fn state(&self, id: u64) -> Option<JobState> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| entry.id == id)
            .map(|entry| entry.state)
    }

    pub(crate) fn set_state(&mut self, id: u64, state: JobState) -> bool {
        let Some(entry) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|entry| entry.id == id)
        else {
            return false;
        };
        entry.state = state;
        true
    }

    pub(crate) fn remove(&mut self, id: u64) -> bool {
        let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.id == id))
        else {
            return false;
        };
        self.entries[index] = None;
        true
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Reply {
    LaunchAccepted(u64),
    JobResult(u64, TerminationResult),
    TerminationAccepted(u64),
    Cancelled(u64),
    Closed(u64),
    Error(ErrorCode),
}

pub(crate) fn reservation(identity: ShellIdentity, transaction_id: u64) -> Reservation {
    Reservation {
        connection_id: identity.launch_connection_id,
        generation: identity.launch_connection_generation,
        transaction_id,
    }
}

pub(crate) fn decode_reply(
    identity: ShellIdentity,
    transaction_id: u64,
    bytes: &[u8],
    handles: usize,
) -> Result<Reply, ()> {
    let ParsedMessage {
        reservation: actual,
        message,
    } = wyrmroot_launch_proto::parse_message(bytes, handles).map_err(|_| ())?;
    if actual != reservation(identity, transaction_id) {
        return Err(());
    }
    Ok(match message {
        Message::LaunchAccepted { job_id } => Reply::LaunchAccepted(job_id),
        Message::JobResult { job_id, result } => Reply::JobResult(job_id, result),
        Message::TerminationAccepted { job_id } => Reply::TerminationAccepted(job_id),
        Message::Cancelled {
            target_transaction_id,
        } => Reply::Cancelled(target_transaction_id),
        Message::Closed { job_id } => Reply::Closed(job_id),
        Message::Error { code } => Reply::Error(code),
        _ => return Err(()),
    })
}

#[derive(Debug, Eq, PartialEq)]
enum LaunchFailureKind {
    Expected(ErrorCode),
    Fatal(ShellError),
}

#[derive(Debug, Eq, PartialEq)]
struct LaunchFailure {
    kind: LaunchFailureKind,
    committed: bool,
}

#[derive(Clone, Copy)]
struct StreamPair {
    retained: DwHandle,
    child: DwHandle,
}

const EMPTY_PAIR: StreamPair = StreamPair {
    retained: DwHandle(0),
    child: DwHandle(0),
};

const CHANNEL_CONSTRUCTION_RIGHTS: deepwyrm_syscall::DwRights =
    deepwyrm_syscall::DwRights(CHILD_CHANNEL_TRANSFER_RIGHTS.0 | DW_RIGHT_DUPLICATE.0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CancelResolution {
    Cancelled,
    Terminal(TerminationResult),
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn<System: WyrmshSystem>(
    system: &mut System,
    stdout: &mut NativeOutput,
    stderr: &mut NativeOutput,
    identity: ShellIdentity,
    controls: Controls,
    transactions: &mut TransactionIds,
    jobs: &mut JobTable,
    path: &str,
    argv: Arguments<'_>,
) -> Result<(), ShellError> {
    let Some(slot) = jobs.reserve() else {
        return expected_text(system, stderr, stdout, controls, b"spawn", b"capacity");
    };
    match launch(
        system,
        stdout,
        stderr,
        identity,
        controls,
        transactions,
        path,
        argv,
        &[],
    ) {
        Ok(job_id) => {
            if !jobs.publish(slot, job_id) {
                return Err(ShellError::InspectionProtocol);
            }
            write_stdout(
                system,
                stdout,
                stderr.endpoint().handle(),
                controls,
                b"spawn job=",
            )?;
            write_decimal(system, stdout, stderr, controls, job_id)?;
            write_stdout(system, stdout, stderr.endpoint().handle(), controls, b"\n")
        }
        Err(LaunchFailure {
            kind: LaunchFailureKind::Expected(code),
            ..
        }) => {
            jobs.abort(slot);
            launch_error(system, stderr, stdout, controls, b"spawn", code)
        }
        Err(LaunchFailure {
            kind: LaunchFailureKind::Fatal(error),
            ..
        }) => {
            jobs.abort(slot);
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run<System: WyrmshSystem>(
    system: &mut System,
    stdout: &mut NativeOutput,
    stderr: &mut NativeOutput,
    identity: ShellIdentity,
    controls: Controls,
    transactions: &mut TransactionIds,
    jobs: &mut JobTable,
    path: &str,
    argv: Arguments<'_>,
) -> Result<(), ShellError> {
    let Some(slot) = jobs.reserve() else {
        return expected_text(system, stderr, stdout, controls, b"run", b"capacity");
    };
    let mut pairs = [EMPTY_PAIR; 3];
    if let Err(error) = create_stream_pairs(system, &mut pairs) {
        jobs.abort(slot);
        close_pairs(system, &mut pairs, true)?;
        return Err(error);
    }
    let transfers = pairs.map(|pair| DwHandleTransferV1 {
        handle: pair.child,
        requested_rights: CHILD_CHANNEL_TRANSFER_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        ..DwHandleTransferV1::default()
    });
    let launched = launch(
        system,
        stdout,
        stderr,
        identity,
        controls,
        transactions,
        path,
        argv,
        &transfers,
    );
    let job_id = match launched {
        Ok(job_id) => {
            for pair in &mut pairs {
                pair.child = DwHandle(0);
            }
            job_id
        }
        Err(LaunchFailure {
            kind: LaunchFailureKind::Expected(code),
            committed,
        }) => {
            jobs.abort(slot);
            close_pairs(system, &mut pairs, !committed)?;
            return launch_error(system, stderr, stdout, controls, b"run", code);
        }
        Err(LaunchFailure {
            kind: LaunchFailureKind::Fatal(error),
            committed,
        }) => {
            jobs.abort(slot);
            close_pairs(system, &mut pairs, !committed)?;
            return Err(error);
        }
    };
    if !jobs.publish(slot, job_id) {
        close_pairs(system, &mut pairs, false)?;
        return Err(ShellError::InspectionProtocol);
    }
    if let Err(error) = close_one(system, &mut pairs[0].retained) {
        return cleanup_then_error(system, &mut pairs, error);
    }
    let mut child_stdout = NativeInput::new(
        StreamEndpoint::from_validated_handle(pairs[1].retained).map_err(ShellError::Stream)?,
    );
    let mut child_stderr = NativeInput::new(
        StreamEndpoint::from_validated_handle(pairs[2].retained).map_err(ShellError::Stream)?,
    );
    let wait_transaction = match start_job_request(
        system,
        stdout,
        stderr,
        identity,
        controls,
        transactions,
        MessageType::Wait,
        job_id,
    ) {
        Ok(transaction) => transaction,
        Err(error) => return cleanup_then_error(system, &mut pairs, error),
    };
    let outcome = drain_foreground(
        system,
        stdout,
        stderr,
        identity,
        controls,
        wait_transaction,
        job_id,
        &mut child_stdout,
        &mut child_stderr,
    );
    // NativeInput does not own or close its endpoint. Reverse-close both
    // retained child outputs before any terminal cleanup transaction.
    close_pairs(system, &mut pairs, false)?;
    match outcome {
        Ok(result) => {
            if !jobs.set_state(job_id, JobState::Completed(result)) {
                return Err(ShellError::InspectionProtocol);
            }
            present_result(system, stdout, stderr, controls, job_id, result, None)?;
            close_job(
                system,
                stdout,
                stderr,
                identity,
                controls,
                transactions,
                jobs,
                job_id,
            )
        }
        Err(ForegroundError::Stream) => {
            let resolution = cancel_wait(
                system,
                stdout,
                stderr,
                identity,
                controls,
                transactions,
                wait_transaction,
                job_id,
            )?;
            if let CancelResolution::Terminal(result) = resolution
                && !jobs.set_state(job_id, JobState::Completed(result))
            {
                return Err(ShellError::InspectionProtocol);
            }
            close_job(
                system,
                stdout,
                stderr,
                identity,
                controls,
                transactions,
                jobs,
                job_id,
            )?;
            write_stderr(
                system,
                stderr,
                stdout.endpoint().handle(),
                controls,
                b"run stream=failed\n",
            )
        }
        Err(ForegroundError::Fatal(error)) => Err(error),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn wait<System: WyrmshSystem>(
    system: &mut System,
    stdout: &mut NativeOutput,
    stderr: &mut NativeOutput,
    identity: ShellIdentity,
    controls: Controls,
    transactions: &mut TransactionIds,
    jobs: &mut JobTable,
    job_id: u64,
) -> Result<(), ShellError> {
    if jobs.state(job_id).is_none() {
        return expected_job_text(
            system, stderr, stdout, controls, b"wait", job_id, b"foreign",
        );
    }
    let transaction = start_job_request(
        system,
        stdout,
        stderr,
        identity,
        controls,
        transactions,
        MessageType::Wait,
        job_id,
    )?;
    match receive_expected(system, identity, controls, stdout, stderr, transaction)? {
        Reply::JobResult(actual, result) if actual == job_id => {
            if !jobs.set_state(job_id, JobState::Completed(result)) {
                return Err(ShellError::InspectionProtocol);
            }
            present_result(system, stdout, stderr, controls, job_id, result, None)?;
            close_job(
                system,
                stdout,
                stderr,
                identity,
                controls,
                transactions,
                jobs,
                job_id,
            )
        }
        Reply::Error(ErrorCode::ForeignOrUnknownJob) => {
            if !jobs.remove(job_id) {
                return Err(ShellError::InspectionProtocol);
            }
            expected_job_text(
                system, stderr, stdout, controls, b"wait", job_id, b"foreign",
            )
        }
        Reply::Error(ErrorCode::InvalidState) => expected_job_text(
            system,
            stderr,
            stdout,
            controls,
            b"wait",
            job_id,
            b"invalid-state",
        ),
        Reply::Error(code) => {
            expected_operation_error(system, stderr, stdout, controls, b"wait", code)
        }
        _ => Err(ShellError::InspectionProtocol),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn terminate<System: WyrmshSystem>(
    system: &mut System,
    stdout: &mut NativeOutput,
    stderr: &mut NativeOutput,
    identity: ShellIdentity,
    controls: Controls,
    transactions: &mut TransactionIds,
    jobs: &mut JobTable,
    job_id: u64,
) -> Result<(), ShellError> {
    if !matches!(jobs.state(job_id), Some(JobState::Active)) {
        return expected_job_text(
            system,
            stderr,
            stdout,
            controls,
            b"terminate",
            job_id,
            b"invalid-state",
        );
    }
    match fixed_job_request(
        system,
        stdout,
        stderr,
        identity,
        controls,
        transactions,
        MessageType::Terminate,
        job_id,
    )? {
        Reply::TerminationAccepted(actual) if actual == job_id => {
            if !jobs.set_state(job_id, JobState::Terminating) {
                return Err(ShellError::InspectionProtocol);
            }
            write_stdout(
                system,
                stdout,
                stderr.endpoint().handle(),
                controls,
                b"terminate job=",
            )?;
            write_decimal(system, stdout, stderr, controls, job_id)?;
            write_stdout(
                system,
                stdout,
                stderr.endpoint().handle(),
                controls,
                b" status=accepted\n",
            )
        }
        Reply::Error(ErrorCode::ForeignOrUnknownJob) => {
            if !jobs.remove(job_id) {
                return Err(ShellError::InspectionProtocol);
            }
            expected_job_text(
                system,
                stderr,
                stdout,
                controls,
                b"terminate",
                job_id,
                b"foreign",
            )
        }
        Reply::Error(ErrorCode::InvalidState) => expected_job_text(
            system,
            stderr,
            stdout,
            controls,
            b"terminate",
            job_id,
            b"invalid-state",
        ),
        Reply::Error(code) => {
            expected_operation_error(system, stderr, stdout, controls, b"terminate", code)
        }
        _ => Err(ShellError::InspectionProtocol),
    }
}

#[allow(clippy::too_many_arguments)]
fn launch<System: WyrmshSystem>(
    system: &mut System,
    stdout: &NativeOutput,
    stderr: &NativeOutput,
    identity: ShellIdentity,
    controls: Controls,
    transactions: &mut TransactionIds,
    path: &str,
    argv: Arguments<'_>,
    transfers: &[DwHandleTransferV1],
) -> Result<u64, LaunchFailure> {
    let transaction = transactions.launch().map_err(|_| LaunchFailure {
        kind: LaunchFailureKind::Fatal(ShellError::TransactionExhausted),
        committed: false,
    })?;
    let reservation = reservation(identity, transaction);
    let mut arguments = [""; MAX_ARGV];
    let mut count = 0;
    for argument in argv.iter() {
        arguments[count] = argument;
        count += 1;
    }
    let mut request = [0_u8; MAX_LAUNCH_MESSAGE_BYTES];
    let size = encode_launch(
        reservation,
        path,
        &arguments[..count],
        &[],
        !transfers.is_empty(),
        &mut request,
    )
    .map_err(|_| LaunchFailure {
        kind: LaunchFailureKind::Fatal(ShellError::InspectionProtocol),
        committed: false,
    })?;
    send_progress_neutral(
        system,
        controls,
        stdout.endpoint().handle(),
        stderr.endpoint().handle(),
        &request[..size],
        transfers,
    )
    .map_err(|error| LaunchFailure {
        kind: LaunchFailureKind::Fatal(error),
        committed: false,
    })?;
    match receive_expected(system, identity, controls, stdout, stderr, transaction).map_err(
        |error| LaunchFailure {
            kind: LaunchFailureKind::Fatal(error),
            committed: true,
        },
    )? {
        Reply::LaunchAccepted(job_id) => Ok(job_id),
        Reply::Error(code) if recoverable_launch_error(code) => Err(LaunchFailure {
            kind: LaunchFailureKind::Expected(code),
            committed: true,
        }),
        _ => Err(LaunchFailure {
            kind: LaunchFailureKind::Fatal(ShellError::InspectionProtocol),
            committed: true,
        }),
    }
}

fn recoverable_launch_error(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::Capacity | ErrorCode::PolicyRejected | ErrorCode::LoaderFailure
    )
}

fn create_stream_pairs<System: WyrmshSystem>(
    system: &mut System,
    pairs: &mut [StreamPair; 3],
) -> Result<(), ShellError> {
    for pair in pairs {
        let (retained_broad, child) = system
            .create_channel(CHANNEL_CONSTRUCTION_RIGHTS)
            .map_err(|cause| native(NativeOperation::CreateChannel, cause))?;
        pair.retained = retained_broad;
        pair.child = child;
        let retained = match system.duplicate_handle(retained_broad, CHILD_CHANNEL_RIGHTS) {
            Ok(handle) => handle,
            Err(cause) => return Err(native(NativeOperation::DuplicateHandle, cause)),
        };
        if let Err(cause) = system.close_handle(retained_broad) {
            let _ = system.close_handle(retained);
            return Err(native(NativeOperation::Cleanup, cause));
        }
        pair.retained = retained;
        for (handle, rights) in [
            (pair.retained, CHILD_CHANNEL_RIGHTS),
            (pair.child, CHANNEL_CONSTRUCTION_RIGHTS),
        ] {
            let fresh = system
                .query_capability_info(handle)
                .map_err(|cause| native(NativeOperation::QueryRole, cause))?;
            if fresh.object_type != DW_OBJECT_TYPE_CHANNEL || fresh.rights != rights {
                return Err(ShellError::InspectionProtocol);
            }
        }
    }
    Ok(())
}

fn close_pairs<System: WyrmshSystem>(
    system: &mut System,
    pairs: &mut [StreamPair; 3],
    include_children: bool,
) -> Result<(), ShellError> {
    let mut failure = None;
    for pair in pairs.iter_mut().rev() {
        if include_children {
            close_record(system, &mut pair.child, &mut failure);
        }
        close_record(system, &mut pair.retained, &mut failure);
    }
    failure.map_or(Ok(()), |cause| Err(native(NativeOperation::Cleanup, cause)))
}

fn cleanup_then_error<System: WyrmshSystem>(
    system: &mut System,
    pairs: &mut [StreamPair; 3],
    original: ShellError,
) -> Result<(), ShellError> {
    match close_pairs(system, pairs, false) {
        Ok(()) => Err(original),
        Err(cleanup) => Err(cleanup),
    }
}

fn close_one<System: WyrmshSystem>(
    system: &mut System,
    handle: &mut DwHandle,
) -> Result<(), ShellError> {
    if handle.0 == 0 {
        return Ok(());
    }
    let local = *handle;
    system
        .close_handle(local)
        .map_err(|cause| native(NativeOperation::Cleanup, cause))?;
    *handle = DwHandle(0);
    Ok(())
}

fn close_record<System: WyrmshSystem>(
    system: &mut System,
    handle: &mut DwHandle,
    failure: &mut Option<NativeError>,
) {
    if handle.0 != 0 {
        let local = *handle;
        if let Err(error) = system.close_handle(local) {
            failure.get_or_insert(error);
        } else {
            *handle = DwHandle(0);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn start_job_request<System: WyrmshSystem>(
    system: &mut System,
    stdout: &NativeOutput,
    stderr: &NativeOutput,
    identity: ShellIdentity,
    controls: Controls,
    transactions: &mut TransactionIds,
    kind: MessageType,
    value: u64,
) -> Result<u64, ShellError> {
    let transaction = transactions
        .launch()
        .map_err(|_| ShellError::TransactionExhausted)?;
    let mut request = [0_u8; 56];
    let size = encode_job_message(
        reservation(identity, transaction),
        kind,
        value,
        &mut request,
    )
    .map_err(|_| ShellError::InspectionProtocol)?;
    send_progress_neutral(
        system,
        controls,
        stdout.endpoint().handle(),
        stderr.endpoint().handle(),
        &request[..size],
        &[],
    )?;
    Ok(transaction)
}

#[allow(clippy::too_many_arguments)]
fn send_progress_neutral<System: WyrmshSystem>(
    system: &mut System,
    controls: Controls,
    stdout: DwHandle,
    stderr: DwHandle,
    bytes: &[u8],
    transfers: &[DwHandleTransferV1],
) -> Result<(), ShellError> {
    let deadline = control_deadline(system)?;
    loop {
        poll_health(system, controls, stdout, stderr)?;
        ensure_before_control_deadline(system, deadline)?;
        match system.send_channel_with_handles(controls.shell_jobs, bytes, transfers) {
            Ok(()) => return Ok(()),
            Err(NativeError::Status(status)) if status == DW_STATUS_WOULD_BLOCK => {}
            Err(cause) => return Err(native(NativeOperation::ControlSend, cause)),
        }
        let mut items = health_items(controls, stdout, stderr);
        items[2] = wait_item(
            controls.shell_jobs,
            DwSignals(DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        );
        match system.wait_many(&items, deadline) {
            Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
                return Err(ShellError::InspectionTimeout);
            }
            Err(cause) => return Err(native(NativeOperation::Wait, cause)),
            Ok(result) if result.index == 2 => {
                if result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
                    return Err(ShellError::RequiredEndpointLost(EndpointRole::ShellJobs));
                }
                if result.observed.0 & DW_SIGNAL_WRITABLE.0 == 0 {
                    return Err(ShellError::InspectionProtocol);
                }
                ensure_before_control_deadline(system, deadline)?;
            }
            Ok(result) => classify_health(result)?,
        }
    }
}

fn progress_deadline<System: WyrmshSystem>(system: &mut System) -> Result<DwDeadline, ShellError> {
    let deadline = system
        .monotonic_active_now()
        .map_err(|cause| native(NativeOperation::MonotonicClock, cause))?
        .checked_add(STATUS_TIMEOUT_NS)
        .ok_or(ShellError::InspectionProtocol)?;
    if deadline == DW_DEADLINE_INFINITE.0 {
        return Err(ShellError::InspectionProtocol);
    }
    Ok(DwDeadline(deadline))
}

#[allow(clippy::too_many_arguments)]
fn receive_expected<System: WyrmshSystem>(
    system: &mut System,
    identity: ShellIdentity,
    controls: Controls,
    stdout: &NativeOutput,
    stderr: &NativeOutput,
    transaction: u64,
) -> Result<Reply, ShellError> {
    loop {
        if let Some((_, reply)) = receive_one(
            system,
            identity,
            controls,
            stdout,
            stderr,
            Some(transaction),
            None,
        )? {
            return Ok(reply);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn receive_one<System: WyrmshSystem>(
    system: &mut System,
    identity: ShellIdentity,
    controls: Controls,
    stdout: &NativeOutput,
    stderr: &NativeOutput,
    first: Option<u64>,
    second: Option<u64>,
) -> Result<Option<(u64, Reply)>, ShellError> {
    let deadline = progress_deadline(system)?;
    let mut items = health_items(
        controls,
        stdout.endpoint().handle(),
        stderr.endpoint().handle(),
    );
    items[2] = wait_item(
        controls.shell_jobs,
        DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    );
    let result = match system.wait_many(&items, deadline) {
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => return Ok(None),
        Err(cause) => return Err(native(NativeOperation::Wait, cause)),
        Ok(result) => result,
    };
    if result.index != 2 {
        classify_health(result)?;
        return Err(ShellError::InspectionProtocol);
    }
    if result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
        return Err(ShellError::RequiredEndpointLost(EndpointRole::ShellJobs));
    }
    if result.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(ShellError::InspectionProtocol);
    }
    let mut bytes = [0_u8; 88];
    let mut handles = [DwReceivedHandleInfoV1::default(); 4];
    let counts = match system.receive_channel(controls.shell_jobs, &mut bytes, &mut handles) {
        Err(NativeError::Status(status)) if status == DW_STATUS_PEER_CLOSED => {
            return Err(ShellError::RequiredEndpointLost(EndpointRole::ShellJobs));
        }
        Err(cause) => return Err(native(NativeOperation::ControlReceive, cause)),
        Ok(counts) => counts,
    };
    if counts.handles != 0 {
        let mut failure = None;
        for received in handles.iter().take(counts.handles.min(handles.len())).rev() {
            if received.handle.0 != 0
                && let Err(error) = system.close_handle(received.handle)
            {
                failure.get_or_insert(error);
            }
        }
        if let Some(cause) = failure {
            return Err(native(NativeOperation::Cleanup, cause));
        }
        return Err(ShellError::InspectionProtocol);
    }
    if counts.bytes > bytes.len() {
        return Err(ShellError::InspectionProtocol);
    }
    let parsed = wyrmroot_launch_proto::parse_message(&bytes[..counts.bytes], 0)
        .map_err(|_| ShellError::InspectionProtocol)?;
    if parsed.reservation.connection_id != identity.launch_connection_id
        || parsed.reservation.generation != identity.launch_connection_generation
        || (Some(parsed.reservation.transaction_id) != first
            && Some(parsed.reservation.transaction_id) != second)
    {
        return Err(ShellError::InspectionProtocol);
    }
    let transaction = parsed.reservation.transaction_id;
    let reply = decode_reply(identity, transaction, &bytes[..counts.bytes], 0)
        .map_err(|_| ShellError::InspectionProtocol)?;
    Ok(Some((transaction, reply)))
}

#[derive(Debug)]
enum ForegroundError {
    Stream,
    Fatal(ShellError),
}

struct PendingOutput {
    bytes: [u8; 256],
    offset: usize,
    used: usize,
}

impl PendingOutput {
    const fn new() -> Self {
        Self {
            bytes: [0; 256],
            offset: 0,
            used: 0,
        }
    }

    const fn is_empty(&self) -> bool {
        self.offset == self.used
    }

    fn clear(&mut self) {
        self.offset = 0;
        self.used = 0;
    }
}

#[allow(clippy::too_many_arguments)]
fn drain_foreground<System: WyrmshSystem>(
    system: &mut System,
    stdout: &mut NativeOutput,
    stderr: &mut NativeOutput,
    identity: ShellIdentity,
    controls: Controls,
    wait_transaction: u64,
    job_id: u64,
    child_stdout: &mut NativeInput,
    child_stderr: &mut NativeInput,
) -> Result<TerminationResult, ForegroundError> {
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    let mut terminal = None;
    let mut first_stdout = true;
    let mut stdout_pending = PendingOutput::new();
    let mut stderr_pending = PendingOutput::new();
    loop {
        poll_health(
            system,
            controls,
            stdout.endpoint().handle(),
            stderr.endpoint().handle(),
        )
        .map_err(ForegroundError::Fatal)?;
        let mut progress = false;
        for offset in 0..2 {
            let use_stdout = (offset == 0) == first_stdout;
            let (input, output, eof, pending, output_role) = if use_stdout {
                (
                    &mut *child_stdout,
                    &mut *stdout,
                    &mut stdout_eof,
                    &mut stdout_pending,
                    EndpointRole::Stdout,
                )
            } else {
                (
                    &mut *child_stderr,
                    &mut *stderr,
                    &mut stderr_eof,
                    &mut stderr_pending,
                    EndpointRole::Stderr,
                )
            };
            if !pending.is_empty() {
                match output.write(system, &pending.bytes[pending.offset..pending.used]) {
                    Ok(0) => return Err(ForegroundError::Stream),
                    Ok(written) => {
                        pending.offset += written;
                        if pending.is_empty() {
                            pending.clear();
                        }
                        progress = true;
                    }
                    Err(StreamError::WouldBlock) => {}
                    Err(StreamError::Broken) => {
                        return Err(ForegroundError::Fatal(ShellError::RequiredEndpointLost(
                            output_role,
                        )));
                    }
                    Err(error) => return Err(ForegroundError::Fatal(ShellError::Stream(error))),
                }
                continue;
            }
            if *eof {
                continue;
            }
            let mut bounded = ReceiveBudget::new(system);
            match input.read(&mut bounded, &mut pending.bytes) {
                Ok(0) => return Err(ForegroundError::Stream),
                Ok(used) => {
                    pending.offset = 0;
                    pending.used = used;
                    progress = true;
                }
                Err(StreamError::WouldBlock) => {}
                Err(StreamError::Eof) => {
                    *eof = true;
                    progress = true;
                }
                Err(_) => return Err(ForegroundError::Stream),
            }
        }
        first_stdout = !first_stdout;
        if terminal.is_none() {
            match try_receive_job(system, identity, controls, stdout, stderr, wait_transaction)
                .map_err(ForegroundError::Fatal)?
            {
                Some(Reply::JobResult(actual, result)) if actual == job_id => {
                    terminal = Some(result);
                    progress = true;
                }
                Some(Reply::Error(code)) => {
                    return Err(ForegroundError::Fatal(job_error_fatal(code)));
                }
                Some(_) => return Err(ForegroundError::Fatal(ShellError::InspectionProtocol)),
                None => {}
            }
        }
        if let Some(result) = terminal
            && stdout_eof
            && stderr_eof
            && stdout_pending.is_empty()
            && stderr_pending.is_empty()
        {
            return Ok(result);
        }
        if !progress {
            wait_foreground(
                system,
                controls,
                stdout,
                stderr,
                child_stdout,
                child_stderr,
                stdout_eof,
                stderr_eof,
                !stdout_pending.is_empty(),
                !stderr_pending.is_empty(),
            )
            .map_err(ForegroundError::Fatal)?;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn try_receive_job<System: WyrmshSystem>(
    system: &mut System,
    identity: ShellIdentity,
    controls: Controls,
    _stdout: &NativeOutput,
    _stderr: &NativeOutput,
    transaction: u64,
) -> Result<Option<Reply>, ShellError> {
    let mut bytes = [0_u8; 88];
    let mut handles = [DwReceivedHandleInfoV1::default(); 4];
    let counts = match system.receive_channel(controls.shell_jobs, &mut bytes, &mut handles) {
        Err(NativeError::Status(status)) if status == DW_STATUS_WOULD_BLOCK => return Ok(None),
        Err(NativeError::Status(status)) if status == DW_STATUS_PEER_CLOSED => {
            return Err(ShellError::RequiredEndpointLost(EndpointRole::ShellJobs));
        }
        Err(cause) => return Err(native(NativeOperation::ControlReceive, cause)),
        Ok(counts) => counts,
    };
    if counts.handles != 0 || counts.bytes > bytes.len() {
        for received in handles.iter().take(counts.handles.min(handles.len())).rev() {
            if received.handle.0 != 0 {
                system
                    .close_handle(received.handle)
                    .map_err(|cause| native(NativeOperation::Cleanup, cause))?;
            }
        }
        return Err(ShellError::InspectionProtocol);
    }
    decode_reply(identity, transaction, &bytes[..counts.bytes], 0)
        .map(Some)
        .map_err(|_| ShellError::InspectionProtocol)
}

#[allow(clippy::too_many_arguments)]
fn wait_foreground<System: WyrmshSystem>(
    system: &mut System,
    controls: Controls,
    stdout: &NativeOutput,
    stderr: &NativeOutput,
    child_stdout: &mut NativeInput,
    child_stderr: &mut NativeInput,
    stdout_eof: bool,
    stderr_eof: bool,
    stdout_pending: bool,
    stderr_pending: bool,
) -> Result<(), ShellError> {
    let health = health_items(
        controls,
        stdout.endpoint().handle(),
        stderr.endpoint().handle(),
    );
    let mut items = [wait_item(DwHandle(0), DwSignals(0)); 7];
    items[..5].copy_from_slice(&[
        health[0],
        health[1],
        wait_item(
            controls.shell_jobs,
            DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        ),
        health[3],
        health[4],
    ]);
    if stdout_pending {
        items[3] = wait_item(
            stdout.endpoint().handle(),
            DwSignals(DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        );
    }
    if stderr_pending {
        items[4] = wait_item(
            stderr.endpoint().handle(),
            DwSignals(DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        );
    }
    let mut count = 5;
    let stdout_index = if stdout_eof || stdout_pending {
        None
    } else {
        items[count] = wait_item(
            child_stdout.endpoint().handle(),
            DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        );
        count += 1;
        Some(count - 1)
    };
    let stderr_index = if stderr_eof || stderr_pending {
        None
    } else {
        items[count] = wait_item(
            child_stderr.endpoint().handle(),
            DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        );
        count += 1;
        Some(count - 1)
    };
    let deadline = progress_deadline(system)?;
    let result = match system.wait_many(&items[..count], deadline) {
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => return Ok(()),
        Err(cause) => return Err(native(NativeOperation::Wait, cause)),
        Ok(result) => result,
    };
    match result.index {
        0 | 1 => classify_health(result),
        3 if stdout_pending => {
            if result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
                classify_health(result)
            } else if result.observed.0 & DW_SIGNAL_WRITABLE.0 != 0 {
                Ok(())
            } else {
                Err(ShellError::InspectionProtocol)
            }
        }
        4 if stderr_pending => {
            if result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
                classify_health(result)
            } else if result.observed.0 & DW_SIGNAL_WRITABLE.0 != 0 {
                Ok(())
            } else {
                Err(ShellError::InspectionProtocol)
            }
        }
        3 | 4 => classify_health(result),
        2 => {
            if result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
                Err(ShellError::RequiredEndpointLost(EndpointRole::ShellJobs))
            } else if result.observed.0 & DW_SIGNAL_READABLE.0 != 0 {
                Ok(())
            } else {
                Err(ShellError::InspectionProtocol)
            }
        }
        index if usize::try_from(index).ok() == stdout_index => child_stdout
            .observe_wait(result.observed)
            .map_err(ShellError::Stream),
        index if usize::try_from(index).ok() == stderr_index => child_stderr
            .observe_wait(result.observed)
            .map_err(ShellError::Stream),
        _ => Err(ShellError::InspectionProtocol),
    }
}

fn job_error_fatal(_code: ErrorCode) -> ShellError {
    ShellError::InspectionProtocol
}

#[allow(clippy::too_many_arguments)]
fn cancel_wait<System: WyrmshSystem>(
    system: &mut System,
    stdout: &NativeOutput,
    stderr: &NativeOutput,
    identity: ShellIdentity,
    controls: Controls,
    transactions: &mut TransactionIds,
    wait_transaction: u64,
    job_id: u64,
) -> Result<CancelResolution, ShellError> {
    let cancel_transaction = transactions
        .launch()
        .map_err(|_| ShellError::TransactionExhausted)?;
    let mut request = [0_u8; 56];
    let size = encode_job_message(
        reservation(identity, cancel_transaction),
        MessageType::Cancel,
        wait_transaction,
        &mut request,
    )
    .map_err(|_| ShellError::InspectionProtocol)?;
    let deadline = control_deadline(system)?;
    send_control(
        system,
        controls.shell_jobs,
        EndpointRole::ShellJobs,
        controls,
        stdout.endpoint().handle(),
        stderr.endpoint().handle(),
        &request[..size],
        deadline,
    )?;
    let mut result = None;
    let mut unavailable = false;
    loop {
        if system
            .monotonic_active_now()
            .map_err(|cause| native(NativeOperation::MonotonicClock, cause))?
            >= deadline.0
        {
            return Err(ShellError::InspectionTimeout);
        }
        let Some((transaction, reply)) = receive_one_until(
            system,
            identity,
            controls,
            stdout,
            stderr,
            wait_transaction,
            cancel_transaction,
            deadline,
        )?
        else {
            return Err(ShellError::InspectionTimeout);
        };
        ensure_before_control_deadline(system, deadline)?;
        if transaction == cancel_transaction {
            match reply {
                Reply::Cancelled(target)
                    if target == wait_transaction && result.is_none() && !unavailable =>
                {
                    return Ok(CancelResolution::Cancelled);
                }
                Reply::Error(ErrorCode::CancellationUnavailable) if !unavailable => {
                    unavailable = true
                }
                _ => return Err(ShellError::InspectionProtocol),
            }
        } else {
            match reply {
                Reply::JobResult(actual, terminal) if actual == job_id && result.is_none() => {
                    result = Some(terminal)
                }
                _ => return Err(ShellError::InspectionProtocol),
            }
        }
        if let (Some(terminal), true) = (result, unavailable) {
            return Ok(CancelResolution::Terminal(terminal));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn receive_one_until<System: WyrmshSystem>(
    system: &mut System,
    identity: ShellIdentity,
    controls: Controls,
    stdout: &NativeOutput,
    stderr: &NativeOutput,
    first: u64,
    second: u64,
    deadline: DwDeadline,
) -> Result<Option<(u64, Reply)>, ShellError> {
    let mut items = health_items(
        controls,
        stdout.endpoint().handle(),
        stderr.endpoint().handle(),
    );
    items[2] = wait_item(
        controls.shell_jobs,
        DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    );
    let result = match system.wait_many(&items, deadline) {
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => return Ok(None),
        Err(cause) => return Err(native(NativeOperation::Wait, cause)),
        Ok(result) => result,
    };
    if result.index != 2 {
        classify_health(result)?;
        return Err(ShellError::InspectionProtocol);
    }
    if result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
        return Err(ShellError::RequiredEndpointLost(EndpointRole::ShellJobs));
    }
    if result.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(ShellError::InspectionProtocol);
    }
    receive_correlated_datagram(system, identity, controls, first, second)
}

fn receive_correlated_datagram<System: WyrmshSystem>(
    system: &mut System,
    identity: ShellIdentity,
    controls: Controls,
    first: u64,
    second: u64,
) -> Result<Option<(u64, Reply)>, ShellError> {
    let mut bytes = [0_u8; 88];
    let mut handles = [DwReceivedHandleInfoV1::default(); 4];
    let counts = match system.receive_channel(controls.shell_jobs, &mut bytes, &mut handles) {
        Err(NativeError::Status(status)) if status == DW_STATUS_PEER_CLOSED => {
            return Err(ShellError::RequiredEndpointLost(EndpointRole::ShellJobs));
        }
        Err(cause) => return Err(native(NativeOperation::ControlReceive, cause)),
        Ok(counts) => counts,
    };
    if counts.handles != 0 || counts.bytes > bytes.len() {
        for received in handles.iter().take(counts.handles.min(handles.len())).rev() {
            if received.handle.0 != 0 {
                system
                    .close_handle(received.handle)
                    .map_err(|cause| native(NativeOperation::Cleanup, cause))?;
            }
        }
        return Err(ShellError::InspectionProtocol);
    }
    let parsed = wyrmroot_launch_proto::parse_message(&bytes[..counts.bytes], 0)
        .map_err(|_| ShellError::InspectionProtocol)?;
    let transaction = parsed.reservation.transaction_id;
    if transaction != first && transaction != second {
        return Err(ShellError::InspectionProtocol);
    }
    let reply = decode_reply(identity, transaction, &bytes[..counts.bytes], 0)
        .map_err(|_| ShellError::InspectionProtocol)?;
    Ok(Some((transaction, reply)))
}

#[allow(clippy::too_many_arguments)]
fn close_job<System: WyrmshSystem>(
    system: &mut System,
    stdout: &NativeOutput,
    stderr: &mut NativeOutput,
    identity: ShellIdentity,
    controls: Controls,
    transactions: &mut TransactionIds,
    jobs: &mut JobTable,
    job_id: u64,
) -> Result<(), ShellError> {
    match fixed_job_request(
        system,
        stdout,
        stderr,
        identity,
        controls,
        transactions,
        MessageType::CloseJob,
        job_id,
    )? {
        Reply::Closed(actual) if actual == job_id => {
            if !jobs.remove(job_id) {
                return Err(ShellError::InspectionProtocol);
            }
            Ok(())
        }
        Reply::Error(ErrorCode::ForeignOrUnknownJob) => {
            if !jobs.remove(job_id) {
                return Err(ShellError::InspectionProtocol);
            }
            Ok(())
        }
        Reply::Error(code) => {
            expected_operation_error(system, stderr, stdout, controls, b"close", code)
        }
        _ => Err(ShellError::InspectionProtocol),
    }
}

#[allow(clippy::too_many_arguments)]
fn fixed_job_request<System: WyrmshSystem>(
    system: &mut System,
    stdout: &NativeOutput,
    stderr: &NativeOutput,
    identity: ShellIdentity,
    controls: Controls,
    transactions: &mut TransactionIds,
    kind: MessageType,
    value: u64,
) -> Result<Reply, ShellError> {
    let transaction = transactions
        .launch()
        .map_err(|_| ShellError::TransactionExhausted)?;
    let mut request = [0_u8; 56];
    let size = encode_job_message(
        reservation(identity, transaction),
        kind,
        value,
        &mut request,
    )
    .map_err(|_| ShellError::InspectionProtocol)?;
    let deadline = control_deadline(system)?;
    send_control(
        system,
        controls.shell_jobs,
        EndpointRole::ShellJobs,
        controls,
        stdout.endpoint().handle(),
        stderr.endpoint().handle(),
        &request[..size],
        deadline,
    )?;
    let mut response = [0_u8; 88];
    let used = receive_control(
        system,
        controls.shell_jobs,
        EndpointRole::ShellJobs,
        controls,
        stdout.endpoint().handle(),
        stderr.endpoint().handle(),
        &mut response,
        deadline,
    )?;
    let reply = decode_reply(identity, transaction, &response[..used], 0)
        .map_err(|_| ShellError::InspectionProtocol)?;
    ensure_before_control_deadline(system, deadline)?;
    Ok(reply)
}

fn present_result<System: WyrmshSystem>(
    system: &mut System,
    stdout: &mut NativeOutput,
    stderr: &NativeOutput,
    controls: Controls,
    job_id: u64,
    result: TerminationResult,
    suffix: Option<&[u8]>,
) -> Result<(), ShellError> {
    write_stdout(
        system,
        stdout,
        stderr.endpoint().handle(),
        controls,
        b"job result job=",
    )?;
    write_decimal(system, stdout, stderr, controls, job_id)?;
    write_stdout(
        system,
        stdout,
        stderr.endpoint().handle(),
        controls,
        b" classification=",
    )?;
    let class = match result.classification {
        TerminationClassification::NormalExit => b"normal".as_slice(),
        TerminationClassification::Authorized => b"authorized".as_slice(),
        TerminationClassification::UnhandledException => b"exception".as_slice(),
        TerminationClassification::ResourcePolicy => b"resource-policy".as_slice(),
        TerminationClassification::TaskGroupTeardown => b"task-group-teardown".as_slice(),
    };
    write_stdout(system, stdout, stderr.endpoint().handle(), controls, class)?;
    for (label, value) in [
        (
            b" application=".as_slice(),
            u64::from(result.application_code),
        ),
        (
            b" exception-class=".as_slice(),
            u64::from(result.exception_class),
        ),
        (
            b" exception-detail=".as_slice(),
            u64::from(result.exception_detail),
        ),
        (b" exception-address=".as_slice(), result.exception_address),
        (b" cleanup=".as_slice(), u64::from(result.cleanup_result)),
    ] {
        write_stdout(system, stdout, stderr.endpoint().handle(), controls, label)?;
        write_decimal(system, stdout, stderr, controls, value)?;
    }
    if let Some(suffix) = suffix {
        write_stdout(system, stdout, stderr.endpoint().handle(), controls, suffix)?;
    }
    write_stdout(system, stdout, stderr.endpoint().handle(), controls, b"\n")
}

fn write_decimal<System: WyrmshSystem>(
    system: &mut System,
    stdout: &mut NativeOutput,
    stderr: &NativeOutput,
    controls: Controls,
    mut value: u64,
) -> Result<(), ShellError> {
    let mut bytes = [0_u8; 20];
    let mut cursor = bytes.len();
    loop {
        cursor -= 1;
        bytes[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            return write_stdout(
                system,
                stdout,
                stderr.endpoint().handle(),
                controls,
                &bytes[cursor..],
            );
        }
    }
}

fn launch_error<System: WyrmshSystem>(
    system: &mut System,
    stderr: &mut NativeOutput,
    stdout: &NativeOutput,
    controls: Controls,
    command: &[u8],
    code: ErrorCode,
) -> Result<(), ShellError> {
    if !recoverable_launch_error(code) {
        return Err(ShellError::InspectionProtocol);
    }
    expected_text(system, stderr, stdout, controls, command, error_name(code))
}

fn expected_operation_error<System: WyrmshSystem>(
    system: &mut System,
    stderr: &mut NativeOutput,
    stdout: &NativeOutput,
    controls: Controls,
    command: &[u8],
    code: ErrorCode,
) -> Result<(), ShellError> {
    match code {
        ErrorCode::ForeignOrUnknownJob | ErrorCode::InvalidState => {
            expected_text(system, stderr, stdout, controls, command, error_name(code))
        }
        _ => Err(ShellError::InspectionProtocol),
    }
}

fn error_name(code: ErrorCode) -> &'static [u8] {
    match code {
        ErrorCode::MalformedRequest => b"malformed",
        ErrorCode::StaleOrUnknownSession => b"stale-session",
        ErrorCode::TransactionReplay => b"transaction-replay",
        ErrorCode::ForeignOrUnknownJob => b"foreign",
        ErrorCode::InvalidState => b"invalid-state",
        ErrorCode::Capacity => b"capacity",
        ErrorCode::PolicyRejected => b"policy-rejected",
        ErrorCode::LoaderFailure => b"loader-failure",
        ErrorCode::CleanupFailure => b"cleanup-failure",
        ErrorCode::CancellationUnavailable => b"cancellation-unavailable",
    }
}

fn expected_text<System: WyrmshSystem>(
    system: &mut System,
    stderr: &mut NativeOutput,
    stdout: &NativeOutput,
    controls: Controls,
    command: &[u8],
    status: &[u8],
) -> Result<(), ShellError> {
    write_stderr(
        system,
        stderr,
        stdout.endpoint().handle(),
        controls,
        command,
    )?;
    write_stderr(
        system,
        stderr,
        stdout.endpoint().handle(),
        controls,
        b" status=",
    )?;
    write_stderr(system, stderr, stdout.endpoint().handle(), controls, status)?;
    write_stderr(system, stderr, stdout.endpoint().handle(), controls, b"\n")
}

fn expected_job_text<System: WyrmshSystem>(
    system: &mut System,
    stderr: &mut NativeOutput,
    stdout: &NativeOutput,
    controls: Controls,
    command: &[u8],
    job_id: u64,
    status: &[u8],
) -> Result<(), ShellError> {
    write_stderr(
        system,
        stderr,
        stdout.endpoint().handle(),
        controls,
        command,
    )?;
    write_stderr(
        system,
        stderr,
        stdout.endpoint().handle(),
        controls,
        b" job=",
    )?;
    write_decimal_stderr(system, stderr, stdout, controls, job_id)?;
    write_stderr(
        system,
        stderr,
        stdout.endpoint().handle(),
        controls,
        b" status=",
    )?;
    write_stderr(system, stderr, stdout.endpoint().handle(), controls, status)?;
    write_stderr(system, stderr, stdout.endpoint().handle(), controls, b"\n")
}

fn write_decimal_stderr<System: WyrmshSystem>(
    system: &mut System,
    stderr: &mut NativeOutput,
    stdout: &NativeOutput,
    controls: Controls,
    mut value: u64,
) -> Result<(), ShellError> {
    let mut bytes = [0_u8; 20];
    let mut cursor = bytes.len();
    loop {
        cursor -= 1;
        bytes[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            return write_stderr(
                system,
                stderr,
                stdout.endpoint().handle(),
                controls,
                &bytes[cursor..],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_job_table_reserves_before_publish_and_never_evicts() {
        let mut table = JobTable::new();
        let first = table.reserve().unwrap();
        assert!(table.publish(first, 91));
        assert_eq!(table.state(91), Some(JobState::Active));
        assert!(table.set_state(91, JobState::Terminating));
        assert_eq!(table.state(91), Some(JobState::Terminating));
        for id in 1..MAX_VISIBLE_JOBS as u64 {
            let slot = table.reserve().unwrap();
            assert!(table.publish(slot, 100 + id));
        }
        assert!(table.reserve().is_none());
        assert!(table.remove(91));
        let replacement = table.reserve().unwrap();
        table.abort(replacement);
        assert!(table.reserve().is_some());
    }

    #[test]
    fn duplicate_and_zero_publish_cannot_corrupt_reservation() {
        let mut table = JobTable::new();
        let first = table.reserve().unwrap();
        assert!(table.publish(first, 7));
        let second = table.reserve().unwrap();
        assert!(!table.publish(second, 0));
        assert!(!table.publish(second, 7));
        table.abort(second);
        assert_eq!(table.state(7), Some(JobState::Active));
    }
}
