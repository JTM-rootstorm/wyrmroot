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

mod foreground;
mod launch;
mod present;
pub(crate) use foreground::*;
pub(crate) use launch::*;
pub(crate) use present::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Entry {
    pub(crate) id: u64,
    pub(crate) state: JobState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Slot(usize);

pub(crate) struct JobTable {
    pub(crate) entries: [Option<Entry>; MAX_VISIBLE_JOBS],
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
pub(crate) enum LaunchFailureKind {
    Expected(ErrorCode),
    Fatal(ShellError),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LaunchFailure {
    pub(crate) kind: LaunchFailureKind,
    pub(crate) committed: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct StreamPair {
    pub(crate) retained: DwHandle,
    pub(crate) child: DwHandle,
}

pub(crate) const EMPTY_PAIR: StreamPair = StreamPair {
    retained: DwHandle(0),
    child: DwHandle(0),
};

pub(crate) const CHANNEL_CONSTRUCTION_RIGHTS: deepwyrm_syscall::DwRights =
    deepwyrm_syscall::DwRights(CHILD_CHANNEL_TRANSFER_RIGHTS.0 | DW_RIGHT_DUPLICATE.0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CancelResolution {
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
        false,
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
    image: Option<(DwHandle, DwHandle)>,
) -> Result<(), ShellError> {
    // The image and namespace Channels go to init with the launch, or are
    // closed here.
    let close_image = |system: &mut System| {
        if let Some((image, namespace)) = image {
            let _ = system.close_handle(image);
            let _ = system.close_handle(namespace);
        }
    };
    let Some(slot) = jobs.reserve() else {
        close_image(system);
        return expected_text(system, stderr, stdout, controls, b"run", b"capacity");
    };
    let mut pairs = [EMPTY_PAIR; 3];
    if let Err(error) = create_stream_pairs(system, &mut pairs) {
        jobs.abort(slot);
        close_image(system);
        close_pairs(system, &mut pairs, true)?;
        return Err(error);
    }
    let mut transfers =
        [DwHandleTransferV1::default(); wyrmroot_launch_proto::LAUNCH_IMAGE_HANDLE_COUNT];
    for (transfer, pair) in transfers.iter_mut().zip(&pairs) {
        *transfer = DwHandleTransferV1 {
            handle: pair.child,
            requested_rights: CHILD_CHANNEL_TRANSFER_RIGHTS,
            operation: DW_HANDLE_TRANSFER_MOVE,
            ..DwHandleTransferV1::default()
        };
    }
    let count = match image {
        Some((image, namespace)) => {
            for (slot, handle) in transfers[3..].iter_mut().zip([image, namespace]) {
                *slot = DwHandleTransferV1 {
                    handle,
                    requested_rights: CHILD_CHANNEL_TRANSFER_RIGHTS,
                    operation: DW_HANDLE_TRANSFER_MOVE,
                    ..DwHandleTransferV1::default()
                };
            }
            wyrmroot_launch_proto::LAUNCH_IMAGE_HANDLE_COUNT
        }
        None => 3,
    };
    let launched = launch(
        system,
        stdout,
        stderr,
        identity,
        controls,
        transactions,
        path,
        argv,
        &transfers[..count],
        image.is_some(),
    );
    if launched.as_ref().is_err_and(|failure| !failure.committed) {
        close_image(system);
    }
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
        Err(ForegroundError::Stream(cause)) => {
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
            // F3A.6n / DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md §3.2: this
            // disposition already collapses many causes into one action
            // (cancel + close the job, shell survives), which §3.1 permits
            // because the action is identical for all of them. But the
            // collapse owes the discarded instance to the reader's channel
            // in the same change, so the literal used to read
            // "run stream=failed\n" now names the cause instead of a bare
            // class, following the "<command> status=<name>\n" shape
            // `expected_text` already uses below.
            write_stderr(
                system,
                stderr,
                stdout.endpoint().handle(),
                controls,
                b"run stream=",
            )?;
            write_stderr(
                system,
                stderr,
                stdout.endpoint().handle(),
                controls,
                foreground_stream_cause_name(&cause),
            )?;
            write_stderr(system, stderr, stdout.endpoint().handle(), controls, b"\n")
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

#[cfg(test)]
mod tests;
