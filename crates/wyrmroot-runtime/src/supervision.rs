//! Bounded temporary parent/child readiness and exit supervision.
//!
//! This module deliberately owns no loader policy.  It observes the two handles returned by a
//! successful WYR0 launch: the parent launch-Channel endpoint and the child Process.  Callers
//! retain those handles and choose their close/termination policy after this bounded observation.

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_SIGNAL_EXITED, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE,
    DW_TASK_STATE_EXITED, DW_TASK_TERMINATION_INFO_V1_SIZE, DW_TERMINATION_NORMAL_EXIT, DwDeadline,
    DwHandle, DwReceivedHandleInfoV1, DwTaskTerminationInfoV1, DwWaitItemV1, DwWaitResultV1,
};
use wyrmroot_loader::launch::{self, HEADER_BYTES, LaunchError};

use crate::{NativeError, ReceiveCounts, query_task_termination_info, receive_channel, wait_many};

const CHANNEL_SIGNALS: deepwyrm_syscall::DwSignals =
    deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0);

/// Native operations needed to supervise one already-started child.
///
/// The trait makes the state machine host-testable while the production implementation below
/// calls only typed wrappers from the pinned `deepwyrm-syscall` consumer crate.
pub trait SupervisionPlatform {
    type Error;

    /// Runs generated WAIT_ANY over the supplied fixed handle set.
    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, Self::Error>;

    /// Receives one complete datagram from the retained parent launch endpoint.
    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, Self::Error>;

    /// Obtains one fresh Process task-state record.
    fn query_task_termination(
        &mut self,
        process: DwHandle,
    ) -> Result<DwTaskTerminationInfoV1, Self::Error>;
}

/// Stateless production adapter for [`SupervisionPlatform`].
pub struct NativeSupervisionPlatform;

impl SupervisionPlatform for NativeSupervisionPlatform {
    type Error = NativeError;

    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, Self::Error> {
        wait_many(items, deadline)
    }

    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, Self::Error> {
        receive_channel(channel, bytes, handles)
    }

    fn query_task_termination(
        &mut self,
        process: DwHandle,
    ) -> Result<DwTaskTerminationInfoV1, Self::Error> {
        query_task_termination_info(process)
    }
}

/// Exact reason a completed Process task-state record is not successful WYR0 completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitValidationError {
    /// The returned ABI record did not have its exact generated envelope.
    InvalidEnvelope,
    /// The Process was not in the level-triggered EXITED state after its EXITED signal.
    NotExited,
    /// The Process did not record a normal application exit.
    NotNormalExit,
    /// The Process reported a nonzero normal application exit code.
    NonzeroApplicationCode(u32),
    /// A normal exit must carry no exception classification, detail, or fault address.
    NonzeroExceptionFields,
}

/// Validates the complete successful Process exit record required by WYR0-E.
pub fn validate_successful_exit(info: &DwTaskTerminationInfoV1) -> Result<(), ExitValidationError> {
    if info.size != DW_TASK_TERMINATION_INFO_V1_SIZE
        || info.version != 1
        || info.reserved0 != 0
        || info.reserved != [0; 3]
    {
        return Err(ExitValidationError::InvalidEnvelope);
    }
    if info.state != DW_TASK_STATE_EXITED {
        return Err(ExitValidationError::NotExited);
    }
    if info.reason != DW_TERMINATION_NORMAL_EXIT {
        return Err(ExitValidationError::NotNormalExit);
    }
    if info.application_code != 0 {
        return Err(ExitValidationError::NonzeroApplicationCode(
            info.application_code,
        ));
    }
    if info.exception_type.0 != 0 || info.detail != 0 || info.fault_address != 0 {
        return Err(ExitValidationError::NonzeroExceptionFields);
    }
    Ok(())
}

/// Failure from temporary WYR0 child readiness/exit observation.
#[derive(Debug, Eq, PartialEq)]
pub enum SupervisionError<PlatformError> {
    /// The temporary supervision protocol must not wait forever.
    UnboundedDeadline,
    /// A typed native operation failed.
    Platform(PlatformError),
    /// Querying termination failed after the Process `EXITED` signal was observed.
    ExitQuery(PlatformError),
    /// A successful wait result did not select a requested handle or signal.
    InvalidWaitResult,
    /// A receive did not contain exactly one handle-free READY datagram.
    InvalidReadyReceive(ReceiveCounts),
    /// The child launch protocol READY was malformed or did not echo the transaction.
    Ready(LaunchError),
    /// The Process exited before the expected READY was accepted.
    ExitedBeforeReady,
    /// The launch Channel peer closed before a queued valid READY could be received.
    PeerClosedBeforeReady,
    /// The child sent another launch-Channel datagram after a valid READY.
    DuplicateReady,
    /// The signaled Process did not report the exact normal zero exit record.
    Exit(ExitValidationError),
}

impl<PlatformError> SupervisionError<PlatformError> {
    /// Returns whether this failure was produced after observing Process `EXITED`.
    ///
    /// Callers may use this to avoid an invalid redundant termination request while
    /// still closing the Process and launch-Channel handles they own.  Every other
    /// error remains an unproven liveness failure and therefore still requires
    /// caller-selected termination during cleanup.
    #[must_use]
    pub const fn process_exit_observed(&self) -> bool {
        matches!(
            self,
            Self::ExitedBeforeReady | Self::ExitQuery(_) | Self::Exit(_)
        )
    }
}

/// Observes exactly one child READY followed by a structured normal Process exit.
///
/// `deadline` is passed unchanged to every generated wait so all observations are bounded by the
/// same integration-selected monotonic deadline.  The function borrows neither handle ownership
/// nor authority: its caller remains responsible for cleanup or authorized termination after a
/// failure.
pub fn supervise_child<P: SupervisionPlatform>(
    platform: &mut P,
    process: DwHandle,
    launch_channel: DwHandle,
    transaction_id: u64,
    deadline: DwDeadline,
) -> Result<(), SupervisionError<P::Error>> {
    if deadline == DW_DEADLINE_INFINITE {
        return Err(SupervisionError::UnboundedDeadline);
    }

    let mut ready = false;
    let mut monitor_channel = true;
    loop {
        let channel_item = DwWaitItemV1 {
            handle: launch_channel,
            signals: CHANNEL_SIGNALS,
        };
        let process_item = DwWaitItemV1 {
            handle: process,
            signals: DW_SIGNAL_EXITED,
        };
        let items = if monitor_channel {
            [channel_item, process_item]
        } else {
            [process_item, process_item]
        };
        let wait_items = if monitor_channel {
            &items[..2]
        } else {
            &items[..1]
        };
        let result = platform
            .wait_many(wait_items, deadline)
            .map_err(SupervisionError::Platform)?;
        let index =
            usize::try_from(result.index).map_err(|_| SupervisionError::InvalidWaitResult)?;
        let Some(item) = wait_items.get(index) else {
            return Err(SupervisionError::InvalidWaitResult);
        };
        if result.observed.0 & item.signals.0 == 0 {
            return Err(SupervisionError::InvalidWaitResult);
        }

        if monitor_channel && index == 0 {
            if result.observed.0 & DW_SIGNAL_READABLE.0 != 0 {
                let mut bytes = [0_u8; HEADER_BYTES];
                let mut handles = [];
                let counts = platform
                    .receive_channel(launch_channel, &mut bytes, &mut handles)
                    .map_err(SupervisionError::Platform)?;
                if counts
                    != (ReceiveCounts {
                        bytes: HEADER_BYTES,
                        handles: 0,
                    })
                {
                    return Err(SupervisionError::InvalidReadyReceive(counts));
                }
                if ready {
                    return Err(SupervisionError::DuplicateReady);
                }
                launch::parse_ready(&bytes, transaction_id).map_err(SupervisionError::Ready)?;
                ready = true;
            } else if !ready {
                return Err(SupervisionError::PeerClosedBeforeReady);
            }
            if ready && result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
                monitor_channel = false;
            }
            continue;
        }

        if index != 0 && !(monitor_channel && index == 1) {
            return Err(SupervisionError::InvalidWaitResult);
        }
        if !ready {
            let info = platform
                .query_task_termination(process)
                .map_err(SupervisionError::ExitQuery)?;
            return match validate_successful_exit(&info) {
                Ok(()) => Err(SupervisionError::ExitedBeforeReady),
                Err(error) => Err(SupervisionError::Exit(error)),
            };
        }
        if monitor_channel {
            // Deepwyrm publishes Process EXITED wait readiness only after the
            // terminal handle drain has closed the child endpoint. Recheck the
            // now-level-triggered peer state so a second datagram queued in the
            // same exit race cannot be mistaken for a clean one-READY launch.
            let result = platform
                .wait_many(core::slice::from_ref(&channel_item), deadline)
                .map_err(SupervisionError::Platform)?;
            if result.index != 0 || result.observed.0 & CHANNEL_SIGNALS.0 == 0 {
                return Err(SupervisionError::InvalidWaitResult);
            }
            if result.observed.0 & DW_SIGNAL_READABLE.0 != 0 {
                return Err(SupervisionError::DuplicateReady);
            }
            if result.observed.0 & DW_SIGNAL_PEER_CLOSED.0 == 0 {
                return Err(SupervisionError::InvalidWaitResult);
            }
        }
        let info = platform
            .query_task_termination(process)
            .map_err(SupervisionError::ExitQuery)?;
        return validate_successful_exit(&info).map_err(SupervisionError::Exit);
    }
}

/// Production convenience entry point using the typed native syscall wrappers.
pub fn supervise_native_child(
    process: DwHandle,
    launch_channel: DwHandle,
    transaction_id: u64,
    deadline: DwDeadline,
) -> Result<(), SupervisionError<NativeError>> {
    supervise_child(
        &mut NativeSupervisionPlatform,
        process,
        launch_channel,
        transaction_id,
        deadline,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    enum WaitEvent {
        Channel(deepwyrm_syscall::DwSignals),
        ProcessExited,
    }

    struct Mock {
        waits: &'static [WaitEvent],
        wait_index: usize,
        received: usize,
        counts: ReceiveCounts,
        task_info: DwTaskTerminationInfoV1,
        query_fails: bool,
    }

    impl Mock {
        fn successful(waits: &'static [WaitEvent]) -> Self {
            Self {
                waits,
                wait_index: 0,
                received: 0,
                counts: ReceiveCounts {
                    bytes: HEADER_BYTES,
                    handles: 0,
                },
                task_info: successful_exit_info(),
                query_fails: false,
            }
        }
    }

    impl SupervisionPlatform for Mock {
        type Error = ();

        fn wait_many(
            &mut self,
            items: &[DwWaitItemV1],
            _deadline: DwDeadline,
        ) -> Result<DwWaitResultV1, Self::Error> {
            let event = self.waits[self.wait_index];
            self.wait_index += 1;
            let (index, observed) = match event {
                WaitEvent::Channel(signals) => {
                    assert!(matches!(items.len(), 1 | 2));
                    assert_eq!(items[0].signals, CHANNEL_SIGNALS);
                    (0, signals)
                }
                WaitEvent::ProcessExited => (items.len() as u32 - 1, DW_SIGNAL_EXITED),
            };
            Ok(DwWaitResultV1 {
                size: deepwyrm_syscall::DW_WAIT_RESULT_V1_SIZE,
                version: 1,
                index,
                observed,
                ..DwWaitResultV1::default()
            })
        }

        fn receive_channel(
            &mut self,
            _channel: DwHandle,
            bytes: &mut [u8],
            _handles: &mut [DwReceivedHandleInfoV1],
        ) -> Result<ReceiveCounts, Self::Error> {
            self.received += 1;
            launch::encode_ready(7, bytes).unwrap();
            Ok(self.counts)
        }

        fn query_task_termination(
            &mut self,
            _process: DwHandle,
        ) -> Result<DwTaskTerminationInfoV1, Self::Error> {
            if self.query_fails {
                return Err(());
            }
            Ok(self.task_info)
        }
    }

    fn successful_exit_info() -> DwTaskTerminationInfoV1 {
        DwTaskTerminationInfoV1 {
            size: DW_TASK_TERMINATION_INFO_V1_SIZE,
            version: 1,
            state: DW_TASK_STATE_EXITED,
            reason: DW_TERMINATION_NORMAL_EXIT,
            ..DwTaskTerminationInfoV1::default()
        }
    }

    const READY: WaitEvent = WaitEvent::Channel(DW_SIGNAL_READABLE);
    const CLOSED: WaitEvent = WaitEvent::Channel(DW_SIGNAL_PEER_CLOSED);
    const EXITED: WaitEvent = WaitEvent::ProcessExited;

    #[test]
    fn accepts_one_ready_then_a_fresh_normal_zero_exit() {
        let mut mock = Mock::successful(&[READY, EXITED, CLOSED]);
        assert_eq!(
            supervise_child(&mut mock, DwHandle(1), DwHandle(2), 7, DwDeadline(99)),
            Ok(())
        );
        assert_eq!(mock.received, 1);
    }

    #[test]
    fn rejects_exit_before_ready() {
        let mut mock = Mock::successful(&[EXITED]);
        assert_eq!(
            supervise_child(&mut mock, DwHandle(1), DwHandle(2), 7, DwDeadline(99)),
            Err(SupervisionError::ExitedBeforeReady)
        );
        assert!(SupervisionError::<()>::ExitedBeforeReady.process_exit_observed());
    }

    #[test]
    fn preserves_nonzero_application_exit_observed_before_ready() {
        let mut mock = Mock::successful(&[EXITED]);
        mock.task_info.application_code = 37;
        let error = supervise_child(&mut mock, DwHandle(1), DwHandle(2), 7, DwDeadline(99));
        assert_eq!(
            error,
            Err(SupervisionError::Exit(
                ExitValidationError::NonzeroApplicationCode(37)
            ))
        );
        assert!(error.unwrap_err().process_exit_observed());
    }

    #[test]
    fn preserves_exit_observation_when_termination_query_fails() {
        let mut mock = Mock::successful(&[EXITED]);
        mock.query_fails = true;
        let error = supervise_child(&mut mock, DwHandle(1), DwHandle(2), 7, DwDeadline(99));
        assert_eq!(error, Err(SupervisionError::ExitQuery(())));
        assert!(error.unwrap_err().process_exit_observed());
    }

    #[test]
    fn preserves_exit_observation_when_post_ready_query_fails() {
        let mut mock = Mock::successful(&[READY, EXITED, CLOSED]);
        mock.query_fails = true;
        let error = supervise_child(&mut mock, DwHandle(1), DwHandle(2), 7, DwDeadline(99));
        assert_eq!(error, Err(SupervisionError::ExitQuery(())));
        assert!(error.unwrap_err().process_exit_observed());
    }

    #[test]
    fn readiness_errors_do_not_claim_process_exit_observation() {
        assert!(!SupervisionError::<()>::PeerClosedBeforeReady.process_exit_observed());
        assert!(!SupervisionError::<()>::DuplicateReady.process_exit_observed());
        assert!(!SupervisionError::<()>::InvalidWaitResult.process_exit_observed());
    }

    #[test]
    fn rejects_peer_close_before_a_queued_ready() {
        let mut mock = Mock::successful(&[WaitEvent::Channel(DW_SIGNAL_PEER_CLOSED)]);
        assert_eq!(
            supervise_child(&mut mock, DwHandle(1), DwHandle(2), 7, DwDeadline(99)),
            Err(SupervisionError::PeerClosedBeforeReady)
        );
    }

    #[test]
    fn rejects_duplicate_ready_before_process_exit() {
        let mut mock = Mock::successful(&[READY, READY]);
        assert_eq!(
            supervise_child(&mut mock, DwHandle(1), DwHandle(2), 7, DwDeadline(99)),
            Err(SupervisionError::DuplicateReady)
        );
    }

    #[test]
    fn rejects_duplicate_ready_queued_in_the_process_exit_race() {
        let mut mock = Mock::successful(&[READY, EXITED, READY]);
        assert_eq!(
            supervise_child(&mut mock, DwHandle(1), DwHandle(2), 7, DwDeadline(99)),
            Err(SupervisionError::DuplicateReady)
        );
    }

    #[test]
    fn rejects_capability_bearing_ready_receive() {
        let mut mock = Mock::successful(&[READY]);
        mock.counts.handles = 1;
        assert_eq!(
            supervise_child(&mut mock, DwHandle(1), DwHandle(2), 7, DwDeadline(99)),
            Err(SupervisionError::InvalidReadyReceive(ReceiveCounts {
                bytes: HEADER_BYTES,
                handles: 1,
            }))
        );
    }

    #[test]
    fn rejects_unbounded_supervision() {
        let mut mock = Mock::successful(&[]);
        assert_eq!(
            supervise_child(&mut mock, DwHandle(1), DwHandle(2), 7, DW_DEADLINE_INFINITE,),
            Err(SupervisionError::UnboundedDeadline)
        );
    }

    #[test]
    fn exit_validation_rejects_nonzero_exception_fields_and_status() {
        let mut info = successful_exit_info();
        info.exception_type = deepwyrm_syscall::DwExceptionType(1);
        assert_eq!(
            validate_successful_exit(&info),
            Err(ExitValidationError::NonzeroExceptionFields)
        );
        info = successful_exit_info();
        info.application_code = 4;
        assert_eq!(
            validate_successful_exit(&info),
            Err(ExitValidationError::NonzeroApplicationCode(4))
        );
        info = successful_exit_info();
        info.reserved0 = 1;
        assert_eq!(
            validate_successful_exit(&info),
            Err(ExitValidationError::InvalidEnvelope)
        );
    }
}
