//! Host tests for card R1's scenario driver.
//!
//! The launch half is covered by the loader's own atomic-INIT tests and by the
//! dispatcher's; what is driver-specific and testable here is the gate-to-plan
//! derivation the probe must parse back, and the report pump, which is where a
//! transcript is either relayed intact or lost. Both run against doubles, in the
//! shape `r1_relay::tests` already uses for the decision half.

use super::*;

use deepwyrm_syscall::{
    DW_HANDLE_TRANSFER_MOVE, DW_STATUS_TIMED_OUT, DwObjectType, DwRights, DwStatus, DwWaitResultV1,
};
use wyrmroot_r1_saturation::record::{encode_step, encode_terminal};
use wyrmroot_r1_saturation::{ProbeOutcome, ProbeStep};

const NONCE: u64 = 0x3400_0000_0000_0001;
const PROBE_IDENTITY: [u8; 32] = [7; 32];
const CHANNEL: DwHandle = DwHandle(0x3401);
const PROCESS: DwHandle = DwHandle(0x3402);
const TASK_GROUP: DwHandle = DwHandle(0x3403);
const FAILURE: NativeError = NativeError::Status(DwStatus(-1));
const QUEUE: usize = 8;

fn configuration(plan: ProbePlan) -> ProbeConfiguration {
    ProbeConfiguration {
        hog_count: plan.hog_count as u16,
        online_cpus: plan.online_cpus as u16,
        probe_identity: PROBE_IDENTITY,
    }
}

fn state(plan: ProbePlan) -> State {
    State {
        plan,
        configuration: configuration(plan),
        grant: EndpointGrant {
            registry_generation: 2,
            endpoint_id: 5,
            endpoint_generation: 1,
            role_generation: PROBE_ROLE_GENERATION,
            kind: EndpointKind::LaunchSession,
        },
        jobs: JobDispatcher::new(),
        probe: LoadedProcess {
            process: PROCESS,
            launch_channel: CHANNEL,
        },
        task_group: TASK_GROUP,
        relay: R1Relay::new(plan),
        finished: false,
    }
}

/// A probe's parent channel, plus the evidence syscall as a capturing double.
struct Probe {
    queued: [[u8; RECORD_BYTES]; QUEUE],
    queued_handles: [usize; QUEUE],
    queued_count: usize,
    delivered: usize,
    exited: bool,
    submitted: [[u8; RECORD_BYTES]; QUEUE],
    submitted_count: usize,
    reject_submission: bool,
    oversized: bool,
    closed: [DwHandle; QUEUE],
    closed_count: usize,
}

impl Probe {
    const fn new() -> Self {
        Self {
            queued: [[0; RECORD_BYTES]; QUEUE],
            queued_handles: [0; QUEUE],
            queued_count: 0,
            delivered: 0,
            exited: false,
            submitted: [[0; RECORD_BYTES]; QUEUE],
            submitted_count: 0,
            reject_submission: false,
            oversized: false,
            closed: [DwHandle(0); QUEUE],
            closed_count: 0,
        }
    }

    fn queue(&mut self, record: [u8; RECORD_BYTES], handles: usize) {
        self.queued[self.queued_count] = record;
        self.queued_handles[self.queued_count] = handles;
        self.queued_count += 1;
    }

    fn pending(&self) -> bool {
        self.delivered < self.queued_count
    }
}

impl InitPlatform for Probe {
    fn query_capability_info(
        &mut self,
        _handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
        Err(FAILURE)
    }

    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        assert_eq!(channel, CHANNEL);
        if !self.pending() {
            return Err(FAILURE);
        }
        let record = self.queued[self.delivered];
        let handle_count = self.queued_handles[self.delivered];
        self.delivered += 1;
        let copied = bytes.len().min(record.len());
        bytes[..copied].copy_from_slice(&record[..copied]);
        for (index, slot) in handles.iter_mut().take(handle_count).enumerate() {
            *slot = DwReceivedHandleInfoV1 {
                handle: DwHandle(0x7000 + index as u64),
                ..DwReceivedHandleInfoV1::default()
            };
        }
        Ok(ReceiveCounts {
            bytes: if self.oversized {
                record.len() + 32
            } else {
                record.len()
            },
            handles: handle_count,
        })
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
        self.closed[self.closed_count] = handle;
        self.closed_count += 1;
        Ok(())
    }

    fn create_attempt_task_group(&mut self, _parent: DwHandle) -> Result<DwHandle, NativeError> {
        Err(FAILURE)
    }

    fn terminate_task_group(&mut self, _task_group: DwHandle) -> Result<(), NativeError> {
        Ok(())
    }

    fn now(&mut self) -> Result<u64, NativeError> {
        Ok(1_000)
    }

    fn wait_until(&mut self, _deadline_ns: u64) -> Result<(), NativeError> {
        Err(FAILURE)
    }
}

impl Wyr1BPlatform for Probe {
    fn channel_create(&mut self, _rights: DwRights) -> Result<(DwHandle, DwHandle), NativeError> {
        Err(FAILURE)
    }

    fn send_channel_with_handles(
        &mut self,
        _channel: DwHandle,
        _bytes: &[u8],
        _transfers: &[DwHandleTransferV1],
    ) -> Result<(), NativeError> {
        let _ = DW_HANDLE_TRANSFER_MOVE;
        Err(FAILURE)
    }

    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        _deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, NativeError> {
        assert_eq!(items.len(), 2);
        // Pins the ordering `drain` depends on: the kernel resolves a tie to the
        // lowest input index, so the Channel must be asked about first or a
        // terminal record queued just before the probe's exit is discarded.
        assert_eq!(
            items[0].signals.0,
            DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0
        );
        assert_eq!(items[1].signals, DW_SIGNAL_EXITED);
        if self.pending() {
            return Ok(DwWaitResultV1 {
                index: 0,
                observed: DW_SIGNAL_READABLE,
                ..DwWaitResultV1::default()
            });
        }
        if self.exited {
            return Ok(DwWaitResultV1 {
                index: 1,
                observed: DW_SIGNAL_EXITED,
                ..DwWaitResultV1::default()
            });
        }
        Err(NativeError::Status(DW_STATUS_TIMED_OUT))
    }

    fn materialize_read_only_memory(
        &mut self,
        _root: DwHandle,
        _bytes: &[u8],
        _rights: DwRights,
    ) -> Result<DwHandle, NativeError> {
        Err(FAILURE)
    }
}

impl R1EvidenceSink for Probe {
    fn submit_r1_evidence(&mut self, record: &[u8; RECORD_BYTES]) -> Result<(), NativeError> {
        if self.reject_submission {
            return Err(FAILURE);
        }
        self.submitted[self.submitted_count] = *record;
        self.submitted_count += 1;
        Ok(())
    }
}

struct Waits {
    exited: bool,
}

impl SupervisionPlatform for Waits {
    type Error = NativeError;

    fn wait_many(
        &mut self,
        _items: &[DwWaitItemV1],
        _deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, Self::Error> {
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
        Ok(DwTaskTerminationInfoV1 {
            state: if self.exited {
                DW_TASK_STATE_EXITED
            } else {
                deepwyrm_syscall::DwTaskState(0)
            },
            ..DwTaskTerminationInfoV1::default()
        })
    }
}

fn step(sequence: u64, plan: ProbePlan) -> [u8; RECORD_BYTES] {
    encode_step(sequence, NONCE, plan, ProbeStep::LaunchHog { index: 0 }, 11)
}

#[test]
fn the_gate_is_turned_into_exactly_the_argv_the_probe_parses_back() {
    for plan in [ProbePlan::SMP, ProbePlan::CONTROL] {
        let arguments = PlanArguments::new(configuration(plan)).expect("accepted plan refused");
        assert_eq!(arguments.plan, plan);
        assert_eq!(
            launch_parameters::parse_plan(&[
                arguments.entry(0).unwrap(),
                arguments.entry(1).unwrap()
            ]),
            Ok(plan)
        );
    }
    let smp = PlanArguments::new(configuration(ProbePlan::SMP)).unwrap();
    assert_eq!(smp.entry(0).unwrap(), "6");
    assert_eq!(smp.entry(1).unwrap(), "4");
}

#[test]
fn a_gate_topology_the_probe_would_refuse_is_refused_before_the_launch() {
    // A product whose gate names an unaccepted topology must fail in init's own
    // classified status, not as an opaque probe exit code.
    let unaccepted = ProbeConfiguration {
        hog_count: 5,
        online_cpus: 4,
        probe_identity: PROBE_IDENTITY,
    };
    assert_eq!(
        PlanArguments::new(unaccepted),
        Err(InitError::WrongManifestProfile)
    );
    let unformattable = ProbeConfiguration {
        hog_count: 600,
        online_cpus: 4,
        probe_identity: PROBE_IDENTITY,
    };
    assert_eq!(
        PlanArguments::new(unformattable),
        Err(InitError::WrongManifestProfile)
    );
    assert_eq!(
        decimal(0, &mut [0; 2]),
        Err(InitError::WrongManifestProfile)
    );
    assert_eq!(
        decimal(100, &mut [0; 2]),
        Err(InitError::WrongManifestProfile)
    );
}

#[test]
fn a_whole_transcript_reaches_the_collector_in_order_and_ends_once() {
    let plan = ProbePlan::SMP;
    let mut state = state(plan);
    let mut system = Probe::new();
    for sequence in 1..=3 {
        system.queue(step(sequence, plan), 0);
    }
    let terminal = encode_terminal(4, NONCE, plan, ProbeOutcome::Passed, 3);
    system.queue(terminal, 0);

    drain(&mut state, &mut system, 500).expect("a well-formed transcript was refused");
    assert_eq!(system.submitted_count, 4);
    for sequence in 1..=3 {
        assert_eq!(
            system.submitted[sequence as usize - 1],
            step(sequence, plan)
        );
    }
    assert_eq!(system.submitted[3], terminal);
    assert_eq!(state.submitted(), 4);
    assert!(state.relay.complete());

    // The terminal record is the end of the run: a later tick submits nothing
    // more even with the probe still queueing.
    system.queue(step(5, plan), 0);
    drain(&mut state, &mut system, 600).expect("a completed run was re-drained as a failure");
    assert_eq!(system.submitted_count, 4);
}

#[test]
fn an_idle_probe_leaves_the_tick_immediately() {
    let mut state = state(ProbePlan::SMP);
    let mut system = Probe::new();
    drain(&mut state, &mut system, 500).expect("an idle probe was reported as a failure");
    assert_eq!(system.submitted_count, 0);
    assert_eq!(state.submitted(), 0);
}

#[test]
fn a_probe_that_stops_reporting_before_its_terminal_record_is_a_failure() {
    // This is A27's shape, and the card exists to tell it apart from a pass.
    let plan = ProbePlan::SMP;
    let mut state = state(plan);
    let mut system = Probe::new();
    system.queue(step(1, plan), 0);
    system.exited = true;
    assert_eq!(
        drain(&mut state, &mut system, 500),
        Err(InitError::Supervision)
    );
    assert_eq!(system.submitted_count, 1);
    assert!(!state.relay.complete());
}

#[test]
fn a_record_arriving_with_a_handle_is_refused_and_the_handle_is_closed() {
    let plan = ProbePlan::SMP;
    let mut state = state(plan);
    let mut system = Probe::new();
    system.queue(step(1, plan), 1);
    assert_eq!(
        drain(&mut state, &mut system, 500),
        Err(InitError::WrongManifestProfile)
    );
    assert_eq!(system.submitted_count, 0);
    assert_eq!(system.closed[..system.closed_count], [DwHandle(0x7000)]);
}

#[test]
fn an_out_of_order_record_is_refused_rather_than_relayed() {
    let plan = ProbePlan::SMP;
    let mut state = state(plan);
    let mut system = Probe::new();
    system.queue(step(2, plan), 0);
    assert_eq!(
        drain(&mut state, &mut system, 500),
        Err(InitError::WrongManifestProfile)
    );
    assert_eq!(system.submitted_count, 0);
}

#[test]
fn a_report_describing_another_topology_never_reaches_the_collector() {
    let mut state = state(ProbePlan::SMP);
    let mut system = Probe::new();
    system.queue(step(1, ProbePlan::CONTROL), 0);
    assert_eq!(
        drain(&mut state, &mut system, 500),
        Err(InitError::WrongManifestProfile)
    );
    assert_eq!(system.submitted_count, 0);
}

#[test]
fn a_kernel_refusal_leaves_the_transcript_retryable() {
    let plan = ProbePlan::SMP;
    let mut state = state(plan);
    let mut system = Probe::new();
    system.queue(step(1, plan), 0);
    system.reject_submission = true;
    assert_eq!(
        drain(&mut state, &mut system, 500),
        Err(InitError::Native(FAILURE))
    );
    // The refused record consumed no sequence, so the same record still fits.
    assert_eq!(state.submitted(), 0);
    system.reject_submission = false;
    system.queue(step(1, plan), 0);
    drain(&mut state, &mut system, 600).expect("a retried record was refused");
    assert_eq!(system.submitted_count, 1);
    assert_eq!(state.submitted(), 1);
}

#[test]
fn teardown_retires_the_probe_and_stops_the_driver() {
    let plan = ProbePlan::SMP;
    let mut state = state(plan);
    let mut system = Probe::new();
    let mut waits = Waits { exited: true };
    // The session was installed at launch, so teardown must retire it exactly
    // once and close its channel along with the probe's own handles.
    state
        .jobs
        .install_session(state.grant, DwHandle(0x3404))
        .expect("launch session refused");
    finish(&mut state, &mut system, &mut waits).expect("terminal teardown failed");
    assert!(state.finished());
    assert_eq!(
        system.closed[..system.closed_count],
        [DwHandle(0x3404), CHANNEL, PROCESS, TASK_GROUP]
    );
    assert_eq!(state.jobs.session_count(), 0);
}

#[test]
fn teardown_tolerates_a_session_the_dispatcher_already_retired() {
    // The probe's peer close races its terminal record; the dispatcher retiring
    // the session first is normal and must not be reported as a model error.
    let mut state = state(ProbePlan::SMP);
    let mut system = Probe::new();
    let mut waits = Waits { exited: true };
    finish(&mut state, &mut system, &mut waits).expect("an already-retired session failed");
    assert_eq!(
        system.closed[..system.closed_count],
        [CHANNEL, PROCESS, TASK_GROUP]
    );
}

#[test]
fn a_datagram_that_is_not_exactly_one_record_is_refused_rather_than_truncated() {
    // A 64-byte prefix of a longer datagram parses as a valid record, so the
    // size is checked before the relay ever sees the bytes.
    let plan = ProbePlan::SMP;
    let mut state = state(plan);
    let mut system = Probe::new();
    system.oversized = true;
    system.queue(step(1, plan), 0);
    assert_eq!(
        drain(&mut state, &mut system, 500),
        Err(InitError::WrongManifestProfile)
    );
    assert_eq!(system.submitted_count, 0);
    assert_eq!(state.submitted(), 0);
}
