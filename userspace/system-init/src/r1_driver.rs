//! Reset card R1's selector-34 scenario driver.
//!
//! Card R1's product stages three things that had no consumer: the saturation
//! probe, the `WRR1` gate describing it, and the evidence relay. This module is
//! what joins them, and it is the whole of permanent init's R1-specific
//! behaviour:
//!
//! 1. it reads `R1_GATE_PATH` and derives the plan from it, rather than
//!    assuming a topology no file states;
//! 2. it launches `R1_PROBE_PATH` as a WRLP 1.3 launch client with one
//!    launch-session endpoint and that plan as arguments;
//! 3. it services the probe's own launches through the ordinary JobV2
//!    dispatcher against card R1's launch policy; and
//! 4. it relays the probe's `R1SP` records to the kernel collector, because
//!    Deepwyrm binds reporter custody to permanent init and a dynamically
//!    launched child therefore cannot submit its own evidence.
//!
//! Nothing here widens a shared mechanism. The launch itself is the
//! `wyr1d_native` console precedent with one endpoint instead of two, the pump
//! is `poll_job_dispatcher` unchanged, and the relay decision half already
//! existed and is host tested on its own.

use super::*;

use crate::r1_relay::{
    R1EvidenceSink, R1Relay, RELAY_CAPACITY, RelayError, RelayFailure, relay_one,
};
use crate::wyr1b::{EndpointGrant, EndpointKind, JobError, RegistryTopology};
use crate::wyr1b_job::JobDispatcher;
use crate::wyr1b_native::{create_controller_channel_pair, poll_job_dispatcher};
use wyrmroot_bootfs::r1::{ProbeConfiguration, R1_GATE_PATH, R1_PROBE_PATH, parse_gate};
use wyrmroot_loader::process::{LaunchClientLoadRequest, load_launch_client_process};
use wyrmroot_r1_saturation::record::BYTES as RECORD_BYTES;
use wyrmroot_r1_saturation::{ProbePlan, launch_parameters};
use wyrmroot_registry_proto::{Correlation, CorrelationEnvironment};
use wyrmroot_runtime::{ExitValidationError, ObservedSupervisionError};

/// The probe's launch transaction. One launch, one generation, so this is a
/// constant rather than an allocator.
const TRANSACTION: u64 = 0x3400_0001;

/// Role generation for the probe's launch-session grant. The probe is launched
/// once and never restarted: a second generation would describe a retry this
/// card does not perform.
const PROBE_ROLE_GENERATION: u64 = 1;

/// One probe's driver state. Constructed only by [`drive`], which launches the
/// probe as part of construction, so a `State` that exists always names a
/// launched probe.
#[derive(Debug, Eq, PartialEq)]
pub struct State {
    plan: ProbePlan,
    configuration: ProbeConfiguration,
    grant: EndpointGrant,
    jobs: JobDispatcher,
    probe: LoadedProcess,
    task_group: DwHandle,
    relay: R1Relay,
    finished: bool,
}

impl State {
    #[must_use]
    pub const fn plan(&self) -> ProbePlan {
        self.plan
    }

    #[must_use]
    pub const fn configuration(&self) -> ProbeConfiguration {
        self.configuration
    }

    /// Records relayed to the kernel collector so far.
    #[must_use]
    pub const fn submitted(&self) -> usize {
        self.relay.submitted()
    }

    /// True once the terminal record has been relayed and the probe has been
    /// torn down. A finished driver performs no further operation.
    #[must_use]
    pub const fn finished(&self) -> bool {
        self.finished
    }
}

/// Advances the scenario by one resident tick, launching the probe on the first
/// call.
///
/// `state` is owned by the caller's resident loop rather than by
/// [`ResidentSystemInit`], because the driver is one selector's scenario and no
/// production product has a field for it.
pub fn drive<S, L, W>(
    resident: &mut ResidentSystemInit,
    state: &mut Option<State>,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    now_ns: u64,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform + R1EvidenceSink,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    if state.as_ref().is_some_and(State::finished) {
        return Ok(());
    }
    let authority = resident.authority;
    let state = match state {
        Some(state) => state,
        None => state.insert(start(resident, system, loader, waits)?),
    };
    pump(state, system, loader, waits, authority, now_ns)
}

/// Reads the gate and launches the probe it names.
fn start<S, L, W>(
    resident: &mut ResidentSystemInit,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
) -> Result<State, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let authority = resident.authority;
    let size = system
        .query_memory_object_size(authority.bootfs)
        .map_err(InitError::Native)?;
    let plan = MappingPlan::for_bootfs(size).map_err(InitError::Mapping)?;
    let topology = *crate::wyr1c_native::resident_topology(resident)?;
    let (started, topology) = system
        .with_bootfs_bytes(
            authority.parent_root,
            authority.bootfs,
            plan,
            |system, bootfs| {
                let mut topology = topology;
                let started = launch(system, loader, waits, authority, &mut topology, bootfs);
                (started, topology)
            },
        )
        .map_err(InitError::Native)?;
    // The allocator advances only for a grant that was actually issued, so the
    // resident copy is replaced whatever the launch did with it.
    *crate::wyr1c_native::resident_topology(resident)? = topology;
    started
}

/// The `WRR1` gate's probe configuration and the exact argv the probe parses
/// back out of it.
#[derive(Debug, Eq, PartialEq)]
struct PlanArguments {
    plan: ProbePlan,
    bytes: [[u8; 2]; 2],
    lengths: [usize; 2],
}

impl PlanArguments {
    /// Derives the probe's two arguments from the gate.
    ///
    /// The formatted pair is parsed back with the probe's own
    /// `launch_parameters::parse_plan` before it is used. That is not
    /// belt-and-braces: the probe refuses a non-canonical spelling and an
    /// unaccepted plan, so a product whose gate disagrees with the accepted
    /// topologies must fail here, in init's own classified status, rather than
    /// as an opaque child exit code.
    fn new(configuration: ProbeConfiguration) -> Result<Self, InitError> {
        let plan = ProbePlan {
            hog_count: configuration.hog_count as usize,
            online_cpus: configuration.online_cpus as usize,
        };
        let mut arguments = Self {
            plan,
            bytes: [[0; 2]; 2],
            lengths: [0; 2],
        };
        for (index, value) in [plan.hog_count, plan.online_cpus].into_iter().enumerate() {
            arguments.lengths[index] = decimal(value, &mut arguments.bytes[index])?;
        }
        let parsed = launch_parameters::parse_plan(&[arguments.entry(0)?, arguments.entry(1)?])
            .map_err(|_| InitError::WrongManifestProfile)?;
        if parsed != plan {
            return Err(InitError::WrongManifestProfile);
        }
        Ok(arguments)
    }

    fn entry(&self, index: usize) -> Result<&str, InitError> {
        let bytes = self
            .bytes
            .get(index)
            .ok_or(InitError::WrongManifestProfile)?;
        let length = *self
            .lengths
            .get(index)
            .ok_or(InitError::WrongManifestProfile)?;
        core::str::from_utf8(bytes.get(..length).ok_or(InitError::WrongManifestProfile)?)
            .map_err(|_| InitError::WrongManifestProfile)
    }
}

/// Canonical decimal with no leading zero, into at most two digits. The gate's
/// two fields are bounded by the accepted topologies, so a value that does not
/// fit is a malformed gate rather than a formatting limit.
fn decimal(value: usize, output: &mut [u8; 2]) -> Result<usize, InitError> {
    match value {
        0 => Err(InitError::WrongManifestProfile),
        1..=9 => {
            output[0] = b'0' + value as u8;
            Ok(1)
        }
        10..=99 => {
            output[0] = b'0' + (value / 10) as u8;
            output[1] = b'0' + (value % 10) as u8;
            Ok(2)
        }
        _ => Err(InitError::WrongManifestProfile),
    }
}

/// Issues the probe's launch session, constructs it, and completes the WRLP
/// ready handshake.
///
/// Every error path below closes exactly the handles this function owns at that
/// point and nothing else, and reports [`InitError::Cleanup`] when a close
/// fails, so a failed launch can never leave a half-owned probe behind. This is
/// the `wyr1d_native::launch_console` discipline with one endpoint instead of
/// two.
fn launch<S, L, W>(
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    topology: &mut RegistryTopology,
    bootfs: &[u8],
) -> Result<State, InitError>
where
    S: Wyr1BPlatform,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    let archive = Archive::new(bootfs).map_err(InitError::Bootfs)?;
    let gate = archive
        .lookup(R1_GATE_PATH.as_bytes())
        .map_err(map_lookup)?;
    if gate.is_executable() {
        return Err(InitError::WrongManifestProfile);
    }
    let configuration = parse_gate(gate.data()).map_err(|_| InitError::WrongManifestProfile)?;
    let arguments = PlanArguments::new(configuration)?;
    let plan = arguments.plan;
    // Borrowed before any handle exists, deliberately. Taken at the load call
    // instead, the two `?` would return from this function after the task group,
    // the Channel pair and the installed session had been acquired, leaking all
    // three and contradicting this function's cleanup invariant. `PlanArguments`
    // has already proved both entries succeed, so this is unreachable today --
    // which is exactly why it would survive review as written.
    let argv = [arguments.entry(0)?, arguments.entry(1)?];
    let image = archive
        .lookup(R1_PROBE_PATH.as_bytes())
        .map_err(map_lookup)?;
    if !image.is_executable() || image.data().is_empty() {
        return Err(InitError::NonExecutableRole);
    }
    // The gate names the image identity the product cross-bound at build time.
    // Checking it here is what stops a substituted probe from being launched
    // under a report that claims the staged one.
    if wyrmroot_runtime::sha256::digest(image.data()) != configuration.probe_identity {
        return Err(InitError::WrongManifestProfile);
    }

    let launch_grant = topology
        .issue(PROBE_ROLE_GENERATION, EndpointKind::LaunchSession)
        .map_err(InitError::Wyr1BModel)?;
    // `crate::wyr1b::correlation_environment` is kind-gated to Publication and
    // RegistryClient and would refuse this grant. The probe's correlation is
    // its *launch session*: the reservation it later sends is checked against
    // the session ticket's owner, which is exactly this endpoint identity. So
    // the environment is built here, in R1-local code, rather than by widening
    // a helper every registry client shares.
    let correlation = CorrelationEnvironment::new(Correlation {
        registry_generation: launch_grant.registry_generation,
        endpoint_id: launch_grant.endpoint_id,
        endpoint_generation: launch_grant.endpoint_generation,
    })
    .map_err(InitError::RegistryProtocol)?;

    let group = system
        .create_attempt_task_group(authority.task_group)
        .map_err(InitError::Native)?;
    let (launch_endpoint, child_launch) = match create_controller_channel_pair(system) {
        Ok(pair) => pair,
        Err(error) => {
            system.close_handle(group).map_err(|_| InitError::Cleanup)?;
            return Err(error);
        }
    };
    let mut jobs = JobDispatcher::new();
    // Install before launching: the probe's first launch may arrive as soon as
    // it has sent READY, and an uninstalled session would refuse it.
    if let Err(error) = jobs.install_session(launch_grant, launch_endpoint) {
        let failed = system.close_handle(launch_endpoint).is_err()
            | system.close_handle(child_launch).is_err()
            | system.close_handle(group).is_err();
        return Err(if failed {
            InitError::Cleanup
        } else {
            InitError::Wyr1BModel(error)
        });
    }
    let loaded = match load_launch_client_process(
        loader,
        LoadAuthority {
            task_group: group,
            ..authority
        },
        LaunchClientLoadRequest {
            image: image.data(),
            display_path: R1_PROBE_PATH,
            launch_session: child_launch,
            arguments: &argv,
            correlation: &correlation,
            transaction_id: TRANSACTION,
        },
    ) {
        Ok(loaded) => loaded,
        Err(failure) => {
            let mut failed = false;
            if !failure.launch_session_consumed {
                failed |= system.close_handle(child_launch).is_err();
            }
            failed |= jobs
                .disconnect_session(launch_grant)
                .map_or(true, |handle| system.close_handle(handle).is_err());
            failed |= system.close_handle(group).is_err();
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::Loader(failure.error)
            });
        }
    };
    let ready = (|| {
        let now = system.now().map_err(InitError::Native)?;
        let deadline = now
            .checked_add(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .ok_or(InitError::Accounting)?;
        await_child_ready_profile_observed(
            waits,
            loaded.process,
            loaded.launch_channel,
            LaunchProfile::LaunchClient,
            TRANSACTION,
            DwDeadline(deadline),
        )
        .map_err(|error| InitError::R1Probe(probe_failure_before_ready(&error)))
    })();
    if let Err(error) = ready {
        let failed = cleanup_loaded(system, waits, loaded, group, true).is_err()
            | jobs
                .disconnect_session(launch_grant)
                .map_or(true, |handle| system.close_handle(handle).is_err());
        return Err(if failed { InitError::Cleanup } else { error });
    }
    // No session owner is attached, deliberately. `poll_job_dispatcher` closes
    // an owner's Process and task group itself when it observes the session's
    // peer close, and its ungated form reports no outcome, so an attached owner
    // would leave this module holding handles it could not know were already
    // closed. The session channel stays the dispatcher's; the Process, launch
    // Channel and task group stay this state's, and `finish` retires them.
    Ok(State {
        plan,
        configuration,
        grant: launch_grant,
        jobs,
        probe: loaded,
        task_group: group,
        relay: R1Relay::new(plan),
        finished: false,
    })
}

/// Classifies a failed READY handshake by the probe's own terminal record.
///
/// Four of the five variants carry an exact `DwTaskTerminationInfoV1`, and a
/// normal exit's `application_code` is the probe's `PROBE_ERROR_BASE | ordinal`.
/// Keeping it is the difference between a run that says the probe never reported
/// and one that says which of its startup checks refused. A zero code means the
/// record was not a normal exit -- a fault, or still running -- and there is no
/// application code to keep, so the site is reported instead.
fn probe_failure_before_ready(error: &ObservedSupervisionError<NativeError>) -> R1ProbeFailure {
    let info = match error {
        // The validator already extracted the code; it is the same field, read
        // through a variant that proves the exit was structurally normal.
        ObservedSupervisionError::Exit(ExitValidationError::NonzeroApplicationCode(code), _) => {
            return R1ProbeFailure::ExitCode(*code);
        }
        ObservedSupervisionError::ExitedBeforeReady(info)
        | ObservedSupervisionError::PeerClosedBeforeReady(info)
        | ObservedSupervisionError::Exit(_, info)
        | ObservedSupervisionError::ExitObservedReadiness(_, info) => info,
        ObservedSupervisionError::Supervision(_) => return R1ProbeFailure::ReadyUnattributed,
    };
    if info.application_code == 0 {
        R1ProbeFailure::ReadyUnattributed
    } else {
        R1ProbeFailure::ExitCode(info.application_code)
    }
}

/// One tick: service the probe's launches, then drain its report channel.
fn pump<S, L, W>(
    state: &mut State,
    system: &mut S,
    loader: &mut L,
    waits: &mut W,
    authority: LoadAuthority,
    now_ns: u64,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform + R1EvidenceSink,
    L: LoaderPlatform<Error = NativeError>,
    W: SupervisionPlatform<Error = NativeError>,
{
    poll_job_dispatcher(system, loader, waits, authority, &mut state.jobs, now_ns)?;
    drain(state, system, waits, now_ns)?;
    if state.relay.complete() {
        return finish(state, system, waits);
    }
    Ok(())
}

/// Counts what was still queued behind a refused out-of-order record.
///
/// Reached only on a run that has already failed, so these datagrams are drained
/// and discarded rather than relayed: the relay refuses everything after a gap by
/// design, and submitting them would put an out-of-order transcript in front of
/// the collector. What they are worth is their *count*, and whether any of them
/// is itself out of sequence -- one lost datagram is a different defect from a
/// channel dropping them repeatedly, and run 9 could not distinguish the two.
///
/// Bounded by the relay's capacity, and a refusal to read further is not an error
/// here: the census is diagnostic, and losing it must not replace the gap that
/// prompted it with some later failure.
fn census_after_gap<S>(
    state: &State,
    system: &mut S,
    expected: u64,
    observed: u64,
    now_ns: u64,
) -> RelayGapCensus
where
    S: Wyr1BPlatform,
{
    let mut census = RelayGapCensus {
        expected,
        observed,
        further: 0,
        further_gaps: 0,
    };
    let mut next = observed;
    for _ in 0..RELAY_CAPACITY {
        let items = [DwWaitItemV1 {
            handle: state.probe.launch_channel,
            signals: DW_SIGNAL_READABLE,
        }];
        match system.wait_many(&items, DwDeadline(now_ns)) {
            Ok(result) if result.observed.0 & DW_SIGNAL_READABLE.0 != 0 => {}
            _ => break,
        }
        let mut bytes = [0_u8; RECORD_BYTES];
        let mut handles = [DwReceivedHandleInfoV1::default(); 1];
        let counts = match system.receive_channel(state.probe.launch_channel, &mut bytes, &mut handles)
        {
            Ok(counts) => counts,
            Err(_) => break,
        };
        for info in handles.iter().take(counts.handles) {
            let _ = system.close_handle(info.handle);
        }
        census.further += 1;
        if counts.bytes != RECORD_BYTES {
            census.further_gaps += 1;
            continue;
        }
        // A record whose sequence is not one past the previous one is a second
        // loss, which is the finding this census exists to surface.
        match wyrmroot_r1_saturation::record::parse_header(&bytes) {
            Ok(header) => {
                if header.sequence != next + 1 {
                    census.further_gaps += 1;
                }
                next = header.sequence;
            }
            Err(_) => census.further_gaps += 1,
        }
    }
    census
}

/// Relays whatever the probe has queued, without blocking the resident tick.
///
/// The loop is bounded by the relay's own capacity: a probe that talked past it
/// is refused by the relay rather than allowed to hold this tick open.
pub(crate) fn drain<S, W>(
    state: &mut State,
    system: &mut S,
    waits: &mut W,
    now_ns: u64,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform + R1EvidenceSink,
    W: SupervisionPlatform<Error = NativeError>,
{
    for _ in 0..=RELAY_CAPACITY {
        if state.relay.complete() {
            return Ok(());
        }
        // The order of these two items is load-bearing. The probe sends its
        // terminal record and then exits, so both can be ready at once, and the
        // kernel resolves a tie to the lowest input index (its wait engine scans
        // requests in order and a test pins that). With the Channel first, a
        // queued terminal record is read; with the Process first, the branch
        // below would read that same run as one that stopped reporting and throw
        // the transcript away. The double asserts this shape on every call.
        let items = [
            DwWaitItemV1 {
                handle: state.probe.launch_channel,
                signals: deepwyrm_syscall::DwSignals(
                    DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0,
                ),
            },
            DwWaitItemV1 {
                handle: state.probe.process,
                signals: DW_SIGNAL_EXITED,
            },
        ];
        let observed = match system.wait_many(&items, DwDeadline(now_ns)) {
            Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => return Ok(()),
            Err(error) => return Err(InitError::Native(error)),
            Ok(observed) => observed,
        };
        if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
            // The probe exited or closed its channel without its terminal
            // record. A run that stopped reporting is not a run that passed,
            // and saying so here is the whole point of the card -- but saying
            // only that much erases the one datum that explains it, so the
            // probe's own exit code is read here rather than inferred later.
            // A live probe that merely closed its channel has no exit code and
            // is reported as the unattributed drain it is.
            return Err(InitError::R1Probe(
                match waits.query_task_termination(state.probe.process) {
                    Ok(info) if info.application_code != 0 => {
                        R1ProbeFailure::ExitCode(info.application_code)
                    }
                    Ok(_) => R1ProbeFailure::DrainUnattributed,
                    Err(_) => R1ProbeFailure::DrainQueryFailed,
                },
            ));
        }
        let mut bytes = [0_u8; RECORD_BYTES];
        let mut handles = [DwReceivedHandleInfoV1::default(); 1];
        let counts = system
            .receive_channel(state.probe.launch_channel, &mut bytes, &mut handles)
            .map_err(InitError::Native)?;
        // The relay refuses a record that arrived with handles, but the handles
        // that did arrive are still init's to close before it reports that.
        if counts.handles != 0 {
            let mut failed = false;
            for info in handles.iter().take(counts.handles) {
                failed |= system.close_handle(info.handle).is_err();
            }
            return Err(if failed {
                InitError::Cleanup
            } else {
                InitError::WrongManifestProfile
            });
        }
        // A datagram of any other size is refused here rather than truncated
        // into the buffer's length: a 64-byte prefix of a longer record would
        // otherwise parse as a valid one and be relayed as evidence.
        if counts.bytes != RECORD_BYTES {
            return Err(InitError::WrongManifestProfile);
        }
        match relay_one(&mut state.relay, system, &bytes, counts.handles) {
            Ok(_) => {}
            // An inadmissible record is a malformed or out-of-order transcript,
            // which the host must see as a classified init failure rather than
            // as a short transcript that looks like a stall -- and the relay's
            // own reason says which, so it travels with the failure. Answering
            // this with a bare category is what made run 6 undiagnosable.
            //
            // A sequence gap gets one further question asked before the run ends.
            // The run is still a failure and nothing more is relayed; the census
            // only counts what was already queued, which is the difference
            // between one lost datagram and a stream of them.
            Err(RelayFailure::Refused(RelayError::OutOfOrder { expected, observed })) => {
                return Err(InitError::R1RelayGap(census_after_gap(
                    state, system, expected, observed, now_ns,
                )));
            }
            Err(RelayFailure::Refused(error)) => return Err(InitError::R1Relay(error)),
            Err(RelayFailure::Rejected(error)) => return Err(InitError::Native(error)),
        }
    }
    Ok(())
}

/// Terminal teardown.
///
/// In the product this does not run. Deepwyrm's terminal branch for the evidence
/// syscall is `complete_r1_evidence`, which is `-> !`: it flushes the transcript,
/// writes the completion record and exits the guest, so the relay's submit of the
/// terminal record never returns and nothing after it executes. This path exists
/// for the host double, which does return, and it is written as real teardown so
/// the double exercises the same ownership the launch established rather than a
/// weaker stub.
///
/// Every job the probe launched was terminated and awaited by the plan itself
/// before its terminal record, so the dispatcher has no live job left to reap
/// here; the session channel is the dispatcher's and the rest is this state's.
pub(crate) fn finish<S, W>(
    state: &mut State,
    system: &mut S,
    waits: &mut W,
) -> Result<(), InitError>
where
    S: Wyr1BPlatform,
    W: SupervisionPlatform<Error = NativeError>,
{
    state.finished = true;
    let mut failed = false;
    match state.jobs.disconnect_session(state.grant) {
        Ok(channel) => failed |= system.close_handle(channel).is_err(),
        // The dispatcher retires the session itself when it observes the
        // probe's peer close, which races the terminal record legitimately.
        Err(JobError::UnknownConnection) => {}
        Err(error) => return Err(InitError::Wyr1BModel(error)),
    }
    failed |= cleanup_loaded(system, waits, state.probe, state.task_group, true).is_err();
    if failed {
        Err(InitError::Cleanup)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
