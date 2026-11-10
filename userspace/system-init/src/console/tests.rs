use super::*;
use deepwyrm_syscall::{
    DW_SIGNAL_READABLE, DW_TASK_STATE_CREATED, DW_TASK_STATE_RUNNING, DW_TERMINATION_NORMAL_EXIT,
    DwStatus,
};
use wyrmroot_device_proto::coordinator::SupervisorGeneration;

const FAILURE: NativeError = NativeError::Status(DwStatus(-1));

#[test]
fn every_absent_owner_combination_stays_inside_its_own_site_block() {
    // The five bits `absent_owner_site` sets are the whole mask, so the
    // block it can produce is exactly `0xa0..=0xbf`. The base has to be
    // aligned to the mask width, or the two overlap and a transcript can
    // no longer say which slots a site named.
    for absent in 0u8..0x20 {
        let site = ABSENT_OWNER_SITE_BASE | absent;
        assert!(
            (0xa0..=0xbf).contains(&site),
            "absent-owner site {site:#04x} left its block"
        );
        assert_eq!(
            site & !0x1f,
            ABSENT_OWNER_SITE_BASE,
            "mask {absent:#04x} disturbed the base"
        );
        assert_eq!(site & 0x1f, absent, "mask {absent:#04x} did not survive");
    }
    // The base itself is not a reachable site: the read only reports when
    // the registry slot is absent, so bit 0 is always set.
    assert_eq!(ABSENT_OWNER_SITE_BASE & 0x1f, 0);
}

struct ObserverPlatform {
    inbound: [u8; 256],
    inbound_len: usize,
    post_receive_now: u64,
    wait_count: usize,
    receive_count: usize,
    closed: [DwHandle; 2],
    close_count: usize,
    console_signals: Option<(deepwyrm_syscall::DwSignals, deepwyrm_syscall::DwSignals)>,
}

impl ObserverPlatform {
    fn generation(observed: PublicationObserver, post_receive_now: u64) -> Self {
        let mut inbound = [0u8; 256];
        let size = wyrmroot_registry_proto::encode_generation_changed(
            RegistryHeader {
                message_type: RegistryMessageType::GenerationChanged,
                registry_generation: observed.grant.registry_generation,
                endpoint_id: observed.grant.endpoint_id,
                endpoint_generation: observed.grant.endpoint_generation,
                transaction_id: PUBLICATION_WATCH_TRANSACTION,
            },
            observed.expected_service_generation,
            &mut inbound,
        )
        .unwrap();
        Self {
            inbound,
            inbound_len: size,
            post_receive_now,
            wait_count: 0,
            receive_count: 0,
            closed: [DwHandle(0); 2],
            close_count: 0,
            console_signals: None,
        }
    }
}

impl InitPlatform for ObserverPlatform {
    fn query_capability_info(
        &mut self,
        _handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
        Err(FAILURE)
    }

    fn receive_channel(
        &mut self,
        _channel: DwHandle,
        bytes: &mut [u8],
        _handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        self.receive_count += 1;
        bytes[..self.inbound_len].copy_from_slice(&self.inbound[..self.inbound_len]);
        Ok(ReceiveCounts {
            bytes: self.inbound_len,
            handles: 0,
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
        self.closed[self.close_count] = handle;
        self.close_count += 1;
        Ok(())
    }

    fn create_attempt_task_group(&mut self, _parent: DwHandle) -> Result<DwHandle, NativeError> {
        Err(FAILURE)
    }

    fn terminate_task_group(&mut self, _task_group: DwHandle) -> Result<(), NativeError> {
        Err(FAILURE)
    }

    fn now(&mut self) -> Result<u64, NativeError> {
        Ok(self.post_receive_now)
    }

    fn wait_until(&mut self, _deadline_ns: u64) -> Result<(), NativeError> {
        Err(FAILURE)
    }
}

impl ResidentPlatform for ObserverPlatform {
    fn channel_create(&mut self, _rights: DwRights) -> Result<(DwHandle, DwHandle), NativeError> {
        Err(FAILURE)
    }

    fn send_channel_with_handles(
        &mut self,
        _channel: DwHandle,
        _bytes: &[u8],
        _transfers: &[DwHandleTransferV1],
    ) -> Result<(), NativeError> {
        Err(FAILURE)
    }

    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        _deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, NativeError> {
        self.wait_count += 1;
        if let Some((process, control)) = self.console_signals {
            for (index, item) in items.iter().enumerate() {
                let signals = if item.handle == console_peer().loaded.process {
                    process
                } else {
                    assert_eq!(item.handle, console_peer().loaded.launch_channel);
                    control
                };
                let observed = deepwyrm_syscall::DwSignals(signals.0 & item.signals.0);
                if observed.0 != 0 {
                    return Ok(DwWaitResultV1 {
                        index: index as u32,
                        observed,
                        ..DwWaitResultV1::default()
                    });
                }
            }
            return Err(NativeError::Status(DW_STATUS_TIMED_OUT));
        }
        assert_eq!(items.len(), 1);
        Ok(DwWaitResultV1 {
            index: 0,
            observed: DW_SIGNAL_READABLE,
            ..DwWaitResultV1::default()
        })
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

struct ObserverWaits {
    state: deepwyrm_syscall::DwTaskState,
    query_count: usize,
}

impl SupervisionPlatform for ObserverWaits {
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
        process: DwHandle,
    ) -> Result<DwTaskTerminationInfoV1, Self::Error> {
        assert_eq!(process, DwHandle(91));
        self.query_count += 1;
        Ok(DwTaskTerminationInfoV1 {
            state: self.state,
            reason: DW_TERMINATION_NORMAL_EXIT,
            ..DwTaskTerminationInfoV1::default()
        })
    }
}

fn driver_request() -> DriverLaunchRequest {
    DriverLaunchRequest {
        supervisor_generation: SupervisorGeneration(7),
        role_id: wyrmroot_device_proto::COM2_ROLE_ID,
        attempt_generation: wyrmroot_device_proto::coordinator::AttemptGeneration(1),
        launch_session: wyrmroot_device_proto::coordinator::LaunchSessionGeneration(2),
        endpoint: wyrmroot_device_proto::ControlEndpoint {
            id: wyrmroot_device_proto::coordinator::EndpointId(3),
            generation: wyrmroot_device_proto::coordinator::EndpointGeneration(1),
        },
        transaction_id: 9,
        driver_path: wyrmroot_device_proto::DEVICE_DRIVER_PATH,
        actor_identity: wyrmroot_device_proto::manifest::ContentIdentity([0x5a; 32]),
        child_is_channel: true,
        child_rights: wyrmroot_device_proto::DirectControlRights::ExactReduced,
    }
}

fn observer() -> PublicationObserver {
    PublicationObserver {
        client: DwHandle(90),
        grant: EndpointGrant {
            registry_generation: 7,
            endpoint_id: 8,
            endpoint_generation: 9,
            role_generation: 10,
            kind: EndpointKind::RegistryClient,
        },
        expected_service_generation: 11,
        expected_driver: driver_request(),
        deadline: 100,
    }
}

fn driver_attempt() -> DriverNativeAttempt {
    DriverNativeAttempt {
        loaded: LoadedProcess {
            process: DwHandle(91),
            launch_channel: DwHandle(92),
        },
        task_group: DwHandle(93),
        request: driver_request(),
    }
}

fn console_peer() -> InstalledPeer {
    InstalledPeer {
        grant: EndpointGrant {
            registry_generation: 7,
            endpoint_id: 12,
            endpoint_generation: 13,
            role_generation: 14,
            kind: EndpointKind::LaunchSession,
        },
        loaded: LoadedProcess {
            process: DwHandle(94),
            launch_channel: DwHandle(95),
        },
        task_group: DwHandle(96),
    }
}

fn generation_changed(observed: PublicationObserver) -> ([u8; 72], usize) {
    let mut bytes = [0u8; 72];
    let size = wyrmroot_registry_proto::encode_generation_changed(
        RegistryHeader {
            message_type: RegistryMessageType::GenerationChanged,
            registry_generation: observed.grant.registry_generation,
            endpoint_id: observed.grant.endpoint_id,
            endpoint_generation: observed.grant.endpoint_generation,
            transaction_id: PUBLICATION_WATCH_TRANSACTION,
        },
        observed.expected_service_generation,
        &mut bytes,
    )
    .unwrap();
    (bytes, size)
}

#[test]
fn console_launch_budget_is_finite_and_only_fresh_registry_replenishes_it() {
    let mut state = ConsoleState::new(7).unwrap();
    let first = state.take_console_transaction().unwrap();
    assert_eq!(first, FIRST_CONSOLE_TRANSACTION);
    for _ in 1..WYR0_I_SUPERVISION_POLICY.max_attempts {
        state.take_console_transaction().unwrap();
    }
    assert_eq!(state.take_console_transaction(), Err(InitError::Cleanup));

    state.shell.poison(7);
    state.shell.reserve_replacement_generation(8).unwrap();
    state.commit_registry_replacement(8).unwrap();
    assert_eq!(
        state.shell.health(),
        crate::ShellRegistryHealth::Healthy { generation: 8 }
    );
    assert!(state.take_console_transaction().is_ok());
}

#[test]
fn closed_console_session_discards_stale_owner_and_requests_fresh_launch() {
    let peer = console_peer();
    let mut state = ConsoleState::new(7).unwrap();
    state.console = Some(peer);
    state.awaiting_ready = true;
    state.bootstrap_released = true;
    state.console_transaction = 23;

    assert_eq!(
        reconcile_job_dispatcher_outcome(
            &mut state,
            JobDispatcherPollOutcome::SessionClosed {
                grant: peer.grant,
                scope: LaunchSessionScope::ConsoleLauncher,
            },
        ),
        Ok(Some(PollOutcome::LaunchConsole))
    );
    assert_eq!(state.console, None);
    assert!(!state.awaiting_ready);
    assert!(!state.bootstrap_released);
    assert_eq!(state.console_transaction, 0);
}

/// F3A.7j. Run 7 closed consoled's launch session before init saw its
/// process exit, and this route relaunched the console. Both routes must
/// conclude the same way once the shell has ended the session.
#[test]
fn a_closed_console_session_after_shutdown_completes_the_session() {
    let peer = console_peer();
    let mut state = ConsoleState::new(7).unwrap();
    state.console = Some(peer);
    state.shell.observe_session_shutdown();

    let outcome = reconcile_job_dispatcher_outcome(
        &mut state,
        JobDispatcherPollOutcome::SessionClosed {
            grant: peer.grant,
            scope: LaunchSessionScope::ConsoleLauncher,
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        conclude_session(outcome, state.shell.session_shutdown()),
        PollOutcome::SessionComplete
    );
    assert_eq!(state.console, None);
}

/// Every route's outcome must pass through `conclude_session`, or a new
/// route reopens run 7's relaunch.
///
/// Source text because `poll` runs `poll_observations` first, which no
/// host fake drives; `conclude_session` itself is host-tested below.
#[test]
fn poll_concludes_every_outcome_through_one_decision() {
    const SOURCE: &str = include_str!("../console.rs");
    let start = SOURCE.find("pub(super) fn poll<").unwrap();
    let poll = &SOURCE[start..start + SOURCE[start..].find("\n}\n").unwrap()];
    let observed = poll
        .find("let outcome = poll_observations(resident, system, loader, waits, now)?;")
        .expect("poll no longer delegates its observations");
    let concluded = poll
        .find("Ok(conclude_session(outcome, session_shutdown))")
        .expect("poll no longer concludes through conclude_session");
    assert!(observed < concluded);
    assert_eq!(poll.matches("return").count(), 0, "poll must have one exit");
}

#[test]
fn only_a_console_departure_after_shutdown_completes_the_session() {
    assert_eq!(
        conclude_session(PollOutcome::LaunchConsole, true),
        PollOutcome::SessionComplete
    );
    assert_eq!(
        conclude_session(PollOutcome::LaunchConsole, false),
        PollOutcome::LaunchConsole
    );
    // A recovery is still a recovery after the session ended: it names
    // something that failed, and a clean shutdown must not hide it.
    for outcome in [
        PollOutcome::Stable,
        PollOutcome::RecoverDevmgr,
        PollOutcome::RecoverRegistry(3),
    ] {
        assert_eq!(conclude_session(outcome, true), outcome);
        assert_eq!(conclude_session(outcome, false), outcome);
    }
}

#[test]
fn closed_console_session_with_wrong_grant_fails_without_discarding_owner() {
    let peer = console_peer();
    let mut state = ConsoleState::new(7).unwrap();
    state.console = Some(peer);
    let mut wrong_grant = peer.grant;
    wrong_grant.endpoint_generation += 1;

    assert_eq!(
        reconcile_job_dispatcher_outcome(
            &mut state,
            JobDispatcherPollOutcome::SessionClosed {
                grant: wrong_grant,
                scope: LaunchSessionScope::ConsoleLauncher,
            },
        ),
        Err(InitError::Accounting)
    );
    assert_eq!(state.console, Some(peer));
}

/// F3A.7g. A completed session is the one outcome that stops the system,
/// so it must not be reported by a teardown that did not finish. A failed
/// retirement returns an error rather than `LaunchConsole`, so
/// `conclude_session` never sees it; answering `LaunchConsole` above the
/// `?` would turn a cleanup failure into a clean shutdown.
#[test]
fn a_failed_console_retirement_is_not_a_completed_session() {
    let peer = console_peer();
    let mut state = ConsoleState::new(7).unwrap();
    state.console = Some(peer);
    state.shell.observe_session_shutdown();
    assert!(state.shell.session_shutdown());
    let observed = observer();
    let mut platform = ObserverPlatform::generation(observed, observed.deadline);
    let mut waits = ObserverWaits {
        state: DW_TASK_STATE_RUNNING,
        query_count: 0,
    };

    // The dispatcher holds no console session, so the retirement cannot
    // complete. The latch is set and must not answer for it.
    assert_ne!(
        handle_console_process_exit(&mut state, &mut platform, &mut waits, false),
        Ok(PollOutcome::SessionComplete)
    );
}

#[test]
fn coordinated_retirement_keeps_an_exited_console_owned_for_the_recovery_join() {
    let peer = console_peer();
    let mut state = ConsoleState::new(7).unwrap();
    state.console = Some(peer);
    state.awaiting_ready = true;
    state.bootstrap_released = true;
    state.console_transaction = 23;
    let observed = observer();
    let mut platform = ObserverPlatform::generation(observed, observed.deadline);
    let mut waits = ObserverWaits {
        state: DW_TASK_STATE_RUNNING,
        query_count: 0,
    };

    assert_eq!(
        handle_console_process_exit(&mut state, &mut platform, &mut waits, true),
        Ok(PollOutcome::Stable)
    );
    assert_eq!(state.console, Some(peer));
    assert!(state.awaiting_ready);
    assert!(state.bootstrap_released);
    assert_eq!(state.console_transaction, 23);
    assert_eq!(platform.close_count, 0);
    assert_eq!(waits.query_count, 0);
}

#[test]
fn coordinated_retirement_services_control_despite_a_retained_console_exit() {
    let peer = console_peer();
    let observed = observer();
    let mut platform = ObserverPlatform::generation(observed, 50);
    platform.console_signals = Some((DW_SIGNAL_EXITED, DW_SIGNAL_READABLE));

    // The ordinary owner still observes process death first.
    let ordinary = poll_console_event(&mut platform, peer.loaded, false, false, 50)
        .unwrap()
        .unwrap();
    assert_eq!(ordinary.index, 0);
    assert_eq!(ordinary.observed, DW_SIGNAL_EXITED);

    // The recovery owner must instead reach the already-committed reply.
    let recovering = poll_console_event(&mut platform, peer.loaded, false, true, 50)
        .unwrap()
        .unwrap();
    assert_eq!(recovering.index, 1);
    assert_eq!(recovering.observed, DW_SIGNAL_READABLE);

    // With the reply consumed, process death must not produce false work.
    platform.console_signals = Some((DW_SIGNAL_EXITED, deepwyrm_syscall::DwSignals(0)));
    assert_eq!(
        poll_console_event(&mut platform, peer.loaded, false, true, 50),
        Ok(None)
    );
    // Later peer closure still reaches the control owner exactly once.
    platform.console_signals = Some((DW_SIGNAL_EXITED, DW_SIGNAL_PEER_CLOSED));
    let closed = poll_console_event(&mut platform, peer.loaded, false, true, 50)
        .unwrap()
        .unwrap();
    assert_eq!(closed.index, 1);
    assert_eq!(closed.observed, DW_SIGNAL_PEER_CLOSED);
    let wait_count = platform.wait_count;
    assert_eq!(
        poll_console_event(&mut platform, peer.loaded, true, true, 50),
        Ok(None)
    );
    assert_eq!(platform.wait_count, wait_count);
    assert_eq!(platform.close_count, 0);
}

#[test]
fn publication_watch_requires_exact_tuple_generation_and_predeadline_validation() {
    let observed = observer();
    let mut request = [0u8; 256];
    let request_size = encode_publication_watch(observed.grant, &mut request).unwrap();
    let parsed_request = parse_registry(&request[..request_size], 0).unwrap();
    assert_eq!(
        parsed_request.header,
        RegistryHeader {
            message_type: RegistryMessageType::Watch,
            registry_generation: observed.grant.registry_generation,
            endpoint_id: observed.grant.endpoint_id,
            endpoint_generation: observed.grant.endpoint_generation,
            transaction_id: PUBLICATION_WATCH_TRANSACTION,
        }
    );
    assert_eq!(
        parsed_request.message,
        RegistryMessage::Watch(Watch {
            protocol_id: SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY.protocol_id,
            last_observed_generation: 0,
            service_name: SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY.service_name,
        })
    );
    let (mut bytes, size) = generation_changed(observed);
    assert_eq!(
        validate_publication_datagram(observed, &bytes[..size], observed.deadline - 1),
        Ok(())
    );
    assert_eq!(
        validate_publication_datagram(observed, &bytes[..size], observed.deadline),
        Err(PollOutcome::RecoverDevmgr)
    );

    let mut stale_generation = observed;
    stale_generation.expected_service_generation += 1;
    assert_eq!(
        validate_publication_datagram(stale_generation, &bytes[..size], observed.deadline - 1,),
        Err(PollOutcome::RecoverDevmgr)
    );

    // F3A.6j: both of these are the datagram's own phase, not the
    // observer's -- a wrong message body and a truncated one.
    let datagram = PollOutcome::RecoverRegistry(crate::abandoned::phase::PUBLICATION_DATAGRAM);
    bytes[48] ^= 1;
    assert_eq!(
        validate_publication_datagram(observed, &bytes[..size], observed.deadline - 1),
        Err(datagram)
    );
    assert_eq!(
        validate_publication_datagram(observed, &bytes[..size - 1], observed.deadline - 1),
        Err(datagram)
    );
}

#[test]
fn observer_deadline_wins_before_receive_and_after_exact_reply_validation() {
    let observed = observer();
    let mut session = ConsoleState::new(observed.grant.registry_generation).unwrap();
    session.publication_observer = Some(observed);
    let mut platform = ObserverPlatform::generation(observed, observed.deadline);
    let mut waits = ObserverWaits {
        state: DW_TASK_STATE_RUNNING,
        query_count: 0,
    };
    assert_eq!(
        poll_publication_observer_state(
            &mut session,
            Some(driver_attempt()),
            observed.grant.registry_generation,
            &mut platform,
            &mut waits,
            observed.deadline,
        ),
        Ok(Some(PollOutcome::RecoverDevmgr))
    );
    assert_eq!(platform.wait_count, 0);
    assert_eq!(platform.receive_count, 0);
    assert_eq!(platform.closed[..platform.close_count], [observed.client]);
    assert_eq!(waits.query_count, 0);
    assert!(session.publication_observer.is_none());

    session.publication_observer = Some(observed);
    let mut platform = ObserverPlatform::generation(observed, observed.deadline);
    assert_eq!(
        poll_publication_observer_state(
            &mut session,
            Some(driver_attempt()),
            observed.grant.registry_generation,
            &mut platform,
            &mut waits,
            observed.deadline - 1,
        ),
        Ok(Some(PollOutcome::RecoverDevmgr))
    );
    assert_eq!(platform.wait_count, 1);
    assert_eq!(platform.receive_count, 1);
    assert_eq!(platform.closed[..platform.close_count], [observed.client]);
    assert_eq!(waits.query_count, 0);
}

#[test]
fn exact_queued_watch_cannot_launch_an_already_exited_driver() {
    let observed = observer();
    let mut session = ConsoleState::new(observed.grant.registry_generation).unwrap();
    session.publication_observer = Some(observed);
    let mut platform = ObserverPlatform::generation(observed, observed.deadline - 1);
    let mut waits = ObserverWaits {
        state: DW_TASK_STATE_EXITED,
        query_count: 0,
    };
    assert_eq!(
        poll_publication_observer_state(
            &mut session,
            Some(driver_attempt()),
            observed.grant.registry_generation,
            &mut platform,
            &mut waits,
            observed.deadline - 1,
        ),
        Ok(Some(PollOutcome::RecoverDevmgr))
    );
    assert_eq!(waits.query_count, 1);
    assert_eq!(platform.closed[..platform.close_count], [observed.client]);
    assert!(session.publication_observer.is_none());
}

#[test]
fn exact_queued_watch_requires_driver_to_be_running() {
    let observed = observer();
    let mut session = ConsoleState::new(observed.grant.registry_generation).unwrap();
    session.publication_observer = Some(observed);
    let mut platform = ObserverPlatform::generation(observed, observed.deadline - 1);
    let mut waits = ObserverWaits {
        state: DW_TASK_STATE_CREATED,
        query_count: 0,
    };
    assert_eq!(
        poll_publication_observer_state(
            &mut session,
            Some(driver_attempt()),
            observed.grant.registry_generation,
            &mut platform,
            &mut waits,
            observed.deadline - 1,
        ),
        Ok(Some(PollOutcome::RecoverDevmgr))
    );
    assert_eq!(waits.query_count, 1);
    assert_eq!(platform.closed[..platform.close_count], [observed.client]);
    assert!(session.publication_observer.is_none());
}
