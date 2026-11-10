use super::*;
use deepwyrm_syscall::DW_OBJECT_TYPE_CHANNEL;
use deepwyrm_syscall::{
    DW_SIGNAL_EXITED, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_TERMINATION_NORMAL_EXIT,
    DwStatus,
};
use wyrmroot_device_proto::controller::{encode as encode_controller, parse as parse_controller};
use wyrmroot_device_proto::driver_launch::LAUNCH_REQUEST_BYTES;
use wyrmroot_device_proto::manifest::{COM2_ROLE_ID, ContentIdentity, Manifest as DeviceManifest};
use wyrmroot_device_proto::manifest::{
    HEADER_BYTES as WRDM_HEADER_BYTES, MAGIC as WRDM_MAGIC, MAJOR as WRDM_MAJOR,
    MINOR as WRDM_MINOR, PROFILE_Q35, PROFILE_Q35_VERSION, RECORD_BYTES as WRDM_RECORD_BYTES,
    UART16550D_PATH,
};
use wyrmroot_loader::launch::{CHILD_CHANNEL_RIGHTS, DEVICE_MANIFEST_RIGHTS};

const FAILURE: NativeError = NativeError::Status(DwStatus(-1));

struct RebindPlatform {
    inbound: [u8; wyrmroot_device_proto::controller::STATUS_BYTES],
    inbound_len: usize,
    send_count: usize,
    fail_send_at: usize,
    closed: [DwHandle; 16],
    close_count: usize,
    /// Plain `send_channel` calls are refused unless a test opts in.
    accept_sends: bool,
    sent: [DwHandle; 4],
    send_plain_count: usize,
    /// `terminate_task_group` is refused unless a test opts in.
    accept_terminate: bool,
    terminated: [DwHandle; 8],
    terminate_count: usize,
    registry_service_generation: Option<u64>,
    controller_service_generation: Option<u64>,
    controller_request: Option<ControllerMessage>,
    now: u64,
    receive_at: Option<u64>,
}

impl RebindPlatform {
    fn with_status(message: ControllerMessage) -> Self {
        let mut inbound = [0; wyrmroot_device_proto::controller::STATUS_BYTES];
        encode_controller(message, &mut inbound).unwrap();
        Self::with_reply(inbound)
    }

    fn with_reply(inbound: [u8; wyrmroot_device_proto::controller::STATUS_BYTES]) -> Self {
        Self {
            inbound,
            inbound_len: wyrmroot_device_proto::controller::STATUS_BYTES,
            send_count: 0,
            fail_send_at: usize::MAX,
            closed: [DwHandle(0); 16],
            close_count: 0,
            accept_sends: false,
            sent: [DwHandle(0); 4],
            send_plain_count: 0,
            accept_terminate: false,
            terminated: [DwHandle(0); 8],
            terminate_count: 0,
            registry_service_generation: None,
            controller_service_generation: None,
            controller_request: None,
            now: 100,
            receive_at: None,
        }
    }
}

impl InitPlatform for RebindPlatform {
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
        if self.inbound_len == 0 {
            return Err(FAILURE);
        }
        bytes[..self.inbound_len].copy_from_slice(&self.inbound[..self.inbound_len]);
        let counts = ReceiveCounts {
            bytes: self.inbound_len,
            handles: 0,
        };
        self.inbound_len = 0;
        if let Some(now) = self.receive_at {
            self.now = now;
        }
        Ok(counts)
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

    fn send_channel(&mut self, channel: DwHandle, _bytes: &[u8]) -> Result<(), NativeError> {
        if !self.accept_sends {
            return Err(FAILURE);
        }
        self.sent[self.send_plain_count] = channel;
        self.send_plain_count += 1;
        Ok(())
    }

    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        self.closed[self.close_count] = handle;
        self.close_count += 1;
        Ok(())
    }

    fn create_attempt_task_group(&mut self, _parent: DwHandle) -> Result<DwHandle, NativeError> {
        Err(FAILURE)
    }

    fn terminate_task_group(&mut self, task_group: DwHandle) -> Result<(), NativeError> {
        if !self.accept_terminate {
            return Err(FAILURE);
        }
        self.terminated[self.terminate_count] = task_group;
        self.terminate_count += 1;
        Ok(())
    }

    fn now(&mut self) -> Result<u64, NativeError> {
        Ok(self.now)
    }

    fn wait_until(&mut self, _deadline_ns: u64) -> Result<(), NativeError> {
        Err(FAILURE)
    }
}

impl ResidentPlatform for RebindPlatform {
    fn channel_create(&mut self, _rights: DwRights) -> Result<(DwHandle, DwHandle), NativeError> {
        Ok((DwHandle(50), DwHandle(51)))
    }

    fn send_channel_with_handles(
        &mut self,
        channel: DwHandle,
        bytes: &[u8],
        transfers: &[DwHandleTransferV1],
    ) -> Result<(), NativeError> {
        self.send_count += 1;
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].operation, DW_HANDLE_TRANSFER_MOVE);
        assert_eq!(transfers[0].requested_rights, CHILD_CHANNEL_RIGHTS);
        assert_eq!(transfers[0].reserved0, 0);
        assert_eq!(transfers[0].reserved, [0; 2]);
        if self.send_count == 1 {
            assert_eq!(channel, DwHandle(40));
            assert_eq!(transfers[0].handle, DwHandle(50));
            let parsed = wyrmroot_registry_proto::parse(bytes, 1).unwrap();
            let wyrmroot_registry_proto::Message::InstallPublication(publication) = parsed.message
            else {
                panic!("registry must receive publication installation");
            };
            self.registry_service_generation = Some(publication.service_generation);
        } else {
            assert_eq!(self.send_count, 2);
            assert_eq!(channel, devmgr().loaded.launch_channel);
            assert_eq!(transfers[0].handle, DwHandle(51));
            {
                let parsed = wyrmroot_device_proto::controller_v1_1::parse(bytes).unwrap();
                self.controller_request = Some(parsed.controller);
                self.controller_service_generation = Some(parsed.service_generation);
                assert_eq!(
                    self.controller_service_generation,
                    self.registry_service_generation
                );
            }
        }
        if self.send_count == self.fail_send_at {
            Err(FAILURE)
        } else {
            Ok(())
        }
    }

    fn wait_many(
        &mut self,
        _items: &[DwWaitItemV1],
        _deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, NativeError> {
        Err(FAILURE)
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

struct StatusWaits {
    fail: bool,
    /// When set, every wait observes EXITED and every termination query
    /// answers this record.
    exit: Option<DwTaskTerminationInfoV1>,
}

impl SupervisionPlatform for StatusWaits {
    type Error = NativeError;

    fn wait_many(
        &mut self,
        _items: &[DwWaitItemV1],
        _deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, Self::Error> {
        if self.fail {
            Err(FAILURE)
        } else {
            Ok(DwWaitResultV1 {
                index: 0,
                observed: if self.exit.is_some() {
                    DW_SIGNAL_EXITED
                } else {
                    DW_SIGNAL_READABLE
                },
                ..DwWaitResultV1::default()
            })
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
        self.exit.ok_or(FAILURE)
    }
}

const fn devmgr() -> ActiveNativeRole {
    ActiveNativeRole {
        role: RoleId::Devmgr,
        generation: 7,
        transaction_id: 8,
        loaded: LoadedProcess {
            process: DwHandle(20),
            launch_channel: DwHandle(30),
        },
        task_group: DwHandle(10),
    }
}

fn binding() -> wyrmroot_device_proto::RegistryBinding {
    wyrmroot_device_proto::RegistryBinding {
        generation: RegistryGeneration(2),
        endpoint: RegistryEndpoint {
            id: RegistryEndpointId(1),
            generation: RegistryEndpointGeneration(1),
        },
    }
}

fn rebound_binding() -> wyrmroot_device_proto::RegistryBinding {
    wyrmroot_device_proto::RegistryBinding {
        generation: RegistryGeneration(2),
        endpoint: RegistryEndpoint {
            id: RegistryEndpointId(2),
            generation: RegistryEndpointGeneration(1),
        },
    }
}

fn waiting_device_status() -> ControllerMessage {
    ControllerMessage::Status {
        supervisor_generation: SupervisorGeneration(7),
        binding: Some(binding()),
        transaction_id: 9,
        status: StatusCode::OperationalWaitingForDeviceBundle,
        attempt_generation: None,
    }
}

fn real_rebind_producer(retired: bool) -> wyrmroot_devmgr::ResidentController {
    use wyrmroot_device_proto::coordinator::BundleGeneration;
    let mut producer = wyrmroot_devmgr::ResidentController::new(
        wyrmroot_devmgr::prepare_operational(&wrdm([0x5a; 32]), 7).unwrap(),
        8,
    )
    .unwrap();
    let mut initial = binding();
    if !retired {
        initial.generation = RegistryGeneration(1);
    }
    producer
        .accept(
            ControllerMessage::InstallPublication {
                supervisor_generation: SupervisorGeneration(7),
                binding: initial,
                transaction_id: 8,
            },
            0,
        )
        .unwrap();
    producer
        .admit_device_resource(deepwyrm_syscall::DwDeviceResourceInfoV1 {
            size: deepwyrm_syscall::DW_DEVICE_RESOURCE_INFO_V1_SIZE,
            version: deepwyrm_syscall::DW_DEVICE_RESOURCE_INFO_V1_VERSION,
            kind: deepwyrm_syscall::DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
            flags: 0,
            resource_id: 1,
            lease_generation: 19,
            pio_base: 0x2f8,
            pio_length: 8,
            interrupt_source: 3,
            reserved: 0,
        })
        .unwrap();
    let driver = producer
        .issue_driver_launch_with_bundle(
            true,
            wyrmroot_device_proto::DirectControlRights::ExactReduced,
        )
        .unwrap();
    producer.driver_constructed().unwrap();
    producer.resource_bundle_message().unwrap();
    producer.bundle_transferred().unwrap();
    producer
        .accept_driver_ready(wyrmroot_device_proto::ControlMessage::Ready {
            role_id: driver.role_id,
            bundle_generation: BundleGeneration(19),
            attempt_generation: driver.attempt_generation,
            endpoint: driver.endpoint,
            transaction_id: driver.transaction_id,
        })
        .unwrap();
    producer.publication_committed().unwrap();
    if retired {
        producer.retire_message().unwrap();
        producer.accept_intentional_driver_terminal(driver).unwrap();
        producer.publication_retired().unwrap();
        producer.reap_driver().unwrap();
    } else {
        producer.publication_peer_closed().unwrap();
    }
    producer
        .accept(
            ControllerMessage::RebindPublication {
                supervisor_generation: SupervisorGeneration(7),
                binding: rebound_binding(),
                transaction_id: 9,
            },
            1,
        )
        .unwrap();
    assert_eq!(producer.driver_ready(), !retired);
    assert_eq!(
        producer.active_driver_request(),
        if retired { None } else { Some(driver) }
    );
    producer
}

#[test]
fn real_rebind_acknowledgements_are_lifecycle_exact_and_reject_swapped_or_stale_replies() {
    for retired in [false, true] {
        let producer = real_rebind_producer(retired);
        let reply = producer.publication_acknowledgement().unwrap();
        let context = if retired {
            PublicationRebindContext::DriverRetirement
        } else {
            PublicationRebindContext::RegistryRecovery
        };
        let expected_status = context
            .expected_status(
                Some(ResourceDomainCustody::new(DwHandle(60))),
                None,
                retired.then(driver_request),
                SupervisorGeneration(7),
            )
            .unwrap();
        assert_eq!(
            parse_controller(&reply).unwrap(),
            ControllerMessage::Status {
                supervisor_generation: SupervisorGeneration(7),
                binding: Some(rebound_binding()),
                transaction_id: 9,
                status: expected_status,
                attempt_generation: None,
            }
        );
        let swapped = if retired {
            StatusCode::OperationalResourceOwned
        } else {
            StatusCode::OperationalWaitingForDeviceBundle
        };
        for mutation in [
            None,
            Some((72, swapped as u64)),
            Some((24, 8)),
            Some((32, 3)),
            Some((40, 3)),
            Some((48, 2)),
            Some((56, 10)),
            Some((80, 1)),
        ] {
            let mut bytes = reply;
            if let Some((offset, value)) = mutation {
                bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            }
            let mut platform = RebindPlatform::with_reply(bytes);
            let mut topology = RegistryTopology::new(2).unwrap();
            topology.issue(7, EndpointKind::Publication).unwrap();
            let result = perform_rebind(
                &mut platform,
                &mut StatusWaits {
                    fail: false,
                    exit: None,
                },
                &mut topology,
                &mut PublicationAllocator::new(),
                DwHandle(40),
                devmgr(),
                9,
                expected_status,
                Some(1_000_000_000),
            );
            if mutation.is_none() {
                assert!(result.is_ok(), "retired={retired}: {result:?}");
            } else {
                assert_eq!(
                    result,
                    Err(InitError::WrongManifestProfile),
                    "retired={retired}, mutation={mutation:?}"
                );
            }
            assert_eq!(platform.inbound_len, 0);
            assert_eq!(platform.send_count, 2);
            assert_eq!(platform.close_count, 0);
            assert_eq!(
                platform.controller_request,
                Some(ControllerMessage::RebindPublication {
                    supervisor_generation: SupervisorGeneration(7),
                    binding: rebound_binding(),
                    transaction_id: 9,
                })
            );
        }
        let mut platform = RebindPlatform::with_reply(reply);
        platform.receive_at = Some(101);
        let mut topology = RegistryTopology::new(2).unwrap();
        topology.issue(7, EndpointKind::Publication).unwrap();
        assert_eq!(
            perform_rebind(
                &mut platform,
                &mut StatusWaits {
                    fail: false,
                    exit: None,
                },
                &mut topology,
                &mut PublicationAllocator::new(),
                DwHandle(40),
                devmgr(),
                9,
                expected_status,
                Some(101),
            ),
            Err(InitError::Supervision)
        );
        assert_eq!(platform.inbound_len, 0);
    }
}

#[test]
fn rebind_postconditions_require_the_reached_resource_and_reaped_owner_context() {
    let custody = Some(ResourceDomainCustody::new(DwHandle(60)));
    let request = driver_request();
    let driver = Some(DriverNativeAttempt {
        loaded: devmgr().loaded,
        task_group: DwHandle(61),
        request,
    });
    let supervisor = SupervisorGeneration(7);
    assert_eq!(
        PublicationRebindContext::RegistryRecovery.expected_status(None, None, None, supervisor),
        Ok(StatusCode::OperationalWaitingForDeviceBundle)
    );
    assert_eq!(
        PublicationRebindContext::RegistryRecovery
            .expected_status(custody, driver, None, supervisor),
        Ok(StatusCode::OperationalResourceOwned)
    );
    assert_eq!(
        PublicationRebindContext::DriverRetirement.expected_status(
            custody,
            None,
            Some(request),
            supervisor
        ),
        Ok(StatusCode::OperationalWaitingForDeviceBundle)
    );
    assert_eq!(
        PublicationRebindContext::DriverRetirement.expected_status(
            custody,
            driver,
            Some(request),
            supervisor
        ),
        // Still an ordering violation, not an absent slot: this reaches
        // the explicit guard rather than a state `Option`.
        Err(InitError::WrongActivationOrder)
    );
    assert_eq!(
        PublicationRebindContext::DriverRetirement.expected_status(custody, None, None, supervisor),
        Err(InitError::AbsentState(0x6c))
    );
    assert_eq!(
        PublicationRebindContext::DriverRetirement.expected_status(
            custody,
            None,
            Some(request),
            SupervisorGeneration(8)
        ),
        // A stale supervisor generation is an ordering violation, and the
        // guard that says so runs before any slot is read.
        Err(InitError::WrongActivationOrder)
    );
}

#[test]
fn successful_rebind_preserves_devmgr_generation_and_commits_correlation() {
    let status = ControllerMessage::Status {
        supervisor_generation: SupervisorGeneration(7),
        binding: Some(rebound_binding()),
        transaction_id: 9,
        status: StatusCode::OperationalWaitingForDeviceBundle,
        attempt_generation: None,
    };
    let mut platform = RebindPlatform::with_status(status);
    let mut waits = StatusWaits {
        fail: false,
        exit: None,
    };
    let mut topology = RegistryTopology::new(2).unwrap();
    let initial_grant = topology.issue(7, EndpointKind::Publication).unwrap();
    assert_eq!(initial_grant.endpoint_id, 1);
    let mut publications = PublicationAllocator::new();
    let initial_publication = publications.issue().unwrap();
    let result = perform_rebind(
        &mut platform,
        &mut waits,
        &mut topology,
        &mut publications,
        DwHandle(40),
        devmgr(),
        9,
        StatusCode::OperationalWaitingForDeviceBundle,
        None,
    )
    .unwrap();
    assert_eq!(result.0, rebound_binding());
    assert!(result.1 > initial_publication.service_generation);
    assert_eq!(result.2, 9);
    assert_eq!(platform.send_count, 2);
    assert_eq!(platform.close_count, 0);
    assert_eq!(devmgr().generation, 7);
    assert_eq!(platform.registry_service_generation, Some(result.1));
    assert_eq!(
        platform.controller_request,
        Some(ControllerMessage::RebindPublication {
            supervisor_generation: SupervisorGeneration(7),
            binding: result.0,
            transaction_id: result.2,
        })
    );
    assert_eq!(platform.controller_service_generation, Some(result.1));
}

#[test]
fn selected_initial_publication_request_keeps_issued_namespace() {
    let request = ControllerMessage::InstallPublication {
        supervisor_generation: SupervisorGeneration(7),
        binding: binding(),
        transaction_id: 9,
    };
    let bytes = encode_publication_request(request, 0xC1_0801).unwrap();
    {
        let parsed = wyrmroot_device_proto::controller_v1_1::parse(&bytes).unwrap();
        assert_eq!(parsed.controller, request);
        assert_eq!(parsed.service_generation, 0xC1_0801);
        assert_ne!(parsed.service_generation, binding().generation.0);
        assert!(parse_controller(&bytes).is_err());
    }
}

#[test]
fn failed_rebind_send_closes_only_the_unmoved_devmgr_endpoint() {
    let mut platform = RebindPlatform::with_status(waiting_device_status());
    platform.fail_send_at = 2;
    let error = perform_rebind(
        &mut platform,
        &mut StatusWaits {
            fail: false,
            exit: None,
        },
        &mut RegistryTopology::new(2).unwrap(),
        &mut PublicationAllocator::new(),
        DwHandle(40),
        devmgr(),
        9,
        StatusCode::OperationalWaitingForDeviceBundle,
        None,
    )
    .unwrap_err();
    assert_eq!(error, InitError::Native(FAILURE));
    assert_eq!(&platform.closed[..platform.close_count], &[DwHandle(51)]);
}

#[test]
fn failed_rebind_status_is_reported_after_both_moves_commit() {
    let mut platform = RebindPlatform::with_status(waiting_device_status());
    let error = perform_rebind(
        &mut platform,
        &mut StatusWaits {
            fail: true,
            exit: None,
        },
        &mut RegistryTopology::new(2).unwrap(),
        &mut PublicationAllocator::new(),
        DwHandle(40),
        devmgr(),
        9,
        StatusCode::OperationalWaitingForDeviceBundle,
        None,
    )
    .unwrap_err();
    assert_eq!(error, InitError::Native(FAILURE));
    assert_eq!(platform.send_count, 2);
    assert_eq!(platform.close_count, 0);
}

#[test]
fn publication_peer_close_status_requires_exact_generation_and_transaction() {
    let message = ControllerMessage::Status {
        supervisor_generation: SupervisorGeneration(7),
        binding: None,
        transaction_id: 8,
        status: StatusCode::OperationalWaitingForRegistry,
        attempt_generation: None,
    };
    let mut platform = RebindPlatform::with_status(message);
    receive_waiting_for_registry(&mut platform, devmgr(), 7, 8).unwrap();

    let mut stale = RebindPlatform::with_status(message);
    assert_eq!(
        receive_waiting_for_registry(&mut stale, devmgr(), 7, 9),
        Err(InitError::WrongManifestProfile)
    );
}

#[test]
fn resident_poll_distinguishes_devmgr_and_registry_failures() {
    let event = |index, observed| {
        classify_resident_poll(
            DwWaitResultV1 {
                index,
                observed,
                ..DwWaitResultV1::default()
            },
            true,
            false,
        )
        .unwrap()
    };
    assert_eq!(event(0, DW_SIGNAL_EXITED), ResidentPollEvent::DevmgrExited);
    assert_eq!(
        event(1, DW_SIGNAL_PEER_CLOSED),
        ResidentPollEvent::DevmgrControlLost
    );
    assert_eq!(
        event(1, DW_SIGNAL_READABLE),
        ResidentPollEvent::DevmgrControlReadable
    );
    assert_eq!(
        event(2, DW_SIGNAL_PEER_CLOSED),
        ResidentPollEvent::RegistryControlLost
    );
    assert_eq!(
        event(3, DW_SIGNAL_EXITED),
        ResidentPollEvent::RegistryExited
    );
}

#[test]
fn registry_exhaustion_enters_degraded_without_a_stale_status_wait() {
    assert_eq!(
        registry_recovery_step(true, false),
        RegistryRecoveryStep::Degraded
    );
    assert_eq!(
        registry_recovery_step(false, false),
        RegistryRecoveryStep::AwaitStatus
    );
    assert_eq!(
        registry_recovery_step(false, true),
        RegistryRecoveryStep::Restart
    );
}

#[test]
fn publication_correlations_advance_across_devmgr_and_registry_recovery() {
    let mut allocator = PublicationAllocator::new();
    let initial = allocator.issue().unwrap();
    let after_devmgr_exit = allocator.issue().unwrap();
    let after_registry_exit = allocator.issue().unwrap();

    assert!(after_devmgr_exit.publication_id > initial.publication_id);
    assert!(after_devmgr_exit.service_generation > initial.service_generation);
    assert!(after_devmgr_exit.transaction_id > initial.transaction_id);
    assert!(after_registry_exit.publication_id > after_devmgr_exit.publication_id);
    assert!(after_registry_exit.service_generation > after_devmgr_exit.service_generation);
    assert!(after_registry_exit.transaction_id > after_devmgr_exit.transaction_id);
    assert_ne!(initial.publication_id, initial.service_generation);
    assert_ne!(initial.publication_id, initial.transaction_id);
    assert_ne!(initial.service_generation, initial.transaction_id);
}

fn wrdm(identity: [u8; 32]) -> [u8; WRDM_HEADER_BYTES + WRDM_RECORD_BYTES] {
    let mut out = [0; WRDM_HEADER_BYTES + WRDM_RECORD_BYTES];
    out[..4].copy_from_slice(&WRDM_MAGIC);
    out[4..6].copy_from_slice(&WRDM_MAJOR.to_le_bytes());
    out[6..8].copy_from_slice(&WRDM_MINOR.to_le_bytes());
    let total = out.len() as u32;
    out[8..12].copy_from_slice(&total.to_le_bytes());
    out[12..14].copy_from_slice(&1u16.to_le_bytes());
    out[16..20].copy_from_slice(&PROFILE_Q35.0.to_le_bytes());
    out[20..24].copy_from_slice(&PROFILE_Q35_VERSION.0.to_le_bytes());
    let base = WRDM_HEADER_BYTES;
    out[base..base + 8].copy_from_slice(&1u64.to_le_bytes());
    out[base + 8..base + 12].copy_from_slice(&2u32.to_le_bytes());
    out[base + 12..base + 16].copy_from_slice(&1u32.to_le_bytes());
    out[base + 16..base + 18].copy_from_slice(&0x2f8u16.to_le_bytes());
    out[base + 18..base + 20].copy_from_slice(&8u16.to_le_bytes());
    out[base + 20..base + 24].copy_from_slice(&3u32.to_le_bytes());
    out[base + 24..base + 26].copy_from_slice(&(UART16550D_PATH.len() as u16).to_le_bytes());
    out[base + 28..base + 60].copy_from_slice(&identity);
    out[base + 60..base + 64].copy_from_slice(&1u32.to_le_bytes());
    out[base + 72..base + 72 + UART16550D_PATH.len()].copy_from_slice(UART16550D_PATH);
    out
}

#[test]
fn wrdm_uart_identity_must_match_the_independent_wrrm_identity() {
    let bytes = wrdm([7; 32]);
    let manifest = DeviceManifest::parse(&bytes).unwrap();
    validate_device_identity(manifest, [7; 32]).unwrap();
    assert_eq!(
        validate_device_identity(manifest, [8; 32]),
        Err(InitError::WrongManifestProfile)
    );
}

struct ControlInputPlatform {
    inbound: [u8; LAUNCH_REQUEST_BYTES],
    inbound_len: usize,
    received: DwReceivedHandleInfoV1,
    received_count: usize,
    queried: CapabilityInfo<DwObjectType, DwRights>,
    closed: Option<DwHandle>,
}

impl InitPlatform for ControlInputPlatform {
    fn query_capability_info(
        &mut self,
        _handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
        Ok(self.queried)
    }
    fn receive_channel(
        &mut self,
        _channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        bytes[..self.inbound_len].copy_from_slice(&self.inbound[..self.inbound_len]);
        if self.received_count == 1 {
            handles[0] = self.received;
        }
        Ok(ReceiveCounts {
            bytes: self.inbound_len,
            handles: self.received_count,
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
        self.closed = Some(handle);
        Ok(())
    }
    fn create_attempt_task_group(&mut self, _parent: DwHandle) -> Result<DwHandle, NativeError> {
        Err(FAILURE)
    }
    fn terminate_task_group(&mut self, _task_group: DwHandle) -> Result<(), NativeError> {
        Err(FAILURE)
    }
    fn now(&mut self) -> Result<u64, NativeError> {
        Err(FAILURE)
    }
    fn wait_until(&mut self, _deadline_ns: u64) -> Result<(), NativeError> {
        Err(FAILURE)
    }
}

fn driver_request() -> DriverLaunchRequest {
    DriverLaunchRequest {
        supervisor_generation: SupervisorGeneration(7),
        role_id: COM2_ROLE_ID,
        attempt_generation: wyrmroot_device_proto::coordinator::AttemptGeneration(1),
        launch_session: wyrmroot_device_proto::coordinator::LaunchSessionGeneration(2),
        endpoint: wyrmroot_device_proto::ControlEndpoint {
            id: wyrmroot_device_proto::coordinator::EndpointId(3),
            generation: wyrmroot_device_proto::coordinator::EndpointGeneration(1),
        },
        transaction_id: 9,
        driver_path: wyrmroot_device_proto::DEVICE_DRIVER_PATH,
        actor_identity: ContentIdentity([0x5a; 32]),
        child_is_channel: true,
        child_rights: wyrmroot_device_proto::DirectControlRights::ExactReduced,
    }
}

fn control_input_platform(request: DriverLaunchRequest) -> ControlInputPlatform {
    let mut inbound = [0u8; LAUNCH_REQUEST_BYTES];
    wyrmroot_device_proto::encode_request(request, &mut inbound).unwrap();
    ControlInputPlatform {
        inbound,
        inbound_len: LAUNCH_REQUEST_BYTES,
        received: DwReceivedHandleInfoV1 {
            handle: DwHandle(91),
            object_type: DW_OBJECT_TYPE_CHANNEL,
            rights: DRIVER_CONTROL_INGRESS_RIGHTS,
            reserved0: 0,
            reserved: [0; 2],
        },
        received_count: 1,
        queried: CapabilityInfo {
            object_type: DW_OBJECT_TYPE_CHANNEL,
            rights: DRIVER_CONTROL_INGRESS_RIGHTS,
        },
        closed: None,
    }
}

#[test]
fn native_driver_request_dispatch_moves_exactly_one_reduced_channel() {
    let request = driver_request();
    let mut platform = control_input_platform(request);
    assert_eq!(
        receive_devmgr_control(&mut platform, DwHandle(12)).unwrap(),
        DevmgrControlInput::DriverLaunch {
            request,
            child_endpoint: DwHandle(91),
        }
    );
    assert_eq!(platform.closed, None);
}

#[test]
fn native_driver_request_requires_transfer_staging_before_actor_reduction() {
    assert_eq!(DRIVER_CONTROL_INGRESS_RIGHTS.0, 0x193);
    assert_eq!(CHILD_CHANNEL_RIGHTS.0, 0x113);
    assert_ne!(
        DRIVER_CONTROL_INGRESS_RIGHTS.0 & deepwyrm_syscall::DW_RIGHT_TRANSFER.0,
        0
    );

    let mut final_actor_rights_are_not_staging = control_input_platform(driver_request());
    final_actor_rights_are_not_staging.received.rights = CHILD_CHANNEL_RIGHTS;
    final_actor_rights_are_not_staging.queried.rights = CHILD_CHANNEL_RIGHTS;
    assert_eq!(
        receive_devmgr_control(&mut final_actor_rights_are_not_staging, DwHandle(12)),
        Err(InitError::ResourceIdentityMismatch)
    );
    assert_eq!(
        final_actor_rights_are_not_staging.closed,
        Some(DwHandle(91))
    );
}

#[test]
fn native_driver_request_rejects_wrong_received_type_or_rights() {
    let mut wrong_rights = control_input_platform(driver_request());
    wrong_rights.received.rights = DEVICE_MANIFEST_RIGHTS;
    assert_eq!(
        receive_devmgr_control(&mut wrong_rights, DwHandle(12)),
        Err(InitError::ResourceIdentityMismatch)
    );
    assert_eq!(wrong_rights.closed, Some(DwHandle(91)));

    let mut wrong_type = control_input_platform(driver_request());
    wrong_type.received.object_type = deepwyrm_syscall::DW_OBJECT_TYPE_MEMORY_OBJECT;
    assert_eq!(
        receive_devmgr_control(&mut wrong_type, DwHandle(12)),
        Err(InitError::ResourceIdentityMismatch)
    );
    assert_eq!(wrong_type.closed, Some(DwHandle(91)));
}

#[test]
fn native_driver_correlation_rejects_replay_and_supervisor_replacement() {
    let request = driver_request();
    assert!(driver_correlation_is_fresh(7, 0, 0, 0, 0, request));
    assert!(!driver_correlation_is_fresh(8, 0, 0, 0, 0, request));
    assert!(!driver_correlation_is_fresh(7, 1, 0, 0, 0, request));
    assert!(!driver_correlation_is_fresh(7, 0, 2, 0, 0, request));
    assert!(!driver_correlation_is_fresh(7, 0, 0, 3, 0, request));
    assert!(!driver_correlation_is_fresh(7, 0, 0, 0, 9, request));

    let mut stale_endpoint_generation = request;
    stale_endpoint_generation.endpoint.generation =
        wyrmroot_device_proto::coordinator::EndpointGeneration(2);
    assert!(!driver_correlation_is_fresh(
        7,
        0,
        0,
        0,
        0,
        stale_endpoint_generation,
    ));
}

#[test]
fn native_replacement_accepts_first_fresh_namespace_and_rejects_old_endpoint() {
    let mut old = driver_request();
    let old_namespace = 7 * (1u64 << 32);
    old.attempt_generation.0 = old_namespace + 1;
    old.launch_session.0 = old_namespace + (1u64 << 30) + 1;
    old.endpoint.id.0 = old_namespace + (2u64 << 30) + 1;
    old.transaction_id = old_namespace + (3u64 << 30) + 1;

    let mut fresh = driver_request();
    let fresh_namespace = 8 * (1u64 << 32);
    fresh.supervisor_generation = SupervisorGeneration(8);
    fresh.attempt_generation.0 = fresh_namespace + 1;
    fresh.launch_session.0 = fresh_namespace + (1u64 << 30) + 1;
    fresh.endpoint.id.0 = fresh_namespace + (2u64 << 30) + 1;
    fresh.transaction_id = fresh_namespace + (3u64 << 30) + 1;

    assert!(driver_correlation_is_fresh(
        8,
        old.attempt_generation.0,
        old.launch_session.0,
        old.endpoint.id.0,
        old.transaction_id,
        fresh,
    ));
    assert!(!driver_correlation_is_fresh(
        8,
        old.attempt_generation.0,
        old.launch_session.0,
        old.endpoint.id.0,
        old.transaction_id,
        old,
    ));
}

#[test]
fn resident_poll_observes_driver_exit_separately_from_registry_exit() {
    assert_eq!(
        classify_resident_poll(
            DwWaitResultV1 {
                index: 4,
                observed: DW_SIGNAL_EXITED,
                ..DwWaitResultV1::default()
            },
            true,
            true,
        ),
        Ok(ResidentPollEvent::DriverExited)
    );
    assert_eq!(
        classify_resident_poll(
            DwWaitResultV1 {
                index: 2,
                observed: DW_SIGNAL_EXITED,
                ..DwWaitResultV1::default()
            },
            false,
            true,
        ),
        Ok(ResidentPollEvent::DriverExited)
    );
}

/// The session teardown retires each role once. `active[0]` and
/// `active[1]` mirror the registry's and devmgr's handles; run 6 of
/// F3A.7j retired both twice, once from the resident state and again from
/// the early-role table, on handles already closed.
mod session_shutdown {
    use super::*;

    #[test]
    fn a_shutdown_retires_each_mirrored_role_once() {
        const GENERATION: u64 = 2;
        let (mut resident, devmgr, _) = recovery_fixture_resident(
            [0x5A; 32],
            GENERATION,
            ConsoleState::new(GENERATION).unwrap(),
            RegistryTopology::new(GENERATION).unwrap(),
            None,
        )
        .unwrap();
        let registry = resident.active[0].unwrap();
        assert_eq!(resident.active[1], Some(devmgr));
        let mut system =
            RebindPlatform::with_reply([0; wyrmroot_device_proto::controller::STATUS_BYTES]);
        system.accept_terminate = true;
        let mut waits = StatusWaits {
            fail: false,
            exit: Some(DwTaskTerminationInfoV1 {
                size: deepwyrm_syscall::DW_TASK_TERMINATION_INFO_V1_SIZE,
                version: 1,
                state: DW_TASK_STATE_EXITED,
                reason: DW_TERMINATION_NORMAL_EXIT,
                ..DwTaskTerminationInfoV1::default()
            }),
        };

        assert_eq!(
            retire_for_session_shutdown(&mut resident, &mut system, &mut waits),
            Ok(())
        );
        let terminated = &system.terminated[..system.terminate_count];
        for task_group in [registry.task_group, devmgr.task_group] {
            assert_eq!(
                terminated
                    .iter()
                    .filter(|handle| **handle == task_group)
                    .count(),
                1,
                "{task_group:?} must be retired exactly once: {terminated:?}"
            );
        }
        let closed = &system.closed[..system.close_count];
        for handle in [registry.loaded.process, devmgr.loaded.process] {
            assert_eq!(
                closed.iter().filter(|closed| **closed == handle).count(),
                1,
                "{handle:?} must be closed exactly once: {closed:?}"
            );
        }
        assert_eq!(resident.active, [None, None]);
        let state = resident.product.as_ref().unwrap();
        assert!(state.devmgr.is_none() && state.registry.is_none());
    }
}
