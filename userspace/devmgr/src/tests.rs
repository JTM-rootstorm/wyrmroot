use super::*;
use wyrmroot_device_proto::manifest::{
    HEADER_BYTES, MAGIC, MAJOR, MINOR, PROFILE_Q35, PROFILE_Q35_VERSION, RECORD_BYTES,
    UART16550D_PATH,
};

fn manifest() -> [u8; HEADER_BYTES + RECORD_BYTES] {
    let mut bytes = [0; HEADER_BYTES + RECORD_BYTES];
    bytes[..4].copy_from_slice(&MAGIC);
    bytes[4..6].copy_from_slice(&MAJOR.to_le_bytes());
    bytes[6..8].copy_from_slice(&MINOR.to_le_bytes());
    let total = bytes.len() as u32;
    bytes[8..12].copy_from_slice(&total.to_le_bytes());
    bytes[12..14].copy_from_slice(&1u16.to_le_bytes());
    bytes[16..20].copy_from_slice(&PROFILE_Q35.0.to_le_bytes());
    bytes[20..24].copy_from_slice(&PROFILE_Q35_VERSION.0.to_le_bytes());
    let record = HEADER_BYTES;
    bytes[record..record + 8].copy_from_slice(&1u64.to_le_bytes());
    bytes[record + 8..record + 12].copy_from_slice(&2u32.to_le_bytes());
    bytes[record + 12..record + 16].copy_from_slice(&1u32.to_le_bytes());
    bytes[record + 16..record + 18].copy_from_slice(&0x2f8u16.to_le_bytes());
    bytes[record + 18..record + 20].copy_from_slice(&8u16.to_le_bytes());
    bytes[record + 20..record + 24].copy_from_slice(&3u32.to_le_bytes());
    bytes[record + 24..record + 26].copy_from_slice(&(UART16550D_PATH.len() as u16).to_le_bytes());
    bytes[record + 28..record + 60].copy_from_slice(&[0x5a; 32]);
    bytes[record + 60..record + 64].copy_from_slice(&1u32.to_le_bytes());
    bytes[record + 72..record + 72 + UART16550D_PATH.len()].copy_from_slice(UART16550D_PATH);
    bytes
}

#[test]
fn exact_manifest_becomes_operational_but_not_device_bound() {
    let status = prepare_operational(&manifest(), 7).unwrap();
    assert_eq!(status.supervisor_generation, SupervisorGeneration(7));
    assert_eq!(status.state, CoordinatorState::WaitingForRegistry);
    assert_eq!(
        status.pio,
        PioRange {
            base: 0x2f8,
            length: 8
        }
    );
    assert_eq!(status.irq, 3);
    assert!(!status.is_device_bound());
}

#[test]
fn page_padded_manifest_becomes_operational_only_when_padding_is_zero() {
    let exact = manifest();
    let mut page = [0u8; 4096];
    page[..exact.len()].copy_from_slice(&exact);
    assert_eq!(
        prepare_operational(&page, 7).unwrap().state,
        CoordinatorState::WaitingForRegistry
    );
    page[exact.len()] = 1;
    assert_eq!(
        prepare_operational(&page, 7),
        Err(DevmgrError::Manifest(ManifestError::NonzeroObjectPadding))
    );
}

#[test]
fn malformed_or_com1_manifest_never_becomes_operational() {
    let mut bytes = manifest();
    bytes[0] = b'X';
    assert_eq!(
        prepare_operational(&bytes, 1),
        Err(DevmgrError::Manifest(ManifestError::WrongMagic))
    );
    bytes = manifest();
    bytes[HEADER_BYTES + 8..HEADER_BYTES + 12].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        prepare_operational(&bytes, 1),
        Err(DevmgrError::Coordinator(CoordinatorError::Manifest(
            ManifestError::Com1Rejected
        )))
    );
}

#[test]
fn zero_supervisor_generation_is_rejected() {
    assert_eq!(
        prepare_operational(&manifest(), 0),
        Err(DevmgrError::Coordinator(
            CoordinatorError::InvalidSupervisorGeneration
        ))
    );
}

fn binding(generation: u64, endpoint: u64) -> RegistryBinding {
    RegistryBinding {
        generation: wyrmroot_device_proto::coordinator::RegistryGeneration(generation),
        endpoint: wyrmroot_device_proto::coordinator::RegistryEndpoint {
            id: wyrmroot_device_proto::coordinator::RegistryEndpointId(endpoint),
            generation: wyrmroot_device_proto::coordinator::RegistryEndpointGeneration(1),
        },
    }
}

fn install(binding: RegistryBinding, transaction_id: u64) -> ControllerMessage {
    install_for(7, binding, transaction_id)
}

fn install_for(
    supervisor_generation: u64,
    binding: RegistryBinding,
    transaction_id: u64,
) -> ControllerMessage {
    ControllerMessage::InstallPublication {
        supervisor_generation: SupervisorGeneration(supervisor_generation),
        binding,
        transaction_id,
    }
}

fn rebind(binding: RegistryBinding, transaction_id: u64) -> ControllerMessage {
    ControllerMessage::RebindPublication {
        supervisor_generation: SupervisorGeneration(7),
        binding,
        transaction_id,
    }
}

fn exact_resource(lease_generation: u64) -> DwDeviceResourceInfoV1 {
    DwDeviceResourceInfoV1 {
        size: DW_DEVICE_RESOURCE_INFO_V1_SIZE,
        version: DW_DEVICE_RESOURCE_INFO_V1_VERSION,
        kind: DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
        flags: 0,
        resource_id: COM2_RESOURCE_ID,
        lease_generation,
        pio_base: 0x2f8,
        pio_length: 8,
        interrupt_source: 3,
        reserved: 0,
    }
}

#[test]
fn publication_install_keeps_service_namespace_and_rebind_high_water() {
    use wyrmroot_device_proto::controller_v1_1::{self, PublicationMessage};
    let mut resident =
        ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
    let first = PublicationMessage {
        controller: install(binding(1, 7), 41),
        service_generation: 0xC1_0801,
    };
    let mut wire = [0; controller_v1_1::RECORD_BYTES];
    controller_v1_1::encode(first, &mut wire).unwrap();
    resident
        .accept_publication(controller_v1_1::parse(&wire).unwrap(), 0)
        .unwrap();
    assert_eq!(resident.active_binding().unwrap().generation.0, 1);
    assert_eq!(resident.publication_service_generation(), Some(0xC1_0801));
    resident.publication_peer_closed().unwrap();
    assert_eq!(resident.publication_service_generation(), None);
    let unchanged = resident;
    let second = PublicationMessage {
        controller: rebind(binding(1, 8), 42),
        service_generation: 0xC1_0802,
    };
    for generation in [0, 1, 0xC1_0800, 0xC1_0801] {
        assert!(
            resident
                .accept_publication(
                    PublicationMessage {
                        service_generation: generation,
                        ..second
                    },
                    1
                )
                .is_err()
        );
        assert_eq!(resident, unchanged);
    }
    assert!(resident.accept(second.controller, 1).is_err());
    assert!(resident.accept_publication(second, 0).is_err());
    assert_eq!(resident, unchanged);
    resident.accept_publication(second, 1).unwrap();
    assert_eq!(resident.active_binding().unwrap().generation.0, 1);
    assert_eq!(resident.publication_service_generation(), Some(0xC1_0802));
    let installed = resident;
    assert!(resident.accept_publication(second, 1).is_err());
    assert_eq!(resident, installed);
}

#[test]
fn controller_correlates_zero_handle_install_to_startup_then_reports_waiting() {
    let mut resident =
        ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
    let installed = binding(1, 7);
    assert_eq!(
        resident.accept(install(installed, 41), 0),
        Ok(ControllerAction::InitialPublicationBound)
    );
    assert_eq!(
        resident.status().state,
        CoordinatorState::WaitingForDeviceBundle
    );
    assert_eq!(
        resident.report(StatusCode::OperationalWaitingForDeviceBundle),
        Ok(ControllerMessage::Status {
            supervisor_generation: SupervisorGeneration(7),
            binding: Some(installed),
            transaction_id: 41,
            status: StatusCode::OperationalWaitingForDeviceBundle,
            attempt_generation: None,
        })
    );
}

#[test]
fn c4_admits_exact_claimed_resource_and_uses_kernel_lease_generation() {
    let mut resident =
        ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
    let installed = binding(1, 7);
    resident.accept(install(installed, 41), 0).unwrap();
    assert_eq!(
        resident.admit_device_resource(exact_resource(19)),
        Ok(BundleGeneration(19))
    );
    assert_eq!(resident.bundle_generation(), Some(BundleGeneration(19)));
    assert_eq!(resident.status().state, CoordinatorState::Matched);
    assert!(resident.status().is_device_bound());
    assert_eq!(
        resident.report(StatusCode::OperationalResourceOwned),
        Ok(ControllerMessage::Status {
            supervisor_generation: SupervisorGeneration(7),
            binding: Some(installed),
            transaction_id: 41,
            status: StatusCode::OperationalResourceOwned,
            attempt_generation: None,
        })
    );
    assert_eq!(
        resident.admit_device_resource(exact_resource(20)),
        Err(DevmgrError::ResourceIdentity)
    );
}

#[test]
fn c4_registry_rebind_preserves_the_owned_resource_without_a_second_claim() {
    let mut resident =
        ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
    let first = binding(1, 7);
    resident.accept(install(first, 41), 0).unwrap();
    resident.admit_device_resource(exact_resource(19)).unwrap();
    resident.publication_peer_closed().unwrap();

    let second = binding(1, 8);
    assert_eq!(
        resident.accept(rebind(second, 42), 1),
        Ok(ControllerAction::PublicationRebound)
    );
    assert_eq!(resident.bundle_generation(), Some(BundleGeneration(19)));
    assert_eq!(resident.status().state, CoordinatorState::Matched);
    assert_eq!(
        resident.report(StatusCode::OperationalResourceOwned),
        Ok(ControllerMessage::Status {
            supervisor_generation: SupervisorGeneration(7),
            binding: Some(second),
            transaction_id: 42,
            status: StatusCode::OperationalResourceOwned,
            attempt_generation: None,
        })
    );
    assert_eq!(
        resident.admit_device_resource(exact_resource(20)),
        Err(DevmgrError::ResourceIdentity)
    );
}

#[test]
fn publication_acknowledgement_preserves_pre_resource_and_retained_custody_statuses() {
    use wyrmroot_device_proto::controller::parse;
    let mut resident =
        ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
    let invalid = Err(PublicationAcknowledgementError::Lifecycle(
        DevmgrError::ControllerPrecondition,
    ));
    assert_eq!(resident.publication_acknowledgement(), invalid);
    resident.accept(install(binding(1, 7), 41), 0).unwrap();
    assert_eq!(
        parse(&resident.publication_acknowledgement().unwrap()).unwrap(),
        resident
            .report(StatusCode::OperationalWaitingForDeviceBundle)
            .unwrap()
    );
    resident.admit_device_resource(exact_resource(19)).unwrap();
    assert_eq!(
        parse(&resident.publication_acknowledgement().unwrap()).unwrap(),
        resident
            .report(StatusCode::OperationalResourceOwned)
            .unwrap()
    );
    let request = resident
        .issue_driver_launch_with_bundle(true, DirectControlRights::ExactReduced)
        .unwrap();
    resident.driver_constructed().unwrap();
    resident.resource_bundle_message().unwrap();
    resident.bundle_transferred().unwrap();
    assert_eq!(resident.publication_acknowledgement(), invalid);
    resident
        .accept_driver_ready(wyrmroot_device_proto::ControlMessage::Ready {
            role_id: request.role_id,
            bundle_generation: BundleGeneration(19),
            attempt_generation: request.attempt_generation,
            endpoint: request.endpoint,
            transaction_id: request.transaction_id,
        })
        .unwrap();
    resident.publication_committed().unwrap();
    assert_eq!(resident.publication_acknowledgement(), invalid);
    resident.publication_peer_closed().unwrap();
    assert_eq!(resident.publication_acknowledgement(), invalid);
    resident.accept(rebind(binding(1, 8), 42), 1).unwrap();
    assert_eq!(
        parse(&resident.publication_acknowledgement().unwrap()).unwrap(),
        resident
            .report(StatusCode::OperationalResourceOwned)
            .unwrap()
    );
    assert_eq!(resident.active_driver_request(), Some(request));
    assert!(resident.driver_ready());
    resident.publication_committed().unwrap();
    resident.retire_message().unwrap();
    assert_eq!(resident.publication_acknowledgement(), invalid);
    resident
        .accept_intentional_driver_terminal(request)
        .unwrap();
    assert_eq!(resident.publication_acknowledgement(), invalid);
    resident.publication_retired().unwrap();
    resident.reap_driver().unwrap();
    assert_eq!(resident.publication_acknowledgement(), invalid);
    resident.accept(rebind(binding(1, 9), 43), 1).unwrap();
    assert_eq!(
        parse(&resident.publication_acknowledgement().unwrap()).unwrap(),
        resident
            .report(StatusCode::OperationalWaitingForDeviceBundle)
            .unwrap()
    );
    assert_eq!(resident.bundle_generation(), Some(BundleGeneration(19)));
    assert_eq!(resident.active_driver_request(), None);
}

#[test]
fn c4_rejects_every_mismatched_resource_identity_field() {
    let mut cases = [exact_resource(7); 10];
    cases[0].size = 47;
    cases[1].version = 2;
    cases[2].kind = deepwyrm_syscall::DwDeviceResourceKind(2);
    cases[3].flags = 1;
    cases[4].resource_id = 2;
    cases[5].lease_generation = 0;
    cases[6].pio_base = 0x3f8;
    cases[7].pio_length = 7;
    cases[8].interrupt_source = 4;
    cases[9].reserved = 1;
    for resource in cases {
        let mut resident =
            ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
        resident.accept(install(binding(1, 7), 41), 0).unwrap();
        assert_eq!(
            resident.admit_device_resource(resource),
            Err(DevmgrError::ResourceIdentity)
        );
        assert_eq!(resident.bundle_generation(), None);
        assert_eq!(
            resident.status().state,
            CoordinatorState::WaitingForDeviceBundle
        );
    }
}

#[test]
fn c4_cannot_claim_before_the_exact_registry_binding() {
    let mut resident =
        ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
    assert_eq!(
        resident.admit_device_resource(exact_resource(1)),
        Err(DevmgrError::ResourceIdentity)
    );
}

#[test]
fn c5_requires_claim_then_constructed_bundle_before_generation_ready_and_publish() {
    let mut resident =
        ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
    resident.accept(install(binding(1, 7), 41), 0).unwrap();
    assert_eq!(
        resident.issue_driver_launch_with_bundle(true, DirectControlRights::ExactReduced),
        Err(DevmgrError::ControllerPrecondition)
    );
    resident.admit_device_resource(exact_resource(19)).unwrap();
    let request = resident
        .issue_driver_launch_with_bundle(true, DirectControlRights::ExactReduced)
        .unwrap();
    assert_eq!(
        resident.resource_bundle_message(),
        Err(DevmgrError::ControllerPrecondition)
    );
    resident.driver_constructed().unwrap();
    let bundle = resident.resource_bundle_message().unwrap();
    assert_eq!(
        bundle,
        wyrmroot_device_proto::ControlMessage::ResourceBundle {
            role_id: request.role_id,
            bundle_generation: BundleGeneration(19),
            attempt_generation: request.attempt_generation,
            endpoint: request.endpoint,
            transaction_id: request.transaction_id,
        }
    );
    assert_eq!(resident.status().state, CoordinatorState::Matched);
    resident.bundle_transferred().unwrap();
    assert_eq!(
        resident.status().state,
        CoordinatorState::AwaitingDriverReady
    );
    assert_eq!(
        resident.accept_driver_ready(wyrmroot_device_proto::ControlMessage::Ready {
            role_id: request.role_id,
            bundle_generation: BundleGeneration(20),
            attempt_generation: request.attempt_generation,
            endpoint: request.endpoint,
            transaction_id: request.transaction_id,
        }),
        Err(DevmgrError::ControllerPrecondition)
    );
    resident
        .accept_driver_ready(wyrmroot_device_proto::ControlMessage::Ready {
            role_id: request.role_id,
            bundle_generation: BundleGeneration(19),
            attempt_generation: request.attempt_generation,
            endpoint: request.endpoint,
            transaction_id: request.transaction_id,
        })
        .unwrap();
    assert_eq!(
        resident.status().state,
        CoordinatorState::AwaitingPublication
    );
    resident.publication_committed().unwrap();
    assert_eq!(resident.status().state, CoordinatorState::Published);
    assert_eq!(
        resident.publication_committed(),
        Err(DevmgrError::ControllerPrecondition)
    );
}

#[test]
fn c5_retire_is_generation_exact_and_cleanup_clears_driver_readiness() {
    let mut resident =
        ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
    resident.accept(install(binding(1, 7), 41), 0).unwrap();
    resident.admit_device_resource(exact_resource(19)).unwrap();
    let request = resident
        .issue_driver_launch_with_bundle(true, DirectControlRights::ExactReduced)
        .unwrap();
    resident.driver_constructed().unwrap();
    resident.resource_bundle_message().unwrap();
    resident.bundle_transferred().unwrap();
    resident
        .accept_driver_ready(wyrmroot_device_proto::ControlMessage::Ready {
            role_id: request.role_id,
            bundle_generation: BundleGeneration(19),
            attempt_generation: request.attempt_generation,
            endpoint: request.endpoint,
            transaction_id: request.transaction_id,
        })
        .unwrap();
    assert_eq!(
        resident.retire_message(),
        Ok(wyrmroot_device_proto::ControlMessage::Retire {
            role_id: request.role_id,
            bundle_generation: BundleGeneration(19),
            attempt_generation: request.attempt_generation,
            endpoint: request.endpoint,
            transaction_id: request.transaction_id,
        })
    );
    assert_eq!(resident.status().state, CoordinatorState::CleaningUp);
    resident.reap_driver().unwrap();
    assert!(!resident.driver_ready());
    assert_eq!(
        resident.retire_message(),
        Err(DevmgrError::ControllerPrecondition)
    );
}

#[test]
fn e8_intentional_driver_terminal_is_exact_once_after_retire() {
    let mut resident =
        ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
    resident.accept(install(binding(1, 7), 41), 0).unwrap();
    resident.admit_device_resource(exact_resource(19)).unwrap();
    let request = resident
        .issue_driver_launch_with_bundle(true, DirectControlRights::ExactReduced)
        .unwrap();
    resident.driver_constructed().unwrap();
    resident.resource_bundle_message().unwrap();
    resident.bundle_transferred().unwrap();
    resident
        .accept_driver_ready(wyrmroot_device_proto::ControlMessage::Ready {
            role_id: request.role_id,
            bundle_generation: BundleGeneration(19),
            attempt_generation: request.attempt_generation,
            endpoint: request.endpoint,
            transaction_id: request.transaction_id,
        })
        .unwrap();
    resident.publication_committed().unwrap();

    let published = resident;
    assert_eq!(
        resident.accept_intentional_driver_terminal(request),
        Err(DevmgrError::ControllerPrecondition)
    );
    assert_eq!(resident, published);

    resident.retire_message().unwrap();
    assert_eq!(resident.status().state, CoordinatorState::CleaningUp);
    let retiring = resident;
    let mut stale = request;
    stale.endpoint.id = EndpointId(request.endpoint.id.0 + 1);
    assert_eq!(
        resident.accept_intentional_driver_terminal(stale),
        Err(DevmgrError::ControllerPrecondition)
    );
    assert_eq!(resident, retiring);

    resident
        .accept_intentional_driver_terminal(request)
        .unwrap();
    assert_eq!(resident.status().state, CoordinatorState::CleaningUp);
    assert!(!resident.driver_ready());
    assert_eq!(resident.active_driver_request(), Some(request));
    let accepted = resident;
    assert_eq!(
        resident.accept_intentional_driver_terminal(request),
        Err(DevmgrError::ControllerPrecondition)
    );
    assert_eq!(resident, accepted);
}

/// The twenty-seven lookups and counters this crate folded into one
/// `ControllerLifecycle` value had no test between them, which is part of
/// why the collapse survived. This covers one of them end to end so the
/// named fault is read rather than merely declared.
#[test]
fn an_exhausted_retry_deadline_names_itself_and_not_the_whole_lifecycle() {
    let mut resident =
        ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
    resident.accept(install(binding(1, 7), 41), 0).unwrap();
    resident.admit_device_resource(exact_resource(19)).unwrap();
    let request = resident
        .issue_driver_launch_with_bundle(true, DirectControlRights::ExactReduced)
        .unwrap();
    resident.driver_constructed().unwrap();
    resident.resource_bundle_message().unwrap();
    resident.bundle_transferred().unwrap();
    resident
        .accept_driver_ready(wyrmroot_device_proto::ControlMessage::Ready {
            role_id: request.role_id,
            bundle_generation: BundleGeneration(19),
            attempt_generation: request.attempt_generation,
            endpoint: request.endpoint,
            transaction_id: request.transaction_id,
        })
        .unwrap();
    resident.publication_committed().unwrap();
    resident.driver_failed(request.endpoint).unwrap();
    resident.publication_retire_transaction(request).unwrap();
    resident.publication_retired().unwrap();
    resident.reap_driver().unwrap();
    assert_eq!(resident.status().state, CoordinatorState::CleaningUp);

    // A backoff deadline that cannot be computed used to arrive as the same
    // value as an absent active driver.
    assert_eq!(
        resident.complete_driver_failure_cleanup(u64::MAX),
        Err(DevmgrError::ControllerLifecycle(
            ControllerLifecycleFault::Exhausted(ControllerCounter::RetryDeadline)
        )),
        "the exhausted counter must name itself"
    );
    // And it is not the precondition failure, which is the other half of
    // what the single variant used to mean.
    assert_ne!(
        resident.complete_driver_failure_cleanup(u64::MAX),
        Err(DevmgrError::ControllerPrecondition)
    );
}

#[test]
fn c6_failure_rebind_preserves_cleanup_gate_before_retry() {
    let mut resident =
        ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
    resident.accept(install(binding(1, 7), 41), 0).unwrap();
    resident.admit_device_resource(exact_resource(19)).unwrap();
    let request = resident
        .issue_driver_launch_with_bundle(true, DirectControlRights::ExactReduced)
        .unwrap();
    resident.driver_constructed().unwrap();
    resident.resource_bundle_message().unwrap();
    resident.bundle_transferred().unwrap();
    resident
        .accept_driver_ready(wyrmroot_device_proto::ControlMessage::Ready {
            role_id: request.role_id,
            bundle_generation: BundleGeneration(19),
            attempt_generation: request.attempt_generation,
            endpoint: request.endpoint,
            transaction_id: request.transaction_id,
        })
        .unwrap();
    resident.publication_committed().unwrap();
    resident.driver_failed(request.endpoint).unwrap();
    let retire_transaction = resident.publication_retire_transaction(request).unwrap();
    assert_eq!(retire_transaction, request.transaction_id + 1);
    assert_ne!(retire_transaction, request.transaction_id);
    resident.publication_retired().unwrap();
    resident.reap_driver().unwrap();
    assert_eq!(
        resident.accept(rebind(binding(1, 8), 42), 1),
        Ok(ControllerAction::PublicationRebound)
    );
    assert_eq!(
        resident.report(StatusCode::OperationalWaitingForDeviceBundle),
        Ok(ControllerMessage::Status {
            supervisor_generation: SupervisorGeneration(7),
            binding: Some(binding(1, 8)),
            transaction_id: 42,
            status: StatusCode::OperationalWaitingForDeviceBundle,
            attempt_generation: None,
        })
    );
    assert_eq!(resident.status().state, CoordinatorState::CleaningUp);
    resident.complete_driver_failure_cleanup(0).unwrap();
    assert_eq!(
        resident.status().state,
        CoordinatorState::Backoff {
            attempt: AttemptGeneration(request.attempt_generation.0 + 1),
            until_ns: wyrmroot_device_proto::coordinator::RETRY_BACKOFF_NS,
        }
    );
    resident
        .driver_retry_ready(wyrmroot_device_proto::coordinator::RETRY_BACKOFF_NS)
        .unwrap();
    let next = resident
        .issue_driver_launch_with_bundle(true, DirectControlRights::ExactReduced)
        .unwrap();
    assert!(next.attempt_generation.0 > request.attempt_generation.0);
}

#[test]
fn d3_stage_reservation_advances_transaction_high_water_across_replacement() {
    let mut resident =
        ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
    resident.accept(install(binding(1, 7), 41), 0).unwrap();
    resident.admit_device_resource(exact_resource(19)).unwrap();
    let request = resident
        .issue_driver_launch_with_bundle(true, DirectControlRights::ExactReduced)
        .unwrap();
    let correlations = resident.reserve_d3_stage_correlations(request).unwrap();
    assert!(correlations.stage_generation.0 != 0);
    assert!(correlations.device_transaction_id > request.transaction_id);
    assert!(correlations.interrupt_transaction_id > correlations.device_transaction_id);
    assert!(correlations.ready_transaction_id > correlations.interrupt_transaction_id);

    resident.driver_constructed().unwrap();
    resident.resource_bundle_message().unwrap();
    resident.bundle_transferred().unwrap();
    resident
        .accept_driver_ready_for_transaction(
            wyrmroot_device_proto::ControlMessage::Ready {
                role_id: request.role_id,
                bundle_generation: BundleGeneration(19),
                attempt_generation: request.attempt_generation,
                endpoint: request.endpoint,
                transaction_id: correlations.ready_transaction_id,
            },
            correlations.ready_transaction_id,
        )
        .unwrap();
    resident.publication_committed().unwrap();
    resident.driver_failed(request.endpoint).unwrap();
    resident.publication_retired().unwrap();
    resident.reap_driver().unwrap();
    resident.accept(rebind(binding(1, 8), 42), 1).unwrap();
    resident.complete_driver_failure_cleanup(0).unwrap();
    resident
        .driver_retry_ready(wyrmroot_device_proto::coordinator::RETRY_BACKOFF_NS)
        .unwrap();
    let replacement = resident
        .issue_driver_launch_with_bundle(true, DirectControlRights::ExactReduced)
        .unwrap();
    assert!(replacement.transaction_id > correlations.ready_transaction_id);
}

#[test]
fn controller_rejects_wrong_install_correlation_or_handle_count() {
    let mut resident =
        ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
    assert_eq!(
        resident.accept(install(binding(1, 7), 40), 0),
        Err(DevmgrError::StartupCorrelation)
    );
    assert_eq!(
        resident.accept(install(binding(1, 7), 41), 1),
        Err(DevmgrError::Controller(
            ControllerParseError::WrongHandleCount
        ))
    );
}

#[test]
fn peer_close_keeps_generation_and_requires_monotonic_one_handle_rebind() {
    let mut resident =
        ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
    let first = binding(1, 7);
    resident.accept(install(first, 41), 0).unwrap();
    resident.publication_peer_closed().unwrap();
    assert_eq!(
        resident.status().supervisor_generation,
        SupervisorGeneration(7)
    );
    assert_eq!(
        resident.status().state,
        CoordinatorState::WaitingForRegistry
    );
    assert_eq!(resident.active_binding(), None);
    assert_eq!(
        resident.report(StatusCode::OperationalWaitingForRegistry),
        Ok(ControllerMessage::Status {
            supervisor_generation: SupervisorGeneration(7),
            binding: None,
            transaction_id: 41,
            status: StatusCode::OperationalWaitingForRegistry,
            attempt_generation: None,
        })
    );
    assert_eq!(
        resident.accept(rebind(first, 42), 1),
        Err(DevmgrError::Controller(ControllerParseError::StaleBinding))
    );
    let second = binding(1, 8);
    assert_eq!(
        resident.accept(rebind(second, 42), 1),
        Ok(ControllerAction::PublicationRebound)
    );
    assert_eq!(resident.active_binding(), Some(second));
    assert_eq!(
        resident.status().supervisor_generation,
        SupervisorGeneration(7)
    );
}

#[test]
fn status_and_replay_messages_cannot_drive_the_resident() {
    let mut resident =
        ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
    let first = binding(1, 7);
    resident.accept(install(first, 41), 0).unwrap();
    assert_eq!(
        resident.accept(rebind(binding(2, 8), 41), 1),
        Err(DevmgrError::StaleControllerTransaction)
    );
    assert_eq!(
        resident.accept(
            ControllerMessage::Status {
                supervisor_generation: SupervisorGeneration(7),
                binding: Some(first),
                transaction_id: 42,
                status: StatusCode::OperationalWaitingForDeviceBundle,
                attempt_generation: None,
            },
            0,
        ),
        Err(DevmgrError::ControllerPrecondition)
    );
}

#[test]
fn c3_launch_is_fresh_direct_and_ready_is_correlation_exact() {
    let mut resident =
        ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
    resident.accept(install(binding(1, 7), 41), 0).unwrap();
    let request = resident
        .issue_driver_launch(true, DirectControlRights::ExactReduced)
        .unwrap();
    assert_eq!(request.supervisor_generation, SupervisorGeneration(7));
    assert_eq!(request.role_id, RoleId(1));
    assert_eq!(
        request.attempt_generation.0,
        7 * DRIVER_CORRELATION_STRIDE + DRIVER_ATTEMPT_OFFSET
    );
    assert_ne!(request.attempt_generation.0, request.launch_session.0);
    assert_ne!(request.attempt_generation.0, request.endpoint.id.0);
    assert_ne!(request.attempt_generation.0, request.transaction_id);
    assert_ne!(request.launch_session.0, request.endpoint.id.0);
    assert_ne!(request.launch_session.0, request.transaction_id);
    assert_ne!(request.endpoint.id.0, request.transaction_id);
    resident.driver_constructed().unwrap();
    assert_eq!(
        resident.accept_driver_control_ready(wyrmroot_device_proto::ControlMessage::ControlReady {
            role_id: request.role_id,
            attempt_generation: request.attempt_generation,
            endpoint: request.endpoint,
            transaction_id: request.transaction_id,
        }),
        Ok(())
    );
    assert!(
        resident
            .issue_driver_launch(true, DirectControlRights::ExactReduced)
            .is_err()
    );
    resident.reap_driver().unwrap();
    let replacement = resident
        .issue_driver_launch(true, DirectControlRights::ExactReduced)
        .unwrap();
    assert!(replacement.attempt_generation.0 > request.attempt_generation.0);
    assert_ne!(replacement.endpoint, request.endpoint);
}

#[test]
fn selector29_u1_is_the_first_supervisor_namespaced_attempt() {
    let mut resident =
        ResidentController::new(prepare_operational(&manifest(), 1).unwrap(), 41).unwrap();
    resident
        .accept(install_for(1, binding(1, 1), 41), 0)
        .unwrap();
    let request = resident
        .issue_driver_launch(true, DirectControlRights::ExactReduced)
        .unwrap();
    assert_eq!(
        request.attempt_generation.0,
        wyrmroot_device_proto::SELECTOR29_FAILURE_ATTEMPT_GENERATION
    );
    assert!(wyrmroot_device_proto::selector29_should_fail(
        request.supervisor_generation,
        request.attempt_generation
    ));
}

#[test]
fn replacement_devmgr_uses_a_supervisor_owned_monotonic_driver_namespace() {
    let mut first =
        ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
    first.accept(install_for(7, binding(1, 7), 41), 0).unwrap();
    let old = first
        .issue_driver_launch(true, DirectControlRights::ExactReduced)
        .unwrap();

    let mut replacement =
        ResidentController::new(prepare_operational(&manifest(), 8).unwrap(), 42).unwrap();
    replacement
        .accept(install_for(8, binding(2, 8), 42), 0)
        .unwrap();
    let fresh = replacement
        .issue_driver_launch(true, DirectControlRights::ExactReduced)
        .unwrap();
    assert!(fresh.attempt_generation.0 > old.attempt_generation.0);
    assert!(fresh.launch_session.0 > old.launch_session.0);
    assert!(fresh.endpoint.id.0 > old.endpoint.id.0);
    assert!(fresh.transaction_id > old.transaction_id);
    assert_ne!(fresh.attempt_generation.0, fresh.launch_session.0);
    assert_ne!(fresh.attempt_generation.0, fresh.endpoint.id.0);
    assert_ne!(fresh.attempt_generation.0, fresh.transaction_id);
    assert_ne!(fresh.launch_session.0, fresh.endpoint.id.0);
    assert_ne!(fresh.launch_session.0, fresh.transaction_id);
    assert_ne!(fresh.endpoint.id.0, fresh.transaction_id);
    replacement.driver_constructed().unwrap();
    assert_eq!(
        replacement.accept_driver_control_ready(
            wyrmroot_device_proto::ControlMessage::ControlReady {
                role_id: old.role_id,
                attempt_generation: old.attempt_generation,
                endpoint: old.endpoint,
                transaction_id: old.transaction_id,
            }
        ),
        Err(DevmgrError::DriverLaunch(DriverLaunchError::StaleEndpoint))
    );
    assert_eq!(
        replacement.accept_driver_control_ready(
            wyrmroot_device_proto::ControlMessage::ControlReady {
                role_id: fresh.role_id,
                attempt_generation: fresh.attempt_generation,
                endpoint: fresh.endpoint,
                transaction_id: fresh.transaction_id,
            }
        ),
        Ok(())
    );
}

#[test]
fn c3_rejects_wrong_child_rights_and_stale_ready() {
    let mut resident =
        ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
    resident.accept(install(binding(1, 7), 41), 0).unwrap();
    assert_eq!(
        resident.issue_driver_launch(true, DirectControlRights::Other),
        Err(DevmgrError::DriverLaunch(DriverLaunchError::WrongRights))
    );
    let request = resident
        .issue_driver_launch(true, DirectControlRights::ExactReduced)
        .unwrap();
    resident.driver_constructed().unwrap();
    assert_eq!(
        resident.accept_driver_control_ready(wyrmroot_device_proto::ControlMessage::ControlReady {
            role_id: request.role_id,
            attempt_generation: request.attempt_generation,
            endpoint: ControlEndpoint {
                id: request.endpoint.id,
                generation: EndpointGeneration(9)
            },
            transaction_id: request.transaction_id,
        }),
        Err(DevmgrError::DriverLaunch(DriverLaunchError::StaleEndpoint))
    );
}

/// A resident whose driver is launched, ready and published, as the role
/// holds it when the driver's readiness has just been committed.
fn published_ready_driver() -> (
    ResidentController,
    wyrmroot_device_proto::DriverLaunchRequest,
) {
    let mut resident =
        ResidentController::new(prepare_operational(&manifest(), 7).unwrap(), 41).unwrap();
    resident
        .accept_publication(
            wyrmroot_device_proto::controller_v1_1::PublicationMessage {
                controller: install(binding(1, 7), 41),
                service_generation: 0xC1_0801,
            },
            0,
        )
        .unwrap();
    resident.admit_device_resource(exact_resource(19)).unwrap();
    let request = resident
        .issue_driver_launch_with_bundle(true, DirectControlRights::ExactReduced)
        .unwrap();
    resident.driver_constructed().unwrap();
    resident.resource_bundle_message().unwrap();
    resident.bundle_transferred().unwrap();
    resident
        .accept_driver_ready(wyrmroot_device_proto::ControlMessage::Ready {
            role_id: request.role_id,
            bundle_generation: BundleGeneration(19),
            attempt_generation: request.attempt_generation,
            endpoint: request.endpoint,
            transaction_id: request.transaction_id,
        })
        .unwrap();
    resident.publication_committed().unwrap();
    (resident, request)
}

/// The Retire that withdraws a failed driver's publication carries the
/// resident's fresh endpoint-local transaction, launch transaction + 1,
/// never the launch transaction the publication was made under: the
/// registry's replay protection would refuse a reused one.
#[test]
fn c6_retirement_uses_a_fresh_endpoint_local_registry_transaction() {
    use deepwyrm_syscall::{DW_STATUS_BAD_STATE, DwHandle};
    use wyrmroot_runtime::NativeError;
    use wyrmroot_runtime::platform::recording::{Call, RecordingPlatform, Reply};

    let (mut resident, request) = published_ready_driver();
    resident.driver_failed(request.endpoint).unwrap();
    let publication = DwHandle(0x51);
    // The send succeeds; the reply deadline then fails, which stops the
    // exchange right after the one message under test.
    let mut platform = RecordingPlatform::scripted([
        Reply::Unit(Ok(())),
        Reply::Deadline(Err(NativeError::Status(DW_STATUS_BAD_STATE))),
    ]);
    assert!(
        crate::role::retire_driver_publication(&mut platform, publication, request, &resident)
            .is_err()
    );
    let [
        Call::SendChannel {
            channel,
            bytes,
            transfers,
        },
        Call::MonotonicDeadlineAfter { .. },
    ] = platform.calls()
    else {
        panic!("unexpected calls {:?}", platform.calls());
    };
    assert_eq!(*channel, publication);
    assert!(transfers.is_empty());
    let retire = wyrmroot_registry_proto::parse(bytes, 0).unwrap().header;
    assert_eq!(
        retire.message_type,
        wyrmroot_registry_proto::MessageType::Retire
    );
    assert_eq!(retire.transaction_id, request.transaction_id + 1);
}

/// Activating the connector broker for the ready, published driver is a
/// model step with no platform: the first activation builds the broker
/// around that driver, a second for the same driver is refused, and an
/// empty broker with no current driver is re-pointed at it.
#[test]
fn connector_broker_activation_publishes_the_ready_driver_once() {
    use crate::connector::ConnectorBroker;
    use crate::role::activate_connector_broker;

    let (mut resident, request) = published_ready_driver();
    let mut broker = None;
    let current = activate_connector_broker(&mut resident, &mut broker).unwrap();
    assert_eq!(current.control.transaction_id, request.transaction_id);
    assert_eq!(current.control.endpoint, request.endpoint);
    assert_eq!(current.publication_generation, 0xC1_0801);
    assert_eq!(
        broker.as_ref().and_then(ConnectorBroker::current),
        Some(current)
    );

    let built = broker;
    assert_eq!(
        activate_connector_broker(&mut resident, &mut broker),
        Err(0xC101_0000 | 246),
        "a broker already serving the driver is not activated again"
    );
    assert_eq!(broker, built);

    let mut empty = Some(ConnectorBroker::new(None, 1, 1).unwrap());
    assert_eq!(
        activate_connector_broker(&mut resident, &mut empty),
        Ok(current)
    );
    assert_eq!(
        empty.as_ref().and_then(ConnectorBroker::current),
        Some(current)
    );
}
