//! Driver lifecycle: failure, retirement, staged launch and publication.

use super::*;

pub(crate) fn service_production_driver_control<P: DevmgrPlatform>(
    platform: &mut P,
    driver_control: DwHandle,
    broker: &mut ConnectorBroker,
) -> Result<(), u32> {
    let mut bytes = [0u8; D3_DEVICE_STAGE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(driver_control, &mut bytes, &mut handles)
        .map_err(|_| failure(272))?;
    if counts.bytes > bytes.len() || counts.handles != 0 {
        close_received(platform, &handles, counts.handles);
        return Err(failure(273));
    }
    let message = parse_control_v1_1(&bytes[..counts.bytes]).map_err(|_| failure(274))?;
    broker.driver_detached(message).map_err(|_| failure(275))
}

pub(crate) fn observe_driver_failure<P: DevmgrPlatform>(
    platform: &mut P,
    control: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
    resident: &mut crate::ResidentController,
    readable: bool,
    peer_closed: bool,
    intentional_retirement: bool,
) -> Result<(), u32> {
    if !readable {
        return record_driver_terminal(resident, request, intentional_retirement);
    }
    let mut bytes = [0u8; wyrmroot_device_proto::control::FAILURE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(control, &mut bytes, &mut handles)
        .map_err(|_| failure(100))?;
    if counts.bytes != bytes.len() || counts.handles != 0 {
        close_received(platform, &handles, counts.handles);
        if peer_closed && counts.bytes == 0 && counts.handles == 0 {
            return record_driver_terminal(resident, request, intentional_retirement);
        }
        return Err(failure(101));
    }
    let message = wyrmroot_device_proto::control::parse(&bytes).map_err(|_| failure(102))?;
    let expected_code = FailureCode::DriverExited;
    let expected = ControlMessage::Failure {
        role_id: request.role_id,
        bundle_generation: resident.bundle_generation().ok_or(failure(103))?,
        attempt_generation: request.attempt_generation,
        endpoint: request.endpoint,
        transaction_id: request.transaction_id,
        code: expected_code,
    };
    if message != expected {
        return Err(failure(104));
    }
    record_driver_terminal(resident, request, intentional_retirement)
}

pub(crate) fn record_driver_terminal(
    resident: &mut crate::ResidentController,
    request: wyrmroot_device_proto::DriverLaunchRequest,
    intentional_retirement: bool,
) -> Result<(), u32> {
    if intentional_retirement {
        return resident
            .accept_intentional_driver_terminal(request)
            .map_err(|_| failure(105));
    }
    resident
        .driver_failed(request.endpoint)
        .map_err(|_| failure(105))
}

pub(crate) fn retire_driver_publication<P: DevmgrPlatform>(
    platform: &mut P,
    publication: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
    resident: &crate::ResidentController,
) -> Result<(), u32> {
    let binding = resident.active_binding().ok_or(failure(106))?;
    let retire_transaction = resident
        .publication_retire_transaction(request)
        .map_err(|_| failure(152))?;
    let header = RegistryHeader {
        message_type: RegistryMessageType::Retire,
        registry_generation: binding.generation.0,
        endpoint_id: binding.endpoint.id.0,
        endpoint_generation: binding.endpoint.generation.0,
        transaction_id: retire_transaction,
    };
    let mut bytes = [0u8; REGISTRY_HEADER_BYTES];
    let size = encode_registry_empty(header, &mut bytes).map_err(|_| failure(107))?;
    platform
        .send_channel(publication, &bytes[..size], &[])
        .map_err(|_| failure(108))?;
    let deadline = platform
        .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| failure(109))?;
    wait_readable(platform, publication, deadline, 110)?;
    let mut response = [0u8; REGISTRY_HEADER_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(publication, &mut response, &mut handles)
        .map_err(|_| failure(111))?;
    if counts.bytes != response.len() || counts.handles != 0 {
        close_received(platform, &handles, counts.handles);
        return Err(failure(112));
    }
    let parsed = parse_registry(&response, 0).map_err(|_| failure(113))?;
    if parsed.header
        != (RegistryHeader {
            message_type: RegistryMessageType::Retired,
            ..header
        })
        || parsed.message != RegistryMessage::Retired
    {
        return Err(failure(114));
    }
    Ok(())
}

pub(crate) fn await_driver_reaped<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
) -> Result<(), u32> {
    let deadline = platform
        .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.cleanup_timeout_ns)
        .map_err(|_| failure(115))?;
    wait_readable(platform, bootstrap, deadline, 116)?;
    let mut bytes = [0u8; REAPED_RESPONSE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(bootstrap, &mut bytes, &mut handles)
        .map_err(|_| failure(117))?;
    if counts.bytes != bytes.len() || counts.handles != 0 {
        close_received(platform, &handles, counts.handles);
        return Err(failure(118));
    }
    parse_reaped(&bytes, request).map_err(|_| failure(119))
}

pub(crate) fn send_driver_retired<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
) -> Result<(), u32> {
    let mut bytes = [0u8; wyrmroot_device_proto::driver_launch::DRIVER_RETIRED_BYTES];
    encode_driver_retired(request, &mut bytes).map_err(|_| failure(120))?;
    send_bootstrap_channel(platform, bootstrap, &bytes, &[], 121)
}

pub(crate) fn launch_driver_with_bundle<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    publication: DwHandle,
    parent_resource: DwHandle,
    resident: &mut crate::ResidentController,
) -> Result<DwHandle, u32> {
    launch_driver_staged(platform, bootstrap, publication, parent_resource, resident)
}

/// One handle the staged launch owns until it moves or returns it.
pub(crate) struct OwnedHandle(DwHandle);

impl OwnedHandle {
    pub(crate) const fn raw(&self) -> DwHandle {
        self.0
    }

    pub(crate) fn moved(&mut self) {
        self.0 = DW_HANDLE_INVALID;
    }

    pub(crate) fn take_raw(&mut self) -> DwHandle {
        let raw = self.0;
        self.moved();
        raw
    }

    pub(crate) fn hold(&mut self, raw: DwHandle) -> &mut Self {
        self.0 = raw;
        self
    }
}

/// The handles one staged launch owns, in creation order.
///
/// These were `Drop` guards local to `launch_driver_staged`, closed at every
/// return in reverse declaration order. A guard cannot reach the caller's
/// platform from `Drop`, so the slots live here instead: each starts
/// invalid, is filled where its guard used to be created, and
/// [`StagedLaunchHandles::close_live`] closes the live ones in the same
/// reverse order when the launch returns. An unfilled or moved slot is
/// skipped, exactly as a guard not yet created or already moved was.
pub(crate) struct StagedLaunchHandles {
    pub(crate) retained: OwnedHandle,
    pub(crate) child: OwnedHandle,
    pub(crate) reduced: OwnedHandle,
    pub(crate) interrupt: OwnedHandle,
}

impl StagedLaunchHandles {
    pub(crate) const fn new() -> Self {
        Self {
            retained: OwnedHandle(DW_HANDLE_INVALID),
            child: OwnedHandle(DW_HANDLE_INVALID),
            reduced: OwnedHandle(DW_HANDLE_INVALID),
            interrupt: OwnedHandle(DW_HANDLE_INVALID),
        }
    }

    pub(crate) fn close_live<P: DevmgrPlatform>(&mut self, platform: &mut P) {
        for slot in [
            &mut self.interrupt,
            &mut self.reduced,
            &mut self.child,
            &mut self.retained,
        ] {
            if slot.0 != DW_HANDLE_INVALID {
                let _ = platform.close_handle(slot.0);
            }
        }
    }
}

pub(crate) fn launch_driver_staged<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    publication: DwHandle,
    parent_resource: DwHandle,
    resident: &mut crate::ResidentController,
) -> Result<DwHandle, u32> {
    let mut owned = StagedLaunchHandles::new();
    let result = launch_driver_staged_owned(
        platform,
        &mut owned,
        bootstrap,
        publication,
        parent_resource,
        resident,
    );
    owned.close_live(platform);
    result
}

pub(crate) fn launch_driver_staged_owned<P: DevmgrPlatform>(
    platform: &mut P,
    owned: &mut StagedLaunchHandles,
    bootstrap: DwHandle,
    publication: DwHandle,
    parent_resource: DwHandle,
    resident: &mut crate::ResidentController,
) -> Result<DwHandle, u32> {
    let (retained_raw, child_raw) = platform
        .create_channel(DIRECT_CONTROL_RIGHTS)
        .map_err(|_| failure(57))?;
    let retained = owned.retained.hold(retained_raw);
    let child = owned.child.hold(child_raw);
    if validate_fresh(
        platform,
        retained.raw(),
        DW_OBJECT_TYPE_CHANNEL,
        DIRECT_CONTROL_RIGHTS,
    )
    .is_err()
        || validate_fresh(
            platform,
            child.raw(),
            DW_OBJECT_TYPE_CHANNEL,
            DIRECT_CONTROL_RIGHTS,
        )
        .is_err()
    {
        return Err(failure(58));
    }
    let request = resident
        .issue_driver_launch_with_bundle(true, DirectControlRights::ExactReduced)
        .map_err(|_| failure(59))?;
    let mut launch = [0u8; LAUNCH_REQUEST_BYTES];
    encode_request(request, &mut launch).map_err(|_| failure(60))?;
    let child_transfer = DwHandleTransferV1 {
        handle: child.raw(),
        requested_rights: CHILD_CHANNEL_TRANSFER_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if send_bootstrap_channel(
        platform,
        bootstrap,
        &launch,
        core::slice::from_ref(&child_transfer),
        61,
    )
    .is_err()
    {
        return Err(failure(61));
    }
    child.moved();
    let deadline = platform
        .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| failure(62))?;
    wait_readable(platform, bootstrap, deadline, 63)?;
    let mut constructed = [0u8; LAUNCH_RESPONSE_BYTES];
    let mut constructed_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(bootstrap, &mut constructed, &mut constructed_handles)
        .map_err(|_| failure(64))?;
    if counts.bytes != constructed.len() || counts.handles != 0 {
        close_received(platform, &constructed_handles, counts.handles);
        return Err(failure(65));
    }
    if parse_constructed(&constructed, request).is_err() || resident.driver_constructed().is_err() {
        return Err(failure(66));
    }

    let correlations = resident
        .reserve_d3_stage_correlations(request)
        .map_err(|_| failure(68))?;
    let ready_identity = ControlIdentityV1_1 {
        role_id: request.role_id,
        bundle_generation: resident.bundle_generation().ok_or(failure(67))?,
        attempt_generation: request.attempt_generation,
        endpoint: request.endpoint,
        transaction_id: correlations.ready_transaction_id,
    };
    let mut staging =
        DeviceStageCoordinator::new(ready_identity, correlations).map_err(|_| failure(68))?;

    let reduced = owned.reduced.hold(
        platform
            .duplicate_handle(parent_resource, DEVICE_RESOURCE_TRANSFER_RIGHTS)
            .map_err(|_| failure(69))?,
    );
    if validate_fresh(
        platform,
        reduced.raw(),
        DW_OBJECT_TYPE_DEVICE_RESOURCE,
        DEVICE_RESOURCE_TRANSFER_RIGHTS,
    )
    .is_err()
    {
        return Err(failure(70));
    }
    let resource = platform
        .device_resource_info(reduced.raw())
        .map_err(|_| failure(71))?;
    if resource.resource_id != crate::COM2_RESOURCE_ID
        || resource.lease_generation != ready_identity.bundle_generation.0
        || resource.pio_base != 0x2f8
        || resource.pio_length != 8
        || resource.interrupt_source != 3
        || resource.flags != 0
        || resource.reserved != 0
    {
        return Err(failure(72));
    }
    let device_message = staging.device_stage_message().map_err(|_| failure(73))?;
    let mut device_bytes = [0; D3_DEVICE_STAGE_BYTES];
    encode_control_v1_1(device_message, &mut device_bytes).map_err(|_| failure(73))?;
    let transfer = DwHandleTransferV1 {
        handle: reduced.raw(),
        requested_rights: DEVICE_RESOURCE_DRIVER_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if platform
        .send_channel(
            retained.raw(),
            &device_bytes,
            core::slice::from_ref(&transfer),
        )
        .is_err()
    {
        return Err(failure(74));
    }
    reduced.moved();
    staging.device_stage_moved().map_err(|_| failure(75))?;
    wait_readable(platform, retained.raw(), deadline, 76)?;
    let mut quiesced_bytes = [0; D3_DEVICE_QUIESCED_BYTES];
    let mut response_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(retained.raw(), &mut quiesced_bytes, &mut response_handles)
        .map_err(|_| failure(77))?;
    if counts.bytes != quiesced_bytes.len() || counts.handles != 0 {
        close_received(platform, &response_handles, counts.handles);
        return Err(failure(78));
    }
    let quiesced = parse_control_v1_1(&quiesced_bytes).map_err(|_| failure(79))?;
    staging
        .accept_device_quiesced(quiesced)
        .map_err(|_| failure(80))?;

    // Creating the route-committing Interrupt is deliberately after the exact
    // DEVICE_QUIESCED reply above.
    let interrupt = owned.interrupt.hold(
        platform
            .create_interrupt(parent_resource, INTERRUPT_CUSTODY_RIGHTS)
            .map_err(|_| failure(81))?,
    );
    if validate_fresh(
        platform,
        interrupt.raw(),
        DW_OBJECT_TYPE_INTERRUPT,
        INTERRUPT_CUSTODY_RIGHTS,
    )
    .is_err()
    {
        return Err(failure(82));
    }
    let interrupt_facts = platform
        .interrupt_info(interrupt.raw())
        .map_err(|_| failure(83))?;
    if interrupt_facts.size != DW_INTERRUPT_INFO_V1_SIZE
        || interrupt_facts.version != DW_INTERRUPT_INFO_V1_VERSION
        || interrupt_facts.source != resource.interrupt_source
        || interrupt_facts.state != DW_INTERRUPT_STATE_ARMED
        || interrupt_facts.object_generation == 0
        || interrupt_facts.binding_generation == 0
        || interrupt_facts.parent_resource_id != resource.resource_id
        || interrupt_facts.parent_lease_generation != resource.lease_generation
        || interrupt_facts.flags.0 != 0
        || interrupt_facts.reserved0 != 0
        || interrupt_facts.reserved != 0
    {
        return Err(failure(84));
    }
    resident
        .set_driver_bindings(
            resource.lease_generation,
            interrupt_facts.binding_generation,
        )
        .map_err(|_| failure(85))?;
    staging.interrupt_created().map_err(|_| failure(86))?;
    let interrupt_message = staging.interrupt_stage_message().map_err(|_| failure(87))?;
    let mut interrupt_bytes = [0; D3_INTERRUPT_STAGE_BYTES];
    encode_control_v1_1(interrupt_message, &mut interrupt_bytes).map_err(|_| failure(87))?;
    let transfer = DwHandleTransferV1 {
        handle: interrupt.raw(),
        requested_rights: INTERRUPT_DRIVER_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if platform
        .send_channel(
            retained.raw(),
            &interrupt_bytes,
            core::slice::from_ref(&transfer),
        )
        .is_err()
    {
        return Err(failure(88));
    }
    interrupt.moved();
    staging.interrupt_stage_moved().map_err(|_| failure(89))?;
    resident.bundle_transferred().map_err(|_| failure(90))?;
    wait_readable(platform, retained.raw(), deadline, 91)?;
    let mut ready_bytes = [0; D3_READY_BYTES];
    let mut ready_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(retained.raw(), &mut ready_bytes, &mut ready_handles)
        .map_err(|_| failure(92))?;
    if counts.bytes != ready_bytes.len() || counts.handles != 0 {
        close_received(platform, &ready_handles, counts.handles);
        return Err(failure(93));
    }
    let ready = parse_control_v1_1(&ready_bytes).map_err(|_| failure(94))?;
    staging
        .accept_driver_ready(ready)
        .map_err(|_| failure(95))?;
    resident
        .accept_driver_ready_for_transaction(
            ControlMessage::Ready {
                role_id: request.role_id,
                bundle_generation: ready_identity.bundle_generation,
                attempt_generation: request.attempt_generation,
                endpoint: request.endpoint,
                transaction_id: correlations.ready_transaction_id,
            },
            correlations.ready_transaction_id,
        )
        .map_err(|_| failure(96))?;
    publish_driver(platform, publication, request, resident)?;
    Ok(retained.take_raw())
}

pub(crate) fn publish_driver<P: DevmgrPlatform>(
    platform: &mut P,
    publication: DwHandle,
    request: wyrmroot_device_proto::DriverLaunchRequest,
    resident: &mut crate::ResidentController,
) -> Result<(), u32> {
    let binding = resident.active_binding().ok_or(failure(82))?;
    let header = RegistryHeader {
        message_type: RegistryMessageType::Publish,
        registry_generation: binding.generation.0,
        endpoint_id: binding.endpoint.id.0,
        endpoint_generation: binding.endpoint.generation.0,
        transaction_id: request.transaction_id,
    };
    let mut bytes = [0u8; REGISTRY_HEADER_BYTES];
    let size = encode_registry_empty(header, &mut bytes).map_err(|_| failure(83))?;
    platform
        .send_channel(publication, &bytes[..size], &[])
        .map_err(|_| failure(84))?;
    let deadline = platform
        .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| failure(85))?;
    wait_readable(platform, publication, deadline, 86)?;
    let mut response = [0u8; REGISTRY_HEADER_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(publication, &mut response, &mut handles)
        .map_err(|_| failure(87))?;
    if counts.bytes != response.len() || counts.handles != 0 {
        close_received(platform, &handles, counts.handles);
        return Err(failure(88));
    }
    let parsed = parse_registry(&response, 0).map_err(|_| failure(89))?;
    if parsed.header
        != (RegistryHeader {
            message_type: RegistryMessageType::Published,
            ..header
        })
        || parsed.message != RegistryMessage::Published
    {
        return Err(failure(90));
    }
    resident.publication_committed().map_err(|_| failure(91))
}

pub(crate) fn send_driver_retire<P: DevmgrPlatform>(
    platform: &mut P,
    control: DwHandle,
    resident: &mut crate::ResidentController,
) -> Result<(), u32> {
    let message = resident.retire_message().map_err(|_| failure(93))?;
    let mut bytes = [0u8; wyrmroot_device_proto::control::RETIRE_BYTES];
    encode_control(message, &mut bytes).map_err(|_| failure(94))?;
    platform
        .send_channel(control, &bytes, &[])
        .map_err(|_| failure(95))
}
