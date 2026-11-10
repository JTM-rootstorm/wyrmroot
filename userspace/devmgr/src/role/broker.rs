//! The connector broker: offers, production client release and cleanup.

use super::*;

pub(crate) fn activate_connector_broker(
    resident: &mut crate::ResidentController,
    broker: &mut Option<ConnectorBroker>,
) -> Result<PublishedDriver, u32> {
    let request = resident.active_driver_request().ok_or(failure(245))?;
    let current = published_driver(resident, request)?;
    if let Some(broker) = broker.as_mut() {
        if !matches!(broker.slot(), ConnectorSlot::Empty) || broker.current().is_some() {
            return Err(failure(246));
        }
        broker
            .replace_published_driver(current)
            .map_err(|_| failure(247))?;
    } else {
        let (attach_transaction, stream_generation) = resident
            .reserve_d3_connector_correlations(request)
            .map_err(|_| failure(248))?;
        *broker = Some(
            ConnectorBroker::new(Some(current), attach_transaction, stream_generation)
                .map_err(|_| failure(249))?,
        );
    }
    Ok(current)
}

pub(crate) fn service_connector_offer<P: DevmgrPlatform>(
    platform: &mut P,
    publication: DwHandle,
    driver_control: DwHandle,
    resident: &crate::ResidentController,
    broker: &mut ConnectorBroker,
    witness: &mut Option<ProductionClientWitness>,
) -> Result<(), u32> {
    let mut offer_bytes = [0u8; 256];
    let mut offer_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(publication, &mut offer_bytes, &mut offer_handles)
        .map_err(|_| failure(174))?;
    if counts.bytes > offer_bytes.len() || counts.handles != 1 {
        close_received(platform, &offer_handles, counts.handles);
        return Err(failure(175));
    }
    let offered = offer_handles[0];
    if offered.handle.0 == 0
        || offered.object_type != DW_OBJECT_TYPE_CHANNEL
        || offered.rights != CHILD_CHANNEL_RIGHTS
        || offered.reserved0 != 0
        || offered.reserved != [0; 2]
        || validate_fresh(
            platform,
            offered.handle,
            DW_OBJECT_TYPE_CHANNEL,
            CHILD_CHANNEL_RIGHTS,
        )
        .is_err()
    {
        close_received(platform, &offer_handles, 1);
        return Err(failure(176));
    }
    let offer = match parse_registry(&offer_bytes[..counts.bytes], counts.handles) {
        Ok(offer) => offer,
        Err(_) => {
            close_received(platform, &offer_handles, 1);
            return Err(failure(177));
        }
    };
    let binding = resident.active_binding().ok_or(failure(178))?;
    let policy = ConnectorBroker::publication_policy();
    let RegistryMessage::ConnectOffer(lookup) = offer.message else {
        close_received(platform, &offer_handles, 1);
        return Err(failure(179));
    };
    if offer.header.message_type != RegistryMessageType::ConnectOffer
        || offer.header.registry_generation != binding.generation.0
        || offer.header.endpoint_id != binding.endpoint.id.0
        || offer.header.endpoint_generation != binding.endpoint.generation.0
        || offer.header.transaction_id == 0
        || lookup
            != (Lookup {
                protocol_id: policy.protocol_id,
                version: ProtocolVersion {
                    major: policy.protocol_major,
                    minor: policy.protocol_minor,
                },
                service_name: policy.service_name,
            })
    {
        close_received(platform, &offer_handles, 1);
        return Err(failure(180));
    }
    let direct = offer_handles[0].handle;
    let deadline = platform
        .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| failure(181))?;
    wait_readable(platform, direct, deadline, 182)?;
    let mut request_bytes = [0u8; CONNECTOR_BYTES];
    let mut request_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(direct, &mut request_bytes, &mut request_handles)
        .map_err(|_| failure(183))?;
    if counts.bytes != request_bytes.len() || counts.handles != 0 {
        close_received(platform, &request_handles, counts.handles);
        let _ = platform.close_handle(direct);
        return Err(failure(184));
    }
    let request = match parse_connector(&request_bytes) {
        Ok(request @ ConnectorMessage::ConnectStream { .. }) => request,
        _ => {
            let _ = platform.close_handle(direct);
            return Err(failure(185));
        }
    };
    let action = match broker.begin_connect(request) {
        Ok(action) => action,
        Err(error) => {
            let reply = error.reply(request).ok_or(failure(186))?;
            let mut bytes = [0u8; CONNECTOR_BYTES];
            let encoded = encode_connector(reply, &mut bytes);
            if encoded.is_ok() {
                // A rejected request owns no raw pair. A disconnected client
                // cannot turn a normal negative response into driver loss.
                let _ = platform.send_channel(direct, &bytes, &[]);
            }
            platform.close_handle(direct).map_err(|_| failure(186))?;
            encoded.map_err(|_| failure(186))?;
            return Ok(());
        }
    };
    let ConnectorAction::AllocatePair {
        attach,
        driver_message,
    } = action
    else {
        let _ = platform.close_handle(direct);
        return Err(failure(187));
    };
    if witness.is_some() {
        let _ = broker.attach_send_failed(attach);
        let _ = platform.close_handle(direct);
        return Err(failure(276));
    }
    let (client_endpoint, driver_endpoint) = platform
        .create_channel(STREAM_BROAD_RIGHTS)
        .map_err(|_| failure(188))?;
    let mut driver_bytes = [0u8; D3_DEVICE_STAGE_BYTES];
    let size = driver_message.wire_size();
    encode_control_v1_1(driver_message, &mut driver_bytes[..size]).map_err(|_| failure(189))?;
    let transfer = DwHandleTransferV1 {
        handle: driver_endpoint,
        requested_rights: CHILD_CHANNEL_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if platform
        .send_channel(driver_control, &driver_bytes[..size], &[transfer])
        .is_err()
    {
        let _ = broker.attach_send_failed(attach);
        let _ = platform.close_handle(driver_endpoint);
        let _ = platform.close_handle(client_endpoint);
        let _ = platform.close_handle(direct);
        return Err(failure(190));
    }
    broker
        .driver_endpoint_moved(attach)
        .map_err(|_| failure(191))?;
    wait_readable(platform, driver_control, deadline, 192)?;
    let mut ready_bytes = [0u8; D3_DEVICE_STAGE_BYTES];
    let mut ready_handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(driver_control, &mut ready_bytes, &mut ready_handles)
        .map_err(|_| failure(193))?;
    if counts.bytes > ready_bytes.len() || counts.handles != 0 {
        close_received(platform, &ready_handles, counts.handles);
        let _ = platform.close_handle(client_endpoint);
        let _ = platform.close_handle(direct);
        return Err(failure(194));
    }
    let ready = parse_control_v1_1(&ready_bytes[..counts.bytes]).map_err(|_| failure(195))?;
    broker
        .accept_stream_ready(ready)
        .map_err(|_| failure(196))?;
    let response = broker.connected_response().map_err(|_| failure(197))?;
    let mut response_bytes = [0u8; CONNECTOR_BYTES];
    encode_connector(response, &mut response_bytes).map_err(|_| failure(198))?;
    let transfer = DwHandleTransferV1 {
        handle: client_endpoint,
        requested_rights: CHILD_CHANNEL_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if platform
        .send_channel(direct, &response_bytes, &[transfer])
        .is_err()
    {
        let _ = broker.connected_send_failed();
        let _ = platform.close_handle(client_endpoint);
        let _ = platform.close_handle(direct);
        return Err(failure(199));
    }
    broker.client_endpoint_moved().map_err(|_| failure(200))?;
    {
        *witness = Some(ProductionClientWitness {
            handle: direct,
            attach,
        });
        Ok(())
    }
}

pub(crate) fn observe_production_client_release<P: DevmgrPlatform>(
    platform: &mut P,
    witness: &mut Option<ProductionClientWitness>,
    broker: &mut ConnectorBroker,
    signals: deepwyrm_syscall::DwSignals,
) -> Result<(), u32> {
    let observed = (*witness).ok_or(failure(279))?;
    let readable = signals.0 & DW_SIGNAL_READABLE.0 != 0;
    let peer_closed = signals.0 & DW_SIGNAL_PEER_CLOSED.0 != 0;
    if classify_direct_client_release(readable, peer_closed) == DirectClientReleaseEvent::Malformed
    {
        if !readable {
            return Err(failure(281));
        }
        let mut bytes = [0u8; 1];
        let mut handles = [DwReceivedHandleInfoV1::default(); 1];
        if let Ok(counts) = platform.receive_channel(observed.handle, &mut bytes, &mut handles) {
            close_received(platform, &handles, counts.handles);
        }
        return Err(failure(280));
    }
    match broker.slot() {
        ConnectorSlot::Active { attach, .. } if attach == observed.attach => broker
            .active_client_released(observed.attach)
            .map_err(|_| failure(282))?,
        ConnectorSlot::AwaitingClientRelease { attach, .. }
        | ConnectorSlot::RetiringActive { attach, .. }
            if attach == observed.attach =>
        {
            broker
                .client_release_observed(observed.attach)
                .map_err(|_| failure(283))?
        }
        _ => return Err(failure(284)),
    }
    platform
        .close_handle(observed.handle)
        .map_err(|_| failure(285))?;
    *witness = None;
    Ok(())
}

pub(crate) fn update_production_cleanup<P: DevmgrPlatform>(
    platform: &mut P,
    broker: &ConnectorBroker,
    deadline: &mut Option<u64>,
) -> Result<(), u32> {
    if matches!(broker.slot(), ConnectorSlot::Empty) {
        *deadline = None;
        return Ok(());
    }
    if matches!(
        broker.slot(),
        ConnectorSlot::AwaitingDriverRelease { .. }
            | ConnectorSlot::AwaitingClientRelease { .. }
            | ConnectorSlot::RetiringActive { .. }
    ) && deadline.is_none()
    {
        *deadline = Some(
            production_cleanup_deadline(platform.monotonic_active_now().map_err(|_| failure(286))?)
                .map_err(|_| failure(287))?,
        );
    }
    Ok(())
}

pub(crate) fn maybe_send_waiting_for_registry<P: DevmgrPlatform>(
    platform: &mut P,
    bootstrap: DwHandle,
    resident: &crate::ResidentController,
    publication: Option<DwHandle>,
    broker: &ConnectorBroker,
    sent: &mut bool,
) -> Result<(), u32> {
    if publication.is_none() && matches!(broker.slot(), ConnectorSlot::Empty) && !*sent {
        send_resident_status(
            platform,
            bootstrap,
            resident,
            StatusCode::OperationalWaitingForRegistry,
        )?;
        *sent = true;
    }
    Ok(())
}

pub(crate) fn await_production_witness_release<P: DevmgrPlatform>(
    platform: &mut P,
    witness: &mut Option<ProductionClientWitness>,
    broker: &mut ConnectorBroker,
    deadline: &mut Option<u64>,
) -> Result<(), u32> {
    let Some(observed) = *witness else {
        return if matches!(broker.slot(), ConnectorSlot::Empty) {
            *deadline = None;
            Ok(())
        } else {
            Err(failure(300))
        };
    };
    update_production_cleanup(platform, broker, deadline)?;
    let absolute = (*deadline).ok_or(failure(301))?;
    if !cleanup_deadline_live(
        platform.monotonic_active_now().map_err(|_| failure(302))?,
        absolute,
    ) {
        return Err(failure(303));
    }
    let result = platform
        .wait_many(
            core::slice::from_ref(&wait_item(observed.handle)),
            deepwyrm_syscall::DwDeadline(absolute),
        )
        .map_err(|_| failure(304))?;
    if result.index != 0
        || !cleanup_deadline_live(
            platform.monotonic_active_now().map_err(|_| failure(305))?,
            absolute,
        )
    {
        return Err(failure(306));
    }
    observe_production_client_release(platform, witness, broker, result.observed)?;
    update_production_cleanup(platform, broker, deadline)
}
