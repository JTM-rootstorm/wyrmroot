//! Serial attach, publication watches and connector lookup.

use super::*;

pub(crate) fn attach_serial<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
) -> Result<SerialSession, u32> {
    let publication_generation = watch_publication(platform, authorities, transactions)?;
    if publication_generation == 0 {
        return Err(13);
    }
    let direct = lookup_connector(platform, authorities, transactions)?;
    let connector_transaction = match transactions.take() {
        Ok(value) => value,
        Err(error) => {
            close_attempt_handles(platform, core::slice::from_ref(&direct))?;
            return Err(error);
        }
    };
    let request = ConnectorMessage::ConnectStream {
        publication_generation,
        client_transaction_id: connector_transaction,
    };
    let connect_request = ConnectRequest {
        registry_generation: authorities.registry_generation,
        registry_endpoint_id: authorities.registry_endpoint_id,
        registry_endpoint_generation: authorities.registry_endpoint_generation,
        requested_publication_generation: publication_generation,
        connector_client_transaction: connector_transaction,
    };
    if model.begin_connect(connect_request).is_err() {
        close_attempt_handles(platform, core::slice::from_ref(&direct))?;
        return Err(14);
    }
    let mut connector_bytes = [0u8; RECORD_BYTES];
    if encode_connector(request, &mut connector_bytes).is_err() {
        finish_connect_abort(
            platform,
            model,
            connect_request,
            core::slice::from_ref(&direct),
        )?;
        return Err(14);
    }
    if platform
        .send_channel(direct, &connector_bytes, &[])
        .is_err()
    {
        finish_connect_abort(
            platform,
            model,
            connect_request,
            core::slice::from_ref(&direct),
        )?;
        return Err(15);
    }
    if wait_readable(platform, direct).is_err() {
        finish_connect_abort(
            platform,
            model,
            connect_request,
            core::slice::from_ref(&direct),
        )?;
        return Err(16);
    }
    let mut received = [DwReceivedHandleInfoV1::default(); 1];
    let counts = match platform.receive_channel(direct, &mut connector_bytes, &mut received) {
        Ok(counts) => counts,
        Err(_) => {
            finish_connect_abort(
                platform,
                model,
                connect_request,
                core::slice::from_ref(&direct),
            )?;
            return Err(17);
        }
    };
    if counts.bytes != RECORD_BYTES
        || counts.handles != 1
        || !valid_received_channel(received[0], CHILD_CHANNEL_RIGHTS)
    {
        let handles = [direct, received[0].handle];
        finish_connect_abort(platform, model, connect_request, &handles)?;
        return Err(18);
    }
    let identity = match parse_connector(&connector_bytes) {
        Ok(ConnectorMessage::Connected { identity }) => identity,
        _ => {
            let handles = [direct, received[0].handle];
            finish_connect_abort(platform, model, connect_request, &handles)?;
            return Err(20);
        }
    };
    if !valid_connector_identity(identity, publication_generation, connector_transaction) {
        let handles = [direct, received[0].handle];
        finish_connect_abort(platform, model, connect_request, &handles)?;
        return Err(21);
    }
    if validate_exact_channel(platform, received[0].handle, CHILD_CHANNEL_RIGHTS).is_err() {
        let handles = [direct, received[0].handle];
        finish_connect_abort(platform, model, connect_request, &handles)?;
        return Err(22);
    }
    let attached_at = match now_millis(platform) {
        Ok(now) => now,
        Err(error) => {
            let cleanup = [direct, received[0].handle];
            finish_connect_abort(platform, model, connect_request, &cleanup)?;
            return Err(error);
        }
    };
    let active_watch = match begin_publication_watch(
        platform,
        authorities,
        transactions,
        publication_generation,
    ) {
        Ok(watch) => watch,
        Err(error) => {
            let cleanup = [direct, received[0].handle];
            finish_connect_abort(platform, model, connect_request, &cleanup)?;
            return Err(error);
        }
    };
    let correlation = serial_correlation(authorities, identity);
    if model.attach_connected(correlation, attached_at).is_err() {
        if cancel_registry_watch(
            platform,
            authorities,
            transactions,
            active_watch.transaction_id,
        )
        .is_err()
        {
            let cleanup = [direct, received[0].handle];
            let _ = finish_connect_abort(platform, model, connect_request, &cleanup);
            return Err(FATAL_ATTACH_BASE | 24);
        }
        let cleanup = [direct, received[0].handle];
        finish_connect_abort(platform, model, connect_request, &cleanup)?;
        return Err(24);
    }
    Ok(SerialSession {
        identity,
        watch: Some(active_watch),
        raw_owned: true,
        release_witness: Some(direct),
        input: NativeInput::new(validated_stream_endpoint(received[0].handle).map_err(|_| 24u32)?),
        output: NativeOutput::new(
            validated_stream_endpoint(received[0].handle).map_err(|_| 24u32)?,
        ),
    })
}

pub(crate) fn begin_publication_watch<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    publication_generation: u64,
) -> Result<ActiveWatch, u32> {
    let transaction_id = transactions.take()?;
    let policy = SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY;
    let header = registry_header(authorities, RegistryMessageType::Watch, transaction_id);
    let mut bytes = [0u8; 256];
    let size = encode_watch(
        header,
        Watch {
            protocol_id: policy.protocol_id,
            last_observed_generation: publication_generation,
            service_name: policy.service_name,
        },
        &mut bytes,
    )
    .map_err(|_| 25u32)?;
    platform
        .send_channel(authorities.registry, &bytes[..size], &[])
        .map_err(|_| 26u32)?;
    Ok(ActiveWatch {
        transaction_id,
        publication_generation,
    })
}

pub(crate) fn attach_serial_bounded<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    model: &mut ConsoleModel,
    first_deadline_ms: Option<u64>,
) -> Result<SerialSession, u32> {
    if let Some(deadline) = first_deadline_ms {
        wait_backoff(platform, authorities.registry, deadline)?;
    }
    loop {
        match attach_serial(platform, authorities, transactions, model) {
            Ok(serial) => return Ok(serial),
            Err(error) if error & FATAL_ATTACH_BASE != 0 => return Err(error),
            Err(_) => match model
                .serial_reconnect_failed(now_millis(platform)?)
                .map_err(|_| 25u32)?
            {
                RecoveryAction::RetrySerialAt(deadline) => {
                    wait_backoff(platform, authorities.registry, deadline)?;
                }
                RecoveryAction::Escalate => return Err(26),
                _ => return Err(27),
            },
        }
    }
}

pub(crate) fn watch_publication<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
) -> Result<u64, u32> {
    let transaction_id = transactions.take()?;
    let policy = SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY;
    let header = registry_header(authorities, RegistryMessageType::Watch, transaction_id);
    let mut bytes = [0u8; 256];
    let size = encode_watch(
        header,
        Watch {
            protocol_id: policy.protocol_id,
            // Zero requests an immediate exact observation when a publication
            // is present and becomes a blocking watch while it is absent.
            last_observed_generation: 0,
            service_name: policy.service_name,
        },
        &mut bytes,
    )
    .map_err(|_| 25u32)?;
    platform
        .send_channel(authorities.registry, &bytes[..size], &[])
        .map_err(|_| 26u32)?;
    if wait_readable(platform, authorities.registry).is_err() {
        return match cancel_registry_watch(platform, authorities, transactions, transaction_id) {
            Ok(Some(generation)) if generation != 0 => Ok(generation),
            Ok(_) => Err(27),
            Err(_) => Err(FATAL_ATTACH_BASE | 27),
        };
    }
    let mut received = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(authorities.registry, &mut bytes, &mut received)
        .map_err(|_| FATAL_ATTACH_BASE | 28)?;
    if counts.handles != 0 {
        close_attempt_handles(platform, core::slice::from_ref(&received[0].handle))?;
        return Err(FATAL_ATTACH_BASE | 29);
    }
    let reply = parse_registry(&bytes[..counts.bytes], 0).map_err(|_| FATAL_ATTACH_BASE | 30)?;
    if reply.header
        != (RegistryHeader {
            message_type: RegistryMessageType::GenerationChanged,
            ..header
        })
    {
        return Err(FATAL_ATTACH_BASE | 31);
    }
    match reply.message {
        RegistryMessage::GenerationChanged { service_generation } => Ok(service_generation),
        _ => Err(FATAL_ATTACH_BASE | 32),
    }
}

pub(crate) fn cancel_registry_watch<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    target: u64,
) -> Result<Option<u64>, u32> {
    let transaction_id = transactions.take()?;
    let header = registry_header(authorities, RegistryMessageType::Cancel, transaction_id);
    let mut bytes = [0u8; 72];
    let size = encode_cancel(header, target, &mut bytes).map_err(|_| FATAL_ATTACH_BASE | 28)?;
    platform
        .send_channel(authorities.registry, &bytes[..size], &[])
        .map_err(|_| FATAL_ATTACH_BASE | 29)?;
    let mut changed = None;
    let mut received_count = 0;
    while received_count < 2 {
        wait_readable(platform, authorities.registry).map_err(|_| FATAL_ATTACH_BASE | 30)?;
        let mut handles = [DwReceivedHandleInfoV1::default(); 1];
        let counts = platform
            .receive_channel(authorities.registry, &mut bytes, &mut handles)
            .map_err(|_| FATAL_ATTACH_BASE | 31)?;
        if counts.handles != 0 {
            close_attempt_handles(platform, core::slice::from_ref(&handles[0].handle))?;
            return Err(FATAL_ATTACH_BASE | 32);
        }
        let reply =
            parse_registry(&bytes[..counts.bytes], 0).map_err(|_| FATAL_ATTACH_BASE | 33)?;
        let common = reply.header.registry_generation == authorities.registry_generation
            && reply.header.endpoint_id == authorities.registry_endpoint_id
            && reply.header.endpoint_generation == authorities.registry_endpoint_generation;
        if !common {
            return Err(FATAL_ATTACH_BASE | 34);
        }
        if reply.header.transaction_id == target
            && reply.header.message_type == RegistryMessageType::GenerationChanged
        {
            let RegistryMessage::GenerationChanged { service_generation } = reply.message else {
                return Err(FATAL_ATTACH_BASE | 34);
            };
            changed = Some(service_generation);
            received_count += 1;
            continue;
        }
        if reply.header
            == (RegistryHeader {
                message_type: RegistryMessageType::Cancelled,
                ..header
            })
            && reply.message
                == (RegistryMessage::Cancelled {
                    target_transaction_id: target,
                })
        {
            return Ok(changed);
        }
        if reply.header
            == (RegistryHeader {
                message_type: RegistryMessageType::Error,
                ..header
            })
            && reply.message
                == (RegistryMessage::Error {
                    code: RegistryErrorCode::UnknownTransaction,
                })
            && changed.is_some()
        {
            return Ok(changed);
        }
        return Err(FATAL_ATTACH_BASE | 34);
    }
    Err(FATAL_ATTACH_BASE | 34)
}

pub(crate) fn receive_publication_change<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    serial: &mut SerialSession,
) -> Result<u64, u32> {
    let watch = serial.watch.ok_or(FATAL_ATTACH_BASE | 35)?;
    let mut bytes = [0u8; 256];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(authorities.registry, &mut bytes, &mut handles)
        .map_err(|_| FATAL_ATTACH_BASE | 35)?;
    if counts.handles != 0 {
        close_attempt_handles(platform, core::slice::from_ref(&handles[0].handle))?;
        return Err(FATAL_ATTACH_BASE | 35);
    }
    let reply = parse_registry(&bytes[..counts.bytes], 0).map_err(|_| FATAL_ATTACH_BASE | 35)?;
    let expected = RegistryHeader {
        message_type: RegistryMessageType::GenerationChanged,
        registry_generation: authorities.registry_generation,
        endpoint_id: authorities.registry_endpoint_id,
        endpoint_generation: authorities.registry_endpoint_generation,
        transaction_id: watch.transaction_id,
    };
    let RegistryMessage::GenerationChanged { service_generation } = reply.message else {
        return Err(FATAL_ATTACH_BASE | 35);
    };
    if reply.header != expected || service_generation == watch.publication_generation {
        return Err(FATAL_ATTACH_BASE | 35);
    }
    serial.watch = None;
    Ok(service_generation)
}

pub(crate) fn retire_publication_watch<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
    serial: &mut SerialSession,
) -> Result<(), u32> {
    let Some(watch) = serial.watch else {
        return Ok(());
    };
    cancel_registry_watch(platform, authorities, transactions, watch.transaction_id)?;
    serial.watch = None;
    Ok(())
}

pub(crate) fn lookup_connector<P: ConsoledPlatform>(
    platform: &mut P,
    authorities: StartupAuthorities,
    transactions: &mut TransactionIds,
) -> Result<DwHandle, u32> {
    let (direct, service) = platform
        .create_channel(CONNECTOR_PAIR_RIGHTS)
        .map_err(|_| 33u32)?;
    let transaction_id = transactions.take()?;
    let policy = SERIAL_CONSOLE_CONNECTOR_PUBLICATION_POLICY;
    let header = registry_header(
        authorities,
        RegistryMessageType::LookupConnect,
        transaction_id,
    );
    let mut bytes = [0u8; 256];
    let size = match encode_lookup(
        header,
        Lookup {
            protocol_id: policy.protocol_id,
            version: ProtocolVersion {
                major: policy.protocol_major,
                minor: policy.protocol_minor,
            },
            service_name: policy.service_name,
        },
        &mut bytes,
    ) {
        Ok(size) => size,
        Err(_) => {
            close_attempt_handles(platform, &[direct, service])?;
            return Err(34);
        }
    };
    let transfer = DwHandleTransferV1 {
        handle: service,
        // Registryd must forward this endpoint once more; it receives the
        // exact broad intermediary rights and reduces them to child rights in
        // the CONNECT_OFFER MOVE.
        requested_rights: CONNECTOR_PAIR_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    if platform
        .send_channel(authorities.registry, &bytes[..size], &[transfer])
        .is_err()
    {
        close_attempt_handles(platform, &[direct, service])?;
        return Err(35);
    }
    if wait_readable(platform, authorities.registry).is_err() {
        close_attempt_handles(platform, core::slice::from_ref(&direct))?;
        return Err(FATAL_ATTACH_BASE | 36);
    }
    let mut received = [DwReceivedHandleInfoV1::default(); 1];
    let counts = match platform.receive_channel(authorities.registry, &mut bytes, &mut received) {
        Ok(counts) => counts,
        Err(_) => {
            close_attempt_handles(platform, core::slice::from_ref(&direct))?;
            return Err(FATAL_ATTACH_BASE | 37);
        }
    };
    if counts.handles != 0 {
        close_attempt_handles(platform, &[direct, received[0].handle])?;
        return Err(38);
    }
    let reply = match parse_registry(&bytes[..counts.bytes], 0) {
        Ok(reply) => reply,
        Err(_) => {
            close_attempt_handles(platform, core::slice::from_ref(&direct))?;
            return Err(39);
        }
    };
    if reply.header
        != (RegistryHeader {
            message_type: RegistryMessageType::Connected,
            ..header
        })
        || reply.message != RegistryMessage::Connected
    {
        close_attempt_handles(platform, core::slice::from_ref(&direct))?;
        return Err(40);
    }
    Ok(direct)
}
