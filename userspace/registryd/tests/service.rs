// SPDX-License-Identifier: GPL-3.0-or-later

use wyrmroot_registry_proto::{
    EnumerationScope, ErrorCode, HEADER_BYTES, Header, InstallClient, Lookup, Message, MessageType,
    ProtocolVersion, encode_empty, encode_header, encode_install_client,
    encode_install_publication, encode_lookup, parse,
};
use wyrmroot_registryd::InstalledEndpoint;
use wyrmroot_registryd::service::{
    ChannelRights, ProbeSignals, ReceiveCounts, ReceivedHandle, RegistryService, ServiceError,
    Transport, WaitEvent,
};

#[derive(Default)]
struct Mock {
    event: Option<WaitEvent>,
    request: Vec<u8>,
    received: Option<ReceivedHandle>,
    extra_received: Vec<ReceivedHandle>,
    sent: Vec<(u64, Vec<u8>)>,
    send_attempts: usize,
    fail_sends: Vec<usize>,
    moves: Vec<u64>,
    fail_move: bool,
    closed: Vec<u64>,
    fail_closes: Vec<u64>,
    probes: Vec<(u64, Result<ProbeSignals, ()>)>,
    probe_calls: Vec<u64>,
}

impl Transport for Mock {
    type Error = ();

    fn wait(&mut self, _control: u64, _endpoints: &[InstalledEndpoint]) -> Result<WaitEvent, ()> {
        Ok(self.event.take().unwrap())
    }

    fn probe(&mut self, endpoint: InstalledEndpoint) -> Result<ProbeSignals, ()> {
        self.probe_calls.push(endpoint.handle);
        self.probes
            .iter()
            .position(|(handle, _)| *handle == endpoint.handle)
            .map(|index| self.probes.remove(index).1)
            .unwrap_or(Ok(ProbeSignals::default()))
    }

    fn receive(
        &mut self,
        _channel: u64,
        bytes: &mut [u8],
        handles: &mut [ReceivedHandle],
    ) -> Result<ReceiveCounts, ()> {
        if self.request.len() > bytes.len() {
            return Err(());
        }
        bytes[..self.request.len()].copy_from_slice(&self.request);
        let mut count = 0;
        if let Some(handle) = self.received.take() {
            handles[count] = handle;
            count += 1;
        }
        for handle in self.extra_received.drain(..) {
            handles[count] = handle;
            count += 1;
        }
        Ok(ReceiveCounts {
            bytes: self.request.len(),
            handles: count,
        })
    }

    fn validate_channel(
        &mut self,
        handle: ReceivedHandle,
        rights: ChannelRights,
    ) -> Result<(), ()> {
        let expected = match rights {
            ChannelRights::Child => 1,
            ChannelRights::Broad => 2,
        };
        (handle.metadata_is_channel && handle.metadata_rights == expected)
            .then_some(())
            .ok_or(())
    }

    fn send(&mut self, channel: u64, bytes: &[u8]) -> Result<(), ()> {
        self.send_attempts += 1;
        if self.fail_sends.contains(&self.send_attempts) {
            return Err(());
        }
        self.sent.push((channel, bytes.to_vec()));
        Ok(())
    }

    fn send_move(
        &mut self,
        _channel: u64,
        _bytes: &[u8],
        moved_handle: u64,
        rights: ChannelRights,
    ) -> Result<(), ()> {
        assert_eq!(rights, ChannelRights::Child);
        if self.fail_move {
            return Err(());
        }
        self.moves.push(moved_handle);
        Ok(())
    }

    fn close(&mut self, handle: u64) -> Result<(), ()> {
        self.closed.push(handle);
        (!self.fail_closes.contains(&handle))
            .then_some(())
            .ok_or(())
    }
}

fn event(index: Option<usize>, readable: bool, peer_closed: bool) -> WaitEvent {
    WaitEvent {
        endpoint_index: index,
        readable,
        peer_closed,
    }
}

fn handle(value: u64, rights: u64) -> ReceivedHandle {
    ReceivedHandle {
        handle: value,
        metadata_is_channel: true,
        metadata_rights: rights,
    }
}

fn drive(
    service: &mut RegistryService,
    mock: &mut Mock,
    observed: WaitEvent,
    request: &[u8],
    received: Option<ReceivedHandle>,
) -> Result<(), ServiceError<()>> {
    mock.event = Some(observed);
    mock.request = request.to_vec();
    mock.received = received;
    service.step(mock)
}

fn endpoint_header(kind: MessageType, id: u64, tx: u64) -> Header {
    Header {
        message_type: kind,
        registry_generation: 7,
        endpoint_id: id,
        endpoint_generation: 1,
        transaction_id: tx,
    }
}

fn install_publication(service: &mut RegistryService, mock: &mut Mock, id: u64, generation: u64) {
    let mut bytes = [0u8; 256];
    let size = encode_install_publication(
        Header {
            message_type: MessageType::InstallPublication,
            registry_generation: 7,
            endpoint_id: 0,
            endpoint_generation: 0,
            transaction_id: id,
        },
        id,
        1,
        1,
        id + 100,
        generation,
        17,
        &[ProtocolVersion { major: 1, minor: 0 }],
        b"echo",
        &mut bytes,
    )
    .unwrap();
    drive(
        service,
        mock,
        event(None, true, false),
        &bytes[..size],
        Some(handle(100 + id, 1)),
    )
    .unwrap();
}

fn install_client(service: &mut RegistryService, mock: &mut Mock) {
    let mut bytes = [0u8; 128];
    let size = encode_install_client(
        Header {
            message_type: MessageType::InstallClient,
            registry_generation: 7,
            endpoint_id: 0,
            endpoint_generation: 0,
            transaction_id: 80,
        },
        InstallClient {
            endpoint_id: 41,
            endpoint_generation: 1,
            client_id: 51,
            client_generation: 1,
            scope: EnumerationScope::BootstrapMetadata,
        },
        &mut bytes,
    )
    .unwrap();
    drive(
        service,
        mock,
        event(None, true, false),
        &bytes[..size],
        Some(handle(141, 1)),
    )
    .unwrap();
}

fn install_client_with(
    service: &mut RegistryService,
    mock: &mut Mock,
    endpoint_id: u64,
    client_id: u64,
    installed_handle: u64,
    transaction: u64,
) -> Result<(), ServiceError<()>> {
    let mut bytes = [0u8; 128];
    let size = encode_install_client(
        Header {
            message_type: MessageType::InstallClient,
            registry_generation: 7,
            endpoint_id: 0,
            endpoint_generation: 0,
            transaction_id: transaction,
        },
        InstallClient {
            endpoint_id,
            endpoint_generation: 1,
            client_id,
            client_generation: 1,
            scope: EnumerationScope::BootstrapMetadata,
        },
        &mut bytes,
    )
    .unwrap();
    drive(
        service,
        mock,
        event(None, true, false),
        &bytes[..size],
        Some(handle(installed_handle, 1)),
    )
}

fn install_publication_with(service: &mut RegistryService, mock: &mut Mock, ordinal: u64) {
    let mut bytes = [0u8; 256];
    let name = [
        b'p',
        b'0' + ((ordinal / 10) as u8),
        b'0' + ((ordinal % 10) as u8),
    ];
    let size = encode_install_publication(
        Header {
            message_type: MessageType::InstallPublication,
            registry_generation: 7,
            endpoint_id: 0,
            endpoint_generation: 0,
            transaction_id: 100 + ordinal,
        },
        1_000 + ordinal,
        1,
        1,
        2_000 + ordinal,
        1,
        100 + ordinal,
        &[ProtocolVersion { major: 1, minor: 0 }],
        &name,
        &mut bytes,
    )
    .unwrap();
    drive(
        service,
        mock,
        event(None, true, false),
        &bytes[..size],
        Some(handle(10_000 + ordinal, 1)),
    )
    .unwrap();
}

fn empty(kind: MessageType, id: u64, tx: u64) -> [u8; HEADER_BYTES] {
    let mut bytes = [0u8; HEADER_BYTES];
    encode_empty(endpoint_header(kind, id, tx), &mut bytes).unwrap();
    bytes
}

fn watch(tx: u64, last: u64) -> Vec<u8> {
    let name = b"echo";
    let mut bytes = vec![0u8; 88 + name.len()];
    encode_header(
        endpoint_header(MessageType::Watch, 41, tx),
        0,
        bytes.len(),
        &mut bytes,
    )
    .unwrap();
    bytes[64..72].copy_from_slice(&17u64.to_le_bytes());
    bytes[72..80].copy_from_slice(&last.to_le_bytes());
    bytes[80..82].copy_from_slice(&(name.len() as u16).to_le_bytes());
    bytes[88..].copy_from_slice(name);
    bytes
}

fn error_codes(mock: &Mock) -> Vec<ErrorCode> {
    mock.sent
        .iter()
        .filter_map(|(_, bytes)| match parse(bytes, 0).ok()?.message {
            Message::Error { code } => Some(code),
            _ => None,
        })
        .collect()
}

#[test]
fn readable_commits_before_peer_close_on_control_and_endpoint() {
    let mut service = RegistryService::new(1);
    let mut mock = Mock::default();
    let mut install = [0u8; 128];
    let size = encode_install_client(
        Header {
            message_type: MessageType::InstallClient,
            registry_generation: 7,
            endpoint_id: 0,
            endpoint_generation: 0,
            transaction_id: 1,
        },
        InstallClient {
            endpoint_id: 41,
            endpoint_generation: 1,
            client_id: 51,
            client_generation: 1,
            scope: EnumerationScope::BootstrapMetadata,
        },
        &mut install,
    )
    .unwrap();
    drive(
        &mut service,
        &mut mock,
        event(None, true, true),
        &install[..size],
        Some(handle(141, 1)),
    )
    .unwrap();
    assert!(service.state().is_some());
    mock.event = Some(event(None, false, true));
    assert_eq!(
        service.step(&mut mock),
        Err(ServiceError::ControlPeerClosed)
    );

    let mut service = RegistryService::new(1);
    let mut mock = Mock::default();
    install_publication(&mut service, &mut mock, 31, 13);
    install_client(&mut service, &mut mock);
    drive(
        &mut service,
        &mut mock,
        event(Some(0), true, false),
        &empty(MessageType::Publish, 31, 1),
        None,
    )
    .unwrap();
    let mut lookup = [0u8; 128];
    let size = encode_lookup(
        endpoint_header(MessageType::LookupConnect, 41, 2),
        Lookup {
            protocol_id: 17,
            version: ProtocolVersion { major: 1, minor: 0 },
            service_name: b"echo",
        },
        &mut lookup,
    )
    .unwrap();
    drive(
        &mut service,
        &mut mock,
        event(Some(1), true, true),
        &lookup[..size],
        Some(handle(900, 2)),
    )
    .unwrap();
    assert_eq!(mock.moves, [900]);
    assert!(!mock.closed.contains(&900));
    assert!(!mock.closed.contains(&141));
    drive(
        &mut service,
        &mut mock,
        event(Some(1), false, true),
        &[],
        None,
    )
    .unwrap();
    assert_eq!(mock.closed.iter().filter(|value| **value == 141).count(), 1);
}

#[test]
fn failed_published_send_keeps_absence_watch_pending() {
    let mut service = RegistryService::new(1);
    let mut mock = Mock::default();
    install_publication(&mut service, &mut mock, 31, 13);
    install_client(&mut service, &mut mock);
    let watch = watch(3, 0);
    drive(
        &mut service,
        &mut mock,
        event(Some(1), true, false),
        &watch,
        None,
    )
    .unwrap();
    mock.fail_sends.push(mock.send_attempts + 1);
    drive(
        &mut service,
        &mut mock,
        event(Some(0), true, false),
        &empty(MessageType::Publish, 31, 1),
        None,
    )
    .unwrap();
    let state = service.state().unwrap();
    assert_eq!(state.published_count(), 0);
    assert_eq!(state.pending_watch_count(), 1);
    assert_eq!(mock.closed.iter().filter(|value| **value == 131).count(), 1);
}

#[test]
fn retire_notifies_even_when_ack_fails_and_forward_failure_closes_once() {
    let mut service = RegistryService::new(1);
    let mut mock = Mock::default();
    install_publication(&mut service, &mut mock, 31, 13);
    install_client(&mut service, &mut mock);
    drive(
        &mut service,
        &mut mock,
        event(Some(0), true, false),
        &empty(MessageType::Publish, 31, 1),
        None,
    )
    .unwrap();
    drive(
        &mut service,
        &mut mock,
        event(Some(1), true, false),
        &watch(3, 13),
        None,
    )
    .unwrap();
    mock.fail_sends.push(mock.send_attempts + 1);
    drive(
        &mut service,
        &mut mock,
        event(Some(0), true, false),
        &empty(MessageType::Retire, 31, 2),
        None,
    )
    .unwrap();
    assert!(mock.sent.iter().any(|(_, bytes)| matches!(
        parse(bytes, 0).unwrap().message,
        Message::GenerationChanged {
            service_generation: 0
        }
    )));
    assert_eq!(mock.closed.iter().filter(|value| **value == 131).count(), 1);

    let mut service = RegistryService::new(1);
    let mut mock = Mock::default();
    install_publication(&mut service, &mut mock, 31, 13);
    install_client(&mut service, &mut mock);
    drive(
        &mut service,
        &mut mock,
        event(Some(0), true, false),
        &empty(MessageType::Publish, 31, 1),
        None,
    )
    .unwrap();
    let mut lookup = [0u8; 128];
    let size = encode_lookup(
        endpoint_header(MessageType::LookupConnect, 41, 4),
        Lookup {
            protocol_id: 17,
            version: ProtocolVersion { major: 1, minor: 0 },
            service_name: b"echo",
        },
        &mut lookup,
    )
    .unwrap();
    mock.fail_move = true;
    drive(
        &mut service,
        &mut mock,
        event(Some(1), true, false),
        &lookup[..size],
        Some(handle(900, 2)),
    )
    .unwrap();
    assert_eq!(mock.closed.iter().filter(|value| **value == 900).count(), 1);
    assert!(error_codes(&mock).contains(&ErrorCode::ForwardFailed));
    assert!(
        !mock
            .sent
            .iter()
            .any(|(_, bytes)| matches!(parse(bytes, 0).unwrap().message, Message::Connected))
    );
}

#[test]
fn recoverable_headers_return_canonical_typed_errors_and_loop_continues() {
    let mut service = RegistryService::new(1);
    let mut mock = Mock::default();
    install_client(&mut service, &mut mock);
    let cases = [
        (4usize, 9u8, ErrorCode::UnsupportedVersion),
        (24, 1, ErrorCode::CorrelationMismatch),
        (
            8,
            MessageType::Published as u8,
            ErrorCode::WrongEndpointKind,
        ),
        (8, 99, ErrorCode::MalformedRequest),
        (12, 1, ErrorCode::MalformedRequest),
    ];
    for (index, (offset, value, expected)) in cases.into_iter().enumerate() {
        let mut bytes = empty(MessageType::Enumerate, 41, 10 + index as u64);
        bytes[offset] = value;
        drive(
            &mut service,
            &mut mock,
            event(Some(0), true, false),
            &bytes,
            None,
        )
        .unwrap();
        assert_eq!(error_codes(&mock).last(), Some(&expected));
    }
    drive(
        &mut service,
        &mut mock,
        event(Some(0), true, false),
        &empty(MessageType::Enumerate, 41, 20),
        None,
    )
    .unwrap();
    assert!(mock.sent.iter().any(|(_, bytes)| matches!(parse(bytes, 0).unwrap().message, Message::ServiceList(page) if page.total_count == 0)));
}

#[test]
fn five_and_sixteen_handles_are_recoverable_but_oversize_removes_endpoint() {
    let mut service = RegistryService::new(1);
    let mut mock = Mock::default();
    install_client(&mut service, &mut mock);
    for (tx, count, base) in [(30u64, 5u64, 200u64), (31, 16, 300)] {
        mock.extra_received = (base..base + count).map(|value| handle(value, 1)).collect();
        drive(
            &mut service,
            &mut mock,
            event(Some(0), true, false),
            &empty(MessageType::Enumerate, 41, tx),
            None,
        )
        .unwrap();
        assert_eq!(
            error_codes(&mock).last(),
            Some(&ErrorCode::MalformedRequest)
        );
        for value in base..base + count {
            assert_eq!(
                mock.closed
                    .iter()
                    .filter(|closed| **closed == value)
                    .count(),
                1
            );
        }
    }
    drive(
        &mut service,
        &mut mock,
        event(Some(0), true, false),
        &vec![0u8; 417],
        None,
    )
    .unwrap();
    assert_eq!(mock.closed.iter().filter(|value| **value == 141).count(), 1);
    assert!(service.state().unwrap().installed_endpoint(0).is_none());
}

#[test]
fn install_client_sweeps_full_snapshot_once_and_readable_does_not_mask_close() {
    let mut service = RegistryService::new(1);
    let mut mock = Mock::default();
    for ordinal in 0..32 {
        install_publication_with(&mut service, &mut mock, ordinal);
    }
    for ordinal in 0..32 {
        install_client_with(
            &mut service,
            &mut mock,
            3_000 + ordinal,
            4_000 + ordinal,
            20_000 + ordinal,
            300 + ordinal,
        )
        .unwrap();
    }
    assert!(service.state().unwrap().installed_endpoint(63).is_some());
    assert!(service.state().unwrap().installed_endpoint(64).is_none());

    mock.probe_calls.clear();
    mock.probes.push((
        20_000,
        Ok(ProbeSignals {
            readable: true,
            peer_closed: true,
        }),
    ));
    let sent_before = mock.sent.len();
    install_client_with(&mut service, &mut mock, 5_000, 6_000, 30_000, 500).unwrap();

    assert_eq!(mock.probe_calls.len(), 64);
    let mut probed = mock.probe_calls.clone();
    probed.sort_unstable();
    probed.dedup();
    assert_eq!(probed.len(), 64);
    assert_eq!(
        mock.closed
            .iter()
            .filter(|handle| **handle == 20_000)
            .count(),
        1
    );
    assert_eq!(
        mock.sent.len(),
        sent_before,
        "INSTALL remains acknowledgement-free"
    );
    let endpoints: Vec<_> = (0..64)
        .filter_map(|index| service.state().unwrap().installed_endpoint(index))
        .collect();
    assert!(endpoints.iter().any(|endpoint| {
        endpoint.identity.id == 5_000
            && endpoint.identity.generation == 1
            && endpoint.handle == 30_000
    }));
    assert!(!endpoints.iter().any(|endpoint| endpoint.handle == 20_000));
}

#[test]
fn sweep_probe_and_cleanup_failures_terminate_before_install() {
    let mut service = RegistryService::new(1);
    let mut mock = Mock::default();
    install_client_with(&mut service, &mut mock, 41, 51, 141, 1).unwrap();
    mock.probe_calls.clear();
    mock.probes.push((141, Err(())));

    assert_eq!(
        install_client_with(&mut service, &mut mock, 42, 52, 142, 2),
        Err(ServiceError::Transport(()))
    );
    assert_eq!(mock.probe_calls, [141]);
    assert_eq!(
        mock.closed.iter().filter(|handle| **handle == 142).count(),
        1
    );
    assert!(service.state().unwrap().installed_endpoint(1).is_none());

    let mut service = RegistryService::new(1);
    let mut mock = Mock::default();
    install_client_with(&mut service, &mut mock, 41, 51, 141, 1).unwrap();
    mock.probes.push((
        141,
        Ok(ProbeSignals {
            readable: false,
            peer_closed: true,
        }),
    ));
    mock.fail_closes.push(141);

    assert_eq!(
        install_client_with(&mut service, &mut mock, 42, 52, 142, 2),
        Err(ServiceError::Transport(()))
    );
    assert_eq!(
        mock.closed.iter().filter(|handle| **handle == 141).count(),
        1
    );
    assert_eq!(
        mock.closed.iter().filter(|handle| **handle == 142).count(),
        1
    );
    assert!(service.state().unwrap().installed_endpoint(0).is_none());

    let mut service = RegistryService::new(1);
    let mut mock = Mock::default();
    install_publication(&mut service, &mut mock, 31, 13);
    install_client(&mut service, &mut mock);
    drive(
        &mut service,
        &mut mock,
        event(Some(0), true, false),
        &empty(MessageType::Publish, 31, 1),
        None,
    )
    .unwrap();
    drive(
        &mut service,
        &mut mock,
        event(Some(1), true, false),
        &watch(3, 13),
        None,
    )
    .unwrap();
    mock.probes.push((
        131,
        Ok(ProbeSignals {
            readable: false,
            peer_closed: true,
        }),
    ));
    mock.probes.push((
        141,
        Ok(ProbeSignals {
            readable: false,
            peer_closed: true,
        }),
    ));
    mock.fail_sends.push(mock.send_attempts + 1);

    assert_eq!(
        install_client_with(&mut service, &mut mock, 42, 52, 142, 2),
        Err(ServiceError::State(
            wyrmroot_registryd::RegistryError::UnknownEndpoint
        ))
    );
    assert_eq!(
        mock.closed.iter().filter(|handle| **handle == 131).count(),
        1
    );
    assert_eq!(
        mock.closed.iter().filter(|handle| **handle == 141).count(),
        1
    );
    assert_eq!(
        mock.closed.iter().filter(|handle| **handle == 142).count(),
        1
    );
}
