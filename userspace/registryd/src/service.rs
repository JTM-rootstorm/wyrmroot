//! Transport-independent bounded registry service step.

use crate::{
    EndpointIdentity, EndpointKind, EnumerationTicket, InstalledEndpoint, RegistryError,
    RegistryState, ServiceMetadata, WatchDisposition, WatchNotifications,
};
use wyrmroot_registry_proto::{
    ErrorCode, HEADER_BYTES, Header, Lookup, Message, MessageType, ServiceListRecord,
    decode_header, encode_cancel, encode_empty, encode_error, encode_generation_changed,
    encode_lookup, encode_service_list, parse,
};

pub const MAX_MESSAGE_BYTES: usize = 416;
pub const MAX_ENDPOINTS: usize = 64;
/// Mirrors the generated Deepwyrm `DW_CHANNEL_MAX_HANDLES`; the native adapter
/// has a compile-time equality assertion against the generated constant.
pub const MAX_RECEIVED_HANDLES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelRights {
    Child,
    Broad,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReceivedHandle {
    pub handle: u64,
    pub metadata_is_channel: bool,
    pub metadata_rights: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReceiveCounts {
    pub bytes: usize,
    pub handles: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitEvent {
    pub endpoint_index: Option<usize>,
    pub readable: bool,
    pub peer_closed: bool,
}

pub trait Transport {
    type Error;
    fn wait(
        &mut self,
        control: u64,
        endpoints: &[InstalledEndpoint],
    ) -> Result<WaitEvent, Self::Error>;
    fn receive(
        &mut self,
        channel: u64,
        bytes: &mut [u8],
        handles: &mut [ReceivedHandle],
    ) -> Result<ReceiveCounts, Self::Error>;
    fn validate_channel(
        &mut self,
        handle: ReceivedHandle,
        rights: ChannelRights,
    ) -> Result<(), Self::Error>;
    fn send(&mut self, channel: u64, bytes: &[u8]) -> Result<(), Self::Error>;
    /// On failure the caller retains `moved_handle`; success consumes it.
    fn send_move(
        &mut self,
        channel: u64,
        bytes: &[u8],
        moved_handle: u64,
        reduced_rights: ChannelRights,
    ) -> Result<(), Self::Error>;
    fn close(&mut self, handle: u64);
}

#[derive(Debug, Eq, PartialEq)]
pub enum ServiceError<E> {
    Transport(E),
    ControlPeerClosed,
    InvalidWaitEvent,
}

pub struct RegistryService {
    control: u64,
    state: Option<RegistryState>,
}

impl RegistryService {
    pub const fn new(control: u64) -> Self {
        Self {
            control,
            state: None,
        }
    }
    pub const fn state(&self) -> Option<&RegistryState> {
        self.state.as_ref()
    }

    pub fn step<T: Transport>(&mut self, io: &mut T) -> Result<(), ServiceError<T::Error>> {
        let placeholder = InstalledEndpoint {
            identity: EndpointIdentity {
                id: 1,
                generation: 1,
            },
            handle: 1,
            kind: EndpointKind::Client,
        };
        let mut endpoints = [placeholder; MAX_ENDPOINTS];
        let mut count = 0;
        if let Some(state) = self.state.as_ref() {
            while let Some(endpoint) = state.installed_endpoint(count) {
                endpoints[count] = endpoint;
                count += 1;
            }
        }
        let event = io
            .wait(self.control, &endpoints[..count])
            .map_err(ServiceError::Transport)?;
        if let Some(index) = event.endpoint_index {
            let endpoint = endpoints
                .get(index)
                .copied()
                .filter(|_| index < count)
                .ok_or(ServiceError::InvalidWaitEvent)?;
            if event.readable {
                return self.receive_endpoint(io, endpoint);
            }
            if event.peer_closed {
                if let Ok(outcome) = self.state.as_mut().unwrap().peer_closed(endpoint.identity) {
                    io.close(outcome.handle);
                    self.send_notifications(io, outcome.notifications);
                }
                return Ok(());
            }
            return Err(ServiceError::InvalidWaitEvent);
        }
        if event.readable {
            return self.receive_control(io);
        }
        if event.peer_closed {
            return Err(ServiceError::ControlPeerClosed);
        }
        Err(ServiceError::InvalidWaitEvent)
    }

    fn receive_control<T: Transport>(&mut self, io: &mut T) -> Result<(), ServiceError<T::Error>> {
        let (mut bytes, mut handles) = (
            [0u8; MAX_MESSAGE_BYTES],
            [ReceivedHandle::default(); MAX_RECEIVED_HANDLES],
        );
        let counts = io
            .receive(self.control, &mut bytes, &mut handles)
            .map_err(ServiceError::Transport)?;
        if counts.bytes > bytes.len() || counts.handles > handles.len() {
            close_received(io, &handles, counts.handles.min(handles.len()));
            return Ok(());
        }
        let Ok(request) = parse(&bytes[..counts.bytes], counts.handles) else {
            close_received(io, &handles, counts.handles);
            return Ok(());
        };
        if !matches!(
            request.message,
            Message::InstallPublication(_) | Message::InstallClient(_)
        ) || counts.handles != 1
            || io
                .validate_channel(handles[0], ChannelRights::Child)
                .is_err()
        {
            close_received(io, &handles, counts.handles);
            return Ok(());
        }
        if self.state.is_none() {
            self.state = RegistryState::new(request.header.registry_generation).ok();
        }
        let Some(state) = self.state.as_mut() else {
            io.close(handles[0].handle);
            return Ok(());
        };
        let result = match request.message {
            Message::InstallPublication(value) => state.install_publication(
                request.header.registry_generation,
                handles[0].handle,
                value,
            ),
            Message::InstallClient(value) => {
                state.install_client(request.header.registry_generation, handles[0].handle, value)
            }
            _ => unreachable!(),
        };
        if result.is_err() {
            io.close(handles[0].handle);
        }
        Ok(())
    }

    fn receive_endpoint<T: Transport>(
        &mut self,
        io: &mut T,
        endpoint: InstalledEndpoint,
    ) -> Result<(), ServiceError<T::Error>> {
        let (mut bytes, mut handles) = (
            [0u8; MAX_MESSAGE_BYTES],
            [ReceivedHandle::default(); MAX_RECEIVED_HANDLES],
        );
        let counts = match io.receive(endpoint.handle, &mut bytes, &mut handles) {
            Ok(v) => v,
            Err(_) => {
                self.remove(io, endpoint);
                return Ok(());
            }
        };
        if counts.bytes > bytes.len() || counts.handles > handles.len() {
            close_received(io, &handles, counts.handles.min(handles.len()));
            self.remove(io, endpoint);
            return Ok(());
        }
        let decoded = match decode_header(&bytes[..counts.bytes]) {
            Ok(v) => v,
            Err(_) => {
                close_received(io, &handles, counts.handles);
                return Ok(());
            }
        };
        let canonical = Header {
            registry_generation: self.state.as_ref().unwrap().generation(),
            endpoint_id: endpoint.identity.id,
            endpoint_generation: endpoint.identity.generation,
            transaction_id: decoded.transaction_id,
            message_type: decoded.message_type.unwrap_or(MessageType::Error),
        };
        if decoded.major != 1 || decoded.minor != 0 {
            close_received(io, &handles, counts.handles);
            self.complete_error(io, endpoint, canonical, ErrorCode::UnsupportedVersion);
            return Ok(());
        }
        if decoded.message_type.is_none() {
            close_received(io, &handles, counts.handles);
            self.complete_error(io, endpoint, canonical, ErrorCode::MalformedRequest);
            return Ok(());
        }
        if !request_type_allowed(endpoint.kind, decoded.message_type) {
            close_received(io, &handles, counts.handles);
            self.complete_error(io, endpoint, canonical, ErrorCode::WrongEndpointKind);
            return Ok(());
        }
        if decoded.registry_generation != canonical.registry_generation
            || decoded.endpoint_id != canonical.endpoint_id
            || decoded.endpoint_generation != canonical.endpoint_generation
        {
            close_received(io, &handles, counts.handles);
            self.complete_error(io, endpoint, canonical, ErrorCode::CorrelationMismatch);
            return Ok(());
        }
        let request = match parse(&bytes[..counts.bytes], counts.handles) {
            Ok(v) => v,
            Err(_) => {
                close_received(io, &handles, counts.handles);
                self.complete_error(io, endpoint, canonical, ErrorCode::MalformedRequest);
                return Ok(());
            }
        };
        self.dispatch(io, endpoint, request.header, request.message, handles);
        Ok(())
    }

    fn dispatch<T: Transport>(
        &mut self,
        io: &mut T,
        endpoint: InstalledEndpoint,
        header: Header,
        message: Message<'_>,
        handles: [ReceivedHandle; MAX_RECEIVED_HANDLES],
    ) {
        match (endpoint.kind, message) {
            (EndpointKind::Publication, Message::Publish) => match self
                .state
                .as_mut()
                .unwrap()
                .prepare_publish(endpoint.identity, header.transaction_id)
            {
                Ok(ticket) => {
                    if !send_empty_raw(io, endpoint.handle, header, MessageType::Published) {
                        self.remove(io, endpoint);
                        return;
                    }
                    let outcome = self
                        .state
                        .as_mut()
                        .unwrap()
                        .commit_publish(ticket)
                        .expect("prepared publication remains installed through send");
                    self.send_notifications(io, outcome.notifications);
                }
                Err(error) => self.state_error(io, endpoint, header, error),
            },
            (EndpointKind::Publication, Message::Retire) => match self
                .state
                .as_mut()
                .unwrap()
                .retire(endpoint.identity, header.transaction_id)
            {
                Ok(outcome) => {
                    let _ =
                        send_empty_raw(io, outcome.registry_handle, header, MessageType::Retired);
                    io.close(outcome.registry_handle);
                    self.send_notifications(io, outcome.notifications);
                }
                Err(error) => self.state_error(io, endpoint, header, error),
            },
            (EndpointKind::Client, Message::LookupConnect(lookup)) => {
                self.connect(io, endpoint, header, lookup, handles[0])
            }
            (EndpointKind::Client, Message::Enumerate) => self.enumerate(io, endpoint, header),
            (EndpointKind::Client, Message::Watch(watch)) => match self
                .state
                .as_mut()
                .unwrap()
                .watch(endpoint.identity, header.transaction_id, watch)
            {
                Ok(WatchDisposition::Immediate { service_generation }) => {
                    if !send_generation(io, endpoint.handle, header, service_generation) {
                        self.remove(io, endpoint);
                    }
                }
                Ok(WatchDisposition::Pending) => {}
                Err(error) => self.state_error(io, endpoint, header, error),
            },
            (
                EndpointKind::Client,
                Message::Cancel {
                    target_transaction_id,
                },
            ) => match self.state.as_mut().unwrap().cancel(
                endpoint.identity,
                header.transaction_id,
                target_transaction_id,
            ) {
                Ok(()) => {
                    let mut bytes = [0u8; 72];
                    let size = encode_cancel(
                        Header {
                            message_type: MessageType::Cancelled,
                            ..header
                        },
                        target_transaction_id,
                        &mut bytes,
                    )
                    .unwrap();
                    if io.send(endpoint.handle, &bytes[..size]).is_err() {
                        self.remove(io, endpoint);
                    }
                }
                Err(error) => self.state_error(io, endpoint, header, error),
            },
            _ => {
                close_received(io, &handles, usize::from(handles[0].handle != 0));
                self.complete_error(io, endpoint, header, ErrorCode::WrongEndpointKind);
            }
        }
    }

    fn connect<T: Transport>(
        &mut self,
        io: &mut T,
        endpoint: InstalledEndpoint,
        header: Header,
        lookup: Lookup<'_>,
        service_endpoint: ReceivedHandle,
    ) {
        if io
            .validate_channel(service_endpoint, ChannelRights::Broad)
            .is_err()
        {
            if service_endpoint.handle != 0 {
                io.close(service_endpoint.handle);
            }
            self.complete_error(io, endpoint, header, ErrorCode::MalformedRequest);
            return;
        }
        let offer = match self.state.as_mut().unwrap().lookup(
            endpoint.identity,
            header.transaction_id,
            lookup,
        ) {
            Ok(v) => v,
            Err(e) => {
                io.close(service_endpoint.handle);
                self.state_error(io, endpoint, header, e);
                return;
            }
        };
        let mut bytes = [0u8; MAX_MESSAGE_BYTES];
        let size = encode_lookup(
            Header {
                message_type: MessageType::ConnectOffer,
                endpoint_id: offer.publication.id,
                endpoint_generation: offer.publication.generation,
                ..header
            },
            lookup,
            &mut bytes,
        )
        .unwrap();
        if io
            .send_move(
                offer.publication_handle,
                &bytes[..size],
                service_endpoint.handle,
                ChannelRights::Child,
            )
            .is_err()
        {
            io.close(service_endpoint.handle);
            self.send_error(io, endpoint, header, ErrorCode::ForwardFailed);
            return;
        }
        self.send_empty(io, endpoint, header, MessageType::Connected);
    }

    fn enumerate<T: Transport>(&mut self, io: &mut T, endpoint: InstalledEndpoint, header: Header) {
        let ticket = match self
            .state
            .as_mut()
            .unwrap()
            .enumerate_begin(endpoint.identity, header.transaction_id)
        {
            Ok(v) => v,
            Err(e) => {
                self.state_error(io, endpoint, header, e);
                return;
            }
        };
        for page in 0..ticket.page_count {
            if !self.send_page(io, endpoint, header, ticket, page) {
                self.remove(io, endpoint);
                return;
            }
        }
        self.state
            .as_mut()
            .unwrap()
            .enumeration_complete(ticket)
            .unwrap();
    }

    fn send_page<T: Transport>(
        &self,
        io: &mut T,
        endpoint: InstalledEndpoint,
        header: Header,
        ticket: EnumerationTicket,
        page: u16,
    ) -> bool {
        let start = usize::from(page) * 2;
        let first = self
            .state
            .as_ref()
            .unwrap()
            .enumeration_record(ticket, start)
            .ok()
            .flatten();
        let second = self
            .state
            .as_ref()
            .unwrap()
            .enumeration_record(ticket, start + 1)
            .ok()
            .flatten();
        let mut bytes = [0u8; MAX_MESSAGE_BYTES];
        let reply = Header {
            message_type: MessageType::ServiceList,
            ..header
        };
        let size = match (first, second) {
            (None, None) => encode_service_list(
                reply,
                page,
                ticket.page_count,
                ticket.total_count,
                &[],
                &mut bytes,
            ),
            (Some(a), None) => encode_service_list(
                reply,
                page,
                ticket.page_count,
                ticket.total_count,
                &[record(&a)],
                &mut bytes,
            ),
            (Some(a), Some(b)) => encode_service_list(
                reply,
                page,
                ticket.page_count,
                ticket.total_count,
                &[record(&a), record(&b)],
                &mut bytes,
            ),
            _ => unreachable!(),
        }
        .unwrap();
        io.send(endpoint.handle, &bytes[..size]).is_ok()
    }

    fn complete_error<T: Transport>(
        &mut self,
        io: &mut T,
        endpoint: InstalledEndpoint,
        header: Header,
        code: ErrorCode,
    ) {
        match self.state.as_mut().unwrap().complete_transaction(
            endpoint.identity,
            endpoint.kind,
            header.transaction_id,
        ) {
            Ok(()) => self.send_error(io, endpoint, header, code),
            Err(e) => self.state_error(io, endpoint, header, e),
        }
    }
    fn state_error<T: Transport>(
        &mut self,
        io: &mut T,
        endpoint: InstalledEndpoint,
        header: Header,
        error: RegistryError,
    ) {
        self.send_error(io, endpoint, header, error_code(error));
    }
    fn send_error<T: Transport>(
        &mut self,
        io: &mut T,
        endpoint: InstalledEndpoint,
        header: Header,
        code: ErrorCode,
    ) {
        let mut bytes = [0u8; 72];
        let size = encode_error(
            Header {
                message_type: MessageType::Error,
                ..header
            },
            code,
            &mut bytes,
        )
        .unwrap();
        if io.send(endpoint.handle, &bytes[..size]).is_err() {
            self.remove(io, endpoint);
        }
    }
    fn send_empty<T: Transport>(
        &mut self,
        io: &mut T,
        endpoint: InstalledEndpoint,
        header: Header,
        kind: MessageType,
    ) -> bool {
        if send_empty_raw(io, endpoint.handle, header, kind) {
            true
        } else {
            self.remove(io, endpoint);
            false
        }
    }
    fn send_notifications<T: Transport>(&mut self, io: &mut T, values: WatchNotifications) {
        for index in 0..values.len() {
            let n = values.get(index).unwrap();
            let header = Header {
                message_type: MessageType::GenerationChanged,
                registry_generation: self.state.as_ref().unwrap().generation(),
                endpoint_id: n.client.id,
                endpoint_generation: n.client.generation,
                transaction_id: n.transaction_id,
            };
            if !send_generation(io, n.client_handle, header, n.service_generation) {
                self.remove(
                    io,
                    InstalledEndpoint {
                        identity: n.client,
                        handle: n.client_handle,
                        kind: EndpointKind::Client,
                    },
                );
            }
        }
    }
    fn remove<T: Transport>(&mut self, io: &mut T, endpoint: InstalledEndpoint) {
        if let Some(state) = self.state.as_mut()
            && let Ok(outcome) = state.peer_closed(endpoint.identity)
        {
            io.close(outcome.handle);
            self.send_notifications(io, outcome.notifications);
        }
    }
}

fn record(value: &ServiceMetadata) -> ServiceListRecord<'_> {
    ServiceListRecord {
        protocol_id: value.protocol_id,
        service_generation: value.service_generation,
        versions: value.versions,
        version_count: value.version_count,
        service_name: value.name(),
    }
}
fn send_empty_raw<T: Transport>(
    io: &mut T,
    handle: u64,
    header: Header,
    kind: MessageType,
) -> bool {
    let mut bytes = [0u8; HEADER_BYTES];
    let size = encode_empty(
        Header {
            message_type: kind,
            ..header
        },
        &mut bytes,
    )
    .unwrap();
    io.send(handle, &bytes[..size]).is_ok()
}
fn send_generation<T: Transport>(io: &mut T, handle: u64, header: Header, generation: u64) -> bool {
    let mut bytes = [0u8; 72];
    let size = encode_generation_changed(
        Header {
            message_type: MessageType::GenerationChanged,
            ..header
        },
        generation,
        &mut bytes,
    )
    .unwrap();
    io.send(handle, &bytes[..size]).is_ok()
}
fn close_received<T: Transport>(io: &mut T, handles: &[ReceivedHandle], count: usize) {
    for value in handles.iter().take(count) {
        if value.handle != 0 {
            io.close(value.handle);
        }
    }
}
fn error_code(error: RegistryError) -> ErrorCode {
    match error {
        RegistryError::TransactionLive => ErrorCode::TransactionLive,
        RegistryError::TransactionReplay => ErrorCode::TransactionReplay,
        RegistryError::OutstandingLimit => ErrorCode::OutstandingLimit,
        RegistryError::Capacity => ErrorCode::Capacity,
        RegistryError::NotPublished => ErrorCode::NotPublished,
        RegistryError::UnsupportedVersion => ErrorCode::UnsupportedVersion,
        RegistryError::EnumerationDenied => ErrorCode::EnumerationDenied,
        RegistryError::UnknownTransaction | RegistryError::UnknownEndpoint => {
            ErrorCode::UnknownTransaction
        }
        RegistryError::WrongEndpointKind => ErrorCode::WrongEndpointKind,
        _ => ErrorCode::InvalidState,
    }
}

fn request_type_allowed(kind: EndpointKind, message: Option<MessageType>) -> bool {
    matches!(
        (kind, message),
        (
            EndpointKind::Publication,
            Some(MessageType::Publish | MessageType::Retire)
        ) | (
            EndpointKind::Client,
            Some(
                MessageType::LookupConnect
                    | MessageType::Enumerate
                    | MessageType::Watch
                    | MessageType::Cancel
            )
        )
    )
}
