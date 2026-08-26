//! Resident, allocation-free WYR1 bootstrap registry state and service loop.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "native-registryd")]
use {deepwyrm_syscall as _, wyrmroot_loader as _, wyrmroot_runtime as _};

pub mod service;

use wyrmroot_registry_proto::{
    EnumerationScope, InstallClient, InstallPublication, Lookup, MAX_CLIENT_REPLAY,
    MAX_OUTSTANDING_PER_CLIENT, MAX_PENDING_WATCHES, MAX_PROTOCOL_VERSIONS, MAX_PUBLICATION_REPLAY,
    MAX_SERVICE_LIST_PAGES, MAX_SERVICE_NAME_BYTES, MAX_SERVICES, ProtocolVersion, Watch,
};

pub const MAX_CLIENTS: usize = 32;
pub const MAX_ISSUED_ENDPOINT_IDS: usize = 128;
pub const MAX_ISSUED_PUBLICATION_IDS: usize = 64;
pub const MAX_ISSUED_CLIENT_IDS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointKind {
    Publication,
    Client,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointIdentity {
    pub id: u64,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstalledEndpoint {
    pub identity: EndpointIdentity,
    pub handle: u64,
    pub kind: EndpointKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForwardOffer {
    pub publication: EndpointIdentity,
    pub publication_handle: u64,
    pub service_generation: u64,
    pub client_transaction: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceMetadata {
    pub name: [u8; MAX_SERVICE_NAME_BYTES],
    pub name_len: u8,
    pub protocol_id: u64,
    pub versions: [ProtocolVersion; MAX_PROTOCOL_VERSIONS],
    pub version_count: u8,
    pub service_generation: u64,
}

impl ServiceMetadata {
    pub fn name(&self) -> &[u8] {
        &self.name[..usize::from(self.name_len)]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryError {
    ZeroIdentity,
    WrongRegistryGeneration,
    DuplicateEndpoint,
    DuplicatePublication,
    DuplicateClient,
    DuplicateService,
    StaleServiceGeneration,
    Capacity,
    UnknownEndpoint,
    WrongEndpointGeneration,
    NotPublished,
    UnsupportedVersion,
    EnumerationDenied,
    TransactionLive,
    TransactionReplay,
    OutstandingLimit,
    WrongEndpointKind,
    UnknownTransaction,
    InvalidState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchNotification {
    pub client: EndpointIdentity,
    pub client_handle: u64,
    pub transaction_id: u64,
    pub service_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchNotifications {
    entries: [Option<WatchNotification>; MAX_PENDING_WATCHES],
    len: usize,
}

impl WatchNotifications {
    const fn new() -> Self {
        Self {
            entries: [None; MAX_PENDING_WATCHES],
            len: 0,
        }
    }

    fn push(&mut self, notification: WatchNotification) {
        self.entries[self.len] = Some(notification);
        self.len += 1;
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn get(&self, index: usize) -> Option<WatchNotification> {
        self.entries.get(index).copied().flatten()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchDisposition {
    Immediate { service_generation: u64 },
    Pending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishOutcome {
    pub service_generation: u64,
    pub notifications: WatchNotifications,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishTicket {
    endpoint: EndpointIdentity,
    transaction: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetireOutcome {
    pub registry_handle: u64,
    pub service_generation: u64,
    pub notifications: WatchNotifications,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCloseOutcome {
    pub handle: u64,
    pub kind: EndpointKind,
    pub notifications: WatchNotifications,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnumerationTicket {
    client: EndpointIdentity,
    transaction: u64,
    pub total_count: u16,
    pub page_count: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Replay<const N: usize> {
    entries: [u64; N],
    start: usize,
    len: usize,
}

impl<const N: usize> Replay<N> {
    const fn new() -> Self {
        Self {
            entries: [0; N],
            start: 0,
            len: 0,
        }
    }

    fn contains(&self, value: u64) -> bool {
        (0..self.len).any(|index| self.entries[(self.start + index) % N] == value)
    }

    fn push(&mut self, value: u64) {
        if self.len < N {
            self.entries[(self.start + self.len) % N] = value;
            self.len += 1;
        } else {
            self.entries[self.start] = value;
            self.start = (self.start + 1) % N;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationPhase {
    Installed,
    Published,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Publication {
    endpoint: EndpointIdentity,
    handle: u64,
    role_id: u32,
    publication_id: u64,
    service_generation: u64,
    protocol_id: u64,
    versions: [ProtocolVersion; MAX_PROTOCOL_VERSIONS],
    version_count: u8,
    phase: PublicationPhase,
    live_transaction: u64,
    replay: Replay<MAX_PUBLICATION_REPLAY>,
}

impl Publication {
    fn supports(&self, version: ProtocolVersion) -> bool {
        self.versions[..usize::from(self.version_count)].contains(&version)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ServiceSlot {
    name: [u8; MAX_SERVICE_NAME_BYTES],
    name_len: u8,
    last_generation: u64,
    active: Option<Publication>,
}

impl ServiceSlot {
    fn name(&self) -> &[u8] {
        &self.name[..usize::from(self.name_len)]
    }

    fn metadata(&self) -> Option<ServiceMetadata> {
        let publication = self.active?;
        if publication.phase != PublicationPhase::Published {
            return None;
        }
        Some(ServiceMetadata {
            name: self.name,
            name_len: self.name_len,
            protocol_id: publication.protocol_id,
            versions: publication.versions,
            version_count: publication.version_count,
            service_generation: publication.service_generation,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Client {
    endpoint: EndpointIdentity,
    handle: u64,
    client_id: u64,
    scope: EnumerationScope,
    live_transactions: [u64; MAX_OUTSTANDING_PER_CLIENT],
    live_count: usize,
    replay: Replay<MAX_CLIENT_REPLAY>,
}

impl Client {
    fn reserve(&mut self, transaction: u64) -> Result<(), RegistryError> {
        if transaction == 0 {
            return Err(RegistryError::ZeroIdentity);
        }
        if self.replay.contains(transaction) {
            return Err(RegistryError::TransactionReplay);
        }
        if self.live_transactions[..self.live_count].contains(&transaction) {
            return Err(RegistryError::TransactionLive);
        }
        if self.live_count == self.live_transactions.len() {
            return Err(RegistryError::OutstandingLimit);
        }
        self.live_transactions[self.live_count] = transaction;
        self.live_count += 1;
        Ok(())
    }

    fn complete(&mut self, transaction: u64) {
        if let Some(index) = self.live_transactions[..self.live_count]
            .iter()
            .position(|value| *value == transaction)
        {
            self.live_count -= 1;
            self.live_transactions[index] = self.live_transactions[self.live_count];
            self.live_transactions[self.live_count] = 0;
            self.replay.push(transaction);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingWatch {
    client: EndpointIdentity,
    client_handle: u64,
    transaction: u64,
    protocol_id: u64,
    last_generation: u64,
    name: [u8; MAX_SERVICE_NAME_BYTES],
    name_len: u8,
}

impl PendingWatch {
    fn name(&self) -> &[u8] {
        &self.name[..usize::from(self.name_len)]
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct RegistryState {
    generation: u64,
    services: [Option<ServiceSlot>; MAX_SERVICES],
    clients: [Option<Client>; MAX_CLIENTS],
    watches: [Option<PendingWatch>; MAX_PENDING_WATCHES],
    issued_endpoint_ids: [u64; MAX_ISSUED_ENDPOINT_IDS],
    issued_endpoint_count: usize,
    issued_publication_ids: [u64; MAX_ISSUED_PUBLICATION_IDS],
    issued_publication_count: usize,
    issued_client_ids: [u64; MAX_ISSUED_CLIENT_IDS],
    issued_client_count: usize,
}

impl RegistryState {
    pub fn new(generation: u64) -> Result<Self, RegistryError> {
        if generation == 0 {
            return Err(RegistryError::ZeroIdentity);
        }
        Ok(Self {
            generation,
            services: [None; MAX_SERVICES],
            clients: [None; MAX_CLIENTS],
            watches: [None; MAX_PENDING_WATCHES],
            issued_endpoint_ids: [0; MAX_ISSUED_ENDPOINT_IDS],
            issued_endpoint_count: 0,
            issued_publication_ids: [0; MAX_ISSUED_PUBLICATION_IDS],
            issued_publication_count: 0,
            issued_client_ids: [0; MAX_ISSUED_CLIENT_IDS],
            issued_client_count: 0,
        })
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn published_count(&self) -> usize {
        self.services
            .iter()
            .flatten()
            .filter(|slot| slot.metadata().is_some())
            .count()
    }

    pub fn pending_watch_count(&self) -> usize {
        self.watches.iter().flatten().count()
    }

    pub fn installed_endpoint(&self, index: usize) -> Option<InstalledEndpoint> {
        let publications = self.services.iter().flatten().filter_map(|slot| {
            slot.active.map(|publication| InstalledEndpoint {
                identity: publication.endpoint,
                handle: publication.handle,
                kind: EndpointKind::Publication,
            })
        });
        let clients = self
            .clients
            .iter()
            .flatten()
            .map(|client| InstalledEndpoint {
                identity: client.endpoint,
                handle: client.handle,
                kind: EndpointKind::Client,
            });
        publications.chain(clients).nth(index)
    }

    pub fn install_publication(
        &mut self,
        registry_generation: u64,
        handle: u64,
        install: InstallPublication<'_>,
    ) -> Result<(), RegistryError> {
        let endpoint = EndpointIdentity {
            id: install.endpoint_id,
            generation: install.endpoint_generation,
        };
        self.validate_install(registry_generation, endpoint, handle)?;
        self.validate_fresh_endpoint_id(endpoint.id)?;
        if self.issued_publication_ids[..self.issued_publication_count]
            .contains(&install.publication_id)
        {
            return Err(RegistryError::DuplicatePublication);
        }
        if self.issued_publication_count == MAX_ISSUED_PUBLICATION_IDS {
            return Err(RegistryError::Capacity);
        }
        let matching = self.services.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|slot| slot.name() == install.service_name)
        });
        let index = if let Some(index) = matching {
            let slot = self.services[index].as_ref().unwrap();
            if slot.active.is_some() {
                return Err(RegistryError::DuplicateService);
            }
            if install.service_generation <= slot.last_generation {
                return Err(RegistryError::StaleServiceGeneration);
            }
            index
        } else {
            self.services
                .iter()
                .position(Option::is_none)
                .ok_or(RegistryError::Capacity)?
        };
        let mut name = [0; MAX_SERVICE_NAME_BYTES];
        name[..install.service_name.len()].copy_from_slice(install.service_name);
        let mut versions = [ProtocolVersion::default(); MAX_PROTOCOL_VERSIONS];
        for (version, target) in versions.iter_mut().enumerate().take(install.versions.len()) {
            *target = install.versions.get(version).expect("validated versions");
        }
        self.services[index] = Some(ServiceSlot {
            name,
            name_len: install.service_name.len() as u8,
            last_generation: install.service_generation,
            active: Some(Publication {
                endpoint,
                handle,
                role_id: install.supervisor_role_id,
                publication_id: install.publication_id,
                service_generation: install.service_generation,
                protocol_id: install.protocol_id,
                versions,
                version_count: install.versions.len() as u8,
                phase: PublicationPhase::Installed,
                live_transaction: 0,
                replay: Replay::new(),
            }),
        });
        self.record_endpoint_id(endpoint.id);
        self.issued_publication_ids[self.issued_publication_count] = install.publication_id;
        self.issued_publication_count += 1;
        Ok(())
    }

    pub fn install_client(
        &mut self,
        registry_generation: u64,
        handle: u64,
        install: InstallClient,
    ) -> Result<(), RegistryError> {
        let endpoint = EndpointIdentity {
            id: install.endpoint_id,
            generation: install.endpoint_generation,
        };
        self.validate_install(registry_generation, endpoint, handle)?;
        self.validate_fresh_endpoint_id(endpoint.id)?;
        if self.issued_client_ids[..self.issued_client_count].contains(&install.client_id) {
            return Err(RegistryError::DuplicateClient);
        }
        if self.issued_client_count == MAX_ISSUED_CLIENT_IDS {
            return Err(RegistryError::Capacity);
        }
        let index = self
            .clients
            .iter()
            .position(Option::is_none)
            .ok_or(RegistryError::Capacity)?;
        self.clients[index] = Some(Client {
            endpoint,
            handle,
            client_id: install.client_id,
            scope: install.scope,
            live_transactions: [0; MAX_OUTSTANDING_PER_CLIENT],
            live_count: 0,
            replay: Replay::new(),
        });
        self.record_endpoint_id(endpoint.id);
        self.issued_client_ids[self.issued_client_count] = install.client_id;
        self.issued_client_count += 1;
        Ok(())
    }

    pub fn prepare_publish(
        &mut self,
        endpoint: EndpointIdentity,
        transaction: u64,
    ) -> Result<PublishTicket, RegistryError> {
        let index = self.publication_index(endpoint)?;
        let publication = self.services[index]
            .as_mut()
            .unwrap()
            .active
            .as_mut()
            .unwrap();
        publication_reserve(publication, transaction)?;
        if publication.phase != PublicationPhase::Installed {
            publication_complete(publication, transaction);
            return Err(RegistryError::InvalidState);
        }
        Ok(PublishTicket {
            endpoint,
            transaction,
        })
    }

    pub fn commit_publish(
        &mut self,
        ticket: PublishTicket,
    ) -> Result<PublishOutcome, RegistryError> {
        let index = self.publication_index(ticket.endpoint)?;
        let publication = self.services[index]
            .as_mut()
            .unwrap()
            .active
            .as_mut()
            .unwrap();
        if publication.live_transaction != ticket.transaction
            || publication.phase != PublicationPhase::Installed
        {
            return Err(RegistryError::InvalidState);
        }
        publication.phase = PublicationPhase::Published;
        let generation = publication.service_generation;
        publication_complete(publication, ticket.transaction);
        let protocol = publication.protocol_id;
        let name = self.services[index].as_ref().unwrap().name;
        let name_len = self.services[index].as_ref().unwrap().name_len;
        let notifications = self.notify(protocol, &name[..usize::from(name_len)], generation);
        Ok(PublishOutcome {
            service_generation: generation,
            notifications,
        })
    }

    pub fn publish(
        &mut self,
        endpoint: EndpointIdentity,
        transaction: u64,
    ) -> Result<PublishOutcome, RegistryError> {
        let ticket = self.prepare_publish(endpoint, transaction)?;
        self.commit_publish(ticket)
    }

    pub fn retire(
        &mut self,
        endpoint: EndpointIdentity,
        transaction: u64,
    ) -> Result<RetireOutcome, RegistryError> {
        let index = self.publication_index(endpoint)?;
        let slot = self.services[index].as_mut().unwrap();
        let publication = slot.active.as_mut().unwrap();
        publication_reserve(publication, transaction)?;
        publication_complete(publication, transaction);
        let publication = slot.active.take().unwrap();
        let protocol = publication.protocol_id;
        let service_generation = publication.service_generation;
        let name = slot.name;
        let name_len = slot.name_len;
        let notifications = self.notify(protocol, &name[..usize::from(name_len)], 0);
        Ok(RetireOutcome {
            registry_handle: publication.handle,
            service_generation,
            notifications,
        })
    }

    pub fn lookup(
        &mut self,
        client: EndpointIdentity,
        transaction: u64,
        request: Lookup<'_>,
    ) -> Result<ForwardOffer, RegistryError> {
        let client_index = self.client_index(client)?;
        self.clients[client_index]
            .as_mut()
            .unwrap()
            .reserve(transaction)?;
        let result = self
            .services
            .iter()
            .flatten()
            .find_map(|slot| {
                let publication = slot.active?;
                (publication.phase == PublicationPhase::Published
                    && publication.protocol_id == request.protocol_id
                    && slot.name() == request.service_name)
                    .then_some(publication)
            })
            .ok_or(RegistryError::NotPublished)
            .and_then(|publication| {
                if publication.supports(request.version) {
                    Ok(ForwardOffer {
                        publication: publication.endpoint,
                        publication_handle: publication.handle,
                        service_generation: publication.service_generation,
                        client_transaction: transaction,
                    })
                } else {
                    Err(RegistryError::UnsupportedVersion)
                }
            });
        self.clients[client_index]
            .as_mut()
            .unwrap()
            .complete(transaction);
        result
    }

    pub fn watch(
        &mut self,
        client: EndpointIdentity,
        transaction: u64,
        request: Watch<'_>,
    ) -> Result<WatchDisposition, RegistryError> {
        let client_index = self.client_index(client)?;
        self.clients[client_index]
            .as_mut()
            .unwrap()
            .reserve(transaction)?;
        let current = self.current_generation(request.protocol_id, request.service_name);
        if current != request.last_observed_generation {
            self.clients[client_index]
                .as_mut()
                .unwrap()
                .complete(transaction);
            return Ok(WatchDisposition::Immediate {
                service_generation: current,
            });
        }
        let per_client = self
            .watches
            .iter()
            .flatten()
            .filter(|watch| watch.client == client)
            .count();
        let Some(index) = self.watches.iter().position(Option::is_none) else {
            self.clients[client_index]
                .as_mut()
                .unwrap()
                .complete(transaction);
            return Err(RegistryError::Capacity);
        };
        if per_client == MAX_OUTSTANDING_PER_CLIENT {
            self.clients[client_index]
                .as_mut()
                .unwrap()
                .complete(transaction);
            return Err(RegistryError::Capacity);
        }
        let mut name = [0; MAX_SERVICE_NAME_BYTES];
        name[..request.service_name.len()].copy_from_slice(request.service_name);
        self.watches[index] = Some(PendingWatch {
            client,
            client_handle: self.clients[client_index].as_ref().unwrap().handle,
            transaction,
            protocol_id: request.protocol_id,
            last_generation: request.last_observed_generation,
            name,
            name_len: request.service_name.len() as u8,
        });
        Ok(WatchDisposition::Pending)
    }

    pub fn cancel(
        &mut self,
        client: EndpointIdentity,
        transaction: u64,
        target: u64,
    ) -> Result<(), RegistryError> {
        let client_index = self.client_index(client)?;
        self.clients[client_index]
            .as_mut()
            .unwrap()
            .reserve(transaction)?;
        let target_index = self.watches.iter().position(|watch| {
            watch
                .as_ref()
                .is_some_and(|watch| watch.client == client && watch.transaction == target)
        });
        if let Some(target_index) = target_index {
            self.watches[target_index] = None;
            let client = self.clients[client_index].as_mut().unwrap();
            client.complete(target);
            client.complete(transaction);
            Ok(())
        } else {
            self.clients[client_index]
                .as_mut()
                .unwrap()
                .complete(transaction);
            Err(RegistryError::UnknownTransaction)
        }
    }

    pub fn enumerate_begin(
        &mut self,
        client: EndpointIdentity,
        transaction: u64,
    ) -> Result<EnumerationTicket, RegistryError> {
        let index = self.client_index(client)?;
        if self.clients[index].as_ref().unwrap().scope != EnumerationScope::BootstrapMetadata {
            self.clients[index].as_mut().unwrap().reserve(transaction)?;
            self.clients[index].as_mut().unwrap().complete(transaction);
            return Err(RegistryError::EnumerationDenied);
        }
        self.clients[index].as_mut().unwrap().reserve(transaction)?;
        let total_count = self.published_count() as u16;
        let page_count = if total_count == 0 {
            1
        } else {
            total_count.div_ceil(2)
        };
        debug_assert!(usize::from(page_count) <= MAX_SERVICE_LIST_PAGES);
        Ok(EnumerationTicket {
            client,
            transaction,
            total_count,
            page_count,
        })
    }

    pub fn enumeration_record(
        &self,
        ticket: EnumerationTicket,
        index: usize,
    ) -> Result<Option<ServiceMetadata>, RegistryError> {
        let client_index = self.client_index(ticket.client)?;
        if !self.clients[client_index]
            .as_ref()
            .unwrap()
            .live_transactions[..self.clients[client_index].as_ref().unwrap().live_count]
            .contains(&ticket.transaction)
        {
            return Err(RegistryError::UnknownTransaction);
        }
        Ok(nth_canonical(&self.services, index).and_then(ServiceSlot::metadata))
    }

    pub fn enumeration_complete(&mut self, ticket: EnumerationTicket) -> Result<(), RegistryError> {
        let index = self.client_index(ticket.client)?;
        if !self.clients[index].as_ref().unwrap().live_transactions
            [..self.clients[index].as_ref().unwrap().live_count]
            .contains(&ticket.transaction)
        {
            return Err(RegistryError::UnknownTransaction);
        }
        self.clients[index]
            .as_mut()
            .unwrap()
            .complete(ticket.transaction);
        Ok(())
    }

    pub fn complete_transaction(
        &mut self,
        endpoint: EndpointIdentity,
        kind: EndpointKind,
        transaction: u64,
    ) -> Result<(), RegistryError> {
        match kind {
            EndpointKind::Client => {
                let index = self.client_index(endpoint)?;
                self.clients[index].as_mut().unwrap().reserve(transaction)?;
                self.clients[index].as_mut().unwrap().complete(transaction);
            }
            EndpointKind::Publication => {
                let index = self.publication_index(endpoint)?;
                let publication = self.services[index]
                    .as_mut()
                    .unwrap()
                    .active
                    .as_mut()
                    .unwrap();
                publication_reserve(publication, transaction)?;
                publication_complete(publication, transaction);
            }
        }
        Ok(())
    }

    pub fn peer_closed(
        &mut self,
        endpoint: EndpointIdentity,
    ) -> Result<PeerCloseOutcome, RegistryError> {
        if let Ok(index) = self.publication_index(endpoint) {
            let slot = self.services[index].as_mut().unwrap();
            let publication = slot.active.take().unwrap();
            let name = slot.name;
            let name_len = slot.name_len;
            let notifications =
                self.notify(publication.protocol_id, &name[..usize::from(name_len)], 0);
            return Ok(PeerCloseOutcome {
                handle: publication.handle,
                kind: EndpointKind::Publication,
                notifications,
            });
        }
        let index = self.client_index(endpoint)?;
        let client = self.clients[index].take().unwrap();
        for watch in &mut self.watches {
            if watch.as_ref().is_some_and(|watch| watch.client == endpoint) {
                *watch = None;
            }
        }
        Ok(PeerCloseOutcome {
            handle: client.handle,
            kind: EndpointKind::Client,
            notifications: WatchNotifications::new(),
        })
    }

    fn current_generation(&self, protocol_id: u64, name: &[u8]) -> u64 {
        self.services
            .iter()
            .flatten()
            .find_map(|slot| {
                let publication = slot.active?;
                (slot.name() == name
                    && publication.protocol_id == protocol_id
                    && publication.phase == PublicationPhase::Published)
                    .then_some(publication.service_generation)
            })
            .unwrap_or(0)
    }

    fn notify(&mut self, protocol_id: u64, name: &[u8], generation: u64) -> WatchNotifications {
        let mut notifications = WatchNotifications::new();
        for index in 0..self.watches.len() {
            let Some(watch) = self.watches[index] else {
                continue;
            };
            if watch.protocol_id == protocol_id
                && watch.name() == name
                && watch.last_generation != generation
            {
                if let Ok(client_index) = self.client_index(watch.client) {
                    self.clients[client_index]
                        .as_mut()
                        .unwrap()
                        .complete(watch.transaction);
                    notifications.push(WatchNotification {
                        client: watch.client,
                        client_handle: watch.client_handle,
                        transaction_id: watch.transaction,
                        service_generation: generation,
                    });
                }
                self.watches[index] = None;
            }
        }
        notifications
    }

    fn validate_install(
        &self,
        generation: u64,
        endpoint: EndpointIdentity,
        handle: u64,
    ) -> Result<(), RegistryError> {
        if generation != self.generation {
            return Err(RegistryError::WrongRegistryGeneration);
        }
        if endpoint.id == 0 || endpoint.generation == 0 || handle == 0 {
            return Err(RegistryError::ZeroIdentity);
        }
        Ok(())
    }

    fn validate_fresh_endpoint_id(&self, id: u64) -> Result<(), RegistryError> {
        if self.issued_endpoint_ids[..self.issued_endpoint_count].contains(&id) {
            return Err(RegistryError::DuplicateEndpoint);
        }
        if self.issued_endpoint_count == MAX_ISSUED_ENDPOINT_IDS {
            return Err(RegistryError::Capacity);
        }
        Ok(())
    }

    fn record_endpoint_id(&mut self, id: u64) {
        self.issued_endpoint_ids[self.issued_endpoint_count] = id;
        self.issued_endpoint_count += 1;
    }

    fn publication_index(&self, endpoint: EndpointIdentity) -> Result<usize, RegistryError> {
        let index = self
            .services
            .iter()
            .position(|slot| {
                slot.as_ref()
                    .and_then(|slot| slot.active)
                    .is_some_and(|publication| publication.endpoint.id == endpoint.id)
            })
            .ok_or(RegistryError::UnknownEndpoint)?;
        if self.services[index]
            .as_ref()
            .unwrap()
            .active
            .unwrap()
            .endpoint
            != endpoint
        {
            return Err(RegistryError::WrongEndpointGeneration);
        }
        Ok(index)
    }

    fn client_index(&self, endpoint: EndpointIdentity) -> Result<usize, RegistryError> {
        let index = self
            .clients
            .iter()
            .position(|client| {
                client
                    .as_ref()
                    .is_some_and(|client| client.endpoint.id == endpoint.id)
            })
            .ok_or(RegistryError::UnknownEndpoint)?;
        if self.clients[index].as_ref().unwrap().endpoint != endpoint {
            return Err(RegistryError::WrongEndpointGeneration);
        }
        Ok(index)
    }
}

fn publication_reserve(
    publication: &mut Publication,
    transaction: u64,
) -> Result<(), RegistryError> {
    if transaction == 0 {
        return Err(RegistryError::ZeroIdentity);
    }
    if publication.live_transaction == transaction {
        return Err(RegistryError::TransactionLive);
    }
    if publication.replay.contains(transaction) {
        return Err(RegistryError::TransactionReplay);
    }
    if publication.live_transaction != 0 {
        return Err(RegistryError::OutstandingLimit);
    }
    publication.live_transaction = transaction;
    Ok(())
}

fn publication_complete(publication: &mut Publication, transaction: u64) {
    debug_assert_eq!(publication.live_transaction, transaction);
    publication.live_transaction = 0;
    publication.replay.push(transaction);
}

fn nth_canonical(
    values: &[Option<ServiceSlot>; MAX_SERVICES],
    target: usize,
) -> Option<&ServiceSlot> {
    let mut previous: Option<&[u8]> = None;
    let mut selected = None;
    for _ in 0..=target {
        selected = values
            .iter()
            .flatten()
            .filter(|slot| slot.metadata().is_some())
            .filter(|slot| previous.is_none_or(|name| slot.name() > name))
            .min_by(|left, right| left.name().cmp(right.name()));
        previous = Some(selected?.name());
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrmroot_registry_proto::{
        Header, Message, MessageType, encode_install_publication, parse,
    };

    fn publication_install<'a>(
        bytes: &'a mut [u8],
        endpoint: EndpointIdentity,
        publication_id: u64,
        service_generation: u64,
        name: &[u8],
    ) -> InstallPublication<'a> {
        let size = encode_install_publication(
            Header {
                message_type: MessageType::InstallPublication,
                registry_generation: 7,
                endpoint_id: 0,
                endpoint_generation: 0,
                transaction_id: 1,
            },
            endpoint.id,
            endpoint.generation,
            1,
            publication_id,
            service_generation,
            17,
            &[ProtocolVersion { major: 1, minor: 0 }],
            name,
            bytes,
        )
        .unwrap();
        let parsed = parse(&bytes[..size], 1).unwrap();
        let Message::InstallPublication(value) = parsed.message else {
            panic!("wrong message")
        };
        value
    }

    fn install_client(
        state: &mut RegistryState,
        endpoint: EndpointIdentity,
        scope: EnumerationScope,
    ) {
        state
            .install_client(
                7,
                1000 + endpoint.id,
                InstallClient {
                    endpoint_id: endpoint.id,
                    endpoint_generation: endpoint.generation,
                    client_id: endpoint.id + 100,
                    client_generation: endpoint.generation,
                    scope,
                },
            )
            .unwrap();
    }

    #[test]
    fn tombstone_retire_allows_only_fresh_p2_and_cross_kind_ids_are_unique() {
        let mut state = RegistryState::new(7).unwrap();
        let p1 = EndpointIdentity {
            id: 31,
            generation: 1,
        };
        let mut bytes = [0u8; 256];
        state
            .install_publication(7, 101, publication_install(&mut bytes, p1, 11, 13, b"echo"))
            .unwrap();
        assert_eq!(
            state.install_client(
                7,
                102,
                InstallClient {
                    endpoint_id: 31,
                    endpoint_generation: 9,
                    client_id: 3,
                    client_generation: 1,
                    scope: EnumerationScope::None,
                }
            ),
            Err(RegistryError::DuplicateEndpoint)
        );
        assert_eq!(state.publish(p1, 1).unwrap().service_generation, 13);
        assert_eq!(state.retire(p1, 2).unwrap().registry_handle, 101);
        assert_eq!(state.published_count(), 0);
        assert_eq!(
            state.install_publication(
                7,
                102,
                publication_install(
                    &mut bytes,
                    EndpointIdentity {
                        id: p1.id,
                        generation: 2
                    },
                    12,
                    1,
                    b"other"
                )
            ),
            Err(RegistryError::DuplicateEndpoint)
        );
        assert_eq!(
            state.install_publication(
                7,
                102,
                publication_install(
                    &mut bytes,
                    EndpointIdentity {
                        id: 34,
                        generation: 1
                    },
                    11,
                    1,
                    b"other"
                )
            ),
            Err(RegistryError::DuplicatePublication)
        );
        let stale = EndpointIdentity {
            id: 32,
            generation: 1,
        };
        assert_eq!(
            state.install_publication(
                7,
                102,
                publication_install(&mut bytes, stale, 12, 13, b"echo")
            ),
            Err(RegistryError::StaleServiceGeneration)
        );
        let p2 = EndpointIdentity {
            id: 33,
            generation: 1,
        };
        state
            .install_publication(7, 103, publication_install(&mut bytes, p2, 13, 14, b"echo"))
            .unwrap();
        assert_eq!(state.publish(p2, 3).unwrap().service_generation, 14);
        assert_eq!(
            state.install_publication(
                7,
                104,
                publication_install(
                    &mut bytes,
                    EndpointIdentity {
                        id: p1.id,
                        generation: 9
                    },
                    99,
                    1,
                    b"third"
                )
            ),
            Err(RegistryError::DuplicateEndpoint)
        );
    }

    #[test]
    fn watches_notify_cancel_and_capacity_without_live_leaks() {
        let mut state = RegistryState::new(7).unwrap();
        let p = EndpointIdentity {
            id: 31,
            generation: 1,
        };
        let c = EndpointIdentity {
            id: 41,
            generation: 1,
        };
        let other = EndpointIdentity {
            id: 42,
            generation: 1,
        };
        let mut bytes = [0u8; 256];
        state
            .install_publication(7, 101, publication_install(&mut bytes, p, 11, 13, b"echo"))
            .unwrap();
        install_client(&mut state, c, EnumerationScope::None);
        install_client(&mut state, other, EnumerationScope::None);
        let watch = Watch {
            protocol_id: 17,
            last_observed_generation: 0,
            service_name: b"echo",
        };
        assert_eq!(state.watch(c, 10, watch), Ok(WatchDisposition::Pending));
        assert_eq!(state.watch(other, 10, watch), Ok(WatchDisposition::Pending));
        assert_eq!(state.cancel(c, 11, 10), Ok(()));
        assert_eq!(
            state.cancel(c, 12, 10),
            Err(RegistryError::UnknownTransaction)
        );
        assert_eq!(
            state.cancel(c, 12, 10),
            Err(RegistryError::TransactionReplay)
        );
        let outcome = state.publish(p, 1).unwrap();
        assert_eq!(outcome.notifications.len(), 1);
        assert_eq!(outcome.notifications.get(0).unwrap().client, other);
        for transaction in 20..36 {
            assert_eq!(
                state.watch(
                    c,
                    transaction,
                    Watch {
                        last_observed_generation: 13,
                        ..watch
                    }
                ),
                Ok(WatchDisposition::Pending)
            );
        }
        assert_eq!(
            state.watch(
                c,
                36,
                Watch {
                    last_observed_generation: 13,
                    ..watch
                }
            ),
            Err(RegistryError::OutstandingLimit)
        );
    }

    #[test]
    fn enumeration_is_ticketed_sorted_and_replayed_only_on_complete() {
        let mut state = RegistryState::new(7).unwrap();
        let c = EndpointIdentity {
            id: 41,
            generation: 1,
        };
        install_client(&mut state, c, EnumerationScope::BootstrapMetadata);
        let mut bytes = [0u8; 256];
        for (id, name) in [(31, b"zeta".as_slice()), (32, b"alpha"), (33, b"middle")] {
            let p = EndpointIdentity { id, generation: 1 };
            state
                .install_publication(
                    7,
                    100 + id,
                    publication_install(&mut bytes, p, id, id, name),
                )
                .unwrap();
            state.publish(p, id).unwrap();
        }
        let ticket = state.enumerate_begin(c, 77).unwrap();
        assert_eq!((ticket.total_count, ticket.page_count), (3, 2));
        assert_eq!(
            state.enumeration_record(ticket, 0).unwrap().unwrap().name(),
            b"alpha"
        );
        assert_eq!(
            state.enumeration_record(ticket, 2).unwrap().unwrap().name(),
            b"zeta"
        );
        assert_eq!(
            state.enumerate_begin(c, 77),
            Err(RegistryError::TransactionLive)
        );
        state.enumeration_complete(ticket).unwrap();
        assert_eq!(
            state.enumerate_begin(c, 77),
            Err(RegistryError::TransactionReplay)
        );
    }

    #[test]
    fn peer_cleanup_removes_client_watches_and_publication_notifies_absence() {
        let mut state = RegistryState::new(7).unwrap();
        let p = EndpointIdentity {
            id: 31,
            generation: 1,
        };
        let c = EndpointIdentity {
            id: 41,
            generation: 1,
        };
        let mut bytes = [0u8; 256];
        state
            .install_publication(7, 101, publication_install(&mut bytes, p, 11, 13, b"echo"))
            .unwrap();
        install_client(&mut state, c, EnumerationScope::None);
        state.publish(p, 1).unwrap();
        state
            .watch(
                c,
                3,
                Watch {
                    protocol_id: 17,
                    last_observed_generation: 13,
                    service_name: b"echo",
                },
            )
            .unwrap();
        let closed = state.peer_closed(p).unwrap();
        assert_eq!(closed.kind, EndpointKind::Publication);
        assert_eq!(closed.notifications.get(0).unwrap().service_generation, 0);
        assert_eq!(state.peer_closed(c).unwrap().kind, EndpointKind::Client);
        assert_eq!(state.pending_watch_count(), 0);
    }

    #[test]
    fn global_watch_pool_and_issued_client_ids_are_generation_lifetime_bounded() {
        let mut state = RegistryState::new(7).unwrap();
        let clients = [
            EndpointIdentity {
                id: 41,
                generation: 1,
            },
            EndpointIdentity {
                id: 42,
                generation: 1,
            },
            EndpointIdentity {
                id: 43,
                generation: 1,
            },
        ];
        for client in clients {
            install_client(&mut state, client, EnumerationScope::None);
        }
        let request = Watch {
            protocol_id: 17,
            last_observed_generation: 0,
            service_name: b"echo",
        };
        for transaction in 1..=16 {
            state.watch(clients[0], transaction, request).unwrap();
            state.watch(clients[1], transaction, request).unwrap();
        }
        assert_eq!(state.pending_watch_count(), 32);
        assert_eq!(
            state.watch(clients[2], 1, request),
            Err(RegistryError::Capacity)
        );
        assert_eq!(
            state.watch(clients[2], 1, request),
            Err(RegistryError::TransactionReplay)
        );
        let closed = state.peer_closed(clients[2]).unwrap();
        assert_eq!(closed.kind, EndpointKind::Client);
        assert_eq!(
            state.install_client(
                7,
                999,
                InstallClient {
                    endpoint_id: 99,
                    endpoint_generation: 1,
                    client_id: clients[2].id + 100,
                    client_generation: 2,
                    scope: EnumerationScope::None,
                }
            ),
            Err(RegistryError::DuplicateClient)
        );
    }

    #[test]
    fn thirty_two_services_enumerate_in_raw_name_order() {
        let mut state = RegistryState::new(7).unwrap();
        let client = EndpointIdentity {
            id: 90,
            generation: 1,
        };
        install_client(&mut state, client, EnumerationScope::BootstrapMetadata);
        let mut bytes = [0u8; 256];
        for index in (0..32u64).rev() {
            let name = [b's', b'0' + (index / 10) as u8, b'0' + (index % 10) as u8];
            let publication = EndpointIdentity {
                id: index + 1,
                generation: 1,
            };
            state
                .install_publication(
                    7,
                    1000 + index,
                    publication_install(&mut bytes, publication, 100 + index, 1 + index, &name),
                )
                .unwrap();
            state.publish(publication, 1).unwrap();
        }
        let ticket = state.enumerate_begin(client, 77).unwrap();
        assert_eq!((ticket.total_count, ticket.page_count), (32, 16));
        for index in 0..32usize {
            let expected = [b's', b'0' + (index / 10) as u8, b'0' + (index % 10) as u8];
            assert_eq!(
                state
                    .enumeration_record(ticket, index)
                    .unwrap()
                    .unwrap()
                    .name(),
                expected
            );
        }
        state.enumeration_complete(ticket).unwrap();
    }
}
