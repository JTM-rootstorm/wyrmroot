//! Resident, allocation-free WYR1 bootstrap registry state.
//!
//! This process owns only controller-installed registry endpoints and direct
//! endpoint routing. It has no loader, task, filesystem, device, or supervisor
//! authority.

#![no_std]
#![forbid(unsafe_code)]

use wyrmroot_registry_proto::{
    EnumerationScope, InstallClient, InstallPublication, Lookup, MAX_CLIENT_REPLAY,
    MAX_OUTSTANDING_PER_CLIENT, MAX_PROTOCOL_VERSIONS, MAX_PUBLICATION_REPLAY,
    MAX_SERVICE_NAME_BYTES, MAX_SERVICES, ProtocolVersion, Watch,
};

const MAX_CLIENTS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointIdentity {
    pub id: u64,
    pub generation: u64,
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchDisposition {
    Immediate { service_generation: u64 },
    Pending,
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
struct Publication {
    endpoint: EndpointIdentity,
    handle: u64,
    role_id: u32,
    publication_id: u64,
    service_generation: u64,
    protocol_id: u64,
    versions: [ProtocolVersion; MAX_PROTOCOL_VERSIONS],
    version_count: u8,
    name: [u8; MAX_SERVICE_NAME_BYTES],
    name_len: u8,
    published: bool,
    live_transaction: u64,
    replay: Replay<MAX_PUBLICATION_REPLAY>,
}

impl Publication {
    fn name(&self) -> &[u8] {
        &self.name[..usize::from(self.name_len)]
    }
    fn supports(&self, version: ProtocolVersion) -> bool {
        self.versions[..usize::from(self.version_count)].contains(&version)
    }
    fn metadata(&self) -> ServiceMetadata {
        ServiceMetadata {
            name: self.name,
            name_len: self.name_len,
            protocol_id: self.protocol_id,
            versions: self.versions,
            version_count: self.version_count,
            service_generation: self.service_generation,
        }
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
        let index = self.live_transactions[..self.live_count]
            .iter()
            .position(|value| *value == transaction)
            .expect("reserved client transaction");
        self.live_count -= 1;
        self.live_transactions[index] = self.live_transactions[self.live_count];
        self.live_transactions[self.live_count] = 0;
        self.replay.push(transaction);
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct RegistryState {
    generation: u64,
    publications: [Option<Publication>; MAX_SERVICES],
    clients: [Option<Client>; MAX_CLIENTS],
}

impl RegistryState {
    pub fn new(generation: u64) -> Result<Self, RegistryError> {
        if generation == 0 {
            return Err(RegistryError::ZeroIdentity);
        }
        Ok(Self {
            generation,
            publications: [None; MAX_SERVICES],
            clients: [None; MAX_CLIENTS],
        })
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub fn published_count(&self) -> usize {
        self.publications
            .iter()
            .flatten()
            .filter(|slot| slot.published)
            .count()
    }

    pub fn install_publication(
        &mut self,
        registry_generation: u64,
        endpoint: EndpointIdentity,
        handle: u64,
        install: InstallPublication<'_>,
    ) -> Result<(), RegistryError> {
        self.validate_install(registry_generation, endpoint, handle)?;
        if self
            .publications
            .iter()
            .flatten()
            .any(|slot| slot.endpoint == endpoint)
        {
            return Err(RegistryError::DuplicateEndpoint);
        }
        if self
            .publications
            .iter()
            .flatten()
            .any(|slot| slot.publication_id == install.publication_id)
        {
            return Err(RegistryError::DuplicatePublication);
        }
        if self
            .publications
            .iter()
            .flatten()
            .any(|slot| slot.name() == install.service_name)
        {
            return Err(RegistryError::DuplicateService);
        }
        let index = self
            .publications
            .iter()
            .position(Option::is_none)
            .ok_or(RegistryError::Capacity)?;
        let mut name = [0; MAX_SERVICE_NAME_BYTES];
        name[..install.service_name.len()].copy_from_slice(install.service_name);
        let mut versions = [ProtocolVersion::default(); MAX_PROTOCOL_VERSIONS];
        for (index, target) in versions.iter_mut().take(install.versions.len()).enumerate() {
            *target = install.versions.get(index).expect("validated version list");
        }
        self.publications[index] = Some(Publication {
            endpoint,
            handle,
            role_id: install.supervisor_role_id,
            publication_id: install.publication_id,
            service_generation: install.service_generation,
            protocol_id: install.protocol_id,
            versions,
            version_count: install.versions.len() as u8,
            name,
            name_len: install.service_name.len() as u8,
            published: false,
            live_transaction: 0,
            replay: Replay::new(),
        });
        Ok(())
    }

    pub fn install_client(
        &mut self,
        registry_generation: u64,
        endpoint: EndpointIdentity,
        handle: u64,
        install: InstallClient,
    ) -> Result<(), RegistryError> {
        self.validate_install(registry_generation, endpoint, handle)?;
        if self
            .clients
            .iter()
            .flatten()
            .any(|slot| slot.endpoint == endpoint)
        {
            return Err(RegistryError::DuplicateEndpoint);
        }
        if self
            .clients
            .iter()
            .flatten()
            .any(|slot| slot.client_id == install.client_id)
        {
            return Err(RegistryError::DuplicateClient);
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
        Ok(())
    }

    pub fn publish(
        &mut self,
        endpoint: EndpointIdentity,
        transaction: u64,
    ) -> Result<u64, RegistryError> {
        let publication = self.publication_mut(endpoint)?;
        publication_transaction(publication, transaction)?;
        publication.published = true;
        publication.replay.push(transaction);
        Ok(publication.service_generation)
    }

    pub fn retire(
        &mut self,
        endpoint: EndpointIdentity,
        transaction: u64,
    ) -> Result<u64, RegistryError> {
        let publication = self.publication_mut(endpoint)?;
        publication_transaction(publication, transaction)?;
        publication.published = false;
        publication.replay.push(transaction);
        Ok(publication.service_generation)
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
            .publications
            .iter()
            .flatten()
            .find(|slot| {
                slot.published
                    && slot.protocol_id == request.protocol_id
                    && slot.name() == request.service_name
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
        let current = self
            .publications
            .iter()
            .flatten()
            .find(|slot| {
                slot.published
                    && slot.protocol_id == request.protocol_id
                    && slot.name() == request.service_name
            })
            .map_or(0, |slot| slot.service_generation);
        if current != request.last_observed_generation {
            self.clients[client_index]
                .as_mut()
                .unwrap()
                .complete(transaction);
            Ok(WatchDisposition::Immediate {
                service_generation: current,
            })
        } else {
            Ok(WatchDisposition::Pending)
        }
    }

    pub fn cancel(
        &mut self,
        client: EndpointIdentity,
        transaction: u64,
        target: u64,
    ) -> Result<(), RegistryError> {
        let index = self.client_index(client)?;
        let client = self.clients[index].as_mut().unwrap();
        client.reserve(transaction)?;
        let target_index = client.live_transactions[..client.live_count]
            .iter()
            .position(|value| *value == target)
            .ok_or(RegistryError::UnknownEndpoint)?;
        client.live_count -= 1;
        client.live_transactions[target_index] = client.live_transactions[client.live_count];
        client.replay.push(target);
        client.complete(transaction);
        Ok(())
    }

    pub fn enumerate(
        &mut self,
        client: EndpointIdentity,
        transaction: u64,
        index: usize,
    ) -> Result<Option<ServiceMetadata>, RegistryError> {
        let client_index = self.client_index(client)?;
        let client = self.clients[client_index].as_mut().unwrap();
        if client.scope != EnumerationScope::BootstrapMetadata {
            return Err(RegistryError::EnumerationDenied);
        }
        client.reserve(transaction)?;
        let result = nth_canonical(&self.publications, index).map(Publication::metadata);
        self.clients[client_index]
            .as_mut()
            .unwrap()
            .complete(transaction);
        Ok(result)
    }

    pub fn peer_closed(&mut self, endpoint: EndpointIdentity) -> Result<u64, RegistryError> {
        if let Some(index) = self
            .publications
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|slot| slot.endpoint == endpoint))
        {
            let handle = self.publications[index].take().unwrap().handle;
            return Ok(handle);
        }
        if let Some(index) = self
            .clients
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|slot| slot.endpoint == endpoint))
        {
            let handle = self.clients[index].take().unwrap().handle;
            return Ok(handle);
        }
        Err(RegistryError::UnknownEndpoint)
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

    fn publication_mut(
        &mut self,
        endpoint: EndpointIdentity,
    ) -> Result<&mut Publication, RegistryError> {
        self.publications
            .iter_mut()
            .flatten()
            .find(|slot| slot.endpoint.id == endpoint.id)
            .ok_or(RegistryError::UnknownEndpoint)
            .and_then(|slot| {
                if slot.endpoint == endpoint {
                    Ok(slot)
                } else {
                    Err(RegistryError::WrongEndpointGeneration)
                }
            })
    }

    fn client_index(&self, endpoint: EndpointIdentity) -> Result<usize, RegistryError> {
        let index = self
            .clients
            .iter()
            .position(|slot| {
                slot.as_ref()
                    .is_some_and(|slot| slot.endpoint.id == endpoint.id)
            })
            .ok_or(RegistryError::UnknownEndpoint)?;
        if self.clients[index].as_ref().unwrap().endpoint != endpoint {
            return Err(RegistryError::WrongEndpointGeneration);
        }
        Ok(index)
    }
}

fn publication_transaction(
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
    publication.live_transaction = transaction;
    publication.live_transaction = 0;
    Ok(())
}

fn nth_canonical(
    values: &[Option<Publication>; MAX_SERVICES],
    target: usize,
) -> Option<&Publication> {
    let mut previous: Option<&[u8]> = None;
    let mut selected = None;
    for _ in 0..=target {
        selected = values
            .iter()
            .flatten()
            .filter(|value| value.published)
            .filter(|value| previous.is_none_or(|name| value.name() > name))
            .min_by(|left, right| left.name().cmp(right.name()));
        previous = Some(selected?.name());
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrmroot_registry_proto::{
        Header, Message, MessageType, ProtocolVersion, encode_install_publication, parse,
    };

    fn install<'a>(bytes: &'a mut [u8]) -> InstallPublication<'a> {
        let header = Header {
            message_type: MessageType::InstallPublication,
            registry_generation: 7,
            endpoint_id: 0,
            endpoint_generation: 0,
            transaction_id: 1,
        };
        let size = encode_install_publication(
            header,
            1,
            11,
            13,
            17,
            &[ProtocolVersion { major: 1, minor: 0 }],
            b"org.wyrmroot.echo",
            bytes,
        )
        .unwrap();
        let parsed = parse(&bytes[..size], 1).unwrap();
        let Message::InstallPublication(value) = parsed.message else {
            panic!("wrong message")
        };
        value
    }

    #[test]
    fn controller_install_publish_direct_lookup_and_retire_are_generation_exact() {
        let mut state = RegistryState::new(7).unwrap();
        let publication = EndpointIdentity {
            id: 31,
            generation: 1,
        };
        let client = EndpointIdentity {
            id: 41,
            generation: 1,
        };
        let mut bytes = [0u8; 160];
        state
            .install_publication(7, publication, 101, install(&mut bytes))
            .unwrap();
        state
            .install_client(
                7,
                client,
                102,
                InstallClient {
                    client_id: 3,
                    client_generation: 1,
                    scope: EnumerationScope::BootstrapMetadata,
                },
            )
            .unwrap();
        assert_eq!(state.publish(publication, 5), Ok(13));
        let lookup = Lookup {
            protocol_id: 17,
            version: ProtocolVersion { major: 1, minor: 0 },
            service_name: b"org.wyrmroot.echo",
        };
        assert_eq!(
            state.lookup(client, 7, lookup).unwrap().publication_handle,
            101
        );
        assert_eq!(state.retire(publication, 9), Ok(13));
        assert_eq!(
            state.lookup(client, 8, lookup),
            Err(RegistryError::NotPublished)
        );
        assert_eq!(
            state.publish(
                EndpointIdentity {
                    generation: 2,
                    ..publication
                },
                10
            ),
            Err(RegistryError::WrongEndpointGeneration)
        );
    }

    #[test]
    fn replays_duplicates_and_enumeration_authority_fail_closed() {
        let mut state = RegistryState::new(7).unwrap();
        let publication = EndpointIdentity {
            id: 31,
            generation: 1,
        };
        let mut bytes = [0u8; 160];
        state
            .install_publication(7, publication, 101, install(&mut bytes))
            .unwrap();
        assert_eq!(state.publish(publication, 5), Ok(13));
        assert_eq!(
            state.publish(publication, 5),
            Err(RegistryError::TransactionReplay)
        );
        let client = EndpointIdentity {
            id: 41,
            generation: 1,
        };
        state
            .install_client(
                7,
                client,
                102,
                InstallClient {
                    client_id: 3,
                    client_generation: 1,
                    scope: EnumerationScope::None,
                },
            )
            .unwrap();
        assert_eq!(
            state.enumerate(client, 7, 0),
            Err(RegistryError::EnumerationDenied)
        );
        assert_eq!(state.peer_closed(publication), Ok(101));
        assert_eq!(state.published_count(), 0);
    }
}
