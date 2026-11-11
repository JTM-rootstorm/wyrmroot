//! The common life of a bootfs service role (root `STORAGE_PLAN.md` W6):
//! startup, init's WRSV stage, registry publication and offers, and registry
//! lookups that wait for a dependency to be published.
//!
//! Every failure is a distinct step number the caller folds into its exit
//! code. Received handles are owned by the returned values as soon as they
//! arrive, so a caller that exits on an error leaves nothing behind but what
//! process exit reclaims.

#![no_std]
#![forbid(unsafe_code)]

pub mod block;
pub mod memory;

use deepwyrm_syscall::{
    DW_HANDLE_INVALID, DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_ADDRESS_REGION,
    DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_TRANSFER, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE,
    DwDeadline, DwHandle, DwHandleTransferV1, DwObjectType, DwReceivedHandleInfoV1, DwRights,
    DwSignals, DwWaitItemV1,
};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, DEVICE_DRIVER_BYTES, SELF_ROOT_RIGHTS, parse_device_driver_init,
};
use wyrmroot_registry_proto::{
    HEADER_BYTES as REGISTRY_HEADER_BYTES, Header as RegistryHeader, Lookup,
    Message as RegistryMessage, MessageType as RegistryMessageType, ProtocolVersion, Watch,
    encode_empty, encode_lookup, encode_watch, parse as parse_registry,
};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, ChannelPlatform, ClockPlatform, HandlePlatform, WaitPlatform,
    validate_bootstrap_channel,
};
use wyrmroot_service_proto::{self as wrsv, Client, MAX_CHANNELS, MAX_LABEL_BYTES, Publication};

/// The platform traits a service role uses.
pub trait ServicePlatform: HandlePlatform + ChannelPlatform + WaitPlatform + ClockPlatform {}
impl<P> ServicePlatform for P where
    P: HandlePlatform + ChannelPlatform + WaitPlatform + ClockPlatform + ?Sized
{
}

pub use wyrmroot_service_proto::roles::ServiceName;

fn lookup(service: &ServiceName) -> Lookup<'static> {
    Lookup {
        protocol_id: service.protocol_id,
        version: ProtocolVersion {
            major: service.major,
            minor: service.minor,
        },
        service_name: service.name,
    }
}

/// The rights a lookup's Channel end carries to the registry, which moves
/// it on once more to the publisher with [`CHILD_CHANNEL_RIGHTS`].
pub const CONNECT_RIGHTS: DwRights = DwRights(CHILD_CHANNEL_RIGHTS.0 | DW_RIGHT_TRANSFER.0);
/// The rights a node Channel's server end carries in every WRFS or WRNS
/// OPEN: a Channel endpoint's rights plus TRANSFER, so whoever receives it
/// can pass it on unchanged (vfsd forwards it to a filesystem).
pub const OPEN_CHANNEL_RIGHTS: DwRights = CONNECT_RIGHTS;
/// The rights of a filesystem root Channel vfsd keeps for a mount.
pub const ROOT_CHANNEL_RIGHTS: DwRights = CHILD_CHANNEL_RIGHTS;
const READABLE_OR_CLOSED: DwSignals = DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0);
const REGISTRY_MESSAGE_BYTES: usize = 512;

/// What the loader's INIT handed the role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Launch {
    pub self_root: DwHandle,
    /// Init's control Channel: STAGE arrives on it, and its closure asks the
    /// role to retire.
    pub control: DwHandle,
    pub role_id: u64,
    pub attempt_generation: u64,
}

/// A staged role Channel: its slot, flags, label and handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagedChannel {
    pub slot: u32,
    pub flags: u32,
    label: [u8; MAX_LABEL_BYTES],
    label_len: usize,
    pub handle: DwHandle,
}

impl StagedChannel {
    pub fn label(&self) -> &[u8] {
        &self.label[..self.label_len]
    }
}

/// Everything STAGE delivered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Staged {
    pub publication: Option<(DwHandle, Publication)>,
    pub client: Option<(DwHandle, Client)>,
    channels: [Option<StagedChannel>; MAX_CHANNELS],
}

impl Staged {
    pub fn channels(&self) -> impl Iterator<Item = &StagedChannel> {
        self.channels.iter().flatten()
    }

    /// The one channel in `slot`, if exactly one was staged there.
    pub fn slot(&self, slot: u32) -> Option<&StagedChannel> {
        let mut found = self.channels().filter(|channel| channel.slot == slot);
        let first = found.next()?;
        found.next().is_none().then_some(first)
    }
}

fn admitted(info: DwReceivedHandleInfoV1, object_type: DwObjectType, rights: DwRights) -> bool {
    info.handle != DW_HANDLE_INVALID
        && info.object_type == object_type
        && info.rights == rights
        && info.reserved0 == 0
        && info.reserved == [0; 2]
}

pub(crate) fn close_all<P: ServicePlatform + ?Sized>(
    platform: &mut P,
    handles: &[DwReceivedHandleInfoV1],
) {
    for info in handles {
        let _ = platform.close_handle(info.handle);
    }
}

/// Waits until `handle` is readable; peer closure or the deadline is `step`.
pub fn wait_readable<P: ServicePlatform + ?Sized>(
    platform: &mut P,
    handle: DwHandle,
    deadline: DwDeadline,
    step: u32,
) -> Result<(), u32> {
    let observed = platform
        .wait_many(
            core::slice::from_ref(&DwWaitItemV1 {
                handle,
                signals: READABLE_OR_CLOSED,
            }),
            deadline,
        )
        .map_err(|_| step)?;
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(step);
    }
    Ok(())
}

/// Receives the loader's INIT: the self root and init's control Channel.
/// Steps 1..=5.
pub fn startup<P: ServicePlatform + ?Sized>(
    platform: &mut P,
    bootstrap: DwHandle,
) -> Result<Launch, u32> {
    validate_bootstrap_channel(
        platform
            .query_capability_info(bootstrap)
            .map_err(|_| 1u32)?,
        BOOTSTRAP_CHANNEL_EXPECTATION,
    )
    .map_err(|_| 2u32)?;
    let mut bytes = [0; DEVICE_DRIVER_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 2];
    let counts = platform
        .receive_channel(bootstrap, &mut bytes, &mut handles)
        .map_err(|_| 3u32)?;
    let received = &handles[..counts.handles.min(2)];
    if counts.bytes != DEVICE_DRIVER_BYTES
        || counts.handles != 2
        || !admitted(handles[0], DW_OBJECT_TYPE_ADDRESS_REGION, SELF_ROOT_RIGHTS)
        || !admitted(handles[1], DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS)
    {
        close_all(platform, received);
        return Err(4);
    }
    let Ok(init) = parse_device_driver_init(&bytes, &handles) else {
        close_all(platform, received);
        return Err(5);
    };
    Ok(Launch {
        self_root: handles[0].handle,
        control: handles[1].handle,
        role_id: init.role_id,
        attempt_generation: init.attempt_generation,
    })
}

/// Receives init's STAGE for `launch` within `deadline`. Steps 10..=15.
pub fn receive_stage<P: ServicePlatform + ?Sized>(
    platform: &mut P,
    launch: &Launch,
    deadline: DwDeadline,
) -> Result<Staged, u32> {
    wait_readable(platform, launch.control, deadline, 10)?;
    let mut bytes = [0u8; wrsv::MAX_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); wrsv::MAX_HANDLES];
    let counts = platform
        .receive_channel(launch.control, &mut bytes, &mut handles)
        .map_err(|_| 11u32)?;
    let received = &handles[..counts.handles.min(wrsv::MAX_HANDLES)];
    let refuse = |platform: &mut P, step: u32| {
        close_all(platform, received);
        Err(step)
    };
    let Ok(stage) = wrsv::parse(&bytes[..counts.bytes.min(bytes.len())], counts.handles) else {
        return refuse(platform, 12);
    };
    if stage.role_id != launch.role_id || stage.attempt_generation != launch.attempt_generation {
        return refuse(platform, 13);
    }
    if !received
        .iter()
        .all(|&info| admitted(info, DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS))
    {
        return refuse(platform, 14);
    }
    let mut next = 0;
    let mut take = || {
        let handle = received[next].handle;
        next += 1;
        handle
    };
    let publication = stage.publication.map(|grant| (take(), grant));
    let client = stage.client.map(|client| (take(), client));
    let mut channels = [None; MAX_CHANNELS];
    for (slot, channel) in channels.iter_mut().zip(stage.channels()) {
        let mut label = [0u8; MAX_LABEL_BYTES];
        label[..channel.label.len()].copy_from_slice(channel.label);
        *slot = Some(StagedChannel {
            slot: channel.slot,
            flags: channel.flags,
            label,
            label_len: channel.label.len(),
            handle: take(),
        });
    }
    if next != received.len() {
        return refuse(platform, 15);
    }
    Ok(Staged {
        publication,
        client,
        channels,
    })
}

/// Publishes the installed service and waits for PUBLISHED. Steps 20..=27.
pub fn publish<P: ServicePlatform + ?Sized>(
    platform: &mut P,
    endpoint: DwHandle,
    grant: Publication,
    deadline: DwDeadline,
) -> Result<(), u32> {
    let header = RegistryHeader {
        message_type: RegistryMessageType::Publish,
        registry_generation: grant.registry_generation,
        endpoint_id: grant.endpoint_id,
        endpoint_generation: grant.endpoint_generation,
        transaction_id: grant.transaction_id,
    };
    let mut bytes = [0u8; REGISTRY_HEADER_BYTES];
    let size = encode_empty(header, &mut bytes).map_err(|_| 20u32)?;
    platform
        .send_channel(endpoint, &bytes[..size], &[])
        .map_err(|_| 21u32)?;
    wait_readable(platform, endpoint, deadline, 22)?;
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(endpoint, &mut bytes, &mut handles)
        .map_err(|_| 23u32)?;
    if counts.handles != 0 {
        close_all(platform, &handles[..counts.handles.min(1)]);
        return Err(24);
    }
    let parsed = parse_registry(&bytes[..counts.bytes], 0).map_err(|_| 25u32)?;
    if parsed.header
        != (RegistryHeader {
            message_type: RegistryMessageType::Published,
            ..header
        })
        || parsed.message != RegistryMessage::Published
    {
        return Err(26);
    }
    Ok(())
}

/// Receives one registry message on a publication endpoint: a connection
/// offer for `service` yields the new connection; anything else that parses
/// is refused (its handles closed) with `Ok(None)`. Steps 30..=31 are
/// failures of the endpoint itself.
pub fn accept_offer<P: ServicePlatform + ?Sized>(
    platform: &mut P,
    endpoint: DwHandle,
    grant: Publication,
    service: ServiceName,
) -> Result<Option<DwHandle>, u32> {
    let mut bytes = [0u8; REGISTRY_MESSAGE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(endpoint, &mut bytes, &mut handles)
        .map_err(|_| 30u32)?;
    let received = &handles[..counts.handles.min(1)];
    let Ok(parsed) = parse_registry(&bytes[..counts.bytes.min(bytes.len())], counts.handles) else {
        close_all(platform, received);
        return Err(31);
    };
    let ours = matches!(parsed.message, RegistryMessage::ConnectOffer(lookup) if lookup == crate::lookup(&service))
        && parsed.header.message_type == RegistryMessageType::ConnectOffer
        && parsed.header.registry_generation == grant.registry_generation
        && parsed.header.endpoint_id == grant.endpoint_id
        && parsed.header.endpoint_generation == grant.endpoint_generation
        && received.len() == 1
        && admitted(received[0], DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS);
    if ours {
        Ok(Some(received[0].handle))
    } else {
        close_all(platform, received);
        Ok(None)
    }
}

/// A registry client endpoint and its next transaction.
pub struct Registry {
    pub endpoint: DwHandle,
    pub identity: Client,
    next_transaction: u64,
}

impl Registry {
    pub const fn new(endpoint: DwHandle, identity: Client) -> Self {
        Self {
            endpoint,
            identity,
            next_transaction: 1,
        }
    }

    fn header(&mut self, message_type: RegistryMessageType) -> RegistryHeader {
        let transaction_id = self.next_transaction;
        self.next_transaction += 1;
        RegistryHeader {
            message_type,
            registry_generation: self.identity.registry_generation,
            endpoint_id: self.identity.endpoint_id,
            endpoint_generation: self.identity.endpoint_generation,
            transaction_id,
        }
    }

    /// Receives the reply to `header`, which must be `reply` with no handles.
    fn expect<P: ServicePlatform + ?Sized>(
        &mut self,
        platform: &mut P,
        header: RegistryHeader,
        reply: RegistryMessageType,
        deadline: DwDeadline,
        step: u32,
    ) -> Result<(), u32> {
        wait_readable(platform, self.endpoint, deadline, step)?;
        let mut bytes = [0u8; REGISTRY_MESSAGE_BYTES];
        let mut handles = [DwReceivedHandleInfoV1::default(); 1];
        let counts = platform
            .receive_channel(self.endpoint, &mut bytes, &mut handles)
            .map_err(|_| step + 1)?;
        if counts.handles != 0 {
            close_all(platform, &handles[..counts.handles.min(1)]);
            return Err(step + 2);
        }
        let parsed =
            parse_registry(&bytes[..counts.bytes.min(bytes.len())], 0).map_err(|_| step + 3)?;
        if parsed.header
            != (RegistryHeader {
                message_type: reply,
                ..header
            })
        {
            return Err(step + 4);
        }
        Ok(())
    }

    /// Waits until `service` is published, then connects to it and returns
    /// the client's end of the new Channel. Steps 40..=59.
    pub fn connect<P: ServicePlatform + ?Sized>(
        &mut self,
        platform: &mut P,
        service: ServiceName,
        deadline: DwDeadline,
    ) -> Result<DwHandle, u32> {
        // A watch from generation zero answers at once when the service is
        // published and otherwise when it first is.
        let header = self.header(RegistryMessageType::Watch);
        let mut bytes = [0u8; REGISTRY_MESSAGE_BYTES];
        let size = encode_watch(
            header,
            Watch {
                protocol_id: service.protocol_id,
                last_observed_generation: 0,
                service_name: service.name,
            },
            &mut bytes,
        )
        .map_err(|_| 40u32)?;
        platform
            .send_channel(self.endpoint, &bytes[..size], &[])
            .map_err(|_| 41u32)?;
        self.expect(
            platform,
            header,
            RegistryMessageType::GenerationChanged,
            deadline,
            42,
        )?;

        let (direct, remote) = platform.create_channel(CONNECT_RIGHTS).map_err(|_| 50u32)?;
        let header = self.header(RegistryMessageType::LookupConnect);
        let size = match encode_lookup(header, lookup(&service), &mut bytes) {
            Ok(size) => size,
            Err(_) => {
                let _ = platform.close_handle(direct);
                let _ = platform.close_handle(remote);
                return Err(51);
            }
        };
        let transfer = DwHandleTransferV1 {
            handle: remote,
            requested_rights: CONNECT_RIGHTS,
            operation: DW_HANDLE_TRANSFER_MOVE,
            reserved0: 0,
            reserved: [0; 2],
        };
        if platform
            .send_channel(self.endpoint, &bytes[..size], &[transfer])
            .is_err()
        {
            let _ = platform.close_handle(direct);
            let _ = platform.close_handle(remote);
            return Err(52);
        }
        if let Err(step) = self.expect(
            platform,
            header,
            RegistryMessageType::Connected,
            deadline,
            53,
        ) {
            let _ = platform.close_handle(direct);
            return Err(step);
        }
        Ok(direct)
    }
}

#[cfg(test)]
mod tests;
