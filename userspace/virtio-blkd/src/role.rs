//! The virtio-blkd role: bootstrap, the publication grant, the one-message
//! WRDP device stage, publication, and the resident loop.
//!
//! Every refusal returns one distinct step number; the exit code is
//! [`FAILURE_BASE`] plus that step.

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_HANDLE_INVALID, DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL,
    DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwDeadline, DwHandle, DwReceivedHandleInfoV1,
    DwRights, DwSignals, DwWaitItemV1,
};
use wyrmroot_device_proto::pci_driver::{
    self, GRANT_BYTES, MAX_BYTES as WRDP_MAX_BYTES, PciDriverMessage, PublicationGrant, READY_BYTES,
};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, DEVICE_DRIVER_BYTES, SELF_ROOT_RIGHTS, parse_device_driver_init,
};
use wyrmroot_registry_proto::{
    HEADER_BYTES as REGISTRY_HEADER_BYTES, Header as RegistryHeader, Message as RegistryMessage,
    MessageType as RegistryMessageType, encode_empty as encode_registry_empty,
    parse as parse_registry,
};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, ChannelPlatform, ClockPlatform, DevicePlatform, HandlePlatform,
    WYR0_I_SUPERVISION_POLICY, WaitPlatform, validate_bootstrap_channel,
};

use crate::{
    LaunchCorrelation, PCI_CONFIG_IDS, admit_config_ids, admit_resource_info, admit_stage_handle,
    admit_stage_message,
};

pub const FAILURE_BASE: u32 = 0xB1D0_0000;
/// Room for any registry message the publication endpoint receives.
const REGISTRY_MESSAGE_BYTES: usize = 512;
const READABLE_OR_CLOSED: DwSignals = DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0);

/// The platform traits the role uses.
pub trait BlockPlatform:
    HandlePlatform + ChannelPlatform + WaitPlatform + ClockPlatform + DevicePlatform
{
}

impl<P> BlockPlatform for P where
    P: HandlePlatform + ChannelPlatform + WaitPlatform + ClockPlatform + DevicePlatform + ?Sized
{
}

/// The handles the role owns; [`Owned::close_all`] closes the live ones.
struct Owned {
    bootstrap: DwHandle,
    self_root: DwHandle,
    control: DwHandle,
    publication: DwHandle,
    resource: DwHandle,
}

impl Owned {
    fn close<P: BlockPlatform>(platform: &mut P, slot: &mut DwHandle) -> bool {
        let handle = core::mem::replace(slot, DW_HANDLE_INVALID);
        handle == DW_HANDLE_INVALID || platform.close_handle(handle).is_ok()
    }

    fn close_all<P: BlockPlatform>(&mut self, platform: &mut P) -> bool {
        let mut closed = true;
        for slot in [
            &mut self.resource,
            &mut self.publication,
            &mut self.control,
            &mut self.self_root,
            &mut self.bootstrap,
        ] {
            closed &= Self::close(platform, slot);
        }
        closed
    }
}

pub fn blk_main<P: BlockPlatform>(platform: &mut P, bootstrap: DwHandle) -> u32 {
    let mut owned = Owned {
        bootstrap,
        self_root: DW_HANDLE_INVALID,
        control: DW_HANDLE_INVALID,
        publication: DW_HANDLE_INVALID,
        resource: DW_HANDLE_INVALID,
    };
    let result = run(platform, &mut owned);
    let closed = owned.close_all(platform);
    match result {
        Ok(()) if closed => 0,
        Ok(()) => FAILURE_BASE | 0xff,
        Err(step) => FAILURE_BASE | step,
    }
}

fn run<P: BlockPlatform>(platform: &mut P, owned: &mut Owned) -> Result<(), u32> {
    let launch = startup(platform, owned)?;
    let grant = receive_grant(platform, owned)?;
    if !Owned::close(platform, &mut owned.bootstrap) {
        return Err(20);
    }
    stage(platform, owned, launch)?;
    publish(platform, owned.publication, grant)?;
    serve(platform, owned)
}

/// Receives the DeviceDriver INIT: the self root and the control Channel.
fn startup<P: BlockPlatform>(
    platform: &mut P,
    owned: &mut Owned,
) -> Result<LaunchCorrelation, u32> {
    validate_bootstrap_channel(
        platform
            .query_capability_info(owned.bootstrap)
            .map_err(|_| 1u32)?,
        BOOTSTRAP_CHANNEL_EXPECTATION,
    )
    .map_err(|_| 2u32)?;
    let mut bytes = [0; DEVICE_DRIVER_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 2];
    let counts = platform
        .receive_channel(owned.bootstrap, &mut bytes, &mut handles)
        .map_err(|_| 3u32)?;
    // Own whatever arrived before judging it, so every exit closes it.
    if counts.handles > 0 {
        owned.self_root = handles[0].handle;
    }
    if counts.handles > 1 {
        owned.control = handles[1].handle;
    }
    if counts.bytes != DEVICE_DRIVER_BYTES
        || counts.handles != 2
        || !valid_received(handles[0], DW_OBJECT_TYPE_ADDRESS_REGION, SELF_ROOT_RIGHTS)
        || !valid_received(handles[1], DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS)
    {
        return Err(4);
    }
    let init = parse_device_driver_init(&bytes, &handles).map_err(|_| 5u32)?;
    Ok(LaunchCorrelation {
        role_id: init.role_id,
        attempt_generation: init.attempt_generation,
        endpoint_id: init.endpoint_id,
        endpoint_generation: init.endpoint_generation,
        transaction_id: init.transaction_id,
    })
}

/// Waits for init's publication grant on the launch Channel.
fn receive_grant<P: BlockPlatform>(
    platform: &mut P,
    owned: &mut Owned,
) -> Result<PublicationGrant, u32> {
    let deadline = platform
        .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| 10u32)?;
    wait_readable(platform, owned.bootstrap, deadline, 11)?;
    let mut bytes = [0; GRANT_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(owned.bootstrap, &mut bytes, &mut handles)
        .map_err(|_| 12u32)?;
    if counts.handles > 0 {
        owned.publication = handles[0].handle;
    }
    if counts.bytes != GRANT_BYTES
        || counts.handles != 1
        || !valid_received(handles[0], DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS)
    {
        return Err(13);
    }
    pci_driver::parse_grant(&bytes).map_err(|_| 14u32)
}

/// Receives devmgr's STAGE, admits the resource it carries, and answers READY.
fn stage<P: BlockPlatform>(
    platform: &mut P,
    owned: &mut Owned,
    launch: LaunchCorrelation,
) -> Result<(), u32> {
    let deadline = platform
        .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| 30u32)?;
    wait_readable(platform, owned.control, deadline, 31)?;
    let mut bytes = [0; WRDP_MAX_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(owned.control, &mut bytes, &mut handles)
        .map_err(|_| 32u32)?;
    if counts.handles > 0 {
        owned.resource = handles[0].handle;
    }
    if counts.handles != 1 || counts.bytes > bytes.len() {
        return Err(33);
    }
    let message = pci_driver::parse(&bytes[..counts.bytes]).map_err(|_| 34u32)?;
    let admitted = admit_stage_message(launch, message).map_err(|error| error.code())?;
    admit_stage_handle(handles[0]).map_err(|error| error.code())?;
    let info = platform
        .device_resource_info(owned.resource)
        .map_err(|_| 35u32)?;
    admit_resource_info(admitted, info).map_err(|error| error.code())?;
    let ids = platform
        .device_pci_config_read(owned.resource, PCI_CONFIG_IDS, 4)
        .map_err(|_| 36u32)?;
    admit_config_ids(admitted, ids).map_err(|error| error.code())?;
    let mut ready = [0; READY_BYTES];
    pci_driver::encode(
        PciDriverMessage::Ready {
            identity: admitted.identity,
        },
        &mut ready,
    )
    .map_err(|_| 37u32)?;
    platform
        .send_channel(owned.control, &ready, &[])
        .map_err(|_| 38u32)
}

/// Publishes the installed service and waits for the registry's PUBLISHED.
fn publish<P: BlockPlatform>(
    platform: &mut P,
    publication: DwHandle,
    grant: PublicationGrant,
) -> Result<(), u32> {
    let header = RegistryHeader {
        message_type: RegistryMessageType::Publish,
        registry_generation: grant.registry_generation,
        endpoint_id: grant.endpoint_id,
        endpoint_generation: grant.endpoint_generation,
        transaction_id: grant.transaction_id,
    };
    let mut bytes = [0u8; REGISTRY_HEADER_BYTES];
    let size = encode_registry_empty(header, &mut bytes).map_err(|_| 50u32)?;
    platform
        .send_channel(publication, &bytes[..size], &[])
        .map_err(|_| 51u32)?;
    let deadline = platform
        .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| 52u32)?;
    wait_readable(platform, publication, deadline, 53)?;
    let mut response = [0u8; REGISTRY_HEADER_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(publication, &mut response, &mut handles)
        .map_err(|_| 54u32)?;
    if counts.handles != 0 {
        close_received(platform, &handles, counts.handles);
        return Err(55);
    }
    let parsed = parse_registry(&response[..counts.bytes], 0).map_err(|_| 56u32)?;
    if parsed.header
        != (RegistryHeader {
            message_type: RegistryMessageType::Published,
            ..header
        })
        || parsed.message != RegistryMessage::Published
    {
        return Err(57);
    }
    Ok(())
}

/// Serves until devmgr closes the control Channel. Until W3 defines the
/// BlockDevice protocol, each connection offer's endpoint is closed. If the
/// registry goes away the driver keeps its device, unpublished.
fn serve<P: BlockPlatform>(platform: &mut P, owned: &mut Owned) -> Result<(), u32> {
    loop {
        let mut items = [DwWaitItemV1::default(); 2];
        items[0] = DwWaitItemV1 {
            handle: owned.control,
            signals: READABLE_OR_CLOSED,
        };
        let mut count = 1;
        if owned.publication != DW_HANDLE_INVALID {
            items[1] = DwWaitItemV1 {
                handle: owned.publication,
                signals: READABLE_OR_CLOSED,
            };
            count = 2;
        }
        let observed = platform
            .wait_many(&items[..count], DW_DEADLINE_INFINITE)
            .map_err(|_| 70u32)?;
        let readable = observed.observed.0 & DW_SIGNAL_READABLE.0 != 0;
        let closed = observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0;
        match observed.index {
            // devmgr sends nothing after STAGE; its closure retires the driver.
            0 if readable => return Err(71),
            0 if closed => return Ok(()),
            1 if readable => serve_offer(platform, owned.publication)?,
            1 if closed => {
                if !Owned::close(platform, &mut owned.publication) {
                    return Err(72);
                }
            }
            _ => return Err(73),
        }
    }
}

fn serve_offer<P: BlockPlatform>(platform: &mut P, publication: DwHandle) -> Result<(), u32> {
    let mut bytes = [0u8; REGISTRY_MESSAGE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(publication, &mut bytes, &mut handles)
        .map_err(|_| 80u32)?;
    let offer = counts.bytes <= bytes.len()
        && counts.handles == 1
        && parse_registry(&bytes[..counts.bytes], counts.handles)
            .is_ok_and(|parsed| matches!(parsed.message, RegistryMessage::ConnectOffer(_)));
    close_received(platform, &handles, counts.handles);
    if offer { Ok(()) } else { Err(81) }
}

fn wait_readable<P: BlockPlatform>(
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

fn valid_received(
    info: DwReceivedHandleInfoV1,
    object_type: deepwyrm_syscall::DwObjectType,
    rights: DwRights,
) -> bool {
    info.handle.0 != 0
        && info.object_type == object_type
        && info.rights == rights
        && info.reserved0 == 0
        && info.reserved == [0; 2]
}

fn close_received<P: BlockPlatform>(
    platform: &mut P,
    handles: &[DwReceivedHandleInfoV1],
    count: usize,
) {
    for info in handles.iter().take(count) {
        let _ = platform.close_handle(info.handle);
    }
}
