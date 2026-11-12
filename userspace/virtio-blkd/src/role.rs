//! The virtio-blkd role: bootstrap, the publication grant, the one-message
//! WRDP device stage, device bring-up and a DMA read of block 0,
//! publication, and the WRBD service loop.
//!
//! Every refusal returns one distinct step number; the exit code is
//! [`FAILURE_BASE`] plus that step.

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_DMA_ACCESS_DEVICE_READ, DW_DMA_ACCESS_DEVICE_WRITE, DW_HANDLE_INVALID,
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_MEMORY_OBJECT,
    DW_RIGHT_INSPECT, DW_RIGHT_MAP, DW_RIGHT_READ, DW_RIGHT_WRITE, DW_SIGNAL_PEER_CLOSED,
    DW_SIGNAL_READABLE, DW_STATUS_NO_MEMORY, DW_STATUS_NO_RESOURCES, DwDeadline, DwHandle,
    DwReceivedHandleInfoV1, DwRights, DwSignals, DwWaitItemV1,
};
use wyrmroot_block_proto::{
    self as wrbd, Body as WrbdBody, MAX_BYTES as WRBD_MAX_BYTES, Message as WrbdMessage,
    Status as WrbdStatus,
};
use wyrmroot_device_proto::manifest::{PublicationPolicy, disk_policy};
use wyrmroot_device_proto::pci_driver::{
    self, GRANT_BYTES, MAX_BYTES as WRDP_MAX_BYTES, PciDriverMessage, PublicationGrant, READY_BYTES,
};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, DEVICE_DRIVER_BYTES, SELF_ROOT_RIGHTS, parse_device_driver_init,
};
use wyrmroot_registry_proto::{
    HEADER_BYTES as REGISTRY_HEADER_BYTES, Header as RegistryHeader, Lookup,
    Message as RegistryMessage, MessageType as RegistryMessageType, ProtocolVersion,
    encode_empty as encode_registry_empty, parse as parse_registry,
};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, ChannelPlatform, ClockPlatform, DevicePlatform, HandlePlatform,
    MemoryPlatform, NativeError, OwnedMemoryMapping, WYR0_I_SUPERVISION_POLICY, WaitPlatform,
    validate_bootstrap_channel,
};

use crate::block::{Buffer, check_attach, info, plan_flush, plan_transfer};
use crate::virtio::{
    BLK_S_OK, DMA_BYTES, Device, Fault, Hardware, Request, SCRATCH_OFFSET, Width, find_capabilities,
};
use crate::{
    LaunchCorrelation, PCI_CONFIG_IDS, admit_config_ids, admit_resource_info, admit_stage_handle,
    admit_stage_message,
};

pub const FAILURE_BASE: u32 = 0xB1D0_0000;
/// How long one request may take before the device counts as hung.
pub const REQUEST_TIMEOUT_NS: u64 = 5_000_000_000;
/// The most WRBD connections served at once; another offer is closed.
pub const MAX_CONNECTIONS: usize = 4;
/// The BAR object's rights: mapped read/write (never executable), and sized.
const BAR_OBJECT_RIGHTS: DwRights =
    DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0 | DW_RIGHT_INSPECT.0);
/// The driver's own DMA memory.
const DMA_OBJECT_RIGHTS: DwRights = BAR_OBJECT_RIGHTS;
/// What a client's attached MemoryObject must carry: exactly what a
/// device-readable and device-writable DMA mapping needs.
pub const ATTACH_RIGHTS: DwRights = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0);
const DMA_ACCESS: u32 = DW_DMA_ACCESS_DEVICE_READ | DW_DMA_ACCESS_DEVICE_WRITE;
/// Room for any registry message the publication endpoint receives.
const REGISTRY_MESSAGE_BYTES: usize = 512;
const READABLE_OR_CLOSED: DwSignals = DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0);

/// The platform traits the role uses.
pub trait BlockPlatform:
    HandlePlatform + ChannelPlatform + WaitPlatform + ClockPlatform + DevicePlatform + MemoryPlatform
{
}

impl<P> BlockPlatform for P where
    P: HandlePlatform
        + ChannelPlatform
        + WaitPlatform
        + ClockPlatform
        + DevicePlatform
        + MemoryPlatform
        + ?Sized
{
}

/// Maps the BAR object and the driver's DMA object into the driver's own
/// address space. Every kernel object stays with the role; only this step,
/// which host tests cannot perform, is supplied from outside.
pub trait DeviceMapper<P: ?Sized> {
    type Hardware: Hardware;
    fn map(
        &mut self,
        platform: &mut P,
        root: DwHandle,
        bar: DwHandle,
        bar_bytes: u64,
        dma: DwHandle,
    ) -> Result<Self::Hardware, NativeError>;
    /// Removes both mappings; `false` if either failed.
    fn unmap(&mut self, platform: &mut P, hardware: Self::Hardware) -> bool;
}

/// The production mapper: the BAR maps uncached (the kernel chooses the
/// memory type from the object), the DMA memory as ordinary memory.
pub struct NativeMapper;

/// The two live mappings.
pub struct NativeHardware {
    bar: OwnedMemoryMapping,
    mem: OwnedMemoryMapping,
}

fn mapping_read(mapping: &OwnedMemoryMapping, offset: u64, width: Width) -> Result<u64, Fault> {
    match width {
        Width::U8 => mapping.read_u8(offset).map(u64::from),
        Width::U16 => mapping.read_u16(offset).map(u64::from),
        Width::U32 => mapping.read_u32(offset).map(u64::from),
        Width::U64 => mapping.read_u64(offset),
    }
    .map_err(|_| Fault)
}

fn mapping_write(
    mapping: &mut OwnedMemoryMapping,
    offset: u64,
    width: Width,
    value: u64,
) -> Result<(), Fault> {
    match width {
        Width::U8 => mapping.write_u8(offset, value as u8),
        Width::U16 => mapping.write_u16(offset, value as u16),
        Width::U32 => mapping.write_u32(offset, value as u32),
        Width::U64 => mapping.write_u64(offset, value),
    }
    .map_err(|_| Fault)
}

impl Hardware for NativeHardware {
    fn bar_read(&mut self, offset: u64, width: Width) -> Result<u64, Fault> {
        mapping_read(&self.bar, offset, width)
    }

    fn bar_write(&mut self, offset: u64, width: Width, value: u64) -> Result<(), Fault> {
        mapping_write(&mut self.bar, offset, width, value)
    }

    fn mem_read(&mut self, offset: u64, width: Width) -> Result<u64, Fault> {
        mapping_read(&self.mem, offset, width)
    }

    fn mem_write(&mut self, offset: u64, width: Width, value: u64) -> Result<(), Fault> {
        mapping_write(&mut self.mem, offset, width, value)
    }
}

impl<P: MemoryPlatform + ?Sized> DeviceMapper<P> for NativeMapper {
    type Hardware = NativeHardware;

    fn map(
        &mut self,
        platform: &mut P,
        root: DwHandle,
        bar: DwHandle,
        bar_bytes: u64,
        dma: DwHandle,
    ) -> Result<NativeHardware, NativeError> {
        let bar = platform.map_memory_read_write(root, bar, bar_bytes)?;
        match platform.map_memory_read_write(root, dma, DMA_BYTES) {
            Ok(mem) => Ok(NativeHardware { bar, mem }),
            Err(error) => {
                let _ = platform.unmap_memory(bar);
                Err(error)
            }
        }
    }

    fn unmap(&mut self, platform: &mut P, hardware: NativeHardware) -> bool {
        let mem = platform.unmap_memory(hardware.mem).is_ok();
        platform.unmap_memory(hardware.bar).is_ok() && mem
    }
}

/// The device side the driver owns once the STAGE is admitted.
struct Live<H> {
    bar_object: DwHandle,
    dma_object: DwHandle,
    /// The DMA object's IOVA, while mapped.
    dma_iova: Option<u64>,
    hardware: Option<H>,
    device: Option<Device>,
    /// Whether the command register was changed, so retirement clears it.
    commanded: bool,
}

impl<H> Live<H> {
    const fn new() -> Self {
        Self {
            bar_object: DW_HANDLE_INVALID,
            dma_object: DW_HANDLE_INVALID,
            dma_iova: None,
            hardware: None,
            device: None,
            commanded: false,
        }
    }
}

/// One client's WRBD Channel and its attached buffer.
struct Connection {
    channel: DwHandle,
    buffer: Option<Attached>,
}

#[derive(Clone, Copy)]
struct Attached {
    memory: DwHandle,
    buffer: Buffer,
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

pub fn blk_main<P: BlockPlatform, M: DeviceMapper<P>>(
    platform: &mut P,
    mapper: &mut M,
    bootstrap: DwHandle,
) -> u32 {
    let mut owned = Owned {
        bootstrap,
        self_root: DW_HANDLE_INVALID,
        control: DW_HANDLE_INVALID,
        publication: DW_HANDLE_INVALID,
        resource: DW_HANDLE_INVALID,
    };
    let mut live = Live::new();
    let mut connections: [Option<Connection>; MAX_CONNECTIONS] = [const { None }; MAX_CONNECTIONS];
    let result = run(platform, mapper, &mut owned, &mut live, &mut connections);
    // The device stops before any memory it can reach is released.
    let stopped = retire_device(
        platform,
        mapper,
        owned.resource,
        &mut live,
        &mut connections,
    );
    let closed = owned.close_all(platform);
    match result {
        Ok(()) if stopped && closed => 0,
        Ok(()) => FAILURE_BASE | 0xff,
        Err(step) => FAILURE_BASE | step,
    }
}

fn run<P: BlockPlatform, M: DeviceMapper<P>>(
    platform: &mut P,
    mapper: &mut M,
    owned: &mut Owned,
    live: &mut Live<M::Hardware>,
    connections: &mut [Option<Connection>; MAX_CONNECTIONS],
) -> Result<(), u32> {
    let launch = startup(platform, owned)?;
    let grant = receive_grant(platform, owned)?;
    if !Owned::close(platform, &mut owned.bootstrap) {
        return Err(20);
    }
    let policy = stage(platform, owned, launch)?;
    bring_up(platform, mapper, owned, live)?;
    self_test(platform, live)?;
    publish(platform, owned.publication, grant)?;
    serve(platform, owned, live, grant, policy, connections)
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
/// Returns the publication the staged disk role's driver serves.
fn stage<P: BlockPlatform>(
    platform: &mut P,
    owned: &mut Owned,
    launch: LaunchCorrelation,
) -> Result<PublicationPolicy, u32> {
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
        .map_err(|_| 38u32)?;
    disk_policy(admitted.identity.role_id)
        .map(|policy| policy.publication)
        .ok_or(39)
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

/// Resets and initializes the device over the staged resource: maps its
/// BAR and the driver's DMA memory, resets the device, maps that memory for
/// the device, enables bus mastering and starts queue 0.
fn bring_up<P: BlockPlatform, M: DeviceMapper<P>>(
    platform: &mut P,
    mapper: &mut M,
    owned: &Owned,
    live: &mut Live<M::Hardware>,
) -> Result<(), u32> {
    let resource = owned.resource;
    let caps = find_capabilities(|offset, width| {
        platform
            .device_pci_config_read(resource, offset, width)
            .map_err(|_| ())
    })
    .map_err(|error| 90 + virtio_code(error))?;
    platform
        .device_pci_command(resource, true, false)
        .map_err(|_| 101u32)?;
    live.commanded = true;
    live.bar_object = platform
        .device_mmio_object_create(resource, caps.bar(), BAR_OBJECT_RIGHTS)
        .map_err(|_| 102u32)?;
    let bar_bytes = platform
        .query_memory_object_size(live.bar_object)
        .map_err(|_| 103u32)?;
    live.dma_object = platform
        .create_memory_object(DMA_BYTES, DMA_OBJECT_RIGHTS)
        .map_err(|_| 104u32)?;
    let hardware = live.hardware.insert(
        mapper
            .map(
                platform,
                owned.self_root,
                live.bar_object,
                bar_bytes,
                live.dma_object,
            )
            .map_err(|_| 106u32)?,
    );
    // A predecessor may have left the device programmed: reset it before it
    // can see any of this driver's memory or master the bus.
    crate::virtio::reset_device(hardware, caps, bar_bytes)
        .map_err(|error| 110 + virtio_code(error))?;
    let iova = platform
        .dma_map(resource, live.dma_object, 0, DMA_BYTES, DMA_ACCESS)
        .map_err(|_| 105u32)?;
    live.dma_iova = Some(iova);
    // The IOMMU confines whatever the device does once it may master the bus.
    platform
        .device_pci_command(resource, true, true)
        .map_err(|_| 107u32)?;
    live.device = Some(
        Device::initialize(hardware, caps, bar_bytes, iova)
            .map_err(|error| 110 + virtio_code(error))?,
    );
    Ok(())
}

fn virtio_code(error: crate::virtio::Error) -> u32 {
    use crate::virtio::Error;
    match error {
        Error::Access => 0,
        Error::Capabilities => 1,
        Error::MissingStructure => 2,
        Error::Layout => 3,
        Error::Reset => 4,
        Error::Features => 5,
        Error::Queue => 6,
        Error::Config => 7,
        Error::Device => 8,
        Error::State => 9,
    }
}

/// The live DMA round trip: block 0 is read into the driver's scratch page
/// and must end in the 0x55AA boot signature the boot disk (the ESP) carries.
/// How much of block 0 the self-test compares: its first 512 bytes.
const SELF_TEST_WORDS: usize = 64;

fn self_test<P: BlockPlatform, H: Hardware>(
    platform: &mut P,
    live: &mut Live<H>,
) -> Result<(), u32> {
    let (Some(device), Some(hardware), Some(iova)) =
        (live.device.as_mut(), live.hardware.as_mut(), live.dma_iova)
    else {
        return Err(120);
    };
    // Block 0 is read twice, into scratch poisoned first with zeros and then
    // with ones. Data that reaches memory reads the same both times whatever
    // the disk holds; a read that never lands leaves the two poisons.
    let bytes = device.geometry().block_size;
    let words = (u64::from(bytes) / 8).min(SELF_TEST_WORDS as u64) as usize;
    let mut first = [0u64; SELF_TEST_WORDS];
    for (pass, poison) in [0u64, u64::MAX].into_iter().enumerate() {
        for word in 0..words {
            hardware
                .mem_write(SCRATCH_OFFSET + word as u64 * 8, Width::U64, poison)
                .map_err(|Fault| 121u32)?;
        }
        let request = Request::Read {
            sector: 0,
            data_iova: iova + SCRATCH_OFFSET,
            bytes,
        };
        let status = execute(platform, device, hardware, request).map_err(|step| 122 + step)?;
        if status != BLK_S_OK {
            return Err(125);
        }
        for (word, seen) in first.iter_mut().enumerate().take(words) {
            let value = hardware
                .mem_read(SCRATCH_OFFSET + word as u64 * 8, Width::U64)
                .map_err(|Fault| 126u32)?;
            if pass == 0 {
                *seen = value;
            } else if *seen != value {
                return Err(126);
            }
        }
    }
    Ok(())
}

/// Runs one request to completion. `Err(0)` is a device fault and `Err(1)`
/// a timeout; either leaves the device unusable, so the driver stops.
fn execute<P: BlockPlatform, H: Hardware>(
    platform: &mut P,
    device: &mut Device,
    hardware: &mut H,
    request: Request,
) -> Result<u8, u32> {
    device.submit(hardware, request).map_err(|_| 0u32)?;
    let deadline = platform
        .monotonic_deadline_after(REQUEST_TIMEOUT_NS)
        .map_err(|_| 2u32)?;
    loop {
        if let Some(status) = device.poll(hardware).map_err(|_| 0u32)? {
            return Ok(status);
        }
        let now = platform.monotonic_active_now().map_err(|_| 2u32)?;
        if now >= deadline.0 {
            return Err(1);
        }
        core::hint::spin_loop();
    }
}

/// Stops the device and releases everything it could reach, in that order:
/// reset (or, without a device, bus mastering off), then every client
/// buffer's IOMMU mapping, then the driver's own memory and the BAR.
fn retire_device<P: BlockPlatform, M: DeviceMapper<P>>(
    platform: &mut P,
    mapper: &mut M,
    resource: DwHandle,
    live: &mut Live<M::Hardware>,
    connections: &mut [Option<Connection>; MAX_CONNECTIONS],
) -> bool {
    let mut clean = true;
    if let (Some(device), Some(hardware)) = (live.device.take(), live.hardware.as_mut()) {
        clean &= device.reset(hardware).is_ok();
    }
    if live.commanded {
        clean &= platform.device_pci_command(resource, false, false).is_ok();
    }
    for slot in connections.iter_mut() {
        if let Some(connection) = slot.take() {
            clean &= drop_connection(platform, resource, connection);
        }
    }
    if let Some(hardware) = live.hardware.take() {
        clean &= mapper.unmap(platform, hardware);
    }
    if let Some(iova) = live.dma_iova.take() {
        clean &= platform.dma_unmap(resource, iova, DMA_BYTES).is_ok();
    }
    for object in [&mut live.dma_object, &mut live.bar_object] {
        let handle = core::mem::replace(object, DW_HANDLE_INVALID);
        if handle != DW_HANDLE_INVALID {
            clean &= platform.close_handle(handle).is_ok();
        }
    }
    clean
}

/// Closes a connection: its buffer's IOMMU mapping first, then the buffer
/// and the Channel. No request is in flight when this runs.
fn drop_connection<P: BlockPlatform>(
    platform: &mut P,
    resource: DwHandle,
    connection: Connection,
) -> bool {
    let mut clean = true;
    if let Some(attached) = connection.buffer {
        clean &= platform
            .dma_unmap(resource, attached.buffer.iova, attached.buffer.bytes)
            .is_ok();
        clean &= platform.close_handle(attached.memory).is_ok();
    }
    clean & platform.close_handle(connection.channel).is_ok()
}

/// Serves WRBD until devmgr closes the control Channel. If the registry goes
/// away the driver keeps serving the connections it has, unpublished.
fn serve<P: BlockPlatform, H: Hardware>(
    platform: &mut P,
    owned: &mut Owned,
    live: &mut Live<H>,
    grant: PublicationGrant,
    policy: PublicationPolicy,
    connections: &mut [Option<Connection>; MAX_CONNECTIONS],
) -> Result<(), u32> {
    loop {
        // Wait-item index -> what it is: 0 control, 1 publication (when
        // live), then connections by slot.
        let mut items = [DwWaitItemV1::default(); 2 + MAX_CONNECTIONS];
        let mut targets = [Target::Control; 2 + MAX_CONNECTIONS];
        items[0] = DwWaitItemV1 {
            handle: owned.control,
            signals: READABLE_OR_CLOSED,
        };
        let mut count = 1;
        if owned.publication != DW_HANDLE_INVALID {
            items[count] = DwWaitItemV1 {
                handle: owned.publication,
                signals: READABLE_OR_CLOSED,
            };
            targets[count] = Target::Publication;
            count += 1;
        }
        for (slot, connection) in connections.iter().enumerate() {
            if let Some(connection) = connection {
                items[count] = DwWaitItemV1 {
                    handle: connection.channel,
                    signals: READABLE_OR_CLOSED,
                };
                targets[count] = Target::Connection(slot);
                count += 1;
            }
        }
        let observed = platform
            .wait_many(&items[..count], DW_DEADLINE_INFINITE)
            .map_err(|_| 70u32)?;
        let readable = observed.observed.0 & DW_SIGNAL_READABLE.0 != 0;
        let closed = observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0;
        let target = targets
            .get(observed.index as usize)
            .filter(|_| (observed.index as usize) < count)
            .ok_or(73u32)?;
        match (*target, readable, closed) {
            // devmgr sends nothing after STAGE; its closure retires the driver.
            (Target::Control, true, _) => return Err(71),
            (Target::Control, false, true) => return Ok(()),
            (Target::Publication, true, _) => {
                serve_offer(platform, owned.publication, grant, policy, connections)?;
            }
            (Target::Publication, false, true) => {
                if !Owned::close(platform, &mut owned.publication) {
                    return Err(72);
                }
            }
            (Target::Connection(slot), true, _) => {
                serve_request(platform, owned.resource, live, &mut connections[slot])?;
            }
            (Target::Connection(slot), false, true) => {
                let connection = connections[slot].take().ok_or(74u32)?;
                if !drop_connection(platform, owned.resource, connection) {
                    return Err(75);
                }
            }
            _ => return Err(73),
        }
    }
}

#[derive(Clone, Copy)]
enum Target {
    Control,
    Publication,
    Connection(usize),
}

/// Accepts one registry connection offer for this service into a free
/// slot. An offer for anything else, or with no slot free, is closed.
fn serve_offer<P: BlockPlatform>(
    platform: &mut P,
    publication: DwHandle,
    grant: PublicationGrant,
    policy: PublicationPolicy,
    connections: &mut [Option<Connection>; MAX_CONNECTIONS],
) -> Result<(), u32> {
    let mut bytes = [0u8; REGISTRY_MESSAGE_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = platform
        .receive_channel(publication, &mut bytes, &mut handles)
        .map_err(|_| 80u32)?;
    let parsed = (counts.bytes <= bytes.len() && counts.handles == 1)
        .then(|| parse_registry(&bytes[..counts.bytes], counts.handles).ok())
        .flatten();
    let Some(parsed) = parsed else {
        close_received(platform, &handles, counts.handles);
        return Err(81);
    };
    let RegistryMessage::ConnectOffer(lookup) = parsed.message else {
        close_received(platform, &handles, counts.handles);
        return Err(81);
    };
    let ours = parsed.header.message_type == RegistryMessageType::ConnectOffer
        && parsed.header.registry_generation == grant.registry_generation
        && parsed.header.endpoint_id == grant.endpoint_id
        && parsed.header.endpoint_generation == grant.endpoint_generation
        && lookup
            == Lookup {
                protocol_id: policy.protocol_id,
                version: ProtocolVersion {
                    major: policy.protocol_major,
                    minor: policy.protocol_minor,
                },
                service_name: policy.service_name,
            }
        && valid_received(handles[0], DW_OBJECT_TYPE_CHANNEL, CHILD_CHANNEL_RIGHTS);
    let free = connections.iter_mut().find(|slot| slot.is_none());
    match free {
        Some(slot) if ours => {
            *slot = Some(Connection {
                channel: handles[0].handle,
                buffer: None,
            });
        }
        // The client sees its Channel close.
        _ => close_received(platform, &handles, 1),
    }
    Ok(())
}

/// Serves one WRBD request. A malformed message closes the connection; a
/// device that fails or hangs stops the driver.
fn serve_request<P: BlockPlatform, H: Hardware>(
    platform: &mut P,
    resource: DwHandle,
    live: &mut Live<H>,
    slot: &mut Option<Connection>,
) -> Result<(), u32> {
    let Some(connection) = slot.as_mut() else {
        return Err(76);
    };
    let mut bytes = [0u8; WRBD_MAX_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); wrbd::MAX_HANDLES];
    let message = match platform.receive_channel(connection.channel, &mut bytes, &mut handles) {
        Ok(counts) => (counts.bytes <= bytes.len())
            .then(|| wrbd::parse(&bytes[..counts.bytes], counts.handles).ok())
            .flatten()
            .filter(|message| message.body.is_request())
            .ok_or(counts.handles),
        // Too large for any WRBD message, or the peer went away.
        Err(_) => Err(0),
    };
    let message = match message {
        Ok(message) => message,
        Err(received) => {
            close_received(platform, &handles, received);
            return close_slot(platform, resource, slot);
        }
    };
    let reply = match message.body {
        WrbdBody::GetInfo => {
            let device = live.device.as_ref().ok_or(77u32)?;
            WrbdBody::Info(info(device.geometry()))
        }
        WrbdBody::Attach { byte_len } => {
            WrbdBody::Complete(attach(platform, resource, connection, handles[0], byte_len))
        }
        WrbdBody::Read(transfer) | WrbdBody::Write(transfer) => {
            let (Some(device), Some(hardware)) = (live.device.as_mut(), live.hardware.as_mut())
            else {
                return Err(77);
            };
            let write = matches!(message.body, WrbdBody::Write(_));
            let buffer = connection.buffer.map(|attached| attached.buffer);
            WrbdBody::Complete(
                match plan_transfer(device.geometry(), buffer, transfer, write) {
                    Ok(request) => run_request(platform, device, hardware, request)?,
                    Err(status) => status,
                },
            )
        }
        WrbdBody::Flush => {
            let (Some(device), Some(hardware)) = (live.device.as_mut(), live.hardware.as_mut())
            else {
                return Err(77);
            };
            WrbdBody::Complete(match plan_flush(device.geometry()) {
                Ok(request) => run_request(platform, device, hardware, request)?,
                Err(status) => status,
            })
        }
        WrbdBody::Info(_) | WrbdBody::Complete(_) => return Err(78),
    };
    let mut reply_bytes = [0u8; WRBD_MAX_BYTES];
    let size = wrbd::encode(
        WrbdMessage {
            transaction_id: message.transaction_id,
            body: reply,
        },
        &mut reply_bytes,
    )
    .map_err(|_| 79u32)?;
    if platform
        .send_channel(connection.channel, &reply_bytes[..size], &[])
        .is_err()
    {
        return close_slot(platform, resource, slot);
    }
    Ok(())
}

fn run_request<P: BlockPlatform, H: Hardware>(
    platform: &mut P,
    device: &mut Device,
    hardware: &mut H,
    request: Request,
) -> Result<WrbdStatus, u32> {
    match execute(platform, device, hardware, request) {
        Ok(BLK_S_OK) => Ok(WrbdStatus::Ok),
        Ok(_) => Ok(WrbdStatus::IoError),
        Err(step) => Err(130 + step),
    }
}

fn close_slot<P: BlockPlatform>(
    platform: &mut P,
    resource: DwHandle,
    slot: &mut Option<Connection>,
) -> Result<(), u32> {
    let Some(connection) = slot.take() else {
        return Ok(());
    };
    if drop_connection(platform, resource, connection) {
        Ok(())
    } else {
        Err(75)
    }
}

/// Admits one attached MemoryObject and maps it for the device. The handle
/// is the connection's on success and closed otherwise.
fn attach<P: BlockPlatform>(
    platform: &mut P,
    resource: DwHandle,
    connection: &mut Connection,
    received: DwReceivedHandleInfoV1,
    byte_len: u64,
) -> WrbdStatus {
    let status = if connection.buffer.is_some() {
        Err(WrbdStatus::AlreadyAttached)
    } else if !valid_received(received, DW_OBJECT_TYPE_MEMORY_OBJECT, ATTACH_RIGHTS) {
        Err(WrbdStatus::Invalid)
    } else {
        check_attach(byte_len).and_then(|()| {
            platform
                .dma_map(resource, received.handle, 0, byte_len, DMA_ACCESS)
                .map_err(|error| match error {
                    NativeError::Status(DW_STATUS_NO_RESOURCES | DW_STATUS_NO_MEMORY) => {
                        WrbdStatus::NoResources
                    }
                    _ => WrbdStatus::Invalid,
                })
        })
    };
    match status {
        Ok(iova) => {
            connection.buffer = Some(Attached {
                memory: received.handle,
                buffer: Buffer {
                    iova,
                    bytes: byte_len,
                },
            });
            WrbdStatus::Ok
        }
        Err(status) => {
            let _ = platform.close_handle(received.handle);
            status
        }
    }
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
