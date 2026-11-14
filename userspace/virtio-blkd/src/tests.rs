//! virtio-blkd's admission checks, and its role driven end to end through the
//! runtime's recording platform.

use std::vec;
use std::vec::Vec;

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_DEVICE_RESOURCE_INFO_V1_SIZE, DW_DEVICE_RESOURCE_INFO_V1_VERSION,
    DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION, DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_DEVICE_RESOURCE,
    DW_RIGHT_DUPLICATE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwDeadline,
    DwDeviceResourceInfoV1, DwHandle, DwReceivedHandleInfoV1, DwSignals, DwWaitItemV1,
    DwWaitResultV1,
};
use wyrmroot_device_proto::control::ControlEndpoint;
use wyrmroot_device_proto::control_v1_1::ControlIdentityV1_1;
use wyrmroot_device_proto::coordinator::{
    AttemptGeneration, BundleGeneration, EndpointGeneration, EndpointId,
};
use wyrmroot_device_proto::manifest::{
    BLOCK_DEVICE_PROTOCOL_ID, BOOT_DISK_POLICY, BOOT_DISK_SERVICE_NAME, RoleId,
};
use wyrmroot_device_proto::pci_driver::{
    self, GRANT_BYTES, PciDriverMessage, PublicationGrant, READY_BYTES, STAGE_BYTES,
};
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, DEVICE_DRIVER_BYTES, SELF_ROOT_RIGHTS, encode_device_driver_init,
};
use wyrmroot_registry_proto::{
    HEADER_BYTES as REGISTRY_HEADER_BYTES, Header as RegistryHeader, Lookup,
    MessageType as RegistryMessageType, ProtocolVersion, encode_empty, encode_lookup,
};
use wyrmroot_runtime::platform::recording::{Call, Datagram, RecordingPlatform, Reply};
use wyrmroot_runtime::{BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo};

use super::*;
use crate::virtio_tests::{BAR_BYTES, CLIENT_IOVA, MEM_IOVA, Model, SECTORS};
use deepwyrm_syscall::{
    DW_DMA_ACCESS_DEVICE_READ, DW_DMA_ACCESS_DEVICE_WRITE, DW_OBJECT_TYPE_MEMORY_OBJECT,
    DW_RIGHT_INSPECT, DW_RIGHT_MAP, DW_RIGHT_READ, DW_RIGHT_WRITE, DwRights,
};
use wyrmroot_block_proto::{
    Body as WrbdBody, MAX_BYTES as WRBD_MAX_BYTES, Message as WrbdMessage, Status as WrbdStatus,
};

const BOOTSTRAP: DwHandle = DwHandle(0x10);
const SELF_ROOT: DwHandle = DwHandle(0x20);
const CONTROL: DwHandle = DwHandle(0x21);
const PUBLICATION: DwHandle = DwHandle(0x22);
const RESOURCE: DwHandle = DwHandle(0x23);
const OFFERED: DwHandle = DwHandle(0x24);
const LEASE: u64 = 0x77;
const LAUNCH_TRANSACTION: u64 = 10;

fn launch() -> LaunchCorrelation {
    LaunchCorrelation {
        role_id: BOOT_DISK_POLICY.role_id.0,
        attempt_generation: 4,
        endpoint_id: 6,
        endpoint_generation: 1,
        transaction_id: LAUNCH_TRANSACTION,
    }
}

fn identity() -> ControlIdentityV1_1 {
    ControlIdentityV1_1 {
        role_id: BOOT_DISK_POLICY.role_id,
        bundle_generation: BundleGeneration(LEASE),
        attempt_generation: AttemptGeneration(4),
        endpoint: ControlEndpoint {
            id: EndpointId(6),
            generation: EndpointGeneration(1),
        },
        transaction_id: LAUNCH_TRANSACTION + 1,
    }
}

fn stage_message() -> PciDriverMessage {
    PciDriverMessage::Stage {
        identity: identity(),
        resource_id: BOOT_DISK_POLICY.resource_id,
        function: BOOT_DISK_POLICY.pci,
    }
}

fn resource_handle() -> DwReceivedHandleInfoV1 {
    DwReceivedHandleInfoV1 {
        handle: RESOURCE,
        object_type: DW_OBJECT_TYPE_DEVICE_RESOURCE,
        rights: PCI_DRIVER_RESOURCE_RIGHTS,
        ..DwReceivedHandleInfoV1::default()
    }
}

fn resource_info() -> DwDeviceResourceInfoV1 {
    DwDeviceResourceInfoV1 {
        size: DW_DEVICE_RESOURCE_INFO_V1_SIZE,
        version: DW_DEVICE_RESOURCE_INFO_V1_VERSION,
        kind: DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION,
        resource_id: BOOT_DISK_POLICY.resource_id,
        lease_generation: LEASE,
        ..DwDeviceResourceInfoV1::default()
    }
}

fn admitted() -> AdmittedStage {
    admit_stage_message(launch(), stage_message()).unwrap()
}

#[test]
fn the_data_disk_role_stages_only_with_its_own_resource_and_function() {
    use wyrmroot_device_proto::manifest::{COM2_ROLE_ID, DATA_DISK_POLICY};
    let data_launch = LaunchCorrelation {
        role_id: DATA_DISK_POLICY.role_id.0,
        ..launch()
    };
    let data_identity = ControlIdentityV1_1 {
        role_id: DATA_DISK_POLICY.role_id,
        ..identity()
    };
    let stage = |resource_id, function| PciDriverMessage::Stage {
        identity: data_identity,
        resource_id,
        function,
    };
    let admitted = admit_stage_message(
        data_launch,
        stage(DATA_DISK_POLICY.resource_id, DATA_DISK_POLICY.pci),
    )
    .unwrap();
    assert_eq!(admitted.function, DATA_DISK_POLICY.pci);
    // Either half of the boot disk's policy is refused for the data role.
    for (resource_id, function) in [
        (BOOT_DISK_POLICY.resource_id, DATA_DISK_POLICY.pci),
        (DATA_DISK_POLICY.resource_id, BOOT_DISK_POLICY.pci),
    ] {
        assert_eq!(
            admit_stage_message(data_launch, stage(resource_id, function)),
            Err(StageError::WrongPolicy)
        );
    }
    // A role that is not a disk never stages a block driver.
    let com2_launch = LaunchCorrelation {
        role_id: COM2_ROLE_ID.0,
        ..launch()
    };
    let com2 = PciDriverMessage::Stage {
        identity: ControlIdentityV1_1 {
            role_id: COM2_ROLE_ID,
            ..identity()
        },
        resource_id: BOOT_DISK_POLICY.resource_id,
        function: BOOT_DISK_POLICY.pci,
    };
    assert_eq!(
        admit_stage_message(com2_launch, com2),
        Err(StageError::WrongPolicy)
    );
}

#[test]
fn a_stage_must_carry_this_attempt_and_the_boot_disk_policy() {
    assert_eq!(admitted().identity, identity());
    let refused = |change: fn(&mut ControlIdentityV1_1)| {
        let mut identity = identity();
        change(&mut identity);
        admit_stage_message(
            launch(),
            PciDriverMessage::Stage {
                identity,
                resource_id: BOOT_DISK_POLICY.resource_id,
                function: BOOT_DISK_POLICY.pci,
            },
        )
    };
    for change in [
        (|identity: &mut ControlIdentityV1_1| identity.attempt_generation.0 += 1)
            as fn(&mut ControlIdentityV1_1),
        |identity| identity.endpoint.id.0 += 1,
        |identity| identity.endpoint.generation.0 += 1,
        |identity| identity.role_id = RoleId(1),
        // The STAGE has its own transaction, after the launch's.
        |identity| identity.transaction_id = LAUNCH_TRANSACTION,
    ] {
        assert_eq!(refused(change), Err(StageError::WrongIdentity));
    }
    let other_function = PciDriverMessage::Stage {
        identity: identity(),
        resource_id: BOOT_DISK_POLICY.resource_id,
        function: wyrmroot_device_proto::manifest::PciFunction {
            address: 2 << 3,
            ..BOOT_DISK_POLICY.pci
        },
    };
    assert_eq!(
        admit_stage_message(launch(), other_function),
        Err(StageError::WrongPolicy)
    );
    let other_resource = PciDriverMessage::Stage {
        identity: identity(),
        resource_id: 1,
        function: BOOT_DISK_POLICY.pci,
    };
    assert_eq!(
        admit_stage_message(launch(), other_resource),
        Err(StageError::WrongPolicy)
    );
    assert_eq!(
        admit_stage_message(
            launch(),
            PciDriverMessage::Ready {
                identity: identity()
            }
        ),
        Err(StageError::NotStage)
    );
}

/// devmgr moves exactly the rights the driver admits.
#[test]
fn devmgr_stages_exactly_the_rights_the_driver_admits() {
    assert_eq!(
        PCI_DRIVER_RESOURCE_RIGHTS,
        wyrmroot_devmgr::role::PCI_DRIVER_RESOURCE_RIGHTS
    );
}

#[test]
fn the_staged_handle_must_be_a_device_resource_with_exactly_the_driver_rights() {
    assert_eq!(admit_stage_handle(resource_handle()), Ok(()));
    let mut wider = resource_handle();
    wider.rights = DwRights(PCI_DRIVER_RESOURCE_RIGHTS.0 | DW_RIGHT_DUPLICATE.0);
    assert_eq!(admit_stage_handle(wider), Err(StageError::WrongHandle));
    let mut channel = resource_handle();
    channel.object_type = DW_OBJECT_TYPE_CHANNEL;
    assert_eq!(admit_stage_handle(channel), Err(StageError::WrongHandle));
    let mut reserved = resource_handle();
    reserved.reserved0 = 1;
    assert_eq!(admit_stage_handle(reserved), Err(StageError::WrongHandle));
}

#[test]
fn the_kernel_facts_must_name_the_staged_pci_resource_and_lease() {
    assert_eq!(admit_resource_info(admitted(), resource_info()), Ok(()));
    let cases: [fn(&mut DwDeviceResourceInfoV1); 6] = [
        |info| info.kind = DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
        |info| info.resource_id = 1,
        |info| info.lease_generation += 1,
        |info| info.pio_length = 8,
        |info| info.flags = 1,
        |info| info.version += 1,
    ];
    for change in cases {
        let mut info = resource_info();
        change(&mut info);
        assert_eq!(
            admit_resource_info(admitted(), info),
            Err(StageError::WrongResource)
        );
    }
}

#[test]
fn the_live_config_ids_must_be_the_modern_virtio_block_device() {
    assert_eq!(admit_config_ids(admitted(), 0x1042_1af4), Ok(()));
    // The transitional (legacy-capable) virtio block device is not admitted.
    assert_eq!(
        admit_config_ids(admitted(), 0x1001_1af4),
        Err(StageError::WrongIds)
    );
    assert_eq!(
        admit_config_ids(admitted(), u32::MAX),
        Err(StageError::WrongIds)
    );
}

// --- The role, end to end. ---

fn grant() -> PublicationGrant {
    PublicationGrant {
        registry_generation: 3,
        endpoint_id: 9,
        endpoint_generation: 1,
        transaction_id: 0x55,
        service_generation: 0x66,
    }
}

fn ready_wait(index: u32, signals: DwSignals) -> Reply {
    Reply::Wait(Ok(DwWaitResultV1 {
        index,
        observed: signals,
        ..DwWaitResultV1::default()
    }))
}

fn receive(bytes: Vec<u8>, handles: Vec<DwReceivedHandleInfoV1>) -> Reply {
    Reply::Receive(Ok(Datagram { bytes, handles }))
}

fn channel(handle: DwHandle) -> DwReceivedHandleInfoV1 {
    DwReceivedHandleInfoV1 {
        handle,
        object_type: DW_OBJECT_TYPE_CHANNEL,
        rights: CHILD_CHANNEL_RIGHTS,
        ..DwReceivedHandleInfoV1::default()
    }
}

fn startup_replies() -> Vec<Reply> {
    let mut init = vec![0; DEVICE_DRIVER_BYTES];
    encode_device_driver_init(LAUNCH_TRANSACTION, 1, 2, 4, 5, 6, 1, &mut init).unwrap();
    let mut grant_bytes = [0; GRANT_BYTES];
    pci_driver::encode_grant(grant(), &mut grant_bytes).unwrap();
    vec![
        Reply::CapabilityInfo(Ok(CapabilityInfo {
            object_type: BOOTSTRAP_CHANNEL_EXPECTATION.object_type,
            rights: BOOTSTRAP_CHANNEL_EXPECTATION.rights,
        })),
        receive(
            init,
            vec![
                DwReceivedHandleInfoV1 {
                    handle: SELF_ROOT,
                    object_type: DW_OBJECT_TYPE_ADDRESS_REGION,
                    rights: SELF_ROOT_RIGHTS,
                    ..DwReceivedHandleInfoV1::default()
                },
                channel(CONTROL),
            ],
        ),
        Reply::Deadline(Ok(DwDeadline(100))),
        ready_wait(0, DW_SIGNAL_READABLE),
        receive(grant_bytes.to_vec(), vec![channel(PUBLICATION)]),
        // Close the launch Channel.
        Reply::Unit(Ok(())),
    ]
}

fn stage_replies(ids: u32) -> Vec<Reply> {
    let mut stage = vec![0; STAGE_BYTES];
    pci_driver::encode(stage_message(), &mut stage).unwrap();
    vec![
        Reply::Deadline(Ok(DwDeadline(200))),
        ready_wait(0, DW_SIGNAL_READABLE),
        receive(stage, vec![resource_handle()]),
        Reply::DeviceResourceInfo(Ok(resource_info())),
        Reply::Pio(Ok(ids)),
    ]
}

fn published_header() -> RegistryHeader {
    RegistryHeader {
        message_type: RegistryMessageType::Publish,
        registry_generation: 3,
        endpoint_id: 9,
        endpoint_generation: 1,
        transaction_id: 0x55,
    }
}

fn registry_bytes(message_type: RegistryMessageType) -> Vec<u8> {
    let mut bytes = vec![0; REGISTRY_HEADER_BYTES];
    let size = encode_empty(
        RegistryHeader {
            message_type,
            ..published_header()
        },
        &mut bytes,
    )
    .unwrap();
    bytes.truncate(size);
    bytes
}

fn offer_bytes() -> Vec<u8> {
    let mut bytes = vec![0; 512];
    let size = encode_lookup(
        RegistryHeader {
            message_type: RegistryMessageType::ConnectOffer,
            ..published_header()
        },
        Lookup {
            protocol_id: BLOCK_DEVICE_PROTOCOL_ID,
            version: ProtocolVersion { major: 1, minor: 0 },
            service_name: BOOT_DISK_SERVICE_NAME,
        },
        &mut bytes,
    )
    .unwrap();
    bytes.truncate(size);
    bytes
}

/// Hands the role the model device in place of the two address-space
/// mappings, and keeps it when the role gives it back.
struct ModelMapper {
    model: Option<Model>,
    returned: Option<Model>,
}

impl ModelMapper {
    fn new(model: Model) -> Self {
        Self {
            model: Some(model),
            returned: None,
        }
    }
}

impl role::DeviceMapper<RecordingPlatform> for ModelMapper {
    type Hardware = Model;

    fn map(
        &mut self,
        platform: &mut RecordingPlatform,
        root: DwHandle,
        bar: DwHandle,
        bar_bytes: u64,
        dma: DwHandle,
    ) -> Result<Model, wyrmroot_runtime::NativeError> {
        assert_eq!(
            (root, bar, bar_bytes, dma),
            (SELF_ROOT, BAR_OBJECT, BAR_BYTES, DMA_OBJECT)
        );
        // The device is mapped, and so reset, before it can reach any of the
        // driver's memory: no DMA mapping or bus mastering yet (review D3).
        assert!(
            !platform.calls().iter().any(|call| matches!(
                call,
                Call::DmaMap { .. }
                    | Call::DevicePciCommand {
                        bus_master: true,
                        ..
                    }
            )),
            "the device could reach driver memory before its reset"
        );
        Ok(self.model.take().expect("mapped twice"))
    }

    fn unmap(&mut self, _: &mut RecordingPlatform, hardware: Model) -> bool {
        self.returned = Some(hardware);
        true
    }
}

const BAR_OBJECT: DwHandle = DwHandle(0x30);
const DMA_OBJECT: DwHandle = DwHandle(0x31);
const CLIENT: DwHandle = DwHandle(0x32);
const CLIENT_MEMORY: DwHandle = DwHandle(0x33);

fn run_scripted(script: Vec<Reply>) -> (u32, Vec<Call>) {
    let (code, calls, _) = run_with_model(script, Model::new());
    (code, calls)
}

fn run_with_model(script: Vec<Reply>, model: Model) -> (u32, Vec<Call>, Option<Model>) {
    let mut platform = RecordingPlatform::scripted(script);
    let mut mapper = ModelMapper::new(model);
    let code = role::blk_main(&mut platform, &mut mapper, BOOTSTRAP);
    platform.assert_script_consumed();
    (code, platform.take_calls(), mapper.returned)
}

/// The config-space reads the capability walk makes, answered from the
/// model's config space.
fn capability_replies() -> Vec<Reply> {
    let config = crate::virtio_tests::config_space();
    let mut read = crate::virtio_tests::reader(&config);
    let mut replies = Vec::new();
    crate::virtio::find_capabilities(|offset, width| {
        let value = read(offset, width);
        replies.push(Reply::Pio(value.map_err(|()| unreachable!())));
        value
    })
    .unwrap();
    replies
}

/// READY, then bring-up and the self-test read.
fn bring_up_replies() -> Vec<Reply> {
    let mut replies = vec![Reply::Unit(Ok(()))];
    replies.extend(capability_replies());
    replies.extend([
        // Memory decoding on, the BAR object and its size, the DMA object
        // and its IOVA, bus mastering on.
        Reply::Unit(Ok(())),
        Reply::Handle(Ok(BAR_OBJECT)),
        Reply::Value(Ok(BAR_BYTES)),
        Reply::Handle(Ok(DMA_OBJECT)),
        Reply::Value(Ok(MEM_IOVA)),
        Reply::Unit(Ok(())),
        // The two self-test reads' deadlines; the model completes at once.
        Reply::Deadline(Ok(DwDeadline(1_000))),
        Reply::Deadline(Ok(DwDeadline(1_000))),
    ]);
    replies
}

fn publish_replies() -> Vec<Reply> {
    vec![
        Reply::Unit(Ok(())),
        Reply::Deadline(Ok(DwDeadline(300))),
        ready_wait(0, DW_SIGNAL_READABLE),
        receive(registry_bytes(RegistryMessageType::Published), vec![]),
    ]
}

/// Bus mastering off, the DMA object unmapped, both objects closed, then
/// the resource, publication, control and self root.
fn retire_replies(connections_with_buffers: usize) -> Vec<Reply> {
    let mut replies = vec![Reply::Unit(Ok(()))];
    replies.extend((0..connections_with_buffers * 3).map(|_| Reply::Unit(Ok(()))));
    replies.extend((0..7).map(|_| Reply::Unit(Ok(()))));
    replies
}

fn retire_calls() -> Vec<Call> {
    vec![
        Call::DmaUnmap {
            resource: RESOURCE,
            iova: MEM_IOVA,
            byte_len: crate::virtio::DMA_BYTES,
        },
        Call::CloseHandle { handle: DMA_OBJECT },
        Call::CloseHandle { handle: BAR_OBJECT },
        Call::CloseHandle { handle: RESOURCE },
        Call::CloseHandle {
            handle: PUBLICATION,
        },
        Call::CloseHandle { handle: CONTROL },
        Call::CloseHandle { handle: SELF_ROOT },
    ]
}

fn sent_on(calls: &[Call], channel: DwHandle) -> Vec<Vec<u8>> {
    calls
        .iter()
        .filter_map(|call| match call {
            Call::SendChannel {
                channel: target,
                bytes,
                transfers,
            } if *target == channel => {
                assert!(transfers.is_empty(), "the driver never sends a handle");
                Some(bytes.clone())
            }
            _ => None,
        })
        .collect()
}

fn wrbd_request(transaction_id: u64, body: WrbdBody) -> Vec<u8> {
    let mut bytes = [0u8; WRBD_MAX_BYTES];
    let size = wyrmroot_block_proto::encode(
        WrbdMessage {
            transaction_id,
            body,
        },
        &mut bytes,
    )
    .unwrap();
    bytes[..size].to_vec()
}

fn client_memory(rights: DwRights) -> DwReceivedHandleInfoV1 {
    DwReceivedHandleInfoV1 {
        handle: CLIENT_MEMORY,
        object_type: DW_OBJECT_TYPE_MEMORY_OBJECT,
        rights,
        ..DwReceivedHandleInfoV1::default()
    }
}

fn accept_client() -> Vec<Reply> {
    vec![
        ready_wait(1, DW_SIGNAL_READABLE),
        receive(offer_bytes(), vec![channel(CLIENT)]),
    ]
}

/// The client's Channel is wait item 2, after control and publication.
fn client_sends(bytes: Vec<u8>, handles: Vec<DwReceivedHandleInfoV1>) -> Vec<Reply> {
    vec![ready_wait(2, DW_SIGNAL_READABLE), receive(bytes, handles)]
}

fn replies_to_client(calls: &[Call]) -> Vec<WrbdMessage> {
    sent_on(calls, CLIENT)
        .iter()
        .map(|bytes| wyrmroot_block_proto::parse(bytes, 0).unwrap())
        .collect()
}

#[test]
fn the_driver_brings_up_the_disk_reads_block_zero_and_publishes_only_then() {
    let mut script = startup_replies();
    script.extend(stage_replies(BOOT_DISK_POLICY.pci.ids));
    script.extend(bring_up_replies());
    script.extend(publish_replies());
    // devmgr closes the control Channel.
    script.push(ready_wait(0, DW_SIGNAL_PEER_CLOSED));
    script.extend(retire_replies(0));
    let (code, calls, model) = run_with_model(script, Model::new());
    assert_eq!(code, 0);
    let model = model.unwrap();

    let mut ready = [0; READY_BYTES];
    pci_driver::encode(
        PciDriverMessage::Ready {
            identity: identity(),
        },
        &mut ready,
    )
    .unwrap();
    assert_eq!(sent_on(&calls, CONTROL), [ready.to_vec()]);
    assert_eq!(
        sent_on(&calls, PUBLICATION),
        [registry_bytes(RegistryMessageType::Publish)]
    );
    // The bring-up order: memory decoding, the BAR, DMA memory mapped for
    // the device, and only then bus mastering.
    let device_calls: Vec<&Call> = calls
        .iter()
        .filter(|call| {
            matches!(
                call,
                Call::DevicePciCommand { .. }
                    | Call::DeviceMmioObjectCreate { .. }
                    | Call::CreateMemoryObject { .. }
                    | Call::DmaMap { .. }
                    | Call::DmaUnmap { .. }
            )
        })
        .collect();
    assert_eq!(
        device_calls,
        [
            &Call::DevicePciCommand {
                resource: RESOURCE,
                memory_space: true,
                bus_master: false
            },
            &Call::DeviceMmioObjectCreate {
                resource: RESOURCE,
                bar: 4,
                requested_rights: DwRights(
                    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0 | DW_RIGHT_INSPECT.0
                ),
            },
            &Call::CreateMemoryObject {
                bytes: crate::virtio::DMA_BYTES,
                rights: DwRights(
                    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0 | DW_RIGHT_INSPECT.0
                ),
            },
            &Call::DmaMap {
                resource: RESOURCE,
                memory_object: DMA_OBJECT,
                offset: 0,
                byte_len: crate::virtio::DMA_BYTES,
                access: DW_DMA_ACCESS_DEVICE_READ | DW_DMA_ACCESS_DEVICE_WRITE,
            },
            &Call::DevicePciCommand {
                resource: RESOURCE,
                memory_space: true,
                bus_master: true
            },
            &Call::DevicePciCommand {
                resource: RESOURCE,
                memory_space: false,
                bus_master: false
            },
            &Call::DmaUnmap {
                resource: RESOURCE,
                iova: MEM_IOVA,
                byte_len: crate::virtio::DMA_BYTES,
            },
        ]
    );
    // Two reads of block 0, before the PUBLISH; the device was reset at exit.
    assert_eq!(
        model.executed,
        [
            (crate::virtio::BLK_T_IN, 0, 512),
            (crate::virtio::BLK_T_IN, 0, 512)
        ]
    );
    assert_eq!(model.status, 0);
    let publish = calls
        .iter()
        .position(
            |call| matches!(call, Call::SendChannel { channel, .. } if *channel == PUBLICATION),
        )
        .unwrap();
    // The self-test read's deadline is the first after bus mastering.
    let bus_master = calls
        .iter()
        .position(|call| {
            matches!(
                call,
                Call::DevicePciCommand {
                    bus_master: true,
                    ..
                }
            )
        })
        .unwrap();
    let self_test = bus_master
        + calls[bus_master..]
            .iter()
            .position(|call| matches!(call, Call::MonotonicDeadlineAfter { .. }))
            .unwrap();
    assert!(self_test < publish);
    assert!(calls.ends_with(&retire_calls()));
}

/// Whatever block 0 holds, a blank data disk included, the driver
/// publishes once its reads reach memory.
#[test]
fn a_blank_disk_is_published() {
    let mut model = Model::new();
    model.disk.fill(0);
    let mut script = startup_replies();
    script.extend(stage_replies(BOOT_DISK_POLICY.pci.ids));
    script.extend(bring_up_replies());
    script.extend(publish_replies());
    // The control Channel closes: the driver retires.
    script.push(ready_wait(0, DW_SIGNAL_PEER_CLOSED));
    script.extend(retire_replies(0));
    let (_, calls, _) = run_with_model(script, model);
    assert!(!sent_on(&calls, PUBLICATION).is_empty());
}

#[test]
fn a_device_whose_reads_never_reach_memory_is_never_published() {
    let mut model = Model::new();
    model.drop_reads = true;
    let mut script = startup_replies();
    script.extend(stage_replies(BOOT_DISK_POLICY.pci.ids));
    script.extend(bring_up_replies());
    script.extend(retire_replies(0));
    let (code, calls, model) = run_with_model(script, model);
    assert_eq!(code, role::FAILURE_BASE | 126);
    assert!(sent_on(&calls, PUBLICATION).is_empty());
    assert_eq!(model.unwrap().status, 0, "the device was reset");
    assert!(calls.ends_with(&retire_calls()));
}

#[test]
fn a_device_without_iommu_translation_stops_the_driver_before_any_request() {
    let mut model = Model::new();
    model.offered &= !crate::virtio::FEATURE_ACCESS_PLATFORM;
    let mut script = startup_replies();
    script.extend(stage_replies(BOOT_DISK_POLICY.pci.ids));
    let mut bring_up = bring_up_replies();
    // Neither self-test read is made.
    bring_up.truncate(bring_up.len() - 2);
    script.extend(bring_up);
    script.extend(retire_replies(0));
    let (code, calls, model) = run_with_model(script, model);
    assert_eq!(code, role::FAILURE_BASE | 115);
    let model = model.unwrap();
    assert!(model.executed.is_empty());
    assert!(model.status & crate::virtio::STATUS_FAILED != 0);
    assert!(sent_on(&calls, PUBLICATION).is_empty());
}

#[test]
fn a_client_attaches_a_buffer_and_reads_writes_and_flushes_through_it() {
    let mut script = startup_replies();
    script.extend(stage_replies(BOOT_DISK_POLICY.pci.ids));
    script.extend(bring_up_replies());
    script.extend(publish_replies());
    script.extend(accept_client());
    script.extend(client_sends(wrbd_request(1, WrbdBody::GetInfo), vec![]));
    script.push(Reply::Unit(Ok(())));
    script.extend(client_sends(
        wrbd_request(2, WrbdBody::Attach { byte_len: 0x1_0000 }),
        vec![client_memory(role::ATTACH_RIGHTS)],
    ));
    script.extend([Reply::Value(Ok(CLIENT_IOVA)), Reply::Unit(Ok(()))]);
    let read = wyrmroot_block_proto::Transfer {
        lba: 1,
        block_count: 2,
        buffer_offset: 512,
    };
    script.extend(client_sends(wrbd_request(3, WrbdBody::Read(read)), vec![]));
    script.extend([Reply::Deadline(Ok(DwDeadline(2_000))), Reply::Unit(Ok(()))]);
    let write = wyrmroot_block_proto::Transfer {
        lba: 40,
        block_count: 1,
        buffer_offset: 512,
    };
    script.extend(client_sends(
        wrbd_request(4, WrbdBody::Write(write)),
        vec![],
    ));
    script.extend([Reply::Deadline(Ok(DwDeadline(3_000))), Reply::Unit(Ok(()))]);
    script.extend(client_sends(wrbd_request(5, WrbdBody::Flush), vec![]));
    script.extend([Reply::Deadline(Ok(DwDeadline(4_000))), Reply::Unit(Ok(()))]);
    // Past the end of the disk: refused before the device sees it.
    let beyond = wyrmroot_block_proto::Transfer {
        lba: SECTORS,
        block_count: 1,
        buffer_offset: 0,
    };
    script.extend(client_sends(
        wrbd_request(6, WrbdBody::Read(beyond)),
        vec![],
    ));
    script.push(Reply::Unit(Ok(())));
    // The client leaves: its buffer is unmapped, then closed with its Channel.
    script.push(ready_wait(2, DW_SIGNAL_PEER_CLOSED));
    script.extend([
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
    ]);
    script.push(ready_wait(0, DW_SIGNAL_PEER_CLOSED));
    script.extend(retire_replies(0));
    let (code, calls, model) = run_with_model(script, Model::new());
    assert_eq!(code, 0);
    let model = model.unwrap();

    let replies = replies_to_client(&calls);
    let complete = |transaction_id, status| WrbdMessage {
        transaction_id,
        body: WrbdBody::Complete(status),
    };
    assert_eq!(
        replies,
        [
            WrbdMessage {
                transaction_id: 1,
                body: WrbdBody::Info(wyrmroot_block_proto::Info {
                    block_size: 512,
                    flags: wyrmroot_block_proto::INFO_FLUSH,
                    block_count: SECTORS,
                    max_transfer_blocks: 256,
                }),
            },
            complete(2, WrbdStatus::Ok),
            complete(3, WrbdStatus::Ok),
            complete(4, WrbdStatus::Ok),
            complete(5, WrbdStatus::Ok),
            complete(6, WrbdStatus::OutOfRange),
        ]
    );
    // The read landed in the client's buffer; the write came from it.
    assert_eq!(model.client[512..1536], model.disk[512..1536]);
    assert_eq!(model.disk[40 * 512..41 * 512], model.disk[512..1024]);
    assert!(calls.contains(&Call::DmaMap {
        resource: RESOURCE,
        memory_object: CLIENT_MEMORY,
        offset: 0,
        byte_len: 0x1_0000,
        access: DW_DMA_ACCESS_DEVICE_READ | DW_DMA_ACCESS_DEVICE_WRITE,
    }));
    let unmap = calls
        .iter()
        .position(|call| {
            *call
                == Call::DmaUnmap {
                    resource: RESOURCE,
                    iova: CLIENT_IOVA,
                    byte_len: 0x1_0000,
                }
        })
        .unwrap();
    assert_eq!(
        calls[unmap + 1..unmap + 3],
        [
            Call::CloseHandle {
                handle: CLIENT_MEMORY
            },
            Call::CloseHandle { handle: CLIENT }
        ]
    );
}

#[test]
fn bad_attachments_are_refused_and_their_handles_closed() {
    let mut script = startup_replies();
    script.extend(stage_replies(BOOT_DISK_POLICY.pci.ids));
    script.extend(bring_up_replies());
    script.extend(publish_replies());
    script.extend(accept_client());
    // A read before any buffer.
    let read = wyrmroot_block_proto::Transfer {
        lba: 0,
        block_count: 1,
        buffer_offset: 0,
    };
    script.extend(client_sends(wrbd_request(1, WrbdBody::Read(read)), vec![]));
    script.push(Reply::Unit(Ok(())));
    // Wider rights than a DMA buffer needs: closed, Invalid.
    script.extend(client_sends(
        wrbd_request(2, WrbdBody::Attach { byte_len: 4096 }),
        vec![client_memory(DwRights(
            role::ATTACH_RIGHTS.0 | DW_RIGHT_DUPLICATE.0,
        ))],
    ));
    script.extend([Reply::Unit(Ok(())), Reply::Unit(Ok(()))]);
    // Above the attach limit: closed, Invalid, never mapped.
    script.extend(client_sends(
        wrbd_request(
            3,
            WrbdBody::Attach {
                byte_len: crate::block::MAX_ATTACH_BYTES + 4096,
            },
        ),
        vec![client_memory(role::ATTACH_RIGHTS)],
    ));
    script.extend([Reply::Unit(Ok(())), Reply::Unit(Ok(()))]);
    // The kernel has no room: closed, NoResources.
    script.extend(client_sends(
        wrbd_request(4, WrbdBody::Attach { byte_len: 4096 }),
        vec![client_memory(role::ATTACH_RIGHTS)],
    ));
    script.extend([
        Reply::Value(Err(wyrmroot_runtime::NativeError::Status(
            deepwyrm_syscall::DW_STATUS_NO_RESOURCES,
        ))),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
    ]);
    // A malformed message closes the connection (no buffer to unmap).
    script.extend(client_sends(vec![0; 40], vec![]));
    script.push(Reply::Unit(Ok(())));
    script.push(ready_wait(0, DW_SIGNAL_PEER_CLOSED));
    script.extend(retire_replies(0));
    let (code, calls, model) = run_with_model(script, Model::new());
    assert_eq!(code, 0);
    assert!(
        model.unwrap().executed.len() == 2,
        "only the two self-test reads"
    );
    let statuses: Vec<_> = replies_to_client(&calls)
        .into_iter()
        .map(|message| message.body)
        .collect();
    assert_eq!(
        statuses,
        [
            WrbdBody::Complete(WrbdStatus::NoBuffer),
            WrbdBody::Complete(WrbdStatus::Invalid),
            WrbdBody::Complete(WrbdStatus::Invalid),
            WrbdBody::Complete(WrbdStatus::NoResources),
        ]
    );
    let memory_closes = calls
        .iter()
        .filter(|call| {
            **call
                == Call::CloseHandle {
                    handle: CLIENT_MEMORY,
                }
        })
        .count();
    assert_eq!(memory_closes, 3);
    let client_maps = calls
        .iter()
        .filter(|call| matches!(call, Call::DmaMap { memory_object, .. } if *memory_object == CLIENT_MEMORY))
        .count();
    assert_eq!(client_maps, 1);
    assert!(calls.contains(&Call::CloseHandle { handle: CLIENT }));
}

#[test]
fn offers_for_another_service_or_beyond_the_limit_are_closed() {
    let mut script = startup_replies();
    script.extend(stage_replies(BOOT_DISK_POLICY.pci.ids));
    script.extend(bring_up_replies());
    script.extend(publish_replies());
    // An offer naming another protocol version.
    let mut other = vec![0; 512];
    let size = encode_lookup(
        RegistryHeader {
            message_type: RegistryMessageType::ConnectOffer,
            ..published_header()
        },
        Lookup {
            protocol_id: BLOCK_DEVICE_PROTOCOL_ID,
            version: ProtocolVersion { major: 2, minor: 0 },
            service_name: BOOT_DISK_SERVICE_NAME,
        },
        &mut other,
    )
    .unwrap();
    other.truncate(size);
    script.push(ready_wait(1, DW_SIGNAL_READABLE));
    script.push(receive(other, vec![channel(OFFERED)]));
    script.push(Reply::Unit(Ok(())));
    // Four accepted, the fifth closed.
    for index in 0..5u64 {
        script.push(ready_wait(1, DW_SIGNAL_READABLE));
        script.push(receive(
            offer_bytes(),
            vec![channel(DwHandle(0x40 + index))],
        ));
    }
    script.push(Reply::Unit(Ok(())));
    script.push(ready_wait(0, DW_SIGNAL_PEER_CLOSED));
    // Retirement closes the four accepted Channels.
    let mut retire = retire_replies(0);
    retire.extend((0..4).map(|_| Reply::Unit(Ok(()))));
    script.extend(retire);
    let (code, calls) = run_scripted(script);
    assert_eq!(code, 0);
    let closes: Vec<_> = calls
        .iter()
        .filter_map(|call| match call {
            Call::CloseHandle { handle }
                if handle.0 == 0x24 || (0x40..0x50).contains(&handle.0) =>
            {
                Some(handle.0)
            }
            _ => None,
        })
        .collect();
    assert_eq!(closes, [0x24, 0x44, 0x40, 0x41, 0x42, 0x43]);
    // The serve loop waits on control, publication and every connection.
    assert!(
        calls.contains(&Call::WaitMany {
            items: [
                CONTROL,
                PUBLICATION,
                DwHandle(0x40),
                DwHandle(0x41),
                DwHandle(0x42),
                DwHandle(0x43)
            ]
            .map(|handle| DwWaitItemV1 {
                handle,
                signals: DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
            })
            .to_vec(),
            deadline: DW_DEADLINE_INFINITE,
        })
    );
}

#[test]
fn a_hung_request_times_out_resets_the_device_and_stops_the_driver() {
    let mut script = startup_replies();
    script.extend(stage_replies(BOOT_DISK_POLICY.pci.ids));
    script.extend(bring_up_replies());
    script.extend(publish_replies());
    script.extend(accept_client());
    script.extend(client_sends(wrbd_request(1, WrbdBody::Flush), vec![]));
    // Before the deadline, then past it.
    script.extend([
        Reply::Deadline(Ok(DwDeadline(5_000))),
        Reply::Value(Ok(4_999)),
        Reply::Value(Ok(5_000)),
    ]);
    // Retirement: the client Channel (no buffer) is closed too.
    let mut retire = retire_replies(0);
    retire.push(Reply::Unit(Ok(())));
    script.extend(retire);
    let mut platform = RecordingPlatform::scripted(script);
    let mut mapper = ModelMapper::new(Model::new());
    // The self-test reads complete; the model stalls from the flush on.
    let code = role::blk_main(
        &mut platform,
        &mut StallAfterSelfTest(&mut mapper),
        BOOTSTRAP,
    );
    platform.assert_script_consumed();
    assert_eq!(code, role::FAILURE_BASE | 131);
    let calls = platform.take_calls();
    // No reply was sent: the client sees its Channel close.
    assert!(sent_on(&calls, CLIENT).is_empty());
    assert!(calls.contains(&Call::CloseHandle { handle: CLIENT }));
    let model = mapper.returned.unwrap();
    assert_eq!(
        model.status, 0,
        "the device was reset before memory was released"
    );
}

/// A mapper whose model stalls after the self-test read.
struct StallAfterSelfTest<'m>(&'m mut ModelMapper);

struct Stalling(Model);

impl crate::virtio::Hardware for Stalling {
    fn bar_read(
        &mut self,
        offset: u64,
        width: crate::virtio::Width,
    ) -> Result<u64, crate::virtio::Fault> {
        self.0.bar_read(offset, width)
    }

    fn bar_write(
        &mut self,
        offset: u64,
        width: crate::virtio::Width,
        value: u64,
    ) -> Result<(), crate::virtio::Fault> {
        let result = self.0.bar_write(offset, width, value);
        if self.0.executed.len() >= 2 {
            self.0.stall = true;
        }
        result
    }

    fn mem_read(
        &mut self,
        offset: u64,
        width: crate::virtio::Width,
    ) -> Result<u64, crate::virtio::Fault> {
        self.0.mem_read(offset, width)
    }

    fn mem_write(
        &mut self,
        offset: u64,
        width: crate::virtio::Width,
        value: u64,
    ) -> Result<(), crate::virtio::Fault> {
        self.0.mem_write(offset, width, value)
    }
}

impl role::DeviceMapper<RecordingPlatform> for StallAfterSelfTest<'_> {
    type Hardware = Stalling;

    fn map(
        &mut self,
        platform: &mut RecordingPlatform,
        root: DwHandle,
        bar: DwHandle,
        bar_bytes: u64,
        dma: DwHandle,
    ) -> Result<Stalling, wyrmroot_runtime::NativeError> {
        self.0
            .map(platform, root, bar, bar_bytes, dma)
            .map(Stalling)
    }

    fn unmap(&mut self, platform: &mut RecordingPlatform, hardware: Stalling) -> bool {
        self.0.unmap(platform, hardware.0)
    }
}

#[test]
fn a_function_with_other_ids_gets_no_ready_and_no_publication() {
    let mut script = startup_replies();
    script.extend(stage_replies(0x1001_1af4));
    script.extend([
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
    ]);
    let (code, calls) = run_scripted(script);
    assert_eq!(code, role::FAILURE_BASE | StageError::WrongIds.code());
    assert!(sent_on(&calls, CONTROL).is_empty());
    assert!(sent_on(&calls, PUBLICATION).is_empty());
    // The function was never touched beyond its config space.
    assert!(!calls.iter().any(|call| matches!(
        call,
        Call::DevicePciCommand { .. } | Call::DeviceMmioObjectCreate { .. } | Call::DmaMap { .. }
    )));
    assert!(calls.ends_with(&[
        Call::CloseHandle { handle: RESOURCE },
        Call::CloseHandle {
            handle: PUBLICATION
        },
        Call::CloseHandle { handle: CONTROL },
        Call::CloseHandle { handle: SELF_ROOT },
    ]));
}

#[test]
fn a_launch_channel_closed_before_the_grant_stops_the_driver_unstaged() {
    let mut script = startup_replies();
    script.truncate(3);
    script.extend([
        ready_wait(0, DW_SIGNAL_PEER_CLOSED),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
        Reply::Unit(Ok(())),
    ]);
    let (code, calls) = run_scripted(script);
    assert_eq!(code, role::FAILURE_BASE | 11);
    assert!(calls.ends_with(&[
        Call::CloseHandle { handle: CONTROL },
        Call::CloseHandle { handle: SELF_ROOT },
        Call::CloseHandle { handle: BOOTSTRAP },
    ]));
}

/// `bytes` in `minor`, with `extra` trailing bytes a later minor might
/// append (X1).
fn in_minor(mut bytes: Vec<u8>, minor: u16, extra: &[u8]) -> Vec<u8> {
    bytes.extend_from_slice(extra);
    bytes[6..8].copy_from_slice(&minor.to_le_bytes());
    let size = bytes.len() as u32;
    bytes[12..16].copy_from_slice(&size.to_le_bytes());
    bytes
}

#[test]
fn the_driver_answers_in_the_request_minor_and_reports_its_version() {
    use wyrmroot_block_proto::{MINOR, Version};
    let mut script = startup_replies();
    script.extend(stage_replies(BOOT_DISK_POLICY.pci.ids));
    script.extend(bring_up_replies());
    script.extend(publish_replies());
    script.extend(accept_client());
    // A 1.0 client.
    script.extend(client_sends(
        in_minor(wrbd_request(1, WrbdBody::GetInfo), 0, &[]),
        vec![],
    ));
    script.push(Reply::Unit(Ok(())));
    // A later one, with fields this driver does not know.
    script.extend(client_sends(
        in_minor(wrbd_request(2, WrbdBody::QueryVersion), MINOR + 1, &[7; 24]),
        vec![],
    ));
    script.push(Reply::Unit(Ok(())));
    // QUERY_VERSION in a 1.0 header is malformed: the connection closes.
    script.extend(client_sends(
        in_minor(wrbd_request(3, WrbdBody::QueryVersion), 0, &[]),
        vec![],
    ));
    script.push(Reply::Unit(Ok(())));
    script.push(ready_wait(0, DW_SIGNAL_PEER_CLOSED));
    script.extend(retire_replies(0));
    let (code, calls) = run_scripted(script);
    assert_eq!(code, 0);
    let sent = sent_on(&calls, CLIENT);
    assert_eq!(sent.len(), 2);
    assert_eq!(&sent[0][6..8], &0u16.to_le_bytes());
    assert!(matches!(
        wyrmroot_block_proto::parse(&sent[0], 0).unwrap().body,
        WrbdBody::Info(_)
    ));
    assert_eq!(&sent[1][6..8], &MINOR.to_le_bytes());
    assert_eq!(
        wyrmroot_block_proto::parse(&sent[1], 0).unwrap().body,
        WrbdBody::Version(Version::current(0))
    );
    assert!(calls.contains(&Call::CloseHandle { handle: CLIENT }));
}
