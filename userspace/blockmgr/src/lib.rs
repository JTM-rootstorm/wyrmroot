//! blockmgr: finds the boot volume on the boot disk and serves it as the
//! `volume.boot0` WRBD BlockDevice (root `STORAGE_PLAN.md` W6).
//!
//! The boot volume is the EFI System Partition: the whole disk when it has
//! no partition table and LBA 0 is a FAT boot sector (the product's ESP),
//! the first EFI System partition of a GPT, or the first type-0xEF entry of
//! an MBR. Discovery is `wyrmroot-partition` (W4) over one connection to the
//! disk driver, which is closed again before serving.
//!
//! Each client gets its own connection to the driver. Its ATTACH passes
//! straight through, so the device reads and writes the client's buffer
//! directly and no data crosses blockmgr. READ and WRITE are checked against
//! the volume and shifted by its first block; GET_INFO is answered with the
//! volume's geometry. A client that breaks WRBD, or whose driver connection
//! fails, loses both connections and nothing else.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;
#[cfg(test)]
use wyrmroot_loader as _;
#[cfg(feature = "native-blockmgr")]
use wyrmroot_loader as _;

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_MEMORY_OBJECT, DW_RIGHT_READ,
    DW_RIGHT_WRITE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwHandle, DwHandleTransferV1,
    DwReceivedHandleInfoV1, DwRights, DwSignals, DwWaitItemV1,
};
use wyrmroot_block_proto::{self as wrbd, Body, Info, MAX_BYTES, Message, Status, Transfer};
use wyrmroot_device_proto::manifest::BOOT_DISK_PUBLICATION_POLICY;
use wyrmroot_partition::{
    BlockSource, DeviceError, PartitionTable, PartitionType, Scheme, discover,
};
use wyrmroot_runtime::{MemoryPlatform, WYR0_I_SUPERVISION_POLICY};
use wyrmroot_service::block::BlockClient;
use wyrmroot_service::memory::{LEND_RIGHTS, Mapper, View, create_buffer};
use wyrmroot_service::{
    Launch, Registry, ServiceName, ServicePlatform, accept_offer, publish, receive_stage, startup,
};
use wyrmroot_service_proto::roles::{BLOCKMGR_ROLE_ID, BOOT_VOLUME};

pub const FAILURE_BASE: u32 = 0xB10C_0000;
/// Clients served at once; the driver serves four connections, and
/// discovery's is closed before the first client arrives.
pub const MAX_LINKS: usize = 3;
/// How long the boot disk may take to appear, from blockmgr's start.
pub const DISK_TIMEOUT_NS: u64 = 60_000_000_000;
/// The discovery buffer: one block of up to 4 KiB.
const DISCOVERY_BYTES: u64 = 4096;
/// What the driver receives with ATTACH (`virtio-blkd`'s `ATTACH_RIGHTS`).
const DRIVER_ATTACH_RIGHTS: DwRights = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0);
const READABLE_OR_CLOSED: DwSignals = DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0);
const MBR_TYPE_EFI_SYSTEM: u8 = 0xef;

pub trait BlockmgrPlatform: ServicePlatform + MemoryPlatform {}
impl<P: ServicePlatform + MemoryPlatform + ?Sized> BlockmgrPlatform for P {}

/// The boot disk as the registry names it.
pub const BOOT_DISK: ServiceName = ServiceName {
    name: BOOT_DISK_PUBLICATION_POLICY.service_name,
    protocol_id: BOOT_DISK_PUBLICATION_POLICY.protocol_id,
    major: BOOT_DISK_PUBLICATION_POLICY.protocol_major,
    minor: BOOT_DISK_PUBLICATION_POLICY.protocol_minor,
    supervisor_role_id: BOOT_DISK_PUBLICATION_POLICY.supervisor_role_id,
};

/// A block range of the disk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Volume {
    pub first_block: u64,
    pub block_count: u64,
}

/// Picks the boot volume out of a discovered table.
pub fn boot_volume(table: &PartitionTable, disk_blocks: u64) -> Option<Volume> {
    match table.scheme() {
        Scheme::None {
            fat_boot_sector: true,
        } => Some(Volume {
            first_block: 0,
            block_count: disk_blocks,
        }),
        Scheme::None { .. } => None,
        Scheme::Gpt(_) => table
            .gpt_partitions()
            .iter()
            .find(|partition| partition.partition_type() == PartitionType::EfiSystem)
            .map(|partition| Volume {
                first_block: partition.first_lba(),
                block_count: partition.block_count(),
            }),
        Scheme::Mbr => table
            .mbr_partitions()
            .iter()
            .find(|partition| partition.os_type() == MBR_TYPE_EFI_SYSTEM)
            .map(|partition| Volume {
                first_block: partition.first_lba(),
                block_count: partition.block_count(),
            }),
    }
}

/// Discovery reads whole blocks through the driver into one mapped buffer.
struct DiskSource<'a, P: ?Sized, V> {
    platform: &'a mut P,
    client: &'a mut BlockClient,
    view: &'a V,
}

impl<P: BlockmgrPlatform + ?Sized, V: View> BlockSource for DiskSource<'_, P, V> {
    fn block_size(&self) -> u32 {
        self.client.info.block_size
    }

    fn block_count(&self) -> u64 {
        self.client.info.block_count
    }

    fn read_block(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), DeviceError> {
        let deadline = self
            .platform
            .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .map_err(|_| DeviceError(1))?;
        match self.client.read(self.platform, lba, 1, 0, deadline) {
            Ok(Status::Ok) if self.view.read(0, buffer) => Ok(()),
            Ok(status) => Err(DeviceError(status as u32 + 0x100)),
            Err(step) => Err(DeviceError(step)),
        }
    }
}

/// Runs blockmgr; returns its exit code (0 when init asks it to retire).
pub fn blockmgr_main<P: BlockmgrPlatform, M: Mapper<P>>(
    platform: &mut P,
    mapper: &mut M,
    bootstrap: DwHandle,
) -> u32 {
    match run(platform, mapper, bootstrap) {
        Ok(()) => 0,
        Err(step) => FAILURE_BASE | step,
    }
}

fn run<P: BlockmgrPlatform, M: Mapper<P>>(
    platform: &mut P,
    mapper: &mut M,
    bootstrap: DwHandle,
) -> Result<(), u32> {
    let launch = startup(platform, bootstrap)?;
    if launch.role_id != BLOCKMGR_ROLE_ID {
        return Err(6);
    }
    let deadline = platform
        .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| 7u32)?;
    let staged = receive_stage(platform, &launch, deadline)?;
    let (Some((publication, grant)), Some((client_endpoint, identity))) =
        (staged.publication, staged.client)
    else {
        return Err(16);
    };
    if staged.channels().next().is_some() {
        return Err(17);
    }
    let mut registry = Registry::new(client_endpoint, identity);
    let (info, volume) = discover_volume(platform, mapper, &launch, &mut registry)?;
    let deadline = platform
        .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
        .map_err(|_| 90u32)?;
    publish(platform, publication, grant, deadline)?;
    let mut server = Server {
        info: Info {
            block_count: volume.block_count,
            ..info
        },
        volume,
        links: [None; MAX_LINKS],
    };
    let result = server.serve(platform, &launch, publication, grant, &mut registry);
    server.close_all(platform);
    result
}

/// Connects to the boot disk, discovers its boot volume and disconnects.
/// Steps 80..=89 (and the helpers' own).
fn discover_volume<P: BlockmgrPlatform, M: Mapper<P>>(
    platform: &mut P,
    mapper: &mut M,
    launch: &Launch,
    registry: &mut Registry,
) -> Result<(Info, Volume), u32> {
    let deadline = platform
        .monotonic_deadline_after(DISK_TIMEOUT_NS)
        .map_err(|_| 80u32)?;
    let channel = registry.connect(platform, BOOT_DISK, deadline)?;
    let result = (|| {
        let deadline = platform
            .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .map_err(|_| 81u32)?;
        let mut client = BlockClient::open(platform, channel, deadline)?;
        let (keep, lend) = create_buffer(platform, DISCOVERY_BYTES).map_err(|_| 82u32)?;
        let mapped = mapper.map(platform, launch.self_root, keep, DISCOVERY_BYTES);
        let result = match mapped {
            Ok(view) => {
                let attached = client.attach(
                    platform,
                    lend,
                    DRIVER_ATTACH_RIGHTS,
                    DISCOVERY_BYTES,
                    deadline,
                );
                let found = attached.and_then(|()| {
                    let mut table = PartitionTable::new();
                    let disk_blocks = client.info.block_count;
                    discover(
                        &mut DiskSource {
                            platform: &mut *platform,
                            client: &mut client,
                            view: &view,
                        },
                        &mut table,
                    )
                    .map_err(|_| 84u32)?;
                    boot_volume(&table, disk_blocks).ok_or(85u32)
                });
                let unmapped = mapper.unmap(platform, view);
                match found {
                    Ok(volume) if unmapped => Ok((client.info, volume)),
                    Ok(_) => Err(86),
                    Err(step) => Err(step),
                }
            }
            Err(_) => {
                let _ = platform.close_handle(lend);
                Err(83)
            }
        };
        let _ = platform.close_handle(keep);
        result
    })();
    // The driver releases its mapping of the buffer with the connection.
    let _ = platform.close_handle(channel);
    result
}

/// One client and its own driver connection.
#[derive(Clone, Copy)]
struct Link {
    client: DwHandle,
    driver: DwHandle,
    /// The client transaction the driver is answering.
    pending: Option<u64>,
}

struct Server {
    info: Info,
    volume: Volume,
    links: [Option<Link>; MAX_LINKS],
}

#[derive(Clone, Copy)]
enum Target {
    Control,
    Publication,
    Client(usize),
    Driver(usize),
}

impl Server {
    fn serve<P: BlockmgrPlatform>(
        &mut self,
        platform: &mut P,
        launch: &Launch,
        publication: DwHandle,
        grant: wyrmroot_service_proto::Publication,
        registry: &mut Registry,
    ) -> Result<(), u32> {
        loop {
            let mut items = [DwWaitItemV1::default(); 2 + 2 * MAX_LINKS];
            let mut targets = [Target::Control; 2 + 2 * MAX_LINKS];
            items[0] = DwWaitItemV1 {
                handle: launch.control,
                signals: READABLE_OR_CLOSED,
            };
            items[1] = DwWaitItemV1 {
                handle: publication,
                signals: READABLE_OR_CLOSED,
            };
            targets[1] = Target::Publication;
            let mut count = 2;
            for (slot, link) in self.links.iter().enumerate() {
                if let Some(link) = link {
                    items[count] = DwWaitItemV1 {
                        handle: link.client,
                        signals: READABLE_OR_CLOSED,
                    };
                    targets[count] = Target::Client(slot);
                    items[count + 1] = DwWaitItemV1 {
                        handle: link.driver,
                        signals: READABLE_OR_CLOSED,
                    };
                    targets[count + 1] = Target::Driver(slot);
                    count += 2;
                }
            }
            let observed = platform
                .wait_many(&items[..count], DW_DEADLINE_INFINITE)
                .map_err(|_| 100u32)?;
            let index = observed.index as usize;
            if index >= count {
                return Err(101);
            }
            let readable = observed.observed.0 & DW_SIGNAL_READABLE.0 != 0;
            match targets[index] {
                // Init sends nothing after STAGE; its closure retires us.
                Target::Control if readable => return Err(102),
                Target::Control => return Ok(()),
                // Without the registry no new client can arrive; keep serving
                // the ones we have.
                Target::Publication if !readable => return Err(103),
                Target::Publication => {
                    if let Some(client) = accept_offer(platform, publication, grant, BOOT_VOLUME)? {
                        self.add_link(platform, registry, client);
                    }
                }
                Target::Client(slot) => {
                    if !readable || !self.on_client_request(platform, slot) {
                        self.drop_link(platform, slot);
                    }
                }
                Target::Driver(slot) => {
                    if !readable || !self.on_driver_reply(platform, slot) {
                        self.drop_link(platform, slot);
                    }
                }
            }
        }
    }

    /// Gives `client` its own driver connection, or closes it.
    fn add_link<P: BlockmgrPlatform>(
        &mut self,
        platform: &mut P,
        registry: &mut Registry,
        client: DwHandle,
    ) {
        let Some(slot) = self.links.iter().position(Option::is_none) else {
            let _ = platform.close_handle(client);
            return;
        };
        let driver = platform
            .monotonic_deadline_after(WYR0_I_SUPERVISION_POLICY.ready_timeout_ns)
            .ok()
            .and_then(|deadline| registry.connect(platform, BOOT_DISK, deadline).ok());
        match driver {
            Some(driver) => {
                self.links[slot] = Some(Link {
                    client,
                    driver,
                    pending: None,
                });
            }
            None => {
                let _ = platform.close_handle(client);
            }
        }
    }

    fn drop_link<P: BlockmgrPlatform>(&mut self, platform: &mut P, slot: usize) {
        if let Some(link) = self.links[slot].take() {
            let _ = platform.close_handle(link.client);
            let _ = platform.close_handle(link.driver);
        }
    }

    fn close_all<P: BlockmgrPlatform>(&mut self, platform: &mut P) {
        for slot in 0..MAX_LINKS {
            self.drop_link(platform, slot);
        }
    }

    /// Handles one client request; `false` drops the link.
    fn on_client_request<P: BlockmgrPlatform>(&mut self, platform: &mut P, slot: usize) -> bool {
        let Some(link) = self.links[slot] else {
            return false;
        };
        let mut bytes = [0u8; MAX_BYTES];
        let mut handles = [DwReceivedHandleInfoV1::default(); wrbd::MAX_HANDLES];
        let Ok(counts) = platform.receive_channel(link.client, &mut bytes, &mut handles) else {
            return false;
        };
        let received = &handles[..counts.handles.min(wrbd::MAX_HANDLES)];
        let message = wrbd::parse(&bytes[..counts.bytes.min(bytes.len())], counts.handles)
            .ok()
            .filter(|message| message.body.is_request());
        let (Some(message), None) = (message, link.pending) else {
            // Malformed, a reply, or a second request while one is out.
            close(platform, received);
            return false;
        };
        let local = |status| Body::Complete(status);
        let forward = match message.body {
            Body::GetInfo => Err(Body::Info(self.info)),
            Body::Attach { .. } => {
                let memory = received[0];
                if memory.object_type == DW_OBJECT_TYPE_MEMORY_OBJECT
                    && memory.rights == LEND_RIGHTS
                    && memory.reserved0 == 0
                    && memory.reserved == [0; 2]
                {
                    Ok((message.body, Some(memory.handle)))
                } else {
                    close(platform, received);
                    Err(local(Status::Invalid))
                }
            }
            Body::Read(transfer) | Body::Write(transfer) => match self.shift(transfer) {
                Some(shifted) => Ok((
                    if matches!(message.body, Body::Read(_)) {
                        Body::Read(shifted)
                    } else {
                        Body::Write(shifted)
                    },
                    None,
                )),
                None => Err(local(Status::OutOfRange)),
            },
            Body::Flush => Ok((Body::Flush, None)),
            Body::Info(_) | Body::Complete(_) => return false,
        };
        match forward {
            Err(reply) => send(platform, link.client, message.transaction_id, reply, None),
            Ok((body, memory)) => {
                if send(platform, link.driver, message.transaction_id, body, memory) {
                    self.links[slot] = Some(Link {
                        pending: Some(message.transaction_id),
                        ..link
                    });
                    true
                } else {
                    if let Some(memory) = memory {
                        let _ = platform.close_handle(memory);
                    }
                    false
                }
            }
        }
    }

    /// The transfer on the disk, or `None` if it leaves the volume.
    fn shift(&self, transfer: Transfer) -> Option<Transfer> {
        let end = transfer.lba.checked_add(u64::from(transfer.block_count))?;
        (end <= self.volume.block_count).then_some(Transfer {
            lba: transfer.lba.checked_add(self.volume.first_block)?,
            ..transfer
        })
    }

    /// Relays the driver's reply; `false` drops the link.
    fn on_driver_reply<P: BlockmgrPlatform>(&mut self, platform: &mut P, slot: usize) -> bool {
        let Some(link) = self.links[slot].as_mut() else {
            return false;
        };
        let mut bytes = [0u8; MAX_BYTES];
        let mut handles = [DwReceivedHandleInfoV1::default(); 1];
        let Ok(counts) = platform.receive_channel(link.driver, &mut bytes, &mut handles) else {
            return false;
        };
        let message = wrbd::parse(&bytes[..counts.bytes.min(bytes.len())], counts.handles).ok();
        match (message, link.pending) {
            (
                Some(Message {
                    transaction_id,
                    body: body @ Body::Complete(_),
                }),
                Some(pending),
            ) if transaction_id == pending => {
                link.pending = None;
                send(platform, link.client, transaction_id, body, None)
            }
            _ => {
                close(platform, &handles[..counts.handles.min(1)]);
                false
            }
        }
    }
}

fn close<P: BlockmgrPlatform>(platform: &mut P, received: &[DwReceivedHandleInfoV1]) {
    for info in received {
        let _ = platform.close_handle(info.handle);
    }
}

/// Sends one WRBD message, moving `memory` with the driver's attach rights.
fn send<P: BlockmgrPlatform>(
    platform: &mut P,
    channel: DwHandle,
    transaction_id: u64,
    body: Body,
    memory: Option<DwHandle>,
) -> bool {
    let mut bytes = [0u8; MAX_BYTES];
    let Ok(size) = wrbd::encode(
        Message {
            transaction_id,
            body,
        },
        &mut bytes,
    ) else {
        return false;
    };
    let transfer = memory.map(|handle| DwHandleTransferV1 {
        handle,
        requested_rights: DRIVER_ATTACH_RIGHTS,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    });
    platform
        .send_channel(channel, &bytes[..size], transfer.as_slice())
        .is_ok()
}

#[cfg(test)]
mod tests;
