//! The modern virtio PCI transport and one split virtqueue (virtio 1.2,
//! OASIS: §2.7 split virtqueues, §3.1 initialization, §4.1 PCI transport,
//! §5.2 block device). Layout constants were cross-checked against the
//! Linux UAPI headers `virtio_pci.h`, `virtio_config.h`, `virtio_ring.h` and
//! `virtio_blk.h` (BSD-3-Clause), used as reference only.
//!
//! Everything here runs against [`Hardware`]: the device's one memory BAR
//! and the driver's own DMA memory, each by byte offset. The driver's role
//! backs it with uncached BAR and ordinary DMA mappings; host tests back it
//! with a model device.
//!
//! The driver keeps one request in flight. Its DMA memory holds the queue
//! and the request's header, status byte and a scratch block; request data
//! goes straight to a client's attached buffer by IOVA.

use core::sync::atomic::{Ordering, fence};

/// Width of one register or memory access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Width {
    U8,
    U16,
    U32,
    U64,
}

/// The access was outside its mapping or misaligned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fault;

/// The device's memory BAR and the driver's DMA memory, by byte offset.
pub trait Hardware {
    fn bar_read(&mut self, offset: u64, width: Width) -> Result<u64, Fault>;
    fn bar_write(&mut self, offset: u64, width: Width, value: u64) -> Result<(), Fault>;
    fn mem_read(&mut self, offset: u64, width: Width) -> Result<u64, Fault>;
    fn mem_write(&mut self, offset: u64, width: Width, value: u64) -> Result<(), Fault>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A config-space or BAR access failed.
    Access,
    /// The capability list is missing, loops, or is malformed.
    Capabilities,
    /// A required virtio structure is absent or too short.
    MissingStructure,
    /// The structures span more than one BAR, or lie outside it.
    Layout,
    /// The device did not reset.
    Reset,
    /// The device lacks VERSION_1 or ACCESS_PLATFORM, or refused FEATURES_OK.
    Features,
    /// Queue 0 is absent, already enabled, or too small.
    Queue,
    /// The device config kept changing, or describes an unusable disk.
    Config,
    /// The device set DEVICE_NEEDS_RESET or completed something we did not
    /// submit.
    Device,
    /// A request was submitted while another is in flight, or none is.
    State,
}

// PCI configuration space.
const PCI_STATUS: u32 = 0x06;
const PCI_STATUS_CAPABILITIES: u32 = 1 << 4;
const PCI_CAPABILITIES_POINTER: u32 = 0x34;
const PCI_CAP_ID_VENDOR: u32 = 0x09;
const PCI_FIRST_CAPABILITY: u32 = 0x40;
/// More capabilities than fit above the standard header cannot exist.
const MAX_CAPABILITIES: usize = (256 - 0x40) / 4;

// virtio_pci_cap cfg_type values (§4.1.4).
const CAP_COMMON: u32 = 1;
const CAP_NOTIFY: u32 = 2;
const CAP_DEVICE: u32 = 4;
const CAP_BYTES: u32 = 16;
const NOTIFY_CAP_BYTES: u32 = 20;
const MAX_BAR: u32 = 5;

// virtio_pci_common_cfg (§4.1.4.3).
const COMMON_DEVICE_FEATURE_SELECT: u64 = 0x00;
const COMMON_DEVICE_FEATURE: u64 = 0x04;
const COMMON_DRIVER_FEATURE_SELECT: u64 = 0x08;
const COMMON_DRIVER_FEATURE: u64 = 0x0c;
const COMMON_MSIX_CONFIG: u64 = 0x10;
const COMMON_NUM_QUEUES: u64 = 0x12;
const COMMON_DEVICE_STATUS: u64 = 0x14;
const COMMON_CONFIG_GENERATION: u64 = 0x15;
const COMMON_QUEUE_SELECT: u64 = 0x16;
const COMMON_QUEUE_SIZE: u64 = 0x18;
const COMMON_QUEUE_MSIX_VECTOR: u64 = 0x1a;
const COMMON_QUEUE_ENABLE: u64 = 0x1c;
const COMMON_QUEUE_NOTIFY_OFF: u64 = 0x1e;
const COMMON_QUEUE_DESC: u64 = 0x20;
const COMMON_QUEUE_DRIVER: u64 = 0x28;
const COMMON_QUEUE_DEVICE: u64 = 0x30;
const COMMON_BYTES: u32 = 0x38;
const NO_VECTOR: u64 = 0xffff;

// Device status bits (§2.1).
pub const STATUS_ACKNOWLEDGE: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_NEEDS_RESET: u8 = 0x40;
pub const STATUS_FAILED: u8 = 0x80;

// Feature bits (§5.2.3, §6).
pub const FEATURE_BLK_RO: u64 = 1 << 5;
pub const FEATURE_BLK_SIZE: u64 = 1 << 6;
pub const FEATURE_BLK_FLUSH: u64 = 1 << 9;
pub const FEATURE_VERSION_1: u64 = 1 << 32;
pub const FEATURE_ACCESS_PLATFORM: u64 = 1 << 33;
/// Without both, the device would bypass the IOMMU or speak legacy virtio.
pub const REQUIRED_FEATURES: u64 = FEATURE_VERSION_1 | FEATURE_ACCESS_PLATFORM;
/// Accepted when offered; everything else is declined.
pub const OPTIONAL_FEATURES: u64 = FEATURE_BLK_RO | FEATURE_BLK_SIZE | FEATURE_BLK_FLUSH;

// virtio_blk_config (§5.2.4).
const BLK_CONFIG_CAPACITY: u64 = 0;
const BLK_CONFIG_BLK_SIZE: u64 = 20;
const BLK_CONFIG_BYTES: u32 = 24;
pub const SECTOR_BYTES: u64 = 512;

// Requests (§5.2.6).
pub const BLK_T_IN: u32 = 0;
pub const BLK_T_OUT: u32 = 1;
pub const BLK_T_FLUSH: u32 = 4;
pub const BLK_S_OK: u8 = 0;

// Split virtqueue (§2.7).
const DESC_F_NEXT: u64 = 1;
const DESC_F_WRITE: u64 = 2;
const AVAIL_F_NO_INTERRUPT: u64 = 1;
/// The queue size the driver asks for: enough for one three-part request.
pub const QUEUE_SIZE: u16 = 16;
const MIN_QUEUE_SIZE: u16 = 4;

/// The driver's DMA memory: three pages, mapped device-readable and
/// device-writable at one IOVA.
pub const DMA_BYTES: u64 = 3 * 4096;
pub const DESC_OFFSET: u64 = 0;
pub const AVAIL_OFFSET: u64 = 16 * QUEUE_SIZE as u64;
pub const USED_OFFSET: u64 = 1024;
pub const HEADER_OFFSET: u64 = 4096;
pub const STATUS_OFFSET: u64 = HEADER_OFFSET + 16;
/// One block for the bring-up read; up to 4096 bytes.
pub const SCRATCH_OFFSET: u64 = 2 * 4096;

/// How many times a config read retries while config_generation moves.
const CONFIG_RETRIES: usize = 8;
/// How many polls a reset may take before the device counts as stuck.
const RESET_POLLS: usize = 1_000_000;

/// One virtio structure: a range of one BAR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Region {
    pub bar: u8,
    pub offset: u32,
    pub length: u32,
}

/// The structures the driver uses, all in one BAR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities {
    pub common: Region,
    pub notify: Region,
    pub notify_multiplier: u32,
    pub device: Region,
}

impl Capabilities {
    pub const fn bar(self) -> u32 {
        self.common.bar as u32
    }
}

/// Walks the standard capability list and keeps the first common, notify and
/// device structure with a valid BAR (§4.1.4: reserved cfg_type and BAR
/// values are ignored).
pub fn find_capabilities(
    mut read: impl FnMut(u32, u32) -> Result<u32, ()>,
) -> Result<Capabilities, Error> {
    let mut read = |offset, width| read(offset, width).map_err(|()| Error::Access);
    if read(PCI_STATUS, 2)? & PCI_STATUS_CAPABILITIES == 0 {
        return Err(Error::Capabilities);
    }
    let mut common = None;
    let mut notify = None;
    let mut device = None;
    let mut pointer = read(PCI_CAPABILITIES_POINTER, 1)? & 0xfc;
    let mut walked = 0;
    while pointer != 0 {
        if pointer < PCI_FIRST_CAPABILITY || walked == MAX_CAPABILITIES {
            return Err(Error::Capabilities);
        }
        walked += 1;
        let id = read(pointer, 1)?;
        let next = read(pointer + 1, 1)? & 0xfc;
        if id == PCI_CAP_ID_VENDOR {
            let length = read(pointer + 2, 1)?;
            let cfg_type = read(pointer + 3, 1)?;
            let bar = read(pointer + 4, 1)?;
            let wanted = matches!(cfg_type, CAP_COMMON | CAP_NOTIFY | CAP_DEVICE);
            if wanted && bar <= MAX_BAR {
                let minimum = if cfg_type == CAP_NOTIFY {
                    NOTIFY_CAP_BYTES
                } else {
                    CAP_BYTES
                };
                if length < minimum || pointer + minimum > 256 {
                    return Err(Error::Capabilities);
                }
                let region = Region {
                    bar: bar as u8,
                    offset: read(pointer + 8, 4)?,
                    length: read(pointer + 12, 4)?,
                };
                match cfg_type {
                    CAP_COMMON if common.is_none() => common = Some(region),
                    CAP_NOTIFY if notify.is_none() => {
                        notify = Some((region, read(pointer + 16, 4)?));
                    }
                    CAP_DEVICE if device.is_none() => device = Some(region),
                    _ => {}
                }
            }
        }
        pointer = next;
    }
    let (Some(common), Some((notify, notify_multiplier)), Some(device)) = (common, notify, device)
    else {
        return Err(Error::MissingStructure);
    };
    if common.length < COMMON_BYTES || notify.length < 2 || device.length < BLK_CONFIG_BYTES {
        return Err(Error::MissingStructure);
    }
    if common.bar != notify.bar || common.bar != device.bar {
        return Err(Error::Layout);
    }
    Ok(Capabilities {
        common,
        notify,
        notify_multiplier,
        device,
    })
}

/// What the device is, once initialized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Geometry {
    /// A power of two from 512 to 4096.
    pub block_size: u32,
    pub block_count: u64,
    pub read_only: bool,
    pub flush: bool,
}

/// One request: a whole number of blocks to or from `data_iova`, or a flush.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request {
    Read {
        sector: u64,
        data_iova: u64,
        bytes: u32,
    },
    Write {
        sector: u64,
        data_iova: u64,
        bytes: u32,
    },
    Flush,
}

/// A live device with queue 0 enabled and DRIVER_OK set.
#[derive(Debug)]
pub struct Device {
    caps: Capabilities,
    geometry: Geometry,
    mem_iova: u64,
    queue_size: u16,
    notify_offset: u64,
    next_avail: u16,
    last_used: u16,
    in_flight: bool,
}

/// Checks every structure, and the notify address, lie inside the BAR.
fn region_end(region: Region, bar_bytes: u64) -> Result<(), Error> {
    let end = u64::from(region.offset) + u64::from(region.length);
    if end > bar_bytes {
        return Err(Error::Layout);
    }
    Ok(())
}

struct Bar<'h, H: Hardware> {
    hardware: &'h mut H,
    caps: Capabilities,
}

impl<H: Hardware> Bar<'_, H> {
    fn common_read(&mut self, offset: u64, width: Width) -> Result<u64, Error> {
        self.hardware
            .bar_read(u64::from(self.caps.common.offset) + offset, width)
            .map_err(|Fault| Error::Access)
    }

    fn common_write(&mut self, offset: u64, width: Width, value: u64) -> Result<(), Error> {
        self.hardware
            .bar_write(u64::from(self.caps.common.offset) + offset, width, value)
            .map_err(|Fault| Error::Access)
    }

    /// 64-bit common-config fields are written low half first (§4.1.3.1).
    fn common_write64(&mut self, offset: u64, value: u64) -> Result<(), Error> {
        self.common_write(offset, Width::U32, value & 0xffff_ffff)?;
        self.common_write(offset + 4, Width::U32, value >> 32)
    }

    fn device_read(&mut self, offset: u64, width: Width) -> Result<u64, Error> {
        self.hardware
            .bar_read(u64::from(self.caps.device.offset) + offset, width)
            .map_err(|Fault| Error::Access)
    }

    fn status(&mut self) -> Result<u8, Error> {
        Ok(self.common_read(COMMON_DEVICE_STATUS, Width::U8)? as u8)
    }

    fn set_status(&mut self, status: u8) -> Result<(), Error> {
        self.common_write(COMMON_DEVICE_STATUS, Width::U8, u64::from(status))
    }

    fn reset(&mut self) -> Result<(), Error> {
        self.set_status(0)?;
        for _ in 0..RESET_POLLS {
            if self.status()? == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(Error::Reset)
    }

    /// Reads the device config consistently: retries while config_generation
    /// changes across the read (§2.5.1, §4.1.4.3.1).
    fn geometry(&mut self, features: u64) -> Result<Geometry, Error> {
        for _ in 0..CONFIG_RETRIES {
            let before = self.common_read(COMMON_CONFIG_GENERATION, Width::U8)?;
            let low = self.device_read(BLK_CONFIG_CAPACITY, Width::U32)?;
            let high = self.device_read(BLK_CONFIG_CAPACITY + 4, Width::U32)?;
            let block_size = if features & FEATURE_BLK_SIZE != 0 {
                self.device_read(BLK_CONFIG_BLK_SIZE, Width::U32)? as u32
            } else {
                SECTOR_BYTES as u32
            };
            if self.common_read(COMMON_CONFIG_GENERATION, Width::U8)? != before {
                continue;
            }
            let sectors = high << 32 | low;
            if !block_size.is_power_of_two() || !(512..=4096).contains(&block_size) {
                return Err(Error::Config);
            }
            let block_count = sectors / (u64::from(block_size) / SECTOR_BYTES);
            if block_count == 0 {
                return Err(Error::Config);
            }
            return Ok(Geometry {
                block_size,
                block_count,
                read_only: features & FEATURE_BLK_RO != 0,
                flush: features & FEATURE_BLK_FLUSH != 0,
            });
        }
        Err(Error::Config)
    }
}

impl Device {
    /// Resets and initializes the device (§3.1.1) with queue 0 in the
    /// driver's DMA memory at `mem_iova`. `bar_bytes` is the BAR's length.
    ///
    /// On any failure after the reset the device is left with FAILED set.
    pub fn initialize<H: Hardware>(
        hardware: &mut H,
        caps: Capabilities,
        bar_bytes: u64,
        mem_iova: u64,
    ) -> Result<Self, Error> {
        region_end(caps.common, bar_bytes)?;
        region_end(caps.notify, bar_bytes)?;
        region_end(caps.device, bar_bytes)?;
        let mut bar = Bar { hardware, caps };
        bar.reset()?;
        let result = Self::bring_up(&mut bar, mem_iova);
        if result.is_err() {
            let status = bar.status().unwrap_or(0);
            let _ = bar.set_status(status | STATUS_FAILED);
        }
        result
    }

    fn bring_up<H: Hardware>(bar: &mut Bar<'_, H>, mem_iova: u64) -> Result<Self, Error> {
        let caps = bar.caps;
        let mut status = STATUS_ACKNOWLEDGE;
        bar.set_status(status)?;
        status |= STATUS_DRIVER;
        bar.set_status(status)?;

        let mut offered = 0u64;
        for select in 0..2u64 {
            bar.common_write(COMMON_DEVICE_FEATURE_SELECT, Width::U32, select)?;
            offered |= bar.common_read(COMMON_DEVICE_FEATURE, Width::U32)? << (32 * select);
        }
        if offered & REQUIRED_FEATURES != REQUIRED_FEATURES {
            return Err(Error::Features);
        }
        let accepted = offered & (REQUIRED_FEATURES | OPTIONAL_FEATURES);
        for select in 0..2u64 {
            bar.common_write(COMMON_DRIVER_FEATURE_SELECT, Width::U32, select)?;
            bar.common_write(
                COMMON_DRIVER_FEATURE,
                Width::U32,
                (accepted >> (32 * select)) & 0xffff_ffff,
            )?;
        }
        status |= STATUS_FEATURES_OK;
        bar.set_status(status)?;
        if bar.status()? & STATUS_FEATURES_OK == 0 {
            return Err(Error::Features);
        }

        let geometry = bar.geometry(accepted)?;

        bar.common_write(COMMON_MSIX_CONFIG, Width::U16, NO_VECTOR)?;
        if bar.common_read(COMMON_NUM_QUEUES, Width::U16)? == 0 {
            return Err(Error::Queue);
        }
        bar.common_write(COMMON_QUEUE_SELECT, Width::U16, 0)?;
        let maximum = bar.common_read(COMMON_QUEUE_SIZE, Width::U16)? as u16;
        if bar.common_read(COMMON_QUEUE_ENABLE, Width::U16)? != 0 {
            return Err(Error::Queue);
        }
        // A size of 0 means the queue is unavailable. Sizes are powers of two
        // (§2.7), so the smaller of two is one too.
        let queue_size = maximum.min(QUEUE_SIZE);
        if queue_size < MIN_QUEUE_SIZE || !queue_size.is_power_of_two() {
            return Err(Error::Queue);
        }
        bar.common_write(COMMON_QUEUE_SIZE, Width::U16, u64::from(queue_size))?;
        bar.common_write(COMMON_QUEUE_MSIX_VECTOR, Width::U16, NO_VECTOR)?;
        bar.common_write64(COMMON_QUEUE_DESC, mem_iova + DESC_OFFSET)?;
        bar.common_write64(COMMON_QUEUE_DRIVER, mem_iova + AVAIL_OFFSET)?;
        bar.common_write64(COMMON_QUEUE_DEVICE, mem_iova + USED_OFFSET)?;
        let notify_off = bar.common_read(COMMON_QUEUE_NOTIFY_OFF, Width::U16)?;
        let notify_offset = notify_off
            .checked_mul(u64::from(caps.notify_multiplier))
            .filter(|offset| offset + 2 <= u64::from(caps.notify.length))
            .ok_or(Error::Layout)?
            + u64::from(caps.notify.offset);

        let device = Self {
            caps,
            geometry,
            mem_iova,
            queue_size,
            notify_offset,
            next_avail: 0,
            last_used: 0,
            in_flight: false,
        };
        device.clear_rings(bar.hardware)?;
        bar.common_write(COMMON_QUEUE_ENABLE, Width::U16, 1)?;

        status |= STATUS_DRIVER_OK;
        bar.set_status(status)?;
        if bar.status()? & (STATUS_NEEDS_RESET | STATUS_FAILED) != 0 {
            return Err(Error::Device);
        }
        Ok(device)
    }

    fn clear_rings<H: Hardware>(&self, hardware: &mut H) -> Result<(), Error> {
        let used_end = USED_OFFSET + 6 + 8 * u64::from(self.queue_size);
        let mut offset = 0;
        while offset < used_end.next_multiple_of(8) {
            mem_write(hardware, offset, Width::U64, 0)?;
            offset += 8;
        }
        // The driver polls, so it asks the device not to interrupt.
        mem_write(hardware, AVAIL_OFFSET, Width::U16, AVAIL_F_NO_INTERRUPT)
    }

    pub const fn geometry(&self) -> Geometry {
        self.geometry
    }

    pub const fn queue_size(&self) -> u16 {
        self.queue_size
    }

    pub const fn mem_iova(&self) -> u64 {
        self.mem_iova
    }

    /// Places `request` on the queue and notifies the device.
    pub fn submit<H: Hardware>(&mut self, hardware: &mut H, request: Request) -> Result<(), Error> {
        if self.in_flight {
            return Err(Error::State);
        }
        let (kind, sector, data) = match request {
            Request::Read {
                sector,
                data_iova,
                bytes,
            } => (BLK_T_IN, sector, Some((data_iova, bytes, DESC_F_WRITE))),
            Request::Write {
                sector,
                data_iova,
                bytes,
            } => (BLK_T_OUT, sector, Some((data_iova, bytes, 0))),
            Request::Flush => (BLK_T_FLUSH, 0, None),
        };
        // virtio_blk_req header: type, reserved, sector.
        mem_write(hardware, HEADER_OFFSET, Width::U32, u64::from(kind))?;
        mem_write(hardware, HEADER_OFFSET + 4, Width::U32, 0)?;
        mem_write(hardware, HEADER_OFFSET + 8, Width::U64, sector)?;
        // Poisoned, so a completion that never wrote it is not mistaken for OK.
        mem_write(hardware, STATUS_OFFSET, Width::U8, 0xff)?;

        // Descriptors 0 (header), 1 (data, if any) and the last (status).
        let header_iova = self.mem_iova + HEADER_OFFSET;
        let status_iova = self.mem_iova + STATUS_OFFSET;
        let status_index = if let Some((iova, bytes, flags)) = data {
            self.write_descriptor(hardware, 0, header_iova, 16, DESC_F_NEXT, 1)?;
            self.write_descriptor(hardware, 1, iova, bytes, flags | DESC_F_NEXT, 2)?;
            2
        } else {
            self.write_descriptor(hardware, 0, header_iova, 16, DESC_F_NEXT, 1)?;
            1
        };
        self.write_descriptor(hardware, status_index, status_iova, 1, DESC_F_WRITE, 0)?;

        let slot = u64::from(self.next_avail % self.queue_size);
        mem_write(hardware, AVAIL_OFFSET + 4 + 2 * slot, Width::U16, 0)?;
        // The ring entry and descriptors are visible before the index
        // (§2.7.13.3.1), and the index before the notification.
        fence(Ordering::SeqCst);
        self.next_avail = self.next_avail.wrapping_add(1);
        mem_write(
            hardware,
            AVAIL_OFFSET + 2,
            Width::U16,
            u64::from(self.next_avail),
        )?;
        fence(Ordering::SeqCst);
        self.in_flight = true;
        hardware
            .bar_write(self.notify_offset, Width::U16, 0)
            .map_err(|Fault| Error::Access)
    }

    fn write_descriptor<H: Hardware>(
        &self,
        hardware: &mut H,
        index: u64,
        address: u64,
        bytes: u32,
        flags: u64,
        next: u64,
    ) -> Result<(), Error> {
        let base = DESC_OFFSET + 16 * index;
        mem_write(hardware, base, Width::U64, address)?;
        mem_write(hardware, base + 8, Width::U32, u64::from(bytes))?;
        mem_write(hardware, base + 12, Width::U16, flags)?;
        mem_write(hardware, base + 14, Width::U16, next)
    }

    /// Checks for the in-flight request's completion: `None` while the
    /// device is still working, else the device's status byte.
    pub fn poll<H: Hardware>(&mut self, hardware: &mut H) -> Result<Option<u8>, Error> {
        if !self.in_flight {
            return Err(Error::State);
        }
        let used = mem_read(hardware, USED_OFFSET + 2, Width::U16)? as u16;
        if used == self.last_used {
            return Ok(None);
        }
        // One request in flight: the device may advance the index by one.
        if used != self.last_used.wrapping_add(1) {
            return Err(Error::Device);
        }
        fence(Ordering::SeqCst);
        let slot = u64::from(self.last_used % self.queue_size);
        let id = mem_read(hardware, USED_OFFSET + 4 + 8 * slot, Width::U32)?;
        if id != 0 {
            return Err(Error::Device);
        }
        self.last_used = used;
        self.in_flight = false;
        Ok(Some(mem_read(hardware, STATUS_OFFSET, Width::U8)? as u8))
    }

    /// Resets the device, which stops all of its DMA. The device is unusable
    /// afterwards.
    pub fn reset<H: Hardware>(self, hardware: &mut H) -> Result<(), Error> {
        Bar {
            hardware,
            caps: self.caps,
        }
        .reset()
    }
}

fn mem_read<H: Hardware>(hardware: &mut H, offset: u64, width: Width) -> Result<u64, Error> {
    hardware
        .mem_read(offset, width)
        .map_err(|Fault| Error::Access)
}

fn mem_write<H: Hardware>(
    hardware: &mut H,
    offset: u64,
    width: Width,
    value: u64,
) -> Result<(), Error> {
    hardware
        .mem_write(offset, width, value)
        .map_err(|Fault| Error::Access)
}
