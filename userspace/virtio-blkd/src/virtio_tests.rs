//! The virtio transport, the split queue and request planning, driven
//! against a model modern virtio-blk PCI function.
//!
//! The model keeps QEMU's layout (one 16 KiB BAR: common config at 0,
//! device config at 0x2000, notify at 0x3000) and services the queue when
//! the driver writes the notify register, translating every IOVA through the
//! mappings it was told about, as the IOMMU would.

use std::vec;
use std::vec::Vec;

use wyrmroot_block_proto::{INFO_FLUSH, INFO_READ_ONLY, Status, Transfer};

use crate::block::{
    Buffer, MAX_ATTACH_BYTES, MAX_TRANSFER_BYTES, check_attach, info, plan_flush, plan_transfer,
};
use crate::virtio::*;

const BAR: u8 = 4;
pub(crate) const BAR_BYTES: u64 = 0x4000;
const COMMON: u64 = 0;
const DEVICE: u64 = 0x2000;
const NOTIFY: u64 = 0x3000;
const MULTIPLIER: u32 = 4;
pub(crate) const MEM_IOVA: u64 = 0x10_0000;
pub(crate) const CLIENT_IOVA: u64 = 0x20_0000;
pub(crate) const CLIENT_BYTES: usize = 64 * 1024;
pub(crate) const SECTORS: u64 = 64;

/// Standard config space: a capability list with an MSI-X capability, the
/// four virtio structures (ISR included, which the driver ignores) and one
/// reserved cfg_type.
pub(crate) fn config_space() -> [u8; 256] {
    let mut config = [0u8; 256];
    config[0x06] = 0x10;
    config[0x34] = 0x40;
    // (pointer, id, next, cfg_type, offset, length)
    let caps: [(usize, u8, u8, u8, u32, u32); 6] = [
        (0x40, 0x11, 0x4c, 0, 0, 0),
        (0x4c, 0x09, 0x5c, 7, 0x3800, 0x10),
        (0x5c, 0x09, 0x6c, 1, COMMON as u32, 0x38),
        (0x6c, 0x09, 0x7c, 3, 0x1000, 4),
        (0x7c, 0x09, 0x90, 4, DEVICE as u32, 0x3c),
        (0x90, 0x09, 0x00, 2, NOTIFY as u32, 0x1000),
    ];
    for (pointer, id, next, cfg_type, offset, length) in caps {
        config[pointer] = id;
        config[pointer + 1] = next;
        if id == 0x09 {
            config[pointer + 2] = if cfg_type == 2 { 20 } else { 16 };
            config[pointer + 3] = cfg_type;
            config[pointer + 4] = BAR;
            config[pointer + 8..pointer + 12].copy_from_slice(&offset.to_le_bytes());
            config[pointer + 12..pointer + 16].copy_from_slice(&length.to_le_bytes());
            if cfg_type == 2 {
                config[pointer + 16..pointer + 20].copy_from_slice(&MULTIPLIER.to_le_bytes());
            }
        }
    }
    config
}

pub(crate) fn reader(config: &[u8; 256]) -> impl FnMut(u32, u32) -> Result<u32, ()> + '_ {
    |offset, width| {
        let start = offset as usize;
        let end = start + width as usize;
        if end > 256 || !start.is_multiple_of(width as usize) {
            return Err(());
        }
        let mut value = [0u8; 4];
        value[..width as usize].copy_from_slice(&config[start..end]);
        Ok(u32::from_le_bytes(value))
    }
}

fn caps() -> Capabilities {
    find_capabilities(reader(&config_space())).unwrap()
}

/// A model virtio-blk device and the memory it can reach.
pub(crate) struct Model {
    pub(crate) offered: u64,
    pub(crate) accepted: u64,
    pub(crate) feature_select: u64,
    pub(crate) driver_select: u64,
    pub(crate) status: u8,
    /// Status bits the device clears when the driver sets them.
    pub(crate) refuse_status: u8,
    pub(crate) config_generation: u8,
    /// Bumped on each config-generation read, while nonzero.
    pub(crate) config_churn: u8,
    pub(crate) capacity: u64,
    pub(crate) blk_size: u32,
    pub(crate) max_queue: u16,
    pub(crate) queue_size: u16,
    pub(crate) queue_enable: u16,
    pub(crate) queue_notify_off: u16,
    pub(crate) desc: u64,
    pub(crate) driver: u64,
    pub(crate) device: u64,
    /// Device-side copy of the next avail index it will consume.
    pub(crate) seen_avail: u16,
    pub(crate) used_idx: u16,
    pub(crate) mem: Vec<u8>,
    pub(crate) client: Vec<u8>,
    pub(crate) disk: Vec<u8>,
    pub(crate) notifications: usize,
    /// Leave a request on the ring without completing it.
    pub(crate) stall: bool,
    /// Complete with this descriptor id instead of the head.
    pub(crate) wrong_id: Option<u32>,
    /// Advance the used index by this much per completion.
    pub(crate) used_step: u16,
    /// Complete reads without writing their data to memory.
    pub(crate) drop_reads: bool,
    /// Every request the device executed: (type, sector, bytes).
    pub(crate) executed: Vec<(u32, u64, u32)>,
    pub(crate) bar_writes: Vec<(u64, u64)>,
}

impl Model {
    pub(crate) fn new() -> Self {
        let mut disk = vec![0u8; (SECTORS * SECTOR_BYTES) as usize];
        for (index, byte) in disk.iter_mut().enumerate() {
            *byte = (index / 512) as u8 ^ (index as u8);
        }
        disk[510] = 0x55;
        disk[511] = 0xaa;
        Self {
            offered: REQUIRED_FEATURES | FEATURE_BLK_FLUSH | FEATURE_BLK_SIZE | (1 << 12),
            accepted: 0,
            feature_select: 0,
            driver_select: 0,
            status: 0x0f,
            refuse_status: 0,
            config_generation: 0,
            config_churn: 0,
            capacity: SECTORS,
            blk_size: 512,
            max_queue: 256,
            queue_size: 0,
            queue_enable: 0,
            queue_notify_off: 3,
            desc: 0,
            driver: 0,
            device: 0,
            seen_avail: 0,
            used_idx: 0,
            mem: vec![0xcc; DMA_BYTES as usize],
            client: vec![0u8; CLIENT_BYTES],
            disk,
            notifications: 0,
            stall: false,
            wrong_id: None,
            used_step: 1,
            drop_reads: false,
            executed: Vec::new(),
            bar_writes: Vec::new(),
        }
    }

    /// The IOMMU: an IOVA range resolves only inside a mapping.
    fn translate(&mut self, iova: u64, bytes: u64) -> Option<&mut [u8]> {
        let ranges = [
            (MEM_IOVA, self.mem.len() as u64),
            (CLIENT_IOVA, self.client.len() as u64),
        ];
        for (index, (base, length)) in ranges.into_iter().enumerate() {
            if iova >= base && iova + bytes <= base + length {
                let start = (iova - base) as usize;
                let end = start + bytes as usize;
                return Some(if index == 0 {
                    &mut self.mem[start..end]
                } else {
                    &mut self.client[start..end]
                });
            }
        }
        None
    }

    fn read_iova(&mut self, iova: u64, bytes: usize) -> Vec<u8> {
        self.translate(iova, bytes as u64)
            .expect("device read outside every IOMMU mapping")
            .to_vec()
    }

    fn write_iova(&mut self, iova: u64, data: &[u8]) {
        self.translate(iova, data.len() as u64)
            .expect("device write outside every IOMMU mapping")
            .copy_from_slice(data);
    }

    fn u16_at(&mut self, iova: u64) -> u16 {
        let bytes = self.read_iova(iova, 2);
        u16::from_le_bytes([bytes[0], bytes[1]])
    }

    fn descriptor(&mut self, index: u16) -> (u64, u32, u16, u16) {
        assert!(index < self.queue_size, "descriptor index out of the table");
        let bytes = self.read_iova(self.desc + 16 * u64::from(index), 16);
        (
            u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            u16::from_le_bytes(bytes[12..14].try_into().unwrap()),
            u16::from_le_bytes(bytes[14..16].try_into().unwrap()),
        )
    }

    fn service(&mut self) {
        assert!(
            self.status & STATUS_DRIVER_OK != 0,
            "notified before DRIVER_OK"
        );
        assert_eq!(self.queue_enable, 1, "notified a disabled queue");
        if self.stall {
            return;
        }
        let avail = self.u16_at(self.driver + 2);
        while self.seen_avail != avail {
            let slot = u64::from(self.seen_avail % self.queue_size);
            let head = self.u16_at(self.driver + 4 + 2 * slot);
            self.seen_avail = self.seen_avail.wrapping_add(1);
            // Walk the chain: device-readable parts first, then writable.
            let mut chain = Vec::new();
            let mut index = head;
            loop {
                let (address, length, flags, next) = self.descriptor(index);
                chain.push((address, length, flags));
                if flags & 1 == 0 {
                    break;
                }
                assert!(chain.len() < 3, "chain longer than a request");
                index = next;
            }
            let (header_iova, header_length, header_flags) = chain[0];
            assert_eq!((header_length, header_flags & 2), (16, 0));
            let header = self.read_iova(header_iova, 16);
            let kind = u32::from_le_bytes(header[0..4].try_into().unwrap());
            let sector = u64::from_le_bytes(header[8..16].try_into().unwrap());
            let (status_iova, status_length, status_flags) = *chain.last().unwrap();
            assert_eq!((status_length, status_flags & 2), (1, 2));
            let mut status = BLK_S_OK;
            let mut bytes = 0;
            match (kind, chain.len()) {
                (BLK_T_IN | BLK_T_OUT, 3) => {
                    let (data, length, flags) = chain[1];
                    bytes = length;
                    assert_eq!(length % 512, 0);
                    let start = (sector * SECTOR_BYTES) as usize;
                    let end = start + length as usize;
                    if end > self.disk.len() {
                        status = 1;
                    } else if kind == BLK_T_IN {
                        assert_eq!(flags & 2, 2, "read data must be device-writable");
                        let block = self.disk[start..end].to_vec();
                        if !self.drop_reads {
                            self.write_iova(data, &block);
                        }
                    } else {
                        assert_eq!(flags & 2, 0, "write data must be device-readable");
                        if self.offered & FEATURE_BLK_RO != 0 {
                            status = 1;
                        } else {
                            let block = self.read_iova(data, length as usize);
                            self.disk[start..end].copy_from_slice(&block);
                        }
                    }
                }
                (BLK_T_FLUSH, 2) => assert_eq!(sector, 0),
                _ => status = 2,
            }
            self.executed.push((kind, sector, bytes));
            self.write_iova(status_iova, &[status]);
            let used_slot = u64::from(self.used_idx % self.queue_size);
            let id = self.wrong_id.unwrap_or(u32::from(head));
            let mut element = [0u8; 8];
            element[..4].copy_from_slice(&id.to_le_bytes());
            element[4..].copy_from_slice(&(bytes + 1).to_le_bytes());
            self.write_iova(self.device + 4 + 8 * used_slot, &element);
            self.used_idx = self.used_idx.wrapping_add(self.used_step);
            let used_idx = self.used_idx;
            self.write_iova(self.device + 2, &used_idx.to_le_bytes());
        }
    }

    fn common_read(&mut self, offset: u64) -> u64 {
        match offset {
            0x00 => self.feature_select,
            0x04 => (self.offered >> (32 * self.feature_select)) & 0xffff_ffff,
            0x08 => self.driver_select,
            0x0c => (self.accepted >> (32 * self.driver_select)) & 0xffff_ffff,
            0x12 => 1,
            0x14 => u64::from(self.status),
            0x15 => {
                let generation = self.config_generation;
                if self.config_churn > 0 {
                    self.config_churn -= 1;
                    self.config_generation = self.config_generation.wrapping_add(1);
                }
                u64::from(generation)
            }
            0x18 => u64::from(if self.queue_size == 0 {
                self.max_queue
            } else {
                self.queue_size
            }),
            0x1c => u64::from(self.queue_enable),
            0x1e => u64::from(self.queue_notify_off),
            _ => 0,
        }
    }

    fn common_write(&mut self, offset: u64, value: u64) {
        let low = |target: &mut u64, value: u64| *target = (*target & !0xffff_ffff) | value;
        let high = |target: &mut u64, value: u64| *target = (*target & 0xffff_ffff) | value << 32;
        match offset {
            0x00 => self.feature_select = value,
            0x08 => self.driver_select = value,
            0x0c => {
                assert!(
                    self.status & STATUS_FEATURES_OK == 0,
                    "features after FEATURES_OK"
                );
                let shift = 32 * self.driver_select;
                self.accepted = (self.accepted & !(0xffff_ffff << shift)) | value << shift;
            }
            0x14 => {
                let value = value as u8;
                if value == 0 {
                    *self = Self {
                        disk: core::mem::take(&mut self.disk),
                        mem: core::mem::take(&mut self.mem),
                        client: core::mem::take(&mut self.client),
                        offered: self.offered,
                        refuse_status: self.refuse_status,
                        config_churn: self.config_churn,
                        capacity: self.capacity,
                        blk_size: self.blk_size,
                        max_queue: self.max_queue,
                        stall: self.stall,
                        wrong_id: self.wrong_id,
                        used_step: self.used_step,
                        drop_reads: self.drop_reads,
                        queue_notify_off: self.queue_notify_off,
                        executed: core::mem::take(&mut self.executed),
                        bar_writes: core::mem::take(&mut self.bar_writes),
                        ..Self::new()
                    };
                    self.status = 0;
                    return;
                }
                assert_eq!(
                    value & self.status,
                    self.status,
                    "driver cleared a status bit"
                );
                if value & STATUS_FEATURES_OK != 0 && self.status & STATUS_FEATURES_OK == 0 {
                    assert_eq!(
                        self.accepted & !self.offered,
                        0,
                        "accepted an unoffered feature"
                    );
                }
                self.status = value & !self.refuse_status;
            }
            0x16 => assert_eq!(value, 0, "only queue 0 exists"),
            0x18 => self.queue_size = value as u16,
            0x1c => {
                assert_eq!(value, 1, "the driver must not write 0 to queue_enable");
                self.queue_enable = 1;
            }
            0x20 => low(&mut self.desc, value),
            0x24 => high(&mut self.desc, value),
            0x28 => low(&mut self.driver, value),
            0x2c => high(&mut self.driver, value),
            0x30 => low(&mut self.device, value),
            0x34 => high(&mut self.device, value),
            _ => {}
        }
    }
}

impl Hardware for Model {
    fn bar_read(&mut self, offset: u64, _width: Width) -> Result<u64, Fault> {
        if offset >= BAR_BYTES {
            return Err(Fault);
        }
        Ok(match offset {
            o if o < 0x38 => self.common_read(o - COMMON),
            o if o == DEVICE => self.capacity & 0xffff_ffff,
            o if o == DEVICE + 4 => self.capacity >> 32,
            o if o == DEVICE + 20 => u64::from(self.blk_size),
            _ => 0,
        })
    }

    fn bar_write(&mut self, offset: u64, width: Width, value: u64) -> Result<(), Fault> {
        if offset >= BAR_BYTES {
            return Err(Fault);
        }
        self.bar_writes.push((offset, value));
        if offset < 0x38 {
            self.common_write(offset, value);
        } else if offset == NOTIFY + u64::from(self.queue_notify_off) * u64::from(MULTIPLIER) {
            assert_eq!(
                (width, value),
                (Width::U16, 0),
                "notify writes the queue index"
            );
            self.notifications += 1;
            self.service();
        } else {
            panic!("write to an unexpected BAR offset {offset:#x}");
        }
        Ok(())
    }

    fn mem_read(&mut self, offset: u64, width: Width) -> Result<u64, Fault> {
        let bytes = width_bytes(width);
        let range = self
            .mem
            .get(offset as usize..offset as usize + bytes)
            .ok_or(Fault)?;
        let mut value = [0u8; 8];
        value[..bytes].copy_from_slice(range);
        Ok(u64::from_le_bytes(value))
    }

    fn mem_write(&mut self, offset: u64, width: Width, value: u64) -> Result<(), Fault> {
        let bytes = width_bytes(width);
        let range = self
            .mem
            .get_mut(offset as usize..offset as usize + bytes)
            .ok_or(Fault)?;
        range.copy_from_slice(&value.to_le_bytes()[..bytes]);
        Ok(())
    }
}

fn width_bytes(width: Width) -> usize {
    match width {
        Width::U8 => 1,
        Width::U16 => 2,
        Width::U32 => 4,
        Width::U64 => 8,
    }
}

fn live(model: &mut Model) -> Device {
    Device::initialize(model, caps(), BAR_BYTES, MEM_IOVA).unwrap()
}

/// Submits and polls once; the model completes synchronously on notify.
fn run(model: &mut Model, device: &mut Device, request: Request) -> Option<u8> {
    device.submit(model, request).unwrap();
    device.poll(model).unwrap()
}

fn client() -> Buffer {
    Buffer {
        iova: CLIENT_IOVA,
        bytes: CLIENT_BYTES as u64,
    }
}

#[test]
fn capabilities_keep_the_first_of_each_wanted_type_and_skip_the_rest() {
    assert_eq!(
        caps(),
        Capabilities {
            common: Region {
                bar: BAR,
                offset: COMMON as u32,
                length: 0x38
            },
            notify: Region {
                bar: BAR,
                offset: NOTIFY as u32,
                length: 0x1000
            },
            notify_multiplier: MULTIPLIER,
            device: Region {
                bar: BAR,
                offset: DEVICE as u32,
                length: 0x3c
            },
        }
    );
    // A second common structure later in the list is ignored.
    let mut config = config_space();
    config[0x91] = 0xb0;
    config[0xb0] = 0x09;
    config[0xb2] = 16;
    config[0xb3] = 1;
    config[0xb4] = BAR;
    config[0xb8] = 0x40;
    config[0xbc] = 0x38;
    assert_eq!(find_capabilities(reader(&config)), Ok(caps()));
    // A wanted structure behind a reserved BAR number is ignored.
    let mut config = config_space();
    config[0x60] = 6;
    assert_eq!(
        find_capabilities(reader(&config)),
        Err(Error::MissingStructure)
    );
}

#[test]
fn malformed_capability_lists_fail_closed() {
    type Change = fn(&mut [u8; 256]);
    let mut cases: Vec<(Change, Error)> = vec![
        (|config| config[0x06] = 0, Error::Capabilities),
        (|config| config[0x34] = 0x20, Error::Capabilities),
        // A loop: the last capability points back at the first.
        (|config| config[0x91] = 0x40, Error::Capabilities),
        (|config| config[0x5e] = 8, Error::Capabilities),
        (|config| config[0x92] = 16, Error::Capabilities),
        (|config| config[0x7d] = 0, Error::MissingStructure),
        (|config| config[0x88] = 0x10, Error::MissingStructure),
        (|config| config[0x80] = 2, Error::Layout),
    ];
    // A notify capability placed so its multiplier would lie past 256.
    cases.push((
        |config| {
            config[0x91] = 0xf0;
            config[0xf0] = 0x09;
            config[0xf2] = 20;
            config[0xf3] = 2;
            config[0x93] = 3;
        },
        Error::Capabilities,
    ));
    for (change, error) in cases {
        let mut config = config_space();
        change(&mut config);
        assert_eq!(find_capabilities(reader(&config)), Err(error), "{error:?}");
    }
    let failing = |_: u32, _: u32| Err(());
    assert_eq!(find_capabilities(failing), Err(Error::Access));
}

#[test]
fn initialization_follows_the_spec_sequence_and_negotiates_only_safe_features() {
    let mut model = Model::new();
    let device = live(&mut model);
    assert_eq!(
        model.status,
        STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK
    );
    // MQ (bit 12) was offered and declined; RO was not offered.
    assert_eq!(
        model.accepted,
        REQUIRED_FEATURES | FEATURE_BLK_FLUSH | FEATURE_BLK_SIZE
    );
    assert_eq!(model.queue_size, QUEUE_SIZE);
    assert_eq!(model.queue_enable, 1);
    assert_eq!(
        (model.desc, model.driver, model.device),
        (
            MEM_IOVA + DESC_OFFSET,
            MEM_IOVA + AVAIL_OFFSET,
            MEM_IOVA + USED_OFFSET
        )
    );
    assert_eq!(
        device.geometry(),
        Geometry {
            block_size: 512,
            block_count: SECTORS,
            read_only: false,
            flush: true,
        }
    );
    // The rings were cleared and the device asked not to interrupt.
    assert_eq!(model.mem[AVAIL_OFFSET as usize], 1);
    assert!(
        model.mem[..USED_OFFSET as usize + 6 + 8 * 16]
            .iter()
            .enumerate()
            .all(|(index, byte)| *byte == 0 || index == AVAIL_OFFSET as usize)
    );
    // The reset came first, and queue_enable came after the queue addresses.
    let order: Vec<u64> = model.bar_writes.iter().map(|(offset, _)| *offset).collect();
    assert_eq!(model.bar_writes[0], (0x14, 0));
    let enable = order.iter().position(|offset| *offset == 0x1c).unwrap();
    assert!(order[..enable].contains(&0x34) && order[..enable].contains(&0x20));
}

#[test]
fn a_small_device_queue_is_used_at_its_own_size() {
    let mut model = Model::new();
    model.max_queue = 8;
    let mut device = live(&mut model);
    assert_eq!((device.queue_size(), model.queue_size), (8, 8));
    // Wrap the ring twice.
    for round in 0..17u64 {
        let status = run(
            &mut model,
            &mut device,
            Request::Read {
                sector: round % SECTORS,
                data_iova: CLIENT_IOVA,
                bytes: 512,
            },
        );
        assert_eq!(status, Some(BLK_S_OK));
    }
}

#[test]
fn devices_without_iommu_translation_or_modern_virtio_are_refused() {
    for missing in [FEATURE_ACCESS_PLATFORM, FEATURE_VERSION_1] {
        let mut model = Model::new();
        model.offered &= !missing;
        assert_eq!(
            Device::initialize(&mut model, caps(), BAR_BYTES, MEM_IOVA).unwrap_err(),
            Error::Features
        );
        assert!(model.status & STATUS_FAILED != 0);
        assert_eq!(model.notifications, 0);
    }
    let mut model = Model::new();
    model.refuse_status = STATUS_FEATURES_OK;
    assert_eq!(
        Device::initialize(&mut model, caps(), BAR_BYTES, MEM_IOVA).unwrap_err(),
        Error::Features
    );
    assert!(model.status & STATUS_FAILED != 0);
}

#[test]
fn unusable_queues_configs_and_layouts_are_refused() {
    for (change, error) in [
        (
            (|model: &mut Model| model.max_queue = 0) as fn(&mut Model),
            Error::Queue,
        ),
        (|model| model.max_queue = 2, Error::Queue),
        (|model| model.max_queue = 12, Error::Queue),
        (|model| model.blk_size = 768, Error::Config),
        (|model| model.blk_size = 8192, Error::Config),
        (|model| model.capacity = 0, Error::Config),
        (|model| model.config_churn = 255, Error::Config),
        (|model| model.queue_notify_off = 0x400, Error::Layout),
    ] {
        let mut model = Model::new();
        change(&mut model);
        assert_eq!(
            Device::initialize(&mut model, caps(), BAR_BYTES, MEM_IOVA).unwrap_err(),
            error
        );
        assert!(model.status & STATUS_FAILED != 0);
    }
    // Structures outside the mapped BAR are refused before any access.
    let mut model = Model::new();
    assert_eq!(
        Device::initialize(&mut model, caps(), 0x2000, MEM_IOVA).unwrap_err(),
        Error::Layout
    );
    assert!(model.bar_writes.is_empty());
}

#[test]
fn a_config_read_retries_until_the_generation_is_stable() {
    let mut model = Model::new();
    model.config_churn = 3;
    let device = live(&mut model);
    assert_eq!(device.geometry().block_count, SECTORS);
}

#[test]
fn larger_logical_blocks_scale_the_count_and_the_sector_numbers() {
    let mut model = Model::new();
    model.blk_size = 4096;
    let device = live(&mut model);
    let geometry = device.geometry();
    assert_eq!(
        (geometry.block_size, geometry.block_count),
        (4096, SECTORS / 8)
    );
    let transfer = Transfer {
        lba: 3,
        block_count: 2,
        buffer_offset: 4096,
    };
    assert_eq!(
        plan_transfer(geometry, Some(client()), transfer, false),
        Ok(Request::Read {
            sector: 24,
            data_iova: CLIENT_IOVA + 4096,
            bytes: 8192,
        })
    );
    assert_eq!(
        info(geometry).max_transfer_blocks,
        MAX_TRANSFER_BYTES / 4096
    );
}

#[test]
fn reads_writes_and_flushes_round_trip_through_the_queue() {
    let mut model = Model::new();
    let mut device = live(&mut model);
    let geometry = device.geometry();

    let read = plan_transfer(
        geometry,
        Some(client()),
        Transfer {
            lba: 2,
            block_count: 4,
            buffer_offset: 1024,
        },
        false,
    )
    .unwrap();
    assert_eq!(run(&mut model, &mut device, read), Some(BLK_S_OK));
    assert_eq!(
        model.client[1024..1024 + 2048],
        model.disk[1024..1024 + 2048]
    );

    model.client[..1024].fill(0x5a);
    let write = plan_transfer(
        geometry,
        Some(client()),
        Transfer {
            lba: 9,
            block_count: 2,
            buffer_offset: 0,
        },
        true,
    )
    .unwrap();
    assert_eq!(run(&mut model, &mut device, write), Some(BLK_S_OK));
    assert!(
        model.disk[9 * 512..11 * 512]
            .iter()
            .all(|byte| *byte == 0x5a)
    );

    let flush = plan_flush(geometry).unwrap();
    assert_eq!(run(&mut model, &mut device, flush), Some(BLK_S_OK));
    assert_eq!(
        model.executed,
        [
            (BLK_T_IN, 2, 2048),
            (BLK_T_OUT, 9, 1024),
            (BLK_T_FLUSH, 0, 0)
        ]
    );
    assert_eq!(model.notifications, 3);
}

#[test]
fn the_device_status_byte_is_returned_and_never_assumed() {
    let mut model = Model::new();
    model.offered |= FEATURE_BLK_RO;
    let mut device = live(&mut model);
    assert!(device.geometry().read_only);
    // The planner refuses writes to a read-only device...
    let transfer = Transfer {
        lba: 0,
        block_count: 1,
        buffer_offset: 0,
    };
    assert_eq!(
        plan_transfer(device.geometry(), Some(client()), transfer, true),
        Err(Status::ReadOnly)
    );
    // ...and if one reached it anyway, the device's IOERR comes back.
    let request = Request::Write {
        sector: 0,
        data_iova: CLIENT_IOVA,
        bytes: 512,
    };
    assert_eq!(run(&mut model, &mut device, request), Some(1));
}

#[test]
fn a_stalled_device_reports_nothing_and_rejects_a_second_request() {
    let mut model = Model::new();
    model.stall = true;
    let mut device = live(&mut model);
    device.submit(&mut model, Request::Flush).unwrap();
    assert_eq!(device.poll(&mut model), Ok(None));
    assert_eq!(device.poll(&mut model), Ok(None));
    assert_eq!(device.submit(&mut model, Request::Flush), Err(Error::State));
    // Reset stops the device; the model's queue is gone.
    device.reset(&mut model).unwrap();
    assert_eq!((model.status, model.queue_enable), (0, 0));
}

#[test]
fn completions_the_driver_did_not_submit_are_device_errors() {
    let mut model = Model::new();
    model.wrong_id = Some(1);
    let mut device = live(&mut model);
    device.submit(&mut model, Request::Flush).unwrap();
    assert_eq!(device.poll(&mut model), Err(Error::Device));

    let mut model = Model::new();
    model.used_step = 2;
    let mut device = live(&mut model);
    device.submit(&mut model, Request::Flush).unwrap();
    assert_eq!(device.poll(&mut model), Err(Error::Device));

    let mut model = Model::new();
    let mut device = live(&mut model);
    assert_eq!(device.poll(&mut model), Err(Error::State));
}

#[test]
fn transfers_are_checked_against_the_device_and_the_buffer() {
    let geometry = Geometry {
        block_size: 512,
        block_count: 100,
        read_only: false,
        flush: false,
    };
    let transfer = |lba, block_count, buffer_offset| Transfer {
        lba,
        block_count,
        buffer_offset,
    };
    let small = Buffer {
        iova: CLIENT_IOVA,
        bytes: 4096,
    };
    let cases = [
        (None, transfer(0, 1, 0), Status::NoBuffer),
        (Some(small), transfer(0, 257, 0), Status::Invalid),
        (Some(small), transfer(0, 1, 100), Status::Invalid),
        (Some(small), transfer(99, 2, 0), Status::OutOfRange),
        (Some(small), transfer(u64::MAX, 1, 0), Status::OutOfRange),
        (Some(small), transfer(0, 9, 0), Status::OutOfRange),
        (Some(small), transfer(0, 1, 4096), Status::OutOfRange),
        (
            Some(small),
            transfer(0, 1, u64::MAX - 511),
            Status::OutOfRange,
        ),
    ];
    for (buffer, transfer, status) in cases {
        assert_eq!(
            plan_transfer(geometry, buffer, transfer, false),
            Err(status),
            "{transfer:?}"
        );
    }
    // The last block, and the end of the buffer, are reachable.
    assert_eq!(
        plan_transfer(geometry, Some(small), transfer(99, 1, 3584), false),
        Ok(Request::Read {
            sector: 99,
            data_iova: CLIENT_IOVA + 3584,
            bytes: 512
        })
    );
    assert_eq!(plan_flush(geometry), Err(Status::Unsupported));
    let flags = info(Geometry {
        read_only: true,
        flush: true,
        ..geometry
    })
    .flags;
    assert_eq!(flags, INFO_READ_ONLY | INFO_FLUSH);
}

#[test]
fn attached_buffers_are_bounded_by_the_limit() {
    assert_eq!(check_attach(4096), Ok(()));
    assert_eq!(check_attach(MAX_ATTACH_BYTES), Ok(()));
    assert_eq!(check_attach(MAX_ATTACH_BYTES + 4096), Err(Status::Invalid));
}
