//! A small in-memory model of Deepwyrm Channels for host tests of service
//! roles: datagrams with atomic MOVE transfers, per-handle rights,
//! PEER_CLOSED and bounded queues (DW0-F0 IPC contract §4), plus
//! MemoryObjects backed by shared byte vectors and a manual clock.
//!
//! One handle table serves every process: the test plays the peers of the
//! code under test, either between calls or as scripted [`Peer`]s that run
//! whenever a wait finds nothing ready, standing in for processes that run
//! concurrently. A wait that still finds nothing ready once no peer makes
//! progress fails with TIMED_OUT at once. Mapping is not modelled: services reach memory
//! through their own mapper seams, and tests read MemoryObjects with
//! [`World::memory`].

pub mod fakes;
pub mod fat_image;

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;

use deepwyrm_syscall::{
    DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_EVENT,
    DW_OBJECT_TYPE_MEMORY_OBJECT, DW_RIGHT_DUPLICATE, DW_RIGHT_READ, DW_RIGHT_TRANSFER,
    DW_RIGHT_WRITE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_STATUS_ACCESS_DENIED,
    DW_STATUS_BAD_HANDLE, DW_STATUS_BUFFER_TOO_SMALL, DW_STATUS_INVALID_ARGUMENT,
    DW_STATUS_PEER_CLOSED, DW_STATUS_TIMED_OUT, DW_STATUS_WOULD_BLOCK, DwDeadline, DwHandle,
    DwHandleTransferV1, DwObjectType, DwReceivedHandleInfoV1, DwRights, DwSignals, DwStatus,
    DwTaskTerminationInfoV1, DwWaitItemV1, DwWaitResultV1,
};
use wyrmroot_runtime::{
    CapabilityInfo, ChannelPlatform, ClockPlatform, HandlePlatform, MappedBootfs, MappingPlan,
    MemoryPlatform, NativeError, OwnedMemoryMapping, ReceiveCounts, WaitPlatform,
};

/// Shared bytes of one MemoryObject.
pub type Memory = Rc<RefCell<Vec<u8>>>;

#[derive(Clone, Debug)]
pub enum Object {
    Channel(usize),
    Event,
    Memory(Memory),
    /// Any other kernel object, known only by its type.
    Other(DwObjectType),
}

impl Object {
    fn object_type(&self) -> DwObjectType {
        match self {
            Self::Channel(_) => DW_OBJECT_TYPE_CHANNEL,
            Self::Event => DW_OBJECT_TYPE_EVENT,
            Self::Memory(_) => DW_OBJECT_TYPE_MEMORY_OBJECT,
            Self::Other(object_type) => *object_type,
        }
    }
}

/// One queued datagram: its bytes and the objects it carries.
type Datagram = (Vec<u8>, Vec<(Object, DwRights)>);

struct Endpoint {
    peer: usize,
    open: bool,
    queue: VecDeque<Datagram>,
}

/// A scripted process: does whatever it can with the world and reports
/// whether it did anything.
pub type Peer = Box<dyn FnMut(&mut World) -> bool>;

pub struct World {
    peers: Vec<Peer>,
    endpoints: Vec<Endpoint>,
    handles: BTreeMap<u64, (Object, DwRights)>,
    next: u64,
    /// Datagrams one endpoint queues before a send would block.
    pub capacity: usize,
    /// The modelled monotonic clock, in nanoseconds.
    pub now: u64,
}

fn fail<T>(status: DwStatus) -> Result<T, NativeError> {
    Err(NativeError::Status(status))
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

impl World {
    pub fn new() -> Self {
        Self {
            peers: Vec::new(),
            endpoints: Vec::new(),
            handles: BTreeMap::new(),
            next: 0x100,
            capacity: 16,
            now: 1_000,
        }
    }

    pub fn add_peer(&mut self, peer: impl FnMut(&mut World) -> bool + 'static) {
        self.peers.push(Box::new(peer));
    }

    /// Runs every peer once; whether any made progress.
    pub fn run_peers(&mut self) -> bool {
        let mut peers = std::mem::take(&mut self.peers);
        let mut progressed = false;
        for peer in &mut peers {
            progressed |= peer(self);
        }
        // Peers added while running join the end.
        peers.append(&mut self.peers);
        self.peers = peers;
        progressed
    }

    pub fn install(&mut self, object: Object, rights: DwRights) -> DwHandle {
        self.next += 1;
        self.handles.insert(self.next, (object, rights));
        DwHandle(self.next)
    }

    /// A MemoryObject of `bytes` zeroed bytes, and its shared contents.
    pub fn memory_object(&mut self, bytes: usize, rights: DwRights) -> (DwHandle, Memory) {
        let memory = Rc::new(RefCell::new(vec![0u8; bytes]));
        (self.install(Object::Memory(memory.clone()), rights), memory)
    }

    /// The contents behind a MemoryObject handle.
    pub fn memory(&self, handle: DwHandle) -> Option<Memory> {
        match self.handles.get(&handle.0)? {
            (Object::Memory(memory), _) => Some(memory.clone()),
            _ => None,
        }
    }

    pub fn rights(&self, handle: DwHandle) -> Option<DwRights> {
        self.handles.get(&handle.0).map(|(_, rights)| *rights)
    }

    pub fn live_handles(&self) -> usize {
        self.handles.len()
    }

    pub fn is_live(&self, handle: DwHandle) -> bool {
        self.handles.contains_key(&handle.0)
    }

    fn channel(&self, handle: DwHandle, right: DwRights) -> Result<usize, NativeError> {
        match self.handles.get(&handle.0) {
            None => fail(DW_STATUS_BAD_HANDLE),
            Some((_, rights)) if rights.0 & right.0 != right.0 => fail(DW_STATUS_ACCESS_DENIED),
            Some((Object::Channel(endpoint), _)) => Ok(*endpoint),
            Some(_) => fail(DW_STATUS_INVALID_ARGUMENT),
        }
    }

    fn release(&mut self, object: Object) {
        if let Object::Channel(endpoint) = object {
            self.endpoints[endpoint].open = false;
            let queued: Vec<_> = self.endpoints[endpoint].queue.drain(..).collect();
            for (_, handles) in queued {
                for (object, _) in handles {
                    self.release(object);
                }
            }
        }
    }

    pub fn signals(&self, handle: DwHandle) -> Result<DwSignals, NativeError> {
        match self.handles.get(&handle.0) {
            None => fail(DW_STATUS_BAD_HANDLE),
            Some((Object::Channel(endpoint), _)) => {
                let endpoint = &self.endpoints[*endpoint];
                let mut signals = 0;
                if !endpoint.queue.is_empty() {
                    signals |= DW_SIGNAL_READABLE.0;
                }
                if !self.endpoints[endpoint.peer].open {
                    signals |= DW_SIGNAL_PEER_CLOSED.0;
                }
                Ok(DwSignals(signals))
            }
            Some(_) => Ok(DwSignals(0)),
        }
    }

    pub fn readable(&self, handle: DwHandle) -> bool {
        self.signals(handle)
            .is_ok_and(|signals| signals.0 & DW_SIGNAL_READABLE.0 != 0)
    }

    pub fn peer_closed(&self, handle: DwHandle) -> bool {
        self.signals(handle)
            .is_ok_and(|signals| signals.0 & DW_SIGNAL_PEER_CLOSED.0 != 0)
    }

    /// Sends `bytes` with handles moved at their full rights; panics on
    /// failure, for test peers.
    pub fn send(&mut self, channel: DwHandle, bytes: &[u8], handles: &[DwHandle]) {
        let transfers: Vec<_> = handles
            .iter()
            .map(|&handle| DwHandleTransferV1 {
                handle,
                requested_rights: self.rights(handle).expect("live handle"),
                operation: DW_HANDLE_TRANSFER_MOVE,
                reserved0: 0,
                reserved: [0; 2],
            })
            .collect();
        self.send_channel(channel, bytes, &transfers).unwrap();
    }

    /// Receives one datagram; panics if none is queued, for test peers.
    pub fn receive(&mut self, channel: DwHandle) -> (Vec<u8>, Vec<DwReceivedHandleInfoV1>) {
        let mut bytes = vec![0u8; 65536];
        let mut handles = [DwReceivedHandleInfoV1::default(); 16];
        let counts = self
            .receive_channel(channel, &mut bytes, &mut handles)
            .unwrap();
        bytes.truncate(counts.bytes);
        (bytes, handles[..counts.handles].to_vec())
    }
}

impl HandlePlatform for World {
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        let (object, _) = self
            .handles
            .remove(&handle.0)
            .ok_or(NativeError::Status(DW_STATUS_BAD_HANDLE))?;
        self.release(object);
        Ok(())
    }

    /// Only MemoryObjects duplicate; a Channel endpoint stays unique so that
    /// closing it is closing the endpoint.
    fn duplicate_handle(
        &mut self,
        handle: DwHandle,
        rights: DwRights,
    ) -> Result<DwHandle, NativeError> {
        let (object, held) = self
            .handles
            .get(&handle.0)
            .cloned()
            .ok_or(NativeError::Status(DW_STATUS_BAD_HANDLE))?;
        if held.0 & DW_RIGHT_DUPLICATE.0 == 0 || rights.0 & !held.0 != 0 {
            return fail(DW_STATUS_ACCESS_DENIED);
        }
        match object {
            Object::Memory(_) => Ok(self.install(object, rights)),
            _ => fail(DW_STATUS_INVALID_ARGUMENT),
        }
    }

    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
        let (object, rights) = self
            .handles
            .get(&handle.0)
            .ok_or(NativeError::Status(DW_STATUS_BAD_HANDLE))?;
        Ok(CapabilityInfo {
            object_type: object.object_type(),
            rights: *rights,
        })
    }

    fn query_memory_object_size(&mut self, handle: DwHandle) -> Result<u64, NativeError> {
        self.memory(handle)
            .map(|memory| memory.borrow().len() as u64)
            .ok_or(NativeError::Status(DW_STATUS_INVALID_ARGUMENT))
    }

    fn query_task_termination_info(
        &mut self,
        _: DwHandle,
    ) -> Result<DwTaskTerminationInfoV1, NativeError> {
        unimplemented!("the model has no tasks")
    }
}

impl ChannelPlatform for World {
    fn create_channel(&mut self, rights: DwRights) -> Result<(DwHandle, DwHandle), NativeError> {
        let first = self.endpoints.len();
        for peer in [first + 1, first] {
            self.endpoints.push(Endpoint {
                peer,
                open: true,
                queue: VecDeque::new(),
            });
        }
        Ok((
            self.install(Object::Channel(first), rights),
            self.install(Object::Channel(first + 1), rights),
        ))
    }

    fn send_channel(
        &mut self,
        channel: DwHandle,
        bytes: &[u8],
        transfers: &[DwHandleTransferV1],
    ) -> Result<(), NativeError> {
        let endpoint = self.channel(channel, DW_RIGHT_WRITE)?;
        let mut moved = Vec::new();
        for transfer in transfers {
            let Some((object, rights)) = self.handles.get(&transfer.handle.0).cloned() else {
                return fail(DW_STATUS_BAD_HANDLE);
            };
            let requested = transfer.requested_rights.0;
            if transfer.handle == channel
                || transfers
                    .iter()
                    .filter(|other| other.handle == transfer.handle)
                    .count()
                    != 1
                || transfer.operation != DW_HANDLE_TRANSFER_MOVE
                || requested == 0
                || requested & !rights.0 != 0
            {
                return fail(DW_STATUS_INVALID_ARGUMENT);
            }
            if rights.0 & DW_RIGHT_TRANSFER.0 == 0 {
                return fail(DW_STATUS_ACCESS_DENIED);
            }
            moved.push((transfer.handle, object, transfer.requested_rights));
        }
        let peer = self.endpoints[endpoint].peer;
        if !self.endpoints[peer].open {
            return fail(DW_STATUS_PEER_CLOSED);
        }
        if self.endpoints[peer].queue.len() >= self.capacity {
            return fail(DW_STATUS_WOULD_BLOCK);
        }
        let mut carried = Vec::new();
        for (handle, object, rights) in moved {
            self.handles.remove(&handle.0);
            carried.push((object, rights));
        }
        self.endpoints[peer]
            .queue
            .push_back((bytes.to_vec(), carried));
        Ok(())
    }

    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        let endpoint = self.channel(channel, DW_RIGHT_READ)?;
        let Some((payload, carried)) = self.endpoints[endpoint].queue.front() else {
            let peer = self.endpoints[endpoint].peer;
            return fail(if self.endpoints[peer].open {
                DW_STATUS_WOULD_BLOCK
            } else {
                DW_STATUS_PEER_CLOSED
            });
        };
        if payload.len() > bytes.len() || carried.len() > handles.len() {
            return fail(DW_STATUS_BUFFER_TOO_SMALL);
        }
        let (payload, carried) = self.endpoints[endpoint].queue.pop_front().unwrap();
        bytes[..payload.len()].copy_from_slice(&payload);
        let count = carried.len();
        for (slot, (object, rights)) in handles.iter_mut().zip(carried) {
            let object_type = object.object_type();
            *slot = DwReceivedHandleInfoV1 {
                handle: self.install(object, rights),
                rights,
                object_type,
                reserved0: 0,
                reserved: [0; 2],
            };
        }
        Ok(ReceiveCounts {
            bytes: payload.len(),
            handles: count,
        })
    }
}

impl WaitPlatform for World {
    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        _: DwDeadline,
    ) -> Result<DwWaitResultV1, NativeError> {
        loop {
            for (index, item) in items.iter().enumerate() {
                let observed = self.signals(item.handle)?;
                if observed.0 & item.signals.0 != 0 {
                    return Ok(DwWaitResultV1 {
                        size: 48,
                        version: 1,
                        index: index as u32,
                        observed,
                        ..DwWaitResultV1::default()
                    });
                }
            }
            // Nothing is ready: let the other processes run, and if none of
            // them does anything the deadline passes.
            if !self.run_peers() {
                return fail(DW_STATUS_TIMED_OUT);
            }
        }
    }

    fn wait_one(
        &mut self,
        handle: DwHandle,
        signals: DwSignals,
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, NativeError> {
        self.wait_many(&[DwWaitItemV1 { handle, signals }], deadline)
    }

    fn create_event(&mut self, rights: DwRights) -> Result<DwHandle, NativeError> {
        Ok(self.install(Object::Event, rights))
    }

    fn signal_event(&mut self, _: DwHandle, _: DwSignals, _: DwSignals) -> Result<(), NativeError> {
        unimplemented!("no service under test signals events")
    }
}

impl ClockPlatform for World {
    fn monotonic_active_now(&mut self) -> Result<u64, NativeError> {
        Ok(self.now)
    }

    fn monotonic_deadline_after(&mut self, interval: u64) -> Result<DwDeadline, NativeError> {
        Ok(DwDeadline(self.now.saturating_add(interval)))
    }

    fn create_timer(&mut self, rights: DwRights) -> Result<DwHandle, NativeError> {
        Ok(self.install(Object::Event, rights))
    }

    fn set_timer(&mut self, _: DwHandle, _: DwDeadline) -> Result<(), NativeError> {
        Ok(())
    }

    fn cancel_timer(&mut self, _: DwHandle) -> Result<(), NativeError> {
        Ok(())
    }
}

/// MemoryObjects exist; mapping them is the services' mapper seam's job.
impl MemoryPlatform for World {
    fn create_memory_object(
        &mut self,
        bytes: u64,
        rights: DwRights,
    ) -> Result<DwHandle, NativeError> {
        Ok(self.memory_object(bytes as usize, rights).0)
    }

    fn map_memory_read_write(
        &mut self,
        _: DwHandle,
        _: DwHandle,
        _: u64,
    ) -> Result<OwnedMemoryMapping, NativeError> {
        fail(DW_STATUS_INVALID_ARGUMENT)
    }

    fn map_memory_read_only(
        &mut self,
        _: DwHandle,
        _: DwHandle,
        _: u64,
    ) -> Result<OwnedMemoryMapping, NativeError> {
        fail(DW_STATUS_INVALID_ARGUMENT)
    }

    fn unmap_memory(&mut self, _: OwnedMemoryMapping) -> Result<(), NativeError> {
        unimplemented!("the model never hands out a mapping")
    }

    fn materialize_read_only_memory(
        &mut self,
        _: DwHandle,
        _: &[u8],
        _: DwRights,
    ) -> Result<DwHandle, NativeError> {
        unimplemented!()
    }

    fn map_bootfs_read_only(
        &mut self,
        _: DwHandle,
        _: DwHandle,
        _: MappingPlan,
    ) -> Result<MappedBootfs, NativeError> {
        unimplemented!()
    }

    fn unmap_bootfs(&mut self, _: MappedBootfs) -> Result<(), NativeError> {
        unimplemented!()
    }
}

/// Memory rights tests commonly give a buffer: READ, WRITE and TRANSFER.
pub const BUFFER_RIGHTS: DwRights =
    DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_TRANSFER.0);
