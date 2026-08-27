use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
    vec,
    vec::Vec,
};

use deepwyrm_syscall::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_MEMORY_OBJECT,
    DW_OBJECT_TYPE_TASK_GROUP, DW_SIGNAL_EXITED, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE,
    DW_TASK_STATE_EXITED, DW_TASK_TERMINATION_INFO_V1_SIZE, DW_TERMINATION_NORMAL_EXIT,
    DW_WAIT_RESULT_V1_SIZE, DwDeadline, DwHandle, DwHandleTransferV1, DwMemoryProtection,
    DwObjectType, DwReceivedHandleInfoV1, DwRights, DwStatus, DwTaskTerminationInfoV1,
    DwWaitItemV1, DwWaitResultV1,
};
use wyrmroot_bootfs::builder::{Builder, FileMode};
use wyrmroot_loader::{
    launch::{self, LaunchProfile, encode_init, encode_ready_for_profile},
    process::{LoaderPlatform, ParentMapping, ProcessCreateRequest, ProcessCreateResult},
};
use wyrmroot_runtime::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo,
    LOADER_TASK_GROUP_EXPECTATION, MappingPlan, NativeError, ReceiveCounts, SELF_ROOT_EXPECTATION,
    SupervisionPlatform,
};

use super::*;

const BOOTSTRAP: DwHandle = DwHandle(11);
const ROOT: DwHandle = DwHandle(12);
const BOOTFS: DwHandle = DwHandle(13);
const TASK_GROUP: DwHandle = DwHandle(14);
const DEADLINE: DwDeadline = DwDeadline(999);
const EXCHANGE_FAILURE: NativeError = NativeError::Status(DwStatus(-80));
const TERMINATE_FAILURE: NativeError = NativeError::Status(DwStatus(-81));
const LOAD_FAILURE: NativeError = NativeError::Status(DwStatus(-82));
const WAIT_FAILURE: NativeError = NativeError::Status(DwStatus(-83));
const QUERY_FAILURE: NativeError = NativeError::Status(DwStatus(-84));
const CLOSE_FAILURE: NativeError = NativeError::Status(DwStatus(-85));

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Peer {
    Hog,
    Progress,
    Hello,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupTarget {
    ProgressData,
    ProgressLaunch,
    ProgressProcess,
    HogLaunch,
    HogProcess,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Event {
    Init(Peer),
    Start(Peer),
    Ready(Peer),
    Arm,
    Exchange(u32),
    ExitWait(Peer),
    Query(Peer),
    Terminate(Peer),
    Close(u64),
    InitReady,
}

#[derive(Default)]
struct Shared {
    rights: BTreeMap<u64, DwRights>,
    launch_peer: BTreeMap<u64, Peer>,
    retained_launch: BTreeMap<Peer, DwHandle>,
    process_peer: BTreeMap<u64, Peer>,
    thread_peer: BTreeMap<u64, Peer>,
    peer_transaction: BTreeMap<Peer, u64>,
    ready_sent: BTreeSet<Peer>,
    data_parent: Option<DwHandle>,
    data_broad: Option<DwHandle>,
    data_child: Option<DwHandle>,
    progress_child_closes: usize,
    events: Vec<Event>,
    reply_round: u32,
}

struct System {
    shared: Rc<RefCell<Shared>>,
    init: [u8; INIT0_BYTES],
    bootfs: Vec<u8>,
    fail_exchange: Option<u32>,
    fail_close: Option<CleanupTarget>,
}

impl System {
    fn new(shared: Rc<RefCell<Shared>>) -> Self {
        let mut init = [0; INIT0_BYTES];
        encode_init(LaunchProfile::Init0, 7, &mut init).unwrap();
        let image = executable();
        let mut builder = Builder::new();
        for path in [DW1B_HOG_PATH, DW1B_PROGRESS_PATH, HELLO_PATH] {
            builder.add(path, &image, FileMode::Executable).unwrap();
        }
        Self {
            shared,
            init,
            bootfs: builder.build().unwrap(),
            fail_exchange: None,
            fail_close: None,
        }
    }
}

impl Init0System for System {
    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
        let fixed = match handle {
            BOOTSTRAP => Some((DW_OBJECT_TYPE_CHANNEL, BOOTSTRAP_CHANNEL_EXPECTATION.rights)),
            ROOT => Some((DW_OBJECT_TYPE_ADDRESS_REGION, SELF_ROOT_EXPECTATION.rights)),
            BOOTFS => Some((DW_OBJECT_TYPE_MEMORY_OBJECT, BOOTFS_EXPECTATION.rights)),
            TASK_GROUP => Some((
                DW_OBJECT_TYPE_TASK_GROUP,
                LOADER_TASK_GROUP_EXPECTATION.rights,
            )),
            _ => None,
        };
        if let Some((object_type, rights)) = fixed {
            return Ok(CapabilityInfo {
                object_type,
                rights,
            });
        }
        let rights = self.shared.borrow().rights[&handle.0];
        Ok(CapabilityInfo {
            object_type: DW_OBJECT_TYPE_CHANNEL,
            rights,
        })
    }

    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        assert_eq!(channel, BOOTSTRAP);
        bytes.copy_from_slice(&self.init);
        for (slot, (handle, object_type, rights)) in handles.iter_mut().zip([
            (
                ROOT,
                DW_OBJECT_TYPE_ADDRESS_REGION,
                SELF_ROOT_EXPECTATION.rights,
            ),
            (
                BOOTFS,
                DW_OBJECT_TYPE_MEMORY_OBJECT,
                BOOTFS_EXPECTATION.rights,
            ),
            (
                TASK_GROUP,
                DW_OBJECT_TYPE_TASK_GROUP,
                LOADER_TASK_GROUP_EXPECTATION.rights,
            ),
        ]) {
            *slot = DwReceivedHandleInfoV1 {
                handle,
                object_type,
                rights,
                ..DwReceivedHandleInfoV1::default()
            };
        }
        Ok(ReceiveCounts {
            bytes: self.init.len(),
            handles: 3,
        })
    }

    fn query_memory_object_size(&mut self, handle: DwHandle) -> Result<u64, NativeError> {
        assert_eq!(handle, BOOTFS);
        Ok(self.bootfs.len() as u64)
    }

    fn with_bootfs_bytes<R>(
        &mut self,
        root_region: DwHandle,
        bootfs: DwHandle,
        _: MappingPlan,
        use_bytes: impl for<'bytes> FnOnce(&'bytes [u8]) -> R,
    ) -> Result<R, NativeError> {
        assert_eq!((root_region, bootfs), (ROOT, BOOTFS));
        Ok(use_bytes(&self.bootfs))
    }

    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
        if channel == BOOTSTRAP {
            self.shared.borrow_mut().events.push(Event::InitReady);
            return Ok(());
        }
        assert_eq!(Some(channel), self.shared.borrow().data_parent);
        let round = self.shared.borrow().reply_round as usize;
        wyrmroot_dw1b_preemption::parse_challenge(bytes, round)
            .expect("init0 emitted the exact next challenge");
        self.shared
            .borrow_mut()
            .events
            .push(Event::Exchange(round as u32));
        if self.fail_exchange == Some(round as u32) {
            return Err(EXCHANGE_FAILURE);
        }
        Ok(())
    }

    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        self.shared.borrow_mut().events.push(Event::Close(handle.0));
        if self.fail_close.is_some_and(|target| {
            cleanup_target_for_handle(&self.shared.borrow(), handle) == Some(target)
        }) {
            Err(CLOSE_FAILURE)
        } else {
            Ok(())
        }
    }

    fn arm_dw1b_preemption(
        &mut self,
        hog_process: DwHandle,
        progress_process: DwHandle,
    ) -> Result<(), NativeError> {
        let shared = self.shared.borrow();
        assert_eq!(shared.process_peer[&hog_process.0], Peer::Hog);
        assert_eq!(shared.process_peer[&progress_process.0], Peer::Progress);
        drop(shared);
        self.shared.borrow_mut().events.push(Event::Arm);
        Ok(())
    }
}

struct Loader {
    shared: Rc<RefCell<Shared>>,
    next: u64,
    channel_creates: usize,
    process_creates: usize,
    current_process: Option<Peer>,
    fail_send_init: Option<Peer>,
    fail_thread_create: Option<Peer>,
    fail_terminate: Option<Peer>,
    fail_close: Option<CleanupTarget>,
    fail_data_duplicate: bool,
    fail_pair_rollback_closes: bool,
    pair_rollback_active: bool,
}

impl Loader {
    fn new(shared: Rc<RefCell<Shared>>) -> Self {
        Self {
            shared,
            next: 100,
            channel_creates: 0,
            process_creates: 0,
            current_process: None,
            fail_send_init: None,
            fail_thread_create: None,
            fail_terminate: None,
            fail_close: None,
            fail_data_duplicate: false,
            fail_pair_rollback_closes: false,
            pair_rollback_active: false,
        }
    }

    fn handle(&mut self) -> DwHandle {
        let handle = DwHandle(self.next);
        self.next += 1;
        handle
    }

    const fn peer_for_load(index: usize) -> Peer {
        match index {
            0 => Peer::Hog,
            1 => Peer::Progress,
            2 => Peer::Hello,
            _ => panic!("unexpected child load"),
        }
    }
}

impl LoaderPlatform for Loader {
    type Error = NativeError;

    fn channel_create(&mut self, rights: DwRights) -> Result<(DwHandle, DwHandle), Self::Error> {
        let broad = self.handle();
        let child = self.handle();
        self.shared.borrow_mut().rights.insert(broad.0, rights);
        self.shared.borrow_mut().rights.insert(child.0, rights);
        match self.channel_creates {
            0 => {
                self.shared
                    .borrow_mut()
                    .launch_peer
                    .insert(broad.0, Peer::Hog);
            }
            1 => {
                let mut shared = self.shared.borrow_mut();
                shared.data_broad = Some(broad);
                shared.data_child = Some(child);
            }
            2 => {
                self.shared
                    .borrow_mut()
                    .launch_peer
                    .insert(broad.0, Peer::Progress);
            }
            3 => {
                self.shared
                    .borrow_mut()
                    .launch_peer
                    .insert(broad.0, Peer::Hello);
            }
            _ => panic!("unexpected Channel pair"),
        }
        self.channel_creates += 1;
        Ok((broad, child))
    }

    fn duplicate(&mut self, handle: DwHandle, rights: DwRights) -> Result<DwHandle, Self::Error> {
        if self.fail_data_duplicate && self.channel_creates == 2 {
            self.pair_rollback_active = true;
            return Err(LOAD_FAILURE);
        }
        let duplicate = self.handle();
        let mut shared = self.shared.borrow_mut();
        shared.rights.insert(duplicate.0, rights);
        if let Some(peer) = shared.launch_peer.get(&handle.0).copied() {
            shared.launch_peer.insert(duplicate.0, peer);
            shared.retained_launch.insert(peer, duplicate);
        } else if self.channel_creates == 2 {
            shared.data_parent = Some(duplicate);
        }
        Ok(duplicate)
    }

    fn close(&mut self, handle: DwHandle) -> Result<(), Self::Error> {
        self.shared.borrow_mut().events.push(Event::Close(handle.0));
        if Some(handle) == self.shared.borrow().data_child {
            self.shared.borrow_mut().progress_child_closes += 1;
        }
        let pair_handle = {
            let shared = self.shared.borrow();
            shared.data_broad == Some(handle) || shared.data_child == Some(handle)
        };
        if self.pair_rollback_active && self.fail_pair_rollback_closes && pair_handle
            || self.fail_close.is_some_and(|target| {
                cleanup_target_for_handle(&self.shared.borrow(), handle) == Some(target)
            })
        {
            Err(CLOSE_FAILURE)
        } else {
            Ok(())
        }
    }

    fn process_create(
        &mut self,
        _: ProcessCreateRequest,
    ) -> Result<ProcessCreateResult, Self::Error> {
        let peer = Self::peer_for_load(self.process_creates);
        self.process_creates += 1;
        self.current_process = Some(peer);
        let process = self.handle();
        let root = self.handle();
        let child_bootstrap = self.handle();
        self.shared
            .borrow_mut()
            .process_peer
            .insert(process.0, peer);
        Ok(ProcessCreateResult {
            process,
            root,
            child_bootstrap,
        })
    }

    fn memory_create(&mut self, _: u64, _: DwRights) -> Result<DwHandle, Self::Error> {
        Ok(self.handle())
    }

    fn materialize_parent(
        &mut self,
        _: DwHandle,
        _: DwHandle,
        object_size: u64,
        _: u64,
        _: &[u8],
    ) -> Result<ParentMapping, Self::Error> {
        Ok(ParentMapping {
            address: 0x5000_0000,
            bytes: object_size,
        })
    }

    fn materialize_parent_with(
        &mut self,
        _: DwHandle,
        _: DwHandle,
        object_size: u64,
        _: u64,
        destination_size: usize,
        materialize: impl FnOnce(&mut [u8]),
    ) -> Result<ParentMapping, Self::Error> {
        let mut destination = vec![0; destination_size];
        materialize(&mut destination);
        Ok(ParentMapping {
            address: 0x5000_0000,
            bytes: object_size,
        })
    }

    fn unmap_parent(&mut self, _: DwHandle, _: ParentMapping) -> Result<(), Self::Error> {
        Ok(())
    }

    fn map_child(
        &mut self,
        _: DwHandle,
        _: DwHandle,
        _: u64,
        _: u64,
        _: DwMemoryProtection,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn unmap_child(&mut self, _: DwHandle, _: u64, _: u64) -> Result<(), Self::Error> {
        Ok(())
    }

    fn thread_create(&mut self, _: DwHandle, _: DwRights) -> Result<DwHandle, Self::Error> {
        let peer = self.current_process.unwrap();
        if self.fail_thread_create == Some(peer) {
            return Err(LOAD_FAILURE);
        }
        let thread = self.handle();
        self.shared.borrow_mut().thread_peer.insert(thread.0, peer);
        Ok(thread)
    }

    fn send_init(
        &mut self,
        _: DwHandle,
        bytes: &[u8],
        transfers: &[DwHandleTransferV1],
    ) -> Result<(), Self::Error> {
        let peer = self.current_process.unwrap();
        let (profile, transaction, handles) = match peer {
            Peer::Hog => (
                LaunchProfile::Hello,
                wyrmroot_dw1b_preemption::HOG_TRANSACTION_ID,
                0,
            ),
            Peer::Progress => (
                LaunchProfile::Dw1bProgress,
                wyrmroot_dw1b_preemption::PROGRESS_TRANSACTION_ID,
                1,
            ),
            Peer::Hello => (LaunchProfile::Hello, HELLO_TRANSACTION_ID, 0),
        };
        assert_eq!(transfers.len(), handles);
        let received = transfers
            .iter()
            .map(|transfer| DwReceivedHandleInfoV1 {
                handle: transfer.handle,
                object_type: DW_OBJECT_TYPE_CHANNEL,
                rights: transfer.requested_rights,
                ..DwReceivedHandleInfoV1::default()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            launch::parse_init(profile, bytes, &received)
                .unwrap()
                .transaction_id,
            transaction
        );
        self.shared
            .borrow_mut()
            .peer_transaction
            .insert(peer, transaction);
        self.shared.borrow_mut().events.push(Event::Init(peer));
        if self.fail_send_init == Some(peer) {
            return Err(LOAD_FAILURE);
        }
        Ok(())
    }

    fn thread_start(
        &mut self,
        thread: DwHandle,
        _: u64,
        _: u64,
        _: DwHandle,
        _: u64,
    ) -> Result<(), Self::Error> {
        let peer = self.shared.borrow().thread_peer[&thread.0];
        self.shared.borrow_mut().events.push(Event::Start(peer));
        Ok(())
    }

    fn thread_terminate(&mut self, _: DwHandle) -> Result<(), Self::Error> {
        Ok(())
    }

    fn process_terminate(&mut self, process: DwHandle) -> Result<(), Self::Error> {
        let peer = self.shared.borrow().process_peer[&process.0];
        self.shared.borrow_mut().events.push(Event::Terminate(peer));
        if self.fail_terminate == Some(peer) {
            Err(TERMINATE_FAILURE)
        } else {
            Ok(())
        }
    }
}

struct Supervisor {
    shared: Rc<RefCell<Shared>>,
    fail_wait: Option<Peer>,
    fail_query: Option<Peer>,
}

impl SupervisionPlatform for Supervisor {
    type Error = NativeError;

    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, Self::Error> {
        assert_eq!(deadline, DEADLINE);
        let handle = items[0].handle;
        let launch_peer = self.shared.borrow().launch_peer.get(&handle.0).copied();
        let (observed, index) = if let Some(peer) = launch_peer {
            if items.len() == 2 {
                let first_ready = self.shared.borrow_mut().ready_sent.insert(peer);
                if first_ready {
                    self.shared.borrow_mut().events.push(Event::Ready(peer));
                    (DW_SIGNAL_READABLE, 0)
                } else {
                    self.shared.borrow_mut().events.push(Event::ExitWait(peer));
                    if self.fail_wait == Some(peer) {
                        return Err(WAIT_FAILURE);
                    }
                    (DW_SIGNAL_EXITED, 1)
                }
            } else {
                (DW_SIGNAL_PEER_CLOSED, 0)
            }
        } else if Some(handle) == self.shared.borrow().data_parent {
            (DW_SIGNAL_READABLE, 0)
        } else {
            let peer = self.shared.borrow().process_peer[&handle.0];
            self.shared.borrow_mut().events.push(Event::ExitWait(peer));
            if self.fail_wait == Some(peer) {
                return Err(WAIT_FAILURE);
            }
            (DW_SIGNAL_EXITED, 0)
        };
        Ok(DwWaitResultV1 {
            size: DW_WAIT_RESULT_V1_SIZE,
            version: 1,
            index,
            observed,
            ..DwWaitResultV1::default()
        })
    }

    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, Self::Error> {
        assert!(handles.is_empty());
        if Some(channel) == self.shared.borrow().data_parent {
            let round = self.shared.borrow().reply_round as usize;
            bytes.copy_from_slice(&wyrmroot_dw1b_preemption::encode_reply(round));
            self.shared.borrow_mut().reply_round += 1;
        } else {
            let peer = self.shared.borrow().launch_peer[&channel.0];
            let transaction = self.shared.borrow().peer_transaction[&peer];
            let profile = match peer {
                Peer::Progress => LaunchProfile::Dw1bProgress,
                Peer::Hog | Peer::Hello => LaunchProfile::Hello,
            };
            encode_ready_for_profile(profile, transaction, bytes).unwrap();
        }
        Ok(ReceiveCounts {
            bytes: bytes.len(),
            handles: 0,
        })
    }

    fn query_task_termination(
        &mut self,
        process: DwHandle,
    ) -> Result<DwTaskTerminationInfoV1, Self::Error> {
        let peer = self.shared.borrow().process_peer[&process.0];
        self.shared.borrow_mut().events.push(Event::Query(peer));
        if self.fail_query == Some(peer) {
            return Err(QUERY_FAILURE);
        }
        Ok(DwTaskTerminationInfoV1 {
            size: DW_TASK_TERMINATION_INFO_V1_SIZE,
            version: 1,
            state: DW_TASK_STATE_EXITED,
            reason: DW_TERMINATION_NORMAL_EXIT,
            ..DwTaskTerminationInfoV1::default()
        })
    }
}

fn cleanup_target_for_handle(shared: &Shared, handle: DwHandle) -> Option<CleanupTarget> {
    if shared.data_parent == Some(handle) {
        return Some(CleanupTarget::ProgressData);
    }
    for (peer, launch_target, process_target) in [
        (
            Peer::Progress,
            CleanupTarget::ProgressLaunch,
            CleanupTarget::ProgressProcess,
        ),
        (
            Peer::Hog,
            CleanupTarget::HogLaunch,
            CleanupTarget::HogProcess,
        ),
    ] {
        if shared.retained_launch.get(&peer) == Some(&handle) {
            return Some(launch_target);
        }
        if shared.process_peer.get(&handle.0) == Some(&peer) {
            return Some(process_target);
        }
    }
    None
}

fn high_level_events(shared: &Shared) -> Vec<Event> {
    shared
        .events
        .iter()
        .filter(|event| !matches!(event, Event::Close(_)))
        .cloned()
        .collect()
}

fn cleanup_handles(shared: &Shared) -> [DwHandle; 5] {
    let process = |peer| {
        DwHandle(
            *shared
                .process_peer
                .iter()
                .find_map(|(handle, observed)| (*observed == peer).then_some(handle))
                .unwrap(),
        )
    };
    [
        shared.data_parent.unwrap(),
        shared.retained_launch[&Peer::Progress],
        process(Peer::Progress),
        shared.retained_launch[&Peer::Hog],
        process(Peer::Hog),
    ]
}

#[test]
fn selector26_executes_the_complete_orchestration_trace() {
    let shared = Rc::new(RefCell::new(Shared::default()));
    let mut system = System::new(shared.clone());
    let mut loader = Loader::new(shared.clone());
    let mut supervisor = Supervisor {
        shared: shared.clone(),
        fail_wait: None,
        fail_query: None,
    };

    assert_eq!(
        run_init0(
            &mut system,
            &mut loader,
            &mut supervisor,
            BOOTSTRAP,
            DEADLINE,
        ),
        Ok(())
    );
    assert_eq!(
        high_level_events(&shared.borrow()),
        vec![
            Event::Init(Peer::Hog),
            Event::Start(Peer::Hog),
            Event::Ready(Peer::Hog),
            Event::Init(Peer::Progress),
            Event::Start(Peer::Progress),
            Event::Ready(Peer::Progress),
            Event::Arm,
            Event::Exchange(0),
            Event::Exchange(1),
            Event::Exchange(2),
            Event::Exchange(3),
            Event::Exchange(4),
            Event::Exchange(5),
            Event::Exchange(6),
            Event::Exchange(7),
            Event::ExitWait(Peer::Progress),
            Event::Query(Peer::Progress),
            Event::Init(Peer::Hello),
            Event::Start(Peer::Hello),
            Event::Ready(Peer::Hello),
            Event::ExitWait(Peer::Hello),
            Event::Query(Peer::Hello),
            Event::Terminate(Peer::Hog),
            Event::ExitWait(Peer::Hog),
            Event::Query(Peer::Hog),
            Event::InitReady,
        ]
    );
    assert_eq!(
        shared
            .borrow()
            .events
            .iter()
            .filter(|event| **event == Event::Arm)
            .count(),
        1
    );
}

#[test]
fn cleanup_aggregates_progress_failure_and_still_reaps_hog() {
    let shared = Rc::new(RefCell::new(Shared::default()));
    let mut system = System::new(shared.clone());
    system.fail_exchange = Some(0);
    let mut loader = Loader::new(shared.clone());
    loader.fail_terminate = Some(Peer::Progress);
    let mut supervisor = Supervisor {
        shared: shared.clone(),
        fail_wait: None,
        fail_query: Some(Peer::Hog),
    };

    assert_eq!(
        run_init0(
            &mut system,
            &mut loader,
            &mut supervisor,
            BOOTSTRAP,
            DEADLINE,
        ),
        Err(Init0Error::Cleanup(TERMINATE_FAILURE))
    );
    let events = &shared.borrow().events;
    assert!(events.windows(3).any(|window| {
        window
            == [
                Event::Terminate(Peer::Progress),
                Event::ExitWait(Peer::Progress),
                Event::Query(Peer::Progress),
            ]
    }));
    assert!(events.windows(3).any(|window| {
        window
            == [
                Event::Terminate(Peer::Hog),
                Event::ExitWait(Peer::Hog),
                Event::Query(Peer::Hog),
            ]
    }));
    assert!(!events.contains(&Event::InitReady));
}

#[test]
fn normal_progress_close_failure_precedes_later_hog_cleanup_failure() {
    let shared = Rc::new(RefCell::new(Shared::default()));
    let mut system = System::new(shared.clone());
    system.fail_close = Some(CleanupTarget::ProgressData);
    let mut loader = Loader::new(shared.clone());
    loader.fail_terminate = Some(Peer::Hog);
    let mut supervisor = Supervisor {
        shared: shared.clone(),
        fail_wait: None,
        fail_query: None,
    };

    assert_eq!(
        run_init0(
            &mut system,
            &mut loader,
            &mut supervisor,
            BOOTSTRAP,
            DEADLINE,
        ),
        Err(Init0Error::Cleanup(CLOSE_FAILURE))
    );
    let shared = shared.borrow();
    assert_eq!(shared.reply_round, 8);
    assert!(shared.events.contains(&Event::Terminate(Peer::Hog)));
    assert!(shared.events.contains(&Event::ExitWait(Peer::Hog)));
    assert!(shared.events.contains(&Event::Query(Peer::Hog)));
    assert!(!shared.events.contains(&Event::Init(Peer::Hello)));
    assert!(!shared.events.contains(&Event::InitReady));
}

#[derive(Clone, Copy)]
enum CleanupFault {
    Terminate(Peer),
    Wait(Peer),
    Query(Peer),
    Close(CleanupTarget),
}

#[test]
fn every_cleanup_failure_still_attempts_all_later_peer_cleanup() {
    for (fault, expected) in [
        (CleanupFault::Terminate(Peer::Progress), TERMINATE_FAILURE),
        (CleanupFault::Wait(Peer::Progress), WAIT_FAILURE),
        (CleanupFault::Query(Peer::Progress), QUERY_FAILURE),
        (
            CleanupFault::Close(CleanupTarget::ProgressLaunch),
            CLOSE_FAILURE,
        ),
        (
            CleanupFault::Close(CleanupTarget::ProgressProcess),
            CLOSE_FAILURE,
        ),
        (
            CleanupFault::Close(CleanupTarget::ProgressData),
            CLOSE_FAILURE,
        ),
        (CleanupFault::Terminate(Peer::Hog), TERMINATE_FAILURE),
        (CleanupFault::Wait(Peer::Hog), WAIT_FAILURE),
        (CleanupFault::Query(Peer::Hog), QUERY_FAILURE),
        (CleanupFault::Close(CleanupTarget::HogLaunch), CLOSE_FAILURE),
        (
            CleanupFault::Close(CleanupTarget::HogProcess),
            CLOSE_FAILURE,
        ),
    ] {
        let shared = Rc::new(RefCell::new(Shared::default()));
        let mut system = System::new(shared.clone());
        system.fail_exchange = Some(0);
        let mut loader = Loader::new(shared.clone());
        let mut supervisor = Supervisor {
            shared: shared.clone(),
            fail_wait: None,
            fail_query: None,
        };
        match fault {
            CleanupFault::Terminate(peer) => loader.fail_terminate = Some(peer),
            CleanupFault::Wait(peer) => supervisor.fail_wait = Some(peer),
            CleanupFault::Query(peer) => supervisor.fail_query = Some(peer),
            CleanupFault::Close(target) => {
                if target == CleanupTarget::ProgressData {
                    system.fail_close = Some(target);
                } else {
                    loader.fail_close = Some(target);
                }
            }
        }

        assert_eq!(
            run_init0(
                &mut system,
                &mut loader,
                &mut supervisor,
                BOOTSTRAP,
                DEADLINE,
            ),
            Err(Init0Error::Cleanup(expected))
        );
        let shared = shared.borrow();
        for peer in [Peer::Progress, Peer::Hog] {
            assert!(shared.events.contains(&Event::Terminate(peer)));
            assert!(shared.events.contains(&Event::ExitWait(peer)));
            assert!(shared.events.contains(&Event::Query(peer)));
        }
        for handle in cleanup_handles(&shared) {
            assert_eq!(
                shared
                    .events
                    .iter()
                    .filter(|event| **event == Event::Close(handle.0))
                    .count(),
                1
            );
        }
        assert!(!shared.events.contains(&Event::InitReady));
    }
}

#[test]
fn data_pair_rollback_attempts_both_closes_then_reaps_hog() {
    let shared = Rc::new(RefCell::new(Shared::default()));
    let mut system = System::new(shared.clone());
    let mut loader = Loader::new(shared.clone());
    loader.fail_data_duplicate = true;
    loader.fail_pair_rollback_closes = true;
    let mut supervisor = Supervisor {
        shared: shared.clone(),
        fail_wait: None,
        fail_query: None,
    };

    assert_eq!(
        run_init0(
            &mut system,
            &mut loader,
            &mut supervisor,
            BOOTSTRAP,
            DEADLINE,
        ),
        Err(Init0Error::Cleanup(CLOSE_FAILURE))
    );
    let shared = shared.borrow();
    for handle in [shared.data_broad.unwrap(), shared.data_child.unwrap()] {
        assert_eq!(
            shared
                .events
                .iter()
                .filter(|event| **event == Event::Close(handle.0))
                .count(),
            1
        );
    }
    assert!(shared.events.contains(&Event::Terminate(Peer::Hog)));
    assert!(shared.events.contains(&Event::ExitWait(Peer::Hog)));
    assert!(shared.events.contains(&Event::Query(Peer::Hog)));
    assert!(!shared.events.contains(&Event::InitReady));
}

#[test]
fn progress_child_is_closed_once_on_both_loader_ownership_sides() {
    for fail_after_recording in [false, true] {
        let shared = Rc::new(RefCell::new(Shared::default()));
        let mut system = System::new(shared.clone());
        let mut loader = Loader::new(shared.clone());
        if fail_after_recording {
            loader.fail_send_init = Some(Peer::Progress);
        } else {
            loader.fail_thread_create = Some(Peer::Progress);
        }
        let mut supervisor = Supervisor {
            shared: shared.clone(),
            fail_wait: None,
            fail_query: None,
        };

        assert!(matches!(
            run_init0(
                &mut system,
                &mut loader,
                &mut supervisor,
                BOOTSTRAP,
                DEADLINE,
            ),
            Err(Init0Error::Loader(LoadError::Platform { .. }))
        ));
        assert_eq!(shared.borrow().progress_child_closes, 1);
        assert!(
            shared
                .borrow()
                .events
                .contains(&Event::Terminate(Peer::Hog))
        );
    }
}

fn executable() -> Vec<u8> {
    let mut bytes = vec![0; 0x2000];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put16(&mut bytes, 16, 2);
    put16(&mut bytes, 18, 62);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 24, 0x400000);
    put64(&mut bytes, 32, 64);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, 56);
    put16(&mut bytes, 56, 1);
    put32(&mut bytes, 64, 1);
    put32(&mut bytes, 68, 5);
    put64(&mut bytes, 72, 0x1000);
    put64(&mut bytes, 80, 0x400000);
    put64(&mut bytes, 88, 0x400000);
    put64(&mut bytes, 96, 16);
    put64(&mut bytes, 104, 32);
    put64(&mut bytes, 112, 4096);
    bytes
}

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
