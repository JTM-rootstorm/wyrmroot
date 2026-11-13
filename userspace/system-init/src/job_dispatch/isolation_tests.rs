//! A session client's fault ends its session and never the tick.
//!
//! These run the real poll over a kernel that keeps a queue per Channel, so
//! a test can say which session misbehaved and then ask whether the one
//! beside it was still served.

extern crate std;

use super::*;
use deepwyrm_syscall::{
    DW_OBJECT_TYPE_CHANNEL, DW_SIGNAL_WRITABLE, DW_STATUS_BUFFER_TOO_SMALL, DW_STATUS_PEER_CLOSED,
    DW_STATUS_WOULD_BLOCK, DwStatus, DwWaitResultV1,
};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;
use std::vec;
use std::vec::Vec;
use wyrmroot_bootfs::builder::{Builder, FileMode};
use wyrmroot_bootfs::launch_policy::{JOB_V2_PROFILE_ID, LaunchPolicyEntry};
use wyrmroot_bootfs::paths::LAUNCH_POLICY_PATH;
use wyrmroot_fs_proto::node;

pub(crate) use super::tests::{InitSendLoader, executable};

const REFUSED: NativeError = NativeError::Status(DwStatus(-1));
pub(crate) const BOOTFS: DwHandle = DwHandle(2);
pub(crate) const AUTHORITY: LoadAuthority = LoadAuthority {
    parent_root: DwHandle(1),
    bootfs: BOOTFS,
    task_group: DwHandle(3),
};

/// How the far end of an image's file Channel behaves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FilePeer {
    /// Answers each request `0` or more nanoseconds after it is sent.
    Answers { after_ns: u64 },
    /// Takes requests and never answers.
    Silent,
}

struct FileServer {
    data: Vec<u8>,
    peer: FilePeer,
}

/// The children the loader made, as the kernel and the supervision waits
/// both see them.
#[derive(Default)]
pub(crate) struct Children {
    /// Each Process's TaskGroup.
    pub(crate) group_of: BTreeMap<u64, u64>,
    /// TaskGroups init has ended; their Processes have exited.
    pub(crate) terminated: BTreeSet<u64>,
    /// Processes that exited by themselves.
    pub(crate) exited: BTreeSet<u64>,
    /// Launch Channels with a READY waiting, and the READY's profile and
    /// transaction.
    pub(crate) ready: BTreeMap<u64, (LaunchProfile, u64)>,
}

impl Children {
    fn has_exited(&self, process: u64) -> bool {
        self.exited.contains(&process)
            || self
                .group_of
                .get(&process)
                .is_some_and(|group| self.terminated.contains(group))
    }
}

pub(crate) type SharedChildren = Rc<RefCell<Children>>;

/// How many replies a Channel queues for a peer that has not read them.
const QUEUE_DEPTH: usize = 2;

/// Something the world does to the kernel at a scheduled time.
pub(crate) type Event = std::boxed::Box<dyn FnMut(&mut FakeKernel)>;

/// One queued message for init: when it becomes receivable, its bytes, and
/// the handles it moves.
type Queued = (u64, Vec<u8>, Vec<u64>);

/// A kernel with a queue per Channel and a clock only waits advance.
///
/// A wait that finds nothing ready sleeps to its deadline, exactly as the
/// real one does -- so a supervisor that blocks on a silent peer shows up as
/// time passing with no tick in it.
pub(crate) struct FakeKernel {
    pub(crate) now: u64,
    next_handle: u64,
    inbound: BTreeMap<u64, VecDeque<Queued>>,
    /// Channels whose peer has closed its end.
    pub(crate) peer_closed: BTreeSet<u64>,
    /// Channels whose peer does not drain its queue: every send is refused.
    pub(crate) full: BTreeSet<u64>,
    /// How many messages init has sent on each Channel that its peer has not
    /// read yet. A Channel holds `QUEUE_DEPTH`.
    unread: BTreeMap<u64, usize>,
    pub(crate) children: SharedChildren,
    /// Handles whose close the kernel refuses.
    pub(crate) fail_close: BTreeSet<u64>,
    /// Channels whose receive the kernel refuses, with this status.
    pub(crate) fail_receive: BTreeMap<u64, DwStatus>,
    pub(crate) sent: Vec<(u64, Vec<u8>)>,
    pub(crate) closed: Vec<u64>,
    memory: BTreeMap<u64, Rc<Vec<u8>>>,
    files: BTreeMap<u64, FileServer>,
    /// When init's clock stops answering, which ends the resident loop.
    pub(crate) clock_stops_at: Option<u64>,
    /// Things that happen by themselves, each at or after its time.
    pub(crate) schedule: Vec<(u64, Event)>,
    /// Refuses to map scratch memory.
    pub(crate) fail_scratch: bool,
    pub(crate) scratch_mapped: usize,
    pub(crate) scratch_unmapped: usize,
}

impl FakeKernel {
    pub(crate) fn new() -> Self {
        let mut kernel = Self {
            now: 1_000,
            next_handle: 0x500,
            inbound: BTreeMap::new(),
            peer_closed: BTreeSet::new(),
            full: BTreeSet::new(),
            unread: BTreeMap::new(),
            children: SharedChildren::default(),
            fail_close: BTreeSet::new(),
            fail_receive: BTreeMap::new(),
            sent: Vec::new(),
            closed: Vec::new(),
            memory: BTreeMap::new(),
            files: BTreeMap::new(),
            clock_stops_at: None,
            schedule: Vec::new(),
            fail_scratch: false,
            scratch_mapped: 0,
            scratch_unmapped: 0,
        };
        kernel.memory.insert(BOOTFS.0, Rc::new(bootfs()));
        kernel
    }

    /// Queues one message for init on `channel`, receivable now.
    pub(crate) fn deliver(&mut self, channel: DwHandle, bytes: &[u8], handles: &[u64]) {
        self.inbound.entry(channel.0).or_default().push_back((
            self.now,
            bytes.to_vec(),
            handles.to_vec(),
        ));
    }

    /// Puts a file of `data` behind `channel`.
    pub(crate) fn serve_file(&mut self, channel: DwHandle, data: Vec<u8>, peer: FilePeer) {
        self.files.insert(channel.0, FileServer { data, peer });
    }

    /// The peer of `channel` reads everything it has been sent.
    pub(crate) fn drain(&mut self, channel: DwHandle) {
        self.unread.remove(&channel.0);
    }

    fn has_room(&self, channel: u64) -> bool {
        !self.full.contains(&channel)
            && self.unread.get(&channel).copied().unwrap_or(0) < QUEUE_DEPTH
    }

    pub(crate) fn is_closed(&self, handle: u64) -> bool {
        self.closed.contains(&handle)
    }

    /// Everything init sent on `channel`, in order.
    pub(crate) fn sent_on(&self, channel: DwHandle) -> Vec<&[u8]> {
        self.sent
            .iter()
            .filter(|(to, _)| *to == channel.0)
            .map(|(_, bytes)| bytes.as_slice())
            .collect()
    }

    fn fresh(&mut self) -> DwHandle {
        self.next_handle += 1;
        DwHandle(self.next_handle)
    }

    fn signals(&self, item: &DwWaitItemV1) -> u64 {
        let mut observed = 0;
        if self
            .inbound
            .get(&item.handle.0)
            .and_then(VecDeque::front)
            .is_some_and(|(ready_at, _, _)| *ready_at <= self.now)
        {
            observed |= DW_SIGNAL_READABLE.0;
        }
        if self.peer_closed.contains(&item.handle.0) {
            observed |= DW_SIGNAL_PEER_CLOSED.0;
        }
        if self.has_room(item.handle.0) {
            observed |= DW_SIGNAL_WRITABLE.0;
        }
        let children = self.children.borrow();
        if children.ready.contains_key(&item.handle.0) {
            observed |= DW_SIGNAL_READABLE.0;
        }
        if children.has_exited(item.handle.0) {
            observed |= DW_SIGNAL_EXITED.0;
        }
        observed & item.signals.0
    }

    fn answer_file(&mut self, channel: u64, request: &[u8]) {
        let server = &self.files[&channel];
        let FilePeer::Answers { after_ns } = server.peer else {
            return;
        };
        let message = node::parse(request, 0).expect("init sends well-formed WRFS");
        let body = match message.body {
            node::Body::GetAttr => node::Body::Attr(node::Attr {
                kind: node::Kind::File,
                access: node::ACCESS_READ,
                size: server.data.len() as u64,
                id: 1,
                filesystem: 1,
            }),
            node::Body::Read { offset, length } => {
                let start = offset as usize;
                let end = (start + length as usize).min(server.data.len());
                node::Body::Data(&server.data[start..end])
            }
            other => panic!("unexpected WRFS request {other:?}"),
        };
        let mut reply = vec![0; node::MAX_BYTES];
        let size = node::encode(
            &node::Message {
                transaction_id: message.transaction_id,
                body,
            },
            &mut reply,
        )
        .unwrap();
        reply.truncate(size);
        let ready_at = self.now + after_ns;
        self.inbound
            .entry(channel)
            .or_default()
            .push_back((ready_at, reply, Vec::new()));
    }
}

/// A bootfs with a manifest, a launch policy and `bin/hello`.
fn bootfs() -> Vec<u8> {
    let hello = executable();
    let mut policy = [0u8; 512];
    let size = wyrmroot_bootfs::launch_policy::encode(
        [0x42; 32],
        &[LaunchPolicyEntry {
            path: "bin/hello",
            content_sha256: wyrmroot_runtime::sha256::digest(&hello),
            startup_abi: 2,
            profile_id: JOB_V2_PROFILE_ID,
            allow_no_streams: true,
            allow_three_streams: true,
        }],
        &mut policy,
    )
    .unwrap();
    let mut manifest = [0u8; 80];
    manifest[48..80].fill(0x42);
    let mut builder = Builder::new();
    builder
        .add(b"bin/hello", &hello, FileMode::Executable)
        .unwrap();
    builder
        .add(
            LAUNCH_POLICY_PATH.as_bytes(),
            &policy[..size],
            FileMode::ReadOnly,
        )
        .unwrap();
    builder
        .add(MANIFEST_PATH.as_bytes(), &manifest, FileMode::ReadOnly)
        .unwrap();
    builder.build().unwrap()
}

impl InitPlatform for FakeKernel {
    fn query_capability_info(
        &mut self,
        _handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
        Ok(CapabilityInfo {
            object_type: DW_OBJECT_TYPE_CHANNEL,
            rights: CONTROLLER_CHANNEL_RIGHTS,
        })
    }
    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        if let Some(status) = self.fail_receive.get(&channel.0) {
            return Err(NativeError::Status(*status));
        }
        let queue = self.inbound.get_mut(&channel.0).ok_or(REFUSED)?;
        let (ready_at, message, moved) = queue.front().ok_or(REFUSED)?;
        if *ready_at > self.now {
            return Err(NativeError::Status(DW_STATUS_WOULD_BLOCK));
        }
        // A message that does not fit the receiver's buffers is refused and
        // stays queued.
        if message.len() > bytes.len() || moved.len() > handles.len() {
            return Err(NativeError::Status(DW_STATUS_BUFFER_TOO_SMALL));
        }
        let (_, message, moved) = queue.pop_front().unwrap();
        bytes[..message.len()].copy_from_slice(&message);
        for (slot, handle) in handles.iter_mut().zip(&moved) {
            slot.handle = DwHandle(*handle);
        }
        Ok(ReceiveCounts {
            bytes: message.len(),
            handles: moved.len(),
        })
    }
    fn query_memory_object_size(&mut self, handle: DwHandle) -> Result<u64, NativeError> {
        self.memory
            .get(&handle.0)
            .map(|bytes| bytes.len() as u64)
            .ok_or(REFUSED)
    }
    fn with_bootfs_bytes<R>(
        &mut self,
        _root: DwHandle,
        memory: DwHandle,
        plan: MappingPlan,
        use_bytes: impl for<'a> FnOnce(&mut Self, &'a [u8]) -> R,
    ) -> Result<R, NativeError> {
        let bytes = self.memory.get(&memory.0).cloned().ok_or(REFUSED)?;
        Ok(use_bytes(self, &bytes[..plan.logical_size() as usize]))
    }
    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
        assert!(!self.is_closed(channel.0), "send on closed {channel:?}");
        if self.peer_closed.contains(&channel.0) {
            return Err(NativeError::Status(DW_STATUS_PEER_CLOSED));
        }
        if self.files.contains_key(&channel.0) {
            if self.full.contains(&channel.0) {
                return Err(NativeError::Status(DW_STATUS_WOULD_BLOCK));
            }
            self.sent.push((channel.0, bytes.to_vec()));
            self.answer_file(channel.0, bytes);
            return Ok(());
        }
        if !self.has_room(channel.0) {
            return Err(NativeError::Status(DW_STATUS_WOULD_BLOCK));
        }
        *self.unread.entry(channel.0).or_default() += 1;
        self.sent.push((channel.0, bytes.to_vec()));
        Ok(())
    }
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        assert!(!self.is_closed(handle.0), "double close of {handle:?}");
        if self.fail_close.contains(&handle.0) {
            return Err(REFUSED);
        }
        self.closed.push(handle.0);
        // Closing a Channel end drops what was queued on it, handles and all.
        self.inbound.remove(&handle.0);
        self.memory.remove(&handle.0);
        Ok(())
    }
    fn create_attempt_task_group(&mut self, _parent: DwHandle) -> Result<DwHandle, NativeError> {
        Ok(self.fresh())
    }
    fn limit_job_task_group(&mut self, _task_group: DwHandle) -> Result<(), NativeError> {
        Ok(())
    }
    fn terminate_task_group(&mut self, task_group: DwHandle) -> Result<(), NativeError> {
        self.children.borrow_mut().terminated.insert(task_group.0);
        Ok(())
    }
    fn now(&mut self) -> Result<u64, NativeError> {
        if self.clock_stops_at.is_some_and(|stop| self.now >= stop) {
            return Err(REFUSED);
        }
        let now = self.now;
        let (due, later): (Vec<_>, Vec<_>) = core::mem::take(&mut self.schedule)
            .into_iter()
            .partition(|(at, _)| *at <= now);
        self.schedule = later;
        for (_, mut event) in due {
            event(self);
        }
        Ok(self.now)
    }
    fn wait_until(&mut self, deadline_ns: u64) -> Result<(), NativeError> {
        self.now = self.now.max(deadline_ns);
        Ok(())
    }
}

impl ResidentPlatform for FakeKernel {
    fn channel_create(&mut self, _rights: DwRights) -> Result<(DwHandle, DwHandle), NativeError> {
        Ok((self.fresh(), self.fresh()))
    }
    fn send_channel_with_handles(
        &mut self,
        channel: DwHandle,
        bytes: &[u8],
        _transfers: &[DwHandleTransferV1],
    ) -> Result<(), NativeError> {
        self.sent.push((channel.0, bytes.to_vec()));
        Ok(())
    }
    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, NativeError> {
        loop {
            for (index, item) in items.iter().enumerate() {
                let observed = self.signals(item);
                if observed != 0 {
                    return Ok(DwWaitResultV1 {
                        index: index as u32,
                        observed: deepwyrm_syscall::DwSignals(observed),
                        ..DwWaitResultV1::default()
                    });
                }
            }
            // Nothing is ready: sleep to whichever comes first, the next
            // message for one of these handles or the deadline.
            let next = items
                .iter()
                .filter_map(|item| self.inbound.get(&item.handle.0)?.front())
                .map(|(ready_at, _, _)| *ready_at)
                .filter(|ready_at| *ready_at > self.now && *ready_at <= deadline.0)
                .min();
            match next {
                Some(ready_at) => self.now = ready_at,
                None => {
                    self.now = self.now.max(deadline.0);
                    return Err(NativeError::Status(DW_STATUS_TIMED_OUT));
                }
            }
        }
    }
    fn materialize_read_only_memory(
        &mut self,
        _root: DwHandle,
        bytes: &[u8],
        _rights: DwRights,
    ) -> Result<DwHandle, NativeError> {
        let handle = self.fresh();
        self.memory.insert(handle.0, Rc::new(bytes.to_vec()));
        Ok(handle)
    }
    fn with_private_memory<R>(
        &mut self,
        _root: DwHandle,
        bytes: u64,
        use_bytes: impl for<'a> FnOnce(&mut Self, &'a mut [u8]) -> R,
    ) -> Result<R, NativeError> {
        if self.fail_scratch {
            return Err(NativeError::Status(deepwyrm_syscall::DW_STATUS_NO_MEMORY));
        }
        self.scratch_mapped += 1;
        let mut scratch = vec![0; bytes as usize];
        let result = use_bytes(self, &mut scratch);
        self.scratch_unmapped += 1;
        Ok(result)
    }
}

/// Supervision waits over the same children the kernel sees.
pub(crate) struct ChildWaits(pub(crate) SharedChildren);

impl SupervisionPlatform for ChildWaits {
    type Error = NativeError;

    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        _deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, Self::Error> {
        let children = self.0.borrow();
        for (index, item) in items.iter().enumerate() {
            let observed =
                if item.signals.0 & DW_SIGNAL_EXITED.0 != 0 && children.has_exited(item.handle.0) {
                    DW_SIGNAL_EXITED
                } else if item.signals.0 & DW_SIGNAL_READABLE.0 != 0
                    && children.ready.contains_key(&item.handle.0)
                {
                    DW_SIGNAL_READABLE
                } else {
                    continue;
                };
            return Ok(DwWaitResultV1 {
                index: index as u32,
                observed,
                ..DwWaitResultV1::default()
            });
        }
        Err(NativeError::Status(DW_STATUS_TIMED_OUT))
    }

    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        _handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, Self::Error> {
        let (profile, transaction) = self
            .0
            .borrow_mut()
            .ready
            .remove(&channel.0)
            .ok_or(REFUSED)?;
        let size = encode_ready_for_profile(profile, transaction, bytes).unwrap();
        Ok(ReceiveCounts {
            bytes: size,
            handles: 0,
        })
    }

    fn query_task_termination(
        &mut self,
        process: DwHandle,
    ) -> Result<DwTaskTerminationInfoV1, Self::Error> {
        Ok(if self.0.borrow().has_exited(process.0) {
            DwTaskTerminationInfoV1 {
                size: deepwyrm_syscall::DW_TASK_TERMINATION_INFO_V1_SIZE,
                version: 1,
                state: DW_TASK_STATE_EXITED,
                reason: deepwyrm_syscall::DW_TERMINATION_NORMAL_EXIT,
                ..DwTaskTerminationInfoV1::default()
            }
        } else {
            DwTaskTerminationInfoV1 {
                state: deepwyrm_syscall::DW_TASK_STATE_RUNNING,
                ..DwTaskTerminationInfoV1::default()
            }
        })
    }
}

/// The launch session `id`'s grant; its Channel is `channel(id)`.
pub(crate) fn session(id: u64) -> EndpointGrant {
    EndpointGrant {
        registry_generation: 7,
        endpoint_id: id,
        endpoint_generation: 3,
        role_generation: 1,
        kind: EndpointKind::LaunchSession,
    }
}

pub(crate) fn channel(id: u64) -> DwHandle {
    DwHandle(90 + id)
}

pub(crate) fn reservation(id: u64, transaction_id: u64) -> LaunchReservation {
    LaunchReservation {
        connection_id: id,
        generation: 3,
        transaction_id,
    }
}

/// A LIST_JOBS request from session `id`.
pub(crate) fn list_jobs(id: u64, transaction_id: u64) -> Vec<u8> {
    let mut bytes = vec![0; wyrmroot_launch_proto::HEADER_BYTES];
    wyrmroot_launch_proto::encode(reservation(id, transaction_id), &mut bytes).unwrap();
    bytes[40..44].copy_from_slice(&(LaunchMessageType::ListJobs as u32).to_le_bytes());
    bytes
}

/// A dispatcher with shell-job sessions 1 and 2 installed.
pub(crate) fn two_sessions() -> JobDispatcher {
    let mut jobs = JobDispatcher::new();
    for id in [1, 2] {
        jobs.install_scoped_session(session(id), channel(id), LaunchSessionScope::ShellJobs)
            .unwrap();
    }
    jobs
}

/// A dispatcher, the kernel under it and the loader beside it.
pub(crate) struct Rig {
    pub(crate) kernel: FakeKernel,
    pub(crate) jobs: JobDispatcher,
    pub(crate) loader: InitSendLoader,
}

impl Rig {
    pub(crate) fn new(jobs: JobDispatcher) -> Self {
        let kernel = FakeKernel::new();
        let mut loader = InitSendLoader::new();
        loader.fail_init = false;
        loader.children = Some(kernel.children.clone());
        Self {
            kernel,
            jobs,
            loader,
        }
    }

    pub(crate) fn try_poll(&mut self) -> Result<JobDispatcherPoll, InitError> {
        let now = self.kernel.now;
        let mut waits = ChildWaits(self.kernel.children.clone());
        poll_job_dispatcher_inner(
            &mut self.kernel,
            &mut self.loader,
            &mut waits,
            AUTHORITY,
            &mut self.jobs,
            now,
            None,
        )
    }

    /// One poll, which a session client can never make fail.
    pub(crate) fn poll(&mut self) -> JobDispatcherPoll {
        self.try_poll()
            .expect("a session client's fault never fails the tick")
    }

    /// One poll, then the 25 ms to the next.
    fn tick(&mut self) -> JobDispatcherPoll {
        let poll = self.poll();
        self.kernel.now += crate::resident_loop::RESIDENT_TICK_NS;
        poll
    }

    /// The Process and launch Channel of the launch session `id` has parked.
    pub(crate) fn parked_child(&self, id: u64) -> (DwHandle, DwHandle) {
        let token = self
            .jobs
            .launches
            .session_transaction(session(id))
            .expect("a launch is parked");
        let resources = self.jobs.launches.resources(token).unwrap().unwrap();
        (resources.process, resources.launch_channel)
    }

    /// Session `id` sends LAUNCH of `bin/hello`; the child is constructed
    /// and parked for READY. Returns its Process.
    pub(crate) fn launch(&mut self, id: u64, transaction_id: u64) -> DwHandle {
        self.kernel
            .deliver(channel(id), &launch_hello(id, transaction_id), &[]);
        while self
            .jobs
            .launches
            .session_transaction(session(id))
            .is_none()
        {
            assert_eq!(self.tick(), JobDispatcherPoll::STABLE);
        }
        self.parked_child(id).0
    }

    /// The parked child of session `id` reports READY for `transaction_id`.
    pub(crate) fn make_ready(&mut self, id: u64, transaction_id: u64) {
        let (_, launch_channel) = self.parked_child(id);
        self.kernel
            .children
            .borrow_mut()
            .ready
            .insert(launch_channel.0, (LaunchProfile::JobV2, transaction_id));
    }

    /// Every reply session `id` has been sent, as `(type, job or code)`.
    pub(crate) fn replies(&self, id: u64) -> Vec<Reply> {
        self.kernel
            .sent_on(channel(id))
            .into_iter()
            .map(
                |bytes| match parse_launch_message(bytes, 0).unwrap().message {
                    LaunchMessage::LaunchAccepted { job_id } => Reply::Accepted(job_id),
                    LaunchMessage::JobList(ids) => Reply::JobList(ids.len()),
                    LaunchMessage::JobResult { job_id, .. } => Reply::Result(job_id),
                    LaunchMessage::Error { code } => Reply::Error(code),
                    other => panic!("unexpected reply {other:?}"),
                },
            )
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Reply {
    Accepted(u64),
    JobList(usize),
    Result(u64),
    Error(LaunchErrorCode),
}

/// A streamless LAUNCH of `bin/hello` from session `id`.
pub(crate) fn launch_hello(id: u64, transaction_id: u64) -> Vec<u8> {
    let mut launch = vec![0; wyrmroot_launch_proto::MAX_LAUNCH_MESSAGE_BYTES];
    let size = wyrmroot_launch_proto::encode_launch(
        reservation(id, transaction_id),
        "bin/hello",
        &["bin/hello"],
        &[],
        false,
        &mut launch,
    )
    .unwrap();
    launch.truncate(size);
    launch
}

/// A WAIT for `job_id` from session `id`.
fn wait_for(id: u64, transaction_id: u64, job_id: u64) -> Vec<u8> {
    let mut wait = vec![0; 56];
    let size = wyrmroot_launch_proto::encode_job_message(
        reservation(id, transaction_id),
        LaunchMessageType::Wait,
        job_id,
        &mut wait,
    )
    .unwrap();
    wait.truncate(size);
    wait
}

fn one_session() -> JobDispatcher {
    let mut jobs = JobDispatcher::new();
    jobs.install_scoped_session(session(1), channel(1), LaunchSessionScope::ShellJobs)
        .unwrap();
    jobs
}

fn shell_fault(id: u64, cause: FaultCause) -> SessionFault {
    SessionFault {
        grant: session(id),
        scope: LaunchSessionScope::ShellJobs,
        cause,
    }
}

/// Session 1 has just been retired for `cause`; session 2, polled next, is
/// still served.
fn assert_only_session_one_is_gone(rig: &mut Rig, poll: JobDispatcherPoll, cause: FaultCause) {
    assert_eq!(poll.fault, Some(shell_fault(1, cause)));
    assert_eq!(
        poll.outcome,
        JobDispatcherPollOutcome::SessionFaulted {
            grant: session(1),
            scope: LaunchSessionScope::ShellJobs,
            cause,
        }
    );
    assert_eq!(
        rig.jobs.session_handle(session(1)),
        Err(JobError::UnknownConnection)
    );
    assert!(
        rig.kernel.is_closed(channel(1).0),
        "the session Channel is closed"
    );
    assert_eq!(rig.jobs.session_handle(session(2)), Ok(channel(2)));
    rig.kernel.deliver(channel(2), &list_jobs(2, 1), &[]);
    assert_eq!(rig.poll(), JobDispatcherPoll::STABLE);
    assert_eq!(rig.replies(2), [Reply::JobList(0)]);
    // And the dispatcher goes on polling with one session fewer.
    assert_eq!(rig.poll(), JobDispatcherPoll::STABLE);
}

#[test]
fn only_what_a_peer_can_cause_is_blamed_on_the_peer() {
    use ChannelOperation::{Receive, Send};
    use deepwyrm_syscall::*;
    let status = |status: DwStatus| NativeError::Status(status);
    assert_eq!(
        peer_cause(Send, status(DW_STATUS_WOULD_BLOCK)),
        Some(PeerCause::QueueFull)
    );
    assert_eq!(
        peer_cause(Receive, status(DW_STATUS_BUFFER_TOO_SMALL)),
        Some(PeerCause::MessageTooLarge)
    );
    for operation in [Send, Receive] {
        assert_eq!(
            peer_cause(operation, status(DW_STATUS_PEER_CLOSED)),
            Some(PeerCause::Closed)
        );
        // Init's own handle, rights, arguments, memory and handle table; a
        // kernel that broke its ABI; a status no ABI defines.
        for init_s_own in [
            DW_STATUS_SUCCESS,
            DW_STATUS_INVALID_ARGUMENT,
            DW_STATUS_BAD_HANDLE,
            DW_STATUS_WRONG_OBJECT_TYPE,
            DW_STATUS_ACCESS_DENIED,
            DW_STATUS_BAD_STATE,
            DW_STATUS_NOT_FOUND,
            DW_STATUS_ALREADY_EXISTS,
            DW_STATUS_TIMED_OUT,
            DW_STATUS_INTERRUPTED,
            DW_STATUS_NO_MEMORY,
            DW_STATUS_NO_RESOURCES,
            DW_STATUS_NOT_SUPPORTED,
            DW_STATUS_BAD_ADDRESS,
            DwStatus(-17),
            DwStatus(7),
        ] {
            assert_eq!(
                peer_cause(operation, status(init_s_own)),
                None,
                "{init_s_own:?}"
            );
        }
        assert_eq!(
            peer_cause(
                operation,
                NativeError::Output(wyrmroot_runtime::NativeOutputError::InvalidChannelReceive)
            ),
            None
        );
    }
    // The two directional statuses, the wrong way round.
    assert_eq!(peer_cause(Receive, status(DW_STATUS_WOULD_BLOCK)), None);
    assert_eq!(peer_cause(Send, status(DW_STATUS_BUFFER_TOO_SMALL)), None);
}

#[test]
fn bytes_that_are_no_request_end_the_session_and_not_the_tick() {
    let mut rig = Rig::new(two_sessions());
    rig.kernel
        .deliver(channel(1), b"this is not a WRLJ request at all", &[41, 42]);
    let poll = rig.poll();
    assert!(rig.kernel.is_closed(41) && rig.kernel.is_closed(42));
    assert!(rig.replies(1).is_empty());
    assert_only_session_one_is_gone(&mut rig, poll, FaultCause::UnparseablePrefix);
}

#[test]
fn an_empty_message_ends_the_session_and_not_the_tick() {
    let mut rig = Rig::new(two_sessions());
    rig.kernel.deliver(channel(1), &[], &[]);
    let poll = rig.poll();
    assert_only_session_one_is_gone(&mut rig, poll, FaultCause::UnparseablePrefix);
}

/// 9.1: any other handle count is malformed. 9.5: that is `ERROR` code 1,
/// to a session that is still there.
#[test]
fn a_wrong_handle_count_on_a_parseable_request_is_answered_as_malformed() {
    let mut rig = Rig::new(one_session());
    let mut launch = vec![0; wyrmroot_launch_proto::MAX_LAUNCH_MESSAGE_BYTES];
    let size = wyrmroot_launch_proto::encode_launch(
        reservation(1, 1),
        "bin/hello",
        &["bin/hello"],
        &[],
        true,
        &mut launch,
    )
    .unwrap();
    // A LAUNCH moves three streams; this one moves four handles.
    rig.kernel
        .deliver(channel(1), &launch[..size], &[41, 42, 43, 44]);
    assert_eq!(rig.poll(), JobDispatcherPoll::STABLE);
    // A LIST_JOBS moves none; this one moves one.
    rig.kernel.drain(channel(1));
    rig.kernel.deliver(channel(1), &list_jobs(1, 2), &[45]);
    assert_eq!(rig.poll(), JobDispatcherPoll::STABLE);
    assert_eq!(
        rig.replies(1),
        [Reply::Error(LaunchErrorCode::MalformedRequest); 2]
    );
    for handle in 41..=45 {
        assert!(
            rig.kernel.is_closed(handle),
            "received handle {handle} closed"
        );
    }
    assert_eq!(rig.jobs.jobs.live_jobs(), 0);
    assert_eq!(rig.jobs.session_handle(session(1)), Ok(channel(1)));
}

#[test]
fn more_handles_than_any_request_carries_end_the_session_and_not_the_tick() {
    let mut rig = Rig::new(two_sessions());
    let handles: Vec<u64> = (41..=41 + wyrmroot_launch_proto::MAX_REQUEST_HANDLES as u64).collect();
    // One handle more than init's receive can take: the kernel refuses the
    // receive and the message stays queued, readable on every later poll.
    rig.kernel.deliver(channel(1), &list_jobs(1, 1), &handles);
    let poll = rig.poll();
    // The message was never received. It goes with the Channel.
    assert!(!rig.kernel.inbound.contains_key(&channel(1).0));
    assert_only_session_one_is_gone(&mut rig, poll, FaultCause::RequestTooLarge);
}

/// What stays fatal: a receive the kernel refuses for init's own reasons --
/// here its handle table -- is no session's fault, and no session is
/// retired for it.
#[test]
fn a_receive_refused_for_init_s_own_reasons_is_init_s_failure() {
    for status in [
        deepwyrm_syscall::DW_STATUS_NO_RESOURCES,
        deepwyrm_syscall::DW_STATUS_NO_MEMORY,
        deepwyrm_syscall::DW_STATUS_BAD_HANDLE,
    ] {
        let mut rig = Rig::new(two_sessions());
        rig.kernel.fail_receive.insert(channel(1).0, status);
        rig.kernel.deliver(channel(1), &list_jobs(1, 1), &[]);
        let failed = rig.try_poll().unwrap_err();
        assert_eq!(failure_kind(&failed), 0x05, "{status:?}");
        assert_eq!(
            failure_instance(&failed),
            wyrmroot_runtime::native_error_code(NativeError::Status(status)) as u16
        );
    }
}

#[test]
fn a_peer_that_closes_mid_request_ends_the_session_and_its_handles_are_closed() {
    let mut rig = Rig::new(two_sessions());
    let mut launch = vec![0; wyrmroot_launch_proto::MAX_LAUNCH_MESSAGE_BYTES];
    let size = wyrmroot_launch_proto::encode_launch(
        reservation(1, 1),
        "system/init",
        &["system/init"],
        &[],
        true,
        &mut launch,
    )
    .unwrap();
    // The request and its three streams are queued, and the client is gone
    // before it can be answered. Readable work is drained first (9.5), so
    // the request is dispatched and its refusal has nowhere to go.
    rig.kernel
        .deliver(channel(1), &launch[..size], &[41, 42, 43]);
    rig.kernel.peer_closed.insert(channel(1).0);
    let poll = rig.poll();
    for handle in 41..=43 {
        assert!(
            rig.kernel.is_closed(handle),
            "received handle {handle} closed"
        );
    }
    assert_eq!(rig.jobs.jobs.live_jobs(), 0);
    assert_only_session_one_is_gone(
        &mut rig,
        poll,
        FaultCause::ReplyUndeliverable(DW_STATUS_PEER_CLOSED),
    );
}

/// Init can owe one session three replies at once and its queue holds two.
/// A client that reads its replies is never retired for init's own burst.
#[test]
fn a_full_reply_queue_is_backpressure_for_a_client_that_drains() {
    let mut rig = Rig::new(one_session());
    // Job 1 is launched and accepted; a WAIT for it is pending.
    let first = rig.launch(1, 1);
    rig.make_ready(1, 1);
    rig.tick();
    assert_eq!(rig.replies(1), [Reply::Accepted(1)]);
    rig.kernel.drain(channel(1));
    rig.kernel.deliver(channel(1), &wait_for(1, 2, 1), &[]);
    rig.tick();
    // Job 2 is launched and parked for READY.
    rig.launch(1, 3);
    // One tick: job 2 reports READY and a LIST_JOBS arrives. Two replies,
    // which is all the queue holds, and the client has not read them yet.
    rig.make_ready(1, 3);
    rig.kernel.deliver(channel(1), &list_jobs(1, 4), &[]);
    assert_eq!(rig.tick(), JobDispatcherPoll::STABLE);
    assert_eq!(
        rig.replies(1),
        [Reply::Accepted(1), Reply::Accepted(2), Reply::JobList(2)]
    );
    // The next: job 1 exits, so its WAIT is owed a third reply, and another
    // LIST_JOBS arrives and is owed a fourth. Neither fits. Neither is
    // sent, neither is lost, and the client is not retired.
    rig.kernel.children.borrow_mut().exited.insert(first.0);
    rig.kernel.deliver(channel(1), &list_jobs(1, 5), &[]);
    for _ in 0..4 {
        assert_eq!(rig.tick(), JobDispatcherPoll::STABLE);
    }
    assert_eq!(rig.replies(1).len(), 3);
    assert_eq!(rig.jobs.session_handle(session(1)), Ok(channel(1)));
    // The client reads. Everything it was owed arrives.
    rig.kernel.drain(channel(1));
    for _ in 0..4 {
        assert_eq!(rig.tick(), JobDispatcherPoll::STABLE);
    }
    let mut late = rig.replies(1)[3..].to_vec();
    late.sort_by_key(|reply| matches!(reply, Reply::Result(_)));
    // The list is the one taken when it was asked for, job 1 still in it.
    assert_eq!(late, [Reply::JobList(2), Reply::Result(1)]);
    // And it is read from again.
    rig.kernel.drain(channel(1));
    rig.kernel.deliver(channel(1), &list_jobs(1, 6), &[]);
    rig.tick();
    assert_eq!(rig.replies(1).last(), Some(&Reply::JobList(1)));
}

/// The longest reply the protocol admits -- a `JOB_LIST` of every job the
/// table holds -- meeting a full queue is held whole and delivered later.
#[test]
fn the_largest_reply_meeting_a_full_queue_is_held_and_delivered() {
    let mut rig = Rig::new(one_session());
    let jobs = wyrmroot_launch_proto::MAX_LIVE_JOBS as u64;
    for job in 1..=jobs {
        let request = rig.jobs.jobs.reserve_request(reservation(1, job)).unwrap();
        let ticket = rig.jobs.jobs.begin_reserved_launch(request, false).unwrap();
        rig.jobs
            .jobs
            .commit_launch(ticket, 0x2000 + job, 0x3000 + job, 0x4000 + job)
            .unwrap();
    }
    rig.kernel.full.insert(channel(1).0);
    rig.kernel.deliver(channel(1), &list_jobs(1, 100), &[]);
    for _ in 0..3 {
        assert_eq!(rig.tick(), JobDispatcherPoll::STABLE);
    }
    assert!(rig.replies(1).is_empty());
    assert_eq!(rig.jobs.session_handle(session(1)), Ok(channel(1)));
    // The client makes room.
    rig.kernel.full.remove(&channel(1).0);
    assert_eq!(rig.tick(), JobDispatcherPoll::STABLE);
    let sent = rig.kernel.sent_on(channel(1));
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].len(), JOB_LIST_REPLY_BYTES);
    assert_eq!(sent[0].len(), MAX_REPLY_BYTES);
    let parsed = parse_launch_message(sent[0], 0).unwrap();
    assert_eq!(parsed.reservation, reservation(1, 100));
    match parsed.message {
        LaunchMessage::JobList(ids) => {
            assert_eq!(ids.len(), jobs as usize);
            for (index, expected) in (1..=jobs).enumerate() {
                assert_eq!(ids.get(index), Some(expected));
            }
        }
        other => panic!("unexpected reply {other:?}"),
    }
}

/// The other side of backpressure: a client that never reads is retired
/// when its patience runs out, and not a tick before.
#[test]
fn a_reply_queue_that_never_drains_ends_the_session_at_its_deadline() {
    let mut rig = Rig::new(two_sessions());
    rig.kernel.full.insert(channel(1).0);
    rig.kernel.deliver(channel(1), &list_jobs(1, 1), &[41]);
    let started = rig.kernel.now;
    let mut retired = None;
    while retired.is_none() {
        assert!(
            rig.kernel.now
                <= started + REPLY_PATIENCE_NS + 4 * crate::resident_loop::RESIDENT_TICK_NS,
            "the session is retired once its patience is spent"
        );
        let poll = rig.tick();
        if poll.fault.is_some() {
            retired = Some(poll);
        } else {
            assert_eq!(poll, JobDispatcherPoll::STABLE);
            assert_eq!(rig.jobs.session_handle(session(1)), Ok(channel(1)));
        }
    }
    assert!(rig.kernel.now >= started + REPLY_PATIENCE_NS);
    assert!(rig.kernel.is_closed(41));
    assert!(rig.replies(1).is_empty());
    assert_only_session_one_is_gone(
        &mut rig,
        retired.unwrap(),
        FaultCause::ReplyQueueNeverDrained,
    );
}

/// A launch whose child is READY while its session's queue is full stays
/// parked; the session that never makes room loses it, rolled back.
#[test]
fn a_deferred_launch_reply_waits_for_room_and_then_costs_the_session() {
    let mut rig = Rig::new(two_sessions());
    let child = rig.launch(1, 1);
    rig.kernel.full.insert(channel(1).0);
    rig.make_ready(1, 1);
    let started = rig.kernel.now;
    let retired = loop {
        let poll = rig.tick();
        if poll.fault.is_some() {
            break poll;
        }
        assert_eq!(poll, JobDispatcherPoll::STABLE);
        // Still parked, still unpublished, still alive.
        assert_eq!(rig.parked_child(1).0, child);
        assert!(!rig.kernel.children.borrow().has_exited(child.0));
    };
    assert!(rig.kernel.now >= started + REPLY_PATIENCE_NS);
    assert!(rig.replies(1).is_empty());
    // The child nobody was told about is ended and reaped.
    assert!(rig.kernel.children.borrow().has_exited(child.0));
    assert!(rig.kernel.is_closed(child.0));
    assert_eq!(rig.jobs.jobs.live_jobs(), 0);
    assert_eq!(rig.jobs.launches.open_count(), 0);
    assert_only_session_one_is_gone(&mut rig, retired, FaultCause::ReplyQueueNeverDrained);
}

/// A pending WAIT whose client has gone is answered to no one: the session
/// is retired for it, and the tick goes on.
#[test]
fn a_wait_result_for_a_closed_peer_ends_the_session_and_not_the_tick() {
    let mut rig = Rig::new(two_sessions());
    let child = rig.launch(1, 1);
    rig.make_ready(1, 1);
    rig.tick();
    rig.kernel.drain(channel(1));
    rig.kernel.deliver(channel(1), &wait_for(1, 2, 1), &[]);
    while rig.jobs.pending_waits.iter().flatten().count() == 0 {
        rig.tick();
    }
    // Session 2's turn is next, so session 1's closed peer is found by the
    // WAIT's result and not by its own poll.
    if rig.jobs.poll_cursor == 0 {
        rig.tick();
    }
    rig.kernel.children.borrow_mut().exited.insert(child.0);
    rig.kernel.peer_closed.insert(channel(1).0);
    let poll = rig.tick();
    assert_eq!(rig.jobs.jobs.live_jobs(), 0, "the job was reaped");
    assert_eq!(rig.replies(1), [Reply::Accepted(1)]);
    assert_only_session_one_is_gone(
        &mut rig,
        poll,
        FaultCause::ReplyUndeliverable(DW_STATUS_PEER_CLOSED),
    );
}

/// A second LAUNCH while the first awaits READY is `ERROR` code 5 (9.5):
/// its child is rolled back, the first launch is untouched, and it was
/// never init's failure.
#[test]
fn a_second_launch_while_one_awaits_ready_is_refused_and_rolled_back() {
    let mut rig = Rig::new(one_session());
    let first = rig.launch(1, 1);
    rig.kernel.deliver(channel(1), &launch_hello(1, 2), &[]);
    assert_eq!(rig.tick(), JobDispatcherPoll::STABLE);
    assert_eq!(
        rig.replies(1),
        [Reply::Error(LaunchErrorCode::InvalidState)]
    );
    // The first is still parked; the second's child is gone.
    assert_eq!(rig.parked_child(1).0, first);
    assert_eq!(rig.jobs.jobs.live_jobs(), 1);
    assert_eq!(rig.jobs.launches.open_count(), 1);
    assert!(!rig.kernel.children.borrow().has_exited(first.0));
    assert_eq!(rig.kernel.children.borrow().terminated.len(), 1);
    // And the first still publishes.
    rig.kernel.drain(channel(1));
    rig.make_ready(1, 1);
    assert_eq!(rig.tick(), JobDispatcherPoll::STABLE);
    assert_eq!(rig.replies(1).last(), Some(&Reply::Accepted(1)));
}

fn launch_image_request(id: u64) -> Vec<u8> {
    let path = "boot/HELLO.ELF";
    let mut launch = vec![0; wyrmroot_launch_proto::MAX_LAUNCH_MESSAGE_BYTES];
    let size = wyrmroot_launch_proto::encode_launch_image(
        reservation(id, 1),
        path,
        &[path],
        &[],
        &mut launch,
    )
    .unwrap();
    launch.truncate(size);
    launch
}

#[test]
fn a_second_launch_image_while_one_is_read_is_refused_as_capacity() {
    let mut rig = Rig::new(two_sessions());
    for (id, first) in [(1, 41), (2, 51)] {
        rig.kernel
            .serve_file(DwHandle(first + 3), executable(), FilePeer::Silent);
        let handles: Vec<u64> = (first..first + 5).collect();
        rig.kernel
            .deliver(channel(id), &launch_image_request(id), &handles);
        assert_eq!(rig.poll(), JobDispatcherPoll::STABLE);
    }
    // Session 1's read is parked and holds its handles.
    assert!(rig.jobs.image.is_some());
    assert!((41..46).all(|handle| !rig.kernel.is_closed(handle)));
    // Session 2 was told there is no room, with its handles closed.
    assert!((51..56).all(|handle| rig.kernel.is_closed(handle)));
    assert_eq!(rig.replies(2), [Reply::Error(LaunchErrorCode::Capacity)]);
    assert_eq!(rig.jobs.session_handle(session(2)), Ok(channel(2)));
}

#[test]
fn a_session_that_closes_takes_its_parked_image_read_with_it() {
    let mut rig = Rig::new(two_sessions());
    rig.kernel
        .serve_file(DwHandle(44), executable(), FilePeer::Silent);
    rig.kernel
        .deliver(channel(1), &launch_image_request(1), &[41, 42, 43, 44, 45]);
    assert_eq!(rig.poll(), JobDispatcherPoll::STABLE);
    let parked_request = rig.jobs.image.expect("the read is parked").request_handle();
    rig.kernel.peer_closed.insert(channel(1).0);
    // Session 2's turn, then session 1's.
    assert_eq!(rig.poll(), JobDispatcherPoll::STABLE);
    let poll = rig.poll();
    assert_eq!(
        poll.outcome,
        JobDispatcherPollOutcome::SessionClosed {
            grant: session(1),
            scope: LaunchSessionScope::ShellJobs,
        }
    );
    assert_eq!(poll.fault, None);
    assert!(rig.jobs.image.is_none());
    assert!((41..46).all(|handle| rig.kernel.is_closed(handle)));
    assert!(rig.kernel.is_closed(parked_request.0));
    assert!(rig.kernel.is_closed(channel(1).0));
}

/// A poll that retires the console launcher cleanly and a shell for its
/// fault reports both: the console's retirement is what the caller
/// reconciles, and the fault is not lost behind it.
#[test]
fn a_console_close_does_not_hide_a_shell_fault_in_the_same_poll() {
    let console = session(7);
    let mut jobs = two_sessions();
    jobs.install_scoped_session(console, channel(7), LaunchSessionScope::ConsoleLauncher)
        .unwrap();
    let mut rig = Rig::new(jobs);
    // Sessions 1 and 2 have their turns; the console launcher's is next.
    assert_eq!(rig.poll(), JobDispatcherPoll::STABLE);
    assert_eq!(rig.poll(), JobDispatcherPoll::STABLE);
    // The image read retired session 2 since the last poll, and the console
    // launcher's peer has closed: one poll finds both.
    let between_polls = shell_fault(2, FaultCause::ReplyQueueNeverDrained);
    rig.jobs.image_fault = Some(between_polls);
    rig.kernel.peer_closed.insert(channel(7).0);
    let closed = JobDispatcherPollOutcome::SessionClosed {
        grant: console,
        scope: LaunchSessionScope::ConsoleLauncher,
    };
    assert_eq!(
        rig.poll(),
        JobDispatcherPoll {
            outcome: closed,
            fault: Some(between_polls),
        }
    );
    // Whichever order they come in, neither displaces the other.
    for (first_is_fault, _) in [(true, ()), (false, ())] {
        let mut poll = JobDispatcherPoll::STABLE;
        if first_is_fault {
            poll.faulted(between_polls);
            poll.closed(console, LaunchSessionScope::ConsoleLauncher);
        } else {
            poll.closed(console, LaunchSessionScope::ConsoleLauncher);
            poll.faulted(between_polls);
        }
        assert_eq!(poll.outcome, closed);
        assert_eq!(poll.fault, Some(between_polls));
    }
}

/// What stays fatal: a received handle init could not close is a handle
/// nothing can name any more, whoever sent it.
#[test]
fn a_received_handle_that_cannot_be_closed_is_still_init_s_failure() {
    let mut rig = Rig::new(two_sessions());
    rig.kernel.fail_close.insert(41);
    rig.kernel.deliver(channel(1), b"not a request", &[41]);
    let failed = rig.try_poll().unwrap_err();
    assert_eq!(failure_kind(&failed), 0x04);
}
