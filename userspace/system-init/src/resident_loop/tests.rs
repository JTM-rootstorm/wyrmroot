//! The resident loop with a file image being read: the read never holds a
//! tick back, whatever is at the other end of the file Channel.

extern crate std;

use super::*;
use crate::image_launch::{
    IMAGE_READ_TIMEOUT_NS, fail_parked_image, service_image_launch as service,
};
use crate::job_dispatch::isolation_tests::{
    AUTHORITY, ChildWaits, FakeKernel, FilePeer, InitSendLoader, Rig, channel, executable,
    list_jobs, reservation, session, two_sessions,
};
use crate::job_sessions::JobDispatcher;
use std::boxed::Box;
use std::vec;
use std::vec::Vec;
use wyrmroot_launch_proto::{ErrorCode, Message, parse_message};

/// The handles session 1's LAUNCH_IMAGE moves: three streams, the file, the
/// namespace.
const STREAMS: [u64; 3] = [41, 42, 43];
const FILE: DwHandle = DwHandle(44);
const NAMESPACE: u64 = 45;

/// What a test does to the kernel at the start of one tick.
type Step = Box<dyn FnMut(&mut FakeKernel)>;

/// Whether the loop should end, asked after tick N.
type Done = Box<dyn Fn(&Dispatcher, usize) -> bool>;

/// The job dispatcher driven as the product drives it, and nothing else of
/// the supervisor: the loop under test is the real one.
struct Dispatcher {
    jobs: JobDispatcher,
    loader: InitSendLoader,
    /// When each tick ran.
    ticks: Vec<u64>,
    /// What to do at the start of tick N.
    script: Vec<(usize, Step)>,
    /// Ends the loop: the session is "complete" once this says so.
    done: Done,
    complete: bool,
}

impl Dispatcher {
    fn new(done: impl Fn(&Dispatcher, usize) -> bool + 'static) -> Self {
        let mut loader = InitSendLoader::new();
        loader.fail_init = false;
        Self {
            jobs: two_sessions(),
            loader,
            ticks: Vec::new(),
            script: Vec::new(),
            done: Box::new(done),
            complete: false,
        }
    }

    fn at(mut self, tick: usize, step: impl FnMut(&mut FakeKernel) + 'static) -> Self {
        self.script.push((tick, Box::new(step)));
        self
    }

    /// The longest the loop went without ticking.
    fn longest_gap(&self) -> u64 {
        self.ticks
            .windows(2)
            .map(|pair| pair[1] - pair[0])
            .max()
            .unwrap_or(0)
    }
}

impl ResidentTicks<FakeKernel> for Dispatcher {
    fn tick(&mut self, system: &mut FakeKernel, now_ns: u64) -> Result<(), u32> {
        let index = self.ticks.len();
        self.ticks.push(now_ns);
        for (at, step) in &mut self.script {
            if *at == index {
                step(system);
            }
        }
        poll_job_dispatcher_inner(
            system,
            &mut self.loader,
            &mut ChildWaits(system.children.clone()),
            AUTHORITY,
            &mut self.jobs,
            now_ns,
            None,
        )
        .map_err(|_| 0xdead_0001_u32)?;
        self.complete = (self.done)(self, index);
        Ok(())
    }

    fn session_complete(&self) -> bool {
        self.complete
    }

    fn service_image(
        &mut self,
        system: &mut FakeKernel,
        now_ns: u64,
        scratch: Option<&mut [u8]>,
    ) -> Result<ImageService, u32> {
        service(
            system,
            &mut self.loader,
            &mut ChildWaits(system.children.clone()),
            AUTHORITY,
            &mut self.jobs,
            now_ns,
            scratch,
        )
        .map_err(|_| 0xdead_0002)
    }

    fn refuse_image_scratch(
        &mut self,
        system: &mut FakeKernel,
        error: NativeError,
    ) -> Result<(), u32> {
        let now_ns = system.now;
        fail_parked_image(
            system,
            &mut ChildWaits(system.children.clone()),
            &mut self.jobs,
            native_launch_error_code(error),
            now_ns,
        )
        .map_err(|_| 0xdead_0003)
    }

    fn scratch_root(&self) -> DwHandle {
        AUTHORITY.parent_root
    }
}

/// A three-chunk executable whose one loaded segment lies in the second
/// 8 KiB chunk, so only a correctly assembled image loads it.
fn image() -> Vec<u8> {
    let mut image = executable();
    image.resize(0x4800, 0);
    image[72..80].copy_from_slice(&0x3000_u64.to_le_bytes());
    image[0x3000..0x3010].copy_from_slice(b"second chunk seg");
    image
}

/// Session 1 asks for `FILE` to be launched.
fn launch_image(kernel: &mut FakeKernel) {
    let path = "boot/EFI/WYRMROOT/HELLO.ELF";
    let mut launch = vec![0; wyrmroot_launch_proto::MAX_LAUNCH_MESSAGE_BYTES];
    let size = wyrmroot_launch_proto::encode_launch_image(
        reservation(1, 1),
        path,
        &["/boot/EFI/WYRMROOT/HELLO.ELF", "argument"],
        &["HOME=/"],
        &mut launch,
    )
    .unwrap();
    kernel.deliver(
        channel(1),
        &launch[..size],
        &[STREAMS[0], STREAMS[1], STREAMS[2], FILE.0, NAMESPACE],
    );
}

fn error_code(reply: &[u8]) -> ErrorCode {
    match parse_message(reply, 0).unwrap().message {
        Message::Error { code } => code,
        other => panic!("unexpected reply {other:?}"),
    }
}

/// The launch reached the point a bootfs launch reaches: the child is
/// constructed from the file's bytes and parked for READY.
fn assert_constructed_from(resident: &Dispatcher, kernel: &FakeKernel, image: &[u8]) {
    assert!(resident.jobs.image.is_none());
    assert!(
        resident
            .jobs
            .launches
            .session_transaction(session(1))
            .is_some()
    );
    assert_eq!(resident.jobs.jobs.live_jobs(), 1);
    assert_eq!(
        resident.loader.materialized,
        [image[0x3000..0x3010].to_vec()],
        "the loader mapped the segment out of the bytes the file holds"
    );
    assert!(!resident.loader.sent_init.is_empty());
    assert!(kernel.is_closed(FILE.0), "the file Channel is closed");
    assert!(
        STREAMS.iter().all(|stream| !kernel.is_closed(*stream)) && !kernel.is_closed(NAMESPACE),
        "the streams and the namespace went to the job"
    );
    assert!(
        kernel.sent_on(channel(1)).is_empty(),
        "no reply before READY"
    );
    assert_eq!((kernel.scratch_mapped, kernel.scratch_unmapped), (1, 1));
}

#[test]
fn a_file_that_answers_is_launched() {
    let mut kernel = FakeKernel::new();
    kernel.serve_file(FILE, image(), FilePeer::Answers { after_ns: 0 });
    let mut resident = Dispatcher::new(|resident, _| {
        resident
            .jobs
            .launches
            .session_transaction(session(1))
            .is_some()
    })
    .at(0, launch_image);
    assert_eq!(run_resident(&mut resident, &mut kernel), 0);
    assert_constructed_from(&resident, &kernel, &image());
    assert!(resident.longest_gap() <= RESIDENT_TICK_NS);
}

#[test]
fn a_file_that_answers_slowly_is_read_across_many_ticks() {
    let mut kernel = FakeKernel::new();
    // Each of the four replies takes three and a half ticks to arrive.
    let slow = RESIDENT_TICK_NS * 7 / 2;
    kernel.serve_file(FILE, image(), FilePeer::Answers { after_ns: slow });
    let mut resident = Dispatcher::new(|resident, _| {
        resident
            .jobs
            .launches
            .session_transaction(session(1))
            .is_some()
    })
    .at(0, launch_image)
    // While the read is in flight, the other session is served as usual.
    .at(5, |kernel| {
        kernel.deliver(channel(2), &list_jobs(2, 1), &[])
    });
    assert_eq!(run_resident(&mut resident, &mut kernel), 0);
    assert_constructed_from(&resident, &kernel, &image());
    assert!(
        resident.ticks.len() > 12,
        "the read spanned {} ticks",
        resident.ticks.len()
    );
    assert!(
        resident.longest_gap() <= RESIDENT_TICK_NS,
        "no tick was held back: longest gap {}",
        resident.longest_gap()
    );
    let replies = kernel.sent_on(channel(2));
    assert_eq!(replies.len(), 1);
    assert!(matches!(
        parse_message(replies[0], 0).unwrap().message,
        Message::JobList(ids) if ids.is_empty()
    ));
}

#[test]
fn a_file_that_never_answers_costs_the_launch_and_not_one_tick() {
    let mut kernel = FakeKernel::new();
    kernel.serve_file(FILE, image(), FilePeer::Silent);
    let started = kernel.now;
    let ticks = (IMAGE_READ_TIMEOUT_NS / RESIDENT_TICK_NS) as usize + 8;
    let mut resident = Dispatcher::new(move |_, tick| tick == ticks)
        .at(0, launch_image)
        // Session 2 is polled every other tick; this request, sent in the
        // middle of the silence, is answered within two.
        .at(100, |kernel| {
            kernel.deliver(channel(2), &list_jobs(2, 1), &[])
        });
    assert_eq!(run_resident(&mut resident, &mut kernel), 0);
    // Supervision never paused: every tick ran on time for the whole ten
    // seconds the file said nothing.
    assert_eq!(resident.ticks.len(), ticks + 1);
    assert_eq!(resident.longest_gap(), RESIDENT_TICK_NS);
    let answered = kernel
        .sent
        .iter()
        .position(|(to, _)| *to == channel(2).0)
        .expect("session 2 was answered");
    let refused = kernel
        .sent
        .iter()
        .position(|(to, _)| *to == channel(1).0)
        .expect("session 1 was told its launch failed");
    assert!(answered < refused, "session 2 was served during the read");
    // The launch failed at its deadline, back to its client.
    let replies = kernel.sent_on(channel(1));
    assert_eq!(replies.len(), 1);
    assert_eq!(error_code(replies[0]), ErrorCode::LoaderFailure);
    let failed_at = resident
        .ticks
        .iter()
        .copied()
        .find(|tick| *tick >= started + IMAGE_READ_TIMEOUT_NS)
        .unwrap();
    assert!(failed_at - started < IMAGE_READ_TIMEOUT_NS + 2 * RESIDENT_TICK_NS);
    assert!(resident.jobs.image.is_none());
    assert_eq!(resident.jobs.jobs.live_jobs(), 0);
    for handle in [STREAMS[0], STREAMS[1], STREAMS[2], FILE.0, NAMESPACE] {
        assert!(kernel.is_closed(handle), "handle {handle} closed");
    }
    // The session itself is still there, and still served.
    assert_eq!(resident.jobs.session_handle(session(1)), Ok(channel(1)));
    assert_eq!(kernel.scratch_mapped, 0);
}

#[test]
fn a_file_that_stops_answering_mid_read_costs_the_launch_and_not_one_tick() {
    let mut kernel = FakeKernel::new();
    kernel.serve_file(FILE, image(), FilePeer::Answers { after_ns: 0 });
    let ticks = (IMAGE_READ_TIMEOUT_NS / RESIDENT_TICK_NS) as usize + 8;
    let mut resident = Dispatcher::new(move |_, tick| tick == ticks).at(0, launch_image);
    // GETATTR and the first READ are answered; then the file goes silent,
    // with the scratch region mapped and the loop running inside it.
    let mut answered = 0;
    let silent_after = 2;
    struct GoesSilent<'a> {
        inner: &'a mut Dispatcher,
        answered: &'a mut usize,
        silent_after: usize,
    }
    impl ResidentTicks<FakeKernel> for GoesSilent<'_> {
        fn tick(&mut self, system: &mut FakeKernel, now_ns: u64) -> Result<(), u32> {
            self.inner.tick(system, now_ns)
        }
        fn session_complete(&self) -> bool {
            self.inner.session_complete()
        }
        fn service_image(
            &mut self,
            system: &mut FakeKernel,
            now_ns: u64,
            scratch: Option<&mut [u8]>,
        ) -> Result<ImageService, u32> {
            let before = system.sent_on(FILE).len();
            let serviced = self.inner.service_image(system, now_ns, scratch);
            *self.answered += system.sent_on(FILE).len() - before;
            if *self.answered >= self.silent_after {
                system.serve_file(FILE, Vec::new(), FilePeer::Silent);
            }
            serviced
        }
        fn refuse_image_scratch(
            &mut self,
            system: &mut FakeKernel,
            error: NativeError,
        ) -> Result<(), u32> {
            self.inner.refuse_image_scratch(system, error)
        }
        fn scratch_root(&self) -> DwHandle {
            self.inner.scratch_root()
        }
    }
    let status = run_resident(
        &mut GoesSilent {
            inner: &mut resident,
            answered: &mut answered,
            silent_after,
        },
        &mut kernel,
    );
    assert_eq!(status, 0);
    assert_eq!(resident.ticks.len(), ticks + 1);
    assert_eq!(resident.longest_gap(), RESIDENT_TICK_NS);
    let replies = kernel.sent_on(channel(1));
    assert_eq!(replies.len(), 1);
    assert_eq!(error_code(replies[0]), ErrorCode::LoaderFailure);
    assert_eq!(resident.jobs.jobs.live_jobs(), 0);
    for handle in [STREAMS[0], STREAMS[1], STREAMS[2], FILE.0, NAMESPACE] {
        assert!(kernel.is_closed(handle), "handle {handle} closed");
    }
    // The region was mapped for the read and released when it failed.
    assert_eq!((kernel.scratch_mapped, kernel.scratch_unmapped), (1, 1));
}

#[test]
fn scratch_memory_that_cannot_be_mapped_costs_the_launch_and_not_init() {
    let mut kernel = FakeKernel::new();
    kernel.fail_scratch = true;
    kernel.serve_file(FILE, image(), FilePeer::Answers { after_ns: 0 });
    let mut resident = Dispatcher::new(|_, tick| tick == 6).at(0, launch_image);
    assert_eq!(run_resident(&mut resident, &mut kernel), 0);
    let replies = kernel.sent_on(channel(1));
    assert_eq!(replies.len(), 1);
    assert_eq!(error_code(replies[0]), ErrorCode::Capacity);
    assert!(resident.jobs.image.is_none());
    for handle in [STREAMS[0], STREAMS[1], STREAMS[2], FILE.0, NAMESPACE] {
        assert!(kernel.is_closed(handle), "handle {handle} closed");
    }
    assert_eq!(resident.jobs.session_handle(session(1)), Ok(channel(1)));
}

#[test]
fn a_client_that_will_not_hear_its_launch_failed_loses_its_session_only() {
    let mut kernel = FakeKernel::new();
    kernel.serve_file(FILE, image(), FilePeer::Silent);
    kernel.full.insert(channel(1).0);
    // The read fails at its deadline; the reply is held for a full queue;
    // the client that never makes room is retired when its patience ends.
    let ticks =
        ((IMAGE_READ_TIMEOUT_NS + crate::REPLY_PATIENCE_NS) / RESIDENT_TICK_NS) as usize + 8;
    let mut resident = Dispatcher::new(move |_, tick| tick == ticks).at(0, launch_image);
    assert_eq!(run_resident(&mut resident, &mut kernel), 0);
    assert!(kernel.sent_on(channel(1)).is_empty());
    assert!(kernel.is_closed(channel(1).0));
    assert!(resident.jobs.session_handle(session(1)).is_err());
    assert_eq!(resident.jobs.session_handle(session(2)), Ok(channel(2)));
    assert_eq!(resident.longest_gap(), RESIDENT_TICK_NS);
}

/// The product's own loop, tick and all: a job that exits while a file image
/// is being read for another launch is detected and reaped on time, by
/// `control_tick_product` running inside the read's scratch region.
#[test]
fn a_job_exit_is_reaped_by_the_real_tick_while_an_image_is_read() {
    const GENERATION: u64 = 2;
    // A running job of session 2, launched and accepted the ordinary way.
    let mut rig = Rig::new(two_sessions());
    let job = rig.launch(2, 1);
    rig.make_ready(2, 1);
    while rig.jobs.launches.open_count() != 0 {
        rig.poll();
    }
    assert_eq!(rig.jobs.jobs.live_jobs(), 1);
    let Rig {
        mut kernel,
        jobs,
        mut loader,
    } = rig;
    // The product resident, with that dispatcher as its session's. Without
    // a devmgr the tick is the console half alone, which is the half that
    // serves sessions and reaps jobs.
    let (mut resident, _, _) = crate::recovery_fixture_resident(
        [0x5A; 32],
        GENERATION,
        ConsoleState::new(GENERATION).unwrap(),
        RegistryTopology::new(GENERATION).unwrap(),
        None,
    )
    .unwrap();
    resident.authority = AUTHORITY;
    resident.product.as_mut().unwrap().devmgr = None;
    *crate::console::session_jobs(&mut resident).unwrap() = jobs;

    // Session 1 has a file image launched; each reply takes three and a
    // half ticks. The job exits while the second chunk is on its way.
    let slow = RESIDENT_TICK_NS * 7 / 2;
    kernel.serve_file(FILE, image(), FilePeer::Answers { after_ns: slow });
    launch_image(&mut kernel);
    let started = kernel.now;
    let exits_at = started + 3 * slow;
    kernel.schedule.push((
        exits_at,
        Box::new(move |kernel: &mut FakeKernel| {
            kernel.children.borrow_mut().exited.insert(job.0);
        }),
    ));
    // The loop has no exit of its own short of a failure; the clock ending
    // is this test's.
    kernel.clock_stops_at = Some(started + 40 * RESIDENT_TICK_NS);
    let mut waits = ChildWaits(kernel.children.clone());
    assert_eq!(
        continue_resident(&mut resident, &mut kernel, &mut loader, &mut waits),
        0xAF01_0003
    );

    let position = |handle: u64| kernel.closed.iter().position(|closed| *closed == handle);
    let reaped = position(job.0).expect("the exited job's Process was closed");
    let read = position(FILE.0).expect("the image was read to the end");
    assert!(
        reaped < read,
        "the job was reaped while the image was still being read"
    );
    assert_eq!((kernel.scratch_mapped, kernel.scratch_unmapped), (1, 1));
    let jobs = crate::console::session_jobs(&mut resident).unwrap();
    // The exited job is gone; the image's job is constructed in its place.
    assert_eq!(jobs.jobs.live_jobs(), 1);
    assert!(jobs.launches.session_transaction(session(1)).is_some());
    assert_eq!(
        loader.materialized.last(),
        Some(&image()[0x3000..0x3010].to_vec())
    );
}
