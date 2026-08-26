use deepwyrm_syscall::{DwHandle, DwHandleTransferV1, DwMemoryProtection, DwRights};
use wyrmroot_loader::{
    launch::LaunchProfile,
    process::{
        JobLoadError, JobLoadRequest, LoadAuthority, LoadError, LoadFault, LoadRequest, LoadStage,
        LoaderPlatform, ParentMapping, ProcessCreateRequest, ProcessCreateResult, ServiceLoadError,
        ServiceLoadRequest, load_job_process, load_process, load_process_with_fault,
        load_service_process,
    },
};
use wyrmroot_registry_proto::{Correlation, CorrelationEnvironment};

#[derive(Clone, Debug, Eq, PartialEq)]
enum Event {
    Channel,
    Duplicate(u64),
    Close(u64),
    Process,
    Memory(u64),
    Materialize(u64, usize),
    UnmapParent(u64),
    Map(u64),
    Unmap(u64),
    Thread,
    Send(usize),
    Start,
    TerminateThread,
    TerminateProcess,
}

struct Mock {
    next: u64,
    events: Vec<Event>,
    fail: Option<&'static str>,
    duplicate_calls: usize,
    fail_duplicate_at: Option<usize>,
    started_thread: Option<DwHandle>,
    started_abi: Option<u64>,
    started_stack_pointer: Option<u64>,
    thread_terminated: bool,
    fail_thread_terminate: bool,
    reject_late_unmap: bool,
    reject_redundant_process_terminate: bool,
    post_start_thread_close_failures: usize,
    close_calls: usize,
    fail_close_at: Option<usize>,
    fail_process_terminate: bool,
    materialized: Vec<Vec<u8>>,
    sent_init: Vec<u8>,
    sent_transfers: Vec<DwHandleTransferV1>,
}

impl Mock {
    fn new(fail: Option<&'static str>) -> Self {
        Self {
            next: 10,
            events: Vec::new(),
            fail,
            duplicate_calls: 0,
            fail_duplicate_at: None,
            started_thread: None,
            started_abi: None,
            started_stack_pointer: None,
            thread_terminated: false,
            fail_thread_terminate: false,
            reject_late_unmap: false,
            reject_redundant_process_terminate: false,
            post_start_thread_close_failures: 0,
            close_calls: 0,
            fail_close_at: None,
            fail_process_terminate: false,
            materialized: Vec::new(),
            sent_init: Vec::new(),
            sent_transfers: Vec::new(),
        }
    }
    fn handle(&mut self) -> DwHandle {
        let value = self.next;
        self.next += 1;
        DwHandle(value)
    }
    fn check(&self, operation: &'static str) -> Result<(), &'static str> {
        if self.fail == Some(operation) {
            Err(operation)
        } else {
            Ok(())
        }
    }
}

impl LoaderPlatform for Mock {
    type Error = &'static str;

    fn channel_create(&mut self, _: DwRights) -> Result<(DwHandle, DwHandle), Self::Error> {
        self.events.push(Event::Channel);
        self.check("channel")?;
        Ok((self.handle(), self.handle()))
    }
    fn duplicate(&mut self, handle: DwHandle, _: DwRights) -> Result<DwHandle, Self::Error> {
        self.events.push(Event::Duplicate(handle.0));
        self.duplicate_calls += 1;
        if self.fail_duplicate_at == Some(self.duplicate_calls) {
            return Err("duplicate");
        }
        self.check("duplicate")?;
        Ok(self.handle())
    }
    fn close(&mut self, handle: DwHandle) -> Result<(), Self::Error> {
        self.events.push(Event::Close(handle.0));
        self.close_calls += 1;
        if self.fail_close_at == Some(self.close_calls) {
            return Err("close");
        }
        if self.started_thread == Some(handle) && self.post_start_thread_close_failures != 0 {
            self.post_start_thread_close_failures -= 1;
            return Err("close-thread");
        }
        Ok(())
    }
    fn process_create(
        &mut self,
        _: ProcessCreateRequest,
    ) -> Result<ProcessCreateResult, Self::Error> {
        self.events.push(Event::Process);
        self.check("process")?;
        Ok(ProcessCreateResult {
            process: self.handle(),
            root: self.handle(),
            child_bootstrap: self.handle(),
        })
    }
    fn memory_create(&mut self, bytes: u64, _: DwRights) -> Result<DwHandle, Self::Error> {
        self.events.push(Event::Memory(bytes));
        self.check("memory")?;
        Ok(self.handle())
    }
    fn materialize_parent(
        &mut self,
        _: DwHandle,
        memory: DwHandle,
        _object_size: u64,
        _: u64,
        source: &[u8],
    ) -> Result<ParentMapping, Self::Error> {
        self.events.push(Event::Materialize(memory.0, source.len()));
        self.materialized.push(source.to_vec());
        self.check("materialize")?;
        Ok(ParentMapping {
            address: 0x6000_0000 + memory.0 * 0x1000,
            bytes: 0x1000,
        })
    }
    fn unmap_parent(&mut self, _: DwHandle, mapping: ParentMapping) -> Result<(), Self::Error> {
        self.events.push(Event::UnmapParent(mapping.address));
        self.check("unmap-parent")
    }
    fn map_child(
        &mut self,
        _: DwHandle,
        _: DwHandle,
        address: u64,
        _: u64,
        _: DwMemoryProtection,
    ) -> Result<(), Self::Error> {
        self.events.push(Event::Map(address));
        self.check("map")
    }
    fn unmap_child(&mut self, _: DwHandle, address: u64, _: u64) -> Result<(), Self::Error> {
        self.events.push(Event::Unmap(address));
        if self.thread_terminated && self.reject_late_unmap {
            return Err("unmap-after-terminate");
        }
        Ok(())
    }
    fn thread_create(&mut self, _: DwHandle, _: DwRights) -> Result<DwHandle, Self::Error> {
        self.events.push(Event::Thread);
        self.check("thread")?;
        Ok(self.handle())
    }
    fn send_init(
        &mut self,
        _: DwHandle,
        bytes: &[u8],
        transfers: &[DwHandleTransferV1],
    ) -> Result<(), Self::Error> {
        self.events.push(Event::Send(transfers.len()));
        self.sent_init = bytes.to_vec();
        self.sent_transfers = transfers.to_vec();
        self.check("send")
    }
    fn thread_start(
        &mut self,
        thread: DwHandle,
        _: u64,
        stack_pointer: u64,
        _: DwHandle,
        startup_abi: u64,
    ) -> Result<(), Self::Error> {
        self.events.push(Event::Start);
        self.check("start")?;
        self.started_thread = Some(thread);
        self.started_abi = Some(startup_abi);
        self.started_stack_pointer = Some(stack_pointer);
        Ok(())
    }
    fn thread_terminate(&mut self, _: DwHandle) -> Result<(), Self::Error> {
        self.events.push(Event::TerminateThread);
        if self.fail_thread_terminate {
            return Err("terminate-thread");
        }
        self.thread_terminated = true;
        Ok(())
    }
    fn process_terminate(&mut self, _: DwHandle) -> Result<(), Self::Error> {
        self.events.push(Event::TerminateProcess);
        if self.thread_terminated && self.reject_redundant_process_terminate {
            return Err("already-exited");
        }
        if self.fail_process_terminate {
            Err("terminate-process")
        } else {
            Ok(())
        }
    }
}

#[test]
fn init0_construction_materializes_before_mapping_and_starts_last() {
    let mut platform = Mock::new(None);
    let image = executable();
    let result = load_process(
        &mut platform,
        authority(),
        request(&image, LaunchProfile::Init0),
    )
    .unwrap();
    assert_ne!(result.process.0, 0);
    assert_ne!(result.launch_channel.0, 0);
    let materialize = position(&platform.events, |e| matches!(e, Event::Materialize(_, _)));
    let unmap_parent = position(&platform.events, |e| matches!(e, Event::UnmapParent(_)));
    let map = position(&platform.events, |e| matches!(e, Event::Map(_)));
    let send = position(&platform.events, |e| matches!(e, Event::Send(3)));
    let start = position(&platform.events, |e| matches!(e, Event::Start));
    assert!(materialize < unmap_parent && unmap_parent < map && map < send && send < start);
    assert_eq!(platform.events.last(), Some(&Event::Close(18)));
}

#[test]
fn probe_child_delegates_only_its_self_root_in_the_wrpl_1_1_init() {
    let mut platform = Mock::new(None);
    let image = executable();
    load_process(
        &mut platform,
        authority(),
        request(&image, LaunchProfile::ProbeChild),
    )
    .unwrap();

    assert_eq!(
        platform
            .events
            .iter()
            .filter(|event| matches!(event, Event::Send(1)))
            .count(),
        1
    );
    assert_eq!(platform.sent_init.len(), 48);
    assert_eq!(&platform.sent_init[6..8], &1_u16.to_le_bytes());
    assert_eq!(platform.sent_transfers.len(), 1);
    assert_eq!(
        platform.sent_transfers[0].requested_rights,
        wyrmroot_loader::launch::SELF_ROOT_RIGHTS
    );
    assert!(!platform.events.contains(&Event::Duplicate(2)));
    assert!(!platform.events.contains(&Event::Duplicate(3)));
}

#[test]
fn bootstrap_registry_moves_self_root_and_controller_endpoint() {
    let mut platform = Mock::new(None);
    let image = executable();
    load_service_process(
        &mut platform,
        authority(),
        ServiceLoadRequest {
            image: &image,
            display_path: "/system/registryd",
            profile: LaunchProfile::BootstrapRegistry,
            service_channel: DwHandle(0x900),
            correlation: None,
            transaction_id: 0x1301,
        },
    )
    .unwrap();

    assert_eq!(platform.sent_transfers.len(), 2);
    assert_eq!(platform.sent_transfers[1].handle, DwHandle(0x900));
    assert_eq!(
        platform.sent_transfers[1].requested_rights,
        wyrmroot_loader::launch::CHILD_CHANNEL_RIGHTS
    );
    assert_eq!(&platform.sent_init[6..8], &3_u16.to_le_bytes());
}

#[test]
fn bootstrap_service_uses_startup_v2_for_controller_correlation_environment() {
    let mut platform = Mock::new(None);
    let image = executable();
    let correlation = CorrelationEnvironment::new(Correlation {
        registry_generation: 7,
        endpoint_id: 11,
        endpoint_generation: 1,
    })
    .unwrap();
    load_service_process(
        &mut platform,
        authority(),
        ServiceLoadRequest {
            image: &image,
            display_path: "test/wyr1-b/publisher",
            profile: LaunchProfile::BootstrapService,
            service_channel: DwHandle(0x904),
            correlation: Some(&correlation),
            transaction_id: 0x1304,
        },
    )
    .unwrap();
    assert_eq!(platform.started_abi, Some(2));
    assert_eq!(
        platform.started_stack_pointer,
        Some(wyrmroot_loader::image::STARTUP_V2_BLOCK_ADDRESS)
    );
    assert_eq!(platform.materialized.last().unwrap().len(), 20 * 1024);
    assert!(
        platform
            .materialized
            .last()
            .unwrap()
            .windows(correlation.entry(2).unwrap().len())
            .any(|window| window == correlation.entry(2).unwrap().as_bytes())
    );

    let missing = load_service_process(
        &mut Mock::new(None),
        authority(),
        ServiceLoadRequest {
            image: &image,
            display_path: "test/wyr1-b/publisher",
            profile: LaunchProfile::BootstrapService,
            service_channel: DwHandle(0x905),
            correlation: None,
            transaction_id: 0x1305,
        },
    );
    assert_eq!(
        missing,
        Err(ServiceLoadError {
            error: LoadError::Startup(
                wyrmroot_loader::image::StartupBlockError::InvalidEnvironment
            ),
            service_channel_consumed: false,
        })
    );
}

#[test]
fn service_load_reports_endpoint_ownership_on_both_sides_of_init_commit() {
    let image = executable();
    let request = |service_channel| ServiceLoadRequest {
        image: &image,
        display_path: "/system/registryd",
        profile: LaunchProfile::BootstrapRegistry,
        service_channel,
        correlation: None,
        transaction_id: 0x1310,
    };

    let mut before = Mock::new(None);
    // The first close reduces the loader's broad bootstrap endpoint. The
    // second is the first mapped image object's pre-INIT scratch close.
    before.fail_close_at = Some(2);
    let before_error = load_service_process(&mut before, authority(), request(DwHandle(0x910)))
        .expect_err("pre-INIT scratch cleanup must fail");
    assert!(matches!(
        before_error.error,
        LoadError::Platform {
            stage: LoadStage::SuccessCleanup,
            ..
        }
    ));
    assert!(!before_error.service_channel_consumed);
    assert!(
        !before
            .events
            .iter()
            .any(|event| matches!(event, Event::Send(_)))
    );

    let mut after = Mock::new(None);
    after.post_start_thread_close_failures = 1;
    let after_error = load_service_process(&mut after, authority(), request(DwHandle(0x911)))
        .expect_err("post-INIT thread cleanup must fail");
    assert!(matches!(
        after_error.error,
        LoadError::Platform {
            stage: LoadStage::SuccessCleanup,
            ..
        }
    ));
    assert!(after_error.service_channel_consumed);
    assert!(
        after
            .events
            .iter()
            .any(|event| matches!(event, Event::Send(2)))
    );
}

#[test]
fn failed_service_init_send_leaves_endpoint_with_caller() {
    let image = executable();
    let service_channel = DwHandle(0x912);
    let mut platform = Mock::new(Some("send"));

    let failure = load_service_process(
        &mut platform,
        authority(),
        ServiceLoadRequest {
            image: &image,
            display_path: "/system/registryd",
            profile: LaunchProfile::BootstrapRegistry,
            service_channel,
            correlation: None,
            transaction_id: 0x1311,
        },
    )
    .expect_err("INIT send must fail");

    assert_eq!(
        failure,
        ServiceLoadError {
            error: LoadError::Platform {
                stage: LoadStage::InitSend,
                cause: "send",
                rollback_failed: false,
            },
            service_channel_consumed: false,
        }
    );
    assert!(platform.events.contains(&Event::Send(2)));
    assert!(!platform.events.contains(&Event::Close(service_channel.0)));
}

#[test]
fn job_v2_selects_zero_or_three_stream_profile_and_retains_streams_on_failed_move() {
    let image = executable();
    let argv = ["bin/hello"];
    let streams = [DwHandle(0x901), DwHandle(0x902), DwHandle(0x903)];
    let mut platform = Mock::new(None);
    load_job_process(
        &mut platform,
        authority(),
        JobLoadRequest {
            image: &image,
            policy_path: "bin/hello",
            argv: &argv,
            environment: &[],
            streams: &streams,
            transaction_id: 0x1302,
        },
    )
    .unwrap();
    assert_eq!(
        platform
            .sent_transfers
            .iter()
            .map(|transfer| transfer.handle)
            .collect::<Vec<_>>(),
        streams
    );
    assert_eq!(&platform.sent_init[6..8], &3_u16.to_le_bytes());

    let mut failing = Mock::new(Some("send"));
    let error = load_job_process(
        &mut failing,
        authority(),
        JobLoadRequest {
            image: &image,
            policy_path: "bin/hello",
            argv: &argv,
            environment: &[],
            streams: &streams,
            transaction_id: 0x1303,
        },
    )
    .unwrap_err();
    assert!(matches!(
        error.error,
        LoadError::Platform {
            stage: LoadStage::InitSend,
            rollback_failed: false,
            ..
        }
    ));
    assert!(!error.streams_consumed);
    for stream in streams {
        assert!(!failing.events.contains(&Event::Close(stream.0)));
    }
}

#[test]
fn job_load_reports_stream_ownership_after_successful_init_move() {
    let image = executable();
    let argv = ["bin/hello"];
    let streams = [DwHandle(0x921), DwHandle(0x922), DwHandle(0x923)];
    let mut platform = Mock::new(None);
    platform.post_start_thread_close_failures = 1;

    let error = load_job_process(
        &mut platform,
        authority(),
        JobLoadRequest {
            image: &image,
            policy_path: "bin/hello",
            argv: &argv,
            environment: &[],
            streams: &streams,
            transaction_id: 0x1320,
        },
    )
    .expect_err("post-INIT cleanup must report transferred stream ownership");

    assert!(matches!(
        error,
        JobLoadError {
            error: LoadError::Platform {
                stage: LoadStage::SuccessCleanup,
                ..
            },
            streams_consumed: true,
        }
    ));
    for stream in streams {
        assert!(!platform.events.contains(&Event::Close(stream.0)));
    }
}

#[test]
fn probe_child_send_failure_rolls_back_the_unmoved_self_root_without_controller_delegations() {
    let mut platform = Mock::new(Some("send"));
    let image = executable();
    let error = load_process(
        &mut platform,
        authority(),
        request(&image, LaunchProfile::ProbeChild),
    )
    .unwrap_err();

    assert_eq!(
        error,
        LoadError::Platform {
            stage: LoadStage::InitSend,
            cause: "send",
            rollback_failed: false,
        }
    );
    assert!(platform.events.contains(&Event::Send(1)));
    assert!(platform.events.contains(&Event::Close(14)));
    assert!(!platform.events.contains(&Event::Duplicate(2)));
    assert!(!platform.events.contains(&Event::Duplicate(3)));
}

#[test]
fn prepublication_failure_unmaps_and_terminates_in_reverse_order() {
    let mut platform = Mock::new(Some("thread"));
    let image = executable();
    let error = load_process(
        &mut platform,
        authority(),
        request(&image, LaunchProfile::Hello),
    )
    .unwrap_err();
    assert_eq!(
        error,
        LoadError::Platform {
            stage: LoadStage::ThreadCreate,
            cause: "thread",
            rollback_failed: false
        }
    );
    let unmaps: Vec<_> = platform
        .events
        .iter()
        .filter_map(|event| {
            if let Event::Unmap(address) = event {
                Some(*address)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(unmaps, vec![0x0000_7fff_fffe_0000, 0x0040_0000]);
    assert!(platform.events.contains(&Event::TerminateProcess));
}

#[test]
fn failed_parent_unmap_retains_exact_alias_for_rollback_retry() {
    let mut platform = Mock::new(Some("unmap-parent"));
    let image = executable();
    let error = load_process(
        &mut platform,
        authority(),
        request(&image, LaunchProfile::Hello),
    )
    .unwrap_err();
    assert_eq!(
        error,
        LoadError::Platform {
            stage: LoadStage::ParentUnmap,
            cause: "unmap-parent",
            rollback_failed: true,
        }
    );
    let attempted: Vec<_> = platform
        .events
        .iter()
        .filter_map(|event| match event {
            Event::UnmapParent(address) => Some(*address),
            _ => None,
        })
        .collect();
    assert_eq!(attempted.len(), 2);
    assert_eq!(attempted[0], attempted[1]);
    assert!(platform.events.contains(&Event::TerminateProcess));
}

#[test]
fn postpublication_cleanup_reports_failed_process_termination() {
    let mut platform = Mock::new(None);
    platform.post_start_thread_close_failures = 1;
    platform.fail_process_terminate = true;
    let image = executable();
    let error = load_process(
        &mut platform,
        authority(),
        request(&image, LaunchProfile::Hello),
    )
    .unwrap_err();
    assert_eq!(
        error,
        LoadError::Platform {
            stage: LoadStage::SuccessCleanup,
            cause: "close-thread",
            rollback_failed: false,
        }
    );
    assert!(platform.events.contains(&Event::TerminateProcess));
    assert!(platform.events.contains(&Event::TerminateThread));
    let terminate_process = position(&platform.events, |event| {
        matches!(event, Event::TerminateProcess)
    });
    let terminate_thread = position(&platform.events, |event| {
        matches!(event, Event::TerminateThread)
    });
    assert!(terminate_process < terminate_thread);
    assert_eq!(
        platform
            .events
            .iter()
            .filter(|event| matches!(event, Event::Close(18)))
            .count(),
        2
    );
}

#[test]
fn failed_start_after_init_transfer_uses_process_teardown() {
    let mut platform = Mock::new(Some("start"));
    let image = executable();
    let error = load_process(
        &mut platform,
        authority(),
        request(&image, LaunchProfile::Init0),
    )
    .unwrap_err();
    assert_eq!(
        error,
        LoadError::Platform {
            stage: LoadStage::ThreadStart,
            cause: "start",
            rollback_failed: false
        }
    );
    assert!(platform.events.contains(&Event::TerminateThread));
    assert!(!platform.events.contains(&Event::TerminateProcess));
    assert!(
        !platform
            .events
            .iter()
            .any(|event| matches!(event, Event::Unmap(_)))
    );
}

#[test]
fn capability_duplicate_rollback_unmaps_before_sole_thread_termination() {
    let mut platform = Mock::new(None);
    // The first duplicate narrows the loader's parent endpoint.  The second
    // is the Init0 bootfs delegation that fails in the live eight-slot table.
    platform.fail_duplicate_at = Some(2);
    platform.reject_late_unmap = true;
    platform.reject_redundant_process_terminate = true;
    let image = executable();
    let error = load_process(
        &mut platform,
        authority(),
        request(&image, LaunchProfile::Init0),
    )
    .unwrap_err();
    assert_eq!(
        error,
        LoadError::Platform {
            stage: LoadStage::CapabilityDuplicate,
            cause: "duplicate",
            rollback_failed: false,
        }
    );
    let final_unmap = platform
        .events
        .iter()
        .rposition(|event| matches!(event, Event::Unmap(_)))
        .unwrap();
    let terminate = position(&platform.events, |event| {
        matches!(event, Event::TerminateThread)
    });
    assert!(final_unmap < terminate);
    assert!(!platform.events.contains(&Event::TerminateProcess));
    for handle in [18, 14, 13, 12] {
        assert!(platform.events.contains(&Event::Close(handle)));
    }
}

#[test]
fn capability_duplicate_rollback_uses_process_termination_after_thread_failure() {
    let mut platform = Mock::new(None);
    platform.fail_duplicate_at = Some(2);
    platform.fail_thread_terminate = true;
    let image = executable();
    let error = load_process(
        &mut platform,
        authority(),
        request(&image, LaunchProfile::Init0),
    )
    .unwrap_err();
    assert_eq!(
        error,
        LoadError::Platform {
            stage: LoadStage::CapabilityDuplicate,
            cause: "duplicate",
            rollback_failed: false,
        }
    );
    let terminate_thread = position(&platform.events, |event| {
        matches!(event, Event::TerminateThread)
    });
    let terminate_process = position(&platform.events, |event| {
        matches!(event, Event::TerminateProcess)
    });
    assert!(terminate_thread < terminate_process);
    for handle in [18, 14, 13, 12] {
        assert!(platform.events.contains(&Event::Close(handle)));
    }
}

#[test]
fn capability_duplicate_rollback_reports_failure_after_both_terminators_fail() {
    let mut platform = Mock::new(None);
    platform.fail_duplicate_at = Some(2);
    platform.fail_thread_terminate = true;
    platform.fail_process_terminate = true;
    let image = executable();
    let error = load_process(
        &mut platform,
        authority(),
        request(&image, LaunchProfile::Init0),
    )
    .unwrap_err();
    assert_eq!(
        error,
        LoadError::Platform {
            stage: LoadStage::CapabilityDuplicate,
            cause: "duplicate",
            rollback_failed: true,
        }
    );
    let terminate_thread = position(&platform.events, |event| {
        matches!(event, Event::TerminateThread)
    });
    let terminate_process = position(&platform.events, |event| {
        matches!(event, Event::TerminateProcess)
    });
    assert!(terminate_thread < terminate_process);
    for handle in [18, 14, 13, 12] {
        assert!(platform.events.contains(&Event::Close(handle)));
    }
}

#[test]
fn selected_faults_change_only_their_locked_child_launch_boundary() {
    let image = executable();

    let mut startup = Mock::new(None);
    load_process_with_fault(
        &mut startup,
        authority(),
        request(&image, LaunchProfile::Init0),
        LoadFault::MalformedStartup,
    )
    .unwrap();
    assert!(
        startup
            .materialized
            .iter()
            .any(|bytes| bytes.len() == 4096 && bytes[..8] == 2_u64.to_le_bytes())
    );

    let mut count = Mock::new(None);
    load_process_with_fault(
        &mut count,
        authority(),
        request(&image, LaunchProfile::Init0),
        LoadFault::InitCapabilityCount,
    )
    .unwrap();
    assert_eq!(&count.sent_init[20..24], &2_u32.to_le_bytes());
    assert_eq!(count.sent_transfers.len(), 3);

    let mut kind = Mock::new(None);
    let mut normal = Mock::new(None);
    load_process(
        &mut normal,
        authority(),
        request(&image, LaunchProfile::Init0),
    )
    .unwrap();
    load_process_with_fault(
        &mut kind,
        authority(),
        request(&image, LaunchProfile::Init0),
        LoadFault::InitCapabilityType,
    )
    .unwrap();
    assert_eq!(kind.sent_transfers[0], normal.sent_transfers[2]);

    let mut rights = Mock::new(None);
    load_process_with_fault(
        &mut rights,
        authority(),
        request(&image, LaunchProfile::Init0),
        LoadFault::InitCapabilityRights,
    )
    .unwrap();
    assert_ne!(
        rights.sent_transfers[0].requested_rights,
        wyrmroot_loader::launch::SELF_ROOT_RIGHTS
    );
}

#[test]
fn malformed_elf_fault_fails_before_any_platform_operation() {
    let mut platform = Mock::new(None);
    let image = executable();
    assert!(matches!(
        load_process_with_fault(
            &mut platform,
            authority(),
            request(&image, LaunchProfile::Init0),
            LoadFault::MalformedElf,
        ),
        Err(LoadError::Elf(_))
    ));
    assert!(platform.events.is_empty());
}

fn authority() -> LoadAuthority {
    LoadAuthority {
        parent_root: DwHandle(1),
        task_group: DwHandle(2),
        bootfs: DwHandle(3),
    }
}
fn request(image: &[u8], profile: LaunchProfile) -> LoadRequest<'_> {
    LoadRequest {
        image,
        display_path: "/bin/test",
        profile,
        transaction_id: 1,
    }
}
fn position(events: &[Event], predicate: impl Fn(&Event) -> bool) -> usize {
    events.iter().position(predicate).unwrap()
}

fn executable() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x2000];
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
