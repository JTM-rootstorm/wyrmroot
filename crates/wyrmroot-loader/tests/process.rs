use deepwyrm_syscall::{DwHandle, DwHandleTransferV1, DwMemoryProtection, DwRights};
use wyrmroot_loader::{
    launch::LaunchProfile,
    process::{
        LoadAuthority, LoadError, LoadRequest, LoadStage, LoaderPlatform, ParentMapping,
        ProcessCreateRequest, ProcessCreateResult, load_process,
    },
};

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
}

impl Mock {
    fn new(fail: Option<&'static str>) -> Self {
        Self {
            next: 10,
            events: Vec::new(),
            fail,
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
        self.check("duplicate")?;
        Ok(self.handle())
    }
    fn close(&mut self, handle: DwHandle) -> Result<(), Self::Error> {
        self.events.push(Event::Close(handle.0));
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
        _: u64,
        _: u64,
        source: &[u8],
    ) -> Result<ParentMapping, Self::Error> {
        self.events.push(Event::Materialize(memory.0, source.len()));
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
        _: &[u8],
        transfers: &[DwHandleTransferV1],
    ) -> Result<(), Self::Error> {
        self.events.push(Event::Send(transfers.len()));
        self.check("send")
    }
    fn thread_start(
        &mut self,
        _: DwHandle,
        _: u64,
        _: u64,
        _: DwHandle,
        _: u64,
    ) -> Result<(), Self::Error> {
        self.events.push(Event::Start);
        self.check("start")
    }
    fn thread_terminate(&mut self, _: DwHandle) -> Result<(), Self::Error> {
        self.events.push(Event::TerminateThread);
        Ok(())
    }
    fn process_terminate(&mut self, _: DwHandle) -> Result<(), Self::Error> {
        self.events.push(Event::TerminateProcess);
        Ok(())
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
    assert!(platform.events.contains(&Event::TerminateProcess));
    assert!(
        !platform
            .events
            .iter()
            .any(|event| matches!(event, Event::Unmap(_)))
    );
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
