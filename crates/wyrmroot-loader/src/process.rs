//! Failure-atomic WYR0 child construction over an explicit platform boundary.

use deepwyrm_syscall::{
    DW_HANDLE_TRANSFER_MOVE, DW_MEMORY_PROTECTION_EXECUTE, DW_MEMORY_PROTECTION_READ,
    DW_MEMORY_PROTECTION_WRITE, DW_RIGHT_DUPLICATE, DW_RIGHT_EXECUTE, DW_RIGHT_INSPECT,
    DW_RIGHT_MAP, DW_RIGHT_MODIFY, DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DW_RIGHT_WRITE,
    DwHandle, DwHandleTransferV1, DwMemoryProtection, DwRights,
};

use crate::{
    elf::{self, ElfError, LoadSegment, MAX_LOAD_SEGMENTS, PAGE_SIZE, SegmentProtection},
    image::{self, INITIAL_STACK, MaterializationPlan, StartupBlockError},
    launch::{
        self, BOOTFS_RIGHTS, INIT0_BYTES, LOADER_TASK_GROUP_RIGHTS, LaunchError, LaunchProfile,
        SELF_ROOT_RIGHTS,
    },
};

const MAX_CHILD_RANGES: usize = MAX_LOAD_SEGMENTS + 1;
const CHANNEL_BROAD_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0
        | DW_RIGHT_WRITE.0
        | DW_RIGHT_WAIT.0
        | DW_RIGHT_DUPLICATE.0
        | DW_RIGHT_TRANSFER.0
        | DW_RIGHT_INSPECT.0,
);
const CHANNEL_RETAINED_RIGHTS: DwRights =
    DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0);
const PROCESS_RIGHTS: DwRights = DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0);
const ROOT_RIGHTS: DwRights =
    DwRights(DW_RIGHT_MAP.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_TRANSFER.0);
const THREAD_RIGHTS: DwRights =
    DwRights(DW_RIGHT_EXECUTE.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0);
const MEMORY_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_EXECUTE.0 | DW_RIGHT_MAP.0 | DW_RIGHT_INSPECT.0,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadAuthority {
    pub parent_root: DwHandle,
    pub task_group: DwHandle,
    pub bootfs: DwHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadRequest<'a> {
    pub image: &'a [u8],
    pub display_path: &'a str,
    pub profile: LaunchProfile,
    pub transaction_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadedProcess {
    pub process: DwHandle,
    pub launch_channel: DwHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadStage {
    ChannelCreate,
    ChannelReduce,
    ProcessCreate,
    MemoryCreate,
    ParentMaterialize,
    ParentUnmap,
    ChildMap,
    ThreadCreate,
    CapabilityDuplicate,
    InitSend,
    ThreadStart,
    SuccessCleanup,
}

#[derive(Debug, Eq, PartialEq)]
pub enum LoadError<PlatformError> {
    Elf(ElfError),
    Startup(StartupBlockError),
    Launch(LaunchError),
    Platform {
        stage: LoadStage,
        cause: PlatformError,
        rollback_failed: bool,
    },
}

#[derive(Clone, Copy)]
pub struct ProcessCreateRequest {
    pub task_group: DwHandle,
    pub bootstrap_channel: DwHandle,
    pub process_rights: DwRights,
    pub root_rights: DwRights,
    pub child_bootstrap_rights: DwRights,
}

#[derive(Clone, Copy)]
pub struct ProcessCreateResult {
    pub process: DwHandle,
    pub root: DwHandle,
    pub child_bootstrap: DwHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParentMapping {
    pub address: u64,
    pub bytes: u64,
}

/// Platform operations used by the transaction driver.
///
/// `materialize_parent` maps the complete object RW in the parent, zeroes its complete extent,
/// copies `source` at `destination_offset`, and returns exact cleanup ownership. The driver
/// removes that alias before calling `map_child`, preserving W^X ordering and retaining enough
/// information to retry cleanup during rollback if the first unmap fails.
pub trait LoaderPlatform {
    type Error;

    fn channel_create(&mut self, rights: DwRights) -> Result<(DwHandle, DwHandle), Self::Error>;
    fn duplicate(&mut self, handle: DwHandle, rights: DwRights) -> Result<DwHandle, Self::Error>;
    fn close(&mut self, handle: DwHandle) -> Result<(), Self::Error>;
    fn process_create(
        &mut self,
        request: ProcessCreateRequest,
    ) -> Result<ProcessCreateResult, Self::Error>;
    fn memory_create(&mut self, bytes: u64, rights: DwRights) -> Result<DwHandle, Self::Error>;
    fn materialize_parent(
        &mut self,
        parent_root: DwHandle,
        memory: DwHandle,
        object_size: u64,
        destination_offset: u64,
        source: &[u8],
    ) -> Result<ParentMapping, Self::Error>;
    fn unmap_parent(
        &mut self,
        parent_root: DwHandle,
        mapping: ParentMapping,
    ) -> Result<(), Self::Error>;
    fn map_child(
        &mut self,
        child_root: DwHandle,
        memory: DwHandle,
        address: u64,
        bytes: u64,
        protection: DwMemoryProtection,
    ) -> Result<(), Self::Error>;
    fn unmap_child(
        &mut self,
        child_root: DwHandle,
        address: u64,
        bytes: u64,
    ) -> Result<(), Self::Error>;
    fn thread_create(
        &mut self,
        process: DwHandle,
        rights: DwRights,
    ) -> Result<DwHandle, Self::Error>;
    fn send_init(
        &mut self,
        channel: DwHandle,
        bytes: &[u8],
        transfers: &[DwHandleTransferV1],
    ) -> Result<(), Self::Error>;
    fn thread_start(
        &mut self,
        thread: DwHandle,
        entry: u64,
        stack_pointer: u64,
        child_bootstrap: DwHandle,
        startup_abi: u64,
    ) -> Result<(), Self::Error>;
    fn thread_terminate(&mut self, thread: DwHandle) -> Result<(), Self::Error>;
    fn process_terminate(&mut self, process: DwHandle) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Default)]
struct Range {
    address: u64,
    bytes: u64,
}

struct Transaction {
    parent_root: DwHandle,
    broad_parent: Option<DwHandle>,
    child_endpoint: Option<DwHandle>,
    parent_channel: Option<DwHandle>,
    process: Option<DwHandle>,
    root: Option<DwHandle>,
    thread: Option<DwHandle>,
    scratch_memory: Option<DwHandle>,
    parent_mapping: Option<ParentMapping>,
    delegated_bootfs: Option<DwHandle>,
    delegated_task_group: Option<DwHandle>,
    ranges: [Range; MAX_CHILD_RANGES],
    range_count: usize,
}

impl Transaction {
    const fn new(parent_root: DwHandle) -> Self {
        Self {
            parent_root,
            broad_parent: None,
            child_endpoint: None,
            parent_channel: None,
            process: None,
            root: None,
            thread: None,
            scratch_memory: None,
            parent_mapping: None,
            delegated_bootfs: None,
            delegated_task_group: None,
            ranges: [Range {
                address: 0,
                bytes: 0,
            }; MAX_CHILD_RANGES],
            range_count: 0,
        }
    }

    fn rollback<P: LoaderPlatform>(&mut self, platform: &mut P) -> bool {
        let mut failed = false;
        if let Some(mapping) = self.parent_mapping.take() {
            failed |= platform.unmap_parent(self.parent_root, mapping).is_err();
        }
        if let Some(thread) = self.thread.take() {
            failed |= platform.thread_terminate(thread).is_err();
            failed |= platform.close(thread).is_err();
        }
        let process = self.process.take();
        if let Some(root) = self.root.take() {
            while self.range_count != 0 {
                self.range_count -= 1;
                let range = self.ranges[self.range_count];
                failed |= platform
                    .unmap_child(root, range.address, range.bytes)
                    .is_err();
            }
            failed |= platform.close(root).is_err();
        }
        if let Some(process) = process {
            failed |= platform.process_terminate(process).is_err();
            failed |= platform.close(process).is_err();
        }
        for handle in [
            self.scratch_memory.take(),
            self.delegated_task_group.take(),
            self.delegated_bootfs.take(),
            self.child_endpoint.take(),
            self.broad_parent.take(),
            self.parent_channel.take(),
        ]
        .into_iter()
        .flatten()
        {
            failed |= platform.close(handle).is_err();
        }
        failed
    }
}

pub fn load_process<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: LoadRequest<'_>,
) -> Result<LoadedProcess, LoadError<P::Error>> {
    let mut segments = [empty_segment(); MAX_LOAD_SEGMENTS];
    let plan = elf::plan(request.image, &mut segments).map_err(LoadError::Elf)?;
    let mut startup_page = [0_u8; PAGE_SIZE as usize];
    image::write_startup_block(
        &mut startup_page,
        image::INITIAL_STACK_POINTER,
        request.display_path,
    )
    .map_err(LoadError::Startup)?;
    let mut init = [0_u8; INIT0_BYTES];
    let init_len = launch::encode_init(request.profile, request.transaction_id, &mut init)
        .map_err(LoadError::Launch)?;

    let mut transaction = Transaction::new(authority.parent_root);
    let (broad_parent, child_endpoint) = platform
        .channel_create(CHANNEL_BROAD_RIGHTS)
        .map_err(|cause| platform_error(LoadStage::ChannelCreate, cause, false))?;
    transaction.broad_parent = Some(broad_parent);
    transaction.child_endpoint = Some(child_endpoint);

    let parent_channel = match platform.duplicate(broad_parent, CHANNEL_RETAINED_RIGHTS) {
        Ok(handle) => handle,
        Err(cause) => {
            return Err(fail(
                platform,
                &mut transaction,
                LoadStage::ChannelReduce,
                cause,
            ));
        }
    };
    transaction.parent_channel = Some(parent_channel);
    if let Err(cause) = platform.close(broad_parent) {
        return Err(fail(
            platform,
            &mut transaction,
            LoadStage::ChannelReduce,
            cause,
        ));
    }
    transaction.broad_parent = None;

    let created = match platform.process_create(ProcessCreateRequest {
        task_group: authority.task_group,
        bootstrap_channel: child_endpoint,
        process_rights: PROCESS_RIGHTS,
        root_rights: ROOT_RIGHTS,
        child_bootstrap_rights: CHANNEL_RETAINED_RIGHTS,
    }) {
        Ok(created) => created,
        Err(cause) => {
            return Err(fail(
                platform,
                &mut transaction,
                LoadStage::ProcessCreate,
                cause,
            ));
        }
    };
    transaction.child_endpoint = None;
    transaction.process = Some(created.process);
    transaction.root = Some(created.root);

    for segment in plan.segments {
        let materialization = MaterializationPlan::from(*segment);
        let memory = match platform.memory_create(materialization.object_size, MEMORY_RIGHTS) {
            Ok(handle) => handle,
            Err(cause) => {
                return Err(fail(
                    platform,
                    &mut transaction,
                    LoadStage::MemoryCreate,
                    cause,
                ));
            }
        };
        transaction.scratch_memory = Some(memory);
        let source_start = materialization.source_offset as usize;
        let source_end = source_start + materialization.source_size as usize;
        let parent_mapping = match platform.materialize_parent(
            authority.parent_root,
            memory,
            materialization.object_size,
            materialization.destination_offset,
            &request.image[source_start..source_end],
        ) {
            Ok(mapping) => mapping,
            Err(cause) => {
                return Err(fail(
                    platform,
                    &mut transaction,
                    LoadStage::ParentMaterialize,
                    cause,
                ));
            }
        };
        transaction.parent_mapping = Some(parent_mapping);
        if let Err(cause) = platform.unmap_parent(authority.parent_root, parent_mapping) {
            return Err(fail(
                platform,
                &mut transaction,
                LoadStage::ParentUnmap,
                cause,
            ));
        }
        transaction.parent_mapping = None;
        if let Err(cause) = platform.map_child(
            created.root,
            memory,
            materialization.child_address,
            materialization.object_size,
            native_protection(materialization.protection),
        ) {
            return Err(fail(platform, &mut transaction, LoadStage::ChildMap, cause));
        }
        transaction.ranges[transaction.range_count] = Range {
            address: materialization.child_address,
            bytes: materialization.object_size,
        };
        transaction.range_count += 1;
        if let Err(cause) = platform.close(memory) {
            return Err(fail(
                platform,
                &mut transaction,
                LoadStage::SuccessCleanup,
                cause,
            ));
        }
        transaction.scratch_memory = None;
    }

    let stack = match platform.memory_create(INITIAL_STACK.object_size, MEMORY_RIGHTS) {
        Ok(handle) => handle,
        Err(cause) => {
            return Err(fail(
                platform,
                &mut transaction,
                LoadStage::MemoryCreate,
                cause,
            ));
        }
    };
    transaction.scratch_memory = Some(stack);
    let parent_mapping = match platform.materialize_parent(
        authority.parent_root,
        stack,
        INITIAL_STACK.object_size,
        INITIAL_STACK.startup_page_offset,
        &startup_page,
    ) {
        Ok(mapping) => mapping,
        Err(cause) => {
            return Err(fail(
                platform,
                &mut transaction,
                LoadStage::ParentMaterialize,
                cause,
            ));
        }
    };
    transaction.parent_mapping = Some(parent_mapping);
    if let Err(cause) = platform.unmap_parent(authority.parent_root, parent_mapping) {
        return Err(fail(
            platform,
            &mut transaction,
            LoadStage::ParentUnmap,
            cause,
        ));
    }
    transaction.parent_mapping = None;
    if let Err(cause) = platform.map_child(
        created.root,
        stack,
        INITIAL_STACK.child_address,
        INITIAL_STACK.object_size,
        DwMemoryProtection(DW_MEMORY_PROTECTION_READ.0 | DW_MEMORY_PROTECTION_WRITE.0),
    ) {
        return Err(fail(platform, &mut transaction, LoadStage::ChildMap, cause));
    }
    transaction.ranges[transaction.range_count] = Range {
        address: INITIAL_STACK.child_address,
        bytes: INITIAL_STACK.object_size,
    };
    transaction.range_count += 1;
    if let Err(cause) = platform.close(stack) {
        return Err(fail(
            platform,
            &mut transaction,
            LoadStage::SuccessCleanup,
            cause,
        ));
    }
    transaction.scratch_memory = None;

    let thread = match platform.thread_create(created.process, THREAD_RIGHTS) {
        Ok(handle) => handle,
        Err(cause) => {
            return Err(fail(
                platform,
                &mut transaction,
                LoadStage::ThreadCreate,
                cause,
            ));
        }
    };
    transaction.thread = Some(thread);

    let mut transfers = [DwHandleTransferV1::default(); 3];
    let transfer_count = if request.profile == LaunchProfile::Init0 {
        let bootfs = match platform.duplicate(authority.bootfs, BOOTFS_RIGHTS) {
            Ok(handle) => handle,
            Err(cause) => {
                return Err(fail(
                    platform,
                    &mut transaction,
                    LoadStage::CapabilityDuplicate,
                    cause,
                ));
            }
        };
        transaction.delegated_bootfs = Some(bootfs);
        let task_group = match platform.duplicate(authority.task_group, LOADER_TASK_GROUP_RIGHTS) {
            Ok(handle) => handle,
            Err(cause) => {
                return Err(fail(
                    platform,
                    &mut transaction,
                    LoadStage::CapabilityDuplicate,
                    cause,
                ));
            }
        };
        transaction.delegated_task_group = Some(task_group);
        transfers[0] = transfer(created.root, SELF_ROOT_RIGHTS);
        transfers[1] = transfer(bootfs, BOOTFS_RIGHTS);
        transfers[2] = transfer(task_group, LOADER_TASK_GROUP_RIGHTS);
        3
    } else {
        0
    };

    if let Err(cause) = platform.send_init(
        parent_channel,
        &init[..init_len],
        &transfers[..transfer_count],
    ) {
        return Err(fail(platform, &mut transaction, LoadStage::InitSend, cause));
    }
    if request.profile == LaunchProfile::Init0 {
        transaction.root = None;
        transaction.delegated_bootfs = None;
        transaction.delegated_task_group = None;
    } else if let Err(cause) = platform.close(created.root) {
        return Err(fail(
            platform,
            &mut transaction,
            LoadStage::SuccessCleanup,
            cause,
        ));
    } else {
        transaction.root = None;
    }

    if let Err(cause) = platform.thread_start(
        thread,
        plan.entry,
        INITIAL_STACK.stack_pointer,
        created.child_bootstrap,
        image::STARTUP_ABI_VERSION,
    ) {
        return Err(fail(
            platform,
            &mut transaction,
            LoadStage::ThreadStart,
            cause,
        ));
    }
    if let Err(cause) = platform.close(thread) {
        let terminate_failed = platform.process_terminate(created.process).is_err();
        let rollback_failed = terminate_failed
            | platform.close(thread).is_err()
            | platform.close(created.process).is_err()
            | platform.close(parent_channel).is_err();
        return Err(platform_error(
            LoadStage::SuccessCleanup,
            cause,
            rollback_failed,
        ));
    }
    Ok(LoadedProcess {
        process: created.process,
        launch_channel: parent_channel,
    })
}

fn fail<P: LoaderPlatform>(
    platform: &mut P,
    transaction: &mut Transaction,
    stage: LoadStage,
    cause: P::Error,
) -> LoadError<P::Error> {
    let rollback_failed = transaction.rollback(platform);
    platform_error(stage, cause, rollback_failed)
}

fn platform_error<E>(stage: LoadStage, cause: E, rollback_failed: bool) -> LoadError<E> {
    LoadError::Platform {
        stage,
        cause,
        rollback_failed,
    }
}

const fn native_protection(protection: SegmentProtection) -> DwMemoryProtection {
    match protection {
        SegmentProtection::Read => DW_MEMORY_PROTECTION_READ,
        SegmentProtection::ReadWrite => {
            DwMemoryProtection(DW_MEMORY_PROTECTION_READ.0 | DW_MEMORY_PROTECTION_WRITE.0)
        }
        SegmentProtection::ReadExecute => {
            DwMemoryProtection(DW_MEMORY_PROTECTION_READ.0 | DW_MEMORY_PROTECTION_EXECUTE.0)
        }
    }
}

const fn transfer(handle: DwHandle, rights: DwRights) -> DwHandleTransferV1 {
    DwHandleTransferV1 {
        handle,
        requested_rights: rights,
        operation: DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    }
}

const fn empty_segment() -> LoadSegment {
    LoadSegment {
        header_index: 0,
        file_offset: 0,
        file_size: 0,
        memory_size: 0,
        virtual_address: 0,
        mapping_start: 0,
        mapping_size: 0,
        leading_bytes: 0,
        protection: SegmentProtection::Read,
    }
}
