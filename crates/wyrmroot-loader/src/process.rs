//! Failure-atomic WYR0 child construction over an explicit platform boundary.

use deepwyrm_syscall::{
    DW_HANDLE_TRANSFER_MOVE, DW_MEMORY_PROTECTION_EXECUTE, DW_MEMORY_PROTECTION_READ,
    DW_MEMORY_PROTECTION_WRITE, DW_RIGHT_DUPLICATE, DW_RIGHT_EXECUTE, DW_RIGHT_INSPECT,
    DW_RIGHT_MAP, DW_RIGHT_MODIFY, DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DW_RIGHT_WRITE,
    DwHandle, DwHandleTransferV1, DwMemoryProtection, DwRights,
};
use wyrmroot_registry_proto::CorrelationEnvironment;

use crate::{
    elf::{self, ElfError, LoadSegment, MAX_LOAD_SEGMENTS, PAGE_SIZE, SegmentProtection},
    image::{self, INITIAL_STACK, MaterializationPlan, StartupBlockError},
    launch::{
        self, BOOTFS_RIGHTS, DEVICE_COORDINATOR_BYTES, LOADER_TASK_GROUP_RIGHTS, LaunchError,
        LaunchProfile, SELF_ROOT_RIGHTS,
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

/// WYR1-B launch request using startup ABI v2 and the WRLP 1.3 JobV2 profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobLoadRequest<'a> {
    pub image: &'a [u8],
    pub policy_path: &'a str,
    pub argv: &'a [&'a str],
    pub environment: &'a [&'a str],
    /// Zero or exactly three owned Channel endpoints in stdin, stdout,
    /// stderr order.
    pub streams: &'a [DwHandle],
    pub transaction_id: u64,
}

/// WYR1-B bootstrap child request carrying one controller-issued endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceLoadRequest<'a> {
    pub image: &'a [u8],
    pub display_path: &'a str,
    pub profile: LaunchProfile,
    pub service_channel: DwHandle,
    /// Present exactly for BootstrapService and RegistryClient. The typed
    /// value prevents arbitrary environment injection at the loader boundary.
    pub correlation: Option<&'a CorrelationEnvironment>,
    pub transaction_id: u64,
}

/// WYR1-C device-coordinator launch request.  The publication endpoint and
/// manifest are caller-owned until the INIT Channel MOVE succeeds; on a
/// failed send the loader leaves both with the caller for one cleanup path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceCoordinatorLoadRequest<'a> {
    pub image: &'a [u8],
    pub display_path: &'a str,
    pub publication_endpoint: DwHandle,
    pub manifest: DwHandle,
    pub supervisor_generation: u64,
    pub transaction_id: u64,
}

#[derive(Clone, Copy)]
enum StartupSpec<'a> {
    Legacy(&'a str),
    JobV2 {
        path: &'a str,
        argv: &'a [&'a str],
        environment: &'a [&'a str],
    },
}

enum StartupMaterialization<'a> {
    Legacy(&'a [u8]),
    JobV2(image::StartupBlockV2Plan<'a>),
}

#[derive(Clone, Copy)]
struct InternalLoadRequest<'a> {
    image: &'a [u8],
    profile: LaunchProfile,
    transaction_id: u64,
    startup: StartupSpec<'a>,
    channels: &'a [DwHandle],
    device_manifest: Option<DwHandle>,
    supervisor_generation: Option<u64>,
}

/// Explicitly selected, test-only corruption of one child-launch boundary.
///
/// Production callers use [`load_process`], which always selects
/// [`LoadFault::None`].  The malformed-ELF case exercises the ordinary parser
/// on a test-synthesized invalid header; every other fault is applied only
/// after the ordinary loader has validated the input ELF and constructed the
/// ordinary startup/INIT records.  A negative variant therefore cannot
/// silently change normal image construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadFault {
    None,
    MalformedElf,
    MalformedStartup,
    InitCapabilityCount,
    InitCapabilityType,
    InitCapabilityRights,
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

/// Service-launch failure with explicit ownership of the caller-supplied
/// service endpoint at the atomic INIT boundary.
#[derive(Debug, Eq, PartialEq)]
pub struct ServiceLoadError<PlatformError> {
    pub error: LoadError<PlatformError>,
    pub service_channel_consumed: bool,
}

/// Job-launch failure with explicit ownership of the caller-supplied stream
/// endpoints at the atomic INIT boundary.
#[derive(Debug, Eq, PartialEq)]
pub struct JobLoadError<PlatformError> {
    pub error: LoadError<PlatformError>,
    pub streams_consumed: bool,
}

impl<E> JobLoadError<E> {
    const fn caller_retains(error: LoadError<E>) -> Self {
        Self {
            error,
            streams_consumed: false,
        }
    }
}

impl<E> ServiceLoadError<E> {
    const fn caller_retains(error: LoadError<E>) -> Self {
        Self {
            error,
            service_channel_consumed: false,
        }
    }
}

/// Device-coordinator launch failure with explicit ownership of both caller
/// inputs at the atomic INIT boundary.
#[derive(Debug, Eq, PartialEq)]
pub struct DeviceCoordinatorLoadError<PlatformError> {
    pub error: LoadError<PlatformError>,
    pub publication_endpoint_consumed: bool,
    pub manifest_consumed: bool,
}

impl<E> DeviceCoordinatorLoadError<E> {
    const fn caller_retains(error: LoadError<E>) -> Self {
        Self {
            error,
            publication_endpoint_consumed: false,
            manifest_consumed: false,
        }
    }
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
    ) -> Result<ParentMapping, Self::Error> {
        self.materialize_parent_with(
            parent_root,
            memory,
            object_size,
            destination_offset,
            source.len(),
            |destination| destination.copy_from_slice(source),
        )
    }
    /// Maps and zeroes the complete object, then lends only the checked
    /// destination extent to one bounded, non-escaping materializer.
    fn materialize_parent_with(
        &mut self,
        parent_root: DwHandle,
        memory: DwHandle,
        object_size: u64,
        destination_offset: u64,
        destination_size: usize,
        materialize: impl FnOnce(&mut [u8]),
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
    delegated_channels: [Option<DwHandle>; 3],
    delegated_manifest: Option<DwHandle>,
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
            delegated_channels: [None; 3],
            delegated_manifest: None,
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
        let root = self.root.take();
        if let Some(root) = root {
            // A successful termination of this transaction's sole child
            // thread also exits its Process.  Tear down child mappings first:
            // the live address-space target ceases to accept them once that
            // Process is terminal.
            while self.range_count != 0 {
                self.range_count -= 1;
                let range = self.ranges[self.range_count];
                failed |= platform
                    .unmap_child(root, range.address, range.bytes)
                    .is_err();
            }
        }
        let thread_terminated = self.thread.take().map(|thread| {
            let thread_terminated = platform.thread_terminate(thread).is_ok();
            failed |= platform.close(thread).is_err();
            thread_terminated
        });
        if let Some(root) = root {
            failed |= platform.close(root).is_err();
        }
        if let Some(process) = self.process.take() {
            let terminated =
                thread_terminated == Some(true) || platform.process_terminate(process).is_ok();
            failed |= !terminated;
            failed |= platform.close(process).is_err();
        }
        for handle in [
            self.scratch_memory.take(),
            self.delegated_task_group.take(),
            self.delegated_bootfs.take(),
            self.delegated_channels[0].take(),
            self.delegated_channels[1].take(),
            self.delegated_channels[2].take(),
            self.delegated_manifest.take(),
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
    load_process_with_fault(platform, authority, request, LoadFault::None)
}

/// Runs one child-construction transaction with an explicitly test-selected
/// malformed-input boundary.
///
/// This is intentionally separate from [`load_process`] so production call
/// sites cannot opt into a negative behavior accidentally.
pub fn load_process_with_fault<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: LoadRequest<'_>,
    fault: LoadFault,
) -> Result<LoadedProcess, LoadError<P::Error>> {
    let mut delegated_channels_consumed = false;
    load_process_internal(
        platform,
        authority,
        InternalLoadRequest {
            image: request.image,
            profile: request.profile,
            transaction_id: request.transaction_id,
            startup: StartupSpec::Legacy(request.display_path),
            channels: &[],
            device_manifest: None,
            supervisor_generation: None,
        },
        fault,
        &mut delegated_channels_consumed,
    )
}

/// Loads one policy-authorized WYR1-B job with startup ABI v2.
pub fn load_job_process<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: JobLoadRequest<'_>,
) -> Result<LoadedProcess, JobLoadError<P::Error>> {
    let profile = match request.streams.len() {
        0 => LaunchProfile::JobV2,
        3 => LaunchProfile::JobV2Streams,
        _ => {
            return Err(JobLoadError::caller_retains(LoadError::Launch(
                LaunchError::HandleCount,
            )));
        }
    };
    let mut delegated_channels_consumed = false;
    load_process_internal(
        platform,
        authority,
        InternalLoadRequest {
            image: request.image,
            profile,
            transaction_id: request.transaction_id,
            startup: StartupSpec::JobV2 {
                path: request.policy_path,
                argv: request.argv,
                environment: request.environment,
            },
            channels: request.streams,
            device_manifest: None,
            supervisor_generation: None,
        },
        LoadFault::None,
        &mut delegated_channels_consumed,
    )
    .map_err(|error| JobLoadError {
        error,
        streams_consumed: delegated_channels_consumed,
    })
}

/// Loads one WYR1-B registry, publisher, or client using the exact
/// profile-specific controller endpoint as the second WRLP capability.
pub fn load_service_process<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: ServiceLoadRequest<'_>,
) -> Result<LoadedProcess, ServiceLoadError<P::Error>> {
    if request.profile.channel_role().is_none() {
        return Err(ServiceLoadError::caller_retains(LoadError::Launch(
            LaunchError::HandleCount,
        )));
    }
    let channels = [request.service_channel];
    let uses_correlation = matches!(
        request.profile,
        LaunchProfile::BootstrapService | LaunchProfile::RegistryClient
    );
    let argv = [request.display_path];
    let mut environment = [""; wyrmroot_registry_proto::CORRELATION_ENVIRONMENT_COUNT];
    let startup = if uses_correlation {
        let correlation = request.correlation.ok_or_else(|| {
            ServiceLoadError::caller_retains(LoadError::Startup(
                StartupBlockError::InvalidEnvironment,
            ))
        })?;
        for (index, slot) in environment.iter_mut().enumerate() {
            *slot = correlation.entry(index).ok_or_else(|| {
                ServiceLoadError::caller_retains(LoadError::Startup(
                    StartupBlockError::InvalidEnvironment,
                ))
            })?;
        }
        StartupSpec::JobV2 {
            path: request.display_path,
            argv: &argv,
            environment: &environment,
        }
    } else if request.correlation.is_none() {
        StartupSpec::Legacy(request.display_path)
    } else {
        return Err(ServiceLoadError::caller_retains(LoadError::Startup(
            StartupBlockError::TooManyArguments,
        )));
    };
    let mut service_channel_consumed = false;
    load_process_internal(
        platform,
        authority,
        InternalLoadRequest {
            image: request.image,
            profile: request.profile,
            transaction_id: request.transaction_id,
            startup,
            channels: &channels,
            device_manifest: None,
            supervisor_generation: None,
        },
        LoadFault::None,
        &mut service_channel_consumed,
    )
    .map_err(|error| ServiceLoadError {
        error,
        service_channel_consumed,
    })
}

/// Launch the hardware-independent WYR1-C device coordinator.  Exactly one
/// publication Channel and one immutable WRDM MemoryObject are moved beside
/// the child self-root; no loader or hardware authority is included.
pub fn load_device_coordinator_process<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: DeviceCoordinatorLoadRequest<'_>,
) -> Result<LoadedProcess, DeviceCoordinatorLoadError<P::Error>> {
    if request.publication_endpoint == request.manifest || request.supervisor_generation == 0 {
        return Err(DeviceCoordinatorLoadError::caller_retains(
            LoadError::Launch(LaunchError::HandleCount),
        ));
    }
    let channels = [request.publication_endpoint];
    let mut inputs_consumed = false;
    load_process_internal(
        platform,
        authority,
        InternalLoadRequest {
            image: request.image,
            profile: LaunchProfile::DeviceCoordinator,
            transaction_id: request.transaction_id,
            startup: StartupSpec::Legacy(request.display_path),
            channels: &channels,
            device_manifest: Some(request.manifest),
            supervisor_generation: Some(request.supervisor_generation),
        },
        LoadFault::None,
        &mut inputs_consumed,
    )
    .map_err(|error| DeviceCoordinatorLoadError {
        error,
        publication_endpoint_consumed: inputs_consumed,
        manifest_consumed: inputs_consumed,
    })
}

fn load_process_internal<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: InternalLoadRequest<'_>,
    fault: LoadFault,
    delegated_channels_consumed: &mut bool,
) -> Result<LoadedProcess, LoadError<P::Error>> {
    let expected_channels = if request.profile.channel_role().is_some()
        || request.profile == LaunchProfile::DeviceCoordinator
    {
        1
    } else if request.profile == LaunchProfile::JobV2Streams {
        3
    } else {
        0
    };
    if request.channels.len() != expected_channels {
        return Err(LoadError::Launch(LaunchError::HandleCount));
    }
    if (request.profile == LaunchProfile::DeviceCoordinator) != request.device_manifest.is_some() {
        return Err(LoadError::Launch(LaunchError::HandleCount));
    }
    let mut segments = [empty_segment(); MAX_LOAD_SEGMENTS];
    if fault == LoadFault::MalformedElf {
        let malformed = [0_u8; 64];
        return match elf::plan(&malformed, &mut segments) {
            Err(error) => Err(LoadError::Elf(error)),
            Ok(_) => unreachable!("test malformed ELF was accepted"),
        };
    }
    let plan = elf::plan(request.image, &mut segments).map_err(LoadError::Elf)?;
    match request.startup {
        StartupSpec::Legacy(display_path) => load_legacy_process_materialized(
            platform,
            authority,
            request,
            display_path,
            fault,
            delegated_channels_consumed,
            plan,
        ),
        StartupSpec::JobV2 {
            path,
            argv,
            environment,
        } => load_job_v2_process_materialized(
            platform,
            authority,
            request,
            path,
            argv,
            environment,
            fault,
            delegated_channels_consumed,
            plan,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn load_legacy_process_materialized<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: InternalLoadRequest<'_>,
    display_path: &str,
    fault: LoadFault,
    delegated_channels_consumed: &mut bool,
    plan: elf::ElfLoadPlan<'_>,
) -> Result<LoadedProcess, LoadError<P::Error>> {
    let mut startup_block = [0_u8; PAGE_SIZE as usize];
    image::write_startup_block(
        &mut startup_block,
        image::INITIAL_STACK_POINTER,
        display_path,
    )
    .map_err(LoadError::Startup)?;
    apply_startup_fault(&mut startup_block, fault);
    load_process_materialized(
        platform,
        authority,
        request,
        fault,
        delegated_channels_consumed,
        plan,
        StartupMaterialization::Legacy(&startup_block),
        INITIAL_STACK.startup_page_offset,
        INITIAL_STACK.stack_pointer,
        image::STARTUP_ABI_VERSION,
    )
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn load_job_v2_process_materialized<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: InternalLoadRequest<'_>,
    path: &str,
    argv: &[&str],
    environment: &[&str],
    fault: LoadFault,
    delegated_channels_consumed: &mut bool,
    plan: elf::ElfLoadPlan<'_>,
) -> Result<LoadedProcess, LoadError<P::Error>> {
    let startup = image::StartupBlockV2Plan::new(
        image::STARTUP_V2_BLOCK_BYTES,
        image::STARTUP_V2_BLOCK_ADDRESS,
        path,
        argv,
        environment,
    )
    .map_err(LoadError::Startup)?;
    load_process_materialized(
        platform,
        authority,
        request,
        fault,
        delegated_channels_consumed,
        plan,
        StartupMaterialization::JobV2(startup),
        INITIAL_STACK.object_size - image::STARTUP_V2_BLOCK_BYTES as u64,
        image::STARTUP_V2_BLOCK_ADDRESS,
        image::STARTUP_ABI_V2,
    )
}

#[allow(clippy::too_many_arguments)]
fn load_process_materialized<P: LoaderPlatform>(
    platform: &mut P,
    authority: LoadAuthority,
    request: InternalLoadRequest<'_>,
    fault: LoadFault,
    delegated_channels_consumed: &mut bool,
    plan: elf::ElfLoadPlan<'_>,
    startup: StartupMaterialization<'_>,
    startup_offset: u64,
    stack_pointer: u64,
    startup_abi: u64,
) -> Result<LoadedProcess, LoadError<P::Error>> {
    let mut init = [0_u8; DEVICE_COORDINATOR_BYTES];
    let init_len = if request.profile == LaunchProfile::DeviceCoordinator {
        launch::encode_device_coordinator_init(
            request.transaction_id,
            request
                .supervisor_generation
                .ok_or(LoadError::Launch(LaunchError::ZeroTransaction))?,
            &mut init,
        )
    } else {
        launch::encode_init(request.profile, request.transaction_id, &mut init)
    }
    .map_err(LoadError::Launch)?;
    apply_init_fault(&mut init[..init_len], fault);

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
    let materialized = match startup {
        StartupMaterialization::Legacy(startup_block) => platform.materialize_parent(
            authority.parent_root,
            stack,
            INITIAL_STACK.object_size,
            startup_offset,
            startup_block,
        ),
        StartupMaterialization::JobV2(startup) => platform.materialize_parent_with(
            authority.parent_root,
            stack,
            INITIAL_STACK.object_size,
            startup_offset,
            image::STARTUP_V2_BLOCK_BYTES,
            |block| {
                startup.write(block);
                apply_startup_fault(block, fault);
            },
        ),
    };
    let parent_mapping = match materialized {
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
    let transfer_count = if request.profile.has_loader_authority_trio() {
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
    } else if request.profile == LaunchProfile::Dw1bProgress {
        transaction.delegated_channels[0] = Some(request.channels[0]);
        transfers[0] = transfer(request.channels[0], launch::CHILD_CHANNEL_RIGHTS);
        1
    } else if request.profile == LaunchProfile::DeviceCoordinator {
        let manifest = request
            .device_manifest
            .ok_or(LoadError::Launch(LaunchError::HandleCount))?;
        transaction.delegated_channels[0] = Some(request.channels[0]);
        transaction.delegated_manifest = Some(manifest);
        transfers[0] = transfer(created.root, SELF_ROOT_RIGHTS);
        transfers[1] = transfer(request.channels[0], launch::CHILD_CHANNEL_RIGHTS);
        transfers[2] = transfer(manifest, launch::DEVICE_MANIFEST_RIGHTS);
        3
    } else if request.profile.channel_role().is_some() {
        transaction.delegated_channels[0] = Some(request.channels[0]);
        transfers[0] = transfer(created.root, SELF_ROOT_RIGHTS);
        transfers[1] = transfer(request.channels[0], launch::CHILD_CHANNEL_RIGHTS);
        2
    } else if request.profile.needs_self_root() {
        // WYR0-I probe children receive only their own mapping authority at
        // startup. Shared MemoryObjects are a typed controller protocol after
        // startup, not a loader launch capability.
        transfers[0] = transfer(created.root, SELF_ROOT_RIGHTS);
        1
    } else if request.profile == LaunchProfile::JobV2Streams {
        for (index, handle) in request.channels.iter().copied().enumerate() {
            transaction.delegated_channels[index] = Some(handle);
            transfers[index] = transfer(handle, launch::CHILD_CHANNEL_RIGHTS);
        }
        3
    } else {
        0
    };
    apply_capability_fault(&mut transfers[..transfer_count], fault);

    if let Err(cause) = platform.send_init(
        parent_channel,
        &init[..init_len],
        &transfers[..transfer_count],
    ) {
        // A failed MOVE consumes nothing. Stream endpoints originate with the
        // caller, so it retains every externally supplied endpoint for one
        // exact cleanup path rather than letting loader rollback take partial
        // ownership.
        for delegated in &mut transaction.delegated_channels {
            *delegated = None;
        }
        transaction.delegated_manifest = None;
        return Err(fail(platform, &mut transaction, LoadStage::InitSend, cause));
    }
    // Successful Channel send consumed every externally supplied endpoint.
    *delegated_channels_consumed = !request.channels.is_empty();
    for delegated in &mut transaction.delegated_channels {
        *delegated = None;
    }
    transaction.delegated_manifest = None;
    if request.profile.needs_self_root() {
        transaction.root = None;
        if request.profile.has_loader_authority_trio() {
            transaction.delegated_bootfs = None;
            transaction.delegated_task_group = None;
        }
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
        stack_pointer,
        created.child_bootstrap,
        startup_abi,
    ) {
        return Err(fail(
            platform,
            &mut transaction,
            LoadStage::ThreadStart,
            cause,
        ));
    }
    if let Err(cause) = platform.close(thread) {
        let process_terminated = platform.process_terminate(created.process).is_ok();
        let thread_terminated = !process_terminated && platform.thread_terminate(thread).is_ok();
        let rollback_failed = !(process_terminated || thread_terminated)
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

fn apply_startup_fault(startup_page: &mut [u8], fault: LoadFault) {
    if fault == LoadFault::MalformedStartup {
        // WYR0-D0 requires argc = 1 for every native child.  The page was
        // otherwise built by the canonical checked constructor above.
        startup_page[..8].copy_from_slice(&2_u64.to_le_bytes());
    }
}

fn apply_init_fault(init: &mut [u8], fault: LoadFault) {
    if fault == LoadFault::InitCapabilityCount {
        // Offset 20 is the locked little-endian WRLP capability-count field.
        // The actual Channel transfer count remains three, so the child must
        // reject both inconsistent representations before using authority.
        init[20..24].copy_from_slice(&2_u32.to_le_bytes());
    }
}

fn apply_capability_fault(transfers: &mut [DwHandleTransferV1], fault: LoadFault) {
    match fault {
        LoadFault::InitCapabilityType if transfers.len() == 3 => transfers.swap(0, 2),
        LoadFault::InitCapabilityRights if !transfers.is_empty() => {
            transfers[0].requested_rights = ROOT_RIGHTS;
        }
        _ => {}
    }
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
