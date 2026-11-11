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
        self, BOOTFS_RIGHTS, LOADER_TASK_GROUP_RIGHTS, LaunchError, LaunchProfile, SELF_ROOT_RIGHTS,
    },
};

mod entry_points;
mod materialize;
pub use entry_points::*;
use materialize::*;

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

/// Explicit D5 `/system/init` request. Resource-domain custody is carried
/// beside ordinary load authority and cannot be substituted for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceDomainLoadRequest<'a> {
    pub image: &'a [u8],
    pub display_path: &'a str,
    pub resource_domain: DwHandle,
    pub transaction_id: u64,
}

/// Selector-30-only owner launch. The owner is created inside the supplied
/// resource domain and receives only its reduced claim authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D6ResourceOwnerLoadRequest<'a> {
    pub image: &'a [u8],
    pub display_path: &'a str,
    pub resource_domain: DwHandle,
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

/// WRLP 1.3 launch-client request: one self root, one launch-session endpoint,
/// and startup ABI v2 so the child receives its plan arguments.
///
/// `ServiceLoadRequest` cannot express this launch. It builds the correlation
/// environment only for `BootstrapService` and `RegistryClient`, and otherwise
/// selects the legacy startup block, which carries no argv tail at all. A
/// launch client is correlated to its *launch session* rather than to a
/// registry endpoint, and its arguments are part of what it is launched to do,
/// so both belong in a request of its own instead of widening that one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaunchClientLoadRequest<'a> {
    pub image: &'a [u8],
    pub display_path: &'a str,
    pub launch_session: DwHandle,
    /// Arguments after `argv[0]`, which is always the display path.
    pub arguments: &'a [&'a str],
    /// The launch session's own correlation. The capability record and the
    /// received handle metadata remain authoritative; these three entries only
    /// let the child name the session it was given.
    pub correlation: &'a CorrelationEnvironment,
    pub transaction_id: u64,
}

/// WYR1-D4 console-broker launch request. The two endpoints are distinct,
/// caller-owned staging capabilities until the atomic INIT MOVE commits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoledLoadRequest<'a> {
    pub image: &'a [u8],
    pub display_path: &'a str,
    pub registry_endpoint: DwHandle,
    pub registry_generation: u64,
    pub registry_endpoint_id: u64,
    pub registry_endpoint_generation: u64,
    pub launch_endpoint: DwHandle,
    pub launch_connection_id: u64,
    pub launch_connection_generation: u64,
    pub transaction_id: u64,
}

/// WYR1-E shell construction request. All six caller-owned Channels move in
/// one atomic INIT send after exact path, handle, and correlation validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WyrmshLoadRequest<'a> {
    pub image: &'a [u8],
    pub stdin: DwHandle,
    pub stdout: DwHandle,
    pub stderr: DwHandle,
    pub console_status: DwHandle,
    pub registry_client: DwHandle,
    pub launch_session: DwHandle,
    pub registry_generation: u64,
    pub registry_endpoint_id: u64,
    pub registry_endpoint_generation: u64,
    pub launch_connection_id: u64,
    pub launch_connection_generation: u64,
    pub console_generation: u64,
    pub status_generation: u64,
    pub child_generation: u64,
    pub outer_launch_transaction: u64,
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

/// WYR1-C4 device-coordinator launch. The broad resource-domain custodian is
/// never moved; the loader stages one duplicate and atomically MOVEs only
/// `RESOURCE | INSPECT` into the exact coordinator generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceCoordinatorResourceLoadRequest<'a> {
    pub image: &'a [u8],
    pub display_path: &'a str,
    pub publication_endpoint: DwHandle,
    pub manifest: DwHandle,
    pub resource_domain: DwHandle,
    pub supervisor_generation: u64,
    pub transaction_id: u64,
}

/// C3 driver construction request.  The supplied Channel is the child half
/// of a fresh direct pair; no resource bundle crosses this API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceDriverLoadRequest<'a> {
    pub image: &'a [u8],
    pub display_path: &'a str,
    pub control_endpoint: DwHandle,
    pub supervisor_generation: u64,
    pub role_id: u64,
    pub attempt_generation: u64,
    pub launch_session: u64,
    pub endpoint_id: u64,
    pub endpoint_generation: u64,
    pub transaction_id: u64,
}

/// A bootfs service role's construction (root `STORAGE_PLAN.md` W6). The
/// Channel is the child's end of init's control pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceRoleLoadRequest<'a> {
    pub image: &'a [u8],
    pub display_path: &'a str,
    pub control_endpoint: DwHandle,
    pub role_id: u64,
    pub attempt_generation: u64,
    pub transaction_id: u64,
}

#[derive(Clone, Copy)]
pub(crate) enum StartupSpec<'a> {
    Legacy(&'a str),
    JobV2 {
        path: &'a str,
        argv: &'a [&'a str],
        environment: &'a [&'a str],
    },
}

pub(crate) enum StartupMaterialization<'a> {
    Legacy(&'a [u8]),
    JobV2(image::StartupBlockV2Plan<'a>),
}

#[derive(Clone, Copy)]
pub(crate) struct WyrmshCorrelation {
    registry_generation: u64,
    registry_endpoint_id: u64,
    registry_endpoint_generation: u64,
    launch_connection_id: u64,
    launch_connection_generation: u64,
    console_generation: u64,
    status_generation: u64,
    child_generation: u64,
    outer_launch_transaction: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct InternalLoadRequest<'a> {
    image: &'a [u8],
    profile: LaunchProfile,
    transaction_id: u64,
    startup: StartupSpec<'a>,
    channels: &'a [DwHandle],
    device_manifest: Option<DwHandle>,
    supervisor_generation: Option<u64>,
    driver_correlation: Option<(u64, u64, u64, u64, u64, u64)>,
    consoled_correlation: Option<(u64, u64, u64, u64, u64)>,
    wyrmsh_correlation: Option<WyrmshCorrelation>,
    resource_domain: Option<DwHandle>,
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

/// Launch-client failure with explicit ownership of the caller-supplied
/// launch-session endpoint at the atomic INIT boundary.
#[derive(Debug, Eq, PartialEq)]
pub struct LaunchClientLoadError<PlatformError> {
    pub error: LoadError<PlatformError>,
    pub launch_session_consumed: bool,
}

impl<E> LaunchClientLoadError<E> {
    const fn caller_retains(error: LoadError<E>) -> Self {
        Self {
            error,
            launch_session_consumed: false,
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

#[derive(Debug, Eq, PartialEq)]
pub struct DeviceDriverLoadError<PlatformError> {
    pub error: LoadError<PlatformError>,
    pub control_endpoint_consumed: bool,
}

/// D4 consoled-launch failure with exact ownership at the all-or-nothing INIT
/// MOVE boundary.
#[derive(Debug, Eq, PartialEq)]
pub struct ConsoledLoadError<PlatformError> {
    pub error: LoadError<PlatformError>,
    pub registry_endpoint_consumed: bool,
    pub launch_endpoint_consumed: bool,
}

/// WYR1-E shell-load failure with explicit all-six endpoint custody at the
/// atomic INIT boundary.
#[derive(Debug, Eq, PartialEq)]
pub struct WyrmshLoadError<PlatformError> {
    pub error: LoadError<PlatformError>,
    pub stdin_consumed: bool,
    pub stdout_consumed: bool,
    pub stderr_consumed: bool,
    pub console_status_consumed: bool,
    pub registry_client_consumed: bool,
    pub launch_session_consumed: bool,
}

impl<E> WyrmshLoadError<E> {
    const fn with_custody(error: LoadError<E>, consumed: bool) -> Self {
        Self {
            error,
            stdin_consumed: consumed,
            stdout_consumed: consumed,
            stderr_consumed: consumed,
            console_status_consumed: consumed,
            registry_client_consumed: consumed,
            launch_session_consumed: consumed,
        }
    }
}

impl<E> ConsoledLoadError<E> {
    const fn caller_retains(error: LoadError<E>) -> Self {
        Self {
            error,
            registry_endpoint_consumed: false,
            launch_endpoint_consumed: false,
        }
    }
}

impl<E> DeviceDriverLoadError<E> {
    const fn caller_retains(error: LoadError<E>) -> Self {
        Self {
            error,
            control_endpoint_consumed: false,
        }
    }
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
pub(crate) struct Range {
    address: u64,
    bytes: u64,
}

pub(crate) struct Transaction {
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
    delegated_resource_domain: Option<DwHandle>,
    delegated_channels: [Option<DwHandle>; launch::MAX_CAPABILITIES],
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
            delegated_resource_domain: None,
            delegated_channels: [None; launch::MAX_CAPABILITIES],
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
            self.delegated_resource_domain.take(),
            self.delegated_bootfs.take(),
        ]
        .into_iter()
        .flatten()
        {
            failed |= platform.close(handle).is_err();
        }
        for slot in &mut self.delegated_channels {
            if let Some(handle) = slot.take() {
                failed |= platform.close(handle).is_err();
            }
        }
        for handle in [
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
