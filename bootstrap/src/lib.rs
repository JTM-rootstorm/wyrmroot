#![no_std]
#![forbid(unsafe_code)]

//! Primordial Wyrmroot bootstrap transaction shared by the native entry and host fixtures.

#[cfg(any(
    all(
        feature = "primordial-blocking-cleanup",
        feature = "primordial-user-exception"
    ),
    all(
        feature = "primordial-blocking-cleanup",
        feature = "primordial-invalid-return"
    ),
    all(
        feature = "primordial-user-exception",
        feature = "primordial-invalid-return"
    )
))]
compile_error!("primordial bootstrap behavior variants are mutually exclusive");

#[cfg(any(
    all(
        feature = "loader-smoke-integration",
        feature = "primordial-blocking-cleanup"
    ),
    all(
        feature = "loader-smoke-integration",
        feature = "primordial-user-exception"
    ),
    all(
        feature = "loader-smoke-integration",
        feature = "primordial-invalid-return"
    )
))]
compile_error!(
    "the WYR0-E loader-smoke integration is mutually exclusive with primordial behavior variants"
);

#[cfg(feature = "loader-smoke-integration")]
use deepwyrm_syscall::DwDeadline;
use deepwyrm_syscall::{DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights};
use wyrmroot_bootfs::archive::{Archive, LookupError, ParseError};
use wyrmroot_bootstrap_proto::{
    BOOTSTRAP_INIT_V2_SIZE, BOOTSTRAP_READY_V2_SIZE, BootstrapMessage, DecodeError, InitMessageV2,
    MAX_BOOTSTRAP_HANDLES, ReadyMessageV2, decode,
};
#[cfg(feature = "loader-smoke-integration")]
use wyrmroot_loader::{
    launch::LaunchProfile,
    process::{LoadAuthority, LoadError, LoadRequest, LoadedProcess, LoaderPlatform, load_process},
};
#[cfg(feature = "primordial-test-support")]
use wyrmroot_runtime::PrimordialTestError;
use wyrmroot_runtime::{
    BOOTFS_EXPECTATION, BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, CapabilityValidationError,
    InitCapability, LOADER_TASK_GROUP_EXPECTATION, MappingPlan, MappingPlanError, NativeError,
    ReceiveCounts, SELF_ROOT_EXPECTATION, validate_bootstrap_channel,
    validate_init_capabilities_v2,
};
#[cfg(feature = "loader-smoke-integration")]
use wyrmroot_runtime::{SupervisionError, SupervisionPlatform, supervise_child};

/// Canonical init executable required in the primordial bootfs.
pub const INIT0_PATH: &[u8] = b"system/init0";
/// Canonical smoke executable required in the primordial bootfs.
pub const HELLO_PATH: &[u8] = b"bin/hello";
/// E-only temporary native loader probe. This is not an init0 policy entry.
#[cfg(feature = "loader-smoke-integration")]
pub const LOADER_SMOKE_PATH: &[u8] = b"test/loader-smoke";
/// Distinct nonzero WRLP transaction identifier used by the temporary E-only child.
#[cfg(feature = "loader-smoke-integration")]
pub const LOADER_SMOKE_TRANSACTION_ID: u64 = 2;

/// Native operations used by the shared bootstrap transaction.
pub trait BootstrapSystem {
    /// Queries fresh basic object metadata.
    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError>;

    /// Receives one complete Channel datagram.
    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError>;

    /// Queries an immutable MemoryObject's exact logical size.
    fn query_memory_object_size(&mut self, handle: DwHandle) -> Result<u64, NativeError>;

    /// Maps the bootfs for one non-escaping logical-byte callback, then unmaps it.
    fn with_bootfs_bytes<R>(
        &mut self,
        root_region: DwHandle,
        bootfs: DwHandle,
        plan: MappingPlan,
        use_bytes: impl for<'bytes> FnOnce(&'bytes [u8]) -> R,
    ) -> Result<R, NativeError>;

    /// Sends one handle-free Channel datagram.
    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError>;

    /// Closes one caller-local handle.
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError>;
}

/// Why the primordial bootstrap transaction failed.
#[derive(Debug, Eq, PartialEq)]
pub enum BootstrapError {
    /// A native Deepwyrm operation failed or returned malformed output.
    Native(NativeError),
    /// The startup Channel did not have its exact type and rights.
    BootstrapChannel(CapabilityValidationError),
    /// INIT bytes or handle counts violated the locked protocol.
    Protocol(DecodeError),
    /// A valid protocol message was not the single expected INIT message.
    UnexpectedMessage,
    /// INIT used a nonzero transaction identifier other than the G0 primordial value `1`.
    UnexpectedTransactionId,
    /// Received or freshly queried capability metadata violated the exact role contract.
    Capability(CapabilityValidationError),
    /// The bootfs logical size could not produce a bounded mapping.
    Mapping(MappingPlanError),
    /// The mapped bootfs archive was malformed.
    Bootfs(ParseError),
    /// A required canonical bootfs entry was absent.
    MissingRequiredEntry,
    /// A required bootfs entry was not immutable executable content.
    RequiredEntryNotExecutable,
    /// An explicitly selected primordial kernel-test behavior failed closed.
    #[cfg(feature = "primordial-test-support")]
    TestSupport(PrimordialTestError),
    /// The E-only loader transaction failed before it published the temporary child.
    #[cfg(feature = "loader-smoke-integration")]
    Loader(LoadError<NativeError>),
    /// Temporary WYR0-E child readiness or completion did not satisfy the exact contract.
    #[cfg(feature = "loader-smoke-integration")]
    Supervision(SupervisionError<NativeError>),
    /// Cleanup of an already-published temporary child failed.
    #[cfg(feature = "loader-smoke-integration")]
    Cleanup(NativeError),
    /// A successful bootfs callback failed to retain the child it created.
    #[cfg(feature = "loader-smoke-integration")]
    MissingLoadedProcess,
}

/// Executes the complete D2 bootstrap handshake without exiting the process.
pub fn run_bootstrap<System: BootstrapSystem>(
    system: &mut System,
    bootstrap_channel: DwHandle,
) -> Result<(), BootstrapError> {
    run_bootstrap_inner(system, bootstrap_channel, |_| Ok(()))
}

/// Runs the WYR0-E-only loader-smoke transaction before primordial READY.
///
/// This path launches only `test/loader-smoke` with the handle-free `Hello` profile.  It neither
/// starts `system/init0` nor establishes an init policy; later WYR0 phases own that behavior.
/// The caller supplies separate platform adapters so bootfs mapping can remain borrowed only for
/// ELF construction while readiness and completion observation remain fully host-testable.
#[cfg(feature = "loader-smoke-integration")]
pub fn run_loader_smoke_bootstrap<
    System: BootstrapSystem,
    Loader: LoaderPlatform<Error = NativeError>,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    loader: &mut Loader,
    supervisor: &mut Supervisor,
    bootstrap_channel: DwHandle,
    deadline: DwDeadline,
) -> Result<(), BootstrapError> {
    let channel_info = system
        .query_capability_info(bootstrap_channel)
        .map_err(BootstrapError::Native)?;
    validate_bootstrap_channel(channel_info, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(BootstrapError::BootstrapChannel)?;

    let mut bytes = [0_u8; BOOTSTRAP_INIT_V2_SIZE];
    let mut handles = [DwReceivedHandleInfoV1::default(); MAX_BOOTSTRAP_HANDLES];
    let counts = system
        .receive_channel(bootstrap_channel, &mut bytes, &mut handles)
        .map_err(BootstrapError::Native)?;

    let operation = (|| {
        let transaction_id =
            expected_primordial_transaction(&bytes[..counts.bytes], counts.handles)?;
        let authority = validated_load_authority(system, &handles[..counts.handles])?;
        let plan = bootfs_mapping_plan(system, authority.bootfs)?;
        let mut loaded = None;
        let mapped =
            system.with_bootfs_bytes(authority.parent_root, authority.bootfs, plan, |bootfs| {
                match load_loader_smoke(loader, authority, bootfs) {
                    Ok(candidate) => {
                        loaded = Some(candidate);
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            });
        let loaded = match (mapped, loaded) {
            (Ok(Ok(())), Some(loaded)) => loaded,
            (Ok(Err(error)), _) => return Err(error),
            (Err(error), Some(loaded)) => {
                if let Err(cleanup) = cleanup_loaded_process(system, loader, loaded, true) {
                    return Err(BootstrapError::Cleanup(cleanup));
                }
                return Err(BootstrapError::Native(error));
            }
            (Err(error), None) => return Err(BootstrapError::Native(error)),
            (Ok(Ok(())), None) => return Err(BootstrapError::MissingLoadedProcess),
        };
        let supervision = supervise_child(
            supervisor,
            loaded.process,
            loaded.launch_channel,
            LOADER_SMOKE_TRANSACTION_ID,
            deadline,
        );
        let loaded_cleanup = cleanup_loaded_process(system, loader, loaded, supervision.is_err());
        if let Err(cleanup) = loaded_cleanup {
            return Err(BootstrapError::Cleanup(cleanup));
        }
        supervision.map_err(BootstrapError::Supervision)?;
        Ok(transaction_id)
    })();
    let cleanup = close_received_handles(system, &handles[..counts.handles]);
    let transaction_id = operation?;
    cleanup?;
    send_primordial_ready(system, bootstrap_channel, transaction_id)
}

/// Executes the bootstrap transaction with one explicit test-only hook before READY and close.
#[cfg(feature = "primordial-test-support")]
pub fn run_bootstrap_with_before_ready<System: BootstrapSystem>(
    system: &mut System,
    bootstrap_channel: DwHandle,
    before_ready: impl FnOnce(DwHandle) -> Result<(), BootstrapError>,
) -> Result<(), BootstrapError> {
    run_bootstrap_inner(system, bootstrap_channel, before_ready)
}

fn run_bootstrap_inner<System: BootstrapSystem>(
    system: &mut System,
    bootstrap_channel: DwHandle,
    before_ready: impl FnOnce(DwHandle) -> Result<(), BootstrapError>,
) -> Result<(), BootstrapError> {
    let channel_info = system
        .query_capability_info(bootstrap_channel)
        .map_err(BootstrapError::Native)?;
    validate_bootstrap_channel(channel_info, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(BootstrapError::BootstrapChannel)?;

    let mut bytes = [0_u8; BOOTSTRAP_INIT_V2_SIZE];
    let mut handles = [DwReceivedHandleInfoV1::default(); MAX_BOOTSTRAP_HANDLES];
    let counts = system
        .receive_channel(bootstrap_channel, &mut bytes, &mut handles)
        .map_err(BootstrapError::Native)?;

    let operation = (|| {
        let transaction_id =
            expected_primordial_transaction(&bytes[..counts.bytes], counts.handles)?;
        process_init(system, &handles[..counts.handles])?;
        Ok(transaction_id)
    })();
    let cleanup = close_received_handles(system, &handles[..counts.handles]);
    let transaction_id = operation?;
    cleanup?;
    before_ready(bootstrap_channel)?;

    send_primordial_ready(system, bootstrap_channel, transaction_id)
}

fn expected_primordial_transaction(
    bytes: &[u8],
    handle_count: usize,
) -> Result<u64, BootstrapError> {
    match decode(bytes, handle_count).map_err(BootstrapError::Protocol)? {
        BootstrapMessage::InitV2(message) => {
            if message.transaction_id != InitMessageV2::primordial().transaction_id {
                return Err(BootstrapError::UnexpectedTransactionId);
            }
            Ok(message.transaction_id)
        }
        _ => Err(BootstrapError::UnexpectedMessage),
    }
}

fn send_primordial_ready<System: BootstrapSystem>(
    system: &mut System,
    bootstrap_channel: DwHandle,
    transaction_id: u64,
) -> Result<(), BootstrapError> {
    let mut ready = [0_u8; BOOTSTRAP_READY_V2_SIZE];
    let ready_size = ReadyMessageV2 { transaction_id }
        .encode_into(&mut ready)
        .map_err(BootstrapError::Protocol)?;
    system
        .send_channel(bootstrap_channel, &ready[..ready_size])
        .map_err(BootstrapError::Native)?;
    system
        .close_handle(bootstrap_channel)
        .map_err(BootstrapError::Native)
}

fn process_init<System: BootstrapSystem>(
    system: &mut System,
    handles: &[DwReceivedHandleInfoV1],
) -> Result<(), BootstrapError> {
    if handles.len() != MAX_BOOTSTRAP_HANDLES {
        return Err(BootstrapError::Capability(
            CapabilityValidationError::WrongInitCapabilityCount,
        ));
    }
    let received = [
        received_capability(handles[0]),
        received_capability(handles[1]),
        received_capability(handles[2]),
    ];
    let fresh = [
        system
            .query_capability_info(handles[0].handle)
            .map_err(BootstrapError::Native)?,
        system
            .query_capability_info(handles[1].handle)
            .map_err(BootstrapError::Native)?,
        system
            .query_capability_info(handles[2].handle)
            .map_err(BootstrapError::Native)?,
    ];
    let capabilities = [
        InitCapability {
            received: received[0],
            fresh: fresh[0],
        },
        InitCapability {
            received: received[1],
            fresh: fresh[1],
        },
        InitCapability {
            received: received[2],
            fresh: fresh[2],
        },
    ];
    validate_init_capabilities_v2(
        &capabilities,
        SELF_ROOT_EXPECTATION,
        BOOTFS_EXPECTATION,
        LOADER_TASK_GROUP_EXPECTATION,
    )
    .map_err(BootstrapError::Capability)?;

    let logical_size = system
        .query_memory_object_size(handles[1].handle)
        .map_err(BootstrapError::Native)?;
    let plan = MappingPlan::for_bootfs(logical_size).map_err(BootstrapError::Mapping)?;
    system
        .with_bootfs_bytes(handles[0].handle, handles[1].handle, plan, validate_bootfs)
        .map_err(BootstrapError::Native)?
}

#[cfg(feature = "loader-smoke-integration")]
fn validated_load_authority<System: BootstrapSystem>(
    system: &mut System,
    handles: &[DwReceivedHandleInfoV1],
) -> Result<LoadAuthority, BootstrapError> {
    if handles.len() != MAX_BOOTSTRAP_HANDLES {
        return Err(BootstrapError::Capability(
            CapabilityValidationError::WrongInitCapabilityCount,
        ));
    }
    let received = [
        received_capability(handles[0]),
        received_capability(handles[1]),
        received_capability(handles[2]),
    ];
    let fresh = [
        system
            .query_capability_info(handles[0].handle)
            .map_err(BootstrapError::Native)?,
        system
            .query_capability_info(handles[1].handle)
            .map_err(BootstrapError::Native)?,
        system
            .query_capability_info(handles[2].handle)
            .map_err(BootstrapError::Native)?,
    ];
    let capabilities = [
        InitCapability {
            received: received[0],
            fresh: fresh[0],
        },
        InitCapability {
            received: received[1],
            fresh: fresh[1],
        },
        InitCapability {
            received: received[2],
            fresh: fresh[2],
        },
    ];
    validate_init_capabilities_v2(
        &capabilities,
        SELF_ROOT_EXPECTATION,
        BOOTFS_EXPECTATION,
        LOADER_TASK_GROUP_EXPECTATION,
    )
    .map_err(BootstrapError::Capability)?;
    Ok(LoadAuthority {
        parent_root: handles[0].handle,
        bootfs: handles[1].handle,
        task_group: handles[2].handle,
    })
}

#[cfg(feature = "loader-smoke-integration")]
fn bootfs_mapping_plan<System: BootstrapSystem>(
    system: &mut System,
    bootfs: DwHandle,
) -> Result<MappingPlan, BootstrapError> {
    system
        .query_memory_object_size(bootfs)
        .map_err(BootstrapError::Native)
        .and_then(|size| MappingPlan::for_bootfs(size).map_err(BootstrapError::Mapping))
}

#[cfg(feature = "loader-smoke-integration")]
fn load_loader_smoke<Loader: LoaderPlatform<Error = NativeError>>(
    loader: &mut Loader,
    authority: LoadAuthority,
    bytes: &[u8],
) -> Result<LoadedProcess, BootstrapError> {
    let archive = Archive::new(bytes).map_err(BootstrapError::Bootfs)?;
    let entry = archive
        .lookup(LOADER_SMOKE_PATH)
        .map_err(|error| match error {
            LookupError::NotFound | LookupError::InvalidPath(_) => {
                BootstrapError::MissingRequiredEntry
            }
        })?;
    if !entry.is_executable() || entry.data().is_empty() {
        return Err(BootstrapError::RequiredEntryNotExecutable);
    }
    let display_path = entry
        .name_utf8()
        .map_err(|_| BootstrapError::MissingRequiredEntry)?;
    load_process(
        loader,
        authority,
        LoadRequest {
            image: entry.data(),
            display_path,
            profile: LaunchProfile::Hello,
            transaction_id: LOADER_SMOKE_TRANSACTION_ID,
        },
    )
    .map_err(BootstrapError::Loader)
}

#[cfg(feature = "loader-smoke-integration")]
fn cleanup_loaded_process<System: BootstrapSystem, Loader: LoaderPlatform<Error = NativeError>>(
    system: &mut System,
    loader: &mut Loader,
    loaded: LoadedProcess,
    terminate: bool,
) -> Result<(), NativeError> {
    let mut first_error = None;
    if terminate && let Err(error) = loader.process_terminate(loaded.process) {
        first_error = Some(error);
    }
    for handle in [loaded.launch_channel, loaded.process] {
        if let Err(error) = system.close_handle(handle)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn received_capability(info: DwReceivedHandleInfoV1) -> CapabilityInfo<DwObjectType, DwRights> {
    CapabilityInfo {
        object_type: info.object_type,
        rights: info.rights,
    }
}

fn close_received_handles<System: BootstrapSystem>(
    system: &mut System,
    handles: &[DwReceivedHandleInfoV1],
) -> Result<(), BootstrapError> {
    let mut first_error = None;
    for info in handles {
        if let Err(error) = system.close_handle(info.handle)
            && first_error.is_none()
        {
            first_error = Some(BootstrapError::Native(error));
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn validate_bootfs(bytes: &[u8]) -> Result<(), BootstrapError> {
    let archive = Archive::new(bytes).map_err(BootstrapError::Bootfs)?;
    for path in [INIT0_PATH, HELLO_PATH] {
        let entry = archive.lookup(path).map_err(|error| match error {
            LookupError::NotFound | LookupError::InvalidPath(_) => {
                BootstrapError::MissingRequiredEntry
            }
        })?;
        if !entry.is_executable() || entry.data().is_empty() {
            return Err(BootstrapError::RequiredEntryNotExecutable);
        }
    }
    Ok(())
}
