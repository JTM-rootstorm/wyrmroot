//! Temporary WYR0 compatibility transactions.
//!
//! This module contains the pre-WYR1 `init0`, loader-smoke, selector-fault, and
//! WRCAP1 relay behavior.  The primordial core in `lib.rs` owns the handoff
//! receipt, capability validation, bootfs mapping, and cleanup facade.

use deepwyrm_syscall::{
    DW_SIGNAL_EXITED, DW_TASK_STATE_EXITED, DwDeadline, DwHandle, DwReceivedHandleInfoV1,
    DwSignals, DwTaskTerminationInfoV1, DwWaitItemV1,
};
use wyrmroot_bootfs::archive::{Archive, LookupError};
use wyrmroot_loader::{
    launch::LaunchProfile,
    process::{LoadAuthority, LoadFault, LoadRequest, LoadedProcess, LoaderPlatform},
};
use wyrmroot_runtime::{
    NativeError, SupervisionError, SupervisionPlatform, supervise_child, validate_successful_exit,
};

use super::{
    BOOTSTRAP_CHANNEL_EXPECTATION, BootstrapError, BootstrapSystem, bootfs_mapping_plan,
    cleanup_loaded_process, cleanup_supervised_process, close_received_handles,
    expected_primordial_transaction, send_primordial_ready, validate_bootfs,
};

/// Canonical init executable required in the primordial WYR0 bootfs.
pub const INIT0_PATH: &[u8] = b"system/init0";
/// Canonical smoke executable required in the primordial WYR0 bootfs.
pub const HELLO_PATH: &[u8] = b"bin/hello";

/// WYR0-F child transaction identifier for `system/init0`.
pub const INIT0_TRANSACTION_ID: u64 = 1;

/// Stable terminal detail for the test-only malformed-ELF variant.
pub const I0_NEGATIVE_MALFORMED_ELF_DETAIL: u32 = 0xB000_0401;
/// Stable terminal detail for the test-only malformed-startup variant.
pub const I0_NEGATIVE_MALFORMED_STARTUP_DETAIL: u32 = 0xB000_0402;
/// Stable terminal detail for the test-only malformed capability-count variant.
pub const I0_NEGATIVE_CAPABILITY_COUNT_DETAIL: u32 = 0xB000_0403;
/// Stable terminal detail for the test-only malformed capability-type variant.
pub const I0_NEGATIVE_CAPABILITY_TYPE_DETAIL: u32 = 0xB000_0404;
/// Stable terminal detail for the test-only malformed capability-rights variant.
pub const I0_NEGATIVE_CAPABILITY_RIGHTS_DETAIL: u32 = 0xB000_0405;

/// Returns the distinct terminal detail only after a selected I0 test fault
/// produced its exact expected failure.
pub fn i0_negative_terminal_detail(fault: LoadFault, error: &BootstrapError) -> Option<u32> {
    use wyrmroot_runtime::{ExitValidationError, StartupError, startup_error_exit_code};

    match (fault, error) {
        (
            LoadFault::MalformedElf,
            BootstrapError::Loader(wyrmroot_loader::process::LoadError::Elf(
                wyrmroot_loader::elf::ElfError::BadMagic,
            )),
        ) => Some(I0_NEGATIVE_MALFORMED_ELF_DETAIL),
        (
            LoadFault::MalformedStartup,
            BootstrapError::Supervision(SupervisionError::Exit(
                ExitValidationError::NonzeroApplicationCode(code),
            )),
        ) if *code == startup_error_exit_code(StartupError::StringPointerOutOfRange) => {
            Some(I0_NEGATIVE_MALFORMED_STARTUP_DETAIL)
        }
        (
            LoadFault::InitCapabilityCount,
            BootstrapError::Supervision(SupervisionError::Exit(
                ExitValidationError::NonzeroApplicationCode(0x1000_0307),
            )),
        ) => Some(I0_NEGATIVE_CAPABILITY_COUNT_DETAIL),
        (
            LoadFault::InitCapabilityType,
            BootstrapError::Supervision(SupervisionError::Exit(
                ExitValidationError::NonzeroApplicationCode(0x1000_0330),
            )),
        ) => Some(I0_NEGATIVE_CAPABILITY_TYPE_DETAIL),
        (
            LoadFault::InitCapabilityRights,
            BootstrapError::Supervision(SupervisionError::Exit(
                ExitValidationError::NonzeroApplicationCode(0x1000_0330),
            )),
        ) => Some(I0_NEGATIVE_CAPABILITY_RIGHTS_DETAIL),
        _ => None,
    }
}

/// Runs the WYR0-F primordial bootstrap transaction before primordial READY.
pub fn run_init0_bootstrap<
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
    run_init0_bootstrap_with_fault_and_before_supervision(
        system,
        loader,
        supervisor,
        bootstrap_channel,
        deadline,
        LoadFault::None,
        |_, _, _, _, _| Ok(()),
    )
}

/// Runs the primordial `init0` transaction with one explicit test-only child launch fault.
pub fn run_init0_bootstrap_with_fault<
    System: BootstrapSystem,
    Loader: LoaderPlatform<Error = NativeError>,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    loader: &mut Loader,
    supervisor: &mut Supervisor,
    bootstrap_channel: DwHandle,
    deadline: DwDeadline,
    fault: LoadFault,
) -> Result<(), BootstrapError> {
    run_init0_bootstrap_with_fault_and_before_supervision(
        system,
        loader,
        supervisor,
        bootstrap_channel,
        deadline,
        fault,
        |_, _, _, _, _| Ok(()),
    )
}

fn run_init0_bootstrap_with_fault_and_before_supervision<
    System: BootstrapSystem,
    Loader: LoaderPlatform<Error = NativeError>,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    loader: &mut Loader,
    supervisor: &mut Supervisor,
    bootstrap_channel: DwHandle,
    deadline: DwDeadline,
    fault: LoadFault,
    before_supervision: impl FnOnce(
        &mut System,
        &mut Supervisor,
        DwHandle,
        DwHandle,
        DwDeadline,
    ) -> Result<(), BootstrapError>,
) -> Result<(), BootstrapError> {
    let channel_info = system
        .query_capability_info(bootstrap_channel)
        .map_err(BootstrapError::Native)?;
    super::validate_bootstrap_channel(channel_info, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(BootstrapError::BootstrapChannel)?;

    let mut bytes = [0_u8; wyrmroot_bootstrap_proto::BOOTSTRAP_INIT_V2_SIZE];
    let mut handles =
        [DwReceivedHandleInfoV1::default(); wyrmroot_bootstrap_proto::MAX_BOOTSTRAP_V2_HANDLES];
    let counts = system
        .receive_channel(bootstrap_channel, &mut bytes, &mut handles)
        .map_err(BootstrapError::Native)?;
    if counts.bytes > bytes.len() || counts.handles > handles.len() {
        return Err(BootstrapError::ReceiveCounts(counts));
    }

    let operation = (|| {
        let transaction_id =
            expected_primordial_transaction(&bytes[..counts.bytes], counts.handles)?;
        let authority = super::validated_load_authority(system, &handles[..counts.handles])?;
        let plan = bootfs_mapping_plan(system, authority.bootfs)?;
        let mut loaded = None;
        let mapped =
            system.with_bootfs_bytes(authority.parent_root, authority.bootfs, plan, |bootfs| {
                match load_init0(loader, authority, bootfs, fault) {
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
        if let Err(error) = before_supervision(
            system,
            supervisor,
            loaded.launch_channel,
            bootstrap_channel,
            deadline,
        ) {
            let terminal =
                observe_terminal_after_relay_failure(supervisor, loaded.process, deadline);
            let cleanup_exit =
                cleanup_supervised_process(system, loader, supervisor, loaded, terminal.is_none())
                    .map_err(BootstrapError::Cleanup)?;
            if let Some(info) = terminal.or(cleanup_exit) {
                validate_successful_exit(&info)
                    .map_err(|error| BootstrapError::Supervision(SupervisionError::Exit(error)))?;
            }
            return Err(error);
        }
        let supervision = supervise_child(
            supervisor,
            loaded.process,
            loaded.launch_channel,
            INIT0_TRANSACTION_ID,
            deadline,
        );
        let late_exit = match &supervision {
            Err(error) if !error.process_exit_observed() => supervisor
                .query_task_termination(loaded.process)
                .ok()
                .filter(|info| info.state == DW_TASK_STATE_EXITED),
            _ => None,
        };
        let terminate = matches!(&supervision, Err(error) if !error.process_exit_observed())
            && late_exit.is_none();
        let cleanup_exit =
            cleanup_supervised_process(system, loader, supervisor, loaded, terminate)
                .map_err(BootstrapError::Cleanup)?;
        if let Some(info) = late_exit.or(cleanup_exit) {
            validate_successful_exit(&info)
                .map_err(|error| BootstrapError::Supervision(SupervisionError::Exit(error)))?;
        }
        supervision.map_err(BootstrapError::Supervision)?;
        Ok(transaction_id)
    })();
    let cleanup = close_received_handles(system, &handles[..counts.handles]);
    let transaction_id = operation?;
    cleanup?;
    send_primordial_ready(system, bootstrap_channel, transaction_id)
}

fn observe_terminal_after_relay_failure<Supervisor: SupervisionPlatform<Error = NativeError>>(
    supervisor: &mut Supervisor,
    process: DwHandle,
    deadline: DwDeadline,
) -> Option<DwTaskTerminationInfoV1> {
    if let Ok(info) = supervisor.query_task_termination(process)
        && info.state == DW_TASK_STATE_EXITED
    {
        return Some(info);
    }
    let item = DwWaitItemV1 {
        handle: process,
        signals: DwSignals(DW_SIGNAL_EXITED.0),
    };
    let observed = supervisor
        .wait_many(core::slice::from_ref(&item), deadline)
        .ok()?;
    if observed.index != 0 || observed.observed.0 & DW_SIGNAL_EXITED.0 == 0 {
        return None;
    }
    supervisor
        .query_task_termination(process)
        .ok()
        .filter(|info| info.state == DW_TASK_STATE_EXITED)
}

fn load_init0<Loader: LoaderPlatform<Error = NativeError>>(
    loader: &mut Loader,
    authority: LoadAuthority,
    bytes: &[u8],
    fault: LoadFault,
) -> Result<LoadedProcess, BootstrapError> {
    validate_bootfs(bytes)?;
    let archive = Archive::new(bytes).map_err(BootstrapError::Bootfs)?;
    let entry = archive.lookup(INIT0_PATH).map_err(|error| match error {
        LookupError::NotFound | LookupError::InvalidPath(_) => BootstrapError::MissingRequiredEntry,
    })?;
    let display_path = entry
        .name_utf8()
        .map_err(|_| BootstrapError::MissingRequiredEntry)?;
    wyrmroot_loader::process::load_process_with_fault(
        loader,
        authority,
        LoadRequest {
            image: entry.data(),
            display_path,
            profile: LaunchProfile::Init0,
            transaction_id: INIT0_TRANSACTION_ID,
        },
        fault,
    )
    .map_err(BootstrapError::Loader)
}
