//! Temporary WYR0 compatibility transactions.
//!
//! This module contains the pre-WYR1 `init0`, loader-smoke, selector-fault, and
//! WRCAP1 relay behavior.  The primordial core in `lib.rs` owns the handoff
//! receipt, capability validation, bootfs mapping, and cleanup facade.

#[cfg(feature = "i-capability-relay")]
use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_SIGNAL_WRITABLE,
    DW_STATUS_TIMED_OUT, DW_STATUS_WOULD_BLOCK,
};
use deepwyrm_syscall::{
    DW_SIGNAL_EXITED, DW_TASK_STATE_EXITED, DwDeadline, DwHandle, DwReceivedHandleInfoV1,
    DwSignals, DwTaskTerminationInfoV1, DwWaitItemV1,
};
use wyrmroot_bootfs::archive::{Archive, LookupError};
#[cfg(feature = "loader-smoke-integration")]
use wyrmroot_loader::process::load_process;
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
/// E-only temporary native loader probe. This is not an init0 policy entry.
#[cfg(feature = "loader-smoke-integration")]
pub const LOADER_SMOKE_PATH: &[u8] = b"test/loader-smoke";
/// Distinct nonzero WRLP transaction identifier used by the temporary E-only child.
#[cfg(feature = "loader-smoke-integration")]
pub const LOADER_SMOKE_TRANSACTION_ID: u64 = 2;

/// WYR0-F child transaction identifier for `system/init0`.
pub const INIT0_TRANSACTION_ID: u64 = 1;

/// Number of controller-originated WYR0-I capability evidence records.
#[cfg(feature = "i-capability-relay")]
pub const WRCAP1_RECORD_COUNT: usize = 15;
/// Canonical ordered WYR0-I controller evidence kinds for the relay.
#[cfg(feature = "i-capability-relay")]
pub const WRCAP1_KINDS: [u8; WRCAP1_RECORD_COUNT] = [
    0x01, 0x02, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x07, 0x08, 0x08, 0x08, 0x08, 0x09, 0x0A,
];
/// Exact fixed-width ASCII length of one `WRCAP1` evidence datagram.
#[cfg(feature = "i-capability-relay")]
pub const WRCAP1_RECORD_SIZE: usize = 117;

/// A capability-evidence relay datagram did not meet the bootstrap boundary contract.
#[cfg(feature = "i-capability-relay")]
#[derive(Debug, Eq, PartialEq)]
pub enum Wrcap1RelayError {
    /// The relay was given an unbounded deadline.
    UnboundedDeadline,
    /// The bounded receive wait elapsed before the next required record arrived.
    TimedOut,
    /// The child Channel closed before its next required record became readable.
    PeerClosed,
    /// A wait result did not select the requested Channel or its requested signals.
    InvalidWaitResult,
    /// A post-readable receive raced with draining and reported `WOULD_BLOCK`.
    ReceiveWouldBlock,
    /// A bounded relay send remained backpressured after every permitted retry.
    SendWouldBlock,
    /// The child attached one or more handles to an evidence datagram.
    CapabilityBearing,
    /// The record was not exact fixed-width, uppercase ASCII `WRCAP1` framing.
    MalformedFraming,
    /// The record sequence was not the contiguous expected value.
    UnexpectedSequence,
    /// The record kind was not the required canonical next kind.
    UnexpectedKind,
    /// The record's checksum did not authenticate its exact preceding byte sequence.
    Checksum,
}

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

/// Runs the selector-gated WYR0-I bootstrap transaction.
#[cfg(feature = "i-capability-relay")]
pub fn run_init0_capability_bootstrap<
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
        relay_wrcap1_records,
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

#[cfg(feature = "i-capability-relay")]
fn relay_wrcap1_records<
    System: BootstrapSystem,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    supervisor: &mut Supervisor,
    launch_channel: DwHandle,
    primordial_parent_channel: DwHandle,
    deadline: DwDeadline,
) -> Result<(), BootstrapError> {
    if deadline == DW_DEADLINE_INFINITE {
        return Err(BootstrapError::CapabilityRelay(
            Wrcap1RelayError::UnboundedDeadline,
        ));
    }
    let mut bytes = [0_u8; WRCAP1_RECORD_SIZE];
    let mut handles = [];
    for (sequence, expected_kind) in WRCAP1_KINDS.into_iter().enumerate() {
        wait_for_wrcap1_record(supervisor, launch_channel, deadline)?;
        let counts = match system.receive_channel(launch_channel, &mut bytes, &mut handles) {
            Err(NativeError::Status(status)) if status == DW_STATUS_WOULD_BLOCK => {
                return Err(BootstrapError::CapabilityRelay(
                    Wrcap1RelayError::ReceiveWouldBlock,
                ));
            }
            Err(error) => return Err(BootstrapError::Native(error)),
            Ok(counts) => counts,
        };
        if counts.handles != 0 {
            return Err(BootstrapError::CapabilityRelay(
                Wrcap1RelayError::CapabilityBearing,
            ));
        }
        if counts.bytes > bytes.len() {
            return Err(BootstrapError::ReceiveCounts(counts));
        }
        validate_wrcap1_record(&bytes[..counts.bytes], sequence as u32, expected_kind)
            .map_err(BootstrapError::CapabilityRelay)?;
        send_wrcap1_record_bounded(
            system,
            supervisor,
            primordial_parent_channel,
            &bytes[..counts.bytes],
            deadline,
        )?;
    }
    Ok(())
}

#[cfg(feature = "i-capability-relay")]
fn send_wrcap1_record_bounded<
    System: BootstrapSystem,
    Supervisor: SupervisionPlatform<Error = NativeError>,
>(
    system: &mut System,
    supervisor: &mut Supervisor,
    parent_channel: DwHandle,
    record: &[u8],
    deadline: DwDeadline,
) -> Result<(), BootstrapError> {
    for _ in 0..32 {
        match system.send_channel(parent_channel, record) {
            Ok(()) => return Ok(()),
            Err(NativeError::Status(status)) if status == DW_STATUS_WOULD_BLOCK => {
                let item = DwWaitItemV1 {
                    handle: parent_channel,
                    signals: DwSignals(DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
                };
                let observed = match supervisor.wait_many(core::slice::from_ref(&item), deadline) {
                    Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
                        return Err(BootstrapError::CapabilityRelay(Wrcap1RelayError::TimedOut));
                    }
                    Err(error) => return Err(BootstrapError::Native(error)),
                    Ok(observed) => observed,
                };
                if observed.index != 0 {
                    return Err(BootstrapError::CapabilityRelay(
                        Wrcap1RelayError::InvalidWaitResult,
                    ));
                }
                if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0 {
                    return Err(BootstrapError::CapabilityRelay(
                        Wrcap1RelayError::PeerClosed,
                    ));
                }
                if observed.observed.0 & DW_SIGNAL_WRITABLE.0 == 0 {
                    return Err(BootstrapError::CapabilityRelay(
                        Wrcap1RelayError::InvalidWaitResult,
                    ));
                }
            }
            Err(error) => return Err(BootstrapError::Native(error)),
        }
    }
    Err(BootstrapError::CapabilityRelay(
        Wrcap1RelayError::SendWouldBlock,
    ))
}

#[cfg(feature = "i-capability-relay")]
fn wait_for_wrcap1_record<Supervisor: SupervisionPlatform<Error = NativeError>>(
    supervisor: &mut Supervisor,
    launch_channel: DwHandle,
    deadline: DwDeadline,
) -> Result<(), BootstrapError> {
    let item = DwWaitItemV1 {
        handle: launch_channel,
        signals: DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    };
    let result = match supervisor.wait_many(core::slice::from_ref(&item), deadline) {
        Err(NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
            return Err(BootstrapError::CapabilityRelay(Wrcap1RelayError::TimedOut));
        }
        Err(error) => return Err(BootstrapError::Native(error)),
        Ok(result) => result,
    };
    if result.index != 0 || result.observed.0 & item.signals.0 == 0 {
        return Err(BootstrapError::CapabilityRelay(
            Wrcap1RelayError::InvalidWaitResult,
        ));
    }
    if result.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(BootstrapError::CapabilityRelay(
            Wrcap1RelayError::PeerClosed,
        ));
    }
    Ok(())
}

#[cfg(feature = "i-capability-relay")]
fn validate_wrcap1_record(
    record: &[u8],
    expected_sequence: u32,
    expected_kind: u8,
) -> Result<(), Wrcap1RelayError> {
    const DELIMITERS: [usize; 10] = [6, 9, 26, 35, 38, 47, 56, 73, 90, 107];
    if record.len() != WRCAP1_RECORD_SIZE
        || record[..7] != *b"WRCAP1|"
        || record[7..9] != *b"01"
        || record[116] != b'\n'
        || DELIMITERS.iter().any(|&index| record[index] != b'|')
        || !record[10..26].iter().any(|&byte| byte != b'0')
        || !record[10..26]
            .iter()
            .chain(record[27..35].iter())
            .chain(record[36..38].iter())
            .chain(record[39..47].iter())
            .chain(record[48..56].iter())
            .chain(record[57..73].iter())
            .chain(record[74..90].iter())
            .chain(record[91..107].iter())
            .chain(record[108..116].iter())
            .all(|&byte| matches!(byte, b'0'..=b'9' | b'A'..=b'F'))
    {
        return Err(Wrcap1RelayError::MalformedFraming);
    }
    if parse_hex_u32(&record[27..35]) != Some(expected_sequence) {
        return Err(Wrcap1RelayError::UnexpectedSequence);
    }
    if parse_hex_u32(&record[36..38]) != Some(u32::from(expected_kind)) {
        return Err(Wrcap1RelayError::UnexpectedKind);
    }
    if parse_hex_u32(&record[108..116]) != Some(fnv1a32(&record[..108])) {
        return Err(Wrcap1RelayError::Checksum);
    }
    Ok(())
}

#[cfg(feature = "i-capability-relay")]
fn parse_hex_u32(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0_u32, |value, &byte| {
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'A'..=b'F' => u32::from(byte - b'A' + 10),
            _ => return None,
        };
        value.checked_mul(16)?.checked_add(digit)
    })
}

#[cfg(feature = "i-capability-relay")]
const fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5_u32;
    let mut index = 0;
    while index < bytes.len() {
        hash ^= bytes[index] as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        index += 1;
    }
    hash
}

/// Runs the WYR0-E-only loader-smoke transaction before primordial READY.
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
