//! Native controller and probe-child execution over the generated Deepwyrm ABI.

use deepwyrm_syscall::{
    self, DW_OBJECT_TYPE_MEMORY_OBJECT, DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT, DW_RIGHT_MAP,
    DW_RIGHT_MODIFY, DW_RIGHT_READ, DW_RIGHT_SIGNAL, DW_RIGHT_TRANSFER, DW_RIGHT_WAIT,
    DW_RIGHT_WRITE, DW_SIGNAL_EXITED, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE,
    DW_SIGNAL_SIGNALED, DW_SIGNAL_WRITABLE, DW_STATUS_BAD_HANDLE, DW_STATUS_PEER_CLOSED,
    DW_STATUS_TIMED_OUT, DW_STATUS_WOULD_BLOCK, DW_TASK_STATE_EXITED, DW_TERMINATION_AUTHORIZED,
    DW_TERMINATION_NORMAL_EXIT, DwDeadline, DwHandle, DwHandleTransferV1, DwReceivedHandleInfoV1,
    DwRights, DwSignals,
};
use wyrmroot_bootfs::archive::Archive;
use wyrmroot_loader::{
    launch::{
        HEADER_BYTES, INIT0_BYTES, LaunchProfile, encode_ready, encode_ready_for_profile,
        parse_init, parse_ready, parse_ready_for_profile,
    },
    process::{LoadAuthority, LoadError, LoadRequest, LoadStage, LoadedProcess, load_process},
};
use wyrmroot_runtime::{
    AccountedResource, AccountingError, AttemptFailure, BOOTSTRAP_CHANNEL_EXPECTATION,
    CleanupDisposition, ExitObservedReadinessError, ExitValidationError,
    LOADER_TASK_GROUP_EXPECTATION, MappingPlan, NativeError, NativeLoaderPlatform,
    ReadinessAccounting, ReservationRequest, RestartState, RestartSupervisor,
    SELF_ROOT_EXPECTATION, SupervisionError, TerminalDisposition, WYR0_I_SUPERVISION_POLICY,
    cancel_timer, close_handle, create_channel, create_event, create_memory_object,
    create_task_group, create_timer, duplicate_handle, map_bootfs_read_only, map_memory_read_only,
    map_memory_read_write, monotonic_active_now, monotonic_deadline_after, native_error_code,
    query_capability_info, query_memory_object_size, query_task_termination_info, receive_channel,
    send_channel, set_timer, signal_event, supervise_native_child, terminate_process, unmap_bootfs,
    unmap_memory, validate_bootstrap_channel, validate_successful_exit, wait_one,
};

use crate::evidence::{
    CANCEL_TRANSACTION, CHANNEL_BACKPRESSURE_ATTEMPT_LIMIT, CHANNEL_TOKEN,
    EXHAUST_TRANSACTION_BASE, MEMORY_TRANSACTION, NORMAL_TRANSACTION, RESTART_TRANSACTION_BASE,
    WAIT_TOKEN,
};
use crate::{
    ASSET_BOOTFS_PATH, CONFIG_BOOTFS_PATH, EvidenceEvent, EvidenceKind, EvidenceTranscript,
    WRCAP1_EVENT_COUNT, failure, prove_overload_replay_and_cleanup,
    prove_restart_replacement_and_exhaustion, sha256_prefix_u64, validate_selector_content,
};

const PAGE_BYTES: u64 = wyrmroot_runtime::PAGE_SIZE;
const CHILD_TIMEOUT_NS: u64 = 1_000_000_000;
const SHORT_TIMEOUT_NS: u64 = 1_000_000;
const BACKPRESSURE_ATTEMPTS: usize = CHANNEL_BACKPRESSURE_ATTEMPT_LIMIT as usize;
const RELAY_SEND_ATTEMPTS: usize = 32;

const MEMORY_COMMAND_BYTES: usize = 16;
const MEMORY_ACK: &[u8] = b"WICMACK1";
const FAIL_EXIT_CODE: u32 = 0x2407_F001;
const EXHAUST_EXIT_CODE: u32 = 0x2408_F001;

const CHANNEL_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0
        | DW_RIGHT_WRITE.0
        | DW_RIGHT_WAIT.0
        | DW_RIGHT_DUPLICATE.0
        | DW_RIGHT_TRANSFER.0
        | DW_RIGHT_INSPECT.0,
);
const TASK_GROUP_RIGHTS: DwRights =
    DwRights(DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_DUPLICATE.0 | DW_RIGHT_TRANSFER.0);
const MEMORY_OWNER_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0
        | DW_RIGHT_WRITE.0
        | DW_RIGHT_MAP.0
        | DW_RIGHT_INSPECT.0
        | DW_RIGHT_DUPLICATE.0
        | DW_RIGHT_TRANSFER.0,
);
const MEMORY_CHILD_RIGHTS: DwRights =
    DwRights(DW_RIGHT_READ.0 | DW_RIGHT_MAP.0 | DW_RIGHT_INSPECT.0);

/// Runs as the trusted capability controller, an ordinary handle-free leaf, or the explicit
/// self-root-only memory probe child according to its WRLP launch profile.
pub fn run_i_capability(channel: DwHandle) -> Result<(), u32> {
    let channel_info = query_capability_info(channel)
        .map_err(|_| failure(EvidenceKind::ProcessLifecycle, 0x0001))?;
    validate_bootstrap_channel(channel_info, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(|_| failure(EvidenceKind::ProcessLifecycle, 0x0002))?;
    let mut bytes = [0_u8; INIT0_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 3];
    let received = receive_channel(channel, &mut bytes, &mut handles)
        .map_err(|_| failure(EvidenceKind::ProcessLifecycle, 0x0003))?;
    if received.bytes > bytes.len() || received.handles > handles.len() {
        return Err(failure(EvidenceKind::ProcessLifecycle, 0x0004));
    }

    if let Ok(message) = parse_init(
        LaunchProfile::Hello,
        &bytes[..received.bytes],
        &handles[..received.handles],
    ) {
        return run_leaf(channel, message.transaction_id);
    }
    if let Ok(message) = parse_init(
        LaunchProfile::ProbeChild,
        &bytes[..received.bytes],
        &handles[..received.handles],
    ) {
        return run_memory_child(channel, handles[0].handle, message.transaction_id);
    }

    let message = parse_init(
        LaunchProfile::CapabilityController,
        &bytes[..received.bytes],
        &handles[..received.handles],
    )
    .map_err(|_| failure(EvidenceKind::ProcessLifecycle, 0x0005))?;
    run_controller(
        channel,
        message.transaction_id,
        LoadAuthority {
            parent_root: handles[0].handle,
            bootfs: handles[1].handle,
            task_group: handles[2].handle,
        },
    )
}

fn run_leaf(channel: DwHandle, transaction: u64) -> Result<(), u32> {
    send_ready(channel, transaction, EvidenceKind::ProcessLifecycle, 0x0010)?;
    if transaction == CANCEL_TRANSACTION {
        let deadline = future_deadline(CHILD_TIMEOUT_NS, EvidenceKind::Cancellation, 0x0001)?;
        match wait_one(channel, DW_SIGNAL_READABLE, deadline) {
            Err(wyrmroot_runtime::NativeError::Status(status)) if status == DW_STATUS_TIMED_OUT => {
                return Err(failure(EvidenceKind::Cancellation, 0x0002));
            }
            Err(_) => return Err(failure(EvidenceKind::Cancellation, 0x0003)),
            Ok(_) => return Err(failure(EvidenceKind::Cancellation, 0x0004)),
        }
    }
    close_handle(channel).map_err(|_| failure(EvidenceKind::ProcessLifecycle, 0x0011))?;
    if transaction == RESTART_TRANSACTION_BASE + 1 {
        return Err(FAIL_EXIT_CODE);
    }
    if (EXHAUST_TRANSACTION_BASE + 1..=EXHAUST_TRANSACTION_BASE + 4).contains(&transaction) {
        return Err(EXHAUST_EXIT_CODE);
    }
    Ok(())
}

fn run_memory_child(channel: DwHandle, root: DwHandle, transaction: u64) -> Result<(), u32> {
    let root_info =
        query_capability_info(root).map_err(|_| failure(EvidenceKind::MemoryShare, 0x0101))?;
    if root_info.object_type != SELF_ROOT_EXPECTATION.object_type
        || root_info.rights != SELF_ROOT_EXPECTATION.rights
    {
        return Err(failure(EvidenceKind::MemoryShare, 0x0102));
    }
    send_probe_ready(channel, transaction, EvidenceKind::MemoryShare, 0x0103)?;
    wait_one(
        channel,
        DW_SIGNAL_READABLE,
        future_deadline(CHILD_TIMEOUT_NS, EvidenceKind::MemoryShare, 0x0104)?,
    )
    .map_err(|_| failure(EvidenceKind::MemoryShare, 0x0105))?;

    let mut command = [0_u8; MEMORY_COMMAND_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let received = receive_channel(channel, &mut command, &mut handles)
        .map_err(|_| failure(EvidenceKind::MemoryShare, 0x0106))?;
    if received.bytes != MEMORY_COMMAND_BYTES
        || received.handles != 1
        || &command[..4] != b"WICM"
        || u32::from_le_bytes(command[4..8].try_into().unwrap()) != 1
        || u64::from_le_bytes(command[8..16].try_into().unwrap()) != transaction
        || handles[0].object_type != DW_OBJECT_TYPE_MEMORY_OBJECT
        || handles[0].rights != MEMORY_CHILD_RIGHTS
    {
        return Err(failure(EvidenceKind::MemoryShare, 0x0107));
    }
    let memory = handles[0].handle;
    let fresh =
        query_capability_info(memory).map_err(|_| failure(EvidenceKind::MemoryShare, 0x0108))?;
    if fresh.object_type != DW_OBJECT_TYPE_MEMORY_OBJECT || fresh.rights != MEMORY_CHILD_RIGHTS {
        return Err(failure(EvidenceKind::MemoryShare, 0x0109));
    }
    if query_memory_object_size(memory).map_err(|_| failure(EvidenceKind::MemoryShare, 0x010A))?
        != PAGE_BYTES
    {
        return Err(failure(EvidenceKind::MemoryShare, 0x010B));
    }
    let mapping = map_memory_read_only(root, memory, PAGE_BYTES)
        .map_err(|_| failure(EvidenceKind::MemoryShare, 0x010C))?;
    close_handle(memory).map_err(|_| failure(EvidenceKind::MemoryShare, 0x010D))?;
    let valid = mapping
        .with_bytes(|bytes| {
            bytes
                .iter()
                .enumerate()
                .all(|(index, byte)| *byte == memory_pattern(index))
        })
        .map_err(|_| failure(EvidenceKind::MemoryShare, 0x010E))?;
    if !valid {
        return Err(failure(EvidenceKind::MemoryShare, 0x010F));
    }
    send_channel(channel, MEMORY_ACK, &[])
        .map_err(|_| failure(EvidenceKind::MemoryShare, 0x0110))?;
    unmap_memory(mapping).map_err(|_| failure(EvidenceKind::MemoryShare, 0x0111))?;
    close_handle(root).map_err(|_| failure(EvidenceKind::MemoryShare, 0x0112))?;
    close_handle(channel).map_err(|_| failure(EvidenceKind::MemoryShare, 0x0113))
}

fn run_controller(
    parent_channel: DwHandle,
    parent_transaction: u64,
    authority: LoadAuthority,
) -> Result<(), u32> {
    validate_controller_authority(authority)?;
    let size = query_memory_object_size(authority.bootfs)
        .map_err(|_| failure(EvidenceKind::ContentDelivery, 0x0001))?;
    let plan = MappingPlan::for_bootfs(size)
        .map_err(|_| failure(EvidenceKind::ContentDelivery, 0x0002))?;
    let mapping = map_bootfs_read_only(authority.parent_root, authority.bootfs, plan)
        .map_err(|_| failure(EvidenceKind::ContentDelivery, 0x0003))?;
    let result = mapping.with_logical_bytes(|bytes| run_mapped_controller(authority, bytes));
    let unmap = unmap_bootfs(mapping).map_err(|_| failure(EvidenceKind::CleanupBaseline, 0x0001));
    let mut transcript = result?;
    unmap?;
    for (operation, handle) in [
        authority.parent_root,
        authority.bootfs,
        authority.task_group,
    ]
    .into_iter()
    .enumerate()
    {
        close_handle(handle)
            .map_err(|_| failure(EvidenceKind::CleanupBaseline, 0x0010 + operation as u16))?;
    }
    push(
        &mut transcript,
        event(EvidenceKind::CleanupBaseline, 0, 0, 0, 0, 0),
    )?;
    for sequence in 0..WRCAP1_EVENT_COUNT {
        let record = transcript
            .encoded(sequence)
            .map_err(|_| failure(EvidenceKind::CleanupBaseline, 0x0040 + sequence as u16))?;
        send_channel_bounded(
            parent_channel,
            &record,
            EvidenceKind::CleanupBaseline,
            0x0050 + sequence as u16,
        )?;
    }
    let mut ready = [0_u8; HEADER_BYTES];
    let ready_bytes = encode_ready(parent_transaction, &mut ready)
        .map_err(|_| failure(EvidenceKind::CleanupBaseline, 0x0020))?;
    send_channel_bounded(
        parent_channel,
        &ready[..ready_bytes],
        EvidenceKind::CleanupBaseline,
        0x0021,
    )?;
    close_handle(parent_channel).map_err(|_| failure(EvidenceKind::CleanupBaseline, 0x0022))
}

fn run_mapped_controller(
    authority: LoadAuthority,
    bootfs: &[u8],
) -> Result<EvidenceTranscript, u32> {
    let archive =
        Archive::new(bootfs).map_err(|_| failure(EvidenceKind::ContentDelivery, 0x0010))?;
    let executable = archive
        .lookup(b"bin/hello")
        .map_err(|_| failure(EvidenceKind::ContentDelivery, 0x0011))?;
    let config = archive
        .lookup(CONFIG_BOOTFS_PATH)
        .map_err(|_| failure(EvidenceKind::ContentDelivery, 0x0012))?;
    let asset = archive
        .lookup(ASSET_BOOTFS_PATH)
        .map_err(|_| failure(EvidenceKind::ContentDelivery, 0x0013))?;
    if !executable.is_executable()
        || executable.data().is_empty()
        || config.is_executable()
        || asset.is_executable()
    {
        return Err(failure(EvidenceKind::ContentDelivery, 0x0014));
    }
    let selector = validate_selector_content(config.data(), asset.data())
        .map_err(|_| failure(EvidenceKind::ContentDelivery, 0x0015))?;
    let display = executable
        .name_utf8()
        .map_err(|_| failure(EvidenceKind::ContentDelivery, 0x0016))?;
    let mut transcript = EvidenceTranscript::new(selector.evidence_nonce)
        .map_err(|_| failure(EvidenceKind::ContentDelivery, 0x0017))?;
    let config_prefix = sha256_prefix_u64(&selector.config_sha256);
    let asset_prefix = sha256_prefix_u64(&selector.asset_sha256);
    let content_token = config_prefix ^ asset_prefix;
    if content_token == 0 {
        return Err(failure(EvidenceKind::ContentDelivery, 0x0018));
    }
    push(
        &mut transcript,
        event(
            EvidenceKind::ContentDelivery,
            0,
            0,
            content_token,
            config_prefix,
            asset_prefix,
        ),
    )?;
    let mut normal_ledger =
        ReadinessAccounting::new().map_err(|_| failure(EvidenceKind::ProcessLifecycle, 0x00F0))?;
    exercise_normal_lifecycle(authority, executable.data(), display, &mut normal_ledger)?;
    push(
        &mut transcript,
        event(
            EvidenceKind::ProcessLifecycle,
            1,
            1,
            NORMAL_TRANSACTION,
            1,
            0,
        ),
    )?;
    push(
        &mut transcript,
        event(
            EvidenceKind::ProcessLifecycle,
            1,
            1,
            NORMAL_TRANSACTION,
            2,
            0,
        ),
    )?;

    exercise_shared_memory(authority, executable.data(), display)?;
    push(
        &mut transcript,
        event(
            EvidenceKind::MemoryShare,
            1,
            1,
            MEMORY_TRANSACTION,
            PAGE_BYTES,
            MEMORY_CHILD_RIGHTS.0,
        ),
    )?;

    let queued = exercise_channel_lifecycle(authority.bootfs)?;
    push(
        &mut transcript,
        event(
            EvidenceKind::ChannelLifecycle,
            1,
            1,
            CHANNEL_TOKEN,
            0xF,
            queued,
        ),
    )?;

    exercise_wait_event_timer()?;
    push(
        &mut transcript,
        event(EvidenceKind::WaitEventTimer, 1, 1, WAIT_TOKEN, 0xF, 0),
    )?;

    exercise_cancellation(authority, executable.data(), display)?;
    push(
        &mut transcript,
        event(
            EvidenceKind::Cancellation,
            2,
            1,
            CANCEL_TRANSACTION,
            u64::from(DW_TERMINATION_AUTHORIZED.0),
            0,
        ),
    )?;

    exercise_restart_replacement(authority, executable.data(), display)?;
    push(
        &mut transcript,
        event(
            EvidenceKind::RestartReplacement,
            3,
            1,
            RESTART_TRANSACTION_BASE + 1,
            1,
            2,
        ),
    )?;
    push(
        &mut transcript,
        event(
            EvidenceKind::RestartReplacement,
            3,
            2,
            RESTART_TRANSACTION_BASE + 2,
            2,
            1,
        ),
    )?;

    exercise_restart_exhaustion(authority, executable.data(), display)?;
    for generation in 1_u32..=4 {
        push(
            &mut transcript,
            event(
                EvidenceKind::RestartExhausted,
                4,
                generation,
                EXHAUST_TRANSACTION_BASE + u64::from(generation),
                u64::from(generation),
                if generation == 4 {
                    0
                } else {
                    u64::from(generation + 1)
                },
            ),
        )?;
    }

    exercise_overload_replay(&mut normal_ledger)?;
    push(
        &mut transcript,
        event(
            EvidenceKind::OverloadReplayRejected,
            1,
            1,
            NORMAL_TRANSACTION,
            0xF,
            2,
        ),
    )?;

    prove_overload_replay_and_cleanup()
        .map_err(|_| failure(EvidenceKind::CleanupBaseline, 0x0030))?;
    prove_restart_replacement_and_exhaustion()
        .map_err(|_| failure(EvidenceKind::CleanupBaseline, 0x0031))?;
    Ok(transcript)
}

fn validate_controller_authority(authority: LoadAuthority) -> Result<(), u32> {
    for (operation, (handle, expectation)) in [
        (authority.parent_root, SELF_ROOT_EXPECTATION),
        (authority.bootfs, wyrmroot_runtime::BOOTFS_EXPECTATION),
        (authority.task_group, LOADER_TASK_GROUP_EXPECTATION),
    ]
    .into_iter()
    .enumerate()
    {
        let info = query_capability_info(handle)
            .map_err(|_| failure(EvidenceKind::ProcessLifecycle, 0x0020 + operation as u16))?;
        if info.object_type != expectation.object_type || info.rights != expectation.rights {
            return Err(failure(
                EvidenceKind::ProcessLifecycle,
                0x0030 + operation as u16,
            ));
        }
    }
    Ok(())
}

fn exercise_normal_lifecycle(
    authority: LoadAuthority,
    image: &[u8],
    display: &str,
    ledger: &mut ReadinessAccounting,
) -> Result<(), u32> {
    let peer = 1_u8;
    let generation = 1_u64;
    ledger
        .begin_generation(peer, generation)
        .map_err(|_| failure(EvidenceKind::ProcessLifecycle, 0x00F1))?;
    let mut transaction = ledger
        .begin_transaction(peer, generation, NORMAL_TRANSACTION)
        .map_err(|_| failure(EvidenceKind::ProcessLifecycle, 0x00F2))?;
    if ledger.begin_transaction(peer, generation, NORMAL_TRANSACTION)
        != Err(AccountingError::DuplicateTransaction)
    {
        return Err(failure(EvidenceKind::ProcessLifecycle, 0x00F3));
    }
    let (loaded, group) = load_child(
        authority,
        image,
        display,
        LaunchProfile::Hello,
        NORMAL_TRANSACTION,
        EvidenceKind::ProcessLifecycle,
        0x0100,
    )?;
    let result = supervise_native_child(
        loaded.process,
        loaded.launch_channel,
        NORMAL_TRANSACTION,
        future_deadline(CHILD_TIMEOUT_NS, EvidenceKind::ProcessLifecycle, 0x0101)?,
    )
    .map_err(|error| supervision_failure(EvidenceKind::ProcessLifecycle, error));
    close_loaded(loaded, group, EvidenceKind::ProcessLifecycle, 0x0110)?;
    result?;
    ledger
        .complete_transaction(&mut transaction)
        .map_err(|_| failure(EvidenceKind::ProcessLifecycle, 0x0120))
}

fn supervision_failure(stage: EvidenceKind, error: SupervisionError<NativeError>) -> u32 {
    let operation = match error {
        SupervisionError::Exit(ExitValidationError::NonzeroApplicationCode(code)) => return code,
        SupervisionError::Platform(error) => 0xa000 | native_cause(error),
        SupervisionError::ExitQuery(error) => 0xa200 | native_cause(error),
        SupervisionError::UnboundedDeadline => 0xa400,
        SupervisionError::InvalidWaitResult => 0xa401,
        SupervisionError::InvalidReadyReceive(_) => 0xa402,
        SupervisionError::Ready(_) => 0xa403,
        SupervisionError::ExitedBeforeReady => 0xa404,
        SupervisionError::PeerClosedBeforeReady => 0xa405,
        SupervisionError::DuplicateReady => 0xa406,
        SupervisionError::Exit(ExitValidationError::InvalidEnvelope) => 0xa420,
        SupervisionError::Exit(ExitValidationError::NotExited) => 0xa421,
        SupervisionError::Exit(ExitValidationError::NotNormalExit) => 0xa422,
        SupervisionError::Exit(ExitValidationError::NonzeroExceptionFields) => 0xa423,
        SupervisionError::ExitObservedReadiness(error) => match error {
            ExitObservedReadinessError::Platform(error) => 0xa600 | native_cause(error),
            ExitObservedReadinessError::InvalidWaitResult => 0xa800,
            ExitObservedReadinessError::InvalidReadyReceive(_) => 0xa801,
            ExitObservedReadinessError::Ready(_) => 0xa802,
            ExitObservedReadinessError::DuplicateReady => 0xa803,
        },
    };
    failure(stage, operation)
}

const fn native_cause(error: NativeError) -> u16 {
    (native_error_code(error) as u16) & 0x01ff
}

fn exercise_shared_memory(
    authority: LoadAuthority,
    image: &[u8],
    display: &str,
) -> Result<(), u32> {
    let memory = create_memory_object(PAGE_BYTES, MEMORY_OWNER_RIGHTS)
        .map_err(|_| failure(EvidenceKind::MemoryShare, 0x0200))?;
    let mut mapping = map_memory_read_write(authority.parent_root, memory, PAGE_BYTES)
        .map_err(|_| failure(EvidenceKind::MemoryShare, 0x0201))?;
    mapping
        .with_bytes_mut(|bytes| {
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = memory_pattern(index);
            }
        })
        .map_err(|_| failure(EvidenceKind::MemoryShare, 0x0202))?;
    mapping
        .protect_read_only()
        .map_err(|_| failure(EvidenceKind::MemoryShare, 0x0203))?;
    let transfer = duplicate_handle(memory, MEMORY_CHILD_RIGHTS)
        .map_err(|_| failure(EvidenceKind::MemoryShare, 0x0204))?;
    let transfer_info =
        query_capability_info(transfer).map_err(|_| failure(EvidenceKind::MemoryShare, 0x0205))?;
    if transfer_info.object_type != DW_OBJECT_TYPE_MEMORY_OBJECT
        || transfer_info.rights != MEMORY_CHILD_RIGHTS
    {
        return Err(failure(EvidenceKind::MemoryShare, 0x0206));
    }

    let (loaded, group) = load_child(
        authority,
        image,
        display,
        LaunchProfile::ProbeChild,
        MEMORY_TRANSACTION,
        EvidenceKind::MemoryShare,
        0x0210,
    )?;
    wait_ready(
        loaded.launch_channel,
        LaunchProfile::ProbeChild,
        MEMORY_TRANSACTION,
        EvidenceKind::MemoryShare,
        0x0211,
    )?;
    let mut command = [0_u8; MEMORY_COMMAND_BYTES];
    command[..4].copy_from_slice(b"WICM");
    command[4..8].copy_from_slice(&1_u32.to_le_bytes());
    command[8..16].copy_from_slice(&MEMORY_TRANSACTION.to_le_bytes());
    let moved = DwHandleTransferV1 {
        handle: transfer,
        requested_rights: MEMORY_CHILD_RIGHTS,
        operation: deepwyrm_syscall::DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    send_channel(loaded.launch_channel, &command, &[moved])
        .map_err(|error| failure(EvidenceKind::MemoryShare, 0xb000 | native_cause(error)))?;
    close_handle(memory).map_err(|_| failure(EvidenceKind::MemoryShare, 0x0213))?;
    let mapping_valid = mapping
        .with_bytes(|bytes| {
            bytes
                .iter()
                .enumerate()
                .all(|(index, byte)| *byte == memory_pattern(index))
        })
        .map_err(|_| failure(EvidenceKind::MemoryShare, 0x0214))?;
    if !mapping_valid {
        return Err(failure(EvidenceKind::MemoryShare, 0x0215));
    }

    wait_one(
        loaded.launch_channel,
        DW_SIGNAL_READABLE,
        future_deadline(CHILD_TIMEOUT_NS, EvidenceKind::MemoryShare, 0x0216)?,
    )
    .map_err(|_| failure(EvidenceKind::MemoryShare, 0x0217))?;
    let mut ack = [0_u8; 8];
    let mut no_handles = [];
    let received = receive_channel(loaded.launch_channel, &mut ack, &mut no_handles)
        .map_err(|_| failure(EvidenceKind::MemoryShare, 0x0218))?;
    if received.bytes != MEMORY_ACK.len() || received.handles != 0 || ack != MEMORY_ACK {
        return Err(failure(EvidenceKind::MemoryShare, 0x0219));
    }
    unmap_memory(mapping).map_err(|_| failure(EvidenceKind::MemoryShare, 0x021A))?;
    wait_normal_exit(loaded, EvidenceKind::MemoryShare, 0x0220)?;
    close_loaded(loaded, group, EvidenceKind::MemoryShare, 0x0230)
}

fn exercise_channel_lifecycle(bootfs: DwHandle) -> Result<u64, u32> {
    let (sender, receiver) = create_channel(CHANNEL_RIGHTS)
        .map_err(|_| failure(EvidenceKind::ChannelLifecycle, 0x0100))?;
    let reduced_rights = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_INSPECT.0);
    let duplicate = duplicate_handle(
        bootfs,
        DwRights(DW_RIGHT_READ.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_TRANSFER.0),
    )
    .map_err(|_| failure(EvidenceKind::ChannelLifecycle, 0x0101))?;
    let moved = DwHandleTransferV1 {
        handle: duplicate,
        requested_rights: reduced_rights,
        operation: deepwyrm_syscall::DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    send_channel(sender, b"handle", &[moved])
        .map_err(|_| failure(EvidenceKind::ChannelLifecycle, 0x0102))?;
    if query_capability_info(duplicate)
        != Err(wyrmroot_runtime::NativeError::Status(DW_STATUS_BAD_HANDLE))
    {
        return Err(failure(EvidenceKind::ChannelLifecycle, 0x0103));
    }
    let mut bytes = [0_u8; 8];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let received = receive_channel(receiver, &mut bytes, &mut handles)
        .map_err(|_| failure(EvidenceKind::ChannelLifecycle, 0x0104))?;
    if received.bytes != 6
        || received.handles != 1
        || &bytes[..6] != b"handle"
        || handles[0].object_type != DW_OBJECT_TYPE_MEMORY_OBJECT
        || handles[0].rights != reduced_rights
    {
        return Err(failure(EvidenceKind::ChannelLifecycle, 0x0105));
    }
    let fresh = query_capability_info(handles[0].handle)
        .map_err(|_| failure(EvidenceKind::ChannelLifecycle, 0x0106))?;
    if fresh.object_type != DW_OBJECT_TYPE_MEMORY_OBJECT || fresh.rights != reduced_rights {
        return Err(failure(EvidenceKind::ChannelLifecycle, 0x0107));
    }
    close_handle(handles[0].handle).map_err(|_| failure(EvidenceKind::ChannelLifecycle, 0x0108))?;

    let mut queued = 0_u64;
    for index in 0..BACKPRESSURE_ATTEMPTS {
        match send_channel(sender, &[index as u8], &[]) {
            Ok(()) => queued += 1,
            Err(wyrmroot_runtime::NativeError::Status(status))
                if status == DW_STATUS_WOULD_BLOCK =>
            {
                break;
            }
            Err(_) => return Err(failure(EvidenceKind::ChannelLifecycle, 0x0110)),
        }
    }
    if queued == 0 || queued as usize == BACKPRESSURE_ATTEMPTS {
        return Err(failure(EvidenceKind::ChannelLifecycle, 0x0111));
    }
    close_handle(sender).map_err(|_| failure(EvidenceKind::ChannelLifecycle, 0x0112))?;
    for index in 0..queued {
        let mut byte = [0_u8; 1];
        let mut none = [];
        let received = receive_channel(receiver, &mut byte, &mut none)
            .map_err(|_| failure(EvidenceKind::ChannelLifecycle, 0x0113))?;
        if received.bytes != 1 || received.handles != 0 || byte[0] != index as u8 {
            return Err(failure(EvidenceKind::ChannelLifecycle, 0x0114));
        }
    }
    let mut empty = [0_u8; 1];
    let mut none = [];
    if receive_channel(receiver, &mut empty, &mut none)
        != Err(wyrmroot_runtime::NativeError::Status(DW_STATUS_PEER_CLOSED))
    {
        return Err(failure(EvidenceKind::ChannelLifecycle, 0x0115));
    }
    close_handle(receiver).map_err(|_| failure(EvidenceKind::ChannelLifecycle, 0x0116))?;
    Ok(queued)
}

fn exercise_wait_event_timer() -> Result<(), u32> {
    let event = create_event(DwRights(
        DW_RIGHT_WAIT.0 | DW_RIGHT_SIGNAL.0 | DW_RIGHT_INSPECT.0,
    ))
    .map_err(|_| failure(EvidenceKind::WaitEventTimer, 0x0100))?;
    signal_event(event, DwSignals(0), DW_SIGNAL_SIGNALED)
        .map_err(|_| failure(EvidenceKind::WaitEventTimer, 0x0101))?;
    wait_one(
        event,
        DW_SIGNAL_SIGNALED,
        future_deadline(SHORT_TIMEOUT_NS, EvidenceKind::WaitEventTimer, 0x0102)?,
    )
    .map_err(|_| failure(EvidenceKind::WaitEventTimer, 0x0103))?;
    signal_event(event, DW_SIGNAL_SIGNALED, DwSignals(0))
        .map_err(|_| failure(EvidenceKind::WaitEventTimer, 0x0104))?;
    let timeout = wait_one(
        event,
        DW_SIGNAL_SIGNALED,
        future_deadline(1, EvidenceKind::WaitEventTimer, 0x0105)?,
    );
    if timeout != Err(wyrmroot_runtime::NativeError::Status(DW_STATUS_TIMED_OUT)) {
        return Err(failure(EvidenceKind::WaitEventTimer, 0x0106));
    }
    close_handle(event).map_err(|_| failure(EvidenceKind::WaitEventTimer, 0x0107))?;

    let timer = create_timer(DwRights(
        DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0,
    ))
    .map_err(|_| failure(EvidenceKind::WaitEventTimer, 0x0110))?;
    let deadline = future_deadline(SHORT_TIMEOUT_NS, EvidenceKind::WaitEventTimer, 0x0111)?;
    set_timer(timer, deadline).map_err(|_| failure(EvidenceKind::WaitEventTimer, 0x0112))?;
    wait_one(
        timer,
        DW_SIGNAL_SIGNALED,
        future_deadline(CHILD_TIMEOUT_NS, EvidenceKind::WaitEventTimer, 0x0113)?,
    )
    .map_err(|_| failure(EvidenceKind::WaitEventTimer, 0x0114))?;
    if monotonic_active_now().map_err(|_| failure(EvidenceKind::WaitEventTimer, 0x0115))?
        < deadline.0
    {
        return Err(failure(EvidenceKind::WaitEventTimer, 0x0116));
    }
    set_timer(
        timer,
        future_deadline(CHILD_TIMEOUT_NS, EvidenceKind::WaitEventTimer, 0x0117)?,
    )
    .map_err(|_| failure(EvidenceKind::WaitEventTimer, 0x0118))?;
    cancel_timer(timer).map_err(|_| failure(EvidenceKind::WaitEventTimer, 0x0119))?;
    let cancelled = wait_one(
        timer,
        DW_SIGNAL_SIGNALED,
        future_deadline(1, EvidenceKind::WaitEventTimer, 0x011A)?,
    );
    if cancelled != Err(wyrmroot_runtime::NativeError::Status(DW_STATUS_TIMED_OUT)) {
        return Err(failure(EvidenceKind::WaitEventTimer, 0x011B));
    }
    close_handle(timer).map_err(|_| failure(EvidenceKind::WaitEventTimer, 0x011C))
}

fn exercise_cancellation(authority: LoadAuthority, image: &[u8], display: &str) -> Result<(), u32> {
    let (loaded, group) = load_child(
        authority,
        image,
        display,
        LaunchProfile::Hello,
        CANCEL_TRANSACTION,
        EvidenceKind::Cancellation,
        0x0100,
    )?;
    wait_ready(
        loaded.launch_channel,
        LaunchProfile::Hello,
        CANCEL_TRANSACTION,
        EvidenceKind::Cancellation,
        0x0101,
    )?;
    terminate_process(loaded.process, DW_TERMINATION_AUTHORIZED, 0)
        .map_err(|_| failure(EvidenceKind::Cancellation, 0x0102))?;
    let info = wait_exit_info(loaded.process, EvidenceKind::Cancellation, 0x0103)?;
    wait_clean_peer_close(loaded.launch_channel, EvidenceKind::Cancellation, 0x0105)?;
    if info.state != DW_TASK_STATE_EXITED
        || info.reason != DW_TERMINATION_AUTHORIZED
        || info.application_code != 0
        || info.exception_type.0 != 0
        || info.detail != 0
        || info.fault_address != 0
    {
        return Err(failure(EvidenceKind::Cancellation, 0x0104));
    }
    close_loaded(loaded, group, EvidenceKind::Cancellation, 0x0110)
}

fn exercise_restart_replacement(
    authority: LoadAuthority,
    image: &[u8],
    display: &str,
) -> Result<(), u32> {
    let peer = 3_u8;
    let mut ledger = ReadinessAccounting::new()
        .map_err(|_| failure(EvidenceKind::RestartReplacement, 0x0100))?;
    let now =
        monotonic_active_now().map_err(|_| failure(EvidenceKind::RestartReplacement, 0x0101))?;
    let mut supervisor = RestartSupervisor::new(WYR0_I_SUPERVISION_POLICY)
        .map_err(|_| failure(EvidenceKind::RestartReplacement, 0x0102))?;
    supervisor
        .begin(now, 1, RESTART_TRANSACTION_BASE + 1)
        .map_err(|_| failure(EvidenceKind::RestartReplacement, 0x0103))?;
    run_restart_attempt(
        authority,
        image,
        display,
        peer,
        1,
        RESTART_TRANSACTION_BASE + 1,
        FAIL_EXIT_CODE,
        &mut supervisor,
        &mut ledger,
        EvidenceKind::RestartReplacement,
        0x0110,
    )?;
    let RestartState::Backoff { deadline_ns, .. } = supervisor.state() else {
        return Err(failure(EvidenceKind::RestartReplacement, 0x0120));
    };
    wait_until(deadline_ns, EvidenceKind::RestartReplacement, 0x0121)?;
    let now =
        monotonic_active_now().map_err(|_| failure(EvidenceKind::RestartReplacement, 0x0122))?;
    supervisor
        .start_replacement(now, 2, RESTART_TRANSACTION_BASE + 2)
        .map_err(|_| failure(EvidenceKind::RestartReplacement, 0x0123))?;
    run_restart_attempt(
        authority,
        image,
        display,
        peer,
        2,
        RESTART_TRANSACTION_BASE + 2,
        0,
        &mut supervisor,
        &mut ledger,
        EvidenceKind::RestartReplacement,
        0x0130,
    )?;
    if supervisor.state() != RestartState::Stopped || supervisor.history().len() != 2 {
        return Err(failure(EvidenceKind::RestartReplacement, 0x0140));
    }
    if ledger
        .finish_restart_episode(peer)
        .map_err(|_| failure(EvidenceKind::RestartReplacement, 0x0141))?
        != 2
    {
        return Err(failure(EvidenceKind::RestartReplacement, 0x0142));
    }
    assert_accounting_zero(&ledger, EvidenceKind::RestartReplacement, 0x0150)
}

fn exercise_restart_exhaustion(
    authority: LoadAuthority,
    image: &[u8],
    display: &str,
) -> Result<(), u32> {
    let peer = 4_u8;
    let mut ledger =
        ReadinessAccounting::new().map_err(|_| failure(EvidenceKind::RestartExhausted, 0x0100))?;
    let now =
        monotonic_active_now().map_err(|_| failure(EvidenceKind::RestartExhausted, 0x0101))?;
    let mut supervisor = RestartSupervisor::new(WYR0_I_SUPERVISION_POLICY)
        .map_err(|_| failure(EvidenceKind::RestartExhausted, 0x0102))?;
    supervisor
        .begin(now, 1, EXHAUST_TRANSACTION_BASE + 1)
        .map_err(|_| failure(EvidenceKind::RestartExhausted, 0x0103))?;
    for generation in 1_u64..=4 {
        if generation > 1 {
            let RestartState::Backoff { deadline_ns, .. } = supervisor.state() else {
                return Err(failure(EvidenceKind::RestartExhausted, 0x0110));
            };
            wait_until(deadline_ns, EvidenceKind::RestartExhausted, 0x0111)?;
            let now = monotonic_active_now()
                .map_err(|_| failure(EvidenceKind::RestartExhausted, 0x0112))?;
            supervisor
                .start_replacement(now, generation, EXHAUST_TRANSACTION_BASE + generation)
                .map_err(|_| failure(EvidenceKind::RestartExhausted, 0x0113))?;
        }
        run_restart_attempt(
            authority,
            image,
            display,
            peer,
            generation,
            EXHAUST_TRANSACTION_BASE + generation,
            EXHAUST_EXIT_CODE,
            &mut supervisor,
            &mut ledger,
            EvidenceKind::RestartExhausted,
            0x0120 + generation as u16 * 0x10,
        )?;
    }
    if !matches!(
        supervisor.state(),
        RestartState::PermanentFailure {
            cleanup: CleanupDisposition::Complete,
            ..
        }
    ) || supervisor.history().len() != 4
    {
        return Err(failure(EvidenceKind::RestartExhausted, 0x0180));
    }
    if ledger
        .finish_restart_episode(peer)
        .map_err(|_| failure(EvidenceKind::RestartExhausted, 0x0181))?
        != 4
    {
        return Err(failure(EvidenceKind::RestartExhausted, 0x0182));
    }
    assert_accounting_zero(&ledger, EvidenceKind::RestartExhausted, 0x0190)
}

#[allow(clippy::too_many_arguments)]
fn run_restart_attempt(
    authority: LoadAuthority,
    image: &[u8],
    display: &str,
    peer: u8,
    generation: u64,
    transaction: u64,
    expected_exit: u32,
    supervisor: &mut RestartSupervisor,
    ledger: &mut ReadinessAccounting,
    stage: EvidenceKind,
    operation: u16,
) -> Result<(), u32> {
    ledger
        .begin_generation(peer, generation)
        .map_err(|_| failure(stage, operation))?;
    let mut transaction_token = ledger
        .begin_transaction(peer, generation, transaction)
        .map_err(|_| failure(stage, operation + 1))?;
    let (loaded, group) = load_child(
        authority,
        image,
        display,
        LaunchProfile::Hello,
        transaction,
        stage,
        operation + 2,
    )?;
    let started = monotonic_active_now().map_err(|_| failure(stage, operation + 3))?;
    supervisor
        .child_started(generation, transaction, started)
        .map_err(|_| failure(stage, operation + 4))?;
    wait_ready(
        loaded.launch_channel,
        LaunchProfile::Hello,
        transaction,
        stage,
        operation + 5,
    )?;
    let ready = monotonic_active_now().map_err(|_| failure(stage, operation + 6))?;
    supervisor
        .ready(generation, transaction, ready)
        .map_err(|_| failure(stage, operation + 7))?;
    ledger
        .complete_transaction(&mut transaction_token)
        .map_err(|_| failure(stage, operation + 8))?;
    let info = wait_exit_info(loaded.process, stage, operation + 9)?;
    wait_clean_peer_close(loaded.launch_channel, stage, operation + 19)?;
    if info.state != DW_TASK_STATE_EXITED
        || info.reason != DW_TERMINATION_NORMAL_EXIT
        || info.application_code != expected_exit
        || info.exception_type.0 != 0
        || info.detail != 0
        || info.fault_address != 0
    {
        return Err(failure(stage, operation + 10));
    }
    let terminal = monotonic_active_now().map_err(|_| failure(stage, operation + 11))?;
    supervisor
        .terminal(
            generation,
            transaction,
            terminal,
            TerminalDisposition::NormalExit(expected_exit),
        )
        .map_err(|_| failure(stage, operation + 12))?;
    close_loaded(loaded, group, stage, operation + 13)?;
    let cleaned = monotonic_active_now().map_err(|_| failure(stage, operation + 14))?;
    supervisor
        .cleanup_complete(generation, transaction, cleaned)
        .map_err(|_| failure(stage, operation + 15))?;
    let record = supervisor
        .history()
        .as_slice()
        .last()
        .and_then(|record| *record)
        .ok_or(failure(stage, operation + 16))?;
    ledger
        .record_restart_history(peer, generation, &record)
        .map_err(|_| failure(stage, operation + 17))?;
    ledger
        .retire_generation(peer, generation)
        .map_err(|_| failure(stage, operation + 18))?;
    Ok(())
}

fn exercise_overload_replay(ledger: &mut ReadinessAccounting) -> Result<(), u32> {
    let peer = 1_u8;
    let generation = 1_u64;
    let transaction = NORMAL_TRANSACTION;
    let exact = ReservationRequest::empty()
        .add(AccountedResource::RetainedPayloadBytes, 4096)
        .map_err(|_| failure(EvidenceKind::OverloadReplayRejected, 0x0102))?;
    let mut reservation = ledger
        .reserve(peer, generation, exact)
        .map_err(|_| failure(EvidenceKind::OverloadReplayRejected, 0x0103))?;
    let over = ReservationRequest::empty()
        .add(AccountedResource::RetainedPayloadBytes, 1)
        .map_err(|_| failure(EvidenceKind::OverloadReplayRejected, 0x0104))?;
    if ledger.reserve(peer, generation, over)
        != Err(AccountingError::PerPeerLimit(
            AccountedResource::RetainedPayloadBytes,
        ))
    {
        return Err(failure(EvidenceKind::OverloadReplayRejected, 0x0105));
    }
    ledger
        .release(&mut reservation)
        .map_err(|_| failure(EvidenceKind::OverloadReplayRejected, 0x0106))?;
    if ledger.begin_transaction(peer, generation, transaction)
        != Err(AccountingError::ReplayedTransaction)
        || ledger.begin_transaction(peer, generation + 1, transaction + 1)
            != Err(AccountingError::StaleGeneration)
    {
        return Err(failure(EvidenceKind::OverloadReplayRejected, 0x010A));
    }
    let record = wyrmroot_runtime::AttemptRecord {
        attempt: 1,
        generation,
        transaction_id: transaction,
        started_at_ns: 1,
        terminal_at_ns: 2,
        failure: AttemptFailure::ExitAfterReady(TerminalDisposition::NormalExit(0)),
        cleanup: CleanupDisposition::Complete,
    };
    ledger
        .record_restart_history(peer, generation, &record)
        .map_err(|_| failure(EvidenceKind::OverloadReplayRejected, 0x010B))?;
    ledger
        .retire_generation(peer, generation)
        .map_err(|_| failure(EvidenceKind::OverloadReplayRejected, 0x010C))?;
    ledger
        .finish_restart_episode(peer)
        .map_err(|_| failure(EvidenceKind::OverloadReplayRejected, 0x010D))?;
    assert_accounting_zero(ledger, EvidenceKind::OverloadReplayRejected, 0x0110)
}

fn assert_accounting_zero(
    ledger: &ReadinessAccounting,
    stage: EvidenceKind,
    operation: u16,
) -> Result<(), u32> {
    for (index, resource) in [
        AccountedResource::LiveProcessGenerations,
        AccountedResource::InFlightTransactions,
        AccountedResource::CompletedReplayEntries,
        AccountedResource::RetainedMessages,
        AccountedResource::RetainedPayloadBytes,
        AccountedResource::DelegatedHandles,
        AccountedResource::SharedMemoryObjects,
        AccountedResource::SharedMemoryBytes,
        AccountedResource::MappedBytes,
        AccountedResource::WaitOperations,
        AccountedResource::Events,
        AccountedResource::Timers,
        AccountedResource::RestartHistoryRecords,
    ]
    .into_iter()
    .enumerate()
    {
        if ledger.aggregate_count(resource) != 0 {
            return Err(failure(stage, operation + index as u16));
        }
    }
    Ok(())
}

fn load_child(
    authority: LoadAuthority,
    image: &[u8],
    display: &str,
    profile: LaunchProfile,
    transaction: u64,
    stage: EvidenceKind,
    operation: u16,
) -> Result<(LoadedProcess, DwHandle), u32> {
    let group = create_task_group(authority.task_group, TASK_GROUP_RIGHTS)
        .map_err(|_| failure(stage, operation))?;
    let loaded = load_process(
        &mut NativeLoaderPlatform,
        LoadAuthority {
            parent_root: authority.parent_root,
            bootfs: authority.bootfs,
            task_group: group,
        },
        LoadRequest {
            image,
            display_path: display,
            profile,
            transaction_id: transaction,
        },
    )
    .map_err(|error| failure(stage, load_error_operation(error)))?;
    Ok((loaded, group))
}

/// Encodes the exact reusable-loader stage, rollback state, and bounded native
/// cause into the operation half of `0x24SSOOOO` failures. This keeps a failed
/// live candidate actionable even when no WRCAP record was publishable.
const fn load_error_operation(error: LoadError<NativeError>) -> u16 {
    match error {
        LoadError::Platform {
            stage,
            cause,
            rollback_failed,
        } => {
            let encoded_cause = native_error_code(cause);
            let output = if encoded_cause & 0x8000 != 0 {
                0x0200
            } else {
                0
            };
            0x8000
                | if rollback_failed { 0x4000 } else { 0 }
                | (load_stage_code(stage) << 10)
                | output
                | (encoded_cause as u16 & 0x01ff)
        }
        LoadError::Elf(_) => 0xf001,
        LoadError::Startup(_) => 0xf002,
        LoadError::Launch(_) => 0xf003,
    }
}

const fn load_stage_code(stage: LoadStage) -> u16 {
    match stage {
        LoadStage::ChannelCreate => 1,
        LoadStage::ChannelReduce => 2,
        LoadStage::ProcessCreate => 3,
        LoadStage::MemoryCreate => 4,
        LoadStage::ParentMaterialize => 5,
        LoadStage::ParentUnmap => 6,
        LoadStage::ChildMap => 7,
        LoadStage::ThreadCreate => 8,
        LoadStage::CapabilityDuplicate => 9,
        LoadStage::InitSend => 10,
        LoadStage::ThreadStart => 11,
        LoadStage::SuccessCleanup => 12,
    }
}

fn wait_ready(
    channel: DwHandle,
    profile: LaunchProfile,
    transaction: u64,
    stage: EvidenceKind,
    operation: u16,
) -> Result<(), u32> {
    let observed = wait_one(
        channel,
        DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        future_deadline(CHILD_TIMEOUT_NS, stage, operation)?,
    )
    .map_err(|_| failure(stage, operation + 1))?;
    if observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
        return Err(failure(stage, operation + 2));
    }
    let mut ready = [0_u8; HEADER_BYTES];
    let mut no_handles = [];
    let received = receive_channel(channel, &mut ready, &mut no_handles)
        .map_err(|_| failure(stage, operation + 3))?;
    let valid = if profile == LaunchProfile::ProbeChild {
        parse_ready_for_profile(profile, &ready, transaction).is_ok()
    } else {
        parse_ready(&ready, transaction).is_ok()
    };
    if received.bytes != HEADER_BYTES || received.handles != 0 || !valid {
        return Err(failure(stage, operation + 4));
    }
    Ok(())
}

fn wait_clean_peer_close(
    channel: DwHandle,
    stage: EvidenceKind,
    operation: u16,
) -> Result<(), u32> {
    let observed = wait_one(
        channel,
        DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
        future_deadline(CHILD_TIMEOUT_NS, stage, operation)?,
    )
    .map_err(|_| failure(stage, operation + 1))?;
    if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 {
        let mut bytes = [0_u8; INIT0_BYTES];
        let mut handles = [DwReceivedHandleInfoV1::default(); 3];
        let received = receive_channel(channel, &mut bytes, &mut handles)
            .map_err(|_| failure(stage, operation + 2))?;
        for handle in handles[..received.handles].iter().map(|info| info.handle) {
            close_handle(handle).map_err(|_| failure(stage, operation + 3))?;
        }
        return Err(failure(stage, operation + 4));
    }
    if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 == 0 {
        return Err(failure(stage, operation + 5));
    }
    Ok(())
}

fn send_channel_bounded(
    channel: DwHandle,
    bytes: &[u8],
    stage: EvidenceKind,
    operation: u16,
) -> Result<(), u32> {
    let deadline = future_deadline(CHILD_TIMEOUT_NS, stage, operation)?;
    for _ in 0..RELAY_SEND_ATTEMPTS {
        match send_channel(channel, bytes, &[]) {
            Ok(()) => return Ok(()),
            Err(wyrmroot_runtime::NativeError::Status(status))
                if status == DW_STATUS_WOULD_BLOCK =>
            {
                let observed = wait_one(
                    channel,
                    DwSignals(DW_SIGNAL_WRITABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
                    deadline,
                )
                .map_err(|_| failure(stage, operation + 1))?;
                if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 != 0
                    || observed.observed.0 & DW_SIGNAL_WRITABLE.0 == 0
                {
                    return Err(failure(stage, operation + 2));
                }
            }
            Err(_) => return Err(failure(stage, operation + 3)),
        }
    }
    Err(failure(stage, operation + 4))
}

fn wait_exit_info(
    process: DwHandle,
    stage: EvidenceKind,
    operation: u16,
) -> Result<deepwyrm_syscall::DwTaskTerminationInfoV1, u32> {
    wait_one(
        process,
        DW_SIGNAL_EXITED,
        future_deadline(CHILD_TIMEOUT_NS, stage, operation)?,
    )
    .map_err(|_| failure(stage, operation + 1))?;
    query_task_termination_info(process).map_err(|_| failure(stage, operation + 2))
}

fn wait_normal_exit(loaded: LoadedProcess, stage: EvidenceKind, operation: u16) -> Result<(), u32> {
    let info = wait_exit_info(loaded.process, stage, operation)?;
    validate_successful_exit(&info).map_err(|_| failure(stage, operation + 3))?;
    let observed = wait_one(
        loaded.launch_channel,
        DW_SIGNAL_PEER_CLOSED,
        future_deadline(CHILD_TIMEOUT_NS, stage, operation + 4)?,
    )
    .map_err(|_| failure(stage, operation + 5))?;
    if observed.observed.0 & DW_SIGNAL_PEER_CLOSED.0 == 0 {
        return Err(failure(stage, operation + 6));
    }
    Ok(())
}

fn close_loaded(
    loaded: LoadedProcess,
    group: DwHandle,
    stage: EvidenceKind,
    operation: u16,
) -> Result<(), u32> {
    for (index, handle) in [loaded.launch_channel, loaded.process, group]
        .into_iter()
        .enumerate()
    {
        close_handle(handle).map_err(|_| failure(stage, operation + index as u16))?;
    }
    Ok(())
}

fn wait_until(deadline_ns: u64, stage: EvidenceKind, operation: u16) -> Result<(), u32> {
    let timer = create_timer(DwRights(
        DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0,
    ))
    .map_err(|_| failure(stage, operation))?;
    set_timer(timer, DwDeadline(deadline_ns)).map_err(|_| failure(stage, operation + 1))?;
    wait_one(
        timer,
        DW_SIGNAL_SIGNALED,
        future_deadline(CHILD_TIMEOUT_NS, stage, operation + 2)?,
    )
    .map_err(|_| failure(stage, operation + 3))?;
    close_handle(timer).map_err(|_| failure(stage, operation + 4))
}

fn send_ready(
    channel: DwHandle,
    transaction: u64,
    stage: EvidenceKind,
    operation: u16,
) -> Result<(), u32> {
    let mut ready = [0_u8; HEADER_BYTES];
    let size = encode_ready(transaction, &mut ready).map_err(|_| failure(stage, operation))?;
    send_channel(channel, &ready[..size], &[]).map_err(|_| failure(stage, operation + 1))
}

fn send_probe_ready(
    channel: DwHandle,
    transaction: u64,
    stage: EvidenceKind,
    operation: u16,
) -> Result<(), u32> {
    let mut ready = [0_u8; HEADER_BYTES];
    let size = encode_ready_for_profile(LaunchProfile::ProbeChild, transaction, &mut ready)
        .map_err(|_| failure(stage, operation))?;
    send_channel(channel, &ready[..size], &[]).map_err(|_| failure(stage, operation + 1))
}

fn future_deadline(delta: u64, stage: EvidenceKind, operation: u16) -> Result<DwDeadline, u32> {
    monotonic_deadline_after(delta).map_err(|_| failure(stage, operation))
}

fn push(transcript: &mut EvidenceTranscript, event: EvidenceEvent) -> Result<(), u32> {
    let stage = event.kind;
    transcript.push(event).map_err(|_| failure(stage, 0x00F0))
}

const fn event(
    kind: EvidenceKind,
    peer: u32,
    generation: u32,
    token: u64,
    arg0: u64,
    arg1: u64,
) -> EvidenceEvent {
    EvidenceEvent {
        kind,
        peer,
        generation,
        token,
        arg0,
        arg1,
    }
}

fn memory_pattern(index: usize) -> u8 {
    (index as u8).wrapping_mul(37).wrapping_add(0x5A)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loader_failure_operation_preserves_stage_cause_and_rollback() {
        assert_eq!(
            load_error_operation(LoadError::Platform {
                stage: LoadStage::ProcessCreate,
                cause: NativeError::Status(deepwyrm_syscall::DwStatus(-13)),
                rollback_failed: false,
            }),
            0x8c0d
        );
        assert_eq!(
            load_error_operation(LoadError::Platform {
                stage: LoadStage::ThreadCreate,
                cause: NativeError::Output(
                    wyrmroot_runtime::NativeOutputError::InvalidLoaderOutput,
                ),
                rollback_failed: true,
            }),
            0xe205
        );
    }

    #[test]
    fn supervision_failure_preserves_child_code_and_classifies_native_failures() {
        let child = failure(EvidenceKind::Cancellation, 0x1234);
        assert_eq!(
            supervision_failure(
                EvidenceKind::ProcessLifecycle,
                SupervisionError::Exit(ExitValidationError::NonzeroApplicationCode(child)),
            ),
            child
        );
        assert_eq!(
            supervision_failure(
                EvidenceKind::ProcessLifecycle,
                SupervisionError::Platform(NativeError::Status(deepwyrm_syscall::DwStatus(-13))),
            ),
            failure(EvidenceKind::ProcessLifecycle, 0xa00d)
        );
    }
}
