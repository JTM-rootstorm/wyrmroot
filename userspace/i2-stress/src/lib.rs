#![no_std]
#![deny(unsafe_code)]

//! Selector-specific, bounded I2 syscall stress payload.
//!
//! The I2 image puts this executable at `bin/hello` and builds init0 with
//! `i2-stress-integration`.  It therefore receives only the ordinary explicit
//! WYR0 loader capabilities; no test-only kernel ABI or ambient handle exists.
//!
//! Stage 7 (concurrent unmap) loads one more copy of this payload under the
//! existing one-capability `ProbeChild` profile.  That child Process holds only
//! its own root AddressRegion; its initial Thread A repeatedly creates, maps,
//! writes, unmaps and closes a page while a second Thread B, created in the
//! same Process by the controller through the loader-returned Process handle,
//! stays resident alternating a user spin with `ClockGet`.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use deepwyrm_syscall::{
    self, DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE, DW_ADDRESS_REGION_MAP_ARGS_V1_VERSION,
    DW_MEMORY_PROTECTION_READ, DW_MEMORY_PROTECTION_WRITE, DW_RIGHT_DUPLICATE, DW_RIGHT_EXECUTE,
    DW_RIGHT_INSPECT, DW_RIGHT_MAP, DW_RIGHT_MODIFY, DW_RIGHT_READ, DW_RIGHT_TRANSFER,
    DW_RIGHT_WAIT, DW_RIGHT_WRITE, DW_SIGNAL_EXITED, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE,
    DW_SIGNAL_SIGNALED, DW_STATUS_SUCCESS, DW_STATUS_TIMED_OUT, DW_STATUS_WOULD_BLOCK,
    DwAddressRegionMapArgsV1, DwAddressRegionMapFlags, DwDeadline, DwHandle, DwHandleTransferV1,
    DwMemoryObjectCreateFlags, DwMemoryProtection, DwOffset, DwReceivedHandleInfoV1, DwRights,
    DwSize, DwThreadStartArgsV1, DwUserAddress, DwWaitResultV1,
};
use wyrmroot_bootfs::archive::Archive;
use wyrmroot_loader::launch::{
    HEADER_BYTES, INIT0_BYTES, LaunchProfile, encode_ready, encode_ready_for_profile, parse_init,
};
use wyrmroot_loader::process::{LoadAuthority, LoadRequest, load_process};
use wyrmroot_runtime::{
    MappingPlan, NativeLoaderPlatform, close_handle, map_bootfs_read_only, monotonic_active_now,
    query_capability_info, query_memory_object_size, receive_channel, send_channel,
    supervise_native_child, unmap_bootfs,
};

/// Fixed input that makes a failure record reproducible without randomized host state.
pub const I2_SEED: u32 = 0x49_32_53_54;
const ITERATIONS: usize = 32;
const BACKPRESSURE_LIMIT: usize = 256;
const PAGE: u64 = 4096;
// Process dispatch and terminal publication require another vCPU to run.  Keep
// this comfortably above the deliberate nanosecond/millisecond timeout probes
// so host scheduling pressure cannot turn the lifecycle oracle into a flake.
const LIFECYCLE_SCHEDULING_TIMEOUT_NS: u64 = 1_000_000_000;

/// WRLP transaction that selects the stage-7 concurrent-unmap child.
pub const CONCURRENT_UNMAP_TRANSACTION: u64 = 0x2207;
/// Thread A's create/map/write/unmap/close rounds.  Sized so the stage spans
/// seconds under four-vCPU TCG QEMU while every round still leaves the root
/// with no stage-7 mapping and no live stage-7 MemoryObject.
pub const CONCURRENT_UNMAP_ROUNDS: u32 = 8192;
/// Thread B's user-mode spin iterations between consecutive `ClockGet` calls.
const RESIDENT_SPIN_ITERATIONS: u32 = 2048;
/// Bound on the whole round loop as observed by the controller, and on every
/// wait whose release depends on that loop finishing.  It sits inside init0's
/// 120-second I2 child deadline (`CHILD_SUPERVISION_DEADLINE_NS`).
const CONCURRENT_UNMAP_TIMEOUT_NS: u64 = 90_000_000_000;
/// Child -> controller announcement tag; followed by little-endian entry and
/// initial stack pointer for Thread B.
pub const RESIDENT_ANNOUNCEMENT_TAG: [u8; 4] = *b"I2S7";
pub const RESIDENT_ANNOUNCEMENT_BYTES: usize = 20;
/// Controller -> child release, sent only after Thread B has exited.
pub const CONCURRENT_UNMAP_JOIN: [u8; 4] = *b"join";
const RESIDENT_STACK_WORDS: usize = 2048;
const PAGE_WORDS: usize = (PAGE / 8) as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Stage {
    Bootstrap = 1,
    Handles = 2,
    Channel = 3,
    Wait = 4,
    Mapping = 5,
    Lifecycle = 6,
    ConcurrentUnmap = 7,
}

/// Stable application result carried by init0's existing structured exit path.
/// Bits 31..24 identify I2, 23..16 the stage, and 15..0 the failing operation.
#[must_use]
pub const fn failure(stage: Stage, operation: u16) -> u32 {
    0x2200_0000 | ((stage as u32) << 16) | operation as u32
}

/// Runs as the I2 controller (`I2Stress` INIT), a normal no-capability leaf
/// (`Hello` INIT), or the stage-7 concurrent-unmap child (`ProbeChild` INIT).
/// The leaf is intentionally tiny and lets the controller exercise init0's real
/// child create/start/exit/terminate path without another ABI.
pub fn run_i2_stress(channel: DwHandle) -> Result<(), u32> {
    let mut bytes = [0_u8; INIT0_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 3];
    let received = receive_channel(channel, &mut bytes, &mut handles)
        .map_err(|_| failure(Stage::Bootstrap, 1))?;
    if received.bytes > bytes.len() || received.handles > handles.len() {
        return Err(failure(Stage::Bootstrap, 2));
    }

    if let Ok(leaf) = parse_init(
        LaunchProfile::Hello,
        &bytes[..received.bytes],
        &handles[..received.handles],
    ) {
        let mut ready = [0_u8; HEADER_BYTES];
        let size = encode_ready(leaf.transaction_id, &mut ready)
            .map_err(|_| failure(Stage::Bootstrap, 3))?;
        send_channel(channel, &ready[..size], &[]).map_err(|_| failure(Stage::Bootstrap, 4))?;
        if leaf.transaction_id == 0x2204 {
            illegal_instruction();
        }
        if leaf.transaction_id == 0x2202 || leaf.transaction_id == 0x2203 {
            let mut command = [0_u8; 4];
            let mut none = [];
            let command_received = receive_channel(channel, &mut command, &mut none)
                .map_err(|_| failure(Stage::Bootstrap, 11))?;
            if command_received.bytes != 4 || command != *b"exit" {
                return Err(failure(Stage::Bootstrap, 12));
            }
        }
        return close_handle(channel).map_err(|_| failure(Stage::Bootstrap, 5));
    }

    if let Ok(child) = parse_init(
        LaunchProfile::ProbeChild,
        &bytes[..received.bytes],
        &handles[..received.handles],
    ) {
        return run_concurrent_unmap_child(channel, handles[0].handle, child.transaction_id);
    }

    let message = parse_init(
        LaunchProfile::I2Stress,
        &bytes[..received.bytes],
        &handles[..received.handles],
    )
    .map_err(|_| failure(Stage::Bootstrap, 6))?;
    let root = handles[0].handle;
    let bootfs = handles[1].handle;
    let task_group = handles[2].handle;
    for handle in [root, bootfs, task_group] {
        query_capability_info(handle).map_err(|_| failure(Stage::Bootstrap, 7))?;
    }

    exercise_handles_and_transfer(bootfs)?;
    exercise_channels_and_waits()?;
    exercise_event_timer_and_atomic()?;
    exercise_mapping(root)?;
    exercise_task_groups(task_group, bootfs)?;
    exercise_lifecycle(root, bootfs, task_group)?;
    close_handle(root).map_err(|_| failure(Stage::Lifecycle, 1))?;
    close_handle(bootfs).map_err(|_| failure(Stage::Lifecycle, 2))?;
    close_handle(task_group).map_err(|_| failure(Stage::Lifecycle, 3))?;
    let mut ready = [0_u8; HEADER_BYTES];
    let size = encode_ready(message.transaction_id, &mut ready)
        .map_err(|_| failure(Stage::Bootstrap, 8))?;
    send_channel(channel, &ready[..size], &[]).map_err(|_| failure(Stage::Bootstrap, 9))?;
    close_handle(channel).map_err(|_| failure(Stage::Bootstrap, 10))
}

#[allow(
    unsafe_code,
    reason = "I2-only exception child deliberately executes UD2 after a valid READY to exercise structured terminal exception handling."
)]
fn illegal_instruction() -> ! {
    // SAFETY: this is an explicit test-only terminal fault. Deepwyrm must convert it into the generated structured illegal-instruction termination record.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

fn exercise_handles_and_transfer(bootfs: DwHandle) -> Result<(), u32> {
    let duplicate_rights =
        DwRights(DW_RIGHT_READ.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_DUPLICATE.0 | DW_RIGHT_TRANSFER.0);
    let mut duplicate = DwHandle(0);
    success(
        deepwyrm_syscall::handle_duplicate(bootfs, duplicate_rights, &mut duplicate),
        Stage::Handles,
        1,
    )?;
    let (first, second) = channel_pair(Stage::Handles, 2)?;
    let moved = DwHandleTransferV1 {
        handle: duplicate,
        requested_rights: duplicate_rights,
        operation: deepwyrm_syscall::DW_HANDLE_TRANSFER_MOVE,
        reserved0: 0,
        reserved: [0; 2],
    };
    success(
        deepwyrm_syscall::channel_send(first, &[I2_SEED as u8], &[moved], 0),
        Stage::Handles,
        3,
    )?;
    let mut bytes = [0_u8; 8];
    let mut received = [DwReceivedHandleInfoV1::default(); 1];
    let mut result = deepwyrm_syscall::DwChannelReceiveResultV1::default();
    success(
        deepwyrm_syscall::channel_receive(second, &mut bytes, &mut received, &mut result),
        Stage::Handles,
        4,
    )?;
    if result.actual_bytes != 1 || result.actual_handles != 1 || received[0].handle.0 == 0 {
        return Err(failure(Stage::Handles, 5));
    }
    close_handle(received[0].handle).map_err(|_| failure(Stage::Handles, 6))?;
    // A fresh query must reject the closed handle, demonstrating stale-handle retirement.
    if query_capability_info(received[0].handle).is_ok() {
        return Err(failure(Stage::Handles, 7));
    }
    close_handle(first).map_err(|_| failure(Stage::Handles, 8))?;
    close_handle(second).map_err(|_| failure(Stage::Handles, 9))
}

fn exercise_channels_and_waits() -> Result<(), u32> {
    let (first, second) = channel_pair(Stage::Channel, 1)?;
    for iteration in 0..ITERATIONS {
        success(
            deepwyrm_syscall::channel_send(first, &[iteration as u8], &[], 0),
            Stage::Channel,
            2,
        )?;
        let mut result = DwWaitResultV1::default();
        success(
            deepwyrm_syscall::wait_one(
                second,
                DW_SIGNAL_READABLE,
                future_deadline(1_000_000)?,
                &mut result,
            ),
            Stage::Wait,
            1,
        )?;
        let mut bytes = [0_u8; 1];
        let mut handles = [];
        let mut receive = deepwyrm_syscall::DwChannelReceiveResultV1::default();
        success(
            deepwyrm_syscall::channel_receive(second, &mut bytes, &mut handles, &mut receive),
            Stage::Channel,
            3,
        )?;
        if receive.actual_bytes != 1 || bytes[0] != iteration as u8 {
            return Err(failure(Stage::Channel, 4));
        }
    }
    let mut filled = 0;
    while filled < BACKPRESSURE_LIMIT {
        let status = deepwyrm_syscall::channel_send(first, &[filled as u8], &[], 0);
        if status == DW_STATUS_WOULD_BLOCK {
            break;
        }
        success(status, Stage::Channel, 7)?;
        filled += 1;
    }
    if filled == BACKPRESSURE_LIMIT {
        return Err(failure(Stage::Channel, 8));
    }
    for _ in 0..filled {
        let mut bytes = [0_u8; 1];
        let mut handles = [];
        let mut receive = deepwyrm_syscall::DwChannelReceiveResultV1::default();
        success(
            deepwyrm_syscall::channel_receive(second, &mut bytes, &mut handles, &mut receive),
            Stage::Channel,
            9,
        )?;
    }
    let mut timeout = DwWaitResultV1::default();
    if deepwyrm_syscall::wait_one(
        second,
        DW_SIGNAL_READABLE,
        future_deadline(1)?,
        &mut timeout,
    ) != DW_STATUS_TIMED_OUT
    {
        return Err(failure(Stage::Wait, 2));
    }
    close_handle(first).map_err(|_| failure(Stage::Channel, 5))?;
    let mut closed = DwWaitResultV1::default();
    success(
        deepwyrm_syscall::wait_one(
            second,
            DW_SIGNAL_PEER_CLOSED,
            future_deadline(1_000_000)?,
            &mut closed,
        ),
        Stage::Wait,
        3,
    )?;
    close_handle(second).map_err(|_| failure(Stage::Channel, 6))
}

fn exercise_event_timer_and_atomic() -> Result<(), u32> {
    let mut event = DwHandle(0);
    let event_rights =
        DwRights(DW_RIGHT_WAIT.0 | deepwyrm_syscall::DW_RIGHT_SIGNAL.0 | DW_RIGHT_INSPECT.0);
    raw::event_create(event_rights, &mut event).map_err(|_| failure(Stage::Wait, 10))?;
    raw::event_signal(event, deepwyrm_syscall::DwSignals(0), DW_SIGNAL_SIGNALED)
        .map_err(|_| failure(Stage::Wait, 11))?;
    let mut result = DwWaitResultV1::default();
    success(
        deepwyrm_syscall::wait_one(
            event,
            DW_SIGNAL_SIGNALED,
            future_deadline(1_000_000)?,
            &mut result,
        ),
        Stage::Wait,
        12,
    )?;
    raw::event_signal(event, DW_SIGNAL_SIGNALED, deepwyrm_syscall::DwSignals(0))
        .map_err(|_| failure(Stage::Wait, 13))?;
    close_handle(event).map_err(|_| failure(Stage::Wait, 14))?;
    let mut timer = DwHandle(0);
    let timer_rights = DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0);
    raw::timer_create(timer_rights, &mut timer).map_err(|_| failure(Stage::Wait, 15))?;
    for _ in 0..3 {
        raw::timer_set(timer, future_deadline(1_000_000)?).map_err(|_| failure(Stage::Wait, 16))?;
        let mut timer_result = DwWaitResultV1::default();
        success(
            deepwyrm_syscall::wait_one(
                timer,
                DW_SIGNAL_SIGNALED,
                future_deadline(10_000_000)?,
                &mut timer_result,
            ),
            Stage::Wait,
            17,
        )?;
    }
    raw::timer_set(timer, future_deadline(10_000_000)?).map_err(|_| failure(Stage::Wait, 18))?;
    raw::timer_cancel(timer).map_err(|_| failure(Stage::Wait, 19))?;
    close_handle(timer).map_err(|_| failure(Stage::Wait, 20))?;
    let word = 1_u32;
    if raw::atomic_wait32(&word, 0, future_deadline(1_000_000)?) != DW_STATUS_WOULD_BLOCK {
        return Err(failure(Stage::Wait, 21));
    }
    let mut woken = 1_u32;
    raw::atomic_wake(&word, 0, &mut woken).map_err(|_| failure(Stage::Wait, 22))?;
    if woken != 0 {
        return Err(failure(Stage::Wait, 23));
    }
    raw::atomic_wake(&word, 1, &mut woken).map_err(|_| failure(Stage::Wait, 24))?;
    if woken != 0 {
        return Err(failure(Stage::Wait, 25));
    }
    Ok(())
}

fn exercise_mapping(root: DwHandle) -> Result<(), u32> {
    let rights = DwRights(
        DW_RIGHT_READ.0
            | DW_RIGHT_WRITE.0
            | DW_RIGHT_EXECUTE.0
            | DW_RIGHT_MAP.0
            | DW_RIGHT_INSPECT.0,
    );
    let mut memory = DwHandle(0);
    success(
        deepwyrm_syscall::memory_object_create(
            DwSize(PAGE),
            DwMemoryObjectCreateFlags(0),
            rights,
            &mut memory,
        ),
        Stage::Mapping,
        1,
    )?;
    let args = DwAddressRegionMapArgsV1 {
        size: DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE,
        version: DW_ADDRESS_REGION_MAP_ARGS_V1_VERSION,
        memory_object_offset: DwOffset(0),
        byte_len: DwSize(PAGE),
        requested_address: DwUserAddress(0),
        protections: DwMemoryProtection(DW_MEMORY_PROTECTION_READ.0 | DW_MEMORY_PROTECTION_WRITE.0),
        flags: DwAddressRegionMapFlags(0),
        reserved: [0; 4],
    };
    let mut address = DwUserAddress(0);
    success(
        deepwyrm_syscall::address_region_map(root, memory, &args, &mut address),
        Stage::Mapping,
        2,
    )?;
    // Mapping captures its authority ceiling; finalization must wait for unmap.
    close_handle(memory).map_err(|_| failure(Stage::Mapping, 3))?;
    success(
        deepwyrm_syscall::address_region_protect(
            root,
            address,
            DwSize(PAGE),
            DW_MEMORY_PROTECTION_READ,
        ),
        Stage::Mapping,
        4,
    )?;
    success(
        deepwyrm_syscall::address_region_unmap(root, address, DwSize(PAGE)),
        Stage::Mapping,
        5,
    )?;
    Ok(())
}

fn exercise_task_groups(parent: DwHandle, wrong_type: DwHandle) -> Result<(), u32> {
    let rights = DwRights(
        DW_RIGHT_MODIFY.0 | DW_RIGHT_DUPLICATE.0 | DW_RIGHT_TRANSFER.0 | DW_RIGHT_INSPECT.0,
    );
    let mut child = DwHandle(0);
    if raw::task_group_create(parent, rights, &mut child) != DW_STATUS_SUCCESS {
        return Err(failure(Stage::Lifecycle, 30));
    }
    raw::task_group_terminate(child, deepwyrm_syscall::DW_TERMINATION_AUTHORIZED)
        .map_err(|_| failure(Stage::Lifecycle, 31))?;
    close_handle(child).map_err(|_| failure(Stage::Lifecycle, 32))?;
    let mut rejected = DwHandle(0);
    if raw::task_group_create(wrong_type, rights, &mut rejected)
        != deepwyrm_syscall::DW_STATUS_WRONG_OBJECT_TYPE
    {
        return Err(failure(Stage::Lifecycle, 33));
    }
    let mut reduced = DwHandle(0);
    success(
        deepwyrm_syscall::handle_duplicate(parent, DW_RIGHT_INSPECT, &mut reduced),
        Stage::Lifecycle,
        34,
    )?;
    if raw::task_group_create(reduced, rights, &mut rejected)
        != deepwyrm_syscall::DW_STATUS_ACCESS_DENIED
    {
        return Err(failure(Stage::Lifecycle, 35));
    }
    close_handle(reduced).map_err(|_| failure(Stage::Lifecycle, 36))
}

fn exercise_lifecycle(root: DwHandle, bootfs: DwHandle, task_group: DwHandle) -> Result<(), u32> {
    let bytes = query_memory_object_size(bootfs).map_err(|_| failure(Stage::Lifecycle, 10))?;
    let plan = MappingPlan::for_bootfs(bytes).map_err(|_| failure(Stage::Lifecycle, 11))?;
    let mapping =
        map_bootfs_read_only(root, bootfs, plan).map_err(|_| failure(Stage::Lifecycle, 12))?;
    let result = mapping.with_logical_bytes(|archive_bytes| {
        let archive = Archive::new(archive_bytes).map_err(|_| failure(Stage::Lifecycle, 13))?;
        let entry = archive
            .lookup(b"bin/hello")
            .map_err(|_| failure(Stage::Lifecycle, 14))?;
        if !entry.is_executable() || entry.data().is_empty() {
            return Err(failure(Stage::Lifecycle, 15));
        }
        let display = entry
            .name_utf8()
            .map_err(|_| failure(Stage::Lifecycle, 16))?;
        let authority = LoadAuthority {
            parent_root: root,
            bootfs,
            task_group,
        };
        let mut loader = NativeLoaderPlatform;
        let normal = load_process(
            &mut loader,
            authority,
            LoadRequest {
                image: entry.data(),
                display_path: display,
                profile: LaunchProfile::Hello,
                transaction_id: 0x2201,
            },
        )
        .map_err(|_| failure(Stage::Lifecycle, 17))?;
        let normal_result = supervise_native_child(
            normal.process,
            normal.launch_channel,
            0x2201,
            future_deadline(LIFECYCLE_SCHEDULING_TIMEOUT_NS)?,
        );
        close_handle(normal.launch_channel).map_err(|_| failure(Stage::Lifecycle, 18))?;
        close_handle(normal.process).map_err(|_| failure(Stage::Lifecycle, 19))?;
        normal_result.map_err(|_| failure(Stage::Lifecycle, 20))?;

        // Start two held leaves before either is supervised.  The first remains
        // running until explicit termination; the second exits only after its
        // launch-channel command, so this is a real overlapping-root teardown.
        let held = load_process(
            &mut loader,
            authority,
            LoadRequest {
                image: entry.data(),
                display_path: display,
                profile: LaunchProfile::Hello,
                transaction_id: 0x2202,
            },
        )
        .map_err(|_| failure(Stage::Lifecycle, 21))?;
        let released = load_process(
            &mut loader,
            authority,
            LoadRequest {
                image: entry.data(),
                display_path: display,
                profile: LaunchProfile::Hello,
                transaction_id: 0x2203,
            },
        )
        .map_err(|_| failure(Stage::Lifecycle, 22))?;
        send_channel(released.launch_channel, b"exit", &[])
            .map_err(|_| failure(Stage::Lifecycle, 23))?;
        let status = deepwyrm_syscall::process_terminate(
            held.process,
            deepwyrm_syscall::DW_TERMINATION_AUTHORIZED,
            I2_SEED,
        );
        if status != DW_STATUS_SUCCESS && status != deepwyrm_syscall::DW_STATUS_BAD_STATE {
            return Err(failure(Stage::Lifecycle, 24));
        }
        let mut terminal = DwWaitResultV1::default();
        success(
            deepwyrm_syscall::wait_one(
                held.process,
                DW_SIGNAL_EXITED,
                future_deadline(LIFECYCLE_SCHEDULING_TIMEOUT_NS)?,
                &mut terminal,
            ),
            Stage::Lifecycle,
            25,
        )?;
        close_handle(held.launch_channel).map_err(|_| failure(Stage::Lifecycle, 26))?;
        close_handle(held.process).map_err(|_| failure(Stage::Lifecycle, 27))?;
        let released_result = supervise_native_child(
            released.process,
            released.launch_channel,
            0x2203,
            future_deadline(LIFECYCLE_SCHEDULING_TIMEOUT_NS)?,
        );
        close_handle(released.launch_channel).map_err(|_| failure(Stage::Lifecycle, 28))?;
        close_handle(released.process).map_err(|_| failure(Stage::Lifecycle, 29))?;
        released_result.map_err(|_| failure(Stage::Lifecycle, 40))?;

        let exception = load_process(
            &mut loader,
            authority,
            LoadRequest {
                image: entry.data(),
                display_path: display,
                profile: LaunchProfile::Hello,
                transaction_id: 0x2204,
            },
        )
        .map_err(|_| failure(Stage::Lifecycle, 41))?;
        let mut exception_wait = DwWaitResultV1::default();
        success(
            deepwyrm_syscall::wait_one(
                exception.process,
                DW_SIGNAL_EXITED,
                future_deadline(LIFECYCLE_SCHEDULING_TIMEOUT_NS)?,
                &mut exception_wait,
            ),
            Stage::Lifecycle,
            42,
        )?;
        let info = wyrmroot_runtime::query_task_termination_info(exception.process)
            .map_err(|_| failure(Stage::Lifecycle, 43))?;
        if info.state != deepwyrm_syscall::DW_TASK_STATE_EXITED
            || info.reason != deepwyrm_syscall::DW_TERMINATION_UNHANDLED_EXCEPTION
            || info.exception_type != deepwyrm_syscall::DW_EXCEPTION_ILLEGAL_INSTRUCTION
        {
            return Err(failure(Stage::Lifecycle, 44));
        }
        close_handle(exception.launch_channel).map_err(|_| failure(Stage::Lifecycle, 45))?;
        close_handle(exception.process).map_err(|_| failure(Stage::Lifecycle, 46))?;

        // Stage 7 needs the same immutable payload image, so it runs while the
        // lifecycle stage's read-only bootfs mapping is still live.
        exercise_concurrent_unmap(&mut loader, authority, entry.data(), display)
    });
    let unmap = unmap_bootfs(mapping).map_err(|_| failure(Stage::Lifecycle, 26));
    result?;
    unmap
}

// ---------------------------------------------------------------------------
// Stage 7: concurrent unmap.
//
// Protocol on the child's WRLP launch channel (transaction 0x2207):
//   1. loader -> child   INIT(ProbeChild): exactly the child's own root.
//   2. child -> ctl      "I2S7" ++ entry:u64le ++ stack_pointer:u64le.
//   3. ctl               thread_create(child Process) + thread_start(Thread B).
//   4. Thread B          RESIDENT=1, then spin/ClockGet until STOP, thread_exit.
//   5. Thread A          waits RESIDENT, runs the rounds, then sets STOP.
//   6. ctl               waits Thread B EXITED (normal, code 0), sends "join".
//   7. Thread A          receives "join", sends READY(ProbeChild, 0x2207), exits 0.
//   8. ctl               waits Process EXITED (normal, code 0) and the READY.
// A nonzero child or Thread B exit code is already a 0x2207xxxx failure and is
// returned unchanged by the controller.

/// Thread B's stack.  Atomics make the region interior-mutable, so the CPU
/// writing it through RSP never aliases a Rust shared reference.
#[repr(C, align(16))]
struct ResidentStack([AtomicU64; RESIDENT_STACK_WORDS]);

static RESIDENT_STACK: ResidentStack =
    ResidentStack([const { AtomicU64::new(0) }; RESIDENT_STACK_WORDS]);
static RESIDENT: AtomicU32 = AtomicU32::new(0);
static STOP: AtomicU32 = AtomicU32::new(0);
static RESIDENT_CLOCK_READS: AtomicU64 = AtomicU64::new(0);

/// Encodes the child's Thread B start announcement.
#[must_use]
pub fn encode_resident_announcement(
    entry: u64,
    stack_pointer: u64,
) -> [u8; RESIDENT_ANNOUNCEMENT_BYTES] {
    let mut bytes = [0_u8; RESIDENT_ANNOUNCEMENT_BYTES];
    bytes[..4].copy_from_slice(&RESIDENT_ANNOUNCEMENT_TAG);
    bytes[4..12].copy_from_slice(&entry.to_le_bytes());
    bytes[12..20].copy_from_slice(&stack_pointer.to_le_bytes());
    bytes
}

/// Decodes an exact announcement; any other length or tag is rejected.
#[must_use]
pub fn decode_resident_announcement(bytes: &[u8]) -> Option<(u64, u64)> {
    if bytes.len() != RESIDENT_ANNOUNCEMENT_BYTES || bytes[..4] != RESIDENT_ANNOUNCEMENT_TAG {
        return None;
    }
    let entry = u64::from_le_bytes(bytes[4..12].try_into().ok()?);
    let stack_pointer = u64::from_le_bytes(bytes[12..20].try_into().ok()?);
    if entry == 0 || stack_pointer == 0 {
        return None;
    }
    Some((entry, stack_pointer))
}

/// Initial RSP for a stack occupying `[base, base + bytes)`: one word below a
/// 16-byte-aligned top, i.e. the SysV state immediately after a `call`.
#[must_use]
pub const fn resident_stack_pointer(base: u64, bytes: u64) -> Option<u64> {
    if bytes < 64 {
        return None;
    }
    let Some(top) = base.checked_add(bytes) else {
        return None;
    };
    if !top.is_multiple_of(16) {
        return None;
    }
    Some(top - 8)
}

/// Value Thread A writes to word `index` of the page in `round`.
#[must_use]
pub const fn concurrent_unmap_word(round: u32, index: usize) -> u64 {
    ((I2_SEED as u64) << 32) ^ ((round as u64) << 12) ^ index as u64
}

fn exercise_concurrent_unmap(
    loader: &mut NativeLoaderPlatform,
    authority: LoadAuthority,
    image: &[u8],
    display: &str,
) -> Result<(), u32> {
    let child = load_process(
        loader,
        authority,
        LoadRequest {
            image,
            display_path: display,
            profile: LaunchProfile::ProbeChild,
            transaction_id: CONCURRENT_UNMAP_TRANSACTION,
        },
    )
    .map_err(|_| failure(Stage::ConcurrentUnmap, 1))?;
    let result = supervise_concurrent_unmap(child.process, child.launch_channel);
    let cleanup = if result.is_err() {
        terminate_concurrent_unmap_child(child.process)
    } else {
        Ok(())
    };
    let channel_closed = close_handle(child.launch_channel);
    let process_closed = close_handle(child.process);
    result?;
    cleanup?;
    channel_closed.map_err(|_| failure(Stage::ConcurrentUnmap, 16))?;
    process_closed.map_err(|_| failure(Stage::ConcurrentUnmap, 17))
}

fn terminate_concurrent_unmap_child(process: DwHandle) -> Result<(), u32> {
    let status = deepwyrm_syscall::process_terminate(
        process,
        deepwyrm_syscall::DW_TERMINATION_AUTHORIZED,
        I2_SEED,
    );
    if status != DW_STATUS_SUCCESS && status != deepwyrm_syscall::DW_STATUS_BAD_STATE {
        return Err(failure(Stage::ConcurrentUnmap, 18));
    }
    let mut terminal = DwWaitResultV1::default();
    success(
        deepwyrm_syscall::wait_one(
            process,
            DW_SIGNAL_EXITED,
            future_deadline(LIFECYCLE_SCHEDULING_TIMEOUT_NS)?,
            &mut terminal,
        ),
        Stage::ConcurrentUnmap,
        19,
    )
}

fn supervise_concurrent_unmap(process: DwHandle, channel: DwHandle) -> Result<(), u32> {
    wait_signal(
        channel,
        DW_SIGNAL_READABLE,
        LIFECYCLE_SCHEDULING_TIMEOUT_NS,
        2,
    )?;
    let mut announcement = [0_u8; RESIDENT_ANNOUNCEMENT_BYTES + 1];
    let mut none = [];
    let received = receive_channel(channel, &mut announcement, &mut none)
        .map_err(|_| failure(Stage::ConcurrentUnmap, 3))?;
    let (entry, stack_pointer) = announcement
        .get(..received.bytes)
        .filter(|_| received.handles == 0)
        .and_then(decode_resident_announcement)
        .ok_or(failure(Stage::ConcurrentUnmap, 3))?;

    let rights =
        DwRights(DW_RIGHT_EXECUTE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0);
    let mut thread = DwHandle(0);
    success(
        deepwyrm_syscall::thread_create(process, rights, &mut thread),
        Stage::ConcurrentUnmap,
        4,
    )?;
    let result = start_and_join_resident(process, channel, thread, entry, stack_pointer);
    let closed = close_handle(thread);
    result?;
    closed.map_err(|_| failure(Stage::ConcurrentUnmap, 15))
}

fn start_and_join_resident(
    process: DwHandle,
    channel: DwHandle,
    thread: DwHandle,
    entry: u64,
    stack_pointer: u64,
) -> Result<(), u32> {
    let args = DwThreadStartArgsV1 {
        size: deepwyrm_syscall::DW_THREAD_START_ARGS_V1_SIZE,
        version: 1,
        thread,
        entry: DwUserAddress(entry),
        stack_pointer: DwUserAddress(stack_pointer),
        startup_argument0: 0,
        startup_argument1: 0,
        flags: 0,
        reserved: [0; 3],
    };
    success(
        deepwyrm_syscall::thread_start(&args),
        Stage::ConcurrentUnmap,
        5,
    )?;
    wait_signal(thread, DW_SIGNAL_EXITED, CONCURRENT_UNMAP_TIMEOUT_NS, 6)?;
    normal_exit(thread, 7, 8)?;

    send_channel(channel, &CONCURRENT_UNMAP_JOIN, &[])
        .map_err(|_| failure(Stage::ConcurrentUnmap, 9))?;
    wait_signal(
        process,
        DW_SIGNAL_EXITED,
        LIFECYCLE_SCHEDULING_TIMEOUT_NS,
        10,
    )?;
    normal_exit(process, 11, 12)?;

    let mut expected = [0_u8; HEADER_BYTES];
    let expected_size = encode_ready_for_profile(
        LaunchProfile::ProbeChild,
        CONCURRENT_UNMAP_TRANSACTION,
        &mut expected,
    )
    .map_err(|_| failure(Stage::ConcurrentUnmap, 14))?;
    let mut ready = [0_u8; HEADER_BYTES + 1];
    let mut none = [];
    let received = receive_channel(channel, &mut ready, &mut none)
        .map_err(|_| failure(Stage::ConcurrentUnmap, 13))?;
    if received.handles != 0 || ready.get(..received.bytes) != expected.get(..expected_size) {
        return Err(failure(Stage::ConcurrentUnmap, 14));
    }
    Ok(())
}

/// Requires a normal exit with application code zero.  A nonzero code from
/// this payload is already a stage-7 failure record and is returned verbatim.
fn normal_exit(task: DwHandle, query_operation: u16, state_operation: u16) -> Result<(), u32> {
    let info = wyrmroot_runtime::query_task_termination_info(task)
        .map_err(|_| failure(Stage::ConcurrentUnmap, query_operation))?;
    if info.state != deepwyrm_syscall::DW_TASK_STATE_EXITED
        || info.reason != deepwyrm_syscall::DW_TERMINATION_NORMAL_EXIT
    {
        return Err(failure(Stage::ConcurrentUnmap, state_operation));
    }
    match info.application_code {
        0 => Ok(()),
        code if code & 0xffff_0000 == failure(Stage::ConcurrentUnmap, 0) => Err(code),
        _ => Err(failure(Stage::ConcurrentUnmap, state_operation)),
    }
}

fn wait_signal(
    handle: DwHandle,
    signals: deepwyrm_syscall::DwSignals,
    timeout: u64,
    operation: u16,
) -> Result<(), u32> {
    let deadline = monotonic_active_now()
        .ok()
        .and_then(|now| now.checked_add(timeout))
        .map(DwDeadline)
        .ok_or(failure(Stage::ConcurrentUnmap, 0x2e))?;
    let mut observed = DwWaitResultV1::default();
    success(
        deepwyrm_syscall::wait_one(handle, signals, deadline, &mut observed),
        Stage::ConcurrentUnmap,
        operation,
    )
}

/// Thread A: the child's initial Thread.
fn run_concurrent_unmap_child(
    channel: DwHandle,
    root: DwHandle,
    transaction_id: u64,
) -> Result<(), u32> {
    if transaction_id != CONCURRENT_UNMAP_TRANSACTION {
        return Err(failure(Stage::ConcurrentUnmap, 0x20));
    }
    let entry = concurrent_unmap_resident as extern "C" fn(u64, u64) -> ! as usize as u64;
    let stack_base = (&raw const RESIDENT_STACK).addr() as u64;
    let stack_pointer =
        resident_stack_pointer(stack_base, core::mem::size_of::<ResidentStack>() as u64)
            .ok_or(failure(Stage::ConcurrentUnmap, 0x20))?;
    send_channel(
        channel,
        &encode_resident_announcement(entry, stack_pointer),
        &[],
    )
    .map_err(|_| failure(Stage::ConcurrentUnmap, 0x21))?;

    let rounds = wait_resident().and_then(|()| concurrent_unmap_rounds(root));
    // Release Thread B whatever the rounds' outcome so the controller can
    // observe its clean exit before it releases this Thread.
    STOP.store(1, Ordering::Release);

    wait_signal(
        channel,
        DW_SIGNAL_READABLE,
        CONCURRENT_UNMAP_TIMEOUT_NS,
        0x28,
    )?;
    let mut join = [0_u8; 5];
    let mut none = [];
    let received = receive_channel(channel, &mut join, &mut none)
        .map_err(|_| failure(Stage::ConcurrentUnmap, 0x29))?;
    if received.handles != 0 || join.get(..received.bytes) != Some(&CONCURRENT_UNMAP_JOIN[..]) {
        return Err(failure(Stage::ConcurrentUnmap, 0x29));
    }
    rounds?;
    close_handle(root).map_err(|_| failure(Stage::ConcurrentUnmap, 0x2d))?;
    let mut ready = [0_u8; HEADER_BYTES];
    let size = encode_ready_for_profile(LaunchProfile::ProbeChild, transaction_id, &mut ready)
        .map_err(|_| failure(Stage::ConcurrentUnmap, 0x2a))?;
    send_channel(channel, &ready[..size], &[])
        .map_err(|_| failure(Stage::ConcurrentUnmap, 0x2b))?;
    close_handle(channel).map_err(|_| failure(Stage::ConcurrentUnmap, 0x2c))
}

fn wait_resident() -> Result<(), u32> {
    let deadline = monotonic_active_now()
        .ok()
        .and_then(|now| now.checked_add(LIFECYCLE_SCHEDULING_TIMEOUT_NS))
        .ok_or(failure(Stage::ConcurrentUnmap, 0x2e))?;
    while RESIDENT.load(Ordering::Acquire) == 0 {
        let now = monotonic_active_now().map_err(|_| failure(Stage::ConcurrentUnmap, 0x2e))?;
        if now >= deadline {
            return Err(failure(Stage::ConcurrentUnmap, 0x22));
        }
        core::hint::spin_loop();
    }
    Ok(())
}

fn concurrent_unmap_rounds(root: DwHandle) -> Result<(), u32> {
    let memory_rights =
        DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0 | DW_RIGHT_INSPECT.0);
    let map = DwAddressRegionMapArgsV1 {
        size: DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE,
        version: DW_ADDRESS_REGION_MAP_ARGS_V1_VERSION,
        memory_object_offset: DwOffset(0),
        byte_len: DwSize(PAGE),
        requested_address: DwUserAddress(0),
        protections: DwMemoryProtection(DW_MEMORY_PROTECTION_READ.0 | DW_MEMORY_PROTECTION_WRITE.0),
        flags: DwAddressRegionMapFlags(0),
        reserved: [0; 4],
    };
    for round in 0..CONCURRENT_UNMAP_ROUNDS {
        let mut memory = DwHandle(0);
        success(
            deepwyrm_syscall::memory_object_create(
                DwSize(PAGE),
                DwMemoryObjectCreateFlags(0),
                memory_rights,
                &mut memory,
            ),
            Stage::ConcurrentUnmap,
            0x23,
        )?;
        let mut address = DwUserAddress(0);
        let mapped = success(
            deepwyrm_syscall::address_region_map(root, memory, &map, &mut address),
            Stage::ConcurrentUnmap,
            0x24,
        );
        let written = mapped.and_then(|()| {
            if write_and_verify_page(address.0, round) {
                Ok(())
            } else {
                Err(failure(Stage::ConcurrentUnmap, 0x25))
            }
        });
        let unmapped = if mapped.is_ok() {
            success(
                deepwyrm_syscall::address_region_unmap(root, address, DwSize(PAGE)),
                Stage::ConcurrentUnmap,
                0x26,
            )
        } else {
            Ok(())
        };
        let closed = close_handle(memory).map_err(|_| failure(Stage::ConcurrentUnmap, 0x27));
        written?;
        unmapped?;
        closed?;
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "I2 stage 7 must store through the one fresh RW page Thread A just mapped and is about to unmap; this is the payload's only raw user-memory access."
)]
fn write_and_verify_page(address: u64, round: u32) -> bool {
    if address == 0 || !address.is_multiple_of(PAGE) {
        return false;
    }
    let page = core::ptr::with_exposed_provenance_mut::<u64>(address as usize);
    for index in 0..PAGE_WORDS {
        // SAFETY: `address` is the page-aligned start of a PAGE-byte READ|WRITE
        // mapping returned by `address_region_map` on this Thread and not yet
        // unmapped; no other Thread or Rust reference uses it, and `index` stays
        // within its PAGE / 8 words.
        unsafe {
            page.add(index)
                .write_volatile(concurrent_unmap_word(round, index))
        };
    }
    (0..PAGE_WORDS).all(|index| {
        // SAFETY: as above; the mapping is still live and exclusively owned.
        unsafe { page.add(index).read_volatile() == concurrent_unmap_word(round, index) }
    })
}

/// Thread B: entered by `thread_start` with RSP one word below a 16-byte
/// boundary, RDI/RSI = 0, and never returns.
extern "C" fn concurrent_unmap_resident(_argument0: u64, _argument1: u64) -> ! {
    RESIDENT.store(1, Ordering::Release);
    let mut code = 0;
    let mut previous = 0_u64;
    while STOP.load(Ordering::Acquire) == 0 {
        for _ in 0..RESIDENT_SPIN_ITERATIONS {
            core::hint::spin_loop();
        }
        let mut now = 0_u64;
        if deepwyrm_syscall::clock_get(deepwyrm_syscall::DW_CLOCK_MONOTONIC_ACTIVE.0, &mut now)
            != DW_STATUS_SUCCESS
        {
            code = failure(Stage::ConcurrentUnmap, 0x30);
            break;
        }
        if now < previous {
            code = failure(Stage::ConcurrentUnmap, 0x31);
            break;
        }
        previous = now;
        RESIDENT_CLOCK_READS.fetch_add(1, Ordering::Relaxed);
    }
    let _ = deepwyrm_syscall::thread_exit(code);
    loop {
        core::hint::spin_loop();
    }
}

fn channel_pair(stage: Stage, operation: u16) -> Result<(DwHandle, DwHandle), u32> {
    let rights = DwRights(
        DW_RIGHT_READ.0
            | DW_RIGHT_WRITE.0
            | DW_RIGHT_WAIT.0
            | DW_RIGHT_DUPLICATE.0
            | DW_RIGHT_TRANSFER.0
            | DW_RIGHT_INSPECT.0,
    );
    let mut first = DwHandle(0);
    let mut second = DwHandle(0);
    success(
        deepwyrm_syscall::channel_create(rights, &mut first, &mut second),
        stage,
        operation,
    )?;
    if first.0 == 0 || second.0 == 0 || first == second {
        return Err(failure(stage, operation + 1));
    }
    Ok((first, second))
}

fn future_deadline(delta: u64) -> Result<DwDeadline, u32> {
    monotonic_active_now()
        .ok()
        .and_then(|now| now.checked_add(delta))
        .map(DwDeadline)
        .ok_or(failure(Stage::Wait, 4))
}

fn success(status: deepwyrm_syscall::DwStatus, stage: Stage, operation: u16) -> Result<(), u32> {
    if status == DW_STATUS_SUCCESS {
        Ok(())
    } else {
        Err(failure(stage, operation))
    }
}

#[allow(
    unsafe_code,
    reason = "I2-only generated-wrapper gap: this is the sole audited raw syscall boundary and uses only generated Deepwyrm exports."
)]
mod raw {
    use deepwyrm_syscall::{
        self, DW_STATUS_SUCCESS, DwDeadline, DwHandle, DwRights, DwSignals, DwStatus, DwSyscallId,
    };

    unsafe extern "C" {
        fn dw_syscall6(
            number: u64,
            arg0: u64,
            arg1: u64,
            arg2: u64,
            arg3: u64,
            arg4: u64,
            arg5: u64,
        ) -> i64;
    }
    fn call(id: DwSyscallId, args: [u64; 6]) -> DwStatus {
        // SAFETY: wrappers supply generated scalar arguments and borrow locals for the entire call.
        unsafe {
            DwStatus(dw_syscall6(
                id.0.into(),
                args[0],
                args[1],
                args[2],
                args[3],
                args[4],
                args[5],
            ) as i32)
        }
    }
    fn result(status: DwStatus) -> Result<(), DwStatus> {
        if status == DW_STATUS_SUCCESS {
            Ok(())
        } else {
            Err(status)
        }
    }
    pub fn event_create(rights: DwRights, out: &mut DwHandle) -> Result<(), DwStatus> {
        result(call(
            deepwyrm_syscall::DW_SYSCALL_EVENT_CREATE,
            [rights.0, core::ptr::from_mut(out) as u64, 0, 0, 0, 0],
        ))
    }
    pub fn event_signal(event: DwHandle, clear: DwSignals, set: DwSignals) -> Result<(), DwStatus> {
        result(call(
            deepwyrm_syscall::DW_SYSCALL_EVENT_SIGNAL,
            [event.0, clear.0, set.0, 0, 0, 0],
        ))
    }
    pub fn timer_create(rights: DwRights, out: &mut DwHandle) -> Result<(), DwStatus> {
        result(call(
            deepwyrm_syscall::DW_SYSCALL_TIMER_CREATE,
            [rights.0, core::ptr::from_mut(out) as u64, 0, 0, 0, 0],
        ))
    }
    pub fn timer_set(timer: DwHandle, deadline: DwDeadline) -> Result<(), DwStatus> {
        result(call(
            deepwyrm_syscall::DW_SYSCALL_TIMER_SET,
            [timer.0, deadline.0, 0, 0, 0, 0],
        ))
    }
    pub fn timer_cancel(timer: DwHandle) -> Result<(), DwStatus> {
        result(call(
            deepwyrm_syscall::DW_SYSCALL_TIMER_CANCEL,
            [timer.0, 0, 0, 0, 0, 0],
        ))
    }
    pub fn atomic_wait32(word: &u32, expected: u32, deadline: DwDeadline) -> DwStatus {
        call(
            deepwyrm_syscall::DW_SYSCALL_ATOMIC_WAIT32,
            [
                core::ptr::from_ref(word) as u64,
                u64::from(expected),
                deadline.0,
                0,
                0,
                0,
            ],
        )
    }
    pub fn atomic_wake(word: &u32, count: u32, out: &mut u32) -> Result<(), DwStatus> {
        result(call(
            deepwyrm_syscall::DW_SYSCALL_ATOMIC_WAKE,
            [
                core::ptr::from_ref(word) as u64,
                u64::from(count),
                core::ptr::from_mut(out) as u64,
                0,
                0,
                0,
            ],
        ))
    }
    pub fn task_group_create(parent: DwHandle, rights: DwRights, out: &mut DwHandle) -> DwStatus {
        call(
            deepwyrm_syscall::DW_SYSCALL_TASK_GROUP_CREATE,
            [parent.0, rights.0, core::ptr::from_mut(out) as u64, 0, 0, 0],
        )
    }
    pub fn task_group_terminate(
        group: DwHandle,
        reason: deepwyrm_syscall::DwTerminationReason,
    ) -> Result<(), DwStatus> {
        result(call(
            deepwyrm_syscall::DW_SYSCALL_TASK_GROUP_TERMINATE,
            [group.0, u64::from(reason.0), 0, 0, 0, 0],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failure_is_stable_and_stage_addressable() {
        assert_eq!(failure(Stage::Channel, 0x55), 0x2203_0055);
        assert_eq!(failure(Stage::ConcurrentUnmap, 0x26), 0x2207_0026);
        assert_ne!(I2_SEED, 0);
    }

    #[test]
    fn stage_seven_uses_its_own_transaction_and_profile() {
        assert_eq!(Stage::ConcurrentUnmap as u8, 7);
        assert_eq!(CONCURRENT_UNMAP_TRANSACTION, 0x2207);
        for leaf in [0x2201, 0x2202, 0x2203, 0x2204] {
            assert_ne!(CONCURRENT_UNMAP_TRANSACTION, leaf);
        }
        // The child is a one-capability ProbeChild: its own root and nothing else.
        let mut bytes = [0_u8; INIT0_BYTES];
        let size = wyrmroot_loader::launch::encode_init(
            LaunchProfile::ProbeChild,
            CONCURRENT_UNMAP_TRANSACTION,
            &mut bytes,
        )
        .unwrap();
        let root = [DwReceivedHandleInfoV1 {
            handle: DwHandle(9),
            object_type: deepwyrm_syscall::DW_OBJECT_TYPE_ADDRESS_REGION,
            rights: wyrmroot_loader::launch::SELF_ROOT_RIGHTS,
            ..DwReceivedHandleInfoV1::default()
        }];
        let parsed = parse_init(LaunchProfile::ProbeChild, &bytes[..size], &root).unwrap();
        assert_eq!(parsed.transaction_id, CONCURRENT_UNMAP_TRANSACTION);
        assert!(parse_init(LaunchProfile::Hello, &bytes[..size], &root).is_err());
        assert!(parse_init(LaunchProfile::I2Stress, &bytes[..size], &root).is_err());
    }

    #[test]
    fn resident_announcement_round_trips_and_rejects_malformed_records() {
        let bytes = encode_resident_announcement(0x40_1000, 0x50_3ff8);
        assert_eq!(&bytes[..4], b"I2S7");
        assert_eq!(
            decode_resident_announcement(&bytes),
            Some((0x40_1000, 0x50_3ff8))
        );
        assert_eq!(decode_resident_announcement(&bytes[..19]), None);
        let mut long = [0_u8; RESIDENT_ANNOUNCEMENT_BYTES + 1];
        long[..RESIDENT_ANNOUNCEMENT_BYTES].copy_from_slice(&bytes);
        assert_eq!(decode_resident_announcement(&long), None);
        let mut wrong_tag = bytes;
        wrong_tag[0] = b'X';
        assert_eq!(decode_resident_announcement(&wrong_tag), None);
        assert_eq!(
            decode_resident_announcement(&encode_resident_announcement(0, 0x50_3ff8)),
            None
        );
        assert_eq!(
            decode_resident_announcement(&encode_resident_announcement(0x40_1000, 0)),
            None
        );
    }

    #[test]
    fn resident_stack_pointer_matches_the_post_call_sysv_state() {
        assert_eq!(
            core::mem::align_of::<ResidentStack>(),
            16,
            "Thread B's stack top must be 16-byte aligned"
        );
        let bytes = core::mem::size_of::<ResidentStack>() as u64;
        assert_eq!(bytes, 16 * 1024);
        let pointer = resident_stack_pointer(0x60_0000, bytes).unwrap();
        assert_eq!(pointer, 0x60_0000 + bytes - 8);
        assert!((pointer + 8).is_multiple_of(16));
        assert_eq!(resident_stack_pointer(0x60_0004, bytes), None);
        assert_eq!(resident_stack_pointer(u64::MAX - 15, bytes), None);
        assert_eq!(resident_stack_pointer(0x60_0000, 32), None);
    }

    #[test]
    fn concurrent_unmap_pattern_distinguishes_rounds_and_words() {
        assert_ne!(concurrent_unmap_word(0, 0), concurrent_unmap_word(1, 0));
        assert_ne!(concurrent_unmap_word(0, 0), concurrent_unmap_word(0, 1));
        assert_ne!(
            concurrent_unmap_word(CONCURRENT_UNMAP_ROUNDS - 1, PAGE_WORDS - 1),
            concurrent_unmap_word(CONCURRENT_UNMAP_ROUNDS - 2, PAGE_WORDS - 1)
        );
        assert_eq!(PAGE_WORDS, 512);
        const { assert!(CONCURRENT_UNMAP_ROUNDS >= 1024) };
        assert_eq!(CONCURRENT_UNMAP_JOIN.len(), 4);
    }
}
