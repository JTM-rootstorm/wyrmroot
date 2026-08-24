#![no_std]
#![forbid(unsafe_code)]

//! Selector-specific, bounded I2 syscall stress payload.
//!
//! The I2 image puts this executable at `bin/hello` and builds init0 with
//! `i2-stress-integration`.  It therefore receives only the ordinary explicit
//! WYR0 loader capabilities; no test-only kernel ABI or ambient handle exists.

use deepwyrm_syscall::{
    self, DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE, DW_ADDRESS_REGION_MAP_ARGS_V1_VERSION,
    DW_MEMORY_PROTECTION_READ, DW_MEMORY_PROTECTION_WRITE, DW_RIGHT_DUPLICATE, DW_RIGHT_EXECUTE,
    DW_RIGHT_INSPECT, DW_RIGHT_MAP, DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WAIT,
    DW_RIGHT_WRITE, DW_SIGNAL_EXITED, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DW_STATUS_SUCCESS,
    DW_STATUS_TIMED_OUT, DwAddressRegionMapArgsV1, DwAddressRegionMapFlags, DwDeadline, DwHandle,
    DwHandleTransferV1, DwMemoryObjectCreateFlags, DwMemoryProtection, DwOffset,
    DwReceivedHandleInfoV1, DwRights, DwSize, DwUserAddress, DwWaitResultV1,
};
use wyrmroot_bootfs::archive::Archive;
use wyrmroot_loader::launch::{HEADER_BYTES, INIT0_BYTES, LaunchProfile, encode_ready, parse_init};
use wyrmroot_loader::process::{LoadAuthority, LoadRequest, load_process};
use wyrmroot_runtime::{
    MappingPlan, NativeLoaderPlatform, close_handle, map_bootfs_read_only, monotonic_active_now,
    query_capability_info, query_memory_object_size, receive_channel, send_channel,
    supervise_native_child, unmap_bootfs,
};

/// Fixed input that makes a failure record reproducible without randomized host state.
pub const I2_SEED: u32 = 0x49_32_53_54;
const ITERATIONS: usize = 32;
const PAGE: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Stage {
    Bootstrap = 1,
    Handles = 2,
    Channel = 3,
    Wait = 4,
    Mapping = 5,
    Lifecycle = 6,
}

/// Stable application result carried by init0's existing structured exit path.
/// Bits 31..24 identify I2, 23..16 the stage, and 15..0 the failing operation.
#[must_use]
pub const fn failure(stage: Stage, operation: u16) -> u32 {
    0x22_00_0000 | ((stage as u32) << 16) | operation as u32
}

/// Runs as either the I2 controller (`I2Stress` INIT) or a normal no-capability
/// leaf (`Hello` INIT).  The latter is intentionally tiny and lets the controller
/// exercise init0's real child create/start/exit/terminate path without another ABI.
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
        return close_handle(channel).map_err(|_| failure(Stage::Bootstrap, 5));
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
    exercise_mapping(root)?;
    exercise_lifecycle(root, bootfs, task_group)?;
    // The generated ABI exposes no cancel operation and the pinned syscall crate
    // lacks Event/Timer wrappers.  Deadline-backed wait and peer-close terminal
    // retirement below are the closest live operations available to this payload.
    close_handle(root).map_err(|_| failure(Stage::Lifecycle, 1))?;
    close_handle(bootfs).map_err(|_| failure(Stage::Lifecycle, 2))?;
    close_handle(task_group).map_err(|_| failure(Stage::Lifecycle, 3))?;
    let mut ready = [0_u8; HEADER_BYTES];
    let size = encode_ready(message.transaction_id, &mut ready)
        .map_err(|_| failure(Stage::Bootstrap, 8))?;
    send_channel(channel, &ready[..size], &[]).map_err(|_| failure(Stage::Bootstrap, 9))?;
    close_handle(channel).map_err(|_| failure(Stage::Bootstrap, 10))
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
    success(
        deepwyrm_syscall::address_region_protect(
            root,
            address,
            DwSize(PAGE),
            DW_MEMORY_PROTECTION_READ,
        ),
        Stage::Mapping,
        3,
    )?;
    success(
        deepwyrm_syscall::address_region_unmap(root, address, DwSize(PAGE)),
        Stage::Mapping,
        4,
    )?;
    close_handle(memory).map_err(|_| failure(Stage::Mapping, 5))
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
            future_deadline(5_000_000)?,
        );
        close_handle(normal.launch_channel).map_err(|_| failure(Stage::Lifecycle, 18))?;
        close_handle(normal.process).map_err(|_| failure(Stage::Lifecycle, 19))?;
        normal_result.map_err(|_| failure(Stage::Lifecycle, 20))?;

        // A second genuine created-and-started child is terminated through its Process handle.
        // Either successful authorization or an already-terminal BAD_STATE is a valid bounded race.
        let terminated = load_process(
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
        let status = deepwyrm_syscall::process_terminate(
            terminated.process,
            deepwyrm_syscall::DW_TERMINATION_AUTHORIZED,
            I2_SEED,
        );
        if status != DW_STATUS_SUCCESS && status != deepwyrm_syscall::DW_STATUS_BAD_STATE {
            return Err(failure(Stage::Lifecycle, 22));
        }
        let mut terminal = DwWaitResultV1::default();
        success(
            deepwyrm_syscall::wait_one(
                terminated.process,
                DW_SIGNAL_EXITED,
                future_deadline(5_000_000)?,
                &mut terminal,
            ),
            Stage::Lifecycle,
            23,
        )?;
        close_handle(terminated.launch_channel).map_err(|_| failure(Stage::Lifecycle, 24))?;
        close_handle(terminated.process).map_err(|_| failure(Stage::Lifecycle, 25))
    });
    let unmap = unmap_bootfs(mapping).map_err(|_| failure(Stage::Lifecycle, 26));
    result?;
    unmap
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failure_is_stable_and_stage_addressable() {
        assert_eq!(failure(Stage::Channel, 0x55), 0x2203_0055);
        assert_ne!(I2_SEED, 0);
    }
}
