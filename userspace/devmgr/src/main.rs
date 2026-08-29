#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;
use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL,
    DW_OBJECT_TYPE_MEMORY_OBJECT, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwHandle,
    DwObjectType, DwReceivedHandleInfoV1, DwRights, DwWaitItemV1,
};
use wyrmroot_device_proto as _;
use wyrmroot_loader::launch::{
    CHILD_CHANNEL_RIGHTS, DEVICE_COORDINATOR_BYTES, DEVICE_MANIFEST_RIGHTS, HEADER_BYTES,
    LaunchProfile, SELF_ROOT_RIGHTS, encode_ready_for_profile, parse_device_coordinator_init,
};
use wyrmroot_runtime::{
    BOOTSTRAP_CHANNEL_EXPECTATION, CapabilityInfo, MappingPlan, StartupBlock, close_handle,
    map_bootfs_read_only, panic_abort, query_capability_info, query_memory_object_size,
    receive_channel, send_channel, unmap_bootfs, validate_bootstrap_channel, wait_many,
};

const FAILURE_BASE: u32 = 0xC101_0000;

fn main(startup: StartupBlock<'_>) -> u32 {
    run(startup).unwrap_or_else(|code| code)
}

fn run(startup: StartupBlock<'_>) -> Result<u32, u32> {
    let bootstrap = startup.bootstrap_channel().as_abi();
    let bootstrap_info = query_capability_info(bootstrap).map_err(|_| failure(1))?;
    validate_bootstrap_channel(bootstrap_info, BOOTSTRAP_CHANNEL_EXPECTATION)
        .map_err(|_| failure(2))?;

    let mut init = [0u8; DEVICE_COORDINATOR_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 3];
    let counts = receive_channel(bootstrap, &mut init, &mut handles).map_err(|_| failure(3))?;
    if counts.bytes > init.len() || counts.handles != handles.len() {
        close_received(&handles, counts.handles);
        return Err(failure(4));
    }
    let parsed = match parse_device_coordinator_init(&init[..counts.bytes], &handles) {
        Ok(parsed) => parsed,
        Err(_) => {
            close_received(&handles, counts.handles);
            return Err(failure(5));
        }
    };
    if validate_fresh(
        handles[0].handle,
        DW_OBJECT_TYPE_ADDRESS_REGION,
        SELF_ROOT_RIGHTS,
    )
    .is_err()
        || validate_fresh(
            handles[1].handle,
            DW_OBJECT_TYPE_CHANNEL,
            CHILD_CHANNEL_RIGHTS,
        )
        .is_err()
        || validate_fresh(
            handles[2].handle,
            DW_OBJECT_TYPE_MEMORY_OBJECT,
            DEVICE_MANIFEST_RIGHTS,
        )
        .is_err()
    {
        close_received(&handles, counts.handles);
        return Err(failure(6));
    }

    let self_root = handles[0].handle;
    let publication = handles[1].handle;
    let manifest = handles[2].handle;
    let size = query_memory_object_size(manifest).map_err(|_| failure(7))?;
    let plan = MappingPlan::for_bootfs(size).map_err(|_| failure(8))?;
    let mapping = map_bootfs_read_only(self_root, manifest, plan).map_err(|_| failure(9))?;
    let prepared = mapping.with_logical_bytes(|bytes| {
        wyrmroot_devmgr::prepare_operational(bytes, parsed.supervisor_generation)
    });
    unmap_bootfs(mapping).map_err(|_| failure(10))?;
    if prepared.is_err() {
        close_three(self_root, publication, manifest);
        return Err(failure(11));
    }
    close_handle(manifest).map_err(|_| failure(12))?;
    close_handle(self_root).map_err(|_| failure(13))?;

    let mut ready = [0u8; HEADER_BYTES];
    let ready_len = encode_ready_for_profile(
        LaunchProfile::DeviceCoordinator,
        parsed.transaction_id,
        &mut ready,
    )
    .map_err(|_| failure(14))?;
    send_channel(bootstrap, &ready[..ready_len], &[]).map_err(|_| failure(15))?;

    let waits = [wait_item(bootstrap), wait_item(publication)];
    loop {
        let observed = wait_many(&waits, DW_DEADLINE_INFINITE).map_err(|_| failure(16))?;
        let index = usize::try_from(observed.index).map_err(|_| failure(17))?;
        if index >= waits.len()
            || observed.observed.0 & (DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0) == 0
        {
            return Err(failure(18));
        }
        if index == 0 || observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 {
            // C1 has no reached post-READY controller or hardware-bundle
            // envelope. Unexpected messages and loss of the supervisor
            // relationship remain fail-closed.
            close_handle(publication).map_err(|_| failure(19))?;
            close_handle(bootstrap).map_err(|_| failure(20))?;
            return Err(failure(21));
        }

        // Registry replacement closes only the old publication binding. Keep
        // this devmgr generation resident and wait for the still-open
        // supervisor relationship; the bounded rebind envelope remains an
        // explicit later C1 integration step.
        close_handle(publication).map_err(|_| failure(22))?;
        let controller_wait = [wait_item(bootstrap)];
        loop {
            let controller =
                wait_many(&controller_wait, DW_DEADLINE_INFINITE).map_err(|_| failure(23))?;
            if controller.index != 0
                || controller.observed.0 & (DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0) == 0
            {
                return Err(failure(24));
            }
            close_handle(bootstrap).map_err(|_| failure(25))?;
            return Err(failure(26));
        }
    }
}

fn validate_fresh(handle: DwHandle, object_type: DwObjectType, rights: DwRights) -> Result<(), ()> {
    let actual: CapabilityInfo<DwObjectType, DwRights> =
        query_capability_info(handle).map_err(|_| ())?;
    if actual.object_type != object_type || actual.rights != rights {
        return Err(());
    }
    Ok(())
}

fn wait_item(handle: DwHandle) -> DwWaitItemV1 {
    DwWaitItemV1 {
        handle,
        signals: deepwyrm_syscall::DwSignals(DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0),
    }
}

fn close_received(handles: &[DwReceivedHandleInfoV1], count: usize) {
    for info in handles.iter().take(count.min(handles.len())) {
        let _ = close_handle(info.handle);
    }
}

fn close_three(first: DwHandle, second: DwHandle, third: DwHandle) {
    let _ = close_handle(third);
    let _ = close_handle(second);
    let _ = close_handle(first);
}

const fn failure(stage: u32) -> u32 {
    FAILURE_BASE | stage
}

wyrmroot_runtime::native_entry!(crate::main);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    panic_abort()
}
