#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;
use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL,
    DW_OBJECT_TYPE_MEMORY_OBJECT, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_READABLE, DwHandle,
    DwObjectType, DwReceivedHandleInfoV1, DwRights, DwWaitItemV1,
};
use wyrmroot_device_proto::{
    ControllerMessage, StatusCode,
    controller::{
        INSTALL_BYTES, STATUS_BYTES, encode as encode_controller, parse as parse_controller,
    },
};
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
    let mut resident = match prepared
        .and_then(|status| wyrmroot_devmgr::ResidentController::new(status, parsed.transaction_id))
    {
        Ok(resident) => resident,
        Err(_) => {
            close_three(self_root, publication, manifest);
            return Err(failure(11));
        }
    };
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

    let mut publication = Some(publication);
    loop {
        let waits = if let Some(publication) = publication {
            [wait_item(bootstrap), wait_item(publication)]
        } else {
            [wait_item(bootstrap), DwWaitItemV1::default()]
        };
        let wait_count = usize::from(publication.is_some()) + 1;
        let observed =
            wait_many(&waits[..wait_count], DW_DEADLINE_INFINITE).map_err(|_| failure(16))?;
        let index = usize::try_from(observed.index).map_err(|_| failure(17))?;
        if index >= wait_count
            || observed.observed.0 & (DW_SIGNAL_READABLE.0 | DW_SIGNAL_PEER_CLOSED.0) == 0
        {
            return Err(failure(18));
        }
        if index == 0 {
            if observed.observed.0 & DW_SIGNAL_READABLE.0 == 0 {
                close_optional(publication);
                close_handle(bootstrap).map_err(|_| failure(19))?;
                return Err(failure(20));
            }
            let replacement = match receive_controller(bootstrap, &mut resident) {
                Ok(replacement) => replacement,
                Err(code) => {
                    close_optional(publication);
                    let _ = close_handle(bootstrap);
                    return Err(code);
                }
            };
            if let Some(replacement) = replacement {
                if let Some(old) = publication.replace(replacement) {
                    let _ = close_handle(replacement);
                    let _ = close_handle(old);
                    let _ = close_handle(bootstrap);
                    return Err(failure(21));
                }
            }
            send_resident_status(
                bootstrap,
                &resident,
                StatusCode::OperationalWaitingForDeviceBundle,
            )?;
            continue;
        }

        if observed.observed.0 & DW_SIGNAL_READABLE.0 != 0 {
            close_optional(publication);
            close_handle(bootstrap).map_err(|_| failure(22))?;
            return Err(failure(23));
        }
        // Registry replacement closes only the old publication binding.  The
        // coordinator generation remains resident; a later WRCS rebind moves
        // one exact child Channel over the still-open bootstrap relationship.
        let old = publication.take().ok_or(failure(24))?;
        close_handle(old).map_err(|_| failure(25))?;
        resident
            .publication_peer_closed()
            .map_err(|_| failure(26))?;
        send_resident_status(
            bootstrap,
            &resident,
            StatusCode::OperationalWaitingForRegistry,
        )?;
    }
}

fn receive_controller(
    bootstrap: DwHandle,
    resident: &mut wyrmroot_devmgr::ResidentController,
) -> Result<Option<DwHandle>, u32> {
    let mut bytes = [0u8; INSTALL_BYTES];
    let mut handles = [DwReceivedHandleInfoV1::default(); 1];
    let counts = receive_channel(bootstrap, &mut bytes, &mut handles).map_err(|_| failure(27))?;
    if counts.bytes > bytes.len() || counts.handles > handles.len() {
        close_received(&handles, counts.handles);
        return Err(failure(28));
    }
    let message = match parse_controller(&bytes[..counts.bytes]) {
        Ok(message) => message,
        Err(_) => {
            close_received(&handles, counts.handles);
            return Err(failure(29));
        }
    };
    if counts.handles as u32 != message.handle_count() {
        close_received(&handles, counts.handles);
        return Err(failure(30));
    }
    let replacement = match message {
        ControllerMessage::InstallPublication { .. } => {
            if counts.handles != 0 {
                close_received(&handles, counts.handles);
                return Err(failure(31));
            }
            None
        }
        ControllerMessage::RebindPublication { .. } => {
            if counts.handles != 1
                || validate_fresh(
                    handles[0].handle,
                    DW_OBJECT_TYPE_CHANNEL,
                    CHILD_CHANNEL_RIGHTS,
                )
                .is_err()
            {
                close_received(&handles, counts.handles);
                return Err(failure(32));
            }
            Some(handles[0].handle)
        }
        ControllerMessage::Status { .. } => {
            close_received(&handles, counts.handles);
            return Err(failure(33));
        }
    };
    if resident.accept(message, counts.handles as u32).is_err() {
        if counts.handles == 1 {
            if let Some(replacement) = replacement {
                let _ = close_handle(replacement);
            }
        }
        return Err(failure(34));
    }
    Ok(replacement)
}

fn send_resident_status(
    bootstrap: DwHandle,
    resident: &wyrmroot_devmgr::ResidentController,
    status: StatusCode,
) -> Result<(), u32> {
    let message = resident.report(status).map_err(|_| failure(35))?;
    let mut bytes = [0u8; STATUS_BYTES];
    encode_controller(message, &mut bytes).map_err(|_| failure(36))?;
    send_channel(bootstrap, &bytes, &[]).map_err(|_| failure(37))
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

fn close_optional(handle: Option<DwHandle>) {
    if let Some(handle) = handle {
        let _ = close_handle(handle);
    }
}

const fn failure(stage: u32) -> u32 {
    FAILURE_BASE | stage
}

wyrmroot_runtime::native_entry!(crate::main);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    panic_abort()
}
