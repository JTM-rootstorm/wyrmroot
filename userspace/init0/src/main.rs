#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use deepwyrm_syscall::{DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights};
use wyrmroot_bootfs as _;
use wyrmroot_init0::{Init0System, run_init0};
use wyrmroot_loader as _;
use wyrmroot_runtime::{
    CapabilityInfo, MappingPlan, NativeError, NativeLoaderPlatform, NativeSupervisionPlatform,
    ReceiveCounts, StartupBlock, close_handle, map_bootfs_read_only, monotonic_deadline_after,
    panic_abort, query_capability_info, query_memory_object_size, receive_channel, send_channel,
    unmap_bootfs,
};

const HELLO_DEADLINE_NS: u64 = 5_000_000_000;

struct NativeSystem;

impl Init0System for NativeSystem {
    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<CapabilityInfo<DwObjectType, DwRights>, NativeError> {
        query_capability_info(handle)
    }

    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        receive_channel(channel, bytes, handles)
    }

    fn query_memory_object_size(&mut self, handle: DwHandle) -> Result<u64, NativeError> {
        query_memory_object_size(handle)
    }

    fn with_bootfs_bytes<R>(
        &mut self,
        root_region: DwHandle,
        bootfs: DwHandle,
        plan: MappingPlan,
        use_bytes: impl for<'bytes> FnOnce(&'bytes [u8]) -> R,
    ) -> Result<R, NativeError> {
        let mapping = map_bootfs_read_only(root_region, bootfs, plan)?;
        let result = mapping.with_logical_bytes(use_bytes);
        unmap_bootfs(mapping)?;
        Ok(result)
    }

    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
        send_channel(channel, bytes, &[])
    }

    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        close_handle(handle)
    }
}

fn init0_main(startup: StartupBlock<'_>) -> u32 {
    let mut system = NativeSystem;
    let deadline = match monotonic_deadline_after(HELLO_DEADLINE_NS) {
        Ok(deadline) => deadline,
        Err(_) => return 1,
    };
    match run_init0(
        &mut system,
        &mut NativeLoaderPlatform,
        &mut NativeSupervisionPlatform,
        startup.bootstrap_channel().as_abi(),
        deadline,
    ) {
        Ok(()) => 0,
        Err(error) => error.exit_code(),
    }
}

wyrmroot_runtime::native_entry!(crate::init0_main);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    panic_abort()
}
