#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use deepwyrm_syscall::{DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights};
use wyrmroot_bootfs as _;
#[cfg(feature = "dw1b-preemption-integration")]
use wyrmroot_dw1b_preemption as _;
#[cfg(feature = "i-capability-integration")]
use wyrmroot_i_capability as _;
use wyrmroot_init0::{Init0System, run_init0};
use wyrmroot_loader as _;
#[cfg(feature = "dw1b-preemption-integration")]
use wyrmroot_runtime::arm_dw1b_preemption;
use wyrmroot_runtime::{
    CapabilityInfo, MappingPlan, NativeError, NativeLoaderPlatform, NativeSupervisionPlatform,
    ReceiveCounts, StartupBlock, close_handle, map_bootfs_read_only, monotonic_deadline_after,
    panic_abort, query_capability_info, query_memory_object_size, receive_channel, send_channel,
    unmap_bootfs,
};
#[cfg(feature = "dw1c-preemption-integration")]
use wyrmroot_runtime::{
    DW1C_ACTOR_COUNT, Dw1cActorBindV1, arm_dw1c_preemption, submit_dw1c_workload_complete,
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

    #[cfg(feature = "dw1b-preemption-integration")]
    fn arm_dw1b_preemption(
        &mut self,
        hog_process: DwHandle,
        progress_process: DwHandle,
    ) -> Result<(), NativeError> {
        arm_dw1b_preemption(hog_process, progress_process)
    }

    #[cfg(feature = "dw1c-preemption-integration")]
    fn arm_dw1c_preemption(
        &mut self,
        bindings: &[Dw1cActorBindV1; DW1C_ACTOR_COUNT],
    ) -> Result<(), NativeError> {
        arm_dw1c_preemption(bindings)
    }

    #[cfg(feature = "dw1c-preemption-integration")]
    fn complete_dw1c_workload(&mut self, digest: u64) -> Result<(), NativeError> {
        submit_dw1c_workload_complete(digest)
    }
}

fn init0_main(startup: StartupBlock<'_>) -> u32 {
    let mut system = NativeSystem;
    let deadline = match monotonic_deadline_after(HELLO_DEADLINE_NS) {
        Ok(deadline) => deadline,
        Err(error) => return 0x1400_0000 | wyrmroot_runtime::native_error_code(error),
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
