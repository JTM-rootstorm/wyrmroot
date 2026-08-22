#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use deepwyrm_syscall::{DwHandle, DwReceivedHandleInfoV1};
use wyrmroot_bootfs as _;
use wyrmroot_bootstrap::BootstrapSystem;
#[cfg(not(feature = "primordial-blocking-cleanup"))]
use wyrmroot_bootstrap::run_bootstrap;
#[cfg(feature = "primordial-blocking-cleanup")]
use wyrmroot_bootstrap::run_bootstrap_with_before_ready;
use wyrmroot_bootstrap_proto as _;
use wyrmroot_runtime::{
    CapabilityInfo, MappingPlan, NativeError, ReceiveCounts, StartupBlock, close_handle,
    map_bootfs_read_only, panic_abort, query_capability_info, query_memory_object_size,
    receive_channel, send_channel, unmap_bootfs,
};

struct NativeSystem;

impl BootstrapSystem for NativeSystem {
    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<
        CapabilityInfo<deepwyrm_syscall::DwObjectType, deepwyrm_syscall::DwRights>,
        NativeError,
    > {
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

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    panic_abort()
}

#[cfg(not(any(
    feature = "primordial-blocking-cleanup",
    feature = "primordial-user-exception",
    feature = "primordial-invalid-return"
)))]
fn bootstrap_main(startup: StartupBlock<'_>) -> u32 {
    let mut system = NativeSystem;
    u32::from(run_bootstrap(&mut system, startup.bootstrap_channel().as_abi()).is_err())
}

#[cfg(feature = "primordial-blocking-cleanup")]
fn bootstrap_main(startup: StartupBlock<'_>) -> u32 {
    let mut system = NativeSystem;
    let result = run_bootstrap_with_before_ready(
        &mut system,
        startup.bootstrap_channel().as_abi(),
        |channel| {
            wyrmroot_runtime::primordial_blocking_cleanup(channel)
                .map_err(wyrmroot_bootstrap::BootstrapError::TestSupport)
        },
    );
    u32::from(result.is_err())
}

#[cfg(feature = "primordial-user-exception")]
fn bootstrap_main(startup: StartupBlock<'_>) -> u32 {
    let mut system = NativeSystem;
    if run_bootstrap(&mut system, startup.bootstrap_channel().as_abi()).is_err() {
        return 1;
    }
    wyrmroot_runtime::trigger_user_exception()
}

#[cfg(feature = "primordial-invalid-return")]
fn bootstrap_main(startup: StartupBlock<'_>) -> u32 {
    let mut system = NativeSystem;
    if run_bootstrap(&mut system, startup.bootstrap_channel().as_abi()).is_err() {
        return 1;
    }
    wyrmroot_runtime::trigger_invalid_syscall_return()
}

wyrmroot_runtime::native_entry!(crate::bootstrap_main);
