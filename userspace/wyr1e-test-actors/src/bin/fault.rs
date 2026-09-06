#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use deepwyrm_syscall::{DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights, DwSignals};
use wyrmroot_loader as _;
use wyrmroot_runtime::{
    CapabilityInfo, NativeError, ReceiveCounts, StartupBlock, close_handle, panic_abort,
    query_capability_info, receive_channel, send_channel, wait_one,
};
use wyrmroot_wyr1e_test_actors::{
    ActorSystem, FAULT_PATH, prepare_stream_actor, validate_actor_entry,
};

struct NativeSystem;

impl ActorSystem for NativeSystem {
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
    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
        send_channel(channel, bytes, &[])
    }
    fn wait_channel(
        &mut self,
        channel: DwHandle,
        signals: DwSignals,
    ) -> Result<DwSignals, NativeError> {
        wait_one(channel, signals, deepwyrm_syscall::DW_DEADLINE_INFINITE)
            .map(|result| result.observed)
    }
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        close_handle(handle)
    }
}

#[cfg(target_arch = "x86_64")]
fn trigger_fault() -> ! {
    #[allow(unsafe_code, reason = "the E7 fault actor deliberately executes UD2")]
    unsafe {
        core::arch::asm!("ud2", options(noreturn, nostack, nomem))
    }
}

fn fault_main(startup: StartupBlock<'_>) -> u32 {
    if let Err(error) = validate_actor_entry(
        startup.version(),
        startup.argc(),
        startup.arg(0).map(|arg| arg.as_str()),
        startup.envc(),
        FAULT_PATH,
    ) {
        return error.exit_code();
    }
    let mut system = NativeSystem;
    match prepare_stream_actor(&mut system, startup.bootstrap_channel().as_abi()) {
        Ok(_) => trigger_fault(),
        Err(error) => error.exit_code(),
    }
}

wyrmroot_runtime::native_entry!(crate::fault_main);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    panic_abort()
}
