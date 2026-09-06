#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use deepwyrm_syscall::{DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights, DwSignals};
use wyrmroot_dw1b_preemption::{
    JobActorSystem, prepare_job_cpu_hog, run_cpu_hog_body, validate_job_cpu_hog_entry,
};
use wyrmroot_loader as _;
use wyrmroot_runtime::{
    CapabilityInfo, NativeError, ReceiveCounts, StartupBlock, close_handle, panic_abort,
    query_capability_info, receive_channel, send_channel, wait_one,
};

struct NativeSystem;

impl JobActorSystem for NativeSystem {
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

fn job_cpu_hog_main(startup: StartupBlock<'_>) -> u32 {
    if let Err(error) = validate_job_cpu_hog_entry(
        startup.version(),
        startup.argc(),
        startup.arg(0).map(|argument| argument.as_str()),
        startup.envc(),
    ) {
        return error.exit_code();
    }
    let mut system = NativeSystem;
    if let Err(error) = prepare_job_cpu_hog(&mut system, startup.bootstrap_channel().as_abi()) {
        return error.exit_code();
    }
    match run_cpu_hog_body() {
        Err(code) => code,
    }
}

wyrmroot_runtime::native_entry!(crate::job_cpu_hog_main);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    panic_abort()
}
