#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use deepwyrm_syscall::{DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights, DwSignals};
use wyrmroot_console_echo::{ConsoleEchoSystem, run_console_echo};
use wyrmroot_loader as _;
use wyrmroot_runtime::{
    CapabilityInfo, NativeError, ReceiveCounts, StartupBlock, StreamSystem, close_handle,
    panic_abort, query_capability_info, receive_channel, send_channel, wait_one,
};

struct NativeSystem;

impl ConsoleEchoSystem for NativeSystem {
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

    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        close_handle(handle)
    }
}

impl StreamSystem for NativeSystem {
    fn receive(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        receive_channel(channel, bytes, handles)
    }

    fn send(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
        send_channel(channel, bytes, &[])
    }

    fn close(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        close_handle(handle)
    }

    fn wait(&mut self, channel: DwHandle, signals: DwSignals) -> Result<DwSignals, NativeError> {
        wait_one(channel, signals, deepwyrm_syscall::DW_DEADLINE_INFINITE).map(|wait| wait.observed)
    }
}

fn console_echo_main(startup: StartupBlock<'_>) -> u32 {
    let mut system = NativeSystem;
    run_console_echo(&mut system, startup.bootstrap_channel().as_abi())
        .map_or_else(|error| error.exit_code(), |_| 0)
}

wyrmroot_runtime::native_entry!(crate::console_echo_main);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    panic_abort()
}
