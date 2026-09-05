// SPDX-License-Identifier: GPL-3.0-or-later
#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use deepwyrm_syscall::{
    DW_DEADLINE_INFINITE, DwDeadline, DwHandle, DwHandleTransferV1, DwObjectType,
    DwReceivedHandleInfoV1, DwRights, DwSignals, DwWaitItemV1, DwWaitResultV1,
};
use wyrmroot_console_proto as _;
use wyrmroot_launch_proto as _;
use wyrmroot_loader as _;
use wyrmroot_registry_proto as _;
use wyrmroot_runtime::{
    CapabilityInfo, NativeError, ReceiveCounts, StartupBlock, StreamSystem, close_handle,
    create_channel, duplicate_handle, monotonic_active_now, panic_abort, query_capability_info,
    receive_channel, send_channel, wait_many, wait_one,
};
use wyrmroot_wyrmsh::{WyrmshSystem, run_wyrmsh};
use wyrmroot_wyrmsh_core as _;

struct NativeSystem;

impl WyrmshSystem for NativeSystem {
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

    fn send_channel_with_handles(
        &mut self,
        channel: DwHandle,
        bytes: &[u8],
        transfers: &[DwHandleTransferV1],
    ) -> Result<(), NativeError> {
        send_channel(channel, bytes, transfers)
    }

    fn create_channel(&mut self, rights: DwRights) -> Result<(DwHandle, DwHandle), NativeError> {
        create_channel(rights)
    }

    fn duplicate_handle(
        &mut self,
        handle: DwHandle,
        rights: DwRights,
    ) -> Result<DwHandle, NativeError> {
        duplicate_handle(handle, rights)
    }

    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        close_handle(handle)
    }

    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, NativeError> {
        wait_many(items, deadline)
    }

    fn monotonic_active_now(&mut self) -> Result<u64, NativeError> {
        monotonic_active_now()
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
        wait_one(channel, signals, DW_DEADLINE_INFINITE).map(|result| result.observed)
    }
}

fn wyrmsh_main(startup: StartupBlock<'_>) -> u32 {
    let mut system = NativeSystem;
    run_wyrmsh(&mut system, startup).map_or_else(|error| error.exit_code(), |_| 0)
}

wyrmroot_runtime::native_entry!(crate::wyrmsh_main);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    panic_abort()
}
