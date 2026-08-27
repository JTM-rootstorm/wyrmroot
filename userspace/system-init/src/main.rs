#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;
use deepwyrm_syscall::{
    DW_RIGHT_INSPECT, DW_RIGHT_MODIFY, DW_RIGHT_WAIT, DW_SIGNAL_SIGNALED, DwDeadline, DwHandle,
    DwHandleTransferV1, DwObjectType, DwReceivedHandleInfoV1, DwRights, DwWaitItemV1,
    DwWaitResultV1,
};
use wyrmroot_bootfs as _;
use wyrmroot_launch_proto as _;
use wyrmroot_loader as _;
use wyrmroot_registry_proto as _;
use wyrmroot_rrc_manifest as _;
use wyrmroot_runtime::{
    CapabilityInfo, MappingPlan, NativeError, NativeLoaderPlatform, NativeSupervisionPlatform,
    ReceiveCounts, StartupBlock, close_handle, create_channel, create_task_group, create_timer,
    map_bootfs_read_only, monotonic_active_now, panic_abort, query_capability_info,
    query_memory_object_size, receive_channel, send_channel, set_timer, unmap_bootfs, wait_many,
    wait_one,
};
#[cfg(not(any(feature = "wyr1-test-evidence", feature = "wyr1b-test-evidence")))]
use wyrmroot_system_init::fatal_application_status;
#[cfg(feature = "wyr1-test-evidence")]
use wyrmroot_system_init::wyr1_test_failure_application_status;
#[cfg(feature = "wyr1b-test-evidence")]
use wyrmroot_system_init::wyr1b_test_failure_application_status;
use wyrmroot_system_init::{
    InitPlatform, ResidentSystemInit, Wyr1BPlatform, continue_system_init_product,
};
use wyrmroot_wyr1b_gate_proto as _;

struct NativeSystem;

impl InitPlatform for NativeSystem {
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
    #[cfg_attr(feature = "wyr1b-test-evidence", inline(always))]
    fn with_bootfs_bytes<R>(
        &mut self,
        root: DwHandle,
        bootfs: DwHandle,
        plan: MappingPlan,
        use_bytes: impl for<'a> FnOnce(&mut Self, &'a [u8]) -> R,
    ) -> Result<R, NativeError> {
        let mapping = map_bootfs_read_only(root, bootfs, plan)?;
        let result = mapping.with_logical_bytes(|bytes| use_bytes(self, bytes));
        unmap_bootfs(mapping)?;
        Ok(result)
    }
    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
        send_channel(channel, bytes, &[])
    }
    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        close_handle(handle)
    }
    fn create_attempt_task_group(&mut self, parent: DwHandle) -> Result<DwHandle, NativeError> {
        create_task_group(parent, DwRights(DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0))
    }
    fn terminate_task_group(&mut self, task_group: DwHandle) -> Result<(), NativeError> {
        wyrmroot_runtime::terminate_task_group(
            task_group,
            deepwyrm_syscall::DW_TERMINATION_AUTHORIZED,
        )
    }
    fn now(&mut self) -> Result<u64, NativeError> {
        monotonic_active_now()
    }
    fn wait_until(&mut self, deadline_ns: u64) -> Result<(), NativeError> {
        let timer = create_timer(DwRights(
            DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0,
        ))?;
        let result = (|| {
            set_timer(timer, DwDeadline(deadline_ns))?;
            let end = deadline_ns
                .checked_add(1_000_000_000)
                .ok_or(NativeError::Output(
                    wyrmroot_runtime::NativeOutputError::DeadlineOverflow,
                ))?;
            wait_one(timer, DW_SIGNAL_SIGNALED, DwDeadline(end))?;
            Ok(())
        })();
        result.and(close_handle(timer))
    }
}

impl Wyr1BPlatform for NativeSystem {
    fn channel_create(&mut self, rights: DwRights) -> Result<(DwHandle, DwHandle), NativeError> {
        create_channel(rights)
    }

    fn send_channel_with_handles(
        &mut self,
        channel: DwHandle,
        bytes: &[u8],
        transfers: &[DwHandleTransferV1],
    ) -> Result<(), NativeError> {
        send_channel(channel, bytes, transfers)
    }

    fn wait_many(
        &mut self,
        items: &[DwWaitItemV1],
        deadline: DwDeadline,
    ) -> Result<DwWaitResultV1, NativeError> {
        wait_many(items, deadline)
    }
}

fn main(startup: StartupBlock<'_>) -> u32 {
    let mut system = NativeSystem;
    let mut loader = NativeLoaderPlatform;
    let mut waits = NativeSupervisionPlatform;
    match continue_system_init_product(
        &mut system,
        &mut loader,
        &mut waits,
        startup.bootstrap_channel().as_abi(),
        continue_resident,
    ) {
        Ok(status) => status,
        Err(error) => {
            #[cfg(feature = "wyr1b-test-evidence")]
            return wyr1b_test_failure_application_status(&error);
            #[cfg(all(feature = "wyr1-test-evidence", not(feature = "wyr1b-test-evidence")))]
            return wyr1_test_failure_application_status(&error);
            #[cfg(not(any(feature = "wyr1-test-evidence", feature = "wyr1b-test-evidence")))]
            return fatal_application_status(&error) as u32;
        }
    }
}

fn continue_resident(
    resident: &mut ResidentSystemInit,
    system: &mut NativeSystem,
    loader: &mut NativeLoaderPlatform,
    waits: &mut NativeSupervisionPlatform,
) -> u32 {
    #[cfg(feature = "wyr1b-test-evidence")]
    {
        let mut index = 0;
        while let Some(record) = resident.wyr1b_evidence_record(index) {
            if wyrmroot_runtime::submit_wyr1b_evidence(record).is_err() {
                return 0xAF1B_0001;
            }
            index += 1;
        }
    }
    #[cfg(feature = "wyr1-test-evidence")]
    let mut evidence_submitted = false;
    loop {
        let Ok(now) = monotonic_active_now() else {
            return 0xAF01_0003;
        };
        let Some(deadline) = now.checked_add(1_000_000_000) else {
            return 0xAF01_0004;
        };
        if resident
            .control_tick_product(system, loader, waits, now)
            .is_err()
        {
            return 0xAF01_0006;
        }
        #[cfg(feature = "wyr1-test-evidence")]
        if resident.evidence_finalized() && !evidence_submitted {
            let mut index = 0;
            while let Some(line) = resident.controller().evidence_line(index) {
                let Ok(record) = <&[u8; 114]>::try_from(line) else {
                    return 0xAF01_0007;
                };
                if wyrmroot_runtime::submit_wyr1_evidence(record).is_err() {
                    return 0xAF01_0008;
                }
                index += 1;
            }
            evidence_submitted = true;
        }
        if InitPlatform::wait_until(system, deadline).is_err() {
            return 0xAF01_0005;
        }
    }
}

wyrmroot_runtime::native_entry!(crate::main);
#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    panic_abort()
}
