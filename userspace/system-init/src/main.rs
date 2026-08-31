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
use wyrmroot_device_proto as _;
#[cfg(feature = "dw1e3-selector31")]
use wyrmroot_dw1e3_com2_test as _;
use wyrmroot_launch_proto as _;
use wyrmroot_loader as _;
use wyrmroot_registry_proto as _;
use wyrmroot_rrc_manifest as _;
#[cfg(feature = "wyr1c6-selector29")]
use wyrmroot_runtime::WYR0_I_SUPERVISION_POLICY;
use wyrmroot_runtime::{
    CapabilityInfo, MappingPlan, NativeError, NativeLoaderPlatform, NativeSupervisionPlatform,
    ReceiveCounts, StartupBlock, close_handle, create_channel, create_task_group, create_timer,
    map_bootfs_read_only, monotonic_active_now, panic_abort, query_capability_info,
    query_memory_object_size, receive_channel, send_channel, set_timer, unmap_bootfs, wait_many,
    wait_one,
};
#[cfg(not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")))]
use wyrmroot_system_init::continue_system_init_product;
#[cfg(any(feature = "wyr1c4-production", feature = "wyr1c5-production"))]
use wyrmroot_system_init::continue_system_init_resource_product;
#[cfg(not(any(
    feature = "wyr1-test-evidence",
    feature = "wyr1b-test-evidence",
    feature = "wyr1c6-selector29"
)))]
use wyrmroot_system_init::fatal_application_status;
use wyrmroot_system_init::validate_wait_until_completion;
#[cfg(feature = "wyr1-test-evidence")]
use wyrmroot_system_init::wyr1_test_failure_application_status;
#[cfg(feature = "wyr1b-test-evidence")]
use wyrmroot_system_init::wyr1b_test_failure_application_status;
use wyrmroot_system_init::{InitPlatform, ResidentSystemInit, Wyr1BPlatform};
#[cfg(feature = "wyr1c6-selector29")]
use wyrmroot_system_init::{wyr1c_native, wyr1c6_gate, wyr1c6_test_failure_application_status};
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
            let wait_result = wait_one(timer, DW_SIGNAL_SIGNALED, DwDeadline(end)).map(|_| ());
            match wait_result {
                Ok(()) => validate_wait_until_completion(
                    deadline_ns,
                    monotonic_active_now()?,
                    wait_result,
                ),
                Err(NativeError::Status(status))
                    if status == deepwyrm_syscall::DW_STATUS_TIMED_OUT =>
                {
                    validate_wait_until_completion(
                        deadline_ns,
                        monotonic_active_now()?,
                        wait_result,
                    )
                }
                Err(error) => Err(error),
            }
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

    fn materialize_read_only_memory(
        &mut self,
        root: DwHandle,
        bytes: &[u8],
        rights: DwRights,
    ) -> Result<DwHandle, NativeError> {
        wyrmroot_runtime::materialize_read_only_memory(root, bytes, rights)
    }
}

fn main(startup: StartupBlock<'_>) -> u32 {
    let mut system = NativeSystem;
    let mut loader = NativeLoaderPlatform;
    let mut waits = NativeSupervisionPlatform;
    #[cfg(not(any(feature = "wyr1c4-production", feature = "wyr1c5-production")))]
    let result = continue_system_init_product(
        &mut system,
        &mut loader,
        &mut waits,
        startup.bootstrap_channel().as_abi(),
        continue_resident,
    );
    #[cfg(any(feature = "wyr1c4-production", feature = "wyr1c5-production"))]
    let result = continue_system_init_resource_product(
        &mut system,
        &mut loader,
        &mut waits,
        startup.bootstrap_channel().as_abi(),
        continue_resident,
    );
    match result {
        Ok(status) => status,
        Err(error) => {
            #[cfg(feature = "wyr1c6-selector29")]
            return wyr1c6_test_failure_application_status(&error);
            #[cfg(feature = "wyr1b-test-evidence")]
            return wyr1b_test_failure_application_status(&error);
            #[cfg(all(feature = "wyr1-test-evidence", not(feature = "wyr1b-test-evidence")))]
            return wyr1_test_failure_application_status(&error);
            #[cfg(not(any(
                feature = "wyr1-test-evidence",
                feature = "wyr1b-test-evidence",
                feature = "wyr1c6-selector29"
            )))]
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
    #[cfg(feature = "wyr1c6-selector29")]
    let mut c6_evidence_submitted = false;
    loop {
        let Ok(now) = monotonic_active_now() else {
            return 0xAF01_0003;
        };
        #[cfg(feature = "wyr1c6-selector29")]
        let tick_ns = WYR0_I_SUPERVISION_POLICY.backoff_ns;
        #[cfg(not(feature = "wyr1c6-selector29"))]
        let tick_ns = 1_000_000_000;
        let Some(deadline) = now.checked_add(tick_ns) else {
            return 0xAF01_0004;
        };
        if resident
            .control_tick_product(system, loader, waits, now)
            .is_err()
        {
            return 0xAF01_0006;
        }
        #[cfg(feature = "wyr1c6-selector29")]
        if !c6_evidence_submitted {
            match wyr1c_native::finish_c6_evidence(resident) {
                Ok(true) => {
                    for index in 0..wyr1c6_gate::EVIDENCE_RECORDS {
                        let mut record = [0u8; wyr1c6_gate::RECORD_BYTES];
                        let Some(()) = resident.write_wyr1c6_evidence_record(index, &mut record)
                        else {
                            return 0xAF1C_0001;
                        };
                        if wyrmroot_runtime::submit_wyr1c6_evidence(&record).is_err() {
                            return 0xAF1C_0002;
                        }
                    }
                    c6_evidence_submitted = true;
                }
                Ok(false) => {}
                Err(_) => return 0xAF1C_0003,
            }
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
