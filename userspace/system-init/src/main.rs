#![cfg_attr(target_os = "wyrmroot", no_std)]
#![cfg_attr(target_os = "wyrmroot", no_main)]
#![deny(unsafe_code)]

use deepwyrm_syscall::{
    DW_RIGHT_INSPECT, DW_RIGHT_MODIFY, DW_RIGHT_WAIT, DW_SIGNAL_SIGNALED, DwDeadline, DwHandle,
    DwHandleTransferV1, DwObjectType, DwReceivedHandleInfoV1, DwRights, DwWaitItemV1,
    DwWaitResultV1,
};
use wyrmroot_bootfs as _;
use wyrmroot_consoled as _;
use wyrmroot_device_proto as _;
use wyrmroot_launch_proto as _;
use wyrmroot_loader as _;
use wyrmroot_registry_proto as _;
use wyrmroot_rrc_manifest as _;
use wyrmroot_runtime::{
    CapabilityInfo, MappingPlan, NativeError, NativeLoaderPlatform, NativeSupervisionPlatform,
    ReceiveCounts, StartupBlock, close_handle, create_channel, create_task_group, create_timer,
    map_bootfs_read_only, monotonic_active_now, query_capability_info, query_memory_object_size,
    receive_channel, send_channel, set_timer, unmap_bootfs, wait_many, wait_one,
};
use wyrmroot_system_init::continue_system_init_resource_product;
use wyrmroot_system_init::fatal_application_status;
use wyrmroot_system_init::validate_wait_until_completion;
use wyrmroot_system_init::{InitPlatform, ResidentPlatform, resident_loop};

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

impl ResidentPlatform for NativeSystem {
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

fn native_main(startup: StartupBlock<'_>) -> u32 {
    let mut system = NativeSystem;
    let mut loader = NativeLoaderPlatform;
    let mut waits = NativeSupervisionPlatform;
    let result = continue_system_init_resource_product(
        &mut system,
        &mut loader,
        &mut waits,
        startup.bootstrap_channel().as_abi(),
        resident_loop::continue_resident,
    );
    match result {
        Ok(status) => status,
        Err(error) => fatal_application_status(&error) as u32,
    }
}

#[cfg(target_os = "wyrmroot")]
wyrmroot_runtime::native_entry!(crate::native_main);
#[cfg(target_os = "wyrmroot")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    wyrmroot_runtime::panic_abort()
}

// This is a guest binary for `x86_64-unknown-wyrmroot`. A host build exists
// so the role binary can be type-checked and linted on the host: `_start`
// and a `#[panic_handler]` would each collide with the std that a host build
// links. Naming the freestanding entry keeps it, and everything it reaches,
// live for host type-checking; nothing here ever runs on the host.
#[cfg(not(target_os = "wyrmroot"))]
fn main() {
    let _: fn(StartupBlock<'_>) -> u32 = native_main;
}
