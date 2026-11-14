#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use deepwyrm_syscall::{DwHandle, DwReceivedHandleInfoV1};
use wyrmroot_bootfs as _;
use wyrmroot_bootstrap::run_supervisor_resource_domain_bootstrap;
use wyrmroot_bootstrap::{BootstrapError, BootstrapSystem};
use wyrmroot_bootstrap_proto as _;
use wyrmroot_loader as _;
use wyrmroot_runtime::{
    CapabilityInfo, MappingPlan, NativeError, ReceiveCounts, StartupBlock, close_handle,
    map_bootfs_read_only, panic_abort, query_capability_info, query_memory_object_size,
    receive_channel, send_channel, unmap_bootfs,
};
use wyrmroot_runtime::{NativeLoaderPlatform, NativeSupervisionPlatform, monotonic_deadline_after};

const BOOTSTRAP_SUPERVISION_TIMEOUT_NS: u64 = if false {
    // Selector 22 sends init0 READY only after the whole I2
    // controller, whose stage-7 concurrent-unmap rounds run for seconds.
    // init0 bounds that controller by its 120-second I2 deadline; this outer
    // watchdog contains it.
    150_000_000_000
} else {
    5_000_000_000
};

struct NativeSystem {
    failed_native_operation: u32,
}

impl NativeSystem {
    const fn new() -> Self {
        Self {
            failed_native_operation: 0,
        }
    }

    fn exit_code(&self, error: &BootstrapError) -> u32 {
        let code = error.exit_code();
        if matches!(error, BootstrapError::Native(_)) {
            code | (self.failed_native_operation << 20)
        } else {
            code
        }
    }
}

impl BootstrapSystem for NativeSystem {
    fn query_capability_info(
        &mut self,
        handle: DwHandle,
    ) -> Result<
        CapabilityInfo<deepwyrm_syscall::DwObjectType, deepwyrm_syscall::DwRights>,
        NativeError,
    > {
        let result = query_capability_info(handle);
        if result.is_err() {
            self.failed_native_operation = 1;
        }
        result
    }

    fn receive_channel(
        &mut self,
        channel: DwHandle,
        bytes: &mut [u8],
        handles: &mut [DwReceivedHandleInfoV1],
    ) -> Result<ReceiveCounts, NativeError> {
        let result = receive_channel(channel, bytes, handles);
        if result.is_err() {
            self.failed_native_operation = 2;
        }
        result
    }

    fn query_memory_object_size(&mut self, handle: DwHandle) -> Result<u64, NativeError> {
        let result = query_memory_object_size(handle);
        if result.is_err() {
            self.failed_native_operation = 3;
        }
        result
    }

    fn with_bootfs_bytes<R>(
        &mut self,
        root_region: DwHandle,
        bootfs: DwHandle,
        plan: MappingPlan,
        use_bytes: impl for<'bytes> FnOnce(&'bytes [u8]) -> R,
    ) -> Result<R, NativeError> {
        let mapping = match map_bootfs_read_only(root_region, bootfs, plan) {
            Ok(mapping) => mapping,
            Err(error) => {
                self.failed_native_operation = 4;
                return Err(error);
            }
        };
        let result = mapping.with_logical_bytes(use_bytes);
        if let Err(error) = unmap_bootfs(mapping) {
            self.failed_native_operation = 5;
            return Err(error);
        }
        Ok(result)
    }

    fn send_channel(&mut self, channel: DwHandle, bytes: &[u8]) -> Result<(), NativeError> {
        let result = send_channel(channel, bytes, &[]);
        if result.is_err() {
            self.failed_native_operation = 6;
        }
        result
    }

    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        let result = close_handle(handle);
        if result.is_err() {
            self.failed_native_operation = 7;
        }
        result
    }

    fn terminate_process(&mut self, process: DwHandle) -> Result<(), NativeError> {
        let result = wyrmroot_runtime::terminate_process(
            process,
            deepwyrm_syscall::DW_TERMINATION_AUTHORIZED,
            0,
        );
        if result.is_err() {
            self.failed_native_operation = 8;
        }
        result
    }

    fn wait_for_process_exit(&mut self, process: DwHandle) -> Result<(), NativeError> {
        let result = (|| {
            let observed = wyrmroot_runtime::wait_one(
                process,
                deepwyrm_syscall::DW_SIGNAL_EXITED,
                deepwyrm_syscall::DW_DEADLINE_INFINITE,
            )?;
            if observed.observed.0 & deepwyrm_syscall::DW_SIGNAL_EXITED.0 == 0
                || wyrmroot_runtime::query_task_termination_info(process)?.state
                    != deepwyrm_syscall::DW_TASK_STATE_EXITED
            {
                return Err(NativeError::Status(deepwyrm_syscall::DW_STATUS_BAD_STATE));
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed_native_operation = 9;
        }
        result
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    panic_abort()
}

fn bootstrap_main(startup: StartupBlock<'_>) -> u32 {
    // The kernel loads this image itself, checking only that its ABI note is
    // in bounds, so bootstrap compares the fingerprint it was built for with
    // the kernel's before any other syscall (root
    // `OS_STACK_ARCHITECTURE_PLAN.md` V1). Everything after it is loaded by
    // the Wyrmroot loader, which refuses another fingerprint.
    if let Err(error) = wyrmroot_runtime::require_kernel_abi() {
        return 0xB300_0000 | wyrmroot_runtime::native_error_code(error);
    }
    let deadline = match monotonic_deadline_after(BOOTSTRAP_SUPERVISION_TIMEOUT_NS) {
        Ok(deadline) => deadline,
        Err(error) => return 0xB300_0000 | wyrmroot_runtime::native_error_code(error),
    };
    let mut system = NativeSystem::new();
    let mut loader = NativeLoaderPlatform;
    let mut supervisor = NativeSupervisionPlatform;
    match run_supervisor_resource_domain_bootstrap(
        &mut system,
        &mut loader,
        &mut supervisor,
        startup.bootstrap_channel().as_abi(),
        deadline,
    ) {
        Ok(()) => 0,
        Err(error) => system.exit_code(&error),
    }
}

wyrmroot_runtime::native_entry!(crate::bootstrap_main);
