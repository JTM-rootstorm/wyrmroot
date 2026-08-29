#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use deepwyrm_syscall::{DwHandle, DwReceivedHandleInfoV1};
use wyrmroot_bootfs as _;
#[cfg(any(
    feature = "i0-negative-malformed-elf",
    feature = "i0-negative-malformed-startup",
    feature = "i0-negative-capability-count",
    feature = "i0-negative-capability-type",
    feature = "i0-negative-capability-rights"
))]
use wyrmroot_bootstrap::i0_negative_terminal_detail;
#[cfg(any(
    feature = "primordial-user-exception",
    feature = "primordial-invalid-return"
))]
use wyrmroot_bootstrap::run_bootstrap;
#[cfg(feature = "primordial-blocking-cleanup")]
use wyrmroot_bootstrap::run_bootstrap_with_before_ready;
#[cfg(not(any(
    feature = "primordial-blocking-cleanup",
    feature = "native-loader-smoke-integration",
    feature = "primordial-user-exception",
    feature = "primordial-invalid-return",
    feature = "i0-negative-malformed-elf",
    feature = "i0-negative-malformed-startup",
    feature = "i0-negative-capability-count",
    feature = "i0-negative-capability-type",
    feature = "i0-negative-capability-rights"
)))]
#[cfg(not(feature = "i-capability-integration"))]
#[cfg(feature = "wyr0-init0-integration")]
use wyrmroot_bootstrap::run_init0_bootstrap;
#[cfg(any(
    feature = "i0-negative-malformed-elf",
    feature = "i0-negative-malformed-startup",
    feature = "i0-negative-capability-count",
    feature = "i0-negative-capability-type",
    feature = "i0-negative-capability-rights"
))]
use wyrmroot_bootstrap::run_init0_bootstrap_with_fault;
#[cfg(feature = "i-capability-integration")]
use wyrmroot_bootstrap::run_init0_capability_bootstrap;
#[cfg(feature = "native-loader-smoke-integration")]
use wyrmroot_bootstrap::run_loader_smoke_bootstrap;
use wyrmroot_bootstrap::run_supervisor_bootstrap;
use wyrmroot_bootstrap::{BootstrapError, BootstrapSystem};
use wyrmroot_bootstrap_proto as _;
use wyrmroot_loader as _;
use wyrmroot_runtime::{
    CapabilityInfo, MappingPlan, NativeError, ReceiveCounts, StartupBlock, close_handle,
    map_bootfs_read_only, panic_abort, query_capability_info, query_memory_object_size,
    receive_channel, send_channel, unmap_bootfs,
};
#[cfg(any(
    feature = "native-loader-smoke-integration",
    feature = "i0-negative-malformed-elf",
    feature = "i0-negative-malformed-startup",
    feature = "i0-negative-capability-count",
    feature = "i0-negative-capability-type",
    feature = "i0-negative-capability-rights",
    not(any(
        feature = "primordial-blocking-cleanup",
        feature = "primordial-user-exception",
        feature = "primordial-invalid-return"
    ))
))]
use wyrmroot_runtime::{NativeLoaderPlatform, NativeSupervisionPlatform, monotonic_deadline_after};

#[cfg(any(
    feature = "native-loader-smoke-integration",
    feature = "i0-negative-malformed-elf",
    feature = "i0-negative-malformed-startup",
    feature = "i0-negative-capability-count",
    feature = "i0-negative-capability-type",
    feature = "i0-negative-capability-rights",
    not(any(
        feature = "primordial-blocking-cleanup",
        feature = "primordial-user-exception",
        feature = "primordial-invalid-return"
    ))
))]
const BOOTSTRAP_SUPERVISION_TIMEOUT_NS: u64 = if cfg!(feature = "dw1c-bootstrap-supervision") {
    // Selector 28 deliberately sends init0 READY only after its complete
    // transaction, matching the established selector-26 contract. Its own
    // controller enforces separate setup/ARM, 240-second workload, and cleanup
    // deadlines. This outer watchdog must contain those phases without
    // replacing them or moving READY ahead of a possible selector failure.
    270_000_000_000
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
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    panic_abort()
}

#[cfg(not(any(
    feature = "primordial-blocking-cleanup",
    feature = "primordial-user-exception",
    feature = "primordial-invalid-return",
    feature = "native-loader-smoke-integration",
    feature = "i0-negative-malformed-elf",
    feature = "i0-negative-malformed-startup",
    feature = "i0-negative-capability-count",
    feature = "i0-negative-capability-type",
    feature = "i0-negative-capability-rights",
    feature = "i-capability-integration",
    feature = "wyr0-init0-integration"
)))]
fn bootstrap_main(startup: StartupBlock<'_>) -> u32 {
    let deadline = match monotonic_deadline_after(BOOTSTRAP_SUPERVISION_TIMEOUT_NS) {
        Ok(deadline) => deadline,
        Err(error) => return 0xB300_0000 | wyrmroot_runtime::native_error_code(error),
    };
    let mut system = NativeSystem::new();
    let mut loader = NativeLoaderPlatform;
    let mut supervisor = NativeSupervisionPlatform;
    match run_supervisor_bootstrap(
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

#[cfg(feature = "wyr0-init0-integration")]
fn bootstrap_main(startup: StartupBlock<'_>) -> u32 {
    let deadline = match monotonic_deadline_after(BOOTSTRAP_SUPERVISION_TIMEOUT_NS) {
        Ok(deadline) => deadline,
        Err(error) => return 0xB300_0000 | wyrmroot_runtime::native_error_code(error),
    };
    let mut system = NativeSystem::new();
    match run_init0_bootstrap(
        &mut system,
        &mut NativeLoaderPlatform,
        &mut NativeSupervisionPlatform,
        startup.bootstrap_channel().as_abi(),
        deadline,
    ) {
        Ok(()) => 0,
        Err(error) => system.exit_code(&error),
    }
}

#[cfg(feature = "i-capability-integration")]
fn bootstrap_main(startup: StartupBlock<'_>) -> u32 {
    let deadline = match monotonic_deadline_after(BOOTSTRAP_SUPERVISION_TIMEOUT_NS) {
        Ok(deadline) => deadline,
        Err(error) => return 0xB300_0000 | wyrmroot_runtime::native_error_code(error),
    };
    let mut system = NativeSystem::new();
    let mut loader = NativeLoaderPlatform;
    let mut supervisor = NativeSupervisionPlatform;
    match run_init0_capability_bootstrap(
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

#[cfg(any(
    feature = "i0-negative-malformed-elf",
    feature = "i0-negative-malformed-startup",
    feature = "i0-negative-capability-count",
    feature = "i0-negative-capability-type",
    feature = "i0-negative-capability-rights"
))]
fn bootstrap_main(startup: StartupBlock<'_>) -> u32 {
    use wyrmroot_loader::process::LoadFault;

    let deadline = match monotonic_deadline_after(BOOTSTRAP_SUPERVISION_TIMEOUT_NS) {
        Ok(deadline) => deadline,
        Err(_) => return 1,
    };
    let fault = if cfg!(feature = "i0-negative-malformed-elf") {
        LoadFault::MalformedElf
    } else if cfg!(feature = "i0-negative-malformed-startup") {
        LoadFault::MalformedStartup
    } else if cfg!(feature = "i0-negative-capability-count") {
        LoadFault::InitCapabilityCount
    } else if cfg!(feature = "i0-negative-capability-type") {
        LoadFault::InitCapabilityType
    } else {
        LoadFault::InitCapabilityRights
    };
    let mut system = NativeSystem::new();
    let mut loader = NativeLoaderPlatform;
    let mut supervisor = NativeSupervisionPlatform;
    match run_init0_bootstrap_with_fault(
        &mut system,
        &mut loader,
        &mut supervisor,
        startup.bootstrap_channel().as_abi(),
        deadline,
        fault,
    ) {
        Ok(()) => 0,
        Err(error) => {
            i0_negative_terminal_detail(fault, &error).unwrap_or_else(|| system.exit_code(&error))
        }
    }
}

#[cfg(feature = "native-loader-smoke-integration")]
fn bootstrap_main(startup: StartupBlock<'_>) -> u32 {
    let deadline = match monotonic_deadline_after(BOOTSTRAP_SUPERVISION_TIMEOUT_NS) {
        Ok(deadline) => deadline,
        Err(_) => return 1,
    };
    let mut system = NativeSystem::new();
    let mut loader = NativeLoaderPlatform;
    let mut supervisor = NativeSupervisionPlatform;
    u32::from(
        run_loader_smoke_bootstrap(
            &mut system,
            &mut loader,
            &mut supervisor,
            startup.bootstrap_channel().as_abi(),
            deadline,
        )
        .is_err(),
    )
}

#[cfg(feature = "primordial-blocking-cleanup")]
fn bootstrap_main(startup: StartupBlock<'_>) -> u32 {
    let mut system = NativeSystem::new();
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
    let mut system = NativeSystem::new();
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
