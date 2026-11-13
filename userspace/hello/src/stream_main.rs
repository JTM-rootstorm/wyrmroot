#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;
use deepwyrm_syscall::{DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights};
use wyrmroot_hello::{HelloSystem, JobHelloSystem, run_stream_hello_with};
use wyrmroot_loader as _;
use wyrmroot_runtime::{
    CapabilityInfo, NativeError, ReceiveCounts, StartupBlock, StreamSystem, close_handle,
    panic_abort, query_capability_info, receive_channel, send_channel, wait_one,
};

struct NativeSystem;
impl HelloSystem for NativeSystem {
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
impl JobHelloSystem for NativeSystem {
    fn wait_channel(
        &mut self,
        channel: DwHandle,
        signals: deepwyrm_syscall::DwSignals,
    ) -> Result<deepwyrm_syscall::DwSignals, NativeError> {
        wait_one(channel, signals, deepwyrm_syscall::DW_DEADLINE_INFINITE)
            .map(|result| result.observed)
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
    fn wait(
        &mut self,
        channel: DwHandle,
        signals: deepwyrm_syscall::DwSignals,
    ) -> Result<deepwyrm_syscall::DwSignals, NativeError> {
        wait_one(channel, signals, deepwyrm_syscall::DW_DEADLINE_INFINITE)
            .map(|result| result.observed)
    }
}
fn hello_main(startup: StartupBlock<'_>) -> u32 {
    let mut system = NativeSystem;
    let mode = (startup.argc() >= 2)
        .then(|| startup.arg(1).map(|argument| argument.as_str()))
        .flatten();
    let exhaust = mode == Some("on-demand-exhaust");
    let mut last_touch = None;
    let mut probe = |region: DwHandle| on_demand::probe(region, exhaust, &mut last_touch);
    let probe: Option<&mut dyn FnMut(DwHandle) -> &'static [u8]> = match mode {
        Some("on-demand" | "on-demand-exhaust") => Some(&mut probe),
        _ => None,
    };
    let status = run_stream_hello_with(&mut system, startup.bootstrap_channel().as_abi(), probe)
        .map_or_else(|error| error.exit_code(), |_| 0);
    // The exhausting touch comes once the job is running, not during its
    // launch, so it ends a job and init reports its termination.
    if let Some(address) = last_touch {
        on_demand::touch(address);
        return 1;
    }
    status
}

/// `run bin/hello on-demand`: exercises an on-demand MemoryObject end to
/// end in a real job (Deepwyrm DW2 M6 §8.7 step 5). It creates and maps a
/// 64 MiB object, larger than the job's whole page budget, touches pages
/// across it (each a served page fault), reads untouched ones as zero, has
/// a syscall write into a page never touched (the fill-in phase), and
/// commits a page. With `on-demand-exhaust` it then spends the job's page
/// quota, and the job touches one more page once it is running, which ends
/// it with `DW_TERMINATION_RESOURCE_POLICY`. The line it returns names the
/// first step that failed.
#[allow(
    unsafe_code,
    reason = "reads and writes the probe's own fresh mapping through raw pointers"
)]
mod on_demand {
    use deepwyrm_syscall::{
        DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE, DW_ADDRESS_REGION_MAP_ARGS_V1_VERSION,
        DW_CLOCK_MONOTONIC_ACTIVE, DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND,
        DW_MEMORY_PROTECTION_READ, DW_MEMORY_PROTECTION_WRITE, DW_RIGHT_INSPECT, DW_RIGHT_MAP,
        DW_RIGHT_READ, DW_RIGHT_WRITE, DW_STATUS_NO_RESOURCES, DW_STATUS_SUCCESS,
        DwAddressRegionMapArgsV1, DwChannelReceiveResultV1, DwHandle, DwMemoryObjectInfoV1,
        DwMemoryProtection, DwOffset, DwRights, DwSize, DwUserAddress,
    };

    const MIB: u64 = 1 << 20;
    const SIZE: u64 = 64 * MIB;
    const MARK: u64 = 0x4f4e_2d44_454d_414e;

    fn read(address: u64) -> u64 {
        // SAFETY: `address` is an aligned word of the probe's own mapping.
        unsafe { core::ptr::read_volatile(address as *const u64) }
    }

    fn write(address: u64, value: u64) {
        // SAFETY: as for `read`; the mapping is read-write.
        unsafe { core::ptr::write_volatile(address as *mut u64, value) }
    }

    /// Writes one word of the probe's mapping.
    pub(super) fn touch(address: u64) {
        write(address, MARK);
    }

    pub(super) fn probe(
        region: DwHandle,
        exhaust: bool,
        last_touch: &mut Option<u64>,
    ) -> &'static [u8] {
        let mut object = DwHandle(0);
        let rights =
            DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0 | DW_RIGHT_INSPECT.0);
        if deepwyrm_syscall::memory_object_create(
            DwSize(SIZE),
            DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND,
            rights,
            &mut object,
        ) != DW_STATUS_SUCCESS
        {
            return b"on-demand failed: create\n";
        }
        let mut info = DwMemoryObjectInfoV1::default();
        let mut required = 0;
        if deepwyrm_syscall::object_get_memory_object_info_v1(object, &mut info, &mut required)
            != DW_STATUS_SUCCESS
            || info.flags != DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND
            || info.byte_size != SIZE
        {
            return b"on-demand failed: info\n";
        }
        let args = DwAddressRegionMapArgsV1 {
            size: DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE,
            version: DW_ADDRESS_REGION_MAP_ARGS_V1_VERSION,
            memory_object_offset: DwOffset(0),
            byte_len: DwSize(SIZE),
            protections: DwMemoryProtection(
                DW_MEMORY_PROTECTION_READ.0 | DW_MEMORY_PROTECTION_WRITE.0,
            ),
            ..DwAddressRegionMapArgsV1::default()
        };
        let mut at = DwUserAddress(0);
        if deepwyrm_syscall::address_region_map(region, object, &args, &mut at) != DW_STATUS_SUCCESS
        {
            return b"on-demand failed: map\n";
        }
        let base = at.0;
        // A read fault, then writes past the first 16 MiB and at the end.
        if read(base) != 0 {
            return b"on-demand failed: first read\n";
        }
        write(base + 40 * MIB + 8, MARK);
        write(base + SIZE - 8, !MARK);
        if read(base + 40 * MIB + 8) != MARK
            || read(base + SIZE - 8) != !MARK
            || read(base + 40 * MIB + 4096) != 0
            || read(base + 8) != 0
        {
            return b"on-demand failed: touch\n";
        }
        // A syscall writes into a page nothing has touched.
        let out = base + 20 * MIB;
        // SAFETY: an aligned word of the probe's own read-write mapping.
        let nanoseconds = unsafe { &mut *(out as *mut u64) };
        if deepwyrm_syscall::clock_get(DW_CLOCK_MONOTONIC_ACTIVE.0, nanoseconds)
            != DW_STATUS_SUCCESS
            || read(out) == 0
        {
            return b"on-demand failed: fill-in\n";
        }
        if deepwyrm_syscall::memory_object_commit(object, DwOffset(30 * MIB), DwSize(4096))
            != DW_STATUS_SUCCESS
            || read(base + 30 * MIB) != 0
        {
            return b"on-demand failed: commit\n";
        }
        // A syscall reads from a page nothing has touched: the kernel fills
        // it in for the read, and what it reads is zeros.
        let input = base + 25 * MIB;
        let (mut sender, mut receiver) = (DwHandle(0), DwHandle(0));
        if deepwyrm_syscall::channel_create(
            DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0),
            &mut sender,
            &mut receiver,
        ) != DW_STATUS_SUCCESS
        {
            return b"on-demand failed: channel\n";
        }
        // SAFETY: 64 bytes of the probe's own mapping, never written.
        let untouched = unsafe { core::slice::from_raw_parts(input as *const u8, 64) };
        let mut received = [0xff_u8; 64];
        let mut result = DwChannelReceiveResultV1::default();
        let sent = deepwyrm_syscall::channel_send(sender, untouched, &[], 0);
        let got = deepwyrm_syscall::channel_receive(receiver, &mut received, &mut [], &mut result);
        let closed = deepwyrm_syscall::handle_close(sender) == DW_STATUS_SUCCESS
            && deepwyrm_syscall::handle_close(receiver) == DW_STATUS_SUCCESS;
        if sent != DW_STATUS_SUCCESS
            || got != DW_STATUS_SUCCESS
            || !closed
            || received.iter().any(|byte| *byte != 0)
            || read(input) != 0
        {
            return b"on-demand failed: read fill-in\n";
        }
        if exhaust {
            // The whole object is four times the job's page budget.
            if deepwyrm_syscall::memory_object_commit(object, DwOffset(0), DwSize(SIZE))
                != DW_STATUS_NO_RESOURCES
            {
                return b"on-demand failed: commit past the quota\n";
            }
            // Untouched and past what the commit reached: the caller's
            // touch of it ends the job.
            *last_touch = Some(base + 50 * MIB);
            return b"on-demand quota spent\n";
        }
        if deepwyrm_syscall::address_region_unmap(region, at, DwSize(SIZE)) != DW_STATUS_SUCCESS
            || deepwyrm_syscall::handle_close(object) != DW_STATUS_SUCCESS
        {
            return b"on-demand failed: teardown\n";
        }
        b"on-demand ok\n"
    }
}
wyrmroot_runtime::native_entry!(crate::hello_main);
#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    panic_abort()
}
