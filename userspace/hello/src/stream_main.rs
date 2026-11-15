#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;
use deepwyrm_syscall::{DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights};
use wyrmroot_hello::{HelloSystem, JobHelloSystem, Probe, run_stream_hello_with};
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
    if mode == Some("slow-ready") {
        // Never answers INIT: init's READY timeout ends it mid-commit.
        memory::slow_ready();
    }
    let mut run = |region: DwHandle, budget: u64, write: &mut dyn FnMut(&[u8]) -> bool| {
        memory::run(mode.unwrap_or(""), region, budget, write)
    };
    let probe: Option<Probe<'_>> = mode.filter(|mode| memory::is_mode(mode)).map(|_| {
        let run: Probe<'_> = &mut run;
        run
    });
    run_stream_hello_with(&mut system, startup.bootstrap_channel().as_abi(), probe)
        .unwrap_or_else(|error| error.exit_code())
}

/// The memory probes of `run bin/hello <mode>` and `spawn bin/hello <mode>`
/// (Deepwyrm DW2 M6 and M5 §10.5). Each runs once the job is running. Every
/// mode first writes the job's budget from its INIT (`job budget-kib=`),
/// which the check compares with init's plan (probe 12).
/// - `on-demand`, `on-demand-exhaust`: an on-demand object end to end
///   (M6); the second then spends the quota and touches past it.
/// - `eager`: eager objects of 4, 8 and 256 MiB created, mapped, touched in
///   every page, protected and unmapped in steps, each timed (probes 13
///   and 14).
/// - `hold-touched`, `hold-released`: maps 64 MiB on demand with no handle
///   left, touches every page and, for the second, unmaps the top half;
///   then waits forever, for the check to read usage (probe 13).
/// - `churn-map`, `churn-create`, `churn-commit`: repeat a 256 MiB map
///   (keeping the mappings until a map is refused), eager create, or
///   on-demand commit forever, for the check to stop mid-call (probe 15).
/// - `slow-ready`: commits forever before READY (see `hello_main`).
/// - `close-spin`: commits a 512 MiB on-demand object, closes it (its
///   finalization is then owed) and spins about a second in user mode with
///   no syscall and no fault, then prints `close-spin spin-us=` (DW2 §10.19:
///   with the job on an AP, only a woken BSP steps the owed work).
#[allow(
    unsafe_code,
    reason = "reads and writes the probe's own fresh mappings through raw pointers"
)]
mod memory {
    use deepwyrm_syscall::{
        DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE, DW_ADDRESS_REGION_MAP_ARGS_V1_VERSION,
        DW_CLOCK_MONOTONIC_ACTIVE, DW_DEADLINE_INFINITE, DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND,
        DW_MEMORY_PROTECTION_READ, DW_MEMORY_PROTECTION_WRITE, DW_RIGHT_MAP, DW_RIGHT_READ,
        DW_RIGHT_WAIT, DW_RIGHT_WRITE, DW_SIGNAL_READABLE, DW_STATUS_NO_RESOURCES,
        DW_STATUS_SUCCESS, DwAddressRegionMapArgsV1, DwHandle, DwMemoryObjectCreateFlags,
        DwMemoryProtection, DwOffset, DwRights, DwSize, DwUserAddress, DwWaitResultV1,
    };

    const MIB: u64 = 1 << 20;
    const PAGE: u64 = 4096;
    const CHURN: u64 = 256 * MIB;
    const HOLD: u64 = 64 * MIB;
    /// `close-spin`'s object: about 256 finalize steps of 512 entries.
    const SPIN_OBJECT: u64 = 512 * MIB;
    /// How long `close-spin` spins after the close, and how long one
    /// calibration call must take at least.
    const SPIN_US: u64 = 1_000_000;
    const SPIN_CALIBRATION_US: u64 = 100_000;
    const RW: DwMemoryProtection =
        DwMemoryProtection(DW_MEMORY_PROTECTION_READ.0 | DW_MEMORY_PROTECTION_WRITE.0);

    pub(super) fn is_mode(mode: &str) -> bool {
        matches!(
            mode,
            "on-demand"
                | "on-demand-exhaust"
                | "eager"
                | "hold-touched"
                | "hold-released"
                | "churn-map"
                | "churn-create"
                | "churn-commit"
                | "close-spin"
        )
    }

    pub(super) fn run(
        mode: &str,
        region: DwHandle,
        budget: u64,
        write: &mut dyn FnMut(&[u8]) -> bool,
    ) -> u32 {
        let mut line = Line::new();
        line.text("job budget-kib=")
            .number(budget / 1024)
            .text("\n");
        write(line.bytes());
        match mode {
            "on-demand" | "on-demand-exhaust" => {
                let exhaust = mode == "on-demand-exhaust";
                match super::on_demand::probe(region, exhaust) {
                    Ok(base) => {
                        if !exhaust {
                            write(b"on-demand ok\n");
                            return 0;
                        }
                        write(b"on-demand quota next\n");
                        super::on_demand::exhaust(base, budget)
                    }
                    Err(failure) => {
                        write(failure);
                        2
                    }
                }
            }
            "eager" => eager(region, write),
            "hold-touched" | "hold-released" => hold(region, mode == "hold-released"),
            "churn-map" => churn_map(region),
            "churn-create" => loop {
                let Ok(object) = create(CHURN, DwMemoryObjectCreateFlags(0)) else {
                    return 2;
                };
                deepwyrm_syscall::handle_close(object);
            },
            "churn-commit" => loop {
                if commit_once(CHURN).is_err() {
                    return 2;
                }
            },
            "close-spin" => close_spin(write),
            _ => 2,
        }
    }

    /// `slow-ready`: commits 512 MiB objects, one after another, forever.
    pub(super) fn slow_ready() -> ! {
        loop {
            let _ = commit_once(512 * MIB);
        }
    }

    fn commit_once(size: u64) -> Result<(), ()> {
        let object = create(size, DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND)?;
        let _ = deepwyrm_syscall::memory_object_commit(object, DwOffset(0), DwSize(size));
        deepwyrm_syscall::handle_close(object);
        Ok(())
    }

    fn now_us() -> u64 {
        let mut nanoseconds = 0;
        deepwyrm_syscall::clock_get(DW_CLOCK_MONOTONIC_ACTIVE.0, &mut nanoseconds);
        nanoseconds / 1000
    }

    fn create(size: u64, flags: DwMemoryObjectCreateFlags) -> Result<DwHandle, ()> {
        let mut object = DwHandle(0);
        let rights = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0);
        (deepwyrm_syscall::memory_object_create(DwSize(size), flags, rights, &mut object)
            == DW_STATUS_SUCCESS)
            .then_some(object)
            .ok_or(())
    }

    fn map(region: DwHandle, object: DwHandle, size: u64) -> Result<u64, ()> {
        let args = DwAddressRegionMapArgsV1 {
            size: DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE,
            version: DW_ADDRESS_REGION_MAP_ARGS_V1_VERSION,
            memory_object_offset: DwOffset(0),
            byte_len: DwSize(size),
            protections: RW,
            ..DwAddressRegionMapArgsV1::default()
        };
        let mut at = DwUserAddress(0);
        (deepwyrm_syscall::address_region_map(region, object, &args, &mut at) == DW_STATUS_SUCCESS)
            .then_some(at.0)
            .ok_or(())
    }

    fn unmap(region: DwHandle, at: u64, size: u64) -> Result<(), ()> {
        (deepwyrm_syscall::address_region_unmap(region, DwUserAddress(at), DwSize(size))
            == DW_STATUS_SUCCESS)
            .then_some(())
            .ok_or(())
    }

    fn read(address: u64) -> u64 {
        // SAFETY: `address` is an aligned word of the probe's own mapping.
        unsafe { core::ptr::read_volatile(address as *const u64) }
    }

    fn write_word(address: u64, value: u64) {
        // SAFETY: as for `read`; the mapping is read-write when written.
        unsafe { core::ptr::write_volatile(address as *mut u64, value) }
    }

    /// Writes a word into every page of `[base, base + size)`, each found
    /// zero first; `false` if one was not.
    fn touch_all(base: u64, size: u64) -> bool {
        let mut page = base;
        while page < base + size {
            if read(page) != 0 {
                return false;
            }
            write_word(page, page);
            page += PAGE;
        }
        true
    }

    fn eager(region: DwHandle, write: &mut dyn FnMut(&[u8]) -> bool) -> u32 {
        for size_mib in [4, 8, 256] {
            match eager_once(region, size_mib * MIB) {
                Ok(times) => {
                    let mut line = Line::new();
                    line.text("eager size-mib=").number(size_mib);
                    for (name, value) in [
                        (" create-us=", times[0]),
                        (" map-us=", times[1]),
                        (" touch-us=", times[2]),
                        (" protect-us=", times[3]),
                        (" unmap-us=", times[4]),
                    ] {
                        line.text(name).number(value);
                    }
                    line.text("\n");
                    write(line.bytes());
                }
                Err(step) => {
                    let mut line = Line::new();
                    line.text("eager failed: ").text(step).text("\n");
                    write(line.bytes());
                    return 2;
                }
            }
        }
        write(b"eager ok\n");
        0
    }

    /// One eager object of `size`: create, map, touch, protect read-only,
    /// unmap; the microseconds each took.
    fn eager_once(region: DwHandle, size: u64) -> Result<[u64; 5], &'static str> {
        let start = now_us();
        let object = create(size, DwMemoryObjectCreateFlags(0)).map_err(|()| "create")?;
        let created = now_us();
        let base = map(region, object, size).map_err(|()| "map")?;
        let mapped = now_us();
        if !touch_all(base, size) {
            return Err("touch");
        }
        let touched = now_us();
        if deepwyrm_syscall::address_region_protect(
            region,
            DwUserAddress(base),
            DwSize(size),
            DW_MEMORY_PROTECTION_READ,
        ) != DW_STATUS_SUCCESS
        {
            return Err("protect");
        }
        let protected = now_us();
        if read(base + size - PAGE) != base + size - PAGE || read(base) != base {
            return Err("read back");
        }
        unmap(region, base, size).map_err(|()| "unmap")?;
        let unmapped = now_us();
        if deepwyrm_syscall::handle_close(object) != DW_STATUS_SUCCESS {
            return Err("close");
        }
        Ok([
            created - start,
            mapped - created,
            touched - mapped,
            protected - touched,
            unmapped - protected,
        ])
    }

    /// Maps [`HOLD`] on demand, lets the object's handle go, touches every
    /// page, unmaps the top half if `release`, then waits forever.
    fn hold(region: DwHandle, release: bool) -> u32 {
        let Ok(object) = create(HOLD, DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND) else {
            return 2;
        };
        let Ok(base) = map(region, object, HOLD) else {
            return 2;
        };
        // Only the mapping holds the object now, so an unmap returns pages.
        if deepwyrm_syscall::handle_close(object) != DW_STATUS_SUCCESS || !touch_all(base, HOLD) {
            return 2;
        }
        if release && unmap(region, base + HOLD / 2, HOLD / 2).is_err() {
            return 2;
        }
        wait_forever()
    }

    fn churn_map(region: DwHandle) -> u32 {
        let Ok(object) = create(CHURN, DwMemoryObjectCreateFlags(0)) else {
            return 2;
        };
        // The object is mapped again and again at new addresses and the
        // mappings are kept, so the job is almost always inside a map's
        // steps when it is stopped (probe 15). Only when a map is refused
        // (slots, room or page-table quota) are they all unmapped.
        let mut bases = [0_u64; 64];
        let mut count = 0;
        loop {
            match map(region, object, CHURN) {
                Ok(base) if count < bases.len() => {
                    bases[count] = base;
                    count += 1;
                }
                Ok(base) => {
                    if unmap(region, base, CHURN).is_err() {
                        return 2;
                    }
                }
                Err(_) if count > 0 => {
                    for &base in &bases[..count] {
                        if unmap(region, base, CHURN).is_err() {
                            return 2;
                        }
                    }
                    count = 0;
                }
                Err(_) => return 2,
            }
        }
    }

    /// `close-spin`: a committed on-demand object closed, then a spin of
    /// about [`SPIN_US`] with no syscall and no page fault, timed by one
    /// clock read after it. The object fills the job's budget, so its
    /// commit may stop at the quota; what was committed is kept.
    fn close_spin(write: &mut dyn FnMut(&[u8]) -> bool) -> u32 {
        let Ok(object) = create(SPIN_OBJECT, DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND) else {
            return 2;
        };
        let committed =
            deepwyrm_syscall::memory_object_commit(object, DwOffset(0), DwSize(SPIN_OBJECT));
        if committed != DW_STATUS_SUCCESS && committed != DW_STATUS_NO_RESOURCES {
            return 2;
        }
        // Calibrated before the close, with the same function, so its code
        // and stack are already touched when it runs after the close.
        let mut iterations: u64 = 1 << 16;
        let elapsed = loop {
            let start = now_us();
            spin(iterations);
            let elapsed = now_us().saturating_sub(start);
            if elapsed >= SPIN_CALIBRATION_US || iterations >= 1 << 40 {
                break elapsed.max(1);
            }
            iterations *= 2;
        };
        let target =
            u64::try_from(u128::from(iterations) * u128::from(SPIN_US) / u128::from(elapsed))
                .unwrap_or(u64::MAX);
        let start = now_us();
        if deepwyrm_syscall::handle_close(object) != DW_STATUS_SUCCESS {
            return 2;
        }
        spin(target);
        let spun = now_us().saturating_sub(start);
        let mut line = Line::new();
        line.text("close-spin spin-us=").number(spun).text("\n");
        write(line.bytes());
        0
    }

    /// Counts to `iterations` in registers or on the touched stack: no
    /// syscall, no new page.
    #[inline(never)]
    fn spin(iterations: u64) -> u64 {
        let mut count = 0_u64;
        while count < iterations {
            count = core::hint::black_box(count) + 1;
        }
        count
    }

    fn wait_forever() -> u32 {
        let (mut sender, mut receiver) = (DwHandle(0), DwHandle(0));
        if deepwyrm_syscall::channel_create(
            DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0),
            &mut sender,
            &mut receiver,
        ) != DW_STATUS_SUCCESS
        {
            return 2;
        }
        // Nothing is ever sent, and the sender stays open.
        let mut result = DwWaitResultV1::default();
        deepwyrm_syscall::wait_one(
            receiver,
            DW_SIGNAL_READABLE,
            DW_DEADLINE_INFINITE,
            &mut result,
        );
        2
    }

    /// A line built without allocation; text past its size is dropped.
    struct Line {
        bytes: [u8; 160],
        len: usize,
    }

    impl Line {
        const fn new() -> Self {
            Self {
                bytes: [0; 160],
                len: 0,
            }
        }

        fn text(&mut self, text: &str) -> &mut Self {
            for &byte in text.as_bytes() {
                if self.len < self.bytes.len() {
                    self.bytes[self.len] = byte;
                    self.len += 1;
                }
            }
            self
        }

        fn number(&mut self, mut value: u64) -> &mut Self {
            let mut digits = [0u8; 20];
            let mut count = 0;
            loop {
                digits[count] = b'0' + (value % 10) as u8;
                count += 1;
                value /= 10;
                if value == 0 {
                    break;
                }
            }
            for &digit in digits[..count].iter().rev() {
                if self.len < self.bytes.len() {
                    self.bytes[self.len] = digit;
                    self.len += 1;
                }
            }
            self
        }

        fn bytes(&self) -> &[u8] {
            &self.bytes[..self.len]
        }
    }
}

/// `run bin/hello on-demand`: exercises an on-demand MemoryObject end to
/// end in a real job (Deepwyrm DW2 M6 §8.7 step 5). It creates and maps a
/// 64 MiB object, touches pages across it (each a served page fault), reads
/// untouched ones as zero, has a syscall write into a page never touched
/// (the fill-in phase), and commits a page. With `on-demand-exhaust` it
/// then commits a second object four times its memory budget (from its
/// INIT, DW2 M5), which stops at the quota, and touches an untouched page of
/// the first, which ends it with `DW_TERMINATION_RESOURCE_POLICY`. A
/// failure names the first step that failed.
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
    /// The mapped object's size, which the fixed offsets below fit in.
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
    fn touch(address: u64) {
        write(address, MARK);
    }

    /// Commits a new object four times the job's budget, so the commit stops
    /// at the quota with `NO_RESOURCES`; then touches an untouched page of
    /// the probe's mapping at `base`, which ends the job. Exit status 2 if
    /// the object could not be made or the commit was not refused.
    pub(super) fn exhaust(base: u64, budget: u64) -> u32 {
        let Some(size) = budget.checked_mul(4) else {
            return 2;
        };
        let mut object = DwHandle(0);
        if deepwyrm_syscall::memory_object_create(
            DwSize(size),
            DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND,
            // Commit needs MAP.
            DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0),
            &mut object,
        ) != DW_STATUS_SUCCESS
            || deepwyrm_syscall::memory_object_commit(object, DwOffset(0), DwSize(size))
                != DW_STATUS_NO_RESOURCES
        {
            return 2;
        }
        touch(base + 50 * MIB);
        1
    }

    /// The probe; with `keep`, the mapping is left for [`exhaust`]. Its
    /// base, or the line naming the step that failed.
    pub(super) fn probe(region: DwHandle, keep: bool) -> Result<u64, &'static [u8]> {
        let size = SIZE;
        let mut object = DwHandle(0);
        let rights =
            DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0 | DW_RIGHT_INSPECT.0);
        if deepwyrm_syscall::memory_object_create(
            DwSize(size),
            DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND,
            rights,
            &mut object,
        ) != DW_STATUS_SUCCESS
        {
            return Err(b"on-demand failed: create\n");
        }
        let mut info = DwMemoryObjectInfoV1::default();
        let mut required = 0;
        if deepwyrm_syscall::object_get_memory_object_info_v1(object, &mut info, &mut required)
            != DW_STATUS_SUCCESS
            || info.flags != DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND
            || info.byte_size != size
        {
            return Err(b"on-demand failed: info\n");
        }
        let args = DwAddressRegionMapArgsV1 {
            size: DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE,
            version: DW_ADDRESS_REGION_MAP_ARGS_V1_VERSION,
            memory_object_offset: DwOffset(0),
            byte_len: DwSize(size),
            protections: DwMemoryProtection(
                DW_MEMORY_PROTECTION_READ.0 | DW_MEMORY_PROTECTION_WRITE.0,
            ),
            ..DwAddressRegionMapArgsV1::default()
        };
        let mut at = DwUserAddress(0);
        if deepwyrm_syscall::address_region_map(region, object, &args, &mut at) != DW_STATUS_SUCCESS
        {
            return Err(b"on-demand failed: map\n");
        }
        let base = at.0;
        // A read fault, then writes past the first 16 MiB and at the end.
        if read(base) != 0 {
            return Err(b"on-demand failed: first read\n");
        }
        write(base + 40 * MIB + 8, MARK);
        write(base + size - 8, !MARK);
        if read(base + 40 * MIB + 8) != MARK
            || read(base + size - 8) != !MARK
            || read(base + 40 * MIB + 4096) != 0
            || read(base + 8) != 0
        {
            return Err(b"on-demand failed: touch\n");
        }
        // A syscall writes into a page nothing has touched.
        let out = base + 20 * MIB;
        // SAFETY: an aligned word of the probe's own read-write mapping.
        let nanoseconds = unsafe { &mut *(out as *mut u64) };
        if deepwyrm_syscall::clock_get(DW_CLOCK_MONOTONIC_ACTIVE.0, nanoseconds)
            != DW_STATUS_SUCCESS
            || read(out) == 0
        {
            return Err(b"on-demand failed: fill-in\n");
        }
        if deepwyrm_syscall::memory_object_commit(object, DwOffset(30 * MIB), DwSize(4096))
            != DW_STATUS_SUCCESS
            || read(base + 30 * MIB) != 0
        {
            return Err(b"on-demand failed: commit\n");
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
            return Err(b"on-demand failed: channel\n");
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
            return Err(b"on-demand failed: read fill-in\n");
        }
        if keep {
            return Ok(base);
        }
        if deepwyrm_syscall::address_region_unmap(region, at, DwSize(size)) != DW_STATUS_SUCCESS
            || deepwyrm_syscall::handle_close(object) != DW_STATUS_SUCCESS
        {
            return Err(b"on-demand failed: teardown\n");
        }
        Ok(base)
    }
}
wyrmroot_runtime::native_entry!(crate::hello_main);
#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    panic_abort()
}
