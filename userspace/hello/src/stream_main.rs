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
    let argument = |index: usize| {
        (startup.argc() > index)
            .then(|| startup.arg(index).map(|argument| argument.as_str()))
            .flatten()
    };
    let arguments = [argument(2), argument(3), argument(4)];
    let mut run = |region: DwHandle, budget: u64, write: &mut dyn FnMut(&[u8]) -> bool| {
        memory::run(mode.unwrap_or(""), arguments, region, budget, write)
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
/// - `eager`: eager objects of 4, 8 and 256 MiB created, mapped, touched
///   in every page, protected, unmapped in steps and closed, each timed
///   (probes 13 and 14).
/// - `unfragmented`, `fragment <MiB>`, `fragmented <MiB>`: the
///   fragmented-guest probe (DW2 §12.10, part 1; see `fragment` and
///   `measure` below).
/// - `hold-touched`, `hold-released`: maps 64 MiB on demand with no handle
///   left, touches every page and, for the second, unmaps the top half;
///   then waits forever, for the check to read usage (probe 13).
/// - `churn-map`, `churn-create`, `churn-commit`: repeat a 256 MiB map
///   (keeping the mappings until a map is refused), eager create, or
///   on-demand commit forever, for the check to stop mid-call (probe 15).
///   A refused create ends the last two: the kernel waits for owed work
///   inside the call (DW2 M8 §13.12 part b), so no probe waits itself.
/// - `slow-ready`: commits forever before READY (see `hello_main`).
/// - `touch-loop <MiB> <rounds> [committed]`: times a first touch of every
///   page of a fresh on-demand mapping, round after round, and prints the
///   least, median and greatest nanoseconds a page (DW2 M8 §13.5; the loop
///   is `wyrmroot_hello::probe::touch_loop`). With `committed`, each round
///   commits its object before mapping it, so every touch is of a page
///   already committed (DW2 M8b §15.2 step 1).
///
/// A mode that fails ends its job with a `ProbeSite` status naming the
/// place and the kernel status (`wyrmroot_hello::probe`, DW2 M8 §13.4
/// item 2); the churn probes themselves are in that module.
/// - `close-spin`: commits a 512 MiB on-demand object, closes it (its
///   finalization is then owed) and spins half a second in user mode with
///   no syscall and no fault, then prints `close-spin spin-us=` with the
///   APIC IDs it spun on (DW2 §10.19: a job on an AP that queues owed work
///   while the BSP is idle has the kernel wake the BSP for it).
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
        DW_STATUS_SUCCESS, DwAddressRegionMapArgsV1, DwDeadline, DwHandle,
        DwMemoryObjectCreateFlags, DwMemoryProtection, DwOffset, DwRights, DwSize, DwStatus,
        DwUserAddress, DwWaitResultV1,
    };
    use wyrmroot_hello::{ChurnCalls, ProbeSite, TouchCalls, probe};

    const MIB: u64 = 1 << 20;
    const PAGE: u64 = 4096;
    const HOLD: u64 = 64 * MIB;
    /// `close-spin`'s object: about 256 finalize steps of 512 entries.
    const SPIN_OBJECT: u64 = 512 * MIB;
    /// How long `close-spin` spins after the close, and how long one
    /// calibration call must take at least.
    const SPIN_US: u64 = 500_000;
    const SPIN_CALIBRATION_US: u64 = 100_000;
    /// The fragmented probe's measured object, and `eager`'s largest.
    const MEASURED_MIB: u64 = 448;
    /// What `fragment` leaves of its budget while it commits, and after its
    /// final object (the harness's `COMMIT_SPARE_KIB` and
    /// `FINAL_SPARE_KIB`).
    const COMMIT_SPARE: u64 = 4 * MIB;
    const FINAL_SPARE: u64 = MIB;
    /// Hole pages committed per pinned page (the harness's `HOLE_PAGES`).
    const HOLE_PAGES: u64 = 3;
    /// How long `fragment` sleeps between tries of its final object.
    const RETRY_US: u64 = 10_000;
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
                | "fragment"
                | "fragmented"
                | "unfragmented"
                | "touch-loop"
        )
    }

    /// Runs `mode`; `arguments` are the job's three arguments after the
    /// mode, where given.
    pub(super) fn run(
        mode: &str,
        arguments: [Option<&str>; 3],
        region: DwHandle,
        budget: u64,
        write: &mut dyn FnMut(&[u8]) -> bool,
    ) -> u32 {
        let size_mib = arguments[0].and_then(parse_mib);
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
                    Err((failure, status)) => {
                        write(failure);
                        status
                    }
                }
            }
            "eager" => eager(region, write),
            "hold-touched" | "hold-released" => hold(region, mode == "hold-released"),
            "churn-map" => probe::churn_map(&mut Calls { region }),
            "churn-create" => probe::churn_create(&mut Calls { region }),
            "churn-commit" => probe::churn_commit(&mut Calls { region }),
            "close-spin" => close_spin(write),
            "touch-loop" => {
                let (size_mib, rounds, committed) =
                    match probe::touch_loop_arguments(arguments[0], arguments[1], arguments[2]) {
                        Ok(parsed) => parsed,
                        Err(status) => return status,
                    };
                probe::touch_loop(&mut Calls { region }, size_mib, rounds, committed, write)
            }
            "fragment" => match size_mib {
                Some(filler) => fragment(budget, filler * MIB),
                None => ProbeSite::FragmentArgument.alone(),
            },
            "fragmented" | "unfragmented" => {
                measure(mode, region, size_mib.unwrap_or(0) * MIB, write)
            }
            _ => ProbeSite::UnknownMode.alone(),
        }
    }

    /// `slow-ready`: commits 512 MiB objects, one after another, forever.
    pub(super) fn slow_ready() -> ! {
        // `slow-ready` maps nothing; the region is never used.
        let mut calls = Calls {
            region: DwHandle(0),
        };
        loop {
            let _ = probe::commit_once(&mut calls, 512 * MIB);
        }
    }

    /// The churn probes' and `touch-loop`'s kernel calls in `region`: the
    /// raw syscalls and the touch pass's writes, and nothing else.
    struct Calls {
        region: DwHandle,
    }

    impl ChurnCalls for Calls {
        fn create(
            &mut self,
            size: u64,
            flags: DwMemoryObjectCreateFlags,
        ) -> Result<DwHandle, DwStatus> {
            create(size, flags)
        }

        fn commit(&mut self, object: DwHandle, size: u64) -> DwStatus {
            deepwyrm_syscall::memory_object_commit(object, DwOffset(0), DwSize(size))
        }

        fn map(&mut self, object: DwHandle, size: u64) -> Result<u64, DwStatus> {
            map(self.region, object, size)
        }

        fn unmap(&mut self, at: u64, size: u64) -> Result<(), DwStatus> {
            unmap(self.region, at, size)
        }

        fn close(&mut self, handle: DwHandle) -> DwStatus {
            deepwyrm_syscall::handle_close(handle)
        }
    }

    impl TouchCalls for Calls {
        fn now_ns(&mut self) -> Result<u64, DwStatus> {
            let mut nanoseconds = 0;
            checked(deepwyrm_syscall::clock_get(
                DW_CLOCK_MONOTONIC_ACTIVE.0,
                &mut nanoseconds,
            ))
            .map(|()| nanoseconds)
        }

        fn touch(&mut self, base: u64, size: u64) {
            let mut page = base;
            while page < base + size {
                write_word(page, page);
                page += PAGE;
            }
        }
    }

    /// The kernel status as an error, `Ok` on success.
    fn checked(status: DwStatus) -> Result<(), DwStatus> {
        if status == DW_STATUS_SUCCESS {
            Ok(())
        } else {
            Err(status)
        }
    }

    fn now_us() -> u64 {
        let mut nanoseconds = 0;
        deepwyrm_syscall::clock_get(DW_CLOCK_MONOTONIC_ACTIVE.0, &mut nanoseconds);
        nanoseconds / 1000
    }

    fn create(size: u64, flags: DwMemoryObjectCreateFlags) -> Result<DwHandle, DwStatus> {
        let mut object = DwHandle(0);
        let rights = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0);
        checked(deepwyrm_syscall::memory_object_create(
            DwSize(size),
            flags,
            rights,
            &mut object,
        ))
        .map(|()| object)
    }

    fn map(region: DwHandle, object: DwHandle, size: u64) -> Result<u64, DwStatus> {
        let args = DwAddressRegionMapArgsV1 {
            size: DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE,
            version: DW_ADDRESS_REGION_MAP_ARGS_V1_VERSION,
            memory_object_offset: DwOffset(0),
            byte_len: DwSize(size),
            protections: RW,
            ..DwAddressRegionMapArgsV1::default()
        };
        let mut at = DwUserAddress(0);
        checked(deepwyrm_syscall::address_region_map(
            region, object, &args, &mut at,
        ))
        .map(|()| at.0)
    }

    fn unmap(region: DwHandle, at: u64, size: u64) -> Result<(), DwStatus> {
        checked(deepwyrm_syscall::address_region_unmap(
            region,
            DwUserAddress(at),
            DwSize(size),
        ))
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
                    write(timed_line("eager", size_mib, times).bytes());
                }
                Err((step, status)) => {
                    let mut line = Line::new();
                    line.text("eager failed: ").text(step).text("\n");
                    write(line.bytes());
                    return status;
                }
            }
        }
        write(b"eager ok\n");
        0
    }

    /// `<name> size-mib=N create-us= map-us= touch-us= protect-us=
    /// unmap-us= close-us=`.
    fn timed_line(name: &str, size_mib: u64, times: [u64; 6]) -> Line {
        let mut line = Line::new();
        line.text(name).text(" size-mib=").number(size_mib);
        for (name, value) in [
            (" create-us=", times[0]),
            (" map-us=", times[1]),
            (" touch-us=", times[2]),
            (" protect-us=", times[3]),
            (" unmap-us=", times[4]),
            (" close-us=", times[5]),
        ] {
            line.text(name).number(value);
        }
        line.text("\n");
        line
    }

    /// One eager object of `size`: create, map, touch, protect read-only,
    /// unmap, close; the microseconds each took, or the step that failed
    /// and the job status that says so.
    fn eager_once(region: DwHandle, size: u64) -> Result<[u64; 6], (&'static str, u32)> {
        let start = now_us();
        let object = create(size, DwMemoryObjectCreateFlags(0))
            .map_err(|status| ("create", ProbeSite::EagerCreate.with(status)))?;
        let created = now_us();
        let base = map(region, object, size)
            .map_err(|status| ("map", ProbeSite::EagerMap.with(status)))?;
        let mapped = now_us();
        if !touch_all(base, size) {
            return Err(("touch", ProbeSite::EagerTouch.alone()));
        }
        let touched = now_us();
        let status = deepwyrm_syscall::address_region_protect(
            region,
            DwUserAddress(base),
            DwSize(size),
            DW_MEMORY_PROTECTION_READ,
        );
        if status != DW_STATUS_SUCCESS {
            return Err(("protect", ProbeSite::EagerProtect.with(status)));
        }
        let protected = now_us();
        if read(base + size - PAGE) != base + size - PAGE || read(base) != base {
            return Err(("read back", ProbeSite::EagerReadBack.alone()));
        }
        unmap(region, base, size)
            .map_err(|status| ("unmap", ProbeSite::EagerUnmap.with(status)))?;
        let unmapped = now_us();
        let status = deepwyrm_syscall::handle_close(object);
        if status != DW_STATUS_SUCCESS {
            return Err(("close", ProbeSite::EagerClose.with(status)));
        }
        let closed = now_us();
        Ok([
            created - start,
            mapped - created,
            touched - mapped,
            protected - touched,
            unmapped - protected,
            closed - unmapped,
        ])
    }

    /// Maps [`HOLD`] on demand, lets the object's handle go, touches every
    /// page, unmaps the top half if `release`, then waits forever.
    fn hold(region: DwHandle, release: bool) -> u32 {
        let object = match create(HOLD, DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND) {
            Ok(object) => object,
            Err(status) => return ProbeSite::HoldCreate.with(status),
        };
        let base = match map(region, object, HOLD) {
            Ok(base) => base,
            Err(status) => return ProbeSite::HoldMap.with(status),
        };
        // Only the mapping holds the object now, so an unmap returns pages.
        let status = deepwyrm_syscall::handle_close(object);
        if status != DW_STATUS_SUCCESS {
            return ProbeSite::HoldClose.with(status);
        }
        if !touch_all(base, HOLD) {
            return ProbeSite::HoldTouch.alone();
        }
        if release && let Err(status) = unmap(region, base + HOLD / 2, HOLD / 2) {
            return ProbeSite::HoldUnmap.with(status);
        }
        wait_forever()
    }

    /// `close-spin`: a committed on-demand object closed, then a spin of
    /// about [`SPIN_US`] with no syscall and no page fault, timed by one
    /// clock read after it. The object fills the job's budget, so its
    /// commit may stop at the quota; what was committed is kept.
    fn close_spin(write: &mut dyn FnMut(&[u8]) -> bool) -> u32 {
        let object = match create(SPIN_OBJECT, DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND) {
            Ok(object) => object,
            Err(status) => return ProbeSite::CloseSpinCreate.with(status),
        };
        let committed =
            deepwyrm_syscall::memory_object_commit(object, DwOffset(0), DwSize(SPIN_OBJECT));
        if committed != DW_STATUS_SUCCESS && committed != DW_STATUS_NO_RESOURCES {
            return ProbeSite::CloseSpinCommit.with(committed);
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
        let status = deepwyrm_syscall::handle_close(object);
        if status != DW_STATUS_SUCCESS {
            return ProbeSite::CloseSpinClose.with(status);
        }
        let cpu_before = cpu();
        spin(target);
        let cpu_after = cpu();
        let spun = now_us().saturating_sub(start);
        let mut line = Line::new();
        line.text("close-spin spin-us=")
            .number(spun)
            .text(" apic-before=")
            .number(cpu_before)
            .text(" apic-after=")
            .number(cpu_after)
            .text(if committed == DW_STATUS_SUCCESS {
                " commit=full\n"
            } else {
                " commit=quota\n"
            });
        write(line.bytes());
        0
    }

    /// The initial APIC ID of the CPU running this, from `cpuid` (no
    /// syscall, no fault), so the check can tell a spin on the BSP (0)
    /// from one on an AP.
    fn cpu() -> u64 {
        u64::from(core::arch::x86_64::__cpuid(1).ebx >> 24)
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

    /// A decimal argument of whole MiB.
    fn parse_mib(text: &str) -> Option<u64> {
        if text.is_empty() || text.len() > 6 {
            return None;
        }
        text.bytes().try_fold(0_u64, |value, digit| {
            digit
                .is_ascii_digit()
                .then(|| value * 10 + u64::from(digit - b'0'))
        })
    }

    /// `fragment <MiB>`: commits a filler of that many MiB (none for 0),
    /// then two on-demand objects, alternately one page of the pins and
    /// [`HOLE_PAGES`] of the holes, all without mapping them, to the budget
    /// less [`COMMIT_SPARE`]. Single pages come out of the buddy allocator
    /// from the smallest free block, ascending and adjacent, so the filler
    /// takes the small blocks already free (the holes of a `fragment` run
    /// before) and each pinned page after it is followed by its holes in
    /// large blocks. Then it closes the filler and the holes: their pages
    /// are freed in owed steps, the holes as a page and a pair that cannot
    /// merge past the pin. Once its budget has room again it creates one
    /// eager object that brings it to the budget less [`FINAL_SPARE`], more
    /// than it held before, which is what the harness waits for; being
    /// eager, it takes large blocks, not holes. Then it waits forever.
    fn fragment(budget: u64, filler: u64) -> u32 {
        let target = budget.saturating_sub(COMMIT_SPARE + filler);
        let group = PAGE * (1 + HOLE_PAGES);
        let groups = target / group;
        let filled = if filler == 0 {
            None
        } else {
            let object = match create(filler, DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND) {
                Ok(object) => object,
                Err(status) => return ProbeSite::FragmentFillerCreate.with(status),
            };
            let status =
                deepwyrm_syscall::memory_object_commit(object, DwOffset(0), DwSize(filler));
            if status != DW_STATUS_SUCCESS {
                return ProbeSite::FragmentFillerCommit.with(status);
            }
            Some(object)
        };
        let (pins, holes) = match (
            create(groups * PAGE, DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND),
            create(
                groups * PAGE * HOLE_PAGES,
                DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND,
            ),
        ) {
            (Ok(pins), Ok(holes)) => (pins, holes),
            (Err(status), _) => return ProbeSite::FragmentPinsCreate.with(status),
            (_, Err(status)) => return ProbeSite::FragmentHolesCreate.with(status),
        };
        for index in 0..groups {
            let hole_size = PAGE * HOLE_PAGES;
            let status =
                deepwyrm_syscall::memory_object_commit(pins, DwOffset(index * PAGE), DwSize(PAGE));
            if status != DW_STATUS_SUCCESS {
                return ProbeSite::FragmentPinCommit.with(status);
            }
            let status = deepwyrm_syscall::memory_object_commit(
                holes,
                DwOffset(index * hole_size),
                DwSize(hole_size),
            );
            if status != DW_STATUS_SUCCESS {
                return ProbeSite::FragmentHoleCommit.with(status);
            }
        }
        if let Some(object) = filled {
            let status = deepwyrm_syscall::handle_close(object);
            if status != DW_STATUS_SUCCESS {
                return ProbeSite::FragmentFillerClose.with(status);
            }
        }
        let status = deepwyrm_syscall::handle_close(holes);
        if status != DW_STATUS_SUCCESS {
            return ProbeSite::FragmentHolesClose.with(status);
        }
        let sleeper = match Sleeper::new() {
            Ok(sleeper) => sleeper,
            Err(status) => return ProbeSite::FragmentSleeper.with(status),
        };
        let last = budget.saturating_sub(FINAL_SPARE + groups * PAGE);
        loop {
            let mut object = DwHandle(0);
            let status = deepwyrm_syscall::memory_object_create(
                DwSize(last),
                DwMemoryObjectCreateFlags(0),
                DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0),
                &mut object,
            );
            if status == DW_STATUS_SUCCESS {
                break;
            }
            if status != DW_STATUS_NO_RESOURCES {
                return ProbeSite::FragmentFinalCreate.with(status);
            }
            sleeper.sleep(RETRY_US);
        }
        sleeper.forever()
    }

    /// `fragmented <MiB>` and `unfragmented`: an eager top-up of that size
    /// (none for 0) held while one eager object of [`MEASURED_MIB`] runs
    /// `eager`'s cycle, each call timed; `name` (the mode) starts each line.
    /// The check runs `unfragmented` before `fragment` and `fragmented`
    /// after, so the two lines come from the same code on the same guest,
    /// unfragmented and fragmented.
    fn measure(
        name: &str,
        region: DwHandle,
        top_up: u64,
        write: &mut dyn FnMut(&[u8]) -> bool,
    ) -> u32 {
        let failed = |write: &mut dyn FnMut(&[u8]) -> bool, step: &str, status: u32| {
            let mut line = Line::new();
            line.text(name).text(" failed: ").text(step).text("\n");
            write(line.bytes());
            status
        };
        let held = if top_up == 0 {
            None
        } else {
            match create(top_up, DwMemoryObjectCreateFlags(0)) {
                Ok(object) => Some(object),
                Err(status) => {
                    return failed(write, "top-up", ProbeSite::MeasureTopUp.with(status));
                }
            }
        };
        let status = match eager_once(region, MEASURED_MIB * MIB) {
            Ok(times) => {
                write(timed_line(name, MEASURED_MIB, times).bytes());
                0
            }
            Err((step, status)) => failed(write, step, status),
        };
        if let Some(object) = held {
            let closed = deepwyrm_syscall::handle_close(object);
            if closed != DW_STATUS_SUCCESS {
                return failed(
                    write,
                    "top-up close",
                    ProbeSite::MeasureTopUpClose.with(closed),
                );
            }
        }
        if status == 0 {
            let mut line = Line::new();
            line.text(name).text(" ok\n");
            write(line.bytes());
        }
        status
    }

    /// A channel nothing is ever sent on, to wait on with a deadline.
    struct Sleeper {
        receiver: DwHandle,
    }

    impl Sleeper {
        fn new() -> Result<Self, DwStatus> {
            let (mut sender, mut receiver) = (DwHandle(0), DwHandle(0));
            // The sender stays open, so the receiver never becomes readable.
            checked(deepwyrm_syscall::channel_create(
                DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0),
                &mut sender,
                &mut receiver,
            ))
            .map(|()| Self { receiver })
        }

        /// Waits about `us` microseconds of active time.
        fn sleep(&self, us: u64) {
            let mut now = 0;
            deepwyrm_syscall::clock_get(DW_CLOCK_MONOTONIC_ACTIVE.0, &mut now);
            let mut result = DwWaitResultV1::default();
            deepwyrm_syscall::wait_one(
                self.receiver,
                DW_SIGNAL_READABLE,
                DwDeadline(now.saturating_add(us * 1000)),
                &mut result,
            );
        }

        /// Waits forever; if the wait ever returns, the job status that
        /// says so, with the wait's status.
        fn forever(&self) -> u32 {
            let mut result = DwWaitResultV1::default();
            let status = deepwyrm_syscall::wait_one(
                self.receiver,
                DW_SIGNAL_READABLE,
                DW_DEADLINE_INFINITE,
                &mut result,
            );
            ProbeSite::WaitEnded.with(status)
        }
    }

    /// `hold-*`'s wait that never ends.
    fn wait_forever() -> u32 {
        Sleeper::new().map_or_else(
            |status| ProbeSite::HoldSleeper.with(status),
            |sleeper| sleeper.forever(),
        )
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
    use wyrmroot_hello::ProbeSite;

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
    /// the probe's mapping at `base`, which ends the job. A [`ProbeSite`]
    /// failure if the object could not be made or the commit was not
    /// refused.
    pub(super) fn exhaust(base: u64, budget: u64) -> u32 {
        let Some(size) = budget.checked_mul(4) else {
            return ProbeSite::ExhaustSize.alone();
        };
        let mut object = DwHandle(0);
        let status = deepwyrm_syscall::memory_object_create(
            DwSize(size),
            DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND,
            // Commit needs MAP.
            DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0),
            &mut object,
        );
        if status != DW_STATUS_SUCCESS {
            return ProbeSite::ExhaustCreate.with(status);
        }
        let status = deepwyrm_syscall::memory_object_commit(object, DwOffset(0), DwSize(size));
        if status != DW_STATUS_NO_RESOURCES {
            return ProbeSite::ExhaustCommit.with(status);
        }
        touch(base + 50 * MIB);
        1
    }

    /// The probe; with `keep`, the mapping is left for [`exhaust`]. Its
    /// base, or the line naming the step that failed and the job status
    /// that says so.
    pub(super) fn probe(region: DwHandle, keep: bool) -> Result<u64, (&'static [u8], u32)> {
        let size = SIZE;
        let mut object = DwHandle(0);
        let rights =
            DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0 | DW_RIGHT_INSPECT.0);
        let status = deepwyrm_syscall::memory_object_create(
            DwSize(size),
            DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND,
            rights,
            &mut object,
        );
        if status != DW_STATUS_SUCCESS {
            return Err((
                b"on-demand failed: create\n",
                ProbeSite::OnDemandCreate.with(status),
            ));
        }
        let mut info = DwMemoryObjectInfoV1::default();
        let mut required = 0;
        let status =
            deepwyrm_syscall::object_get_memory_object_info_v1(object, &mut info, &mut required);
        if status != DW_STATUS_SUCCESS
            || info.flags != DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND
            || info.byte_size != size
        {
            return Err((
                b"on-demand failed: info\n",
                ProbeSite::OnDemandInfo.with(status),
            ));
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
        let status = deepwyrm_syscall::address_region_map(region, object, &args, &mut at);
        if status != DW_STATUS_SUCCESS {
            return Err((
                b"on-demand failed: map\n",
                ProbeSite::OnDemandMap.with(status),
            ));
        }
        let base = at.0;
        // A read fault, then writes past the first 16 MiB and at the end.
        if read(base) != 0 {
            return Err((
                b"on-demand failed: first read\n",
                ProbeSite::OnDemandFirstRead.alone(),
            ));
        }
        write(base + 40 * MIB + 8, MARK);
        write(base + size - 8, !MARK);
        if read(base + 40 * MIB + 8) != MARK
            || read(base + size - 8) != !MARK
            || read(base + 40 * MIB + 4096) != 0
            || read(base + 8) != 0
        {
            return Err((
                b"on-demand failed: touch\n",
                ProbeSite::OnDemandTouch.alone(),
            ));
        }
        // A syscall writes into a page nothing has touched.
        let out = base + 20 * MIB;
        // SAFETY: an aligned word of the probe's own read-write mapping.
        let nanoseconds = unsafe { &mut *(out as *mut u64) };
        let status = deepwyrm_syscall::clock_get(DW_CLOCK_MONOTONIC_ACTIVE.0, nanoseconds);
        if status != DW_STATUS_SUCCESS || read(out) == 0 {
            return Err((
                b"on-demand failed: fill-in\n",
                ProbeSite::OnDemandFillIn.with(status),
            ));
        }
        let status =
            deepwyrm_syscall::memory_object_commit(object, DwOffset(30 * MIB), DwSize(4096));
        if status != DW_STATUS_SUCCESS || read(base + 30 * MIB) != 0 {
            return Err((
                b"on-demand failed: commit\n",
                ProbeSite::OnDemandCommit.with(status),
            ));
        }
        // A syscall reads from a page nothing has touched: the kernel fills
        // it in for the read, and what it reads is zeros.
        let input = base + 25 * MIB;
        let (mut sender, mut receiver) = (DwHandle(0), DwHandle(0));
        let status = deepwyrm_syscall::channel_create(
            DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0),
            &mut sender,
            &mut receiver,
        );
        if status != DW_STATUS_SUCCESS {
            return Err((
                b"on-demand failed: channel\n",
                ProbeSite::OnDemandChannel.with(status),
            ));
        }
        // SAFETY: 64 bytes of the probe's own mapping, never written.
        let untouched = unsafe { core::slice::from_raw_parts(input as *const u8, 64) };
        let mut received = [0xff_u8; 64];
        let mut result = DwChannelReceiveResultV1::default();
        let sent = deepwyrm_syscall::channel_send(sender, untouched, &[], 0);
        let got = deepwyrm_syscall::channel_receive(receiver, &mut received, &mut [], &mut result);
        // The receiver is closed only if the sender was, as before.
        let closed_sender = deepwyrm_syscall::handle_close(sender);
        let closed_receiver = if closed_sender == DW_STATUS_SUCCESS {
            deepwyrm_syscall::handle_close(receiver)
        } else {
            DW_STATUS_SUCCESS
        };
        let read_fill_in = b"on-demand failed: read fill-in\n";
        for (status, site) in [
            (sent, ProbeSite::OnDemandSend),
            (got, ProbeSite::OnDemandReceive),
            (closed_sender, ProbeSite::OnDemandCloseSender),
            (closed_receiver, ProbeSite::OnDemandCloseReceiver),
        ] {
            if status != DW_STATUS_SUCCESS {
                return Err((read_fill_in, site.with(status)));
            }
        }
        if received.iter().any(|byte| *byte != 0) || read(input) != 0 {
            return Err((read_fill_in, ProbeSite::OnDemandReadFillIn.alone()));
        }
        if keep {
            return Ok(base);
        }
        let status = deepwyrm_syscall::address_region_unmap(region, at, DwSize(size));
        if status != DW_STATUS_SUCCESS {
            return Err((
                b"on-demand failed: teardown\n",
                ProbeSite::OnDemandUnmap.with(status),
            ));
        }
        let status = deepwyrm_syscall::handle_close(object);
        if status != DW_STATUS_SUCCESS {
            return Err((
                b"on-demand failed: teardown\n",
                ProbeSite::OnDemandClose.with(status),
            ));
        }
        Ok(base)
    }
}
wyrmroot_runtime::native_entry!(crate::hello_main);
#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    panic_abort()
}
