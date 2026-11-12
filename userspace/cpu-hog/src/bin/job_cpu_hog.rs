#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use deepwyrm_syscall::{DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights, DwSignals};
use wyrmroot_cpu_hog::{
    JobActorSystem, WITNESS_BYTES, WITNESS_MXCSR, WitnessFailure, fs_anchor_value,
    is_initial_entry_state, prepare_job_cpu_hog, validate_job_cpu_hog_auxv,
    validate_job_cpu_hog_entry, witness_pattern, witness_selectors,
};
use wyrmroot_loader as _;
use wyrmroot_runtime::{
    CapabilityInfo, NativeError, ReceiveCounts, StartupBlock, close_handle, panic_abort,
    query_capability_info, receive_channel, send_channel, wait_one,
};

struct NativeSystem;

impl JobActorSystem for NativeSystem {
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

    fn wait_channel(
        &mut self,
        channel: DwHandle,
        signals: DwSignals,
    ) -> Result<DwSignals, NativeError> {
        wait_one(channel, signals, deepwyrm_syscall::DW_DEADLINE_INFINITE)
            .map(|result| result.observed)
    }

    fn close_handle(&mut self, handle: DwHandle) -> Result<(), NativeError> {
        close_handle(handle)
    }
}

fn job_cpu_hog_main(startup: StartupBlock<'_>) -> u32 {
    if let Err(error) = validate_job_cpu_hog_entry(
        startup.version(),
        startup.argc(),
        startup.arg(0).map(|argument| argument.as_str()),
        startup.envc(),
    ) {
        return error.exit_code();
    }
    #[allow(
        unsafe_code,
        reason = "names the entry shim's own `_start` only to take its address; it is never called"
    )]
    unsafe extern "C" {
        fn _start();
    }
    if let Err(error) = validate_job_cpu_hog_auxv(
        (0..startup.auxc()).filter_map(|index| startup.aux(index)),
        _start as unsafe extern "C" fn() as usize as u64,
    ) {
        return error.exit_code();
    }
    let mut system = NativeSystem;
    let seed = match prepare_job_cpu_hog(&mut system, startup.bootstrap_channel().as_abi()) {
        Ok(seed) => seed,
        Err(error) => return error.exit_code(),
    };
    // `_start` captured these before any compiled code ran: a Thread that has never run must
    // hold the initial FP state and null selectors, not what the previous Thread on this CPU
    // left.
    let (fxsave, selectors) = registers::entry_state();
    if !is_initial_entry_state(&fxsave, selectors) {
        return WitnessFailure::InitialState.exit_code();
    }
    let anchor = fs_anchor_value(seed);
    let anchor_address = core::ptr::from_ref(&anchor) as u64;
    if deepwyrm_syscall::thread_set_fs_base(anchor_address) != deepwyrm_syscall::DW_STATUS_SUCCESS {
        return WitnessFailure::SetFsBase.exit_code();
    }
    let pattern = witness_pattern(seed);
    let held = witness_selectors(seed);
    match registers::hold_and_spin(&pattern, WITNESS_MXCSR, held, core::hint::black_box(anchor)) {
        registers::Lost::FpState => WitnessFailure::FpState.exit_code(),
        registers::Lost::FsBase => WitnessFailure::FsBase.exit_code(),
        registers::Lost::Selectors => WitnessFailure::Selectors.exit_code(),
    }
}

/// What `_start` stores before any compiled code runs: an FXSAVE image, then
/// DS, ES, FS and GS. Only `_start` writes it, once.
#[allow(
    unsafe_code,
    reason = "the entry prologue stores into this static by symbol name"
)]
mod entry_capture {
    #[repr(C, align(16))]
    pub(super) struct EntryState(pub(super) [u8; 528]);

    #[unsafe(no_mangle)]
    pub(super) static mut WYRMROOT_CPU_HOG_ENTRY_STATE: EntryState = EntryState([0; 528]);
}

/// The register code. Compiled Rust may use XMM registers, so the hog holds
/// its pattern only inside one asm block that loads XMM0-15, MXCSR and the
/// DS, ES and GS selectors, then spins checking them and the word at its FS
/// base, and leaves only when one changed. It never yields, blocks or makes a
/// syscall in that loop, and puts MXCSR and the selectors back on the way out.
#[allow(
    unsafe_code,
    reason = "loads and checks XMM0-15, MXCSR, DS/ES/GS and the word at the FS base, and reads the entry capture"
)]
mod registers {
    use super::WITNESS_BYTES;
    use wyrmroot_cpu_hog::FXSAVE_BYTES;

    pub(super) enum Lost {
        FpState,
        FsBase,
        Selectors,
    }

    /// XMM0-15 (0..256), MXCSR (256), DS/ES/GS (264..270), compared up to
    /// 272; the scratch copy keeps the original MXCSR at 272 and the original
    /// selectors at 276..282.
    #[repr(C, align(16))]
    struct Image([u8; WITNESS_BYTES + 32]);

    const COMPARED: usize = WITNESS_BYTES + 16;

    pub(super) fn entry_state() -> ([u8; FXSAVE_BYTES], [u16; 4]) {
        // SAFETY: only `_start` writes the static, before any Rust code runs, and this process
        // has one Thread, so a plain copy cannot race.
        let state = unsafe {
            core::ptr::read_volatile(&raw const super::entry_capture::WYRMROOT_CPU_HOG_ENTRY_STATE)
        };
        let mut fxsave = [0u8; FXSAVE_BYTES];
        fxsave.copy_from_slice(&state.0[..FXSAVE_BYTES]);
        let selector = |index: usize| {
            let at = FXSAVE_BYTES + 2 * index;
            u16::from_le_bytes([state.0[at], state.0[at + 1]])
        };
        (fxsave, [selector(0), selector(1), selector(2), selector(3)])
    }

    pub(super) fn hold_and_spin(
        pattern: &[u8; WITNESS_BYTES],
        mxcsr: u32,
        selectors: [u16; 3],
        anchor: u64,
    ) -> Lost {
        let source = Image({
            let mut bytes = [0u8; WITNESS_BYTES + 32];
            bytes[..WITNESS_BYTES].copy_from_slice(pattern);
            bytes[WITNESS_BYTES..WITNESS_BYTES + 4].copy_from_slice(&mxcsr.to_le_bytes());
            for (index, selector) in selectors.iter().enumerate() {
                let at = WITNESS_BYTES + 8 + 2 * index;
                bytes[at..at + 2].copy_from_slice(&selector.to_le_bytes());
            }
            bytes
        });
        let mut scratch = Image([0; WITNESS_BYTES + 32]);
        let lost: u64;
        // SAFETY: the block reads `source` and writes `scratch`, both 16-byte aligned and
        // WITNESS_BYTES + 32 long; MXCSR comes from `mxcsr`, whose reserved bits are clear; the
        // selectors come from `LOADABLE_SELECTORS`, which CPL3 may load into DS, ES and GS, and
        // GS's base stays zero either way; the FS base is the address of the caller's live
        // anchor. It declares every XMM register it loads and restores MXCSR, DS, ES and GS
        // before it leaves.
        unsafe {
            core::arch::asm!(
                "stmxcsr dword ptr [{scr} + 272]",
                "mov word ptr [{scr} + 276], ds",
                "mov word ptr [{scr} + 278], es",
                "mov word ptr [{scr} + 280], gs",
                "movdqa xmm0, xmmword ptr [{src} + 0]",
                "movdqa xmm1, xmmword ptr [{src} + 16]",
                "movdqa xmm2, xmmword ptr [{src} + 32]",
                "movdqa xmm3, xmmword ptr [{src} + 48]",
                "movdqa xmm4, xmmword ptr [{src} + 64]",
                "movdqa xmm5, xmmword ptr [{src} + 80]",
                "movdqa xmm6, xmmword ptr [{src} + 96]",
                "movdqa xmm7, xmmword ptr [{src} + 112]",
                "movdqa xmm8, xmmword ptr [{src} + 128]",
                "movdqa xmm9, xmmword ptr [{src} + 144]",
                "movdqa xmm10, xmmword ptr [{src} + 160]",
                "movdqa xmm11, xmmword ptr [{src} + 176]",
                "movdqa xmm12, xmmword ptr [{src} + 192]",
                "movdqa xmm13, xmmword ptr [{src} + 208]",
                "movdqa xmm14, xmmword ptr [{src} + 224]",
                "movdqa xmm15, xmmword ptr [{src} + 240]",
                "ldmxcsr dword ptr [{src} + 256]",
                "mov ds, word ptr [{src} + 264]",
                "mov es, word ptr [{src} + 266]",
                "mov gs, word ptr [{src} + 268]",
                "2:",
                "movdqa xmmword ptr [{scr} + 0], xmm0",
                "movdqa xmmword ptr [{scr} + 16], xmm1",
                "movdqa xmmword ptr [{scr} + 32], xmm2",
                "movdqa xmmword ptr [{scr} + 48], xmm3",
                "movdqa xmmword ptr [{scr} + 64], xmm4",
                "movdqa xmmword ptr [{scr} + 80], xmm5",
                "movdqa xmmword ptr [{scr} + 96], xmm6",
                "movdqa xmmword ptr [{scr} + 112], xmm7",
                "movdqa xmmword ptr [{scr} + 128], xmm8",
                "movdqa xmmword ptr [{scr} + 144], xmm9",
                "movdqa xmmword ptr [{scr} + 160], xmm10",
                "movdqa xmmword ptr [{scr} + 176], xmm11",
                "movdqa xmmword ptr [{scr} + 192], xmm12",
                "movdqa xmmword ptr [{scr} + 208], xmm13",
                "movdqa xmmword ptr [{scr} + 224], xmm14",
                "movdqa xmmword ptr [{scr} + 240], xmm15",
                "stmxcsr dword ptr [{scr} + 256]",
                "mov word ptr [{scr} + 264], ds",
                "mov word ptr [{scr} + 266], es",
                "mov word ptr [{scr} + 268], gs",
                "xor {i:e}, {i:e}",
                "3:",
                "mov {t}, qword ptr [{scr} + {i}]",
                "cmp {t}, qword ptr [{src} + {i}]",
                "jne 4f",
                "add {i}, 8",
                "cmp {i}, {compared}",
                "jb 3b",
                "mov {t}, qword ptr fs:[0]",
                "cmp {t}, {anchor}",
                "jne 5f",
                "pause",
                "jmp 2b",
                "4:",
                "mov {lost:e}, 1",
                "cmp {i}, {selectors_at}",
                "jb 6f",
                "mov {lost:e}, 3",
                "jmp 6f",
                "5:",
                "mov {lost:e}, 2",
                "6:",
                "ldmxcsr dword ptr [{scr} + 272]",
                "mov ds, word ptr [{scr} + 276]",
                "mov es, word ptr [{scr} + 278]",
                "mov gs, word ptr [{scr} + 280]",
                src = in(reg) source.0.as_ptr(),
                scr = in(reg) scratch.0.as_mut_ptr(),
                anchor = in(reg) anchor,
                compared = const COMPARED,
                selectors_at = const WITNESS_BYTES + 8,
                i = out(reg) _,
                t = out(reg) _,
                lost = out(reg) lost,
                out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
                out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
                options(nostack)
            );
        }
        match lost {
            2 => Lost::FsBase,
            3 => Lost::Selectors,
            _ => Lost::FpState,
        }
    }
}

wyrmroot_runtime::native_entry!(
    crate::job_cpu_hog_main,
    prologue = "
        fxsave64 WYRMROOT_CPU_HOG_ENTRY_STATE(%rip)
        movw %ds, WYRMROOT_CPU_HOG_ENTRY_STATE+512(%rip)
        movw %es, WYRMROOT_CPU_HOG_ENTRY_STATE+514(%rip)
        movw %fs, WYRMROOT_CPU_HOG_ENTRY_STATE+516(%rip)
        movw %gs, WYRMROOT_CPU_HOG_ENTRY_STATE+518(%rip)
    "
);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    panic_abort()
}
