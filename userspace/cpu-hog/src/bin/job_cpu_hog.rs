#![no_std]
#![no_main]
#![deny(unsafe_code)]

use core::panic::PanicInfo;

use deepwyrm_syscall::{DwHandle, DwObjectType, DwReceivedHandleInfoV1, DwRights, DwSignals};
use wyrmroot_cpu_hog::{
    JobActorSystem, WITNESS_BYTES, WITNESS_MXCSR, WitnessFailure, fs_anchor_value,
    is_initial_state, prepare_job_cpu_hog, validate_job_cpu_hog_entry, witness_pattern,
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
    // Read before the hog changes anything: a Thread that has never run
    // must hold the initial MXCSR and x87 control word, not what the
    // previous Thread on this CPU left.
    let (initial_mxcsr, initial_fcw) = registers::controls();
    let mut system = NativeSystem;
    let seed = match prepare_job_cpu_hog(&mut system, startup.bootstrap_channel().as_abi()) {
        Ok(seed) => seed,
        Err(error) => return error.exit_code(),
    };
    if !is_initial_state(initial_mxcsr, initial_fcw) {
        return WitnessFailure::InitialState.exit_code();
    }
    let anchor = fs_anchor_value(seed);
    let anchor_address = core::ptr::from_ref(&anchor) as u64;
    if deepwyrm_syscall::thread_set_fs_base(anchor_address) != deepwyrm_syscall::DW_STATUS_SUCCESS {
        return WitnessFailure::SetFsBase.exit_code();
    }
    let pattern = witness_pattern(seed);
    match registers::hold_and_spin(&pattern, WITNESS_MXCSR, core::hint::black_box(anchor)) {
        registers::Lost::FpState => WitnessFailure::FpState.exit_code(),
        registers::Lost::FsBase => WitnessFailure::FsBase.exit_code(),
    }
}

/// The FP-register code. Compiled Rust may use XMM registers, so the hog
/// holds its pattern only inside one asm block that loads XMM0-15 and MXCSR,
/// then spins checking them and the word at its FS base, and leaves only when
/// one changed. It never yields, blocks or makes a syscall in that loop.
#[allow(
    unsafe_code,
    reason = "loads and checks XMM0-15, MXCSR and the word at the FS base, and reads the x87 control word"
)]
mod registers {
    use super::WITNESS_BYTES;

    pub(super) enum Lost {
        FpState,
        FsBase,
    }

    #[repr(C, align(16))]
    struct Image([u8; WITNESS_BYTES + 16]);

    pub(super) fn controls() -> (u32, u16) {
        let mut mxcsr = 0u32;
        let mut fcw = 0u16;
        // SAFETY: the two stores target the two locals.
        unsafe {
            core::arch::asm!(
                "stmxcsr dword ptr [{m}]",
                "fnstcw word ptr [{f}]",
                m = in(reg) &raw mut mxcsr,
                f = in(reg) &raw mut fcw,
                options(nostack, preserves_flags)
            );
        }
        (mxcsr, fcw)
    }

    pub(super) fn hold_and_spin(pattern: &[u8; WITNESS_BYTES], mxcsr: u32, anchor: u64) -> Lost {
        let source = Image({
            let mut bytes = [0u8; WITNESS_BYTES + 16];
            bytes[..WITNESS_BYTES].copy_from_slice(pattern);
            bytes[WITNESS_BYTES..WITNESS_BYTES + 4].copy_from_slice(&mxcsr.to_le_bytes());
            bytes
        });
        let mut scratch = Image([0; WITNESS_BYTES + 16]);
        let lost: u64;
        // SAFETY: the block reads `source` and writes `scratch`, both 16-byte aligned and
        // WITNESS_BYTES + 16 long; MXCSR comes from `mxcsr`, whose reserved bits are clear; the FS
        // base is the address of the caller's live anchor. It declares every XMM register it
        // loads, and leaves MXCSR as the hog's pattern, which only the exit path runs under.
        unsafe {
            core::arch::asm!(
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
                "xor {i:e}, {i:e}",
                "3:",
                "mov {t}, qword ptr [{scr} + {i}]",
                "cmp {t}, qword ptr [{src} + {i}]",
                "jne 4f",
                "add {i}, 8",
                "cmp {i}, 264",
                "jb 3b",
                "mov {t}, qword ptr fs:[0]",
                "cmp {t}, {anchor}",
                "jne 5f",
                "pause",
                "jmp 2b",
                "4:",
                "mov {lost:e}, 1",
                "jmp 6f",
                "5:",
                "mov {lost:e}, 2",
                "6:",
                src = in(reg) source.0.as_ptr(),
                scr = in(reg) scratch.0.as_mut_ptr(),
                anchor = in(reg) anchor,
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
        if lost == 2 {
            Lost::FsBase
        } else {
            Lost::FpState
        }
    }
}

wyrmroot_runtime::native_entry!(crate::job_cpu_hog_main);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    panic_abort()
}
