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
    // Read before anything else: a Thread that has never run must hold the
    // initial FP state, not what the previous Thread on this CPU left.
    let (initial_xmm, initial_mxcsr, initial_fcw) = registers::read();
    let mut system = NativeSystem;
    let seed = match prepare_job_cpu_hog(&mut system, startup.bootstrap_channel().as_abi()) {
        Ok(seed) => seed,
        Err(error) => return error.exit_code(),
    };
    if !is_initial_state(&initial_xmm, initial_mxcsr, initial_fcw) {
        return WitnessFailure::InitialState.exit_code();
    }
    match hold_and_spin(seed) {
        Err(failure) => failure.exit_code(),
    }
}

/// Holds this launch's pattern in XMM0-15, MXCSR and FS, and spins checking
/// them; never yields, blocks or makes a syscall once the pattern is held.
fn hold_and_spin(seed: u64) -> Result<core::convert::Infallible, WitnessFailure> {
    let anchor = fs_anchor_value(seed);
    let anchor_address = core::ptr::from_ref(&anchor) as u64;
    if deepwyrm_syscall::thread_set_fs_base(anchor_address) != deepwyrm_syscall::DW_STATUS_SUCCESS {
        return Err(WitnessFailure::SetFsBase);
    }
    let pattern = witness_pattern(seed);
    registers::load(&pattern, WITNESS_MXCSR);
    loop {
        let (xmm, mxcsr, _) = registers::read();
        if xmm != pattern || mxcsr != WITNESS_MXCSR {
            return Err(WitnessFailure::FpState);
        }
        if registers::fs_word() != core::hint::black_box(anchor) {
            return Err(WitnessFailure::FsBase);
        }
        core::hint::spin_loop();
    }
}

/// The only code that touches FP registers. The guest target is soft-float,
/// so compiled Rust never reads or writes XMM, MXCSR or x87 state, and what
/// this module loads stays put between its calls unless the kernel loses it.
#[allow(
    unsafe_code,
    reason = "reads and loads XMM0-15, MXCSR and the x87 control word, and reads the word at the FS base"
)]
mod registers {
    use super::WITNESS_BYTES;

    #[repr(C, align(16))]
    struct Image([u8; WITNESS_BYTES]);

    pub(super) fn read() -> ([u8; WITNESS_BYTES], u32, u16) {
        let mut image = Image([0; WITNESS_BYTES]);
        let mut mxcsr = 0u32;
        let mut fcw = 0u16;
        // SAFETY: every store targets the 256-byte, 16-byte-aligned `image` or the two locals.
        unsafe {
            core::arch::asm!(
                "movdqa xmmword ptr [{p} + 0], xmm0",
                "movdqa xmmword ptr [{p} + 16], xmm1",
                "movdqa xmmword ptr [{p} + 32], xmm2",
                "movdqa xmmword ptr [{p} + 48], xmm3",
                "movdqa xmmword ptr [{p} + 64], xmm4",
                "movdqa xmmword ptr [{p} + 80], xmm5",
                "movdqa xmmword ptr [{p} + 96], xmm6",
                "movdqa xmmword ptr [{p} + 112], xmm7",
                "movdqa xmmword ptr [{p} + 128], xmm8",
                "movdqa xmmword ptr [{p} + 144], xmm9",
                "movdqa xmmword ptr [{p} + 160], xmm10",
                "movdqa xmmword ptr [{p} + 176], xmm11",
                "movdqa xmmword ptr [{p} + 192], xmm12",
                "movdqa xmmword ptr [{p} + 208], xmm13",
                "movdqa xmmword ptr [{p} + 224], xmm14",
                "movdqa xmmword ptr [{p} + 240], xmm15",
                "stmxcsr dword ptr [{m}]",
                "fnstcw word ptr [{f}]",
                p = in(reg) image.0.as_mut_ptr(),
                m = in(reg) &raw mut mxcsr,
                f = in(reg) &raw mut fcw,
                options(nostack, preserves_flags)
            );
        }
        (image.0, mxcsr, fcw)
    }

    pub(super) fn load(pattern: &[u8; WITNESS_BYTES], mxcsr: u32) {
        let image = Image(*pattern);
        // SAFETY: every load reads the 256-byte, 16-byte-aligned `image` or `mxcsr`, whose
        // reserved bits are clear.
        unsafe {
            core::arch::asm!(
                "movdqa xmm0, xmmword ptr [{p} + 0]",
                "movdqa xmm1, xmmword ptr [{p} + 16]",
                "movdqa xmm2, xmmword ptr [{p} + 32]",
                "movdqa xmm3, xmmword ptr [{p} + 48]",
                "movdqa xmm4, xmmword ptr [{p} + 64]",
                "movdqa xmm5, xmmword ptr [{p} + 80]",
                "movdqa xmm6, xmmword ptr [{p} + 96]",
                "movdqa xmm7, xmmword ptr [{p} + 112]",
                "movdqa xmm8, xmmword ptr [{p} + 128]",
                "movdqa xmm9, xmmword ptr [{p} + 144]",
                "movdqa xmm10, xmmword ptr [{p} + 160]",
                "movdqa xmm11, xmmword ptr [{p} + 176]",
                "movdqa xmm12, xmmword ptr [{p} + 192]",
                "movdqa xmm13, xmmword ptr [{p} + 208]",
                "movdqa xmm14, xmmword ptr [{p} + 224]",
                "movdqa xmm15, xmmword ptr [{p} + 240]",
                "ldmxcsr dword ptr [{m}]",
                p = in(reg) image.0.as_ptr(),
                m = in(reg) &raw const mxcsr,
                options(nostack, preserves_flags, readonly)
            );
        }
    }

    /// The word at the FS base.
    pub(super) fn fs_word() -> u64 {
        let value: u64;
        // SAFETY: the FS base is the address of the caller's live anchor, set by
        // `thread_set_fs_base`; the kernel keeps it with this Thread.
        unsafe {
            core::arch::asm!(
                "mov {}, qword ptr fs:[0]",
                out(reg) value,
                options(nostack, preserves_flags, readonly)
            );
        }
        value
    }
}

wyrmroot_runtime::native_entry!(crate::job_cpu_hog_main);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    panic_abort()
}
