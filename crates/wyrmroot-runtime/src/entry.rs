//! Native process-entry support shared by every freestanding Wyrmroot executable.

/// Defines the WYR0 native `_start` shim for one freestanding executable.
///
/// The supplied function receives a fully validated startup block and returns the process exit
/// code. This macro deliberately owns the only assembly and raw startup-page boundary needed by
/// ordinary Wyrmroot executables.
#[macro_export]
macro_rules! native_entry {
    ($handler:path) => {
        #[allow(
            unsafe_code,
            reason = "the shared Wyrmroot entry shim captures the kernel-supplied initial stack pointer and crosses the runtime's documented startup-page boundary"
        )]
        mod __wyrmroot_native_entry {
            use core::arch::global_asm;

            global_asm!(
                r#"
                .section .text._start,"ax",@progbits
                .global _start
                .type _start,@function
            _start:
                movq %rsp, %rdx
                xorq %rbp, %rbp
                andq $-16, %rsp
                call __wyrmroot_native_main
                ud2
                .size _start, .-_start
                "#,
                options(att_syntax)
            );

            #[unsafe(no_mangle)]
            extern "C" fn __wyrmroot_native_main(
                startup_argument0: u64,
                startup_argument1: u64,
                startup_address: u64,
            ) -> ! {
                let registers = $crate::StartupRegisters {
                    startup_argument0,
                    startup_argument1,
                };
                // SAFETY: `_start` passes the unmodified initial RSP supplied by Deepwyrm. The
                // startup ABI guarantees that it names the immutable, readable 4 KiB block.
                let exit_code = match unsafe {
                    $crate::with_native_startup(registers, startup_address, $handler)
                } {
                    Ok(exit_code) => exit_code,
                    Err(error) => $crate::startup_error_exit_code(error),
                };
                $crate::exit_process(exit_code)
            }
        }
    };
}
