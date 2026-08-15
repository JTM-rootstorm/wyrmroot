//! Narrow x86_64 post-`ExitBootServices` diagnostic and raw transfer boundary.
//!
//! Keep this module owned by the firmware binary, not the safe loader library. Host builds expose
//! only validation and diagnostic sequencing; privileged register inspection, COM1 port I/O, CR3
//! replacement, and the nonreturning jump exist only for the x86_64 UEFI target.

#[cfg(test)]
use crate::transition::{AllocationLifetime, TransitionPlan};
#[cfg(not(test))]
use wyrmroot_efi_loader::transition::{AllocationLifetime, TransitionPlan};

/// Evidence collected immediately before the raw transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X86_64EntryStateEvidence {
    pub exit_boot_services_complete: bool,
    pub cr0_write_protect: bool,
    pub execute_disable: bool,
    pub four_level_paging: bool,
    pub initial_processor_is_bsp: bool,
    /// UEFI x64 segment selectors were observed nonzero; descriptor semantics remain a firmware
    /// ABI precondition documented at the privileged boundary.
    pub valid_code_and_stack_segments: bool,
}

/// Checked entry-state token required by the raw transfer function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedX86_64EntryState {
    _private: (),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X86_64HandoffError {
    BootServicesStillAvailable,
    WriteProtectDisabled,
    ExecuteDisableUnavailable,
    WrongPagingMode,
    NotBootstrapProcessor,
    InvalidSegmentState,
    InvalidPageTableRoot,
    PageTableRootOutsidePreExitStorage,
    InvalidKernelEntry,
    InvalidBootInfoPointer,
    InvalidTransitionStack,
    InvalidHandoffStub,
}

/// Validate the machine-state facts that cannot be repaired by the final three-instruction seam.
pub fn verify_x86_64_entry_state(
    evidence: X86_64EntryStateEvidence,
) -> Result<VerifiedX86_64EntryState, X86_64HandoffError> {
    if !evidence.exit_boot_services_complete {
        return Err(X86_64HandoffError::BootServicesStillAvailable);
    }
    if !evidence.cr0_write_protect {
        return Err(X86_64HandoffError::WriteProtectDisabled);
    }
    if !evidence.execute_disable {
        return Err(X86_64HandoffError::ExecuteDisableUnavailable);
    }
    if !evidence.four_level_paging {
        return Err(X86_64HandoffError::WrongPagingMode);
    }
    if !evidence.initial_processor_is_bsp {
        return Err(X86_64HandoffError::NotBootstrapProcessor);
    }
    if !evidence.valid_code_and_stack_segments {
        return Err(X86_64HandoffError::InvalidSegmentState);
    }
    Ok(VerifiedX86_64EntryState { _private: () })
}

/// Fully checked register values for the nonreturning x86_64 transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X86_64Transfer {
    kernel_entry: u64,
    boot_info_identity_pointer: u64,
    transition_stack_pointer: u64,
    page_table_root_physical: u64,
    handoff_stub_start: u64,
    handoff_stub_end: u64,
    entry_state: VerifiedX86_64EntryState,
}

impl X86_64Transfer {
    pub fn kernel_entry(&self) -> u64 {
        self.kernel_entry
    }

    pub fn boot_info_identity_pointer(&self) -> u64 {
        self.boot_info_identity_pointer
    }

    pub fn transition_stack_pointer(&self) -> u64 {
        self.transition_stack_pointer
    }

    pub fn page_table_root_physical(&self) -> u64 {
        self.page_table_root_physical
    }

    pub fn handoff_stub_range(&self) -> (u64, u64) {
        (self.handoff_stub_start, self.handoff_stub_end)
    }
}

/// Bind a validated mapping plan, preallocated page-table root, and verified machine state.
pub fn prepare_x86_64_transfer(
    plan: &TransitionPlan<'_>,
    page_table_root_physical: u64,
    entry_state: VerifiedX86_64EntryState,
) -> Result<X86_64Transfer, X86_64HandoffError> {
    if plan.kernel_entry() == 0 {
        return Err(X86_64HandoffError::InvalidKernelEntry);
    }
    if plan.boot_info_identity_pointer() == 0 {
        return Err(X86_64HandoffError::InvalidBootInfoPointer);
    }
    if plan.transition_stack_pointer() == 0
        || !plan
            .transition_stack_pointer()
            .is_multiple_of(plan.stack_pointer_alignment())
    {
        return Err(X86_64HandoffError::InvalidTransitionStack);
    }
    if page_table_root_physical == 0
        || !page_table_root_physical.is_multiple_of(plan.mapping_granule())
    {
        return Err(X86_64HandoffError::InvalidPageTableRoot);
    }
    let storage = plan.pre_exit().page_table_storage;
    if storage.lifetime != AllocationLifetime::RetainedUntilKernelPageTableReplacement {
        return Err(X86_64HandoffError::PageTableRootOutsidePreExitStorage);
    }
    let storage_end = storage
        .physical_start
        .checked_add(storage.byte_len)
        .ok_or(X86_64HandoffError::PageTableRootOutsidePreExitStorage)?;
    let root_end = page_table_root_physical
        .checked_add(plan.mapping_granule())
        .ok_or(X86_64HandoffError::PageTableRootOutsidePreExitStorage)?;
    if page_table_root_physical < storage.physical_start || root_end > storage_end {
        return Err(X86_64HandoffError::PageTableRootOutsidePreExitStorage);
    }

    let handoff_stub_start = plan.pre_exit().handoff_stub.physical_start;
    let handoff_stub_end = handoff_stub_start
        .checked_add(plan.pre_exit().handoff_stub.byte_len)
        .ok_or(X86_64HandoffError::InvalidHandoffStub)?;
    if plan.handoff_stub_entry() != handoff_stub_start || handoff_stub_start >= handoff_stub_end {
        return Err(X86_64HandoffError::InvalidHandoffStub);
    }

    Ok(X86_64Transfer {
        kernel_entry: plan.kernel_entry(),
        boot_info_identity_pointer: plan.boot_info_identity_pointer(),
        transition_stack_pointer: plan.transition_stack_pointer(),
        page_table_root_physical,
        handoff_stub_start,
        handoff_stub_end,
        entry_state,
    })
}

/// Required post-EBS/final-handoff diagnostics. This path must not call UEFI output services.
pub const FINAL_HANDOFF_MARKER: &[u8] = b"wyrmroot-loader: ExitBootServices complete\n\
wyrmroot-loader: entering Deepwyrm\n";

/// Bounded byte sink usable after firmware services are gone.
pub trait PostExitDiagnosticWriter {
    type Error;

    fn write_byte_bounded(&mut self, byte: u8, poll_limit: u32) -> Result<(), Self::Error>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum FinalDiagnosticError<Error> {
    ZeroPollLimit,
    Write(Error),
}

/// Emit the final marker without heap allocation or firmware services.
pub fn write_final_handoff_marker<Writer: PostExitDiagnosticWriter>(
    writer: &mut Writer,
    poll_limit: u32,
) -> Result<(), FinalDiagnosticError<Writer::Error>> {
    if poll_limit == 0 {
        return Err(FinalDiagnosticError::ZeroPollLimit);
    }
    for byte in FINAL_HANDOFF_MARKER {
        writer
            .write_byte_bounded(*byte, poll_limit)
            .map_err(FinalDiagnosticError::Write)?;
    }
    Ok(())
}

const COM1_DATA: u16 = 0x03f8;
const COM1_INTERRUPT_ENABLE: u16 = COM1_DATA + 1;
const COM1_FIFO_CONTROL: u16 = COM1_DATA + 2;
const COM1_LINE_CONTROL: u16 = COM1_DATA + 3;
const COM1_MODEM_CONTROL: u16 = COM1_DATA + 4;
const COM1_LINE_STATUS: u16 = COM1_DATA + 5;
const COM1_TRANSMIT_EMPTY: u8 = 0x20;
const COM1_LINE_ERROR_MASK: u8 = 0x1e;

/// Host-testable byte-I/O seam for programming the legacy COM1 UART.
pub trait Com1RegisterIo {
    type Error;

    fn read(&mut self, port: u16) -> Result<u8, Self::Error>;
    fn write(&mut self, port: u16, value: u8) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Com1InitializationError<Error> {
    ZeroPollLimit,
    RegisterIo(Error),
    ConfigurationMismatch {
        register: u16,
        expected: u8,
        observed: u8,
    },
    LineStatusFault(u8),
    TransmitTimeout,
}

/// Program COM1 for 115200 baud, eight data bits, no parity, one stop bit, and FIFO operation.
///
/// UART interrupt generation is disabled before DLAB is set. No loopback probe is used because a
/// platform may legitimately route COM1 to an external observer. Readiness polling is bounded and
/// line faults fail closed.
pub fn initialize_com1_registers<Io: Com1RegisterIo>(
    io: &mut Io,
    poll_limit: u32,
) -> Result<(), Com1InitializationError<Io::Error>> {
    if poll_limit == 0 {
        return Err(Com1InitializationError::ZeroPollLimit);
    }

    for (port, value) in [
        (COM1_INTERRUPT_ENABLE, 0x00),
        (COM1_LINE_CONTROL, 0x80),
        (COM1_DATA, 0x01),
        (COM1_INTERRUPT_ENABLE, 0x00),
        (COM1_LINE_CONTROL, 0x03),
        (COM1_FIFO_CONTROL, 0xc7),
        (COM1_MODEM_CONTROL, 0x03),
    ] {
        io.write(port, value)
            .map_err(Com1InitializationError::RegisterIo)?;
    }

    for (register, expected) in [(COM1_LINE_CONTROL, 0x03), (COM1_INTERRUPT_ENABLE, 0x00)] {
        let observed = io
            .read(register)
            .map_err(Com1InitializationError::RegisterIo)?;
        if observed != expected {
            return Err(Com1InitializationError::ConfigurationMismatch {
                register,
                expected,
                observed,
            });
        }
    }

    for _ in 0..poll_limit {
        let status = io
            .read(COM1_LINE_STATUS)
            .map_err(Com1InitializationError::RegisterIo)?;
        if status & COM1_LINE_ERROR_MASK != 0 {
            return Err(Com1InitializationError::LineStatusFault(status));
        }
        if status & COM1_TRANSMIT_EMPTY != 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(Com1InitializationError::TransmitTimeout)
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
mod privileged {
    use core::arch::{asm, global_asm, x86_64::__cpuid};

    use super::{
        Com1InitializationError, Com1RegisterIo, PostExitDiagnosticWriter,
        X86_64EntryStateEvidence, X86_64Transfer,
    };
    const IA32_EFER: u32 = 0xc000_0080;
    const IA32_APIC_BASE: u32 = 0x0000_001b;
    const CR0_WRITE_PROTECT: u64 = 1 << 16;
    const EFER_EXECUTE_DISABLE_ENABLE: u64 = 1 << 11;
    const CPUID_EXTENDED_FEATURES: u32 = 0x8000_0001;
    const CPUID_NX: u32 = 1 << 20;

    global_asm!(
        r#"
        .section .text$wyrmroot_handoff,"xr"
        .p2align 4
        .global __wyrmroot_handoff_start
        .global __wyrmroot_handoff_end
__wyrmroot_handoff_start:
        cli
        cld
        mov cr3, rdi
        mov rsp, rsi
        mov rdi, rcx
        xor rbp, rbp
        jmp rdx
__wyrmroot_handoff_end:
"#
    );

    unsafe extern "C" {
        static __wyrmroot_handoff_start: u8;
        static __wyrmroot_handoff_end: u8;
    }

    /// Exact linked byte range and entry address of the instruction sequence that replaces CR3.
    /// The firmware adapter must supply this exact range to `IdentityMapInputs::handoff_stub`.
    pub fn linked_handoff_stub() -> Result<(u64, u64, u64), super::X86_64HandoffError> {
        let start = core::ptr::addr_of!(__wyrmroot_handoff_start) as u64;
        let end = core::ptr::addr_of!(__wyrmroot_handoff_end) as u64;
        let byte_len = end
            .checked_sub(start)
            .filter(|length| *length != 0)
            .ok_or(super::X86_64HandoffError::InvalidHandoffStub)?;
        Ok((start, byte_len, start))
    }

    /// Capability token for direct COM1 port access after EBS.
    pub struct Com1Writer {
        _private: (),
    }

    impl Com1Writer {
        /// Program COM1 explicitly and return the initialized diagnostic capability.
        ///
        /// # Safety
        ///
        /// The caller must be executing at x86_64 firmware privilege with legacy COM1 I/O-port
        /// access permitted. No other component may concurrently program the UART.
        pub unsafe fn initialize(
            poll_limit: u32,
        ) -> Result<Self, Com1InitializationError<core::convert::Infallible>> {
            let mut io = DirectCom1Io;
            super::initialize_com1_registers(&mut io, poll_limit)?;
            Ok(Self { _private: () })
        }
    }

    struct DirectCom1Io;

    impl Com1RegisterIo for DirectCom1Io {
        type Error = core::convert::Infallible;

        fn read(&mut self, port: u16) -> Result<u8, Self::Error> {
            // SAFETY: `DirectCom1Io` is private and only instantiated by the unsafe initializer.
            Ok(unsafe { inb(port) })
        }

        fn write(&mut self, port: u16, value: u8) -> Result<(), Self::Error> {
            // SAFETY: `DirectCom1Io` is private and only instantiated by the unsafe initializer.
            unsafe { outb(port, value) };
            Ok(())
        }
    }

    impl PostExitDiagnosticWriter for Com1Writer {
        type Error = Com1WriteError;

        fn write_byte_bounded(&mut self, byte: u8, poll_limit: u32) -> Result<(), Self::Error> {
            for _ in 0..poll_limit {
                // SAFETY: `Com1Writer` can only be constructed under its port-access contract.
                let status = unsafe { inb(super::COM1_LINE_STATUS) };
                if status & super::COM1_LINE_ERROR_MASK != 0 {
                    return Err(Com1WriteError::LineStatusFault(status));
                }
                if status & super::COM1_TRANSMIT_EMPTY != 0 {
                    // SAFETY: the same capability contract covers the COM1 data port.
                    unsafe { outb(super::COM1_DATA, byte) };
                    return Ok(());
                }
                core::hint::spin_loop();
            }
            Err(Com1WriteError::TransmitTimeout)
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Com1WriteError {
        LineStatusFault(u8),
        TransmitTimeout,
    }

    /// Enable CR0.WP and EFER.NXE, then observe and validate all entry-state facts.
    ///
    /// # Safety
    ///
    /// Must execute in 64-bit firmware supervisor mode on the initial processor. `rdmsr` must be
    /// permitted and the architectural EFER/APIC-base MSRs must be available.
    pub unsafe fn enable_and_verify_entry_state(
        exit_boot_services_complete: bool,
    ) -> Result<super::VerifiedX86_64EntryState, super::X86_64HandoffError> {
        if !exit_boot_services_complete {
            return Err(super::X86_64HandoffError::BootServicesStillAvailable);
        }
        let maximum_extended_leaf = __cpuid(0x8000_0000).eax;
        if maximum_extended_leaf < CPUID_EXTENDED_FEATURES
            || __cpuid(CPUID_EXTENDED_FEATURES).edx & CPUID_NX == 0
        {
            return Err(super::X86_64HandoffError::ExecuteDisableUnavailable);
        }

        // SAFETY: the function contract grants supervisor register/MSR access. Read-modify-write
        // preserves all unrelated architectural bits, and the following observation reads back.
        unsafe {
            let cr0 = read_cr0();
            write_cr0(cr0 | CR0_WRITE_PROTECT);
            let efer = rdmsr(IA32_EFER);
            wrmsr(IA32_EFER, efer | EFER_EXECUTE_DISABLE_ENABLE);
        }

        // SAFETY: same privileged-mode and architectural-MSR contract as this function.
        let evidence = unsafe { observe_entry_state(exit_boot_services_complete) };
        super::verify_x86_64_entry_state(evidence)
    }

    unsafe fn observe_entry_state(exit_boot_services_complete: bool) -> X86_64EntryStateEvidence {
        // SAFETY: guaranteed by the caller's supervisor-mode contract.
        let cr0 = unsafe { read_cr0() };
        let cr4: u64;
        let code_segment: u16;
        let stack_segment: u16;
        unsafe {
            asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
            asm!("mov {0:x}, cs", out(reg) code_segment, options(nomem, nostack, preserves_flags));
            asm!("mov {0:x}, ss", out(reg) stack_segment, options(nomem, nostack, preserves_flags));
        }
        // SAFETY: EFER and APIC-base availability is part of the function contract.
        let efer = unsafe { rdmsr(IA32_EFER) };
        // SAFETY: same as above.
        let apic_base = unsafe { rdmsr(IA32_APIC_BASE) };

        X86_64EntryStateEvidence {
            exit_boot_services_complete,
            cr0_write_protect: cr0 & (1 << 16) != 0,
            execute_disable: efer & (1 << 11) != 0,
            four_level_paging: cr0 & (1 << 31) != 0
                && efer & (1 << 10) != 0
                && cr4 & (1 << 12) == 0,
            initial_processor_is_bsp: apic_base & (1 << 8) != 0,
            valid_code_and_stack_segments: code_segment != 0 && stack_segment != 0,
        }
    }

    /// Install the transition CR3, switch to the dedicated stack, and jump to Deepwyrm.
    ///
    /// IF and DF are cleared immediately before CR3 replacement. Only RDI has defined incoming
    /// GPR content. This is a `jmp`, never a `call`, so no return address is created.
    ///
    /// # Safety
    ///
    /// `transfer` must come from `prepare_x86_64_transfer`; the new page table must contain every
    /// validated mapping, including the currently executing stub and transition stack. The caller
    /// must have emitted its final diagnostic and must never invoke firmware services afterward.
    pub unsafe fn jump_to_kernel(transfer: X86_64Transfer) -> ! {
        let _verified = transfer.entry_state;
        let (linked_start, linked_len, linked_entry) = match linked_handoff_stub() {
            Ok(layout) => layout,
            // SAFETY: malformed linker symbols cannot support a sound CR3 replacement.
            Err(_) => unsafe { halt_forever() },
        };
        let linked_end = linked_start.checked_add(linked_len);
        if transfer.handoff_stub_start != linked_start
            || linked_end != Some(transfer.handoff_stub_end)
            || linked_entry != linked_start
        {
            // SAFETY: a mismatched mapping would make CR3 replacement unsound; halting preserves
            // the fail-closed contract without invoking unavailable firmware services.
            unsafe { halt_forever() }
        }
        // SAFETY: the caller guarantees the page-table, identity-stub, stack, and entry mappings.
        // This jumps into the exact symbol-anchored stub whose entire range was checked above.
        unsafe {
            asm!(
                "jmp __wyrmroot_handoff_start",
                in("rdi") transfer.page_table_root_physical,
                in("rsi") transfer.transition_stack_pointer,
                in("rdx") transfer.kernel_entry,
                in("rcx") transfer.boot_info_identity_pointer,
                options(noreturn)
            );
        }
    }

    unsafe fn read_cr0() -> u64 {
        let value: u64;
        // SAFETY: caller guarantees supervisor register access.
        unsafe { asm!("mov {}, cr0", out(reg) value, options(nomem, nostack, preserves_flags)) };
        value
    }

    unsafe fn write_cr0(value: u64) {
        // SAFETY: caller preserves required CR0 bits and deliberately enables WP.
        unsafe { asm!("mov cr0, {}", in(reg) value, options(nomem, nostack, preserves_flags)) };
    }

    unsafe fn inb(port: u16) -> u8 {
        let value: u8;
        // SAFETY: caller owns the I/O-port capability represented by `Com1Writer`.
        unsafe {
            asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack));
        }
        value
    }

    unsafe fn outb(port: u16, value: u8) {
        // SAFETY: caller owns the I/O-port capability represented by `Com1Writer`.
        unsafe {
            asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
        }
    }

    unsafe fn rdmsr(msr: u32) -> u64 {
        let low: u32;
        let high: u32;
        // SAFETY: the caller guarantees the MSR exists and supervisor access is permitted.
        unsafe {
            asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high, options(nomem, nostack));
        }
        (u64::from(high) << 32) | u64::from(low)
    }

    unsafe fn wrmsr(msr: u32, value: u64) {
        let low = value as u32;
        let high = (value >> 32) as u32;
        // SAFETY: the caller guarantees the MSR exists and supervisor access is permitted.
        unsafe {
            asm!("wrmsr", in("ecx") msr, in("eax") low, in("edx") high, options(nomem, nostack));
        }
    }

    unsafe fn halt_forever() -> ! {
        // SAFETY: this is the terminal fail-closed path after EBS; interrupts remain disabled.
        unsafe { asm!("cli", "2:", "hlt", "jmp 2b", options(noreturn)) }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub type Com1Writer = privileged::Com1Writer;
#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub type Com1WriteError = privileged::Com1WriteError;

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub fn linked_handoff_stub() -> Result<(u64, u64, u64), X86_64HandoffError> {
    privileged::linked_handoff_stub()
}

/// Enable and verify the target-only architectural entry state after EBS.
///
/// # Safety
///
/// The caller must satisfy the supervisor-mode and architectural-MSR contract documented by the
/// privileged implementation.
#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub unsafe fn enable_and_verify_entry_state(
    exit_boot_services_complete: bool,
) -> Result<VerifiedX86_64EntryState, X86_64HandoffError> {
    // SAFETY: the caller accepts the wrapper's identical privileged-mode contract.
    unsafe { privileged::enable_and_verify_entry_state(exit_boot_services_complete) }
}

/// Enter Deepwyrm through the symbol-anchored nonreturning transfer stub.
///
/// # Safety
///
/// The caller must satisfy the mapping, diagnostic, and post-EBS contract documented by the
/// privileged implementation.
#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
pub unsafe fn jump_to_kernel(transfer: X86_64Transfer) -> ! {
    // SAFETY: the caller accepts the wrapper's identical handoff contract.
    unsafe { privileged::jump_to_kernel(transfer) }
}
