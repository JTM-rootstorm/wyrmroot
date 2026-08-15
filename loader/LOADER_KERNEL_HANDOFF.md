# Wyrmroot Loader to Deepwyrm x86_64 Handoff

This document records the shared `DW_BOOT_X86_64_ENTRY_V1` machine-state
contract used by WYR0-B and DW0-B. Deepwyrm remains authoritative for the
kernel ELF link layout and generated ABI definitions. Wyrmroot consumes those
definitions from its exact Deepwyrm revision pin.

## Transfer operation

- The loader calls `ExitBootServices()` successfully before transfer and does
  not call UEFI firmware services afterward.
- The loader transfers control to the validated ELF `e_entry` with a
  nonreturning `jmp`, never a function call.
- `RDI` contains an eight-byte-aligned, identity-mapped virtual address whose
  numeric value is the physical address of `DwBootInfoV1`.
- Other general-purpose registers have unspecified values.
- The bootstrap processor is in x86_64 long mode with four-level paging,
  paging enabled, NX enabled, `CR0.WP` enabled, `IF = 0`, and `DF = 0`.
- Descriptor-table state and `FS`/`GS` state are unspecified. Deepwyrm must
  install or reset them before use.
- No floating-point, SIMD, TLS, or per-CPU runtime state is established by the
  loader.

The raw entry is an assembly shim, not a Rust or System V function boundary.
The shim must not push to the incoming stack. It immediately switches to the
kernel-owned bootstrap stack, executes `cli` and `cld`, clears `RBP` as an
unwind sentinel, preserves the BootInfo argument in `RDI`, and calls a
nonreturning System V Rust entry. Returning from the Rust entry is fatal and
must end in an interrupts-disabled halt path. Kernel code is built without a
red zone.

## Stack ownership

The loader provides a dedicated, page-aligned 16 KiB transition stack mapped
read/write and non-executable. At raw entry, `RSP` is 16-byte aligned at the
one-past-the-end address and no return address is present. The stack is
loader-owned and reserved across the jump.

The Deepwyrm image provides its own page-aligned 64 KiB
`.bss.boot_stack`, mapped read/write and non-executable. The raw assembly shim
switches to that stack before making any call or push. Deepwyrm may reclaim the
loader transition stack only after replacing the transition environment.

## ELF and transition mappings

- The kernel image is the Deepwyrm-owned fixed-base `ET_EXEC` layout. Wyrmroot
  obtains the link-base constant from the canonical Deepwyrm handoff source;
  it does not maintain an independent numeric policy.
- Every accepted `PT_LOAD` range is upper-canonical, nonoverlapping, mapped at
  its actual ELF `p_vaddr`, and subject to W^X.
- `e_entry` must lie within an executable accepted load segment.
- Page zero remains unmapped.
- The transition page tables preserve the currently executing loader handoff
  stub at its current virtual address until the jump completes.
- BootInfo and the early-copy memory map, module table, module data, command
  line, entropy bytes, and required ACPI pages are identity mapped.
- Framebuffer pixel memory is not identity mapped merely for handoff. BootInfo
  preserves its physical description for a later mapping with the correct
  cache policy.

BootInfo, referenced handoff allocations, the loader transition stack, and
transition page tables remain reserved until Deepwyrm has validated and
copied or claimed the required information, switched to its own page tables,
and switched to kernel-owned stack state.

## Validation boundary

The Wyrmroot loader must reject malformed or unsupported ELF input, mapping
overlap, arithmetic overflow, writable-executable segments, invalid entry
placement, malformed BootInfo inputs, and handoff ranges that cannot remain
mapped and reserved for the required lifetime. The loader must not guess a
missing Deepwyrm ABI or linker constant.
