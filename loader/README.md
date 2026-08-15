# Wyrmroot EFI loader scaffold

This directory reserves the Wyrmroot-owned EFI loader boundary described by the
canonical WYR0 architecture. It is an inert WYR0-A scaffold, not a bootable EFI
application.

The crate is deliberately library-only and dependency-free. In particular, it
currently provides none of the following:

- an EFI executable target or firmware entry point;
- UEFI protocol calls or an EFI framework dependency;
- boot-artifact discovery, file loading, or path policy;
- Deepwyrm or bootstrap ELF parsing;
- generated Deepwyrm ABI consumption;
- `DwBootInfoV1` construction;
- UEFI memory-map capture or `ExitBootServices()` handling;
- kernel page-table transition or handoff behavior;
- media, image-building, QEMU, or VM control;
- a loader configuration format or parser.

Future implementation begins in WYR0-B only after WYR0-A has established the
exact Deepwyrm revision and generated ABI dependency, the adopted Rust toolchain
and UEFI target, centralized build commands, and the shared kernel linker and
handoff contract. The future loader must remain only the firmware-to-kernel
boundary: it loads the canonical artifacts, gathers validated firmware state,
exits boot services, and transfers control to Deepwyrm. It must not absorb
bootfs parsing, normal userspace executable loading, init, service management,
image construction, or VM orchestration.

The authoritative requirements remain:

- `../Plans/ARCHITECTURE_INDEX.md`
- `../Plans/WYRMROOT_PLATFORM_CONVENTIONS.md`
- `../Plans/WYR0_IMPLEMENTATION_PLAN.md`
- the WYR0 locked addenda named by the architecture index
- the companion Deepwyrm architecture and DW0 plans for shared handoff contracts

Do not infer a stable source-module layout, configuration schema, artifact path
API, or ABI type from this scaffold. Those boundaries must be introduced with
their owning plan gate and tests rather than guessed here.
