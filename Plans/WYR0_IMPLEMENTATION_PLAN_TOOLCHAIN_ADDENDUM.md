# Wyrmroot WYR0 Implementation Plan Addendum: LLVM Toolchain and Debugging

**Status:** Canonical locked addendum to `Plans/WYR0_IMPLEMENTATION_PLAN.md`  
**Repository:** `JTM-rootstorm/wyrmroot`  
**Milestone:** WYR0  
**Scope:** Canonical compiler/linker family, native target direction, self-hosting stages, and host-side debugging

This document is part of the WYR0 implementation contract. Codex and human contributors must treat the decisions below as **locked** unless an explicit architecture revision updates this addendum and the matching Deepwyrm DW0 toolchain addendum together.

The central rule is:

> **Wyrmroot standardizes on the LLVM toolchain family for its canonical C/C++ and linker environment, while retaining host-side GDB as a first-class debugger for the QEMU guest.**

The canonical toolchain direction is intended to align Rust and C/C++ code generation around LLVM, simplify cross-compilation, support the libc-independent native runtime model, and avoid making GCC/binutils assumptions part of Wyrmroot's ABI.

---

# 1. Locked canonical toolchain family

Wyrmroot's canonical toolchain family is:

```text
Rust:                   Wyrmroot-maintained rustc fork, LLVM backend
C:                      Clang
C++:                    Clang++ when required
Linker:                 LLD (`ld.lld`)
Compiler builtins:      compiler-rt
Assembler:              Clang integrated assembler and/or LLVM tooling
Archiver:               llvm-ar
ELF/object inspection:  llvm-readelf / llvm-objdump / llvm-nm
Binary manipulation:    llvm-objcopy
Symbolization:           llvm-symbolizer
Guest/kernel debugger:  host-side GDB through QEMU gdbstub
```

GCC and GNU binutils remain valid future optional packages/toolchains, but they are not required for WYR0 and do not define native Wyrmroot ABI behavior.

---

# 2. WYR0 build-host model

WYR0 is cross-built from the Gentoo development host.

Canonical initial direction:

```text
Gentoo host
   |
   +-- Wyrmroot rustc fork
   +-- Clang / LLVM
   +-- LLD
   +-- compiler-rt
   +-- LLVM binary utilities
   +-- GDB
   |
   v
Wyrmroot native/UEFI artifacts
```

Host tooling may use the Gentoo host libc and normal Gentoo package environment. The libc-independent Wyrmroot policy applies to artifacts executing inside Wyrmroot, not to the compiler/debugger programs used to produce them.

WYR0 must not require a self-hosting Clang/LLVM installation inside the guest.

---

# 3. Native Clang target direction

The long-term native target should be represented by an explicit Wyrmroot target identity, expected to resemble:

```text
x86_64-unknown-wyrmroot
```

The exact canonical triple must remain aligned with the Wyrmroot Rust target and ABI policy.

Early WYR0 work may use explicit generic/freestanding target settings where target-specific Clang support does not yet exist. Do not block WYR0 merely to maintain an LLVM fork before there is a concrete target behavior that needs patching.

When native C SDK work matures, the desired command shape is conceptually:

```text
clang --target=x86_64-unknown-wyrmroot --sysroot=<wyrmroot-sysroot> ...
```

The future Wyrmroot sysroot is expected to provide native startup/runtime and SDK artifacts, not an obligatory libc.

Conceptually:

```text
sysroot/
├── include/
│   ├── deepwyrm/
│   └── wyrmroot/
└── lib/
    ├── startup objects
    ├── compiler-rt support
    └── native Wyrmroot libraries
```

A POSIX/libc sysroot layer may later be installed separately.

---

# 4. Native C/C++ remains libc-optional

LLVM/Clang adoption must preserve the locked libc policy.

A native Wyrmroot C program should eventually be able to target native SDK interfaces without requiring a POSIX libc:

```text
native C/C++ program
       |
Wyrmroot native SDK/runtime
       |
compiler-rt as needed
       |
Deepwyrm/Wyrmroot native interfaces
```

Existing large C/C++ software may initially be ported through the optional POSIX/libc personality. That is a pragmatic compatibility route and does not make libc foundational.

The WYR0 guest artifacts remain static, libc-free native programs as already required by the libc-policy addendum.

---

# 5. compiler-rt policy

`compiler-rt` is the preferred canonical provider for low-level compiler builtins required by Clang/LLVM-produced Wyrmroot code.

This is consistent with the existing rule:

```text
compiler runtime support       allowed
mandatory guest libc           not allowed
```

Do not treat compiler-rt as libc and do not pull a POSIX environment into WYR0 merely to satisfy generated arithmetic/atomic/runtime helpers.

Where only a tiny subset is needed for WYR0, link only the required support rather than making the entire compiler runtime an uncontrolled dependency.

---

# 6. LLD policy

LLD is the canonical Wyrmroot linker for WYR0/native cross-builds where a linker is required.

Requirements:

- use explicit target/link settings rather than host defaults
- keep startup/linker configuration centralized in Wyrmroot build tooling
- avoid accidental dependence on host GNU linker paths or default search directories
- preserve useful DWARF/debug information for QEMU/GDB debugging
- keep output ELF compatible with the locked Wyrmroot/Deepwyrm ABI contracts

LTO is not a WYR0 requirement.

ThinLTO or other LLVM optimization modes may be evaluated later after reproducible debug/release builds are proven.

---

# 7. LLVM utility policy

The canonical host-side inspection/manipulation suite should use LLVM tools where practical:

```text
llvm-readelf
llvm-objdump
llvm-nm
llvm-objcopy
llvm-ar
llvm-symbolizer
```

Expected uses include:

- validating `bootstrap.elf`, `init0`, and `hello` program headers
- proving the libc-free/no-`PT_INTERP` constraints
- inspecting symbols and section layouts
- preparing debug/symbol artifacts
- symbolizing panic and integration-test addresses

These tools do not replace GDB for interactive live debugging.

---

# 8. Host-side GDB remains a canonical QEMU debugger

Using an LLVM compiler family does not require Wyrmroot to standardize on LLDB.

WYR0 explicitly supports and expects host-side GDB debugging through QEMU's remote gdbstub.

Canonical architecture:

```text
Wyrmroot/Deepwyrm images
       |
      QEMU
       |
remote GDB stub
       |
Gentoo host GDB
       |
Deepwyrm/Wyrmroot symbol files
```

Tooling should expose a stable developer command similar to:

```text
cargo xtask gdb
```

The implementation should coordinate with the Deepwyrm DW0 debugger tooling so one workflow can:

- start the canonical q35/UEFI VM paused when requested
- enable the QEMU gdbstub
- load the correct `deepwyrm.elf` symbols
- optionally load/switch to Wyrmroot userspace symbols when bootstrap/`init0` debugging becomes practical
- permit breakpoints and register/memory inspection across the boot handoff

Host GDB is allowed to depend on the Gentoo host libc and normal host packages.

LLDB may be added later as another option, but WYR0 does not require it.

---

# 9. Debug metadata and symbol handling

WYR0 debug builds should retain sufficient DWARF/symbol data to support:

- host GDB breakpoints/backtraces
- `llvm-symbolizer` processing
- loader/bootstrap fault diagnosis
- correlation between serial panic addresses and source/build artifacts

Image-building must not accidentally strip the only available debug information from the host build products merely because the boot copy is optimized or stripped.

A useful split is:

```text
boot/image artifact        possibly stripped when appropriate later
host debug artifact        full symbols/debug info
```

For WYR0, simplicity is preferred and fully symbolized debug builds are acceptable.

---

# 10. Sanitizers and host-side analysis

WYR0 should use LLVM sanitizers where practical for host-testable components, especially:

- bootfs parser/builder
- ELF parser/layout calculations
- loader configuration parser
- bootstrap protocol encoder/decoder
- image-manifest tooling

Host ASan/UBSan or equivalent tooling may be integrated into security/fuzz validation.

WYR0 must **not** assume guest-side sanitizer runtimes have already been ported to Wyrmroot.

Guest sanitizer support is future work and not a milestone-zero dependency.

---

# 11. GCC and GNU binutils future role

Wyrmroot should eventually be capable of supporting GCC and GNU binutils as optional packages/toolchains.

Potential goals:

```text
pkg install gcc
pkg install binutils
```

with real Wyrmroot targets when the package ecosystem is ready.

Benefits include:

- compiler-diversity testing
- detection of Clang-specific source assumptions
- support for third-party software preferring GCC
- developer choice

However:

- GCC/binutils are not WYR0 prerequisites
- GCC is not the ABI oracle
- GNU `ld` is not the canonical WYR0 linker
- `libgcc` is not the canonical compiler-runtime dependency
- alternative compiler output must conform to the Wyrmroot ABI rather than altering it

---

# 12. Self-hosting stages

Do not conflate "Clang can target Wyrmroot" with "Clang can run natively on Wyrmroot."

The locked progression is:

## Stage 1 - host cross-compile

```text
Gentoo Clang/LLVM
      |
      v
Wyrmroot binaries
```

This is sufficient for WYR0 and early milestones.

## Stage 2 - pragmatic self-hosting

After the optional POSIX/libc personality exists, upstream Clang/LLVM may initially run through that compatibility environment.

```text
Clang/LLVM
    |
POSIX/libc personality
    |
Wyrmroot
```

This is acceptable even though the base operating system remains libc-independent.

## Stage 3 - optional native LLVM port

Only if the benefit justifies the maintenance cost, LLVM/Clang may later be ported against native Wyrmroot C++/runtime services with reduced or no POSIX/libc dependency.

This is explicitly **not** required for WYR0 or for early Wyrmroot self-hosting.

---

# 13. LLVM fork policy

Unlike the Wyrmroot Rust compiler fork, an LLVM/Clang fork is **not required at WYR0 kickoff** merely to cross-build ELF artifacts.

Create/maintain a Wyrmroot LLVM patchset or fork only when needed for concrete target support such as:

- recognition of the canonical Wyrmroot target triple
- Wyrmroot-specific default runtime/linker selection
- target-specific predefined macros/configuration
- native sysroot/startup behavior
- other target semantics that cannot be expressed cleanly by external driver/build flags

When such a fork becomes necessary, it should follow an explicitly pinned upstream stable/release baseline with a small auditable patchset, similar in spirit to the Rust toolchain policy.

Do not fork LLVM early merely for branding.

---

# 14. Implementation-phase amendments

## WYR0-A

- Detect/document canonical host Clang, LLD, LLVM utilities, compiler-rt availability, and GDB.
- Ensure build configuration does not accidentally invoke host GCC or GNU `ld` through defaults.
- Preserve the existing pinned Wyrmroot Rust toolchain policy.

## WYR0-B through WYR0-G

- Use explicit target/link settings for all guest artifacts.
- Use LLVM inspection tools to validate ELF restrictions and libc-independent linkage.
- Keep generated/native C bindings independent of Clang-specific ABI accidents.

## WYR0-H

- Integrate the host-side GDB/QEMU workflow with the same q35/UEFI image runner used by normal tests.
- Keep host symbol files available even if image artifacts later become stripped.

## WYR0-I

- Milestone closure must prove the canonical LLVM/Clang/LLD toolchain path builds WYR0 from a clean checkout.
- Verify no hidden GCC/binutils dependency exists in the canonical path.
- Verify host-side GDB can connect to the WYR0 QEMU configuration and debug at least the Deepwyrm portion of the boot with correct symbols.

---

# 15. Mandatory WYR0 toolchain/debug gate

WYR0 must not be tagged complete until:

- the canonical build succeeds with the documented LLVM/Clang/LLD environment plus the pinned Wyrmroot Rust toolchain
- WYR0 guest artifacts use explicit target/sysroot/link configuration rather than accidental Gentoo host defaults
- compiler-rt/runtime helpers do not introduce a guest libc dependency
- LLVM ELF/object inspection can validate the produced bootstrap/userspace artifacts
- host-side GDB can attach to the canonical QEMU gdbstub workflow and resolve the correct kernel symbols
- GCC and GNU binutils are not hidden WYR0 prerequisites
- no Wyrmroot ABI behavior is defined only by undocumented Clang-specific implementation behavior
- the self-hosting plan does not require native Clang/LLVM execution inside WYR0

This gate is additive to the existing WYR0 functional, libc-independence, image-delivery, and security-validation gates.
