# Wyrmroot WYR0 Implementation Plan Addendum: Native libc Policy

**Status:** Canonical locked addendum to `Plans/WYR0_IMPLEMENTATION_PLAN.md`  
**Repository:** `JTM-rootstorm/wyrmroot`  
**Milestone:** WYR0  
**Scope:** Native runtime, Rust platform support, and optional POSIX/libc boundary

This document is part of the WYR0 implementation contract. Codex and human contributors must treat the decisions below as **locked** unless an explicit architecture revision updates this addendum and the matching Deepwyrm DW0 libc-policy addendum together.

The central rule is:

> **Native Wyrmroot must not require libc to boot, run its base userspace, or provide its native system APIs.**

libc is an optional future component of the POSIX compatibility personality. It is not the foundation of Wyrmroot.

---

# 1. Locked native runtime policy

Wyrmroot's native software stack is expected to use:

```text
native application
      |
Rust std for Wyrmroot or native Wyrmroot SDK
      |
Wyrmroot native runtime/services
      |
generated Deepwyrm ABI bindings
      |
Deepwyrm
```

It must not require the following architecture merely for convenience:

```text
native application
      |
libc
      |
POSIX shim
      |
Deepwyrm
```

The WYR0 base environment therefore has **no mandatory dependency** on glibc, musl, newlib, or another libc implementation.

---

# 2. WYR0 runtime is not libc

The planned `wyrmroot-runtime` crate is a **native Wyrmroot runtime**, not a libc replacement.

For WYR0 it may provide:

- native executable startup glue
- generated Deepwyrm syscall wrapper access
- bootstrap-channel acquisition
- auxv/startup metadata parsing
- allocator hooks and a small native allocator when `alloc` is used
- panic/abort/process-exit support
- TLS/bootstrap support as required by Rust code
- development diagnostic output

It does not need to implement:

- `stdio`
- `fopen`
- `malloc/free` as a C ABI contract
- `fork`
- POSIX signals
- `pthread`
- POSIX locale/user databases
- Unix file descriptors as Wyrmroot's native I/O model

Do not grow `wyrmroot-runtime` into a home-grown libc merely because native programs require low-level runtime glue.

---

# 3. WYR0 primordial/base userspace requirement

The following WYR0 guest artifacts must be capable of building and running without libc:

```text
bootstrap.elf
/system/init0
/bin/hello
```

They may use:

- Rust `core`
- Rust `alloc` with a Wyrmroot-native allocator
- the minimal `wyrmroot-runtime`
- generated `deepwyrm-abi` wrappers
- compiler/runtime support required for correct machine code

They must not acquire a hidden glibc/musl/newlib dependency.

WYR0 remains fully static for these initial binaries and does not require a dynamic linker.

---

# 4. Native allocation model

The native Wyrmroot allocator should be layered over Deepwyrm memory primitives rather than over libc `malloc`.

Expected direction:

```text
Rust alloc / native allocation API
             |
Wyrmroot allocator
             |
MemoryObject / AddressRegion
             |
Deepwyrm
```

The WYR0 allocator may be deliberately simple. Its algorithm is implementation detail.

A future libc may implement `malloc/free` on top of the same native Wyrmroot facilities.

---

# 5. Rust toolchain and `std` direction

The Wyrmroot-maintained Rust fork should eventually provide a genuine native platform implementation.

Desired long-term structure:

```text
library/std/src/sys/pal/wyrmroot/
```

or the equivalent layout used by the adopted stable Rust baseline.

Native Rust operations should ultimately map directly to Wyrmroot facilities, for example:

```text
std::thread        -> native thread/task primitives
std::sync          -> native atomics/waits/events
std::fs            -> Wyrmroot filesystem service
std::net           -> Wyrmroot networking service
std::process       -> Wyrmroot native process loader/service
std::time          -> native monotonic/time services
```

Do not implement the Wyrmroot Rust target primarily by forwarding these operations through libc/POSIX if a native Wyrmroot facility exists.

WYR0 itself does not require the complete `std` port; `no_std` + `alloc` remains acceptable for milestone zero.

---

# 6. Rust target-family policy

The existing WYR0 decision remains locked:

> Do not mark native Wyrmroot `cfg(unix)` merely to make existing crates compile.

Doing so would encourage crates to assume:

- libc
- POSIX file descriptors
- pthreads
- Unix signals
- `fork()`
- other Unix-specific runtime behavior

Native Wyrmroot code should prefer explicit Wyrmroot platform support.

A future POSIX-oriented target/environment may expose Unix-family behavior if that proves useful, but that decision belongs to the POSIX/libc milestone rather than WYR0.

---

# 7. Native C/C++ strategy

WYR0 does not require a hosted C/C++ environment.

The intended layering is:

```text
freestanding C
    -> Deepwyrm/Wyrmroot native ABI bindings

native Wyrmroot C SDK
    -> native Wyrmroot service libraries

existing POSIX C/C++ software
    -> optional POSIX libc/personality
```

This means a native C API may exist later without requiring the C standard/POSIX library to become foundational.

For existing large C/C++ software, using the POSIX personality may be the pragmatic first porting path. That is acceptable.

---

# 8. POSIX/libc becomes an optional compatibility package

A later Wyrmroot milestone may introduce a POSIX compatibility environment and a libc, likely adapting an existing implementation such as musl instead of rewriting a complete libc from scratch.

The architecture is expected to look like:

```text
                         Applications
                             |
             +---------------+----------------+
             |                                |
          Native                           POSIX
             |                                |
     Wyrmroot runtime                       libc
             |                                |
     native services                  POSIX personality
             |                                |
             +---------------+----------------+
                             |
                         Deepwyrm
```

The package manager should eventually be able to install the POSIX environment explicitly rather than having it be an inseparable base dependency.

A conceptual future package boundary might resemble:

```text
compat/posix
sys-libs/musl-wyrmroot
```

Exact names remain future package-manager policy.

---

# 9. Base-system implications

The intended Wyrmroot-native base should eventually be able to provide, without libc as a required runtime dependency:

- PID 1 / bootstrap orchestration
- service supervision/controller
- logging
- package manager
- device manager
- networking policy services
- shell
- native core utilities
- native Glasswyrm/Prismdrake integration where those components support Wyrmroot-native interfaces

Some third-party applications may still pull in the optional POSIX/libc environment. That does not violate the policy.

The rule is that **Wyrmroot itself does not need libc in order to be Wyrmroot**.

---

# 10. Shell and terminal implications

The future native Wyrmroot shell does not need to implement its internals through POSIX/libc.

It may expose familiar syntax while using native concepts such as:

- process handles
- channels/stream capabilities
- native namespaces
- native process creation

A strict POSIX `/bin/sh` may later be provided separately through the POSIX environment or through a dedicated compatibility mode.

Do not force WYR0 or the future native shell design to adopt POSIX semantics solely because libc traditionally expects them.

---

# 11. Host-tooling exception

The libc-independent rule applies to **native guest runtime dependencies**, not the Gentoo development host.

Normal host-side components may depend on the host libc, including:

- Cargo/rustc
- Wyrmroot Rust toolchain build machinery
- `xtask`
- QEMU/OVMF
- image builders
- fuzzers
- debuggers
- other development utilities

Do not waste WYR0 effort making host tooling freestanding.

The build/test system must distinguish host dependencies from artifacts that execute inside Wyrmroot.

---

# 12. Implementation-phase changes

The following requirements amend the corresponding WYR0 phases.

## WYR0-A

- Establish `wyrmroot-runtime` explicitly as a libc-independent native runtime.
- Add dependency inspection for native guest artifacts so accidental libc linkage fails milestone validation.
- Keep the native Rust target from advertising Unix-family behavior merely for crate compatibility.

## WYR0-D

- Implement startup, allocation, bootstrap IPC, diagnostics, and exit through native Wyrmroot/Deepwyrm interfaces.
- Do not introduce libc as a shortcut for allocator, thread, I/O, or process support.

## WYR0-E

- `wyrmroot-loader` must remain a native userspace loader and must not rely on `execve`, POSIX filesystem calls, or libc process creation.

## WYR0-F/G

- `bootstrap`, `init0`, and `hello` must execute in a libc-free WYR0 guest environment.
- Capability distribution and child startup remain Wyrmroot-native.

## WYR0-I

- Milestone closure must inspect the produced guest binaries and verify no required libc dependency has slipped into the native WYR0 chain.

---

# 13. Testing requirements

Add explicit libc-independence tests/checks:

1. Inspect `bootstrap.elf`, `/system/init0`, and `/bin/hello` as part of the build/test pipeline.
2. Verify the WYR0 static binaries have no `PT_INTERP` requirement.
3. Verify there are no dynamic dependencies on glibc, musl, newlib, or equivalent libc artifacts.
4. Exercise allocation, IPC, process creation/loading, waits, and exit through native interfaces.
5. Keep host dependency reports separate so host libc usage does not create false failures.
6. When compiler-runtime objects are linked, record them as compiler/runtime support rather than misclassifying them as libc.

Security review should flag accidental libc/POSIX shortcuts that weaken the intended native capability model or create ambient authority not present in the native design.

---

# 14. WYR0 non-goal clarification

The existing WYR0 non-goal `libc/musl port` is strengthened as follows:

- WYR0 does not port libc.
- WYR0 does not create a temporary home-grown libc.
- WYR0 does not require libc to satisfy Rust-native runtime needs.
- WYR0 does not mark the native target Unix simply to inherit a libc-oriented Rust backend.

The future POSIX/libc effort must be planned as its own compatibility milestone rather than allowed to leak backward into WYR0.

---

# 15. Mandatory WYR0 libc-independence gate

WYR0 must not be tagged complete until:

- `bootstrap.elf`, `/system/init0`, and `/bin/hello` run without a guest libc
- `wyrmroot-runtime` is documented as a native runtime rather than a libc
- Wyrmroot process loading, memory allocation, IPC, waits, and exit use native Deepwyrm/Wyrmroot interfaces
- no native WYR0 artifact requires glibc, musl, newlib, or another libc
- the native Rust target has not gained accidental `cfg(unix)`/libc assumptions
- compiler/runtime support linked into WYR0 binaries is separately identified and documented where necessary
- host-only libc dependencies remain clearly outside the guest runtime dependency graph
- WYR0 security review confirms that libc/POSIX shortcuts have not bypassed the locked native handle/capability architecture

This gate is additive to the existing WYR0 functional, image-delivery, and security-validation gates.