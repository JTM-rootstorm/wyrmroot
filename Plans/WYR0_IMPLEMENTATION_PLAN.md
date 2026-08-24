# Wyrmroot WYR0 Implementation Plan

**Status:** Canonical WYR0 architecture and implementation contract  
**Repository:** `JTM-rootstorm/wyrmroot`  
**Milestone:** WYR0 - UEFI loader, primordial userspace, and native process bootstrap

This plan pins the WYR0 decisions that must remain aligned with Deepwyrm DW0. Codex and human contributors should treat the **Locked decisions** sections as requirements. Any change to a shared loader/kernel/native-ABI contract must update both repositories before implementation continues.

WYR0 deliberately stops before a real shell, TTY/PTY stack, service manager, package manager, networking stack, libc, or desktop. Its purpose is to prove the operating-system side of the boundary: Wyrmroot can load Deepwyrm, supply its primordial bootstrap image and boot filesystem, enter native userspace, and use the Deepwyrm ABI to load and run a second Wyrmroot process entirely from userspace.

---

# 1. WYR0 success condition

WYR0 is complete when this real boot path works from a clean checkout:

```text
UEFI firmware
      |
Wyrmroot loader.efi
      |
      +-- deepwyrm.elf
      +-- bootstrap.elf
      +-- bootfs.img
      |
DwBootInfoV1
      |
Deepwyrm DW0
      |
primordial Wyrmroot bootstrap process
      |
bootfs MemoryObject + bootstrap Channel
      |
userspace ELF loader
      |
/system/init0
      |
/bin/hello (or equivalent smoke process)
      |
clean exit/wait result
```

The decisive proof is not merely that `bootstrap.elf` runs. The bootstrap must use the native ABI to create and load another ELF process from bootfs, start it, wait for it, and observe a correct exit status.

---

# 2. Locked WYR0 architecture decisions

## 2.1 Relationship to Deepwyrm

1. Deepwyrm owns the native kernel ABI and `DwBootInfoV1` definitions.
2. Wyrmroot consumes `deepwyrm-abi` from a pinned Deepwyrm revision. Do not copy ABI constants/types manually into Wyrmroot.
3. Wyrmroot owns the EFI loader, bootfs construction, primordial bootstrap executable, normal userspace ELF loading, and higher-level startup semantics.
4. ABI 0 is intentionally unstable. Wyrmroot and Deepwyrm are rebuilt together after native ABI changes until ABI 1 is explicitly declared.
5. Cross-repository changes to BootInfo, primordial-process startup, or bootstrap-channel semantics require coordinated plan/schema updates.

## 2.2 Boot separation

The boot path is modular:

```text
UEFI firmware
    |
Wyrmroot EFI loader
    |
Deepwyrm
    |
primordial bootstrap
    |
normal Wyrmroot userspace
```

The EFI loader does not become init or a service manager. It loads the boot artifacts, gathers firmware state, exits UEFI boot services, and transfers control.

The software service manager is a later Wyrmroot component and has no role in locating/loading the kernel.

## 2.3 Boot artifacts

WYR0 produces exactly three principal boot payloads plus the EFI application:

```text
/EFI/Wyrmroot/loader.efi
/EFI/Wyrmroot/deepwyrm.elf
/EFI/Wyrmroot/bootstrap.elf
/EFI/Wyrmroot/bootfs.img
```

A small loader configuration file may also be present, but no complex boot-manager database is required for WYR0.

## 2.4 UEFI behavior

`loader.efi` must:

- run as a 64-bit UEFI application
- locate/load the Deepwyrm ELF, primordial bootstrap ELF, and bootfs image
- gather the UEFI memory map
- locate ACPI RSDP where available
- gather framebuffer information where available, without making graphics a WYR0 dependency
- gather command-line/loader configuration
- gather firmware entropy using the best available UEFI mechanism
- allocate/load the kernel according to the documented DW0 ELF/linker handoff scheme
- build `DwBootInfoV1`
- call `ExitBootServices()`
- enter Deepwyrm with the BootInfo pointer in the agreed x86_64 register contract

After `ExitBootServices()`, the loader does not call firmware boot services again.

WYR0 does not require a graphical boot menu. UEFI firmware boot selection is sufficient during development.

## 2.5 Native executable model

Wyrmroot native processes use:

- ELF64
- x86-64 System V userspace calling convention
- Deepwyrm-specific syscalls through generated wrappers

The primordial `bootstrap.elf` is intentionally restricted to the narrow DW0 kernel-loader subset and must be fully static.

The **userspace ELF loader** is the beginning of the normal Wyrmroot executable-loading path. It should be designed to grow later, but WYR0 itself only needs static ELF64 executables with no dynamic interpreter.

Do not ask Deepwyrm to add `exec(path)` or filesystem-aware executable loading for WYR0.

## 2.6 Rust toolchain direction

Wyrmroot will maintain its own Rust fork based on an explicitly adopted upstream **stable** release.

Locked policy:

1. At WYR0 kickoff, select the current upstream stable Rust release and record the exact upstream tag/commit.
2. Build the Wyrmroot Rust fork from that baseline and record the exact Wyrmroot fork commit used by the milestone.
3. Do not silently follow moving `stable` state after the milestone begins.
4. A newer upstream stable release is adopted only through a controlled toolchain-update branch with rebuild/test validation.
5. WYR0 does not require a complete Rust `std` port. Primordial userspace may be `#![no_std]` plus `alloc` and a small Wyrmroot runtime.
6. WYR0 should establish the native target identity, expected long term to be `x86_64-unknown-wyrmroot` or the corresponding canonical target name in the Wyrmroot fork.
7. Do **not** advertise native Wyrmroot as `cfg(unix)` merely for convenience during WYR0. Whether the final native target participates in Rust's Unix target family remains a later libc/POSIX decision.

The UEFI loader may use Rust's UEFI target/support independently from the Wyrmroot userspace target because it executes under firmware rather than Wyrmroot.

## 2.7 Native startup and capabilities

A newly started native Wyrmroot process receives:

- conventional ELF startup metadata (`argc`, `argv`, `envp`, auxv as applicable)
- one bootstrap channel capability

Capabilities such as bootfs access, future namespace access, stdio, and service-registry access are passed through bootstrap channels rather than ambient global handles.

WYR0 does not invent global magic handle numbers.

## 2.8 Userspace loading

Normal process loading belongs in Wyrmroot userspace.

The WYR0 bootstrap loader must use native operations equivalent to:

```text
TaskGroup / Process create
MemoryObject create/populate
AddressRegion map/protect
Thread create/start
Channel create/transfer
wait for Process EXITED
```

The loader parses the application ELF, constructs its userspace image and initial stack, creates a child bootstrap channel, passes initial capabilities, and starts the process.

This implementation should become a reusable `wyrmroot-loader` library rather than hard-coding ELF loading inside the one WYR0 bootstrap binary.

## 2.9 Bootfs

WYR0 bootfs is a **bootstrap transport**, not Wyrmroot's permanent filesystem design.

For WYR0, use an **uncompressed `cpio newc` archive** or an equivalently simple deterministic read-only archive if implementation constraints require it. Prefer `cpio newc` because it is easy to generate, inspect on the Gentoo host, and parse without requiring a filesystem driver.

Locked bootfs properties:

- deterministic file ordering
- no compression in WYR0
- read-only after boot
- safe bounds-checked parser
- normal file names treated as UTF-8 Wyrmroot policy, while archive parsing remains byte-safe
- malformed entries fail closed
- bootfs is transferred to the primordial bootstrap as a read-only Deepwyrm `MemoryObject`

The WYR0 bootfs should contain at minimum:

```text
/system/init0
/bin/hello
```

plus any small metadata needed by the bootstrap.

## 2.10 Diagnostics instead of a premature terminal ABI

WYR0 must **not** accidentally define the final TTY/PTY/stdio model merely to print boot messages.

Use a clearly development-only diagnostic path for primordial userspace output during WYR0. Acceptable approaches include a DW0 debug-write syscall/capability or a bootstrap diagnostic channel whose semantics are explicitly marked unstable and non-production.

The WYR0 milestone may print messages such as:

```text
wyrmroot bootstrap: online
wyrmroot bootstrap: mounted bootfs view
wyrmroot bootstrap: starting /system/init0
init0: starting /bin/hello
hello: native Wyrmroot userspace
init0: child exited 0
WYR0 PASS
```

A real console/TTY/shell belongs to WYR1 or a later dedicated plan.

## 2.11 No systemd dependency and post-WYR0 boot spine

WYR0 must not introduce systemd components. `bootstrap.elf` and `init0` remain temporary proof machinery, not the permanent service architecture.

The default post-WYR0 bring-up spine is:

```text
EFI loader
  -> Deepwyrm
  -> primordial Wyrmroot bootstrap
  -> small permanent init/supervisor
  -> separate bootstrap service discovery/registry
  -> device coordinator
  -> essential boot driver servers (especially block storage)
  -> VFS + FAT32 ESP access when boot management requires it
  -> ext4 persistent-root discovery/mount
  -> ordinary foundational services + recovery/admin console
  -> remaining drivers/subsystems
  -> login/session/desktop
```

The permanent init/supervisor is intentionally narrow. It may consume the immutable boot manifest, spawn/reap processes, distribute initial capabilities, enforce bounded startup/readiness/restart policy, perform boot/shutdown sequencing, and launch the components needed to reach persistent root. It must not absorb device-driver logic, filesystem implementations, the global service registry, general dependency policy, configuration storage, structured logging, scheduled jobs, or package management merely because those services start early.

A small static bootstrap manifest/readiness graph is allowed before the general service dependency controller exists. The general registry/discovery, activation, supervision, and dependency-control responsibilities remain separable components and protocols.

Persistent storage is not a prerequisite for entering useful userspace. The bootfs must remain capable of carrying the permanent supervisor plus enough service-discovery, device, storage, VFS/filesystem, and recovery components to discover and mount the real root. FAT32 support is needed early for native guest access to the EFI System Partition once running userspace owns boot-artifact management; it is not the root filesystem. The first persistent root is ext4, and mounting it is required before the normal persistent userspace is considered fully online. If that ext4 root cannot be mounted, the bootfs path should be able to remain as a bounded recovery environment instead of making failure synonymous with an unusable machine.

WYR0 itself still implements only the loader and primordial startup pieces necessary to prove userspace process loading. It does not implement this permanent supervisor/service/storage stack.

## 2.12 Scheduling and future real-time boundary

WYR0 does not require or define the permanent Deepwyrm scheduler policy. Its loader -> bootstrap -> `init0` -> `hello` proof must remain valid on DW0's simple scheduler and must not acquire a hidden dependency on priority classes, timer-driven preemption, real-time reservations, or scheduler-specific protocol metadata.

The longer-term direction is deliberately staged:

1. DW0-H validates the existing task/wait/scheduler mechanisms under SMP without introducing RT policy.
2. The first scheduler-focused post-DW0 work establishes the normal general-purpose timer-preemptive/SMP scheduler and latency instrumentation.
3. A later DW1 phase may expose capability-authorized firm/soft real-time mechanisms after the normal scheduler is proven.
4. Wyrmroot should use its real multi-process/service dependency chains to validate later priority/deadline propagation and admission policy rather than shaping WYR0 bootstrap protocol around speculative RT semantics.

WYR0 therefore reserves no priority scale, scheduler-class identifier, budget/period/deadline record, RT package metadata, or service-manager field. Native protocols should remain asynchronous/bounded where already required and must not prevent later urgency propagation, but no new RT field is added merely for future-proofing.

---

# 3. Canonical dependency and version pinning

Create a small machine-readable version file, for example:

```text
wyrmroot/toolchain/versions.toml
```

It should pin at least:

```toml
[deepwyrm]
revision = "<exact commit>"
abi_version = 0

[rust]
upstream_stable = "<exact stable tag/commit selected at kickoff>"
wyrmroot_revision = "<exact fork commit>"
```

The exact format may evolve before package management exists, but the rule does not: **a WYR0 build must identify exactly which Deepwyrm and Rust revisions produced it**.

Do not use floating Git branches as reproducibility inputs in milestone validation.

---

# 4. Proposed WYR0 repository layout

The implementation may refine names, but preserve responsibility boundaries:

```text
wyrmroot/
├── Cargo.toml
├── loader/
│   ├── src/
│   └── config/
├── crates/
│   ├── wyrmroot-runtime/
│   ├── wyrmroot-loader/
│   ├── wyrmroot-bootfs/
│   └── wyrmroot-bootstrap-proto/
├── bootstrap/
│   └── src/
├── userspace/
│   ├── init0/
│   └── hello/
├── image/
│   └── ...
├── tests/
│   ├── host/
│   └── integration/
├── toolchain/
│   └── versions.toml
├── tools/
│   └── xtask/
└── Plans/
```

Do not place all loader, bootfs, ELF, bootstrap-protocol, and QEMU code in one executable crate. The reusable parts should already have narrow library boundaries so later Wyrmroot milestones can replace `bootstrap` without rewriting the loader or ELF implementation.

---

# 5. Shared contract with DW0

WYR0 consumes these Deepwyrm-owned contracts:

1. `DwBootInfoV1`
2. native `DwStatus`
3. handle and rights definitions
4. syscall definitions/wrappers
5. TaskGroup/Process/Thread semantics
6. MemoryObject/AddressRegion semantics
7. Channel/Event/Timer/wait semantics
8. primordial process bootstrap-channel handoff

WYR0 owns:

1. EFI artifact discovery/configuration
2. bootfs image format/content
3. userspace bootstrap protocol message meanings
4. normal userspace ELF loading policy
5. initial process environment and capability distribution above the primordial handoff

When ambiguity exists, do not let an implementation agent independently extend the kernel ABI. Record the missing operation and route it through the coordinator/Deepwyrm ABI schema first. If the requested operation is motivated by POSIX/Linux/Windows/DOS compatibility, routing it to the schema is not approval: it must first pass the workspace cross-personality kernel-mechanism admission doctrine, with composition/userspace alternatives considered explicitly.

---

# 6. Implementation phases

## Phase WYR0-A - workspace, reproducible tooling, and Deepwyrm ABI consumption

### Tasks

- Create the Wyrmroot Rust workspace and `xtask` tooling skeleton.
- Add pinned Deepwyrm revision and consume `deepwyrm-abi` directly from that revision.
- Add `toolchain/versions.toml` or equivalent version manifest.
- Establish the selected stable Rust baseline/fork revision for WYR0.
- Establish build profiles for:
  - UEFI loader
  - Wyrmroot native `no_std` bootstrap/userspace
  - host-side tools/tests
- Add commands with a stable interface similar to:

```text
cargo xtask build
cargo xtask image
cargo xtask run
cargo xtask test host <filter>
cargo xtask test integration <filter>
```

- Add ABI compatibility sanity checks that fail early if the pinned Deepwyrm ABI cannot be consumed.

### Gate

A host build must compile the ABI consumer, bootfs tooling skeleton, and UEFI loader skeleton without duplicating Deepwyrm ABI definitions.

## Phase WYR0-B - EFI loader

### Tasks

- Implement 64-bit UEFI entry.
- Implement deterministic artifact location under `/EFI/Wyrmroot/`.
- Parse a deliberately tiny loader config format if command-line/config selection is needed. Do not build a general configuration language.
- Load and validate `deepwyrm.elf` according to the DW0 kernel linker/handoff contract.
- Load `bootstrap.elf` and `bootfs.img` into firmware-allocated pages and record them as BootInfo modules.
- Gather memory map, ACPI RSDP, optional framebuffer metadata, configuration/command line, and entropy.
- Construct `DwBootInfoV1` using canonical `deepwyrm-abi` definitions.
- Retry the final UEFI memory-map acquisition if required by `ExitBootServices()` semantics.
- Call `ExitBootServices()`.
- Install/use the documented transition mappings required by the Deepwyrm ELF layout.
- Enter the Deepwyrm kernel with the agreed BootInfo pointer contract.
- Provide loader-stage serial/UEFI diagnostics before `ExitBootServices()` and a clear last handoff marker.

### Negative tests

Host-test or parser-test at least:

- missing kernel
- missing bootstrap
- missing bootfs
- malformed kernel ELF
- unsupported ELF machine/class
- overlapping load ranges
- BootInfo allocation failure paths where testable

### Gate

The loader reaches a DW0 test kernel under QEMU `q35` + UEFI and DW0 reports a valid BootInfo handoff.

## Phase WYR0-C - deterministic bootfs builder/parser

### Tasks

- Implement host-side deterministic bootfs creation.
- Implement the userspace read-only bootfs parser in a reusable crate.
- If using `cpio newc`, validate alignment, namesize/filesize fields, trailer handling, duplicate path policy, and archive bounds.
- Reject path traversal attempts such as entries that would escape the bootfs root.
- Define a tiny lookup API by byte path plus UTF-8 helper API for normal Wyrmroot use.
- Ensure the parser can operate directly over a read-only mapped `MemoryObject` without copying the whole archive.
- Add a manifest or build rule that places `init0` and `hello` into stable paths.

### Gate

Host tests must round-trip a deterministic archive and exercise malformed/truncated/overflow/path-traversal cases without QEMU.

## Phase WYR0-D - minimal native runtime and bootstrap protocol

### Tasks

- Implement a small `#![no_std]` Wyrmroot runtime that provides:
  - raw/generated syscall wrapper access
  - allocator glue if `alloc` is used
  - startup argument/auxv parsing as needed
  - bootstrap-channel acquisition
  - process exit
  - development diagnostic output
- Define a versioned bootstrap protocol envelope in `wyrmroot-bootstrap-proto`.
- The primordial bootstrap should receive the bootfs `MemoryObject` capability from Deepwyrm and validate it before use.
- Avoid defining final service-registry or stdio protocols in WYR0.

### Gate

A synthetic userspace test can parse startup state, receive a transferred handle, send a reply over its channel, and exit.

## Phase WYR0-E - reusable userspace ELF loader

### Tasks

Implement `wyrmroot-loader` as a reusable userspace library.

For WYR0 it must:

- parse static x86_64 ELF64 safely
- validate all arithmetic/ranges before mapping
- accept only executable forms intentionally supported by WYR0
- reject `PT_INTERP`/dynamic dependencies for this milestone
- create a child process under an authorized task group
- create backing `MemoryObject` objects for loadable segments
- copy segment data and zero BSS tails correctly
- map segments using read/write/execute protections consistent with ELF flags and W^X policy
- create a userspace stack with guard space
- build conventional `argc`/`argv`/`envp`/auxv startup metadata
- create a child bootstrap channel
- transfer only explicitly selected initial capabilities
- create/start the initial thread
- return a child process handle suitable for waiting/inspection

Keep loader policy separate from ELF parsing so future dynamic-linker, POSIX, and compatibility work can reuse the parser without inheriting WYR0 assumptions.

### Gate

Host tests validate ELF parsing and layout calculation. An integration test launches a tiny static ELF entirely from Wyrmroot userspace using Deepwyrm process/memory/thread syscalls.

## Phase WYR0-F - primordial bootstrap

### Tasks

The primordial `bootstrap.elf` should do only enough to bridge kernel bootstrap into normal Wyrmroot userspace:

1. initialize the tiny native runtime
2. receive/map the bootfs `MemoryObject`
3. validate the bootfs archive
4. locate `/system/init0`
5. load `init0` through `wyrmroot-loader`
6. transfer a deliberately minimal bootstrap channel/capability set to `init0`
7. wait for `init0` or enter the documented temporary supervision behavior
8. report deterministic diagnostic state

The primordial bootstrap is not the final PID 1. Keep it replaceable and minimal.

### Gate

QEMU reaches `init0` through the real loader -> Deepwyrm -> primordial bootstrap chain.

## Phase WYR0-G - `init0` and child process smoke test

### Tasks

Implement a deliberately temporary `init0` program that proves the userspace-loader contract rather than becoming the final init design.

`init0` must:

1. initialize native runtime
2. obtain the bootfs capability or a narrowly delegated view/channel from bootstrap
3. locate `/bin/hello`
4. invoke `wyrmroot-loader`
5. start `/bin/hello`
6. wait for the child process `EXITED` signal
7. inspect/receive its exit result using the native task API
8. report pass/fail through WYR0 diagnostic output
9. exit or enter a deterministic idle/test-completion state

`hello` should be a separate native ELF executable that performs at least:

- native startup
- diagnostic output
- one channel or trivial kernel-object operation in addition to printing, where practical
- clean exit code `0`

### Gate

The integration test observes that `init0` created `hello` from userspace, `hello` exited `0`, and `init0` received the correct state.

## Phase WYR0-H - image builder and QEMU integration

### Tasks

- Build a deterministic FAT EFI System Partition image.
- Install:
  - `loader.efi`
  - pinned `deepwyrm.elf`
  - `bootstrap.elf`
  - `bootfs.img`
  - minimal config if used
- Locate/use a documented OVMF/UEFI firmware installation from the Gentoo development host without vendoring proprietary firmware blobs into the repository.
- Add QEMU `q35` run/test commands aligned with DW0.
- Capture serial output to a file/pipe for test assertions.
- Add a structured integration-test completion mechanism. Prefer a Deepwyrm test-build QEMU-exit path or explicit protocol over screenshots/timeouts.
- Add GDB launch support that coordinates with the Deepwyrm symbols.

### Gate

`cargo xtask test integration wyr0` or equivalent performs the entire WYR0 boot path from an image and returns success/failure to the host.

## Phase WYR0-I - milestone hardening and closure

### Tasks

- Build twice and compare deterministic bootfs/image outputs where feasible.
- Verify exact Deepwyrm and Rust revisions are recorded in build metadata.
- Verify no manual ABI copies exist in Wyrmroot.
- Verify unsupported ELF features fail with clear diagnostics.
- Verify malformed bootfs does not cause unchecked memory access.
- Verify primordial bootstrap has only the capabilities required for WYR0.
- Verify `init0` is clearly marked temporary and does not fossilize a service-management design.
- Produce a short WYR0 completion report and list WYR1 prerequisites.

### Gate

All WYR0 host and integration tests pass from a clean checkout using documented commands.

---

# 7. Testing strategy

The WYR0 test plan must avoid full-image boot cycles for ordinary parser and runtime fixes.

## Tier 1 - host-only tests

Run on the Gentoo development host for:

- loader configuration parser
- ELF parser/layout calculations
- bootfs builder/parser
- bootstrap protocol encoding/decoding
- version manifest parsing
- image manifest logic

Desired interface:

```text
cargo xtask test host elf
cargo xtask test host bootfs
cargo xtask test host protocol
```

## Tier 2 - component integration tests

Use QEMU only for pieces requiring the real ABI:

```text
cargo xtask test integration boot-handoff
cargo xtask test integration bootstrap-ipc
cargo xtask test integration userspace-loader
```

## Tier 3 - WYR0 end-to-end

Run:

```text
UEFI -> loader -> Deepwyrm -> bootstrap -> init0 -> hello
```

only at phase gates, cross-contract changes, and milestone closure.

## Failure quality

Prefer deterministic messages such as:

```text
WYR0 TEST userspace_loader::hello ... FAIL
stage: region_map
status: DW_ERR_ACCESS_DENIED
segment: PT_LOAD[2] flags=RX
```

rather than `QEMU timed out` with no stage information.

---

# 8. Parallel Codex execution model

This plan supports one coordinator plus up to seven parallel workers. With fewer workers, combine adjacent lanes. Shared ABI and boot-contract changes belong to the coordinator.

## Stage 1 lanes

After workspace bootstrap:

1. **UEFI loader lane** - artifact loading, firmware metadata, BootInfo construction.
2. **bootfs lane** - deterministic builder and safe parser.
3. **ELF loader lane** - host-testable ELF validation/layout library.
4. **runtime/protocol lane** - `no_std` startup runtime and bootstrap protocol.
5. **tooling lane** - `xtask`, image builder, QEMU/OVMF runner, symbol integration.
6. **toolchain lane** - stable Rust baseline/fork pinning and native target scaffolding.

The coordinator keeps Deepwyrm revision and ABI consumption coherent across all lanes.

## Stage 2 lanes

After Deepwyrm can start primordial userspace:

1. bootstrap integration
2. userspace process loader integration
3. `init0` + `hello`
4. negative security/parser tests
5. end-to-end image tests

## Worker return contract

Every worker must report:

- files changed
- targeted tests run
- exact Deepwyrm ABI revision used
- assumptions made
- any requested ABI extension

A worker must not locally patch around a missing Deepwyrm syscall by adding undocumented behavior.

---

# 9. WYR0 dependency ordering

High-level dependency graph:

```text
Deepwyrm ABI schema / DwBootInfoV1
          |
          +-------------------+
          |                   |
     loader.efi          native runtime
          |                   |
     boot artifacts        bootstrap protocol
          |                   |
          +--------+----------+
                   |
              Deepwyrm DW0
                   |
            primordial process
                   |
          bootfs parser + ELF loader
                   |
                init0
                   |
                hello
```

Host-testable parser/tool work should proceed before DW0 is fully ready. QEMU integration waits for the corresponding Deepwyrm gates rather than inventing mocks of unstable ABI behavior.

---

# 10. Explicit WYR0 non-goals

Do not expand WYR0 to include:

- final PID 1 design
- one-shot boot-stage manager
- service supervisor
- service dependency controller
- final logging service
- permanent scheduler/resource-control policy or timer-driven preemption work
- real-time scheduling authorization/admission, priority/deadline propagation, reservations/budgets, or hard-real-time guarantees
- TTY/PTY
- interactive shell
- POSIX shell compatibility
- libc/musl port
- dynamic linker/shared libraries
- package manager
- package repository
- persistent filesystem/VFS service
- networking or SSH
- user accounts/authentication
- Linux binary compatibility
- Windows/DOS compatibility
- general WyrmIDL compiler/bindings and stable native service-protocol rollout beyond the narrow WYR0 bootstrap/evidence protocols
- post-bootstrap native vDSO transition; WYR0 continues to consume the generated ABI-0 Deepwyrm entry binding
- Glasswyrm
- Prismdrake
- audio
- installer
- Secure Boot
- final Rust `std` port

If a non-goal becomes necessary merely to prove WYR0, stop and revisit the boundary instead of silently absorbing it.

---

# 11. WYR0 deliverables

At milestone completion the Wyrmroot repository should contain at minimum:

- reproducible workspace/tooling
- pinned Deepwyrm revision
- pinned stable-Rust/Wyrmroot-toolchain revision metadata
- 64-bit `loader.efi`
- deterministic bootfs builder
- safe bootfs parser
- `wyrmroot-runtime` `no_std` foundation
- versioned bootstrap protocol
- reusable static ELF userspace loader
- primordial `bootstrap.elf`
- temporary `/system/init0`
- separate `/bin/hello` native process
- deterministic EFI System Partition image builder
- QEMU q35 + UEFI run/test integration
- host parser/unit tests
- end-to-end WYR0 test
- WYR0 completion notes and WYR1 blockers

---

# 12. Suggested WYR0 acceptance transcript

The exact wording is not ABI, but the end-to-end test should expose equivalent stages:

```text
wyrmroot-loader: Deepwyrm image loaded
wyrmroot-loader: bootstrap module loaded
wyrmroot-loader: bootfs loaded
wyrmroot-loader: ExitBootServices complete

deepwyrm: DW_ABI_VERSION=0
deepwyrm: primordial process started

wyrmroot-bootstrap: online
wyrmroot-bootstrap: bootfs valid
wyrmroot-bootstrap: starting /system/init0

init0: online
init0: starting /bin/hello
hello: native Wyrmroot process online
hello: exiting 0
init0: child exited 0
WYR0 PASS
```

The host test runner must turn this completed protocol into a real success result rather than requiring a person to inspect the console manually.

---

# 13. Exit criteria

WYR0 is finished only when all of the following are true:

- clean checkout builds with documented local commands
- exact Deepwyrm and Rust/Wyrmroot-toolchain revisions are pinned
- Wyrmroot contains no hand-copied Deepwyrm ABI definitions
- `loader.efi` boots Deepwyrm under QEMU q35 + UEFI
- BootInfo contains validated memory/module metadata
- `ExitBootServices()` occurs before Deepwyrm handoff
- Deepwyrm starts the real Wyrmroot `bootstrap.elf`
- bootstrap receives and safely parses the bootfs MemoryObject
- bootstrap loads `/system/init0` using userspace ELF loading
- `init0` loads `/bin/hello` using the same reusable loader path
- `hello` runs in its own Deepwyrm process and exits `0`
- `init0` observes the correct child exit state
- host-only parser tests can run without QEMU
- subsystem integration tests can run without the full WYR0 suite
- end-to-end WYR0 returns a structured host success/failure result
- no TTY, shell, service manager, package manager, or persistent filesystem has been pulled into WYR0 as accidental scope

Once these conditions hold, freeze a WYR0 completion commit/tag. The next layer should preserve the pinned post-WYR0 spine: replace temporary `init0` with the small permanent supervisor/bootstrap-control path, bring up device/block storage plus VFS/filesystem services from bootfs, make FAT32 ESP access available for native boot management as required, mount the initial ext4 persistent root, then add the foundational recovery/admin console and broader services without destabilizing the proven loader/native-process chain. The later native-filesystem track does not block this first persistent-root bring-up.

---

# 14. Mandatory security validation flow and gate

Security review is a **required WYR0 acceptance gate**. It complements functional testing and does not replace parser tests, QEMU integration, code review, or Deepwyrm's own kernel security gate. Daybreak Blue / Codex Security should be used as a dedicated review lane when available, but Wyrmroot must not acquire a runtime or build dependency on that service.

## 14.1 Review flow

For security-sensitive changes and at every applicable phase gate, use this sequence:

```text
implementation
    |
targeted functional/negative tests
    |
static/lint checks + fuzz/property tests for host-testable parsers
    |
Daybreak Blue security review of the exact revision/diff
    |
triage findings against WYR0 threat model and capability boundaries
    |
remediate confirmed findings
    |
add regression tests reproducing the failure class
    |
rerun targeted + affected integration tests
    |
re-review security-relevant remediation
    |
coordinator records security-gate disposition
```

Security review must identify the exact Wyrmroot revision and the pinned Deepwyrm revision used for integration. A report against stale loader/parser/runtime code does not satisfy the gate after security-sensitive changes land.

If Daybreak Blue is temporarily unavailable, equivalent manual/security-tool review may cover an intermediate phase, but **WYR0 milestone closure requires a recorded security review of the release candidate** before tagging.

## 14.2 Required WYR0 security-review surfaces

Review at minimum:

- UEFI artifact discovery, size/range arithmetic, memory allocation, and `ExitBootServices()` transition handling
- Deepwyrm kernel ELF validation performed by `loader.efi`
- `DwBootInfoV1` construction, module ranges, memory-map copying, framebuffer/ACPI metadata, command-line lengths, entropy fields, and reserved fields
- loader configuration parsing and any path construction used before boot
- `cpio newc` or replacement bootfs parsing, including bounds, alignment, numeric-field parsing, duplicate paths, malformed names, traversal attempts, and truncated archives
- userspace ELF parser arithmetic, program-header validation, overlap detection, permissions, BSS zeroing, stack construction, and rejected unsupported features
- capability distribution from primordial bootstrap to `init0` and from `init0` to children
- bootstrap protocol length/version/type validation and transferred-handle expectations
- runtime startup parsing for `argc`/`argv`/`envp`/auxv and bootstrap-channel acquisition
- W^X and segment-protection requests made through the Deepwyrm ABI
- deterministic image construction and exact Deepwyrm/Rust revision pinning as supply-chain/reproducibility controls
- all production `unsafe` blocks in Wyrmroot loader/runtime/parser code and the abstractions containing them

WYR0 has no network-facing service, package ingestion, login system, or persistent filesystem, so those threat surfaces remain explicitly out of scope rather than receiving speculative implementations.

## 14.3 Required adversarial tests

WYR0 should preserve reusable malformed-input corpora/regression tests for at least:

- missing/zero-length/oversized boot artifacts
- malformed ELF identification/class/machine/header sizes
- arithmetic overflow and overlapping kernel/application ELF segments
- `PT_INTERP` or unsupported dynamic features
- segments requesting invalid W+X combinations
- malformed/truncated `cpio newc` headers
- enormous or overflowing namesize/filesize values
- entries missing NUL termination where the format requires it
- archive records extending beyond the mapped bootfs object
- absolute paths, `..` traversal, duplicate paths, and ambiguous normalization cases
- malformed bootstrap protocol size/version/type/reserved fields
- unexpected, missing, duplicate, wrong-type, or excessive transferred handles
- attempts to pass broader capability rights to `init0`/`hello` than their declared bootstrap contract permits
- startup metadata whose pointers/ranges would exceed the constructed child address space

Use coverage-guided fuzzing or equivalent fuzz/property testing for host-testable ELF, bootfs, configuration, and protocol parsers where practical. Every confirmed parser/security bug should add a minimized regression input when feasible.

## 14.4 Cross-repository security boundary

WYR0 and DW0 security reviews must meet at the shared contracts rather than assuming the other repository checked everything.

Cross-repository review must explicitly validate:

1. the exact `deepwyrm-abi` revision consumed by Wyrmroot
2. `DwBootInfoV1` producer/consumer agreement
3. bootstrap ELF restrictions expected by the Deepwyrm primordial loader
4. bootstrap-channel transferred handle types and rights
5. bootfs `MemoryObject` immutability/rights expectations
6. process/memory/thread syscall use by `wyrmroot-loader`

A Wyrmroot workaround that weakens a Deepwyrm security invariant is not an acceptable remediation. Missing kernel behavior must be routed through the Deepwyrm ABI coordinator.

## 14.5 Finding disposition

Before a phase or milestone security gate can close:

- **Critical/High:** no confirmed unresolved finding may remain.
- **Medium:** must be fixed or have an explicit written disposition, rationale, compensating control if any, and target milestone for remediation.
- **Low/Informational:** may be tracked, but must not contradict a locked WYR0 security/capability invariant.
- False positives must be documented with enough technical reasoning to avoid repeated rediscovery.

Tool-provided severity is advisory. The coordinator validates exploitability, capability impact, and whether the issue crosses the UEFI/kernel/userspace trust boundaries.

## 14.6 Security review artifact

Maintain a milestone review record, for example:

```text
security/WYR0_SECURITY_REVIEW.md
```

Record:

- reviewed Wyrmroot commit
- pinned/reviewed Deepwyrm integration commit
- Rust/Wyrmroot toolchain revision relevant to the build
- review date/tooling
- threat-model scope
- findings and dispositions
- parser/fuzz/regression tests added
- explicitly accepted residual risks
- final gate status

Do not commit credentials, secrets, private prompts, or unnecessary proprietary scanner internals.

## 14.7 Phase integration

Security review is distributed across WYR0 rather than postponed to WYR0-I:

- **WYR0-A:** dependency/ABI pinning, generated-boundary consumption, reproducibility controls.
- **WYR0-B:** EFI artifact parsing/loading, kernel ELF, BootInfo construction, ExitBootServices transition.
- **WYR0-C:** bootfs parser and path/traversal rules, fuzz corpus.
- **WYR0-D:** startup/runtime/bootstrap protocol and capability receipt.
- **WYR0-E:** userspace ELF loading, mapping arithmetic, stack construction, capability delegation.
- **WYR0-F:** primordial bootstrap authority and bootfs validation.
- **WYR0-G:** `init0` child delegation and rights minimization.
- **WYR0-H:** image construction, integration boundaries, test harness assumptions.
- **WYR0-I:** whole-milestone threat-model review, residual-risk triage, release-candidate security review.

## 14.8 Mandatory WYR0 security exit gate

The earlier WYR0 exit criteria are necessary but not sufficient. WYR0 **must not be tagged complete** until all of the following are also true:

- the release-candidate Wyrmroot commit and pinned Deepwyrm revision have completed the recorded security-review flow
- no confirmed Critical/High security finding remains unresolved
- every Medium finding has an explicit disposition
- confirmed security bugs have regression tests where technically practical
- malformed kernel/application ELF inputs fail closed
- malformed/traversal/overflow bootfs inputs fail closed
- bootstrap protocol rejects malformed messages and unexpected handle sets
- primordial/bootstrap/`init0` capability reviews confirm least privilege for WYR0's declared responsibilities
- W^X/protection and userspace loader negative tests pass against the real Deepwyrm ABI
- deterministic image/version pin checks pass
- all security-sensitive production `unsafe` blocks are documented and reviewed
- `security/WYR0_SECURITY_REVIEW.md` (or the canonical equivalent) records the exact reviewed revisions and final `PASS`/accepted-risk state

Any security-sensitive code change after the recorded release-candidate review invalidates the final gate for the affected surface and requires targeted re-review before the WYR0 tag is created.
