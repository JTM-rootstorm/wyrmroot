# WYR1-D3B/D3D implementation status

**Status:** Reached D3B and D3D host/model and native-build gates

**Reached:** 2026-08-31

**Base Wyrmroot revision:** `8ef248905886288b66eb9b534f12f73f31b13a89`

**Scope:** staged Interrupt activation plus the bounded production UART/WRST
event loop; no product selection, VM, or live-hardware acceptance

## Reached behavior

Devmgr now reserves one nonzero stage generation and three distinct staged
transactions from resident-owned high-water marks. The DeviceResource MOVE,
Interrupt MOVE, and production `DRIVER_READY` therefore cannot collide with
the launch transaction or a replacement launch. The reservation is consumed
even if staging later fails.

The production-only coordinator path:

- moves the exact reduced DeviceResource and requires the correlation-exact
  `DEVICE_QUIESCED` reply before creating an Interrupt;
- creates and validates one fresh source-3 Interrupt at exact
  `WAIT | MODIFY | INSPECT`, armed state, nonzero object and binding
  generations, parent resource 1 and matching lease, with all flags and
  reserved fields zero;
- records MOVE ownership only after each Channel send commits and closes every
  still-local handle on failure; and
- accepts `DRIVER_READY` only at its separately reserved transaction before
  publication.

The historical C5/C6 path remains a separately compiled function and
selector 29 still selects WRDC 1.0 rather than the D3 staged flow.

The production `uart16550d` native entry validates the exact staged Interrupt
before enabling only RDI and RLSI. Register I/O health is sticky. Interrupt
handling drains one bounded UART epoch, checks core and native PIO health, and
only then consumes a single-use drained token in exactly one
`interrupt_ack`. Unknown causes, drain exhaustion, or PIO failure disable IER
and fail without acknowledging; acknowledge failure is fatal. A coalesced
next epoch may make the following wait immediately ready.

The D3D loop rebuilds a bounded wait set for control, Interrupt, and the
optional stream. Control peer-close or exact `RETIRE` wins when readiness
coexists. Stream readable interest is exposed only with at least 1024 bytes of
TX-ring capacity, and writable interest only while RX bytes are pending. RX
bytes are copied without removal and leave the core ring only after the WRST
send commits; `WOULD_BLOCK` retains them. Malformed or handle-bearing WRST and
stream transport failure detach and isolate only that stream so the healthy
hardware generation can reconnect. A peer-closed stream first drains
already-queued records under the same 1024-byte admission gate; if TX capacity
is exhausted, the loop suppresses the sticky peer-close wake until Interrupt
progress restores capacity, then resumes draining and detaches only after the
queue is empty.

Teardown is bounded and ordered: best-effort IER zero while the resource is
usable, close local stream state, close Interrupt, close DeviceResource, and
close control last. It does not wait indefinitely for TX drain. Diagnostics
and lifecycle counters saturate.

## Validation

Host commands used the pinned Rust/Cargo 1.97.1 launcher. Every invocation
sets `WYRMROOT_PINNED_TARGET_DIR` to a fresh project-local directory; the
launcher intentionally rejects a nonempty target without its pinned identity
marker.

```text
tools/pinned-cargo test -p wyrmroot-uart16550-core --lib --tests
# 10 tests passed
tools/pinned-cargo test -p wyrmroot-device-proto --lib --tests
# 42 unit + 9 D0 model tests passed
tools/pinned-cargo test -p wyrmroot-devmgr --lib --tests
# 30 unit + 12 native-source regression tests passed
tools/pinned-cargo test -p wyrmroot-uart16550d --lib --tests
# 10 unit + 5 native-source + 1 D3C joined test passed
tools/pinned-cargo clippy -p wyrmroot-device-proto --lib --tests -- -D warnings
tools/pinned-cargo clippy -p wyrmroot-uart16550-core --lib --tests -- -D warnings
tools/pinned-cargo clippy -p wyrmroot-devmgr --lib --tests -- -D warnings
tools/pinned-cargo clippy -p wyrmroot-uart16550d --lib --tests -- -D warnings
tools/pinned-cargo fmt --all -- --check
# all passed
```

The native build gate used immutable accepted compiler
`wyrmroot-1.97.1-a92dc7f7`, offline locked dependencies, `-D warnings`, path
remapping, and isolated target directories:

```text
accepted-cargo check --offline --locked --target x86_64-unknown-wyrmroot \
  --package wyrmroot-uart16550d --bin uart16550d \
  --features native-uart16550d
accepted-cargo check --offline --locked --target x86_64-unknown-wyrmroot \
  --package wyrmroot-devmgr --bin devmgr --features wyr1d-production
accepted-cargo check --offline --locked --target x86_64-unknown-wyrmroot \
  --package wyrmroot-devmgr --bin devmgr \
  --features wyr1c6-production,wyr1c6-selector29
# all passed; the third command is the historical selector-29 target regression
```

## Required-source receipt and provenance

All external use was conceptual; no upstream code, ABI, structure, or wire
format was copied or adapted. New first-party code remains GPL-3.0-or-later.

| Source | Exact revision | D3B/D3D disposition |
| --- | --- | --- |
| root WYR1-D plan, serial/stream contract, bootstrap/recovery architecture, WYR1 B/C contracts and validation, D1/D2/D3A-D3C statuses, and Deepwyrm E2C status | reached workspace state | adapted the exact authority order, staged correlations, MOVE ownership, bounded wait/cleanup, and historical selector boundary |
| Fuchsia Zircon interrupt/resource and narrow driver-manager lifetime files | `6a606ff7fd9b055edee6557566fb3f112df1a812` | concept only: coalesced interrupt wait/ack epochs, capability authority, dependency-first retirement, and host lifetime separation; FIDL, component topology, dynamic linking, devfs, and colocation are not applicable |
| xv6 `uart.c`, `console.c`, `trap.c`, `plic.c` | `35b088427ef37611c38afdeed5a52a278cae38f9` | concept only: disable-before-init and drain UART work before controller completion; RISC-V PLIC, kernel-global console, synchronous echo, descriptors, and line discipline are not applicable |
| rust-osdev `uart_16550` README, `lib.rs`, `config.rs`, `spec.rs`, `backend/pio.rs` | `176b07b076bdc1fe999a5e757ab53a0e24b4005c` | concept only: register ordering and injected backend boundary; direct unsafe port I/O, MMIO, TTY, and spin APIs are not applicable |
| linenoise `linenoise.c`, `linenoise.h` | `a473823d74b93eab2ba83480df16ed37617493f2` | not applicable: line editing, allocation, termios, POSIX descriptors, signals, ioctl, history, and terminal escapes remain outside D3B/D3D |

## Nonclaims and released join

D3B/D3D do not claim selector 31 or 32, a selected product/image, VM or guest
execution, physical IRQ3/IOAPIC routing, COM2 traffic, restart acceptance,
`consoled`/D4, terminal or shell behavior, or a security gate. Native target
checks are compilation evidence only and did not execute PIO. Live acceptance
remains a later product/selector join.
