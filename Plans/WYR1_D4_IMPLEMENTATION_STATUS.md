# WYR1-D4 implementation status

**Status:** Reached WYR1-D4 host/model and native-build gate

**Reached:** 2026-09-04

**Base Wyrmroot revision:** `06299cf0a2f8f5db8b582b862b278e8b2bd9eb38`

**Scope:** production `consoled` startup, serial/child generation ownership,
bounded stream brokerage, and native target construction; no selector 32,
product-image, VM, or live COM2 acceptance

## Reached behavior

Wyrmroot now has a dedicated static `userspace/consoled` process and WRLP
1.10 `Consoled` launch profile. The profile accepts exactly the existing
self-root AddressRegion, registry-client Channel, and launch-session Channel.
It grants no DeviceResource, Interrupt, raw PIO, boot-device, or debug-write
authority. The canonical child path is `bin/console-echo`; selecting and
placing that child in the acceptance image remains D5 work.

The host model owns the full serial and child lifecycle rather than treating
reconnect as a set of unrelated callbacks. It:

- binds lookup, connector, publication, driver, stream, console, launch, job,
  and child-stream identities to exact nonzero generations and transactions;
- mints a fresh console generation only after a correlation-exact serial
  attachment and moves exactly the three JobV2 stdin/stdout/stderr endpoints;
- keeps serial invalidation and child retirement as orthogonal cleanup
  obligations, so either event ordering converges without losing the other;
- preserves a healthy serial attachment across child-only replacement while
  keeping child exhaustion separate from serial reconnect exhaustion;
- requires evidence for every locally closed or remotely revoked endpoint
  before a partial launch may be forgotten or a replacement admitted;
- rejects stale READY, launch, cleanup, stream, child, and publication events
  without mutating the current generation; and
- exposes bounded snapshot state for pending connect/launch cleanup, stream
  liveness, restart windows, exhaustion, and the last failure category.

The byte model applies the frozen directional semantics: serial RX normalizes
CR/LF into child stdin, while child stdout and stderr independently normalize
LF to CRLF for serial TX. Cross-record CR/LF state is preserved. Each source
uses bounded 4096-byte staging with 1024-byte service quanta; reservations are
committed only after the corresponding atomic WRST send succeeds. Full queues
mask further reads and `WOULD_BLOCK` retains queued data.

The native no-std broker composes the reached registry, WRSC 1.1, WRST, JobV2,
and runtime Channel APIs. It maintains one exact outstanding publication
`WATCH`, performs lookup and connector negotiation, validates the complete
returned connector identity and handle rights, and watches publication
retirement for the lifetime of the serial attachment. Cancelling a watch or
JobV2 wait drains the exact transaction and accepts only the specified
terminal-vs-cancel race.

Control and retirement signals win over data. Fixed child peer-close slots
precede a rotating raw/stdin/stdout/stderr data order, preventing a
continuously ready lower-index source from starving another stream. Readiness
is masked by staging capacity, raw peer-close and publication retirement
invalidate the console before a co-ready launch reply can win, and stable-run
time advances even under continuous traffic.

Launch-session observation is transactional: one exact JobV2 `WAIT` remains
outstanding for the active child. A `JobResult` is already terminal evidence,
so the broker closes the three streams and the job record without requesting
a second termination. If serial or publication retirement wins, it cancels or
drains that wait, closes child peers, requests termination only when needed,
reaps the job, completes all pending launch cleanup, and only then admits a
fresh serial generation. Cleanup uncertainty fails closed.

The review was deliberately broader than the immediate event-loop path. It
covered registry publication lifetime, connector and lookup correlation,
partial MOVE states, JobV2 cancellation and terminal races, both retirement
orders, failure-window boundaries, starvation, readiness masking, and
fail-closed cleanup visibility. The resulting model has direct regression
coverage for the joined transition matrix rather than one test per observed
symptom.

## Validation

Host commands used the pinned Rust/Cargo 1.97.1 launcher. Each invocation set
`WYRMROOT_PINNED_TARGET_DIR` to a fresh project-local directory and used locked,
offline dependencies.

```text
tools/pinned-cargo test --offline --locked -p wyrmroot-consoled --lib --tests
# 26 tests passed

tools/pinned-cargo clippy --offline --locked \
  -p wyrmroot-consoled -p wyrmroot-loader -p wyrmroot-runtime \
  -p wyrmroot-registry-proto --lib --tests -- -D warnings
tools/pinned-cargo fmt --all -- --check
# passed

tools/pinned-cargo test --offline --locked --workspace --lib --tests
# passed; 244 xtask unit tests, 1 ignored, plus every workspace library and
# integration-test target completed without failure
```

Focused pre-join regressions also passed: 104 runtime unit tests plus 16
source-contract tests, 22 bootstrap transaction tests, 64 loader tests, and 8
registry-protocol tests.

The native construction gate used immutable accepted compiler/toolchain
`wyrmroot-1.97.1-a92dc7f7`, isolated project-local Cargo state, locked offline
dependencies, deterministic path remapping, and warnings denied:

```text
accepted-cargo check --offline --locked --target x86_64-unknown-wyrmroot \
  --package wyrmroot-consoled --bin consoled --features native-consoled
# passed with -D warnings
```

## Required-source receipt and provenance

All external use was conceptual; no upstream code, ABI, structure, or wire
format was copied or adapted. New first-party code remains GPL-3.0-or-later.

| Source | Exact revision | D4 disposition |
| --- | --- | --- |
| root `DW1E_WYR1D_IMPLEMENTATION_PLAN.md`, WYR1-D serial/stream contract, bootstrap/recovery architecture, Wyrmroot architecture index, WYR1-B launch/registry contracts, and D1 through D3 implementation records | reached workspace state | supplied the authority order, WRLP/JobV2 ownership, finite-recovery rules, exact generation joins, bounded pressure, and D4/D5 boundary |
| Fuchsia Zircon interrupt/resource and driver-manager lifetime sources | `6a606ff7fd9b055edee6557566fb3f112df1a812` | concept only: dependency-first retirement and generation/lifetime separation; FIDL, component topology, dynamic linking, devfs, and colocation are not applicable |
| xv6 `uart.c`, `console.c`, `trap.c`, and `plic.c` | `35b088427ef37611c38afdeed5a52a278cae38f9` | concept only: bounded drain and retirement ordering; kernel-global console, synchronous echo, descriptors, and line discipline are not applicable |
| rust-osdev `uart_16550` README and implementation/configuration files | `176b07b076bdc1fe999a5e757ab53a0e24b4005c` | concept only: register/driver boundary; direct port I/O, MMIO, TTY, and spin APIs are not applicable |
| linenoise `linenoise.c` and `linenoise.h` | `a473823d74b93eab2ba83480df16ed37617493f2` | not applicable: editing, history, allocation, termios, POSIX descriptors, signals, ioctl, and terminal escapes remain outside D4 |

## Nonclaims and released join

D4 does not claim selector 32, a selected product/image, VM or guest execution,
COM2 traffic, a live `/bin/console-echo` session, WRD1 acceptance records,
terminal/TTY semantics, shell behavior, WYR1-E, or a security gate. The native
target check is construction evidence only and did not execute hardware I/O.

D5 may now join this exact consoled transport path to the selector-32 product
and prove generation replacement, byte flow, backpressure, isolation, and
cleanup in the guest without changing the frozen D4 ownership model.
