# WYR1-D3A/D3C implementation status

**Status:** Reached D3A and D3C host/model gates
**Reached:** 2026-08-31
**Base Wyrmroot revision:** `ec7d863ff310f8ab6c655c735f3f64a821e23424`
**Scope:** production UART DeviceResource staging plus direct serial-connector
codec/ownership model; no Interrupt activation or raw byte event loop

## Reached behavior

WRDC 1.1 is implemented in a separate allocation-free codec. It retains the
72-byte common header but accepts only the production minor and the exact
`DEVICE_STAGE`, `DEVICE_QUIESCED`, `INTERRUPT_STAGE`, `ATTACH_STREAM`,
`STREAM_READY`, `STREAM_DETACHED`, `DRIVER_READY`, `DRIVER_FAILURE`, and
`RETIRE` shapes. Exact sizes, embedded handle counts, identities, reserved
bytes, and nonzero stage/stream/publication correlations fail closed. The
selector-29-only intentional-restart failure is not legal in the 1.1 codec.
The existing WRDC 1.0 codec and its byte values were not changed.

The new `userspace/uart16550d` package is distinct from
`userspace/wyr1-retained-stubs`. Its D3A policy:

- admits exactly one DeviceResource at exact
  `READ | WRITE | INSPECT`, resource ID 1, lease/bundle generation, PIO
  `[0x2f8,0x300)`, and source 3;
- validates all startup/attempt/control/stage correlation before register I/O;
- uses the D2 core to run `initialize_quiesced()` with IER zero first and
  returns correlation-exact `DEVICE_QUIESCED` only while the core remains
  quiesced; and
- supplies a target-compiling native D3A entry that closes malformed or
  rejected transferred handles and stops before parsing `INTERRUPT_STAGE`.

Devmgr now owns a narrow `DeviceStageCoordinator` seam. It allocates a stage
generation and a transaction distinct from launch, records the one-handle MOVE
only after send commits, and will not leave `AwaitingQuiesced` without the
exact reply. It intentionally exposes no Interrupt-stage constructor.

WRSC 1.1 is an independent fixed 128-byte codec. Minor 0, wrong records,
handle counts, results, zero identities, and reserved data fail closed. The
stable service/protocol identity now has a separate product-gated minor-1
publication constant; the historical minor-0 publication constant is still
the selector-29 default.

The devmgr connector broker makes native handle actions explicit:

- pre-MOVE owns both endpoints in devmgr and closes both on failure;
- post-MOVE pending retains only the client endpoint while the driver owns its
  peer;
- `STREAM_READY` must match the exact publication/driver/attach/stream chain
  before `CONNECTED` may MOVE the retained client endpoint;
- at most one pending or active stream exists; stale READY/detach events do not
  mutate the slot;
- attach/reply failure, client-first or driver-first detach, and retirement
  preserve the remaining endpoint owner until exact release is observed; and
- a healthy driver generation may reconnect only after both endpoints from the
  prior stream are released, with fresh attach and stream generations.

The new driver-side `StreamAttachment` model consumes that exact
`ATTACH_STREAM`, validates one Channel at
`READ | WRITE | WAIT | INSPECT`, emits correlation-exact `STREAM_READY`, and
returns `STREAM_DETACHED` on release. It performs no WRST byte I/O. The joined
host test proves devmgr-to-driver attach, client connection, two-sided release,
and reconnect.

## Validation

Host commands used the pinned Rust/Cargo 1.97.1 launcher and isolated
lane-owned target directories under `/tmp/wyr1d-d3ac-*-target`:

```text
tools/pinned-cargo test -p wyrmroot-device-proto --lib --tests
# 42 unit + 9 D0 model tests passed
tools/pinned-cargo test -p wyrmroot-devmgr --lib --tests
# 23 unit + 12 native-source regression tests passed
tools/pinned-cargo test -p wyrmroot-uart16550d --lib --tests
# 3 unit + 1 joined D3C integration tests passed
tools/pinned-cargo clippy -p wyrmroot-device-proto --lib --tests -- -D warnings
tools/pinned-cargo clippy -p wyrmroot-devmgr --lib --tests -- -D warnings
tools/pinned-cargo clippy -p wyrmroot-uart16550d --lib --tests -- -D warnings
tools/pinned-cargo fmt --all -- --check
# all passed
```

The native source/build gate used the immutable accepted Wyrmroot compiler
`wyrmroot-1.97.1-a92dc7f7` and its built-in
`x86_64-unknown-wyrmroot` target, isolated under
`/tmp/wyr1d-d3ac-native-target`:

```text
accepted-cargo check --offline --locked --target x86_64-unknown-wyrmroot \
  --package wyrmroot-uart16550d --bin uart16550d \
  --features native-uart16550d
# passed with -D warnings and deterministic path remapping
```

## Required-source receipt and provenance

All external use was conceptual; no upstream code, ABI, structure, or wire
format was copied or adapted. New first-party files are GPL-3.0-or-later.

| Source | Exact revision | D3A/D3C disposition |
| --- | --- | --- |
| root plan, WYR1-D contract, recovery architecture, Wyrmroot architecture index, WYR1-C handoff/validation, D1/D2 status and current device/runtime source | reached workspace state | adapt exact version separation, stage order, MOVE ownership, fresh generations, and historical selector boundary |
| Fuchsia Zircon interrupt/resource and driver-manager `resource`, `node`, `driver_host`, and `driver_runner` files | `6a606ff7fd9b055edee6557566fb3f112df1a812` | concept only: coordinator/driver authority separation, dependency-first retirement, and not reusing dying hosts; FIDL, component topology, dynamic linking, devfs, and colocation are not applicable |
| xv6 `uart.c`, `console.c`, `trap.c`, `plic.c` | `35b088427ef37611c38afdeed5a52a278cae38f9` | concept only: disable-before-init and drain-before-controller-complete; RISC-V PLIC, kernel-global console, synchronous echo, fd and line discipline are not applicable |
| rust-osdev `uart_16550` README, `lib.rs`, `config.rs`, `spec.rs`, `backend/pio.rs` | `176b07b076bdc1fe999a5e757ab53a0e24b4005c` | concept only: register ordering and injected backend boundary; direct unsafe in/out, MMIO, TTY and spin APIs are not applicable |
| linenoise `linenoise.c`, `linenoise.h` | `a473823d74b93eab2ba83480df16ed37617493f2` | not applicable to D3A/D3C: line editing, allocation, termios, POSIX descriptors, signals, ioctl, history and terminal escapes remain outside this phase |

The reread cache matched the D0 hashes, including Fuchsia `resource.cc`
`eae8e971...`, `node.cc` `9f3223cc...`, `driver_host.cc` `e5366cbf...`,
`driver_runner.cc` `7cce7060...`; xv6 `uart.c` `6c284f94...`; and
rust-osdev `src/lib.rs` `6ece78f7...`.

## Nonclaims and released join

D3A/D3C do not claim a live Interrupt, IER activation, wait/drain/ack loop,
physical IRQ3/IOAPIC behavior, raw WRST byte transfer, graceful stream event
loop, selected product/image, selector 31 or 32, VM acceptance, COM2 traffic,
`consoled`, terminal/shell behavior, or security closure. The native driver
target check is compilation evidence only; it did not execute PIO.

D3B must join the exact post-`DEVICE_QUIESCED` state to a fresh validated
Interrupt before enabling RDI/RLSI. D3D must join the existing connector
ownership model to the WRST event loop and preserve its release ordering.
