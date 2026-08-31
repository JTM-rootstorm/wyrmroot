# WYR1-D2 implementation status

**Status:** Reached host-testable UART-core gate
**Reached:** 2026-08-31
**Scope:** bounded, no-std 16550 register policy only
**Authority:** root `DW1E_WYR1D_IMPLEMENTATION_PLAN.md` D2 and
`Plans/WYR1_D_SERIAL_STREAM_CONSOLE_CONTRACT.md`

## Exact baseline and files

This lane began at Wyrmroot `b6b97350ee2c94da393db62862c81d7602a44b7f`.
The paired Deepwyrm E0 baseline was
`16722c1b86ff9da7ed18208c78bb0c690b7d5215`; D2 changes no Deepwyrm source or
ABI.

- `crates/wyrmroot-uart16550-core/Cargo.toml` — GPL-3.0-or-later, no-std
  package definition.
- `crates/wyrmroot-uart16550-core/src/lib.rs` — injected byte-register trait,
  exact staged initialization, fixed rings, bounded IIR service, sticky
  saturating diagnostics, and fake-register unit tests.
- root `Cargo.toml` and `Cargo.lock` — workspace admission only.
- this status record and the architecture-index entry — reached-state receipt.

The closing lane handoff records the final commit identity and committed-source
hash; no pre-commit hash is treated as final evidence.

## Reached behavior

`Uart16550<I>` has no allocation, unsafe code, port constants used for I/O, or
production syscall dependency. Its adapter trait is only `read(offset)` and
`write(offset, byte)`.

- `initialize_quiesced()` writes IER zero first; programs divisor one, 8N1,
  enabled/cleared FIFO, and `OUT2 | RTS | DTR`; drains stale state with a 256
  cause limit; and returns with IER still zero.
- `activate_interrupts()` separately enables RDI and RLSI, plus THRI if bytes
  were queued during the quiesced stage. While active, THRI is enabled exactly
  when TX is nonempty and is disabled immediately after the TX ring empties.
- RX and TX are separate 4096-byte fixed rings. RX continues consuming RBR on
  overflow, drops newest bytes, and saturates a distinct software-overrun
  counter. TX returns the unsent suffix to its caller by accepting only the
  prefix that fits.
- IIR service explicitly covers RLSI, RDI, receiver timeout, THRI, MSI, and
  invalid encodings. MSI reads MSR and records unexpected modem status; an
  invalid cause or either exhausted drain limit disables IER and yields a
  fail-closed error. One caller acknowledgement is therefore after all
  currently indicated UART work, not after each byte.

## Validation

All commands used the pinned Rust 1.97.1 launcher and a lane-local target
directory `/tmp/wyr1d-d2-target`:

```text
WYRMROOT_PINNED_TARGET_DIR=/tmp/wyr1d-d2-target tools/pinned-cargo test -p wyrmroot-uart16550-core --lib
# 9 passed, 0 failed
WYRMROOT_PINNED_TARGET_DIR=/tmp/wyr1d-d2-target tools/pinned-cargo clippy -p wyrmroot-uart16550-core --lib --tests -- -D warnings
# passed
WYRMROOT_PINNED_TARGET_DIR=/tmp/wyr1d-d2-target tools/pinned-cargo fmt --all -- --check
# passed
```

The fake-register suite proves exact quiesced writes, activation separation,
all IIR paths, line/error accounting, 16-byte THRI fill, 4096-byte drop-newest
RX overflow, TX empty-transition toggling, both 256-cause limits, and sticky
saturating counters. The core offers no idle-poll API; device reads occur only
in initialization or a caller-declared interrupt service.

## Required-source receipt and provenance

All listed sources were read at the exact revisions below. They informed an
independent implementation; no upstream source, ABI, data structure, or code
was copied. This new first-party crate is explicitly GPL-3.0-or-later.

| Source | Revision | Use | Outcome |
| --- | --- | --- | --- |
| root plan and WYR1-D contract | reached workspace state | staged order, exact bounds, q35 policy | adapt |
| current device-proto/runtime and WYR1-C contracts | reached workspace state | ownership boundary and no production adapter | adapt |
| retained selector-29 `uart16550d` actor | reached workspace state | preserve historical artifact unchanged | not-applicable as architecture |
| Fuchsia Zircon interrupt/resource and driver-manager separation | `6a606ff7fd9b055edee6557566fb3f112df1a812` | bounded lifetime/authority separation | concept only |
| xv6 `uart.c`, `console.c`, `trap.c`, `plic.c` | `35b088427ef37611c38afdeed5a52a278cae38f9` | cause-drain ordering only | concept only; RISC-V/PLIC/global-console model not applicable |
| rust-osdev `uart_16550` README, lib/config/spec/pio | `176b07b076bdc1fe999a5e757ab53a0e24b4005c` | register names, no-std adapter shape, init ordering | concept only; MIT notice not required because no code was adapted |
| linenoise | `a473823d74b93eab2ba83480df16ed37617493f2` | terminal/newline comparison | not applicable; D2 is raw UART policy only |

Pinned-source SHA-256 receipts are retained in the task-owned prior-art cache:
Fuchsia `interrupt_dispatcher.cc` `8fcf75bfa8d47d99549266f2b097041d754cccf05dbeb052d18fea3f374f6a70`,
`resource_dispatcher.cc` `db1bfb63e8175d25916d1abcdd4f0a0c13f6c1cc379e57145f0ec7ead7f7e678`;
xv6 `uart.c` `6c284f94eb8fcca9c723015f366a849a441f462b99d16e3cca5880439df6a493`;
and rust-osdev `src/lib.rs` `6ece78f79b483ebd4ff5a2673c9381c41946020a110174f4929ac2ecf3100376`.

## Released D3 seam and nonclaims

D3 may implement a typed `DeviceResource` PIO adapter for `ByteRegisterIo`,
call quiesced initialization before fresh Interrupt validation, call activation
only after that validation, and acknowledge an Interrupt only after a
successful `handle_interrupt()` drain. It must add its own ownership,
generation, process, connector, and live-validation proof.

This record does **not** claim a DeviceResource adapter, real port I/O,
physical IRQ3/IOAPIC behavior, a production `uart16550d`, stream connector,
`devmgr`, `consoled`, selector 31/32, VM acceptance, COM2 traffic, or a
change to selector-29/WRDC 1.0. It also does not claim a security closure.
