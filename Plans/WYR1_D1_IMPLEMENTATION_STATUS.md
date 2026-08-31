# Wyrmroot WYR1-D1 Implementation Status

**Status:** Reached WYR1-D1 host gate

**Base Wyrmroot revision:** `b6b97350ee2c94da393db62862c81d7602a44b7f`

**Scope:** production WRST v1 codec, bounded `NativeInput`/`NativeOutput`,
JobV2 stream-role validation, and the selected native-stdout hello source.

## Delivered seam

`wyrmroot-stream-proto` is an allocation-free, `no_std`, byte-defined codec.
It accepts exactly the 24-byte WRST v1 DATA header and at most 1024 payload
bytes; it does not cast Channel bytes into Rust structures and has no syscall
dependency. Wrong magic/version/header/type/flags/reserved fields, overflow,
size mismatch, trailing data, and oversized payload fail closed.

`wyrmroot-runtime` exposes bounded wrappers around an exact child Channel:

- `NativeInput` retains at most one decoded 1024-byte record, drains it across
  caller-sized reads and immediately available subsequent records until the
  output fills or Channel `WOULD_BLOCK`, treats a zero caller buffer as a
  no-op, and maps a fresh peer-close-only wait to explicit EOF;
- `NativeOutput` packetizes arbitrary caller input into successive at-most-
  1024-byte DATA records and returns the total committed count; a later
  `WOULD_BLOCK` returns prior progress, while its bounded blocking helper waits
  on the reached native wait primitive before retrying the caller-owned suffix;
- runtime `wait_readable`/`wait_writable` helpers call the reached wait
  primitive with the exact READABLE/WRITABLE plus PEER_CLOSED masks;
- malformed/count-invalid/handle-bearing receives close all known transferred
  handles before making the input endpoint terminally failed; and
- `extract_job_v2_streams` first applies the reached WRLP JobV2Streams parser,
  then exposes only the validated stdin/stdout/stderr ordered tuple.

The new `wyrmroot-stream-hello` native source uses `NativeOutput` for the
selected stdout greeting. It contains no diagnostic/debug-write success path.
Historical hello and selector-29 artifacts remain unchanged.

## Required-reading receipt

| Source | Disposition |
| --- | --- |
| root `DW1E_WYR1D_IMPLEMENTATION_PLAN.md`, D1 and required-reading sections | adapt: exact grammar, bounds, partial-I/O, peer-close, and non-goals |
| `Plans/ARCHITECTURE_INDEX.md` and `WYR1_D_SERIAL_STREAM_CONSOLE_CONTRACT.md` | adapt: Wyrmroot ownership, frozen WRST v1 grammar, and D0 vectors |
| `Plans/WYR1_B_REGISTRY_LAUNCH_CONTRACT.md` and current loader launch parser | adapt: exact JobV2 three-role order and full-duplex Channel rights |
| WYR1-C coordinator/handoff/validation and current device protocol | not-applicable to D1 implementation; preserved selector-29 and generation boundaries |
| current runtime native/wait/startup wrappers | adapt: complete-datagram validation, exact wait signals, native error preservation |
| retained `uart16550d` actor | not-applicable as a D1 architecture template; preserved unchanged |
| Fuchsia `6a606ff7fd9b055edee6557566fb3f112df1a812` interrupt/resource and driver-manager pieces | concept: separate lifetime/authority domains; no ABI/code imported |
| xv6 `35b088427ef37611c38afdeed5a52a278cae38f9` UART/console/trap/PLIC | concept: byte-flow only; RISC-V, global console, fds, and line discipline not applicable |
| rust-osdev `uart_16550` `176b07b076bdc1fe999a5e757ab53a0e24b4005c` | not-applicable to D1 production code; D2 owns register policy |
| linenoise `a473823d74b93eab2ba83480df16ed37617493f2` | negative comparison only; terminal control, POSIX fds, and line editing remain out of scope |

No external code, ABI, structure, or wire format was copied.

## Evidence and validation

The commit handoff records the exact Wyrmroot head and hashes of the changed
source/status files. Host validation covers arbitrary binary bytes, a 1024-byte
record, malformed headers/trailing bytes, partial input, zero-sized reads,
`WOULD_BLOCK`, peer-close, concatenated records, partial final records,
multi-record output, terminal malformed-input behavior, wait/retry races, and
packetized output. Product/native compilation
is a source/build gate only; this status claims no VM or live serial behavior.

Pre-commit source hashes:

| File | SHA-256 |
| --- | --- |
| `crates/wyrmroot-stream-proto/src/lib.rs` | `3c26f597ef5be31e420146902ca288f52996ca896e6802189b3603d198d4bf45` |
| `crates/wyrmroot-runtime/src/stream.rs` | `642d36bcc20abd383d36bd7873451aafcb576ad0eb71494a34181acb60420227` |
| `userspace/hello/src/lib.rs` | `ebde1dbc05622a00a4658de49a26fbc63e0ab9cefc9a90b864800fa24b0ce8e5` |
| `userspace/hello/src/stream_main.rs` | `cec66aabf01f727728406bf8a80b2dc93fb58d4f32449894135c707638a13776` |

## Nonclaims and released successors

This gate does not claim UART register I/O, IOAPIC/IRQ3, production
`uart16550d`, connector activation, consoled, selector-31/32, terminal or
shell behavior, POSIX descriptors, or physical hardware. D2 may independently
implement the pure UART core. D3 consumes the wrappers for driver stream I/O;
D4 consumes them for consoled and native child routing.
