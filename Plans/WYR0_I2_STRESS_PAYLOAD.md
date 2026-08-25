# WYR0 I2 selector-specific runtime-stress payload

## Scope

Schema-v2 selector `smp-runtime-stress` uses test ID 22.  Its image builds
`wyrmroot-i2-stress` and passes that ELF as the existing `hello` image input;
the I2-only `wyrmroot-init0/i2-stress-integration` feature then selects the
`I2Stress` WRLP profile.  Ordinary init0 builds still use `Hello` and ordinary
images still place `wyrmroot-hello` at `bin/hello`.

The I2 controller receives the same explicit three capabilities as init0:
its own AddressRegion, the immutable bootfs MemoryObject, and its delegated
TaskGroup.  It accepts no ambient capability and does not add an ABI record,
syscall, right, or selector transport.

## Bounded live work

The deterministic seed is `0x49325354`; every stage runs at most 32 channel
iterations.  An application failure is `0x22SSOOOO`, where `SS` is the stage
and `OOOO` the exact failed operation.  This propagates through init0's
existing structured Process exit and the selector's terminal result.
Lifecycle waits that depend on another vCPU receiving dispatch use a one-second
active-monotonic bound.  The intentionally tiny nanosecond/millisecond timeout
probes remain unchanged; they test timeout semantics rather than scheduling
latency.

- Handle stage duplicates an immutable bootfs capability, move-transfers it
  through a new Channel, receives and closes it, then proves the closed value
  is stale by querying it.
- Channel/wait stage sends and receives bounded datagrams, observes READABLE,
  fills the queue until the exact `WOULD_BLOCK` backpressure status then drains
  it, verifies a finite active-monotonic timeout, and observes PEER_CLOSED.
- The I2-only audited raw boundary uses generated syscall IDs/types to create,
  set, reset, and wait on a manual Event; it also creates, arms, waits, and
  cancels a one-shot Timer for three finite deadline cycles. Atomic mismatch
  and bounded zero/one wake calls exercise the generated atomic wait/wake path.
- Mapping stage creates a page-backed MemoryObject, maps it RW through the
  delegated root, reduces it to R with `address_region_protect`, unmaps it, and
  closes the object.
- Lifecycle stage maps the immutable bootfs, uses the normal Wyrmroot loader
  to create/start a no-capability leaf copy of the payload, supervises normal
  READY/exit, then starts two command-held leaves before terminating one and
  releasing/supervising the other. A third transaction-selected leaf emits a
  valid READY then executes the narrow test-only `UD2`; its generated EXITED
  record must report `UNHANDLED_EXCEPTION` plus `ILLEGAL_INSTRUCTION`.

## Explicit present limits

The raw boundary exists only because the pinned safe consumer lacks wrappers
for Event/Timer/atomic operations; it does not define a public API or copy ABI
numbers/layouts. Cross-process Event/atomic correlation remains unimplemented:
the launch-channel command protocol establishes the two-live-child overlap but
does not transfer a shared Event or atomic address, so no such correlation is
claimed.

## Live closure evidence

The exact I2 tuple Deepwyrm
`18b59ef6f7b20e3ebf1abc8b793452cb22c5f2c6`, Wyrmroot
`e6072c94c678f97ea5993285346408537e5c28a0`, and Rust
`a92dc7f7464ad6ddfece4402bd7b86dbfa86166d` passed five consecutive canonical
four-vCPU runs without a rebuild or source change. The immutable candidate is
`56670e4a01b6d766c45bfd27a858ae671cbd12066fef439209287e5c253ef2fc`;
its kernel and payload SHA-256 values are respectively
`62c890e3df328ac8e660c6addf101872beed212b3914c6bf2034b7393ba0c089`
and `66d2647242f31ce05e33c2603d95859b4bc56b86e6d230a543f523b58e1506e7`.

The five structured PASS results are preserved under
`artifacts/dw0-i2/checkpoint-dw-18b59ef__wyr-e6072c9__rust-a92dc7f7-live-7/repeats/pass-1`
through `pass-5`. Every result reports schema 2, selector test ID 22, four
vCPUs, 2048 MiB, detail zero, QEMU status 33, and `no_host_share = true`.
This closes the bounded live I2 payload as specified; it does not broaden the
explicit cross-process Event/atomic limit above.

## Build selection

```text
cargo build --offline --package wyrmroot-i2-stress --bin wyrmroot-i2-stress --features native-i2-stress --target x86_64-unknown-wyrmroot
cargo build --offline --package wyrmroot-init0 --bin wyrmroot-init0 --features native-init0,i2-stress-integration --target x86_64-unknown-wyrmroot
```

Supply the first output as the request's `hello` artifact only for the I2
image.  The normal image continues to supply `wyrmroot-hello` and an init0
without `i2-stress-integration`.
