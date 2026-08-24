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

- Handle stage duplicates an immutable bootfs capability, move-transfers it
  through a new Channel, receives and closes it, then proves the closed value
  is stale by querying it.
- Channel/wait stage sends and receives bounded datagrams, observes READABLE,
  verifies a finite active-monotonic timeout, and observes PEER_CLOSED after
  closing the peer.
- Mapping stage creates a page-backed MemoryObject, maps it RW through the
  delegated root, reduces it to R with `address_region_protect`, unmaps it, and
  closes the object.
- Lifecycle stage maps the immutable bootfs, uses the normal Wyrmroot loader
  to create/start a no-capability leaf copy of the payload, supervises normal
  READY/exit, then creates/starts a second leaf and issues a real authorized
  Process termination before waiting for terminal retirement.

## Explicit present limits

The pinned generated ABI has `atomic_wait32`/`atomic_wake` but no safe wrapper
in `deepwyrm-syscall`; it has Event/Timer object definitions, but the pinned
consumer crate does not expose `event_create`, `event_signal`, or timer setup.
It also has no standalone wait-cancellation syscall.  I2 consequently uses
the closest available real primitives: Channel level signals, finite
active-monotonic deadlines, peer-close, structured child terminal state, and
authorized process termination.  Remote address-space residency, exception
child delivery, subtree-authority rejection, queue backpressure saturation,
and PM-timer idle/wake cycles require either existing test-support wrappers or
the paired Deepwyrm selector implementation; they are deliberately not faked
by this payload.

## Build selection

```text
cargo build --offline --package wyrmroot-i2-stress --bin wyrmroot-i2-stress --features native-i2-stress --target x86_64-unknown-wyrmroot
cargo build --offline --package wyrmroot-init0 --bin wyrmroot-init0 --features native-init0,i2-stress-integration --target x86_64-unknown-wyrmroot
```

Supply the first output as the request's `hello` artifact only for the I2
image.  The normal image continues to supply `wyrmroot-hello` and an init0
without `i2-stress-integration`.
