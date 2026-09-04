# D5 supervision validation checkpoint

Date: 2026-09-04. Construction and host evidence only; no live acceptance.

The selector retains the consoled launch-session owner before polling its first
JobV2 launch. The existing dispatcher maps the retained bootfs authority and
validates its hash-bound launch policy for each request. It is polled before
consoled READY, because consoled waits for its first child's launch response
before becoming ready. Polling borrows the dispatcher in place.

The exact console cleanup status is retained until the matching driver process
has been reaped. The ordinary driver-reaped acknowledgement and WDR5 client
release use the same devmgr Channel in that order. Failed sends retain the
pending status; successful sends consume it once. Native helper tests cover
early release, wrong reaped identity, failed send, and duplicate polling.

Driver-only replacement preserves the bundle, requires a newer attempt,
distinct endpoint ID/generation pair, and newer attach transaction, stream,
console, and child. Child-only replacement preserves every raw-session field
including the attach transaction. Tests use an unchanged endpoint generation
of one across distinct endpoints in the same bundle.

## Correct validation invocations

Run from the Wyrmroot checkout. Every command uses a fresh normalized absolute
target directory inside that checkout's `.tmp`. Host identity verification is
performed by `tools/pinned-cargo`; its compiler is Rust 1.97.1. The launcher
intentionally rejects caller-selected features. For the selector library gate,
use the verified `/opt/rust-bin-1.97.1/bin/cargo` directly with the project
offline Cargo home, host compiler from `.cargo/config.toml`, and explicit
isolated `CARGO_TARGET_DIR`:

```text
cargo test --offline --locked -p wyrmroot-system-init -p wyrmroot-consoled \
  --lib --features wyrmroot-system-init/wyr1d-selector32,wyrmroot-consoled/wyr1d-selector32
cargo clippy --offline --locked -p wyrmroot-system-init -p wyrmroot-consoled \
  --lib --features wyrmroot-system-init/wyr1d-selector32,wyrmroot-consoled/wyr1d-selector32 \
  -- -D warnings
```

Use `--lib` for this host selector gate: selector32 enables `native-init`, and
`--tests` would also try to link the freestanding binary on the host. Run
default-feature integration/source contracts separately through the launcher:

```text
tools/pinned-cargo test --offline --locked -p wyrmroot-system-init \
  -p wyrmroot-consoled -p wyrmroot-runtime --lib --tests
```

The native check uses the accepted compiler at
`artifacts/toolchains/accepted/RUST-WYR0-I-B-SYSROOTS-007/toolchains/wyrmroot-1.97.1-a92dc7f7/bin/rustc`
under the OS-Project root, supplied as Cargo `build.rustc`, with `-D warnings`:

```text
cargo check --offline --locked --target x86_64-unknown-wyrmroot \
  -p wyrmroot-system-init -p wyrmroot-consoled --bins \
  --features wyrmroot-system-init/wyr1d-selector32,wyrmroot-consoled/native-consoled,wyrmroot-consoled/wyr1d-selector32
```

Selector libraries passed 99 system-init and 30 consoled tests. Default gates
passed 94 system-init unit tests, 37 system-init integration/source tests,
27 consoled tests, and 120 runtime unit/source tests. Selector Clippy and both
native binary checks passed with warnings denied.

## Stack budget and remaining evidence

The selector-enabled resident is 32,072 bytes on x86-64. Its specification-only
resident partition is raised from 20 KiB to 40 KiB with headroom. The physical
128 KiB child stack and 20 KiB JobV2 startup block remain unchanged. The D5
dispatcher is no longer moved out of its resident on each tick. Consolidating
the mutually exclusive B/D dispatchers is deferred optimization; actual guest
stack usage and live UP/SMP operation still require product validation.

The consoled observation establishes committed raw Channel output. It does not
prove the UART has emptied its software queue, FIFO, or shift register. The
coordinator must reconcile this with U1 retirement before live acceptance.
