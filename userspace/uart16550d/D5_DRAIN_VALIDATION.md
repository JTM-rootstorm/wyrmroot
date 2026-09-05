# Selector-32 UART transport fence

The UART feature is `wyr1d-selector32`, which includes `native-uart16550d`.
Devmgr uses its existing `wyr1d-selector32` feature. The implementation follows
`Plans/WYR1_D5_DRAIN_FENCE.md` and reuses the first-party selector-31 ordering:
receive normal WRST, drain/acknowledge IRQ, freshly observe an empty Channel,
then require an empty software ring and hardware LSR.TEMT. No external code
was imported.

UART retains the launch transaction separately from its later READY
transaction. The fence additionally matches the exact active attach
transaction and stream generation. Byte accounting begins at attempt start.
Each attempt accepts one fence; duplicate or crossed requests fail. Devmgr
allows U1 retirement only after successfully forwarding the exact completion.
The pending UART fence uses a 1 ms wait deadline to permit TEMT rechecks and
fails after 2000 timed-out waits. A timeout never establishes drain success.

## Reproducible validation

Use `tools/pinned-cargo` for default host tests with a fresh absolute
`WYRMROOT_PINNED_TARGET_DIR` inside this checkout's `.tmp`. Feature host tests
must use the pinned Cargo directly, as the wrapper rejects feature overrides.
Set `CARGO_HOME` to the OS-Project `.tmp/cargo-home/offline-v1` and use a fresh
absolute checkout-local `CARGO_TARGET_DIR` per compiler/mode. Explicitly prefix
`PATH` with `/opt/rust-bin-1.98.1/bin` for direct Cargo Clippy: Cargo resolves
`cargo-clippy`/`clippy-driver` through PATH even if Cargo and build.rustc are
pinned. Historically, omitting that prefix mixed Clippy 1.98.1 with the then
pinned Rust 1.97.1 and caused an incompatible-metadata error. Keep compiler and
Clippy identities aligned after every host update; that mismatch was a tooling
failure, not a code failure.

Default gate:

```text
tools/pinned-cargo test --offline --locked -p wyrmroot-devmgr -p wyrmroot-uart16550d --lib --tests
```

Feature gates (pinned Cargo):

```text
cargo test --offline --locked -p wyrmroot-devmgr -p wyrmroot-uart16550d --lib --features wyrmroot-devmgr/wyr1d-selector32,wyrmroot-uart16550d/wyr1d-selector32
cargo clippy --offline --locked -p wyrmroot-devmgr -p wyrmroot-uart16550d --lib --features wyrmroot-devmgr/wyr1d-selector32,wyrmroot-uart16550d/wyr1d-selector32 -- -D warnings
```

Native checks use the accepted Wyrmroot compiler named in
`userspace/system-init/D5_VALIDATION.md`, `--target x86_64-unknown-wyrmroot`,
`--bins`, the two selector features, and `RUSTFLAGS='-D warnings'`.
The selector-31 regression check substitutes `dw1e3-selector31` for both
features and must set `DEEPWYRM_DW1E_EVIDENCE_NONCE=E300000000000001` for the
compile-time evidence binding, as the canonical selector-31 builder does.
Omitting that binding produces an intentional compile-time error.

Tests cover bytes queued before the request, cumulative partial acceptance,
three 16-byte FIFO epochs for a 45-byte response, post-ack software-empty but
TEMT-false state, exact completion/retirement ordering, stale identities,
duplicates, failed-forward preservation, and over-target bytes. Host and
native construction checks do not establish live COM2 or UP/SMP acceptance.

On 2026-09-04 the default gate passed 70 tests (33 devmgr model, 12 devmgr
source, 11 UART model, 13 UART source, and 1 connector integration). The
selector-32 library gate passed 49 tests (35 devmgr, 14 UART). Pinned Clippy
and native binary checks for both selector 32 and selector 31 passed with
warnings denied. The consumed source base was
`11f6715e07a27b8a91129470e17d6ba3970fe787`; generated Deepwyrm ABI stayed at
`085b184c32ae1fa3d5ec322c86957dd5d036595c`. No VM was inspected or operated.
