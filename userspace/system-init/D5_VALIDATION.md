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

The exact offline home is
`/home/mike/Documents/Programming/OS-Project/.tmp/cargo-home/offline-v1`,
not `wyrmroot/.tmp/cargo-home/offline-v1`. A checkout-relative guess produces
an offline dependency-checkout error before compilation; it is not a product
failure. For direct feature checks set `CARGO_HOME` to that absolute root
path, and prefix `PATH` with `/opt/rust-bin-1.97.1/bin` so Clippy also uses the
verified host version. Default gates continue through the launcher, which
owns these settings and rejects a caller-supplied `CARGO_HOME`.
Neighbor selector-31 native checks also require the compile-time
`DEEPWYRM_DW1E_EVIDENCE_NONCE` (for example `0000000000000106`). Omitting it
fails the existing runtime `env!` before the selected binary is checked;
selector 32 obtains its nonce from the frozen gate configuration instead.

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

The subsequent transport-drain fence raises the system-init selector suite to
100 tests. One retained batch withholds record 8/U1 retirement and record 12
until the exact devmgr-forwarded UART `TxDrained` completion. Its identity
includes the driver launch transaction and the distinct connector attach
transaction, stream, fixed target (45/46 bytes), and leg (2/4). A request is
marked sent only after Channel commit; an unsolicited, stale, duplicate,
expired, or unsent completion cannot release the batch. Completion consumes
the pending fence before publication, so a later submission/send failure
cannot replay its record. The supervisor uses the existing bounded cleanup
deadline while normal dispatcher polling continues. Tests cover the complete
four-leg sequence, held retirement/terminal action, failed request send,
wrong identity, duplicate request/completion, and deadline equality.

## Stack budget and remaining evidence

The selector-enabled resident including the pending drain batch and retirement
join is 33,384 bytes on x86-64 (GDB host type inspection; previously 33,320).
Its specification-only
resident partition is raised from 20 KiB to 40 KiB with headroom. The physical
128 KiB child stack and 20 KiB JobV2 startup block remain unchanged. The D5
dispatcher is no longer moved out of its resident on each tick. Consolidating
the mutually exclusive B/D dispatchers is deferred optimization; actual guest
stack usage and live UP/SMP operation still require product validation.

The consoled observation establishes committed raw Channel output. UART
transmission completion is supplied through the selector-private drain fence
specified in `Plans/WYR1_D5_DRAIN_FENCE.md`. The paired devmgr/UART implementation
must be integrated and the full frozen product validated live before acceptance.

## A1 GDB and broader join corrections

The frozen A1 pair failed before D5READY. GDB A1-02 captured the exact connector
STALE branch: the request publication was `0xC10801`, but devmgr had incorrectly
substituted registry lifetime `1`. WRCS 1.1 now carries the owner-issued service
generation; see `Plans/WYR1_D5_PUBLICATION_HANDOFF.md`. A1-01 also recorded
devmgr `C10100BA` and consoled's eventual `D400001A`. Its wait-capacity trap
did not fire. The independent kernel wait-budget correction is justified by
the full actor graph, not attributed to that early failure.

Broader transition review identified two independent races before another
freeze. A selector-owned retirement join now records DriverRetired without
blocking, continues job/status polling, and claims rebind once only after exact
ClientReleased has successfully been sent. This preserves same-Channel FIFO
release-before-rebind in either fact arrival order. Its absolute cleanup
deadline begins after the retirement request commits; failure/expiry cannot
open a second replacement. Driver-reap remains a separate prerequisite for
the release send.

A queued OBSERVED status may arrive after the same child has exited/reaped.
It now uses the retained exact accepted READY identity instead of requiring
the historical child to remain live. The Gate still checks sequence, nonce,
full tuple, job, publication, client transaction, leg and response hash. New
READY still requires a current nonterminal JobV2, and replacement READY still
requires old cleanup. No sleep or host timing assumption establishes success.

At the A2 preparation checkpoint: default devmgr 35 and init 95 tests pass;
selector-32 devmgr 37 and init 103 pass; full default workspace reports 1,067
passing executions across 76 summaries, zero failures and one existing ignore.
Default workspace and selected-library Clippy pass with warnings denied, as
do native checks of all four D5 actors and neighboring selector-31 init/devmgr.
Tests cover helper joins, both fact orders, failed-send retention, timeout,
one-shot rebind and post-reap observation identity. They do not substitute for
the full native callback/VM sequence. Source review found no further blocker
in the prescribed D5 path. General registry-only broker refresh remains the
separate limitation recorded in the publication handoff.

## A2 GDB and JobV2 stream-hop correction

The exact A2 product still failed both live profiles before D5READY. This was
a different demonstrated cause: low-overhead GDB traced consoled exit
`D400002F`, and its actual 56-byte WRLJ reply contained `ERROR` code 7
(`PolicyRejected`). Init's existing exact Channel validator rejected the
three streams before task-group or loader construction: consoled had removed
`TRANSFER` on the first hop instead of the final child hop.

Consoled now uses the existing authoritative
`CHILD_CHANNEL_TRANSFER_RIGHTS` in its native descriptor constructor. Init's
validator and the loader's final reduction remain unchanged. The regression
compiles that same constructor and executes it through actual init validation,
actual `load_job_process` INIT/MOVE generation, and the actual JobV2 child
parser. It also rejects early reduction and excess `DUPLICATE` at ingress.
This connects the previously isolated native sender and consumer assumptions.

The selected suites now pass devmgr 37/init 105 tests, and all four native D5
actors check with warnings denied. Full workspace and VM results must be
recorded separately; A2 remains immutable and not accepted. Broader review
found no additional demonstrated defect in policy/artifact matching, startup
ordering, bootfs mapping lifetime, or static stack/resource estimates. Those
estimates are not live high-water measurements.
