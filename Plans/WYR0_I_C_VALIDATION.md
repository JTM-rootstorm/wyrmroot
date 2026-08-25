# WYR0-I-C bounded native supervision validation

**Date:** 2026-08-24  
**Status:** I-C host/model gate accepted

## Exact implementation identity

| Component | Identity |
| --- | --- |
| Wyrmroot I-C product | `758f31ccebac6661778f7175bb33172b9c339ef5` |
| Wyrmroot parent | `815bde454b15eda1c6e1e57e3d33d1a3048f0474` |
| Deepwyrm checkout and generated-ABI source | `cf45e9b794ef39de4d5a8cbc8f28d3dee0f315d3` |
| Rust fork | `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d` |

This validation document is an evidence-only descendant of the Wyrmroot I-C product revision. I-C changes no Deepwyrm ABI/schema, object, right, syscall, status, scheduler policy, image, selector, or guest payload.

## Implemented boundary

`wyrmroot-runtime` now exposes one allocation-free finite restart policy above the existing exact READY/structured-exit observer. It remains separate from loading, activation, dependency ordering, service discovery/registry, persistent configuration, filesystem control, and final service-manager policy.

The locked WYR0-I policy is represented directly:

- four total attempts, including the initial attempt;
- a four-record fixed terminal history;
- 25 ms fixed replacement backoff;
- a two-second restart window;
- one-second READY and cleanup deadlines; and
- explicit observable `PermanentFailure` after budget/window exhaustion or cleanup failure.

All caller-supplied times are absolute monotonic-active nanoseconds. Checked addition constructs deadlines, timestamp regression fails closed, and timeout wins deterministically at exact deadline equality. READY, terminal, timeout, and cleanup events are bound to the current nonzero generation and transaction; timeout callbacks additionally bind the exact deadline. A replacement advances the generation only after the old generation's terminal classification and exactly-once cleanup acknowledgement. Stale READY, exit, timer, or cleanup events cannot mutate the replacement.

The policy distinguishes creation/start failure, malformed or wrong-transaction READY, duplicate/terminal-drain readiness failure, peer close, wait/exit-query failure, READY timeout, clean/nonzero exit, authorized termination, TaskGroup teardown, unhandled exception, explicit cancellation, and cleanup failure. Cleanup actions tell the native caller whether to close unpublished state, terminate the child TaskGroup, or close already-terminal state without redundant termination. Exact normal zero exit after READY cleans and stops without consuming crash-restart budget.

## Host/model coverage

The runtime tests cover every I-C plan family and the additional race/identity boundaries found during review:

- READY strictly before deadline and timeout at exact equality;
- exit before READY;
- malformed, wrong-transaction, duplicate, and post-exit readiness failure;
- READY followed by normal exit or exception;
- authorized termination and TaskGroup teardown classification;
- startup timeout, bounded TaskGroup cancellation, and cleanup;
- peer close and native wait failure while awaiting READY;
- no early backoff and the exact restart-window boundary;
- fourth failure enters permanent failure once, with no fifth attempt;
- stale READY, exit, and timeout callbacks cannot satisfy a replacement;
- cleanup acknowledgement requires exact generation plus transaction;
- cleanup failure/timeout remains visible and blocks replacement;
- terminal classification time remains distinct from cleanup completion time;
- duplicate events during cleanup cannot release twice;
- monotonic timestamp regression and generation reuse fail closed; and
- deadline, counter, and generation arithmetic overflow fails closed.

No concurrent transition remained ambiguous after explicit generation/transaction/deadline binding, so Loom was not added.

## Validation commands and results

From the exact Wyrmroot product revision:

```text
cargo fmt --all -- --check
cargo test -p wyrmroot-runtime
cargo clippy -p wyrmroot-runtime --all-targets -- -D warnings
cargo test --workspace
```

Results:

- formatting: PASS;
- `wyrmroot-runtime`: 64 unit tests, 10 source-contract tests, and 2 compile-fail doctests passed;
- focused clippy with warnings denied: PASS;
- complete Wyrmroot workspace: PASS, including xtask 92 passed / 1 accepted environment-gated toolchain test ignored; and
- final independent review of the corrected exact diff: no remaining actionable finding.

The one ignored workspace test requires `WYRMROOT_RUSTC` to point at the coordinator-accepted immutable toolchain and is not part of this host-only I-C state-machine gate. I-B already records its positive accepted-toolchain execution.

## Required-source and provenance disposition

The reached WYR0-I capability contract, existing E0 READY/exit and TaskGroup cleanup contract, platform supervision/recovery boundaries, canonical WYR0 plan/addenda, accepted DW0-H READY-drain remediation, and downstream porting-ladder separation materially constrained this implementation.

The complete active prior-art set was consulted at its pinned revisions. Fuchsia/Zircon reinforced endpoint/object identity, atomic capability transfer, terminal-before-reclaim lifetime, and separation between lifecycle and logical instance policy. s6 reinforced explicit finite states, READY separate from start, bounded death history, delayed retry, and permanent failure. The inherited xv6, Redox, and OpenBSD sources reinforced terminal/acknowledgement-before-reclaim ordering; Loom remained an optional model aid only.

No upstream source was copied or substantially adapted. The implementation is first-party code inside the existing `wyrmroot-runtime` `GPL-2.0-or-later` component boundary and imports no POSIX signal, fd, filesystem-control, component-manager, service-registry, or dependency-controller semantics.

## Gate disposition

WYR0-I-C is accepted at Wyrmroot `758f31ccebac6661778f7175bb33172b9c339ef5`. The host/model gate proves finite, generation-safe reusable supervision without a new Deepwyrm primitive or a general service framework.

This closes I-C only. I-D readiness accounting, I-E capability payload/live proof, I-F evidence certificate, final ordinary validation, Daybreak review, and WYR0 completion remain open.
