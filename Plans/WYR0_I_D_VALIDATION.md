# WYR0-I-D bounded readiness accounting validation

**Date:** 2026-08-24  
**Status:** I-D host/accounting gate accepted

## Exact implementation identity

| Component | Identity |
| --- | --- |
| Wyrmroot I-D product | `bc81924aaf59fcd01bb009155c1f8ee96fa97e19` |
| Wyrmroot parent | `a1299c4fd54fc94db20eff3b79edcd50d979e067` |
| Deepwyrm checkout and generated-ABI source | `cf45e9b794ef39de4d5a8cbc8f28d3dee0f315d3` |
| Rust fork | `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d` |

This validation document is an evidence-only descendant of the Wyrmroot I-D product revision. I-D changes no Deepwyrm ABI/schema, object, right, syscall, status, scheduler policy, image, selector, or guest payload.

## Implemented boundary

`wyrmroot-runtime` now exposes one allocation-free readiness ledger for controller-owned admission. Four fixed peer slots carry canonical per-peer and aggregate budgets for live generations, in-flight transactions, replay entries, retained messages/bytes/handles, shared MemoryObjects/bytes, mappings, waits, events, timers, and restart history. The ledger uses fixed arrays only; it has no dynamic collection, allocator, host-personality, or filesystem-control dependency.

Reservations are checked across every requested resource before any counter is committed. Affine, non-cloneable tokens bind release/publication to one internally unique controller, peer, and generation. Checked addition/subtraction rejects overflow, underflow, double release, cross-controller use, and stale identity. Controller cleanup must release every externally meaningful per-generation reservation before retirement.

Transaction admission rejects zero, duplicate, over-capacity, and retained replay IDs before publication. Completion atomically releases the in-flight slot and inserts the ID into a bounded FIFO. Aggregate replay failure preserves the live token for explicit rollback. Generation retirement clears the fixed replay state only after the exact I-C terminal generation has a `CleanupDisposition::Complete` record; missing terminal evidence, failed cleanup, or outstanding resources visibly blocks replacement.

Generated `DW_CHANNEL_MAX_PAYLOAD` and `DW_CHANNEL_MAX_HANDLES` values remain the sole numeric source for kernel-owned per-datagram limits. The ledger truthfully classifies controller-owned admission as `Wyrmroot`, generated Channel envelope enforcement as `Kernel`, and directly peer-mintable native resources/general containment as `Future`.

## Host/accounting coverage

The focused tests cover:

- every canonical per-peer and aggregate budget shape;
- exact limit and one-over rejection for payload and generated Channel handle envelopes;
- atomic mixed-resource peer and aggregate admission;
- reservation publication, rollback, origin binding, and exactly-once release;
- checked request/counter overflow and release underflow without partial mutation;
- WOULD_BLOCK rollback for retained message, byte, and handle accounting;
- duplicate, replayed, aborted, and aggregate-blocked transaction paths;
- fixed-capacity FIFO eviction and reinsertion ordering;
- peer retirement, replay cleanup, and fresh replacement identity;
- required terminal record, complete cleanup, and zero outstanding generation resources;
- exact I-C `AttemptRecord` generation/attempt sequence and bounded episode history; and
- explicit rejection of invalid peer, generation, transaction, managed-resource, and custom-budget policies.

## Validation commands and results

From the exact Wyrmroot product revision:

```text
cargo fmt --all -- --check
cargo test -p wyrmroot-runtime
cargo clippy -p wyrmroot-runtime --all-targets -- -D warnings
cargo test --workspace --quiet
```

Results:

- formatting: PASS;
- `wyrmroot-runtime`: 81 unit tests, 11 source-contract tests, and 2 compile-fail doctests passed;
- focused clippy with warnings denied: PASS;
- complete Wyrmroot workspace: PASS, including xtask 92 passed / 1 accepted environment-gated toolchain test ignored; and
- final independent review after the terminal-cleanup remediation: no remaining confirmed I-D correctness blocker.

The one ignored workspace test requires `WYRMROOT_RUSTC` to point at the coordinator-accepted immutable toolchain and is not part of this host-only accounting gate. I-B already records its positive accepted-toolchain execution.

## Required-source and provenance disposition

The reached WYR0-I capability contract, I-C restart/cleanup state machine, E0 READY/exit observation, generated Deepwyrm Channel maxima, platform recovery boundaries, canonical WYR0 plan/addenda, and downstream porting-ladder separation materially constrained this implementation.

The complete active prior-art set was consulted at its pinned revisions. Fuchsia/Zircon informed staged atomic capability-transfer accounting and bounded object identity without importing its differing failed-transfer semantics. s6 informed explicit bounded history and retry visibility without importing POSIX process-control policy. The inherited xv6, Redox, and OpenBSD sources reinforced terminal/cleanup-before-reclaim ordering. No upstream source was copied or substantially adapted.

The implementation is first-party code inside the existing `wyrmroot-runtime` `GPL-2.0-or-later` component boundary. It adds no generic kernel quota claim, service framework, registry, dependency controller, filesystem control plane, or hostile-process containment claim.

## Gate disposition

WYR0-I-D is accepted at Wyrmroot `bc81924aaf59fcd01bb009155c1f8ee96fa97e19`. The host/accounting gate proves fixed-capacity, generation-safe controller-owned resource admission and replay behavior without a new Deepwyrm primitive.

This closes I-D only. I-E capability payload/live proof, I-F evidence certificate, final ordinary validation, Daybreak review, and WYR0 completion remain open.
