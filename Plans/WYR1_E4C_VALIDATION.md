# WYR1-E4C scoped inspection builtins

**Date:** 2026-09-05
**Status:** E4C complete at its host/native gate; full E4 complete.
**Scope:** `services`, `tasks` and `status` in the production wyrmsh runtime.
E5 job operations, E6 product/stack acceptance and E7/E8 guest gates remain later.

## Baseline and authority

Root baseline: `3c5fdff35d2f3321e8753a940ce2944765faf48a`.
Wyrmroot baseline: `bbe7c864b06659a41aff3bd7ef8c0e80d1a56104`.
Deepwyrm remains `18c5b6abf52deb08d2d5ccc45b40896329dc8650`; Rust remains
`a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`. Generated ABI remains pinned to
`085b184c32ae1fa3d5ec322c86957dd5d036595c`. All were clean at preflight.

The active plan's E4C card and inspection-command semantics, frozen shell
contract, WYR1-B registry/launch contract and current servers/codecs govern the
new clients. Earlier E0/E1/E2/E3/E4A/B authority and required-source receipts
remain applicable. The source-reading lane reread the reached registryd
enumeration, system-init job-list and consoled status paths plus all three codecs
at the baseline above; no required source was unavailable. Editor/parser prior
art is not applicable to this control-client slice and no external code is adapted. The completed E4A/B NativeInput/NativeOutput loop, exact
startup/release and partial-output wait behavior must be preserved.

No kernel, server wire, compiler, selected-product, retained-stub or VM change
is required. New first-party shell code remains GPL-3.0-or-later; existing
protocol and runtime component declarations are unchanged.

## Canonical checks

The existing E4 canonical gates are reused without private target/feature flags:

```text
tools/pinned-cargo xtask test host wyr1e4-model
tools/pinned-cargo xtask test host wyr1e4-clippy
tools/pinned-cargo xtask test host wyr1e4-native
```

Host commands use pinned Rust 1.98.1, locked/offline dependencies and a
60-second bound. Native checks use the existing accepted Rust artifact,
Wyrmroot target, isolated scratch and warnings denied under a 600-second bound.
The coordinator captures direct process logs on the committed candidate.
Cargo check does not produce a selected product/media or guest execution result.

## Reached protocol bounds

WRRG enumeration uses pages of at most 416 bytes: an 80-byte prefix and at most
two 168-byte records. A complete list has at most 16 pages/32 services; an empty
list still has one page. Registryd emits a stable canonical name-ordered sequence.
The shell's registry transaction counter starts at 2 because init consumed 1
for the E3 preflight. Endpoint/registry/transaction correlation, consecutive page
indices, consistent totals and cross-page name order must agree.

WRCN uses a maximum 160-byte record and an independent counter starting at 1.
The entire header tuple must match; if a child is present, child generation and
outer launch transaction must also match INIT. Valid absent-child/reconnecting
snapshots are accepted without inventing a current child. LastFailure::NoChild
is diagnostic. The frozen status deadline is 1000 ms in the monotonic-active
clock domain; a narrow native/mock clock facade is needed for bounded tests.

## Local deadline/error policy and API seams

WRCN freezes its 1000 ms absolute monotonic-active deadline. E4C applies the same
local policy to the complete read-only WRRG/WRLJ operations; their older wire
contracts require bounded progress but do not specify that exact duration.
All correlated ERROR responses, malformed/stale/foreign replies, timeout and
required-peer loss terminate the generation after bounded diagnostics/cleanup.
Empty registry/job lists remain successful results. This is client policy, not
a server or wire change; it avoids late-reply reuse and guessed recovery.

The coordinator approved two narrow seams: a mockable monotonic-active clock
method in the shell's existing native facade, and a canonical `encode_list_jobs`
helper in `wyrmroot-launch-proto`. The latter emits the existing header-only
request rather than duplicating wire offsets in the shell. Existing protocol
bytes, IDs and server behavior remain unchanged.

## Reached tasks response boundary

The server's `list_reserved` returns only current-owner, non-orphaned,
non-Reserved live jobs (Running or Terminating), at most 32. Recently completed
records are separately retained and are not in JOB_LIST. The response is at
most 312 bytes and its order is server-slot order, which can become nonnumeric
after slot reuse. The codec carries opaque IDs, not a phase field.

E4C therefore uses LIST_JOBS without QUERY fan-out. Presentation `state=active`
means membership in that bounded live set, covering Running and Terminating;
it is not a claim of a precise phase or a completed-job inventory. Wire order
is preserved. This resolves the plan's general “bounded controller state” prose
using the reached response without expanding WRLJ or E5 job operations.

E5 must reuse the same checked launch-connection transaction namespace for
LIST_JOBS and later launch/job commands. It must not introduce a second counter
starting at 1 on the existing ShellJobs connection.

## Implementation and host validation

Source commit `714ac1d32019e6cff20f4e64dc9d66eb06489349`, tree
`0e0ac9822bbbc45cd3f790068f90b032b159320b`, adds the three inspection clients,
canonical LIST_JOBS encoder, native clock facade and integrated command tests.
The seven-file diff is exactly `bbe7c864..714ac1d`; the canonical checkout was
fast-forwarded to that committed candidate before the final checks.

Registry results remain buffered in fixed storage until the complete sequence
validates. Requests use the existing protocol encoders and independent checked
transaction counters, with one outstanding operation. Status presentation uses
the bounded snapshot plus local relationship health. Unexpected transferred
handles are closed on rejection. The existing startup/READY/release, editor,
NativeInput/NativeOutput and partial-output wait paths remain covered.

The coordinator's direct final model check passes **73 tests**: two inspection
unit tests, 27 runtime integration tests and 44 pure shell-core tests. The
protocol/server regression passes **250 tests** across launch/registry/console
codecs, registryd, consoled and system-init. Both have zero failed or ignored
tests. Strict shell/core Clippy and formatting pass. The author's additional
focused package check also exercises the existing 15-test E0 construction model.

The runtime harness drives actual parsed commands, encoded requests, scripted
Channel replies, NativeOutput bytes and prompt/exit behavior. It covers empty,
nonempty and maximum service/job lists; complete multipage ordering/version
presentation; stale/crossed/malformed correlation and bodies; typed errors;
all console states and valid absent-child snapshots; restart facts; independent
successive transaction namespaces; unexpected-handle cleanup; each target's
peer loss; bounded send backpressure and timeout without duplicate commit; and
normal exit without inspection requests. The server regressions preserve the
reached scoped job-list visibility policy.

## Independent review and deadline correction

Implementation and independent review use explicitly selected
`gpt-daybreak-blue-latest`, reasoning **high**, on **2026-09-05**. Review is
bounded to the exact E4C diff above and does not replace the later E8/F security
gate. Final commit/hash reconciliation reports no remaining actionable finding.

The initial review identified one Medium deadline contract defect: checked
addition could produce the reserved infinite-deadline value without overflowing,
and a ready wait result could permit progress at or after expiry. The correction
rejects that sentinel and rechecks the clock before send, after accepting a wait,
and after response validation, with expiry winning at equality. Every page and
retry retains the original absolute deadline. Rendering follows the existing
output policy after the control exchange completes. The finite page/retry bounds still
held in the initial implementation; this finding is not an unbounded-spin claim.

Three intentionally failing regression runs reproduced the sentinel, later-page
and send-retry defects before correction. The final boundary suite also checks
post-validation expiry. Review caught clock scripts that expired one stage too
early after a new pre-send clock read; the corrected scripts and interaction
assertions now prove the intended later-page, retry and validation paths.
This was a test-evidence correction, not another production defect. The earlier
`test-matrix-red.log` contains a passing suite despite its filename and is not
credited as failing-first evidence.

| Deadline evidence | SHA-256 |
| --- | --- |
| `lane-logs/deadline-red-sentinel.log` | `350ee859b69afa2727a305d4e8fd8a20754b867ff892b98eb3da800cfad5ec99` |
| `lane-logs/deadline-red-page.log` | `1728f265c13cb73668e11f8395d9d07b6faf2d86a066029371074ff907a89867` |
| `lane-logs/deadline-red-send.log` | `e286c179e1eb8ed2e39d3d92decbc9775e36b36280cde175e352e4a04332c567` |
| `lane-logs/deadline-green-final.log` | `66651126257c2128f4d67777dd26ce4bc936d80483da1049875fd87484dee02b` |

## Closure

The final canonical native check passes on `714ac1d` in **138.75 seconds**, under
the 600-second bound, using the accepted compiler and Wyrmroot target. It is
compilation evidence, not selected ELF/media or guest execution evidence.
All nine preflight preservation hashes match: retained stub/features, consoled
entry/features, registry service, system-init native dispatcher, frozen shell
and editor contracts, and existing native-check tooling. The clean, integrated,
inactive worker lane was retired, its merged branch deleted and registrations
pruned. Strict Wyrmroot/Deepwyrm audit reports zero lanes.

Source commits are local and unsigned with the configured author and exact
Codex trailer. All 27 lane logs were copied and hash-verified into the
canonical evidence directory. `source-hashes.json` records all seven reviewed
files; each final check has a direct log and JSON receipt with revision, exact
arguments, timeout, elapsed time, exit code and SHA-256.

| Final check | SHA-256 of direct log |
| --- | --- |
| `final-model.log` | `3c3ff2ac8b0df3df6a2548530667b03f29c1f0ac1df365827f0be2ba3491f201` |
| `final-clippy.log` | `832dc79c8639100b23106ebb241c8d64094cc33bdf59cb578700d22fab0d7c66` |
| `final-regression.log` | `5b69d3bc814eb9c4017702d3d53777c1cf6e9f40ddf91b9730d46c805a868ce2` |
| `final-fmt.log` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `final-native.log` | `d1235185e173c1cdff367b96757ef1a309feddd3f5079541026ef18dd3985b6a` |

E4's production shell harness now executes every non-job builtin. E5 owns job
commands and the child stream bridge. E6 owns selected product assembly,
resident-loop selection, final native stack/call-chain acceptance and exact
artifact/RRC/policy binding. No E5, E6, selector33, interactive guest,
physical-hardware, final security-gate or WYR1 completion claim is made.

Local operator evidence is under `.tmp/wyr1e-e4c-20260905/`, excluded from Git.
No VM or persistent disk is inspected or operated for this gate.
