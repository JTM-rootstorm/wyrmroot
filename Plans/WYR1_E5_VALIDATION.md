# WYR1-E5 scoped job commands and foreground streams

**Date:** 2026-09-05
**Status:** E5A/E5B/E5C complete at their host/native gate.
**Scope:** ShellJobs adapter, `run`, `spawn`, `wait` and `terminate` in production
wyrmsh. Product selection/native stack acceptance remain E6; guest gates remain
E7/E8.

## Baseline and authority

Root baseline: `6a523fb634e53c2fb2384f48e39662f2bce0d49d`.
Wyrmroot baseline: `3fc7c5bbb9f3cdfedaf707a1b2d9c0b6c9ea9119`.
Deepwyrm remains `18c5b6abf52deb08d2d5ccc45b40896329dc8650`; Rust remains
`a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`; generated ABI remains
`085b184c32ae1fa3d5ec322c86957dd5d036595c`. All repositories were clean at entry.
The saved preflight was taken after the coordinator's three-file tooling edit
and labels that dirty state explicitly.

Required reading reconciles the active E5 card and sections 3.12-3.15, frozen
Wyrmsh contract, WYR1-B registry/launch contract, reached codecs/controller and
native stream wrappers, E4 validation, architecture indexes and root recovery
authority. The separate broad source lane consumed the 21 named section-2
root/Deepwyrm/Wyrmroot authority documents and found no missing source or blocking
contradiction. Its ordered manifest digest is
`26330fc03d8c1acdd85544eea05b8f3bfa3dc5012562567b2660e55a1797170b`.
Current server/runtime details were independently reconciled in a second reading
lane. Earlier Ion/linenoise concept-only receipts remain applicable to unchanged
parser/editor code; E5 adds no external adaptation or parser/editor semantics.

The active plan supersedes predecessor display spelling: WRLJ uses `bin/hello`,
not a leading-slash path alias. Foreground means waiting and draining streams;
the shell never forwards interactive keystrokes or adds terminal takeover,
process groups or signal semantics. Init alone owns loader, Process/TaskGroup,
termination and reap. Deepwyrm and device/serial contracts are reached
dependencies; they supply no new E5 kernel or hardware change.

## Canonical gates

Tooling commit `8a5284eb3245be3e7945eb1aa096590545d654ec` adds named E5 gates:

```text
tools/pinned-cargo xtask test host wyr1e5-model
tools/pinned-cargo xtask test host wyr1e5-clippy
tools/pinned-cargo xtask test host wyr1e5-native
```

Model and Clippy select shell/core libraries and tests through the pinned
Rust 1.98.1 host launcher, locked/offline. Native uses the existing accepted
compiler, exact Wyrmroot target, `native-wyrmsh` binary selection, isolated
scratch and denied warnings. Existing E4 selections are preserved. The two
focused tooling tests and strict xtask Clippy pass; formatting passes.
Host checks have a 60-second bound and native verification a 600-second bound.
These gates neither build a selected product nor execute guest payloads.

## Job identity and bounded storage

All job operations reuse E4C's checked launch transaction namespace, including
LIST_JOBS. Accepted job IDs are opaque and scoped to the exact ShellJobs
connection/generation. The local table has 64 fixed slots to cover the reached
32-live plus 32-completed maximum; reserve local capacity before LAUNCH and
never evict a visible local job to admit another.

The controller's completed-result ring is global and may evict an old result.
An exact-correlated `ForeignOrUnknownJob` therefore removes the stale local
entry after reporting the error; it never fabricates a result. `InvalidState`
retains the entry without inferring a terminal phase. LIST_JOBS contains only
live jobs and cannot reconcile completed entries. A fresh shell cannot recover
the previous connection's jobs. Init retains and reaps disconnected orphans.

## Stream ownership and completion

`run` creates three fresh Channel pairs with
`READ | WRITE | WAIT | INSPECT | TRANSFER | DUPLICATE`. The reached create-broad,
duplicate retained endpoint to final `READ | WRITE | WAIT | INSPECT` rights,
close retained broad endpoint pattern keeps local endpoints exact. The child
endpoints are atomically MOVEd to init in stdin/stdout/stderr order with staging
`READ | WRITE | WAIT | INSPECT | TRANSFER` rights. Init needs TRANSFER for the
subsequent loader handoff; the loader removes it at the final child boundary.
Failed MOVE retains all sender endpoints; successful MOVE removes all three
from local cleanup custody.

After exact LAUNCH_ACCEPTED, close the retained child-stdin writer. Fairly drain
independent child stdout/stderr through the reached bounded WRST wrappers and
shell outputs while observing the exact WAIT transaction. Ordinary stream peer
close is EOF, not a stream failure; drain committed data before final close.
Normal completion requires an authoritative structured result and drained or
explicitly failed streams, followed by CLOSE_JOB. Child text cannot establish
termination classification or success.

`spawn` sends zero streams and reports an ID only after acceptance. `wait`
handles immediate or asynchronous structured results and closes the completed
record. `terminate` reports the scoped controller outcome; it does not imply a
wait, and natural completion may win with InvalidState.

## Local waiting, cancellation and error policy

Committed LAUNCH, foreground RUN and explicit WAIT have no job-lifetime timeout.
They use repeated finite 1000 ms monotonic-active wait slices to revisit required
peer health and fair stream work. Slice expiry is progress-neutral: no resend,
guessed result, cancellation or implicit termination. This is local client
policy; WRLJ does not fix a lifetime deadline.

TERMINATE acknowledgement and CLOSE_JOB are finite control operations, each
with one absolute 1000 ms response bound. Expiry or ambiguous cleanup ends the
generation without guessing job state or local visibility removal.

Only a malformed, handle-bearing or native child-stream failure before a result
triggers exceptional internal cancellation. Close local child streams, issue a
fresh CANCEL targeting the exact pending WAIT and retain both correlations.
The CANCEL exchange has one finite 1000 ms absolute
deadline. CANCELLED proves the WAIT was removed; CLOSE_JOB can then release
active visibility while init retains/reaps the job. This path reports explicit
stream failure and is not normal foreground completion.

If completion wins, require both the original JOB_RESULT and the CANCEL
CancellationUnavailable error before closing the completed record. The reached
serialized server sends the result first; the client accepts either arrival
order without replacing the WAIT or guessing completion. Contradictory responses,
unresolved disposition at the cancellation deadline or required-peer loss end
the generation. Ctrl-C remains editor-only.

MalformedRequest, StaleOrUnknownSession, TransactionReplay and CleanupFailure
are generation-fatal. Capacity, PolicyRejected and LoaderFailure are reported
LAUNCH command failures. ForeignOrUnknownJob and InvalidState are typed job
command outcomes. CancellationUnavailable is admitted only in the exact
two-response cancellation race. Unexpected response types, correlation or
handles are generation-fatal. Required shell output/control loss ends the
generation without speculative further job messages.

## Implementation and executable evidence

The compatible Wyrmroot sequence is:

| Commit | Scope |
| --- | --- |
| `8a5284eb3245be3e7945eb1aa096590545d654ec` | Canonical E5 tooling selections |
| `ce546e650e679741f9bdf6c70df0ae18f1f187ac` | Controller tests only: completed-ring eviction and orphan cleanup |
| `a31199bc1b9c397974ff856fcba9655bbee0847e` | Production E5 job adapter, native facade and command/stream harness |
| `eec8862c78293cb3a24e8e74da64ec005e851742` | Test-only handle-bearing launch backpressure regression |

The production change occupies `userspace/wyrmsh/src/jobs.rs`, the shell
dispatch and native facade, plus the existing runtime test harness. It reuses
canonical WRLJ encoders; no protocol, ABI, shared runtime or Cargo dependency
change is needed. New first-party code remains GPL-3.0-or-later. Two fixed
256-byte pending suffixes decouple child output from shell output capacity.
Alternating stream work, bounded receives (including empty records) and combined
waits let stderr and the job result advance while stdout is blocked. The
adapter never reads interactive shell input during a synchronous job.

The final coordinator model check on `eec8862` passes **98 tests**: four shell
unit tests, 50 integrated runtime tests and 44 pure-core tests. Strict Clippy and
formatting pass. The broader launch/runtime/loader/system-init/consoled/hello/
console-echo regression on `a31199b` passes **445 tests**, including runtime
compile-fail documentation tests. Both suites have zero failures or ignored
tests. That broader suite is unaffected by the later shell-test-only addition.

The command harness exercises real parsing, native facade calls, canonical
messages, WRST output and prompt behavior with scripted syscall/controller
outcomes. Coverage includes pre-launch validation/capacity; partial construction
and duplication failures; atomic MOVE failure and retry ownership; post-MOVE
rejection; both stream-close orders; result before output drain; buffered
exception output; independent progress under output pressure; empty-record
fairness; exact structured termination fields; shared counters; immediate and
asynchronous waits; both cancellation response orders and contradictions;
termination versus natural completion; close replay/expiry; stale local IDs;
control loss; and zero-stream background lifecycle. Normal completion closes
visibility before returning the prompt. Exceptional stream failure closes local
streams, resolves the wait/cancel exchange and closes visibility before reporting
the failure.

The independent controller test drives an actual owner completion followed by
32 other-owner completions through the global result ring. It proves eviction,
live-list exclusion of completed jobs, preservation of unrelated active IDs,
and exact result/terminate/close rejection. Additional controller assertions
prove disconnect/active-close invisibility, no replacement-session reattachment,
phased retain-and-reap cleanup and rejection of a second reap. Its focused
19-test run and strict Clippy pass. The controller production prefix is byte
identical to the baseline, SHA-256
`38b03059a96801e0fbd7eac60818c930547c8c1aa909c23fb96fecbc3de22a69`.
The shell consumes matching scripted errors; this is complementary controller
and client evidence, not a live end-to-end controller run.

## Independent review and corrections

Implementation, controller tests and independent review use explicitly selected
`gpt-daybreak-blue-latest`, high reasoning, on 2026-09-05. Exact source review
is `ce546e6..a31199b`, tree `7d4adef5739c2097f1ba3abfd9e29defbc64d9e5`,
diff SHA-256 `744407c773be0405330913475146c4853445907e67fbb45a36e9816b1faabb08`.
Tooling and controller-test commits above were separately reconciled.
This bounded review does not replace E8/final-F review.

Draft review found High precommit MOVE/retained-stream custody defects and
Medium fairness, closed-stream wake, cancellation ordering/contradiction and
deadline defects. Corrections keep precommit and postcommit ownership explicit,
close local dynamic handles on all exits, remove completed streams from wait
sets, preserve independent output progress, retain exact pending correlations,
and enforce finite send/cleanup deadlines without guessing completion.

Five controlled regression mutations reintroduced earlier draft faults after
correction. Each has its exact patch and failing direct log, followed by restored
production and passing final gates. These are deliberately mutated regression
inputs, not original failing-first implementation runs. The saved restored
`jobs.final.rs` and committed `jobs.rs` have identical SHA-256
`276b884c6b06ffc6d3f6bdea7616a8eadd9019052e71954fb1d9787350f618c7`.

| Controlled regression log under `lane-logs/regressions/` | SHA-256 |
| --- | --- |
| `precommit-custody-red.log` | `c17f30eedafbefa6b1419895409d86c6ae26328e85381431eb87c44dd84602a0` |
| `retained-output-cleanup-red.log` | `d0039c2c23e51fbb1250a41dc6d9735422c3f8bc07cf65b2de78c12334a6d0cc` |
| `output-fairness-red.log` | `da16ae493eee7d1ae4331663fcbf82d4ab8e78cec9daac690f423582a7032075` |
| `cancel-contradiction-red.log` | `a5ccb8a1d4e31bd08d56535ebe74f0182a164b5b9b5080c4d90e31f8767bfa7d` |
| `request-presend-deadline-red.log` | `2d20f8377696170a647e04f6db16f2d1e7ce86f2acdb7841c5b19129e79ee9cc` |

The final review identified a Low test gap: the mock's handle-bearing send
bypassed WOULD_BLOCK injection. Test-only follow-up `a31199b..eec8862`, diff
SHA-256 `c38f808c01c83680cf0eb0b0ad6d7d7cfdd47c338ca07041bcb8e61a2e72bc3a`,
records two identical three-MOVE attempts, exactly one committed launch and
exact retained-handle cleanup. Independent review closes the gap. No production
finding or coverage finding remains open in the assigned scope.

Review also checked nonzero structured cleanup bits: loader relinquishes all
three streams to the child, and JOB_RESULT follows observed EXITED. Deepwyrm's
final-thread exit drains the process handle table, independently of the
controller's later cleanup bits. Thus the child peers close; the shell still
drains committed DATA and requires explicit EOF rather than inferring it from
an empty receive opportunity.

## Native validation and closure

The directly captured canonical native check on production `a31199b` passes in
**128.61 seconds**, under the 600-second bound. The subsequent `eec8862` changes
only `tests/runtime.rs`; the coordinator verified all production files are
byte-identical and reran the affected model/Clippy/format gates. Native and
broader regression checks were not repeated for that test-only change.
Cargo check provides no selected ELF/media or guest execution identity.

All eight preservation inputs match preflight: retained stub/features, consoled
entry/features, system-init native dispatcher, shared stream runtime and frozen
shell/editor contracts. Both clean, integrated and inactive lanes were retired,
their merged branches deleted and registrations pruned. Strict Wyrmroot/Deepwyrm
audit reports zero lanes. Three controller logs and 31 shell evidence files,
including mutation patches and restored source, were copied and hash-verified
before retirement. Every commit is local, unsigned, configured-author and has
the exact Codex trailer. `final-receipt.json` records checks, revisions, hashes,
review identity, preservation and the native/test-only distinction.

| Final evidence | SHA-256 |
| --- | --- |
| `final-r2-model.log` | `92d39a1000701c42dbcd9396ea4bf54ed4a7c5cdbfd609d6d19d2950f72e1931` |
| `final-r2-clippy.log` | `679f9c6c2f80d490b23b87cefd305176e441f93bdab8f47953588f58d8e95192` |
| `final-r2-fmt.log` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `final-regression.log` | `1baed52d68c54fe15a385e22f9f5d14269e26fe7146e8b92656e0ac131750672` |
| `final-native.log` | `2072b095bcb672ad2ec2305a39a9bcf7b9667e346364b129d3897f356bf32102` |

Operator evidence is under `.tmp/wyr1e-e5-20260905/`, excluded from commits.
No VM or persistent disk is inspected or operated for this gate. Host/model CPU
hog coverage does not establish real native preemption or UP/SMP responsiveness.
