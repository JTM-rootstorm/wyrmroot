# WYR1-E6 production integration addendum

**Date:** 2026-09-05
**Authority:** active root E6A/E6B card; frozen Wyrmsh ownership/product contract;
WYR1-B direct-connection ownership; WYR1-D serial lifecycle; root bootstrap and
recovery architecture. This addendum freezes the concrete normal-product joins
identified by the E6 widened review. It does not certify their implementation.

## Selected product and unchanged wire contracts

Only the new WYR1-E product selects the production shell at `system/wyrmsh`,
WRRM role 5/profile 4, and the ConsoleLauncher/ShellJobs construction path.
Historical selector32 retains console-echo, its immediate CONNECT direct-peer
closure, and its historical release evidence. No WRRG, WRDC, WRST, WRLP, WRLJ
or kernel ABI bytes change here. E6 exports a native bootfs freeze; selector33
media and fixtures remain E7.

## Independent production client-release witness

WYR1-B already transfers one unique direct CONNECT Channel peer from the client
through registryd to the publisher. For the new E6 consoled/devmgr pair, both
processes retain that direct pair after CONNECTED commits. This is a control
lifetime witness, not another byte stream. Do not duplicate or retain either raw
WRST endpoint as a witness, since doing so would prolong raw peer lifetime.

Devmgr reserves an empty witness slot before committing CONNECTED's raw MOVE.
Only a committed response binds the retained direct handle to the complete
`AttachCorrelation`. Before commit, rejection and cleanup retain the reached
one-shot custody rules. One active attach costs one retained Channel handle in
each process and one devmgr wait entry. Historical selector profiles remain on
their existing lifetime branch.

Consoled owns the retained direct handle in its raw serial session. Normal or
exceptional cleanup closes raw endpoints first, then the direct witness, before
potentially blocking watch cancellation or child cleanup. Every post-CONNECTED
abort follows that order. Unexpected devmgr witness-peer loss invalidates the
serial generation. Process death may expose the two release signals in either
order; the broker must support both.

Devmgr treats only witness PEER_CLOSED as client release, after checking the
stored full attach tuple against its current slot. READABLE, including
READABLE with PEER_CLOSED, is malformed: boundedly receive/close any transferred
handles and fail the generation. No payload is a release certificate. Record
client release through the existing broker transition, then close/remove the
witness exactly once. Independently, exact STREAM_DETACHED or supervisor-proved
driver reap records driver release. STREAM_DETACHED alone is insufficient:
UART sends it both after peer-close draining and after driver-initiated
isolation, and its existing wire record does not distinguish those causes.

Cleanup carries one original absolute 1000 ms deadline; equality is expiry.
Clock, signal, close or correlation ambiguity fails the generation. Do not
leave an incomplete broker under an infinite wait. While cleanup is incomplete,
omit publication offers from admission and service release evidence first;
queued offers must not consume a replacement console's finite retry budget.

## Retirement before publication and driver replacement

Registry loss retires the broker's current publication before closing the old
publication endpoint. Init first retires/reaps the dependent console and shell.
Devmgr reports waiting-for-registry only after the old broker is empty through
independent client and driver release. A rebound registry installs a fresh
PublishedDriver identity before any new offer is admitted. Init uses the exact
publication gate below before constructing the next console.

Driver loss follows the reached single-owner recovery: retire the old broker
publication; init retires/reaps dependent console/shell, reaps the exact driver,
and sends the existing exact reap acknowledgement. Devmgr records driver reap
only from that proof, combines it with client-witness release, and starts the
replacement only after old cleanup is complete. Healthy devmgr/lease retention
must not be claimed from whole-subsystem reconstruction. Ambiguous cleanup or
exhausted local recovery enters the existing finite supervisor reconstruction
and degraded-recovery policy rather than guessing release or resetting budgets.

When coordinated recovery owns console retirement, the resident console poll
omits the retained console Process's EXITED signal from its wait admission.
Its authenticated control Channel remains serviceable until peer closure is
consumed. A level-triggered process exit must not starve an already committed
quiescence reply. The recovery owner retains the process/session for the exact
retirement join and keeps the original action deadline; ordinary console
supervision continues to give process exit precedence outside that ownership.

The recovery trigger's exact WAIT enters the same retained barrier whether the
actor completes before or after WAIT admission. An already available terminal
result must not bypass the controller's quiescence request or reach the retiring
shell. The existing result, successor-transaction and deadline checks apply to
both completion orders.

Consoled's final quiescence poll may discover output still queued in a native
child Channel even when its local staging queues are empty. Such bytes pass
through ordinary output staging, serial reservation, retry and commit before
acknowledgement. Only fresh WOULD_BLOCK reads from both still-live child outputs
after those queues and reservations drain establish quiescence; peer closure
remains a failure. Discovering more output immediately resumes reservation work
without waiting for another native readability event.

## Exact publication gate before consoled construction

Driver construction acknowledgement precedes staging, driver READY and serial
publication. It cannot authorize consoled startup. Init instead creates a
temporary controller-owned WRRG client with `EnumerationScope::None`, sends
WATCH for the exact serial connector policy with last generation zero and fresh
per-client transaction 1, and returns to its resident loop.

The pending state binds the client grant, registry identity, exact driver
request, reserved publication service generation and one absolute readiness
deadline. It has an explicit wait entry; devmgr, driver and registry continue
progressing. Only a handle-free, exactly correlated GenerationChanged for the
reserved current service generation can complete the gate. Before launching,
recheck that the exact driver is still current and running, then successfully
close and clear the observer. WATCH does not consume a connector or authorize
enumeration. The reached registry cleanup-before-INSTALL sweep retires the
closed observer without a new acknowledgement.

Use this gate for the initial publication and every rebind/replacement, including
when consoled was never created. Every recovery path cleans its pending observer.
Registry peer loss enters registry recovery; malformed or untrustworthy registry
correlation poisons that registry generation. A well-formed stale generation
rejects the stale chain. A clean deadline with a live registry is a bounded
publication/driver failure. Current WRCS status precedes publication and cannot
substitute for this gate.

## Required evidence

Host models must execute both release orders, co-ready offers, stale tuples,
READABLE/handle abuse, close failure, deadline equality, post-CONNECTED abort
ordering, driver/registry recovery, and one fresh reconnect. Native checks must
compile selected E6 init/devmgr/consoled and all directly affected selector32
variants. Source-string assertions support feature isolation but do not prove
these state transitions. The exact normal artifact/RRC/policy freeze and shell
stack report remain E6 gates; live recovery and interactive evidence remain E7/E8.

Run consoled's model and native-source checks together with
`tools/pinned-cargo test --locked --offline --package wyrmroot-consoled --tests`.
Its native-source targets are `e3d_native_source` and `e8_recovery_source`;
the package has no target named `source_contract`.
