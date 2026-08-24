# WYR0-I Native Userspace Capability Contract

**Status:** Locked WYR0-I reached-subsystem contract
**Date:** 2026-08-24
**Wyrmroot baseline:** `c6f2f6c10972983eeb76e3b686f4379cbab08c78`
**Deepwyrm product baseline:** `5da17d0d2460936e171d0874ffd2262ad4a5cc97`
**Deepwyrm documentation descendant:** `85af3e4d2a5091810c9eeced70d9b7da4b0b901d`
**Rust baseline:** `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`

This contract freezes the generic native-userspace substrate that WYR0-I certifies before the dedicated readiness payload is implemented. It is subordinate to the Deepwyrm native ABI/schema, Wyrmroot platform conventions, the canonical WYR0 plan/addenda, and already accepted D0/E0 contracts.

The Deepwyrm documentation descendant changes only accepted completion/security documentation relative to the product baseline. `abi/`, `kernel/`, `crates/deepwyrm-abi`, and `crates/deepwyrm-syscall` are unchanged across that range.

---

## 1. Contract purpose

WYR0-I closes the generic WYR0 native-userspace milestone and produces an exact capability certificate reusable by later native consumers.

It proves mechanisms and Wyrmroot-owned policy that are independent of any particular desktop/display workload. It does not itself certify Glasswyrm, Prismdrake, a final service manager, or a general resource controller.

The WYR0-I certificate may be consumed only together with its exact Deepwyrm, Wyrmroot, Rust/toolchain, ABI, image, payload, protocol, and evidence identities.

---

## 2. WYR0-I versus WYR0-GW

WYR0-I certifies the generic substrate:

- native process/thread creation and startup through the userspace loader;
- exact READY, wait, exit, cancellation, termination, and cleanup behavior;
- shareable `MemoryObject` mappings and lifetime/rights rules;
- bounded Channels, atomic handle transfer, peer close, and backpressure;
- waits, Events, Timers, cancellation, and absolute monotonic deadlines;
- bounded Wyrmroot supervision/restart behavior;
- reusable admission/accounting for resources whose admission Wyrmroot owns; and
- exact artifact, protocol, evidence, and final security provenance.

WYR0-GW remains a separate workload-specific certificate. It must bind the exact Glasswyrm binaries/configuration/assets, launch its exact native process set, establish its exact channel graph/peer cardinality, transfer/map its actual bounded shared buffer, exercise its deadline/peer-loss/restart behavior, and prove its own resource budgets and authority graph.

No workload-specific process name, service name, protocol identifier, graphical contract, or process/channel topology is part of this document.

Acceptance of WYR0-I therefore satisfies only the generic DW0-H/WYR0-I prerequisite in the root porting ladder. It does not satisfy WYR0-GW.

---

## 3. Accepted Deepwyrm primitive surface

The WYR0-I probe consumes only already-accepted generic Deepwyrm objects:

- `TASK_GROUP`, `PROCESS`, and `THREAD`;
- `MEMORY_OBJECT` and `ADDRESS_REGION`;
- `CHANNEL`;
- `EVENT`; and
- `TIMER`.

It consumes generated ABI definitions from the exact pinned Deepwyrm revision. Wyrmroot must not copy syscall numbers, object values, rights bits, status values, record layouts, signal values, or implementation limits into a private ABI table.

The allowed native operations are the existing object-info/handle operations, task/process/thread lifecycle operations, memory/mapping operations, Channel operations, waits, Event/Timer operations, and explicit monotonic clock read needed by this contract.

Concretely, implementation may use:

- `handle_close`, `handle_duplicate`, and `object_get_info_v1`;
- `task_group_create` and `task_group_terminate`;
- `process_create`, `process_exit`, and `process_terminate`;
- `thread_create`, `thread_start`, `thread_exit`, and `thread_terminate` where needed by the reusable loader/rollback path;
- `memory_object_create`;
- `address_region_map`, `address_region_protect`, and `address_region_unmap`;
- `channel_create`, `channel_send`, and `channel_receive`;
- `wait_many`;
- `event_create` and `event_signal`;
- `clock_get`, `timer_create`, `timer_set`, and `timer_cancel`; and
- generated atomic wait/wake operations only if a focused WYR0-I implementation genuinely needs them.

`wait_one`, atomic wait/wake, or another already-generated convenience operation may be used instead when it preserves the same contract. Such use does not add a WYR0-I ABI promise.

### I-A privileged-primitive conclusion

No missing privileged operation has been found for WYR0-I. The capability probe, supervision, and Wyrmroot-owned accounting can be implemented from the existing accepted Deepwyrm surface.

A general kernel-enforced TaskGroup resource quota/controller is **not** present. That absence is recorded as an enforcement limitation in Section 9, not treated as permission to add a syscall during WYR0-I.

---

## 4. Process, startup, and termination contract

The existing E0 userspace-loader transaction remains authoritative. Child construction is complete and rollback-safe before `thread_start`, which is the final publication action.
Every WYR0-I supervised launch has a nonzero controller-owned transaction ID and one logical peer generation. A child is not considered ready merely because its Process/Thread exists or entered userspace.

Normal lifecycle is:

```text
Prepared -> Started -> AwaitingReady -> Ready -> AwaitingExit -> Terminal -> Cleaned
```

READY remains an exact transaction acknowledgement, not a service-health assertion. The controller accepts exactly one valid, handle-free READY for the expected transaction.
After receiving READY the controller performs a fresh level-triggered Channel wait so a queued duplicate, malformed, or capability-bearing second datagram cannot hide behind simultaneous `PEER_CLOSED`.

Normal completion requires Process `EXITED` plus fresh structured task information with `NORMAL_EXIT`, application code `0`, and zero exception fields.

Process exit before valid READY, peer close before valid READY, malformed/duplicate READY, transaction mismatch, wait failure, non-normal termination, or nonzero application exit is failure even when diagnostic text claims success.

Cancellation uses authorized task control and is distinct from normal exit. A WYR0-I cancellation test that invokes `process_terminate` expects `DW_TERMINATION_AUTHORIZED`; descendant teardown through an ancestor TaskGroup expects `DW_TERMINATION_TASK_GROUP_TEARDOWN` where applicable.

A selector-local cancellation detail may be used for deterministic diagnostics, but it is not a new Deepwyrm termination reason or stable application ABI.

Cleanup after any terminal path closes parent-owned Process/Channel/object handles exactly once and does not request redundant termination after Process `EXITED` was already observed.

### 4.1 Probe authority flow

The WYR0-I controller receives the already-established loader authority trio:

- self root AddressRegion: exact `MAP | MODIFY | INSPECT`;
- immutable bootfs MemoryObject: exact `READ | MAP | INSPECT | DUPLICATE | TRANSFER`; and
- loader TaskGroup: exact `MODIFY | INSPECT | DUPLICATE | TRANSFER`.

Ordinary probe children do **not** receive TaskGroup, Process, Thread, bootfs, or ambient service authority.

A child that must map a shared object may receive only its self-root AddressRegion with exact `MAP | MODIFY | INSPECT` at startup. This is a Wyrmroot launch-profile extension, not a Deepwyrm ABI extension. If the existing `WRLP` family is extended for this profile, the new accepted shape must receive an explicit protocol-minor revision rather than silently changing the meaning of `WRLP` 1.0.

The child launch Channel remains rights-reduced to exact `READ | WRITE | WAIT | INSPECT`. Additional objects arrive only through controller-originated typed transfers after startup.

Because an ordinary probe child receives neither a TaskGroup handle nor a Process handle with `MODIFY`, the controller can enforce one active Process and its loader-created initial Thread per logical peer slot by capability absence. This narrow statement does not imply a general kernel process/thread quota.

---

## 5. MemoryObject and mapping contract
Deepwyrm's MemoryObject `byte_size` is immutable. WYR0-I uses exact logical extents and checked page rounding; it never treats final-page padding as logical application content.

The canonical shared-memory proof uses one page (`4096` bytes).

The controller creates the object with only the rights needed to populate, inspect, duplicate, map, and prepare one transfer. It maps RW to populate deterministic bytes, removes writable authority from the live mapping before publishing the read-only consumer view, and never creates simultaneous writable/executable authority.

A transfer token is a rights-reduced duplicate. The move transfer installs the child handle with exact `READ | MAP | INSPECT`; the child does not receive `WRITE`, `EXECUTE`, `DUPLICATE`, or `TRANSFER` on the shared object.

The child maps the object read-only through its delegated self root and validates deterministic content before teardown.
The proof includes mapping-owned backing lifetime: after the relevant source MemoryObject handle is closed, an already-established mapping remains valid under its captured mapping authority until explicit unmap/address-space teardown.

`address_region_protect` may only reduce or remain within captured mapping authority. `address_region_unmap` is transactional and exact-range. Stale handles, wrong type, over-broad rights, overflowing geometry, W+X, and range errors fail closed through existing native semantics.

No WYR0-I claim depends on resizing/shrinking a MemoryObject; the current object has immutable extent.

---

## 6. Channel and peer contract

Deepwyrm's ABI-0 per-datagram maxima remain kernel-enforced:

- payload: `DW_CHANNEL_MAX_PAYLOAD = 65536` bytes;
- moved handles: `DW_CHANNEL_MAX_HANDLES = 16`.

Queue depth, total payload storage, and transfer-token storage are bounded kernel implementation resources, not ABI constants. A valid send to an open peer that cannot reserve queue resources returns `WOULD_BLOCK`. Peer closure wins over queue exhaustion.
WYR0-I control messages are deliberately smaller than the kernel maximum. The readiness controller accepts at most `256` payload bytes and `1` transferred handle in any one WYR0-I control transaction unless a later explicit protocol revision changes those limits.

Handle transfer is move-only and atomic. Transfer rights must be nonzero, object-compatible, and a subset of source rights. Failure before commit preserves every source handle. Successful receive creates receiver-local handle values; sender raw values have no meaning in the receiver.

The probe freshly validates received object type and exact rights before use. Unexpected count, wrong type, missing/additional rights, duplicate/unknown role, or malformed attachment fails closed.

### 6.1 Peer role and cardinality

Peer role is assigned by the controller when it creates the launch transaction and Channel endpoint. The endpoint is bound to a logical peer slot plus nonzero generation.

A payload field, executable name, process ID, path string, or self-asserted role cannot change that binding. A transferred or stolen endpoint does not gain another role by naming it in bytes.
WYR0-I supports at most four simultaneously registered logical peer slots. This is a readiness-controller bound, not a platform service-count ABI.

At most one live Process generation is authoritative for one peer slot. Replacement publication occurs only after the old generation has entered the cleanup state required by Section 8.

### 6.2 Backpressure and peer close

The probe exercises both layers deliberately:

1. Wyrmroot admission rejects one-over-budget retained protocol work before publication; and
2. a bounded kernel-backpressure subtest sends no more than 32 deterministic datagrams while looking for exact `WOULD_BLOCK`, then drains the queue.
The second rule preserves I2's bounded saturation discipline and does not expose the private kernel queue capacity as an ABI constant.

`PEER_CLOSED` is normal detectable failure/lifecycle input. A queued datagram remains receivable after peer closure; an empty queue plus closed peer yields `PEER_CLOSED`. No client assumes an IPC endpoint survives a service restart.

---

## 7. Wait, Event, Timer, and deadline contract

All WYR0-I finite deadlines use `DW_CLOCK_MONOTONIC_ACTIVE` and absolute nanosecond deadlines. Deadline construction uses checked addition from a fresh `clock_get` result. Overflow fails closed.

`DW_DEADLINE_INFINITE` is forbidden in readiness/supervision paths. `DW_DEADLINE_NOW` may be used only for deliberate immediate polling.

`wait_many` uses `WAIT_ANY`, never the ABI-0 reserved `WAIT_ALL`, and no call exceeds `DW_WAIT_MANY_MAX_ITEMS = 64`. A successful wait must select a requested handle whose observed mask intersects its requested signals.

Generic wait signals remain level-triggered and non-spurious. Closing a handle after wait registration does not cancel the registration; terminal task retirement consumes blocked registrations and stale wake generations cannot revive a terminal Thread.
Events are manual-reset objects. WYR0-I proves set, observed `SIGNALED`, reset, and finite timeout behavior through generated native semantics.

Timers are one-shot monotonic timers. WYR0-I proves arm/set, observed `SIGNALED`, re-arm as required, and explicit cancel. An armed timer must never report successful expiration before its requested deadline.

Cancellation in this section means explicit cancellation of the controller-owned wait/timer operation or terminal retirement of the participant, not a new POSIX signal model.

The WYR0-I probe does not claim cross-process atomic-wait correlation. I2's existing atomic-wait coverage remains inherited evidence unless a later implementation adds a separately contracted shared-atomic test.

---

## 8. Bounded restart and supervision contract

WYR0-I adds a reusable finite supervision policy above the existing READY/exit observer. It is not the final service manager.

The state machine is:

```text
Stopped -> Starting -> AwaitingReady -> Ready
   ^          |             |            |
   |          +------ failure/exit -------+
   |                        |
   +---- Backoff <----------+
              |
              +-- budget/window exhausted -> PermanentFailure
```
The following constants are WYR0-I supervision policy, not stable platform ABI:

- maximum launch attempts per logical supervision episode: `4` total, including the initial attempt;
- replacement attempts: at most `3`;
- restart-history capacity: `4` terminal attempt records;
- fixed backoff between replacement attempts: `25,000,000 ns` (25 ms);
- restart window from initial attempt: `2,000,000,000 ns` (2 s);
- READY deadline per attempt: at most `1,000,000,000 ns` after that attempt begins; and
- cleanup/termination observation deadline: at most `1,000,000,000 ns` after cleanup begins.

All deadlines are absolute monotonic-active values computed with checked arithmetic. If the next backoff/start would exceed the restart window or the fourth attempt fails, the episode enters `PermanentFailure`; the budget does not silently reset and spin forever.

A successful replacement gets a new nonzero peer generation, new Process identity, and new launch Channel endpoints. No old ephemeral endpoint becomes the replacement endpoint.

Before replacement publication, the old generation must have reached terminal/cleanup disposition, stale controller-owned endpoints/handles must be closed, and that generation's accounting reservations must have been released or the restart itself fails.

Permanent failure is an explicit observable result. A supervisor never hides it by continuing to retry.

The final service-management milestone may adopt a different long-lived restart policy. These numbers exist to make WYR0-I and early consumer readiness deterministic and bounded.

---

## 9. Resource accounting and quota truth

Every readiness-critical counter uses checked arithmetic, reserve-before-publish semantics, and exactly-once release. Counter overflow is a hard admission failure.

WYR0-I distinguishes three enforcement classes:

1. **KERNEL:** enforced by existing Deepwyrm ABI/object semantics;
2. **WYRMROOT:** enforceable because the WYR0-I controller owns the relevant admission/delegation path; and
3. **FUTURE:** observable/accountable in a cooperative workload but not generically enforceable against a compromised native process with today's ABI.

### 9.1 Canonical WYR0-I controller budgets

These are WYR0-I/readiness-library limits, not stable OS-wide resource ABI. WYR0-GW must instantiate and certify its own exact workload budgets rather than assuming these numbers are automatically sufficient.

| Resource | Per peer | Aggregate | Class for this probe |
| --- | ---: | ---: | --- |
| authoritative live Process generations | 1 | 4 | WYRMROOT, when TaskGroup/Process authority is withheld |
| in-flight protocol transactions | 4 | 16 | WYRMROOT |
| completed replay entries | 8 | 32 | WYRMROOT |
| retained protocol messages | 8 | 32 | WYRMROOT |
| retained protocol payload bytes | 4096 | 16384 | WYRMROOT |
| controller-delegated retained handles | 8 | 32 | WYRMROOT |
| controller-created shared MemoryObjects | 2 | 8 | WYRMROOT for controller-owned creations only |
| controller-created shared-object bytes | 8192 | 32768 | WYRMROOT for controller-owned creations only |
| controller-owned mapped bytes | 16384 | 65536 | WYRMROOT for controller-owned mappings only |
| in-flight controller wait operations | 4 | 16 | WYRMROOT |
| controller-owned Events | 2 | 8 | WYRMROOT for controller-owned creations only |
| controller-owned Timers | 2 | 8 | WYRMROOT for controller-owned creations only |
| restart-history records | 4 | 16 | WYRMROOT |

A peer-limit reservation also consumes the corresponding aggregate reservation. Failure of either admission leaves both counters unchanged.

The accounting scope excludes transient internal objects owned solely by the already-bounded transactional ELF loader; their construction/rollback limits remain governed by the E0 loader contract. It also excludes kernel-internal queue/storage pools whose exhaustion already has native `NO_RESOURCES`/`WOULD_BLOCK` semantics.

### 9.2 Existing kernel-enforced bounds/invariants

WYR0-I may rely on these existing kernel facts without relabeling them as Wyrmroot quotas:

- Channel datagram payload <= 65536 bytes and moved handles <= 16;
- Channel queue/payload/transfer storage is bounded and returns deterministic `WOULD_BLOCK` on open-peer admission exhaustion;
- `wait_many` accepts at most 64 items;
- handle transfer preserves/reduces rights and is failure-atomic;
- MemoryObject extent is immutable and mapping geometry is checked;
- mapping authority cannot exceed the source/captured rights ceiling; and
- task/object/handle storage remains bounded by Deepwyrm implementation resources and reports native exhaustion statuses.

### 9.3 Not yet generically enforceable

The following are **FUTURE** security boundaries for an arbitrary compromised native peer because current Deepwyrm does not require a delegable resource-budget capability to create/use them:

- total MemoryObjects or MemoryObject bytes directly created by that peer;
- total Channels directly created by that peer;
- total Events or Timers directly created by that peer;
- total handles in that peer's handle table;
- total mappings/mapped bytes created through authority the peer already holds;
- total wait registrations/operations the peer independently initiates;
- general per-TaskGroup process/thread/memory/IPC/CPU quotas after TaskGroup authority itself is delegated; and
- CPU-time/share/priority, I/O, or device-resource budgets.

`memory_object_create`, `channel_create`, `event_create`, and `timer_create` are directly callable native operations and do not consume a Wyrmroot budget capability. A userspace ledger cannot turn them into a security boundary after the fact.

Similarly, a peer holding its own `MAP | MODIFY` root can perform mappings permitted by the objects it obtains. Wyrmroot can bound objects/mappings it brokers, but not all objects/mappings a compromised peer can create itself.

The WYR0-I certificate must preserve this classification. If WYR0-GW or another consumer requires hostile-peer containment for these resource classes, that consumer is blocked on a separately designed TaskGroup/resource-control milestone rather than a WYR0-I syscall expansion.

---

## 10. Transaction, replay, and generation contract
Every controller request expecting a reply uses a nonzero `u64` transaction ID and is interpreted together with the controller-assigned peer slot and nonzero peer generation.

The controller maintains, per peer:

- at most 4 live transaction IDs; and
- a fixed FIFO/ring of at most 8 recently completed transaction IDs for the current generation.

A transaction ID already live in the same generation is rejected as a duplicate before state mutation. A recently completed ID in the same generation is rejected as replay.

A new peer generation starts with no live transaction and a fresh bounded replay set. Old-generation endpoints are closed during cleanup and are never rebound to the new generation. Any controller-side stale generation token is rejected before performing peer-visible mutation.

The controller need not maintain unbounded global replay history after an old endpoint/generation is dead and unreachable. Generation retirement plus endpoint destruction is the lifetime boundary.

The readiness library owns its own typed error/result enum; it does not allocate new `DwStatus` values. Native syscall failures retain their real `DwStatus` at the native boundary and are wrapped with the Wyrmroot stage/operation that encountered them.

---

## 11. Evidence and failure identity

WYR0-I evidence is test/readiness evidence, not production IPC ABI.

The reserved identities are:

- selector: `native-userspace-capability`;
- test ID: `24`;
- request schema: `4`;
- evidence protocol magic: `WRCAP1`;
- evidence protocol version: `1`; and
- canonical required capability kinds: ten kinds defined below.
The canonical ASCII record form is:

```text
WRCAP1|01|NONCE16HEX|SEQ8HEX|KIND2HEX|PEER8HEX|GEN8HEX|TOKEN16HEX|ARG016HEX|ARG116HEX|CHECKSUM8HEX\n
```

All hexadecimal fields are uppercase and fixed-width. Nonce is the exact nonzero request nonce; sequence starts at zero and is contiguous.
Peer `0` is reserved for controller/global evidence. Nonzero peer IDs name an admitted logical slot, and peer-scoped events carry that slot's current nonzero generation.

Token is a transaction/object/test correlation value defined by the event kind. `arg0`/`arg1` are kind-defined bounded facts, never raw pointers or secret data.

Checksum is FNV-1a-32 over the record through the delimiter immediately before the checksum.

A line whose beginning case-insensitively resembles `WRCAP1` is protocol input and must use exact uppercase magic plus complete valid framing. Malformed lookalikes fail rather than becoming human diagnostics.

Only the trusted WYR0-I controller emits `WRCAP1`. Child payload output cannot satisfy evidence by printing protocol-shaped lines.

Host evidence is accepted only with a matching terminal PASS for test ID 24 and one exact immutable request/candidate/provenance identity.
### 11.1 Evidence kind assignments

| Kind | Name | Required proof |
| ---: | --- | --- |
| `01` | `CONTENT_DELIVERY` | selector-bound executable plus non-executable config/asset content matched expected identity |
| `02` | `PROCESS_LIFECYCLE` | Process/Thread launch, exact READY, wait, and structured normal exit |
| `03` | `MEMORY_SHARE` | bounded MemoryObject creation, rights-reduced transfer/map, content, source-handle close lifetime, teardown |
| `04` | `CHANNEL_LIFECYCLE` | atomic handle transfer, deterministic Wyrmroot overload rejection, kernel backpressure, peer close |
| `05` | `WAIT_EVENT_TIMER` | finite monotonic wait, Event set/reset, Timer arm/expiry/cancel, no early success |
| `06` | `CANCELLATION` | authorized cancellation/termination plus bounded observation/cleanup |
| `07` | `RESTART_REPLACEMENT` | old generation retired and a new generation/Channel becomes authoritative after backoff |
| `08` | `RESTART_EXHAUSTED` | fourth failed attempt enters PermanentFailure and no fifth spawn occurs |
| `09` | `OVERLOAD_REPLAY_REJECTED` | one-over-budget and duplicate/replay/stale-generation requests fail without leaked reservation |
| `0A` | `CLEANUP_BASELINE` | final Wyrmroot-owned counters and owned handles/mappings return to expected baseline |

The canonical request requires all ten capability bits; the observed mask is assembled from successfully validated events and is never a hard-coded success constant.

Event count may exceed ten when one proof requires multiple joined records, but all evidence remains bounded by the request/parser limit established in I-F.
### 11.2 Failure-code ownership

WYR0-I does not allocate native status codes. Selector-local terminal failure detail uses:

```text
0x24SSOOOO
```

where `24` is the WYR0-I test family, `SS` is an 8-bit stage, and `OOOO` is the exact 16-bit failed operation. Detail zero is success.

Stage assignments are:

- `01` content delivery;
- `02` process lifecycle;
- `03` memory sharing;
- `04` Channel behavior;
- `05` wait/Event/Timer;
- `06` cancellation;
- `07` restart replacement;
- `08` restart exhaustion;
- `09` overload/replay; and
- `0A` cleanup/accounting.

A platform `DwStatus` remains separately observable in structured diagnostics/evidence where applicable; it is not overwritten or redefined by the selector-local detail.

---

## 12. Inherited versus new live evidence

WYR0-I does not reimplement or rename accepted I0/I1/I2 proofs. It cites them as revision-bound inherited evidence and reruns their required regression selectors on the final candidate during I-G.

| Capability | Inherited evidence | New WYR0-I live proof |
| --- | --- | --- |
| real UEFI -> loader -> kernel -> bootstrap -> init0 -> child chain | I0 | final default regression plus selector content identity |
| malformed startup/capability fail-closed cases | I0 | new malformed WRCAP1/control attachment/replay cases only |
| real SMP/native CPL3 participation and remote cleanup | I1 | final SMP capability selector runs on same candidate |
| handle stale/reuse, Channel saturation/peer close, waits/timers, mapping, task authority, exception stress | I2 | consumer-shaped shared-memory, restart, accounting, and evidence joins |
| exact TLB/rendezvous acknowledgement-before-reclaim | I1/I2 | inherited; no new public Wyrmroot proof protocol needed |
| bounded READY/exit semantics | E0 + final DW0-H remediation | reused by supervision and restart controller |
| bounded restart/crash-loop exhaustion | none sufficient | **new I-C/I-E proof** |
| per-peer/aggregate Wyrmroot admission accounting | none sufficient | **new I-D/I-E proof** |
| consumer-facing exact capability certificate | none | **new I-F output** |

Historical acceptance is not a substitute for final-candidate reruns where I-G requires them. Conversely, I-G should not build another broad concurrency oracle just because I0/I1/I2 came from an earlier checkpoint.

---

## 13. Boot/system-image content delivery
The WYR0-I selector must prove delivery of its exact executable payload plus at least one deterministic non-executable configuration record and one deterministic asset/blob through the canonical boot/system-image path.

These are selector/test content, not the final `/config`, `/state`, package, VFS, or service-discovery design. Use test-owned bootfs paths and bind their byte identities in the request/certificate.

The controller validates content by exact expected path, logical length, and digest/content contract before emitting `CONTENT_DELIVERY`.

The final WYR0-I certificate proves only that trusted immutable boot/system-image delivery can carry binaries plus bounded configuration/assets. WYR0-GW must bind the actual Glasswyrm binaries, configuration, and assets itself.

---

## 14. Prior-art and provenance disposition

I-A rechecked the prior-art family selected by the root WYR0-I plan.

### Fuchsia/Zircon

Pinned reference revision: `6a606ff7fd9b055edee6557566fb3f112df1a812`.

Relevant Zircon object/syscall source, including `zircon/kernel/lib/syscalls/channel.cc`, carries the repository's MIT-style license header. The useful precedent is conceptual: rights-bearing handles, Channel handle-transfer/lifetime behavior, Job-like hierarchy, VMO/VMAR separation, and tiny userspace bootstrap structure.

WYR0-I does not import Fuchsia Component Manager topology/routing policy and does not copy a Zircon ABI.
### s6

Pinned reference revision: `skarnet/s6` `4ea3aea9f7c7096e20b774cebbdf7d16f122e464`.

`s6` uses the permissive ISC license. `src/supervision/s6-supervise.c` and `s6-permafailon.c` are precedent for a small explicit supervision state machine, readiness separate from process existence, bounded failure history, retry delay, and permanent-failure disposition.

WYR0-I does not import s6 filesystem/FIFO/fd/signal/POSIX semantics or turn its supervisor into a service dependency controller.

### Import disposition

No upstream code is copied or substantially adapted by I-A. These sources constrain design/proof shape only, so I-A introduces no third-party source file or new imported-code license boundary.

Any later direct source adaptation must pin the exact upstream file/revision/license and update provenance before landing.

---

## 15. I-A closure and downstream implementation rules

I-A is closed when this contract and the architecture-index registration are accepted on one Wyrmroot revision and the root coordination plan records that revision.

No Deepwyrm ABI/schema change is required by this contract.
B/C/D implementations must obey these joins:

- **I-B** may audit clean-build/toolchain/libc/provenance independently and must not redefine runtime protocol or quota semantics.
- **I-C** owns the finite supervision/restart state machine and constants from Section 8; it extends the existing bounded supervision surface rather than building a service manager.
- **I-D** owns the checked admission/accounting representation and budgets in Section 9; it must preserve the KERNEL/WYRMROOT/FUTURE classification in APIs and tests.
- shared Wyrmroot launch/protocol types touched by C/D remain a coordinator join point rather than two independently evolving wire contracts.

I-C/I-D must not broaden a FUTURE resource class into a claimed security boundary merely because a test ledger can count it.

I-E/I-F later own the dedicated live payload and evidence/certificate integration. They may refine selector-internal operation numbering and evidence `arg0`/`arg1` meanings without changing the capability kinds, trust source, enforcement classes, restart constants, or WYR0-I/WYR0-GW split pinned here.

Any discovered need for a new privileged operation stops the affected lane and returns to coordinated Deepwyrm/Wyrmroot architecture review. Convenience, foreign-personality similarity, or a desire to make a certificate table greener is not sufficient justification.

### Final I-A finding

The existing accepted Deepwyrm primitive set is sufficient for WYR0-I. The only material capability gap exposed by I-A is **generic enforceable resource quotas/accounting for arbitrary untrusted native peers**, which remains intentionally deferred to a later TaskGroup/resource-control milestone.

That limitation must remain visible in every WYR0-I certificate consumed by later porting work.
