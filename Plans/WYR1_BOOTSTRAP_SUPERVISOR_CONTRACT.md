# Wyrmroot WYR1-A Permanent Supervisor and RRC-A Contract

**Status:** Reached contract; authoritative for WYR1-A
**Prepared:** 2026-08-25
**Wyrmroot baseline:** `120fafa36e0e32402656b23d5a4b0c03b949c7b6`
**Accepted WYR0 product:** `ec84cc6441db15de83d55329ac442a01988c52e9`
**Paired Deepwyrm baseline:** `5a8bb0a75979bb3ecde9bd7209619e924ec5e36d`
**Milestone:** WYR1 permanent bootfs supervisor and recovery closure

This contract replaces the normal WYR0 `init0` proof path with a permanent,
bootfs-resident `/system/init`. It refines the accepted WYR0 loader,
capability, generation, READY, accounting, and finite-restart contracts without
adding kernel ABI or turning init into a general service manager.

The baselines above are design inputs. Later validation binds the exact paired
product commits, generated ABI/toolchain, bootfs, media, and evidence.

## 1. Ownership and scope

The normal post-WYR0 lifetime is:

```text
loader -> Deepwyrm -> primordial bootstrap -> /system/init
                                              |-- registryd
                                              |-- devmgr -> uart16550d
                                              |-- consoled
                                              `-- wyrmsh
```

The primordial bootstrap is one-shot. `/system/init` remains for the boot and
owns narrow boot-role launch/reap/restart policy. Registry/discovery, device
coordination and drivers, general dependency control, console/shell, logging,
configuration, VFS/filesystems, package policy, and authentication remain
separate responsibilities.

The supervisor may sequence the fixed WYR1 bootstrap graph. It does not
interpret arbitrary dependency expressions, activate unknown services, proxy
all IPC, host drivers, provide filesystem-aware `exec(path)`, or grant authority
from self-asserted names.

No Deepwyrm ABI change is required for WYR1-A. Wyrmroot composes the accepted
TaskGroup, Process, Thread, MemoryObject, AddressRegion, Channel, wait, Event,
Timer, object-info, and termination mechanisms through generated bindings.

## 2. Primordial-to-supervisor handoff

The primordial bootstrap launches exactly `/system/init` for normal WYR1
media. `system/init0` remains only in explicitly selected WYR0 regression/test
media and is not a fallback if `/system/init` is absent or invalid.

Primordial launches `/system/init` with the new WRLP `Supervisor` profile. It is
WRLP major `1`, minor `2`. Existing minor `0` and `1` profiles retain their
current meanings.

WRLP 1.2 uses the established 40-byte little-endian header:

| Offset | Width | Field | Required value |
| ---: | ---: | --- | --- |
| 0 | 4 | magic | `WRLP` |
| 4 | 2 | major | `1` |
| 6 | 2 | minor | `2` |
| 8 | 4 | message type | `1` INIT, `2` READY |
| 12 | 4 | flags | zero |
| 16 | 4 | total size | `64` INIT, `40` READY |
| 20 | 4 | capability count | `3` INIT, `0` READY |
| 24 | 8 | transaction ID | nonzero; READY echoes INIT |
| 32 | 8 | reserved | zero |

INIT appends three eight-byte role descriptors in this exact handle order. Each
descriptor is one little-endian `u32` role followed by a zero `u32` reserved
field:

| Index | Role | Object type | Exact rights |
| ---: | ---: | --- | --- |
| 0 | `1` self root | AddressRegion | `MAP | MODIFY | INSPECT` |
| 1 | `2` bootfs | MemoryObject | `READ | MAP | INSPECT | DUPLICATE | TRANSFER` |
| 2 | `3` loader TaskGroup | TaskGroup | `MODIFY | INSPECT | DUPLICATE | TRANSFER` |

The loader TaskGroup is scoped to init's descendant construction/reap subtree;
the rights mask is not ambient authority over another TaskGroup. Init requires
bootfs duplicate/transfer rights because it creates exact immutable child
startup views; it must still reduce child rights/profile authority.

READY is exactly 40 bytes, carries no handle, and echoes the exact nonzero
transaction. Wrong version, size, type, flags, reserved field, role order,
handle count/type/rights, or transaction fails before publication and closes
every received handle.

The RRC manifest is the exact bootfs entry defined below, not a fourth startup
handle. The expected path and external SHA-256 are part of the immutable bootfs
content/build receipt. Init validates the entry before becoming operational.
Any future startup handle role requires another reached profile/minor and
rollback tests.

WYR1-A transfers no device resource to init. The later DW1-D/WYR1-C paired
contract must arrange direct primordial/bootstrap-authority transfer to the
exact `devmgr` generation, or another reached non-usable custody mechanism.
`/system/init` must never receive a handle whose rights permit PIO or Interrupt
operations.

The supervisor sends one exact operational READY after its startup profile,
manifest, retained immutable closure, role table, restart engines, and control
loop are initialized, but before dependent role readiness is treated as system
success. Primordial READY therefore means “permanent supervisor operational,”
not “normal WYR1 activation complete.”

After primordial retires, init starts separate `registryd` and `devmgr` stubs
for the WYR1-A gate. Their READY results move activation to NORMAL; bounded
exhaustion of either required role moves the already-operational supervisor to
DEGRADED_RECOVERY.

After accepting supervisor READY, primordial reports its own READY through the
established parent transaction, closes remaining endpoints/capabilities in
order, and retires. It does not wait for the permanent supervisor to exit and
does not remain as a second supervisor.

Failure performs the existing transactional termination/cleanup and returns a
structured bootstrap-owned result. It never launches `init0`, a shell, or an
undeclared binary as ambient fallback.

## 3. Immutable restart source

The selected boot generation supplies one bounded deterministic bootfs before
persistent root. `/system/init` retains its immutable MemoryObject, or an
equivalent per-artifact immutable representation, for the life of the boot.

Every RRC-A executable, configuration, protocol, firmware, and runtime
dependency resolves transitively from RAM-resident immutable material. No
RRC-A member depends on future persistent root, dynamic root loading, a host
share, networking, libc, an interpreter, or mutable `/config` state.

The restart source is immutable input, not a second running copy. Each
replacement is a fresh Process/TaskGroup/service generation. Process IDs,
handles, mappings, Channels, READY state, transactions, retry counters, and
live generations are current-boot topology and are never persisted as intent.

## 4. Machine-readable RRC-A manifest

WYR1-A introduces the versioned bootfs entry
`system/bootstrap/rrc-a-v1`. The builder emits it deterministically and init
parses it without filesystem access. This archive path is not a VFS pathname or
stable public service ABI.

All numeric fields are little-endian. The header is exactly 80 bytes:

| Offset | Width | Field | Version-1 rule |
| ---: | ---: | --- | --- |
| 0 | 4 | magic | `WRRM` |
| 4 | 2 | major | `1` |
| 6 | 2 | minor | `0` |
| 8 | 2 | header size | `80` |
| 10 | 2 | role-record size | `96` |
| 12 | 2 | edge-record size | `32` |
| 14 | 2 | reserved | zero |
| 16 | 4 | flags | zero |
| 20 | 4 | total size | exact byte length |
| 24 | 2 | role count | `1..=16` |
| 26 | 2 | edge count | `0..=64` |
| 28 | 4 | string byte count | `0..=16384` |
| 32 | 4 | roles offset | `80` |
| 36 | 4 | edges offset | `80 + role_count * 96` |
| 40 | 4 | strings offset | `edges_offset + edge_count * 32` |
| 44 | 4 | reserved | zero |
| 48 | 32 | boot-generation SHA-256 | nonzero exact integration-request identity |

The manifest's own SHA-256 is deliberately external: the bootfs content
manifest and build receipt hash all serialized `rrc-a-v1` bytes. No digest is
embedded in and made self-referential with its own byte stream.

Each 96-byte role record is:

| Offset | Width | Field |
| ---: | ---: | --- |
| 0 | 4 | nonzero role ID |
| 4 | 4 | flags: bit 0 required, bit 1 requires READY; all others zero |
| 8 | 2 | residency: `1` RRC-A |
| 10 | 2 | activation: `1` EARLY, `2` DEVICE_BOUND, `3` CONSOLE_BOUND |
| 12 | 2 | restart policy: `1` finite WYR1 policy |
| 14 | 2 | startup-profile ID |
| 16 | 4 | path string offset relative to string table |
| 20 | 2 | path byte length, `1..=256` |
| 22 | 2 | reserved, zero |
| 24 | 4 | justification string offset relative to string table |
| 28 | 2 | justification byte length, `1..=512` |
| 30 | 2 | reserved, zero |
| 32 | 2 | first edge index |
| 34 | 2 | edge count for this role |
| 36 | 4 | reserved, zero |
| 40 | 32 | executable/content SHA-256 |
| 72 | 24 | reserved, zero |

Each 32-byte dependency edge is:

| Offset | Width | Field |
| ---: | ---: | --- |
| 0 | 4 | owning role ID |
| 4 | 2 | kind: `1` EXECUTABLE, `2` CONFIG, `3` RUNTIME, `4` FIRMWARE, `5` ROLE_READY |
| 6 | 2 | flags: bit 0 required; all others zero |
| 8 | 4 | target role ID |
| 12 | 4 | target-path offset relative to string table |
| 16 | 2 | target-path byte length, `0..=256` |
| 18 | 14 | reserved, zero |

`ROLE_READY` requires a nonzero target role and a zero-length target path. All
other kinds require target role zero and a nonempty canonical target path.
Every edge in RRC-A version 1 has the required flag set.

The string table is raw UTF-8 with no terminators or padding. Role records are
strictly increasing by role ID. Each role's edge range is contiguous; edges are
canonical by `(owner role, kind, target role, target path bytes)`. Strings are
laid out without gaps or overlaps in this order: each role path and
justification in role order, followed by each nonempty edge target path in edge
order. Repeated text is encoded again rather than aliased. These rules leave one
canonical byte representation.

Role IDs are fixed for this milestone: `1 registryd`, `2 devmgr`,
`3 uart16550d`, `4 consoled`, `5 wyrmsh`. Startup-profile ID `0` means
retained-but-not-launchable and is permitted only for a non-EARLY activation
class. Startup-profile ID `1` is the WYR1-A `EarlyBootStub` profile defined
below. Other values are unknown until a later reached child-launch contract
assigns them and therefore fail closed. SHA-256 means the standard 32-byte
SHA-256 digest over the exact immutable artifact bytes.

| Limit | WYR1-A value |
| --- | ---: |
| roles | 16 |
| dependency edges | 64 |
| bytes per canonical path | 256 |
| bytes per justification | 512 |
| aggregate string bytes | 16 KiB |
| total manifest bytes | 64 KiB |

Unknown versions/kinds/profile IDs, nonzero reserved fields, zero identities or
digests, wrong offsets/sizes/order, duplicate IDs/paths, invalid UTF-8,
noncanonical/traversal paths, unused/overlapping string bytes, out-of-range
slices, overflow, cycles, missing dependencies, undeclared bootfs dependencies,
identity mismatch, and dependencies outside retained material fail before child
creation. Golden empty-edge and full five-role vectors bind builder/parser
agreement before live use.

The manifest is build/recovery evidence, not a general configuration language.
It cannot promote arbitrary packages into RRC-A. Each entry identifies the
exact recovery dependency cycle or minimum degraded-control requirement it
breaks.

## 5. Initial RRC-A disposition

The first manifest names:

| Role | Activation | RRC-A justification |
| --- | --- | --- |
| `registryd` | EARLY | minimum bootfs discovery needed to reconstruct direct recovery-service connections without root |
| `devmgr` | EARLY | binding/restart path for root-critical and console devices without root reload |
| `uart16550d` | DEVICE_BOUND | selected q35 recovery-console transport, launched only by devmgr after exact delegation |
| `consoled` | CONSOLE_BOUND | bounded operator-control transport when root recovery degrades |
| `wyrmsh` | CONSOLE_BOUND | minimum recovery/admin control path independent of persistent root |

`/system/init` and its parser/runtime dependencies are also RRC-A members even
though init consumes rather than appears in the child-role table. The builder
checks their immutable closure too.

WYR1-A may use truthful registryd/devmgr stubs for live sequencing. Stub
evidence does not certify later registry or device-manager phases.

WYR1-A activates only records whose activation value is `EARLY`: role IDs `1`
and `2`. It validates and retains role IDs `3..=5` as immutable RRC-A closure
but must not launch them. DW1-D/WYR1-C activates `DEVICE_BOUND` only after the
reached device-handoff contract supplies an exact devmgr generation and
authority path. WYR1-D activates `CONSOLE_BOUND` only after the reached serial
and stream dependencies exist. An implementation cannot reinterpret retention
as activation merely because an executable is present in bootfs.

## 6. Fixed graph and generation identity

Role IDs are coordinator-owned Wyrmroot policy identifiers, not PIDs, kernel
object numbers, service names, or stable external ABI. One logical role has at
most one authoritative active generation.

```text
validate retained closure
    -> start registryd; require exact READY
    -> start devmgr; require exact READY
    -> later: devmgr starts uart16550d after device authority
    -> later: consoled starts after the exact serial generation exists
    -> later: wyrmsh starts after exact console streams exist
```

This is compiled/validated WYR1 policy, not a general dependency solver. A role
publishes only through later supervisor-issued registry authority.

Every attempt carries role ID, nonzero increasing generation, nonzero launch
transaction, executable identity, startup profile, absolute monotonic-active
READY deadline, and controller-owned Process/TaskGroup/Channel/mapping/accounting
records. Restart invalidates old READY, endpoints, publications, jobs,
transactions, mappings, and capabilities.

## 7. Per-role supervision

WYR1-A composes the existing allocation-free `RestartSupervisor`; it does not
copy its logic into init or broaden `wyrmroot-runtime` into a service manager.

```text
Stopped -> Starting -> AwaitingReady -> Ready
                       |                 |
                       `-> CleaningUp <-'
                               |
                            Backoff -> Starting
                               |
                        PermanentFailure
```

Process existence and READY are distinct. READY is accepted once for the exact
role/generation/transaction and expected byte/handle contract. Duplicate,
malformed, late, stale, wrong-role/profile/transaction READY triggers exact
cleanup.

The initial WYR1 policy remains the accepted WYR0-I policy:

- four attempts including initial launch;
- `25_000_000 ns` fixed backoff;
- `2_000_000_000 ns` restart window;
- `1_000_000_000 ns` READY deadline; and
- `1_000_000_000 ns` cleanup deadline.

These values are policy, not ABI. Deadlines use checked monotonic-active time.
Replacement is forbidden until the prior generation is terminal/terminated and
controller state has exact cleanup. Cleanup failure is visible
PermanentFailure, never permission to overlap generations.

Bounded oldest-to-newest history records generation, transaction,
start/classification time, terminal/failure disposition, requested cleanup, and
cleanup outcome. It is current-boot state.

## 8. Launch, READY, exit, and reaping

Init reuses `wyrmroot-loader` ELF validation, mapping, construction, startup
stack, launch protocol, and transactional rollback. It embeds no second loader.

WYR1-A EARLY stubs use WRLP 1.2 `EarlyBootStub`, manifest startup-profile ID
`1`. Its INIT and READY both use the 40-byte header layout from Section 2. INIT
has type `1`, exact size `40`, capability count `0`, a nonzero transaction, and
no role descriptors or transferred handles. READY has type `2`, exact size
`40`, capability count `0`, no handle, and echoes that transaction. The fresh
private launch Channel and supervisor attempt record bind the message to the
expected role and generation; that endpoint is never shared with another role
or replacement.

Roles `3..=5` carry startup-profile ID `0` in the WYR1-A manifest and are
retained but unlaunchable. Later phase contracts replace the selected boot
generation with exact nonzero profiles before activating them.

1. Resolve one manifest-authorized immutable executable.
2. Validate content identity and startup profile.
3. Reserve accounting and construct an unpublished child subtree.
4. Transfer exact reduced startup roles.
5. Publish/start its initial Thread.
6. Await exact READY and/or Process `EXITED` with fresh generation-bound waits.
7. Publish role READY only after validation.
8. On failure/exit, drain and classify terminal readiness safely.
9. Reap/close controller state exactly once before restart or retention.

READY carries no ambient authority. Count, type, rights, version, role,
generation, and transaction are checked before mutation; unexpected received
handles close on all failure paths.

Exit observation uses structured Process information. User-visible text and
magic exit codes are not authoritative. Normal exit, authorized termination,
TaskGroup teardown, and unhandled exception remain distinct.

The later launch/job service reuses this engine through a separate versioned,
connection-scoped authority surface. WYR1-A reserves no ambient `exec(path)`,
PID lookup, fd inheritance, signal, or global job namespace.

## 9. Capability distribution

Init receives authority only by explicit primordial delegation, creates child
subtrees, and reduces rights before transfer. Init and the shell never receive
direct PIO/IRQ authority; the device bundle flows to `devmgr`, which later
delegates an exact driver subset.

Versioned child profiles may include self AddressRegion, immutable bootfs view
or exact artifact MemoryObject, READY/control Channel, supervisor-issued
publication endpoint, devmgr's assigned bundle, and later stream roles. No
profile inherits init's loader TaskGroup, bootfs-wide lookup, device authority,
publication authority, or launch control unless its reached contract says so.
Unknown roles or wrong handles fail before child publication.

## 10. Degraded recovery result

The global result is separate from per-role state:

```text
BOOTSTRAP
    -> SUPERVISOR_OPERATIONAL
        -> ACTIVATING_EARLY_ROLES
            -> NORMAL
            -> DEGRADED_RECOVERY
        -> REBOOT_REQUIRED

NORMAL -> LOCAL_RECOVERY
       -> SUBSYSTEM_RECONSTRUCTION
       -> ROOT_REACQUISITION
       -> DEGRADED_RECOVERY
       -> REBOOT_REQUIRED
```

`SUPERVISOR_OPERATIONAL` is the state acknowledged to primordial bootstrap.
It owns the retained bootfs, parsed role table, restart engines, and control
endpoint but makes no claim that required child roles are READY.

WYR1-A exercises bootstrap, early-role activation, bounded local restart, and
the direct `ACTIVATING_EARLY_ROLES -> DEGRADED_RECOVERY` transition. Later
storage phases fill the middle tiers without changing finite escalation.

When a required role exhausts policy, init records PermanentFailure/history,
stops dependent activation, stops automatic retry for that episode, and enters
structured `DEGRADED` only if Deepwyrm/init/RRC-A remain trustworthy. Loss or
corruption of that substrate is `FATAL`/`REBOOT_REQUIRED`, not a claim that
spawning a shell restored trust.

`RECOVERED`, `DEGRADED`, and `FATAL` are structured results. Text may describe
them but cannot satisfy acceptance.

## 11. Failure atomicity and cleanup

Before READY, any manifest, ELF, mapping, capability, launch, wait, timeout,
peer-close, or terminal-query failure rolls back the partial transaction. After
publication, failure classifies exact Process/READY state, terminates the owned
TaskGroup only if terminal state is not already authoritative, then closes
mappings/handles/reservations.

Cleanup order is: forbid publication; observe terminal or request scoped
termination; reconcile exit/termination race; close endpoints/received handles;
unmap/release mappings and MemoryObjects; release task/accounting records; and
acknowledge exact-generation cleanup before backoff/replacement.

Failure never launches undeclared code, widens authority, reuses stale
endpoints, masks the primary cause with a cleanup error, or retries forever.

## 12. Validation obligations

Host tests must prove:

- deterministic manifest serialize/parse/identity;
- fail-closed bounds, versions, strings, paths, edges, reserved fields, and
  arithmetic;
- duplicate/cyclic/missing/root-backed dependencies are rejected;
- every RRC-A entry has accepted justification and retained transitive closure;
- exact role/generation/transaction READY and process-exists distinction;
- structured exit/reap/cleanup races;
- finite retry/backoff/window and PermanentFailure;
- stale READY/exit/timer/cleanup cannot mutate replacement;
- required-role exhaustion enters degraded once;
- capability profiles reject wrong count/type/rights/role; and
- WYR0 bootstrap/init0/runtime/bootfs regressions remain green.

The focused guest gate must then prove the real `/system/init` path starts
separate registryd/devmgr stubs, observes exact READY, reaps deterministic
exits, and enters explicit degraded state after bounded exhaustion. Host tests
or image inspection do not substitute for this live gate.

## 13. Deferrals

WYR1-A does not certify real registry publication/lookup, completed shell launch
service, device handoff/driver authority, UART/console/streams, interactive
shell, VFS/root, dependency management, authentication, generic TaskGroup CPU
or device quotas, or transparent preservation across restart.

## 14. Required-source and provenance disposition

The required Wyrmroot/root plans, conventions, WYR0 contracts, validation,
completion/security records, storage direction, and Bootstrap and Recovery
Architecture were read before this contract.

Pinned s6 sources at `4ea3aea9f7c7096e20b774cebbdf7d16f122e464`
were used conceptually for compact supervisor states, READY distinct from child
existence, bounded death history/backoff, and visible permanent failure. No code
was copied or adapted. Its POSIX PID/signal/fd/filesystem/FIFO and exit-status
mechanisms do not fit Wyrmroot's typed capability/Channel/generation model.

This contract is first-party `GPL-3.0-or-later` documentation. Existing runtime,
loader, bootstrap, and bootfs components retain their explicit licenses. Any
future third-party adaptation requires file-level provenance and notices.
