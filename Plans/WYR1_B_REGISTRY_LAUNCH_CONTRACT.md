# Wyrmroot WYR1-B Bootstrap Registry and Launch/Job Contract

**Status:** Reached contract; authoritative for WYR1-B implementation
**Prepared:** 2026-08-26
**Wyrmroot baseline:** `f6d4044be33a812a91eb7da2a8c9b9251e5736e0`
**Paired Deepwyrm baseline:** `419af582b3beca0208dfa802a113e4547e4f5620`
**Parent contract:** `WYR1_BOOTSTRAP_SUPERVISOR_CONTRACT.md`
**Milestone:** separate bootstrap registry and supervisor-owned launch/job service

This contract replaces the WYR1-A `registryd` READY-and-exit stub with one
bounded resident registry Process and admits the first narrow launch/job
service owned by `/system/init`. It composes existing Deepwyrm Channels, atomic
handle transfer, waits, task lifecycle, and structured termination. It adds no
Deepwyrm ABI, global process namespace, filesystem-aware kernel execution,
POSIX descriptors/signals, D-Bus, or general dependency manager.

The 2026-08-27 non-hard child-stack revision raises Wyrmroot-loaded child
stacks to 128 KiB while preserving the fixed top, adjacent 4 KiB guard, and
topmost startup blocks. Deepwyrm's separately owned production primordial stack
target is also 128 KiB under its paired contract; ownership remains separate.

## 1. Ownership and trust

- `registryd` is a separate static bootfs Process. It owns registry state and
  no loader, task, device, filesystem, or supervisor authority.
- `/system/init` creates every registry control, publication, client, and
  launch-session Channel pair. Possession of the controller-installed endpoint,
  not a payload name, is authority.
- `/system/init` alone owns loader TaskGroup authority, bootfs lookup, child
  construction, Process/TaskGroup handles, launch Channels, mappings, job
  accounting, termination, and reaping.
- The registry forwards a direct service endpoint exactly once. It never
  proxies later service traffic.
- One service, client, registry, launch connection, and job generation is
  current-boot topology. No endpoint or numeric identity is rebound across a
  replacement generation.

The pinned Fuchsia tree is conceptual comparison only. WYR1-B does not import
Component Manager policy, routing manifests, driver-framework ABI, ambient
namespaces, or Fuchsia service semantics.

## 2. Fixed limits

| Resource | WYR1-B limit |
| --- | ---: |
| published services | 32 |
| service-name bytes | 128 |
| protocol versions per service | 4 |
| outstanding lookup/watch operations per client | 16 |
| completed client replay records | 32 |
| completed publication replay records | 8 |
| shell-visible live jobs | 32 |
| argv entries, including `argv[0]` | 64 |
| environment entries | 64 |
| aggregate argv/environment string bytes | 16 KiB |
| recently completed job records | 32 |
| startup stream roles | 0 or exactly 3 |

These are Wyrmroot implementation limits, not stable platform or kernel ABI.
All counters use checked reserve-before-publish and exactly-once release.

## 3. Wyrmroot startup ABI version 2

Existing startup ABI version 1 and WRLP 1.0 through 1.2 remain byte-for-byte
unchanged.

WYR1-B adds startup ABI version `2` for launched jobs. `RSI` carries value `2`.
The vector retains the established little-endian layout:

```text
argc
argv pointers...
0
envp pointers...
0
aux type/value pairs...
0, 0
string bytes
```

Version 2 uses the highest five mapped stack pages as a 20 KiB startup block.
`RSP` names the block's 16-byte-aligned beginning and every vector word,
pointer, NUL-terminated string, and terminator must lie wholly inside that
block. The 128 KiB RW/NX child stack and immediately preceding 4 KiB guard
remain; exactly 108 KiB of ordinary downward-growing stack remains below the
startup block.

The fixed limits in Section 2 fit by construction: at most 64 argv pointers,
64 environment pointers, vector terminators/auxv, and 16 KiB of aggregate
argv/environment strings. Encoding is canonical and checked before child
publication. The runtime rejects wrong ABI version, count, pointer,
terminator, overlap, non-UTF-8, missing NUL, range, alignment, or arithmetic.

`argv[0]` is required and must exactly equal the launch-policy bootfs path.
Environment entries are `NAME=VALUE`; `NAME` matches
`[A-Z_][A-Z0-9_]{0,63}` and duplicate names are rejected. No value is treated
as capability, handle, path authority, or loader configuration.

## 4. WRLP 1.3 profiles

WRLP major `1`, minor `3` retains the established 40-byte header and uses
profile-specific ordered eight-byte role descriptors. Every received handle is
validated from Channel metadata and fresh object info for exact type and exact
rights before use.

| Profile | Ordered roles |
| --- | --- |
| `BootstrapRegistry` | self root; supervisor control Channel |
| `BootstrapService` | self root; publication-authority Channel |
| `RegistryClient` | self root; registry-client Channel |
| `LaunchClient` | self root; launch-session Channel |
| `JobV2` | zero or exactly three stream Channels in stdin, stdout, stderr order |

The WRRM v1 startup-profile field truthfully encodes `BootstrapRegistry` as
wire value `2`. WYR1-A manifests continue to encode `EarlyBootStub` as `1`;
selector 25 is not reinterpreted and no retained role gains a launch profile.

Exact role contracts are:

| Role | Object | Exact child rights |
| --- | --- | --- |
| self root | AddressRegion | `MAP | MODIFY | INSPECT` |
| supervisor control | Channel | `READ | WRITE | WAIT | INSPECT` |
| publication authority | Channel | `READ | WRITE | WAIT | INSPECT` |
| registry client | Channel | `READ | WRITE | WAIT | INSPECT` |
| launch session | Channel | `READ | WRITE | WAIT | INSPECT` |
| stdin/stdout/stderr | Channel | `READ | WRITE | WAIT | INSPECT` |

Startup ABI v2 covers `JobV2` plus the profile-authorized `BootstrapService`
and `RegistryClient` peers. `JobV2` receives its vector through the Thread
start stack and its optional stream roles through WRLP. Its `argv[0]` exactly
matches the launch-policy path. A bootstrap peer's `argv[0]` exactly matches
the controller-authorized bootfs path. Stream roles are opaque Channels in
WYR1-B; WYR1-D defines their byte-stream protocol. Passing the roles here does
not claim console, fd, terminal, or stdout behavior.

Unknown profile/role, wrong order/count/type/rights, nonzero reserved words, or
unexpected transferred handles fail before child publication or exact cleanup.

`BootstrapService` and `RegistryClient` use startup ABI v2. Init supplies
exactly these three controller-owned environment entries in this order:

1. `WYR_REGISTRY_GENERATION=<u64>`;
2. `WYR_REGISTRY_ENDPOINT_ID=<u64>`; and
3. `WYR_REGISTRY_ENDPOINT_GENERATION=<u64>`.

Each value is nonzero canonical base-10 ASCII with no leading zero and checked
`u64` overflow. Missing, duplicate, reordered, extra, malformed, or zero values
fail before the peer's first protocol send. These values are correlation data
only. Possession of the profile-specific WRLP-transferred Channel remains the
authority, and registryd validates each request header against the installed
endpoint identity received out-of-band from init.

## 5. Registry control topology

Init launches `registryd` with one private `SUPERVISOR_CONTROL` endpoint. For
each publisher or client, init creates another Channel pair and:

1. transfers the registry-side endpoint through supervisor control with an
   exact install record; and
2. transfers the peer endpoint only to the authorized child profile.

The registry records the receiving control endpoint out-of-band. Header IDs are
checked correlation values and never manufacture authority.

Init creates the registry-control and every dependent-peer Channel pair with
controller-broad `READ | WRITE | WAIT | INSPECT | TRANSFER` rights. Immediately
before each atomic MOVE, init freshly queries the still-owned source endpoint
and requires exact Channel type plus those exact broad rights. Rights are
reduced to `READ | WRITE | WAIT | INSPECT` only by the MOVE descriptor that
transfers the endpoint to registryd or the launched child; the retained
controller endpoint is never prematurely reduced.

Restarting registryd closes every old control, publication, and client endpoint.
Init waits for exact terminal cleanup, creates fresh pairs and a nonzero new
registry generation exactly equal to the new RRC `Registryd` role generation,
then relaunches dependent bootstrap publisher/client
generations with fresh Channels and fresh correlation environment entries. It
reinstalls only policy-authorized current service and client generations; it
does not claim that a running old peer can be rebound. Old endpoints cannot
register with or satisfy the new registry.

Controller-issued endpoint IDs are boot-monotonic across registry restarts;
the allocator never resets during one boot. Endpoint generation remains
nonzero correlation metadata, but a new registry generation receives fresh
endpoint IDs as well as fresh Channels. This makes old numeric identities
unavailable for accidental rebinding even after registryd's generation-local
issued-identity ledgers are discarded.

The four generations are intentionally distinct. Registry generation is the
current RRC `Registryd` role generation. Endpoint generation is the
controller-issued generation of one endpoint identity (WYR1-B issues `1` for
each fresh boot-monotonic endpoint ID) and is what WRTG actor/object generation
fields carry. Publication service generation is the P1/P2 service incarnation
stored by WRRG. Client generation is the installed logical client incarnation.
Neither service/client generation nor an RRC role generation may be substituted
for endpoint generation in WRTG correlation.

WRRG v1 has no installation acknowledgement. Therefore an init-side failure
after a successful atomic `INSTALL_PUBLICATION` or `INSTALL_CLIENT` MOVE cannot
prove whether registryd committed the grant. Init poisons and restarts the
whole registry generation, tears down all dependent peers first, and never
retries installation against that generation. Failures before the atomic MOVE
commits remain locally recoverable because init still owns the endpoint.

The controller represents that boundary as typed `PreInstall` versus
`InstallCommitted` failure. Every staged owner removes a handle from local
ownership only when the corresponding atomic MOVE succeeds. Rollback consumes
each remaining handle, process, task group, and reservation at most once. A
failed native cleanup is recorded as RRC cleanup failure and reaches permanent
failure/degraded state; init never reports `cleanup_complete` merely because a
rollback was attempted.

The loader reports service-endpoint MOVE ownership independently of its
diagnostic load stage: before the successful WRLP INIT send the caller still
owns and closes that endpoint, while after that send the loader has consumed
it. A `PreInstall` rollback that itself fails cleanup is sticky fatal cleanup,
not a recoverable pre-install attempt, and is never retried against the same
registry generation.

Registry replacement follows one ownership order. Dependents are terminated
and reaped first, then the old registry process/task group and controller
endpoint close, then RRC admits a replacement. A newly READY registry remains
staged until its dependent gate succeeds. Any committed-install gate failure
cleans dependents first and rolls that registry generation back before another
replacement can start. A dependent cleanup failure forbids replacement.
`devmgr` uses its independent RRC state and neither blocks registry recovery nor
inherits registry failure.

## 6. WRRG version 1 envelope

`wyrmroot-registry-proto` is dependency-free, `no_std`, allocation-free, and
forbids unsafe code. Every datagram begins with this exact 64-byte
little-endian header:

| Offset | Width | Field |
| ---: | ---: | --- |
| 0 | 4 | magic `WRRG` |
| 4 | 2 | major `1` |
| 6 | 2 | minor `0` |
| 8 | 4 | message type |
| 12 | 4 | flags, zero |
| 16 | 4 | exact total size |
| 20 | 4 | exact moved-handle count |
| 24 | 8 | active registry generation, nonzero |
| 32 | 8 | controller-issued endpoint ID; zero only on supervisor control |
| 40 | 8 | endpoint generation; zero only on supervisor control |
| 48 | 8 | transaction ID, nonzero |
| 56 | 8 | reserved, zero |

All variable arrays are contiguous, checked, and followed immediately by raw
string bytes. No padding, gaps, aliasing, overlap, trailing data, in-memory
struct serialization, or implicit host endianness is permitted.

Service names are `1..=128` ASCII bytes matching
`[a-z][a-z0-9.-]{0,127}`. They are identifiers, not filesystem paths.
Protocol IDs are nonzero `u64` Wyrmroot-owned identifiers. A version is one
`(major: u16, minor: u16)` pair. Version lists contain `1..=4` sorted distinct
pairs.

## 7. WRRG messages

| Type | Name | Endpoint | Handles |
| ---: | --- | --- | ---: |
| 1 | `INSTALL_PUBLICATION` | supervisor control | 1 |
| 2 | `INSTALL_CLIENT` | supervisor control | 1 |
| 3 | `PUBLISH` | publication | 0 |
| 4 | `PUBLISHED` | publication | 0 |
| 5 | `RETIRE` | publication | 0 |
| 6 | `RETIRED` | publication | 0 |
| 7 | `LOOKUP_CONNECT` | client | 1 |
| 8 | `CONNECT_OFFER` | publication | 1 |
| 9 | `CONNECTED` | client | 0 |
| 10 | `ENUMERATE` | client | 0 |
| 11 | `SERVICE_LIST` | client | 0 |
| 12 | `WATCH` | client | 0 |
| 13 | `GENERATION_CHANGED` | client | 0 |
| 14 | `CANCEL` | client | 0 |
| 15 | `CANCELLED` | client | 0 |
| 16 | `ERROR` | any installed endpoint | 0 |

### 7.1 Installation

`INSTALL_PUBLICATION` carries one registry-side Channel reduced by the atomic
MOVE to exact `READ | WRITE | WAIT | INSPECT`. Its body is:

| Offset | Width | Field |
| ---: | ---: | --- |
| 64 | 8 | nonzero installed endpoint ID |
| 72 | 8 | nonzero installed endpoint generation |
| 80 | 4 | nonzero supervisor role ID |
| 84 | 4 | flags, zero |
| 88 | 8 | nonzero publication ID |
| 96 | 8 | nonzero service generation |
| 104 | 8 | nonzero protocol ID |
| 112 | 2 | version count |
| 114 | 2 | service-name byte count |
| 116 | 4 | reserved, zero |
| 120 | `4*n` | version pairs |
| following | name length | service-name bytes |

`INSTALL_CLIENT` carries one registry-side Channel reduced by the atomic MOVE
to exact `READ | WRITE | WAIT | INSPECT`. Its fixed 104-byte message appends nonzero
installed endpoint ID, nonzero installed endpoint generation, nonzero client
ID, nonzero client generation, enumeration scope, and zero reserved fields.
Enumeration scope is `0 NONE` or `1 BOOTSTRAP_METADATA`.

Duplicate endpoint/publication/client IDs, duplicate live service names,
unsupported versions, wrong handles, capacity exhaustion, or stale generation
reject before installation.

### 7.2 Publication and retirement

The installed publication endpoint already fixes role, publication ID, service
generation, name, protocol, and versions. `PUBLISH` and `RETIRE` therefore name
none of those values in attacker-controlled body bytes.

A service is visible only after one exact `PUBLISH`/`PUBLISHED` transaction.
`RETIRE`, publication peer closure, registry replacement, or supervisor cleanup
first prevents new lookups, removes the slot, closes every forwarded but not
yet committed endpoint, and then releases the grant. Existing direct service
sessions are not proxied or silently rebound; their service generation owns
their closure.

### 7.3 Lookup and direct connection

`LOOKUP_CONNECT` carries one newly created service-side Channel endpoint. Its
source and registry-installed rights include
`READ | WRITE | WAIT | INSPECT | TRANSFER`. The client retains the paired
endpoint. The request body appends protocol ID, requested major/minor,
service-name length, reserved zero, and canonical service-name bytes.

On success, registryd atomically forwards that endpoint to the matching live
publication through `CONNECT_OFFER`, reducing its rights to exact
`READ | WRITE | WAIT | INSPECT`, then replies `CONNECTED`. It forwards no
payload traffic afterward. If forwarding cannot commit, registryd closes the
received endpoint exactly once and returns `ERROR`; it never reports a
connection while retaining or losing ambiguous authority.

### 7.4 Enumeration and watches

Only clients installed with `BOOTSTRAP_METADATA` may enumerate. `SERVICE_LIST`
is canonical service-name/protocol/version/current-generation metadata for at
most 32 services. It contains no Process ID, handle value, supervisor role ID,
or capability. `ENUMERATE` is header-only. One reply page has this fixed
prefix:

| Offset | Width | Field |
| ---: | ---: | --- |
| 64 | 2 | zero-based page index |
| 66 | 2 | nonzero page count, at most 16 |
| 68 | 2 | record count, `0..=2` |
| 70 | 2 | total record count, `0..=32` |
| 72 | 4 | flags, zero |
| 76 | 4 | reserved, zero |
| 80 | `168*n` | fixed service records |

Each 168-byte record contains nonzero protocol ID at `+0`, nonzero current
service generation at `+8`, name length at `+16`, version count at `+18`, zero
reserved bytes at `+19..+24`, four fixed version slots at `+24..+40`, and a
128-byte name field at `+40`. Version count is `1..=4`; unused version slots
and unused name bytes are zero. Consequently the only page sizes are 80, 248,
and 416 bytes. Published services sort by raw service-name bytes. Empty
enumeration is one empty page. Every nonfinal page contains exactly two
records. All pages use the same installed endpoint and transaction, which
remains live until the final page send commits. A page-send failure removes
the client endpoint. Registryd uses a begin/record/complete ticket so the
single service loop cannot interleave registry mutation into a page sequence.

`WATCH` identifies one canonical name/protocol and a last-observed service
generation. If current state differs, `GENERATION_CHANGED` replies immediately.
Otherwise the exact transaction remains registered until publication,
retirement, replacement, peer close, or `CANCEL`. Generation `0` in the reply
means absent/retired; no old endpoint is returned.

Pending watches occupy a fixed global pool of 32 and each client may own at
most 16. A capacity rejection completes the watch transaction into replay and
returns `ERROR(CAPACITY)`. Publication becomes visible only after the
`PUBLISHED` send commits; only then does registryd complete matching watches
and emit their original transaction IDs. A failed `PUBLISHED` send removes the
publisher while leaving absence watches pending. Retirement and publication
peer close commit absence before notification. Once a watch is consumed, a
notification-send failure removes that client endpoint so no live client can
silently lose a completed watch.

`CANCEL` owns a distinct transaction and may target only a pending watch on
the same client. Success completes both target and cancel into replay before
`CANCELLED`. An unknown, foreign, or already completed target still completes
the cancel transaction, then returns `ERROR(UNKNOWN_TRANSACTION)`.

### 7.5 Typed errors and recoverable framing

The fixed 72-byte `ERROR` body carries exactly one of these `u32` codes and a
zero reserved word:

| Code | Name |
| ---: | --- |
| 1 | `MALFORMED_REQUEST` |
| 2 | `CORRELATION_MISMATCH` |
| 3 | `WRONG_ENDPOINT_KIND` |
| 4 | `TRANSACTION_LIVE` |
| 5 | `TRANSACTION_REPLAY` |
| 6 | `OUTSTANDING_LIMIT` |
| 7 | `CAPACITY` |
| 8 | `NOT_PUBLISHED` |
| 9 | `UNSUPPORTED_VERSION` |
| 10 | `ENUMERATION_DENIED` |
| 11 | `UNKNOWN_TRANSACTION` |
| 12 | `INVALID_STATE` |
| 13 | `FORWARD_FAILED` |

Zero, unknown codes, and nonzero reserved fields are invalid. Registryd first
decodes only the correlation boundary. A message shorter than 64 bytes, with
wrong magic, or with transaction zero is uncorrelatable and is discarded after
closing received handles. On an installed wait slot with a recoverable nonzero
transaction, replies use the canonical controller-installed registry and
endpoint identities: wrong protocol version returns `UNSUPPORTED_VERSION`, a
supervisor-only or directionally wrong known type returns
`WRONG_ENDPOINT_KIND`, an unknown numeric message type returns
`MALFORMED_REQUEST`, wrong registry/endpoint correlation returns
`CORRELATION_MISMATCH`, and bad size/flags/reserved/body/handle framing returns
`MALFORMED_REQUEST`. Such
transactions complete into replay. Semantic errors also complete into replay
and do not stop the loop; failure to send their `ERROR` removes the endpoint.
Supervisor install rejection closes the moved endpoint and continues without
sending a supervisor `ERROR`.

The receive handle array is the generated kernel maximum of 16 entries. Thus
every dequeued WRRG-sized datagram with `0..=16` transferred handles can close
all unexpected handles exactly once and return recoverable
`MALFORMED_REQUEST`. The byte buffer remains the maximum valid WRRG page size,
416 bytes. A payload of 417 bytes or more, or an impossible over-kernel handle
condition, cannot be safely dequeued inside this fixed envelope: the receive
failure removes the endpoint, whose finalization drains the queued bytes and
transfer references. This over-capacity case is intentionally not a typed
recoverable error.

## 8. Registry replay and cleanup

All registry, endpoint, client, publication, service, and transaction identities
are nonzero outside the supervisor-control exceptions above.

Each client admits at most 16 live lookup/watch/enumeration transactions and
retains a FIFO of 32 completed transaction IDs for its current generation.
Each publication admits one live publish/retire operation and retains eight
completed IDs. Duplicate-live and completed replay reject before mutation.

A new generation receives fresh Channels and empty replay state. Old endpoint
destruction is the replay-history lifetime boundary; WYR1-B claims no unbounded
global replay database. Every rejected received handle closes exactly once.

Service-name slots are tombstones for the registry-generation lifetime. Each
of the 32 slots retains its last issued service generation and an optional
active grant. Retirement or publication peer close removes the active grant
before acknowledgement, retains the tombstone, and permits a replacement only
with a strictly greater service generation and fresh identities. The active
grant owns its endpoint handle, role, publication ID, protocol, versions,
phase, live transaction, and replay state.

Numeric identities never rebind within one registry generation. Registryd
keeps fixed no-eviction ledgers for 128 endpoint IDs shared across publication
and client kinds, 64 publication IDs, and 64 client IDs. Exhaustion returns
`CAPACITY`; only construction of a new registry generation resets the ledgers.
Thus P1 endpoint/publication identities remain rejected after retirement,
peer close, and a later successful P2 replacement.

The native resident loop is a thin syscall adapter over a bounded generic
service step. When `READABLE` and `PEER_CLOSED` are observed together, it first
receives and dispatches the committed datagram; cleanup occurs only on a fresh
observation with no readable message. Direct forwarding moves the service
endpoint only after exact metadata and fresh capability validation. Failed
MOVE retains and closes it exactly once and returns `FORWARD_FAILED`; successful
MOVE transfers ownership to the publisher before `CONNECTED`, and a later
client-send failure never reclaims publisher-owned authority.

## 9. WRLJ version 1 protocol

`wyrmroot-launch-proto` retains its existing exact 40-byte envelope:

| Offset | Width | Field |
| ---: | ---: | --- |
| 0 | 4 | magic `WRLJ` |
| 4 | 2 | major `1` |
| 6 | 2 | minor `0` |
| 8 | 8 | nonzero launch connection ID |
| 16 | 8 | nonzero connection generation |
| 24 | 8 | nonzero transaction ID |
| 32 | 8 | reserved, zero |

Every complete message appends an eight-byte prefix: `type: u32` and zero
`flags: u32`.

| Type | Name |
| ---: | --- |
| 1 | `LAUNCH` |
| 2 | `LAUNCH_ACCEPTED` |
| 3 | `QUERY` |
| 4 | `JOB_STATE` |
| 5 | `WAIT` |
| 6 | `JOB_RESULT` |
| 7 | `TERMINATE` |
| 8 | `TERMINATION_ACCEPTED` |
| 9 | `LIST_JOBS` |
| 10 | `JOB_LIST` |
| 11 | `CANCEL` |
| 12 | `CANCELLED` |
| 13 | `CLOSE_JOB` |
| 14 | `CLOSED` |
| 15 | `ERROR` |

### 9.1 Launch body

The fixed body records exact total size, moved-handle count, path length, argv
count, environment count, stream-role count, aggregate string bytes, and zero
reserved fields. It is followed by:

1. `argv_count` eight-byte `(offset: u32, length: u16, reserved: u16)` records;
2. `env_count` records with the same shape;
3. zero or three eight-byte `(role: u32, reserved: u32)` stream descriptors;
4. the canonical path bytes; then
5. argv and environment bytes in record order without gaps or aliases.

`argv_count` is `1..=64`; `argv[0]` exactly equals the path. Environment count
is `0..=64`. Aggregate argv/environment bytes are at most 16 KiB. Stream roles
are either absent or exactly `STDIN`, `STDOUT`, `STDERR` in that order.

For three streams, `LAUNCH` moves exactly three Channel endpoints into init
with `READ | WRITE | WAIT | INSPECT | TRANSFER`; init later forwards them to
the child with `TRANSFER` removed. Zero streams moves no handle. Every mismatch
fails before loader construction.

The path is a canonical nonempty relative bootfs path with no leading slash,
empty component, `.`, `..`, alias, NUL, or non-ASCII byte. Display spelling may
use `/bin/hello`; archive and protocol spelling is `bin/hello`.

### 9.2 Static launch policy

Only paths in immutable `system/bootstrap/launch-policy-v1` may launch. The
deterministic selected-boot-generation record binds each path to exact content
SHA-256, executable classification, startup ABI/profile, and allowed startup
roles. It is validated from independently constructed expected state and reread
bootfs observations before the service becomes available.

This is static bootfs policy, not a general `exec(path)`, VFS, package manager,
or dependency resolver.

### 9.3 Job identity and result

Successful transactional loader publication creates a nonzero opaque job ID.
It is scoped to the exact launch connection and generation and is neither PID,
kernel handle, globally resolvable name, nor transferable authority.

`QUERY`, `WAIT`, `TERMINATE`, `LIST_JOBS`, and `CLOSE_JOB` reject foreign,
retired, stale-generation, or replayed IDs before mutation. At most 32 live jobs
and 32 recently completed results are visible to one connection.

`JOB_RESULT` reports the exact structured Deepwyrm termination classification,
application code, exception class/detail/address, and controller cleanup result.
It never derives success from text, a PID, or a synthetic POSIX signal status.

`CANCEL` cancels one still-pending protocol request; it does not implicitly
terminate a job. `CLOSE_JOB` releases a completed record or the connection's
visibility of an active job; supervisor ownership and reaping remain.

### 9.4 Orphan policy

WYR1-B uses retain-and-reap. On launch-client peer closure, init revokes future
query/wait/terminate visibility for that connection, retains every active job's
controller records, permits the job to run, observes terminal state, and reaps
it exactly once. A later connection cannot reattach to the orphan. This creates
neither leaked children nor ambient cross-connection kill authority.

### 9.5 Slice-F dispatcher dispositions

Slice F fixes the following controller behavior for selector 27 only. These
rules do not extend selector 25, add evidence authority to a test actor, or
turn init into a general service manager.

- `ERROR` carries one of these stable numeric codes: `1` malformed request,
  `2` stale or unknown session, `3` replayed transaction, `4` foreign or
  unknown job, `5` invalid state, `6` capacity, `7` launch-policy rejection,
  `8` loader failure, `9` cleanup failure, or `10` cancellation unavailable.
  Each response repeats the request connection ID/generation/transaction ID;
  only a fresh request transaction may receive one response.
- `LAUNCH_ACCEPTED` is emitted only after the loader transfer has committed and
  init has observed the exact `JobV2`/`JobV2Streams` READY record. A process
  that is both readable with READY and exited during the bounded observation is
  classified from its exact termination record before acceptance; it is never
  accepted merely because its Channel was readable. The READY observation is
  bound to the exact profile, request transaction, child Process, and launch
  Channel; no observation can publish another prepared child.
- A `JobV2`/`JobV2Streams` child remains alive after READY until init has sent
  `LAUNCH_ACCEPTED` and closes its retained launch-Channel endpoint. The child
  accepts only clean peer closure as its completion release, then closes its
  endpoint and exits. Readable post-READY data is a protocol failure. Init
  records the released endpoint before terminal reap so cleanup never closes it
  twice. This adds no WRLP message or authority and removes scheduler timing
  from the READY-and-exited publication decision.
- A successful acceptance reports the job's post-release model state, not the
  pre-release snapshot. The launch-Channel handle is already closed at that
  point, so any caller that reaps directly from the acceptance result -- such as
  a controller that closes and reaps immediately -- must see a zero
  launch-Channel handle and can never close that endpoint a second time.
- Preterminal reap observes the child's level-triggered EXITED task state over a
  bounded budget of `max_attempts` rounds, each bounded by `ready_timeout_ns`. A
  round that expires without the exit signal is not yet a cleanup failure and is
  retried after a fresh task-state query; any other native wait failure ends the
  attempt with cleanup bit 1 and retains the job. Terminal reap therefore does
  not depend on one wait observing the exact EXITED transition, nor on the child
  having been scheduled before the controller's first observation.
- A fresh correlatable LAUNCH transaction is reserved before stream or launch
  policy validation. Semantic rejection aborts the invisible job reservation
  and retains the transaction in replay history, so retrying the same request
  is `TransactionReplay` and cannot allocate or publish a job.
- The loader owns all zero or three stream endpoints uniformly. A failed send
  leaves all supplied endpoints owned by the caller for reverse-order cleanup;
  a successful MOVE transfers all of them and every later rollback path must
  not close them again.
- Deepwyrm termination fields are copied without POSIX translation. The
  classification wire values are exactly `1` normal exit, `2` authorized
  termination, `3` unhandled exception, `4` resource policy, and `5` task-group
  teardown. Unknown or zero classifications fail closed. The
  `cleanup_result` bit set is controller-owned: bit 0 task-group termination
  failed, bit 1 terminal wait timed out or failed, bit 2 launch Channel close
  failed, bit 3 process close failed, and bit 4 task-group close failed. Zero
  means every required controller cleanup/reap action completed.
- There are at most 16 simultaneously open sessions and 32 live jobs globally.
  Job visibility is exact-owner-session only. Session identities are the
  nonzero boot-monotonic `(connection_id, generation)` pair, never a handle or
  a reused slot. A closed session is reclaimed only after all its orphaned jobs
  have reached terminal observation and exact reap.
- The dispatcher polls a bounded session/job subset per tick and uses no giant
  aggregate wait set. It drains readable work before acting on `PEER_CLOSED`.
  Timeout and cleanup-retry outcomes remain explicit `ERROR` or structured
  terminal results; they are never reported as a successful job result.

## 10. Implementation ownership

- `crates/wyrmroot-registry-proto`: WRRG types, codecs, limits, golden vectors.
- `crates/wyrmroot-launch-proto`: typed WRLJ messages above the preserved
  envelope.
- `crates/wyrmroot-loader` and `wyrmroot-runtime`: startup ABI v2 and WRLP 1.3
  profile construction/validation; no registry policy.
- `userspace/registryd`: fixed registry state and Channel service loop only.
- `userspace/system-init`: endpoint distribution, launch policy, loader
  transaction, job/replay/accounting, orphan handling, termination and reaping.
- `wyrmroot-bootfs` and `xtask`: deterministic WYR1-B bootfs/image/request,
  independent identity joins, preparation and evidence verification.

`wyrmroot-runtime` may gain reusable bounded Channel/wait/task wrappers but must
not become registryd, a service manager, or a dependency controller.

## 11. Selector-27 test actors and WRTG v1

Slice B fixes one test-private echo service named `test.wyr1-b.echo`, protocol
ID wire spelling `WYR1ECHO` (`0x4F48_4345_3152_5957`), and version `1.0`.
Its supervisor role ID is test-private `0xFFFF001B`; policy must reject that
role from RRC-A even when the gate artifacts are present in acceptance media.

`wyrmroot-wyr1b-gate-proto` is a dependency-free, allocation-free, `no_std`,
forbid-unsafe codec. Every handle-free WRTG v1 datagram is exactly 96 bytes:

| Offset | Width | Field |
| ---: | ---: | --- |
| 0 | 4 | magic `WRTG` |
| 4 | 2 | major `1` |
| 6 | 2 | minor `0` |
| 8 | 4 | message type |
| 12 | 4 | flags, zero |
| 16 | 4 | size, exactly 96 |
| 20 | 4 | handle count, zero |
| 24 | 8 | nonzero nonce |
| 32 | 8 | nonzero registry generation `R` |
| 40 | 8 | actor ID |
| 48 | 8 | actor generation |
| 56 | 8 | object ID |
| 64 | 8 | object generation |
| 72 | 8 | operation ID |
| 80 | 8 | value |
| 88 | 8 | reserved, zero |

Operations are fixed: `1` first registry generation, `2` replacement/stale,
`3` normal job, `4` foreign probe, and `5` orphan. Values are zero except
types 7 through 10, whose value is the exact challenge, and `FAILURE`, whose
test-local diagnostic class is `1..=0xFFFF`. A failure class is never a
`DwStatus` and never success evidence. The challenge is FNV-1a-64 over the
little-endian u64 sequence `[nonce,R,C,CG,P,SG,op]`, offset basis
`0xCBF29CE484222325`, prime `0x100000001B3`. The independent vector
`[1,2,3,4,5,6,1]` yields `0x4322F6213655B843`.

For registry operations, `P/SG` means the controller-issued publication
endpoint ID and endpoint generation, not publication ID and not service
generation. Likewise `C/CG` is the installed client endpoint ID/generation.
Service generation remains WRRG installation state and is never substituted
into a WRTG actor field.

| Type | Name | Exact direction and meaning |
| ---: | --- | --- |
| 1 | `CONFIGURE_PUBLISHER` | init to publisher; `P/SG,C/CG`, op 1 or 2 |
| 2 | `CONFIGURE_REGISTRY_CLIENT` | init to client; `C/CG,P/SG`, op 1 or 2 |
| 3 | `CONFIGURE_LAUNCH_OWNER` | init to owner; `L/LG,0/0`, op 3 or 5 |
| 4 | `CONFIGURE_LAUNCH_FOREIGN` | init to foreign; `F/FG,L/LG`, op 4 |
| 5 | `PUBLISHED` | publisher to init, mirrors type 1 |
| 6 | `CONNECTED` | client to init, mirrors type 2 |
| 7 | `DIRECT_CHALLENGE` | client to direct Channel, `C/CG,P/SG`, exact challenge |
| 8 | `DIRECT_ECHO` | publisher to direct Channel, `P/SG,C/CG`, exact challenge |
| 9 | `ECHOED` | publisher to init, exact type-8 challenge |
| 10 | `EXCHANGED` | client to init, exact type-7 challenge |
| 11 | `RETIRE` | init to P1; `P1/SG1,C/CG`, op 1 |
| 12 | `RETIRED` | P1 to init, mirrors type 11 |
| 13 | `PROBE_STALE` | init to old P1; `P1/SG1,P2/SG2`, op 2 |
| 14 | `STALE_REJECTED` | P1 to init only after exact old-authority peer close |
| 15 | `JOB_ACCEPTED` | owner to init; `L/LG,J/LG`, op 3 |
| 16 | `JOB_RESULT` | owner to init only after normal exit 0 and cleanup 0 |
| 17 | `PROBE_FOREIGN` | init to foreign; `F/FG,J/LG`, op 4 |
| 18 | `FOREIGN_REJECTED` | foreign to init only after bounded WRLJ foreign-job `ERROR` |
| 19 | `ORPHAN_DISCONNECTING` | owner to init; `L/LG,O/LG`, op 5, immediately before close |
| 20 | `DONE` | init to configured child, object `0/0`, exact current op |
| 255 | `FAILURE` | child to init, object `0/0`, bounded diagnostic only |

Types 1-4, 11, 13, 17, and 20 exist only on the init-to-child parent
Channel. Types 5, 6, 9, 10, 12, 14-16, 18, 19, and 255 exist only in the
reverse direction. Types 7 and 8 exist only on the direct Channel. Actor and
object identities are nonzero except the stated object `0/0` shapes. Types
15, 16, and 19 additionally require object generation equal actor generation.
Before configuration only, `FAILURE` may use actor/object `0/0`, operation 1;
the parent Channel scopes that diagnostic and no success record may accompany
it.

The inherited bootstrap Channel becomes a test-only, post-exact-WRLP-READY
WRTG control/report path. It transfers no WRTG handles and conveys no service,
registry, or launch authority. WRLP-transferred publication, registry-client,
and launch-session Channels remain the only authority. The shared client
artifact stays unconfigured until type 2, 3, or 4 selects its actor mode.
Bootstrap publisher and registry-client peers parse the exact Section 4
startup-v2 correlation environment before their first WRRG send and construct
every WRRG header from it.

WRRG transaction IDs are stage-specific while WRTG operation IDs remain 1 or
2. One RegistryClient uses lookup transaction 1 then 2 on the same installed
endpoint. A publisher uses transaction `2*op-1` for `PUBLISH` (1 for P1, 3 for
P2); P1 uses transaction `2*op` (2) for `RETIRE`. Replies and offers must match
the exact stage transaction.

Init creates each Channel pair. WRLP MOVE transfers only the child endpoint.
For lookup the client creates a broad-rights pair, retains the direct endpoint,
and MOVEs the service endpoint to registryd with exact
`READ|WRITE|WAIT|INSPECT|TRANSFER`. On failed MOVE the client still owns and
closes both endpoints exactly once. On success it never closes the moved
endpoint; registryd owns it, reduces the forwarded endpoint to exact child
rights, and closes it exactly once on a failed forward. Publisher/client
rejection paths freshly validate received metadata and object info and close
rejected handles exactly once.

P1 accepts retirement only after the exact direct exchange. Its later
peer-close proof depends explicitly on Slice C making registry retirement
close the old publication endpoint; Slice B does not patch registryd or claim
integrated retirement/replacement. P2 accepts exact op-2 `DONE` after exchange
without waiting for retirement. Types 15 through 19 are host-model-only until
Slice F supplies native WRLJ task execution; no launch success is claimed here.

### 11.1 WRB1 relational meanings

The existing 14 WRB1 event labels are not standalone booleans. A later
controller producer may emit them only after these joins are proven:

1. `RegistryReady`: exact resident registryd WRLP READY and installed registry generation.
2. `PublisherReady`: exact publisher WRLP READY plus matching type-1 configuration.
3. `ClientReady`: exact client WRLP READY plus matching type-2 configuration.
4. `Published`: matching WRRG `PUBLISH/PUBLISHED` stage transaction and WRTG type 5.
5. `Connected`: matching WRRG lookup/offer/connected authority move and WRTG type 6.
6. `DirectExchange`: one identical computed challenge joined across WRTG types 7-10.
7. `Retired`: exact P1 WRRG retirement transaction joined with WRTG types 11-12.
8. `StaleRejected`: old-authority peer-close failure joined with WRTG types 13-14, never `ERROR` or success.
9. `JobAccepted`: owner-scoped WRLJ acceptance joined with WRTG type 15.
10. `JobExitZero`: exact structured WRLJ normal exit 0 and cleanup 0 joined with type 16.
11. `JobReaped`: the accepted normal job's controller-owned terminal cleanup and exact reap.
12. `ForeignRejected`: type-17 command, bounded foreign-job WRLJ `ERROR`, then once-only type 18.
13. `OrphanReaped`: type 19 before session close, retained ownership, terminal observation, and exact reap.
14. `Terminal`: all required prior joins, exact sequence/cardinality, and no `FAILURE`.

Slice B documents these meanings but adds no WRB1 producer and makes no
selector-27 evidence, receipt, or live-acceptance claim.

## 12. Product and evidence

WYR1-B introduces:

- bootfs entry `system/bootstrap/launch-policy-v1`;
- gate entry `system/bootstrap/wyr1-b-gate-v1`;
- real `system/registryd` and `bin/hello` artifacts;
- selector `bootstrap-registry-launch`, test ID `27`;
- request/receipt schema `6`; and
- controller-originated structured evidence magic `WRB1`.

Selector 25 and its measured 42-page capacity exception remain unchanged.
Selector 26 is reserved for Deepwyrm DW1-B one-CPU preemption. Any WYR1-B
capacity increase is measured from clean release artifacts and admitted only
for selector 27.

Test clients and gate configuration are test content, not RRC-A merely because
they appear in acceptance media. The RRC manifest retains only components that
pass its recovery dependency-cycle admission test.

## 13. Validation

Host/model tests must cover:

- golden and malformed WRRG/WRLJ/WRLP/startup-v2 encodings;
- every bound, size, version, reserved, name/path, offset and arithmetic rule;
- exact received handle count/type/rights and failure-atomic cleanup;
- controller-only installation and payload-name spoof rejection;
- duplicate publication, live duplicate/replay, stale generation, peer close,
  explicit retirement, restart, and watch cancellation;
- direct endpoint forward success/failure without proxying;
- enumeration authorization and canonical ordering;
- launch-policy identity and executable classification;
- argv/environment packing through the full 16 KiB bound;
- zero and three exact startup-stream roles;
- loader rollback, job owner isolation, wait/terminate/result races;
- launch-client disconnect with retained exact reaping; and
- WYR0/WYR1-A loader, runtime, bootstrap, manifest, image and supervisor
  regressions.

The live one-vCPU q35/OVMF gate proves:

1. separate resident `registryd` READY under `/system/init`;
2. independently launched publisher and client endpoints;
3. authorized publish, lookup, direct Channel exchange, explicit retirement,
   peer-close unpublish, and fresh service generation;
4. spoofed/stale publication and old endpoint rejection;
5. launch-session creation and scoped job identity;
6. transactional `bin/hello` launch with bounded argv/environment and startup
   roles, structured normal exit `0`, and exact reaping;
7. stale/foreign job operation rejection and disconnected-client orphan reap;
8. deterministic request, receipt, bootfs, media, and structured evidence
   identities; and
9. no host share, guest network, VFS, libc, POSIX, or interactive-console claim.

Selector-25 normal/degraded default/SMP acceptance is rerun as regression.
WYR1-B does not claim DW1-C SMP scheduling, WYR1-C device coordination,
WYR1-D stream semantics, or WYR1-E interactive shell behavior.

## 14. Required-source and provenance disposition

The root WYR1-B plan, Bootstrap and Recovery Architecture, Wyrmroot architecture
index/platform conventions, reached WYR1-A contract/validation, WYR0-D/E/I
startup/loader/generation/replay contracts, and Deepwyrm Channel/handle-transfer
contract were used as authority.

Fuchsia revision `6a606ff7fd9b055edee6557566fb3f112df1a812` was consulted
conceptually for capability routing and service-generation comparison. The
named `src/devices/driver_framework/` directory contains only `OWNERS` at that
revision and provides no implementation to adapt. No upstream code, wire ABI,
or component policy was copied.

This document is first-party `GPL-3.0-or-later` work. Existing component/file
license declarations remain unchanged.
