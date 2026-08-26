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
block. The existing 64 KiB RW/NX stack and guard page remain; at least 44 KiB
of ordinary downward-growing stack remains below the startup block.

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

Exact role contracts are:

| Role | Object | Exact child rights |
| --- | --- | --- |
| self root | AddressRegion | `MAP | MODIFY | INSPECT` |
| supervisor control | Channel | `READ | WRITE | WAIT | INSPECT` |
| publication authority | Channel | `READ | WRITE | WAIT | INSPECT` |
| registry client | Channel | `READ | WRITE | WAIT | INSPECT` |
| launch session | Channel | `READ | WRITE | WAIT | INSPECT` |
| stdin/stdout/stderr | Channel | `READ | WRITE | WAIT | INSPECT` |

`JobV2` receives its startup ABI v2 vector through the Thread start stack and
its optional stream roles through WRLP. Stream roles are opaque Channels in
WYR1-B; WYR1-D defines their byte-stream protocol. Passing the roles here does
not claim console, fd, terminal, or stdout behavior.

Unknown profile/role, wrong order/count/type/rights, nonzero reserved words, or
unexpected transferred handles fail before child publication or exact cleanup.

## 5. Registry control topology

Init launches `registryd` with one private `SUPERVISOR_CONTROL` endpoint. For
each publisher or client, init creates another Channel pair and:

1. transfers the registry-side endpoint through supervisor control with an
   exact install record; and
2. transfers the peer endpoint only to the authorized child profile.

The registry records the receiving control endpoint out-of-band. Header IDs are
checked correlation values and never manufacture authority.

Restarting registryd closes every old control, publication, and client endpoint.
Init waits for exact terminal cleanup, creates fresh pairs and a nonzero new
registry generation, then reinstalls only policy-authorized current service and
client generations. Old endpoints cannot register with or satisfy the new
registry.

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

`INSTALL_PUBLICATION` carries one registry-side Channel with exact
`READ | WRITE | WAIT | INSPECT`. Its body is:

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

`INSTALL_CLIENT` carries one registry-side Channel with exact
`READ | WRITE | WAIT | INSPECT`. Its fixed 104-byte message appends nonzero
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
or capability.

`WATCH` identifies one canonical name/protocol and a last-observed service
generation. If current state differs, `GENERATION_CHANGED` replies immediately.
Otherwise the exact transaction remains registered until publication,
retirement, replacement, peer close, or `CANCEL`. Generation `0` in the reply
means absent/retired; no old endpoint is returned.

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

## 11. Product and evidence

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

## 12. Validation

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

## 13. Required-source and provenance disposition

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
