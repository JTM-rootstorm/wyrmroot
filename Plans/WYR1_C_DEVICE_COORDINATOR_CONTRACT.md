# Wyrmroot WYR1-C Device Coordinator Contract

**Status:** Reached WYR1-C0 contract, WYR1-C1 host/native implementation,
WYR1-C2 deterministic unselected product isolation, and WYR1-C3 host/native
pre-resource driver construction
**Reached:** 2026-08-29
**Validation:** [`WYR1_C1_VALIDATION.md`](WYR1_C1_VALIDATION.md),
[`WYR1_C2_VALIDATION.md`](WYR1_C2_VALIDATION.md), and
[`WYR1_C3_VALIDATION.md`](WYR1_C3_VALIDATION.md)
**Scope:** Static q35 COM2 role policy, coordinator state and identity, manifest,
driver-control protocol, restart ordering, and the truthful pre-DW1-D waiting
state  
**Not acceptance:** This contract is not WYR1-C live closure and grants no
DeviceResource, Interrupt, PIO, UART, console, stream, or shell authority

## 1. Authority and phase boundary

`/system/devmgr` is a separate resident Wyrmroot process. It owns device-role
policy intake, exact matching, driver-attempt coordination, later direct
resource delegation, and device-service publication. It is not part of
`/system/init`, `registryd`, `wyrmroot-runtime`, or a shared driver-host process.

WYR1-C0 and C1 stop before hardware authority. The reached pre-DW1-D process
may validate its immutable role manifest, establish its controller and registry
relationships, report `CoordinatorOperational`, and block waiting for a future
bundle endpoint. It must not report `Matched`, `Published`, `Com2Bound`, or an
equivalent device-success state without the exact authority admitted by the
future paired DW1-D/WYR1-C handoff contract.

The following remain outside this contract:

- DeviceResource and Interrupt kernel objects, rights, and operations;
- boot-resource custody or replacement-devmgr authority recovery;
- PIO access and COM2 register programming;
- IRQ routing, acknowledgement, or rearming;
- UART RX/TX, console streams, `consoled`, and `wyrmsh`;
- PCI/ACPI enumeration, hotplug, devfs, udev, descriptors, and `ioctl`;
- selector 29 and WYR1-C live acceptance.

Any implementation requiring one of these stops at the DW1-D seam rather than
inventing a local object, right, handle shape, or custody mechanism.

## 2. Required sources and import disposition

This contract applies the root recovery architecture, Wyrmroot platform
conventions, the WYR1-A supervisor contract, the WYR1-B registry/launch
contract, the accepted WYR1-A/B validation boundaries, and the dedicated
DW1-C/WYR1-C phase plan. Existing startup profiles and selector products retain
their accepted meanings.

The pinned Fuchsia driver-manager files at revision
`6a606ff7fd9b055edee6557566fb3f112df1a812` were read as required conceptual
prior art:

- `src/devices/bin/driver_manager/resource.{h,cc}`;
- `src/devices/bin/driver_manager/node.{h,cc}`;
- `src/devices/bin/driver_manager/driver_runner.{h,cc}`; and
- `src/devices/bin/driver_manager/driver_host.{h,cc}`.

Their BSD-style headers were verified. Wyrmroot adopts only the general
separation between coordinator and driver fault domains and the ordering rule
that dependents and old bindings retire before replacement. No Fuchsia code,
FIDL, Component Manager policy, driver-index ABI, node topology, devfs policy,
dynamic-linker assumptions, colocation policy, or reboot policy is copied or
adapted.

## 3. Fixed product policy

WYR1-C admits exactly one immutable role:

| Field | Required value |
| --- | --- |
| logical role | serial recovery console transport |
| device-role ID | nonzero product-owned identity |
| machine profile | canonical q35 profile and version |
| resource kind | PIO plus interrupt |
| PIO range | `[0x2f8, 0x300)` |
| interrupt source | IRQ 3 |
| expected driver | `system/uart16550d` |
| driver identity | exact nonzero content identity |
| publication policy | fixed WYR1-C serial-transport metadata policy |

COM1 (`[0x3f8, 0x400)`, IRQ 4) is structurally excluded. It remains the
loader/kernel diagnostic path and is never a matching candidate or delegation
target. A manifest containing COM1, another resource kind, another IRQ, an
unknown role, an unknown driver, an overflowed range, an overlapping range,
duplicate role/resource identity, nonzero reserved data, or more or fewer than
the exact WYR1-C role set fails before devmgr reports operational readiness.

Matching is equality over the complete record. Names and payload bytes cannot
manufacture kernel authority and no fallback driver selection exists.

## 4. Immutable device-role manifest

The guest format is the allocation-free canonical binary `WRDM` version 1.
Choosing a canonical guest binary here is the explicit format decision required
by the phase plan; it is not a silent substitution for a host-authored policy
source. WYR1-C2 may add a deterministic host compiler from a reviewed TOML
source, but the compiled `WRDM` bytes and source identity must both enter the
product receipt.

The parser is bounded, little-endian, and fail-closed. It validates the header,
version, total size, fixed record size, bounded record count, exact string
encoding, checked range arithmetic, canonical ordering, uniqueness, reserved
zeros, and complete WYR1-C product policy. It borrows the supplied bytes and
does not allocate. A parsed manifest conveys policy only; it contains no handle,
kernel object number, right, service name with ambient resolution semantics, or
field that can create authority.

For C1, init must transfer an exact read-only manifest object or bounded view;
devmgr does not receive bootfs-wide authority merely to find one policy record.
The WRDM bytes are immutable for the devmgr generation. Replacement devmgr
generations receive a freshly validated view bound to the same selected product
identity unless a separately selected product generation changes it.

## 5. Distinct identities

The following nonzero identities are different types and never substitute for
one another:

1. devmgr supervisor role generation;
2. device-role ID;
3. boot resource/bundle generation;
4. driver-attempt generation;
5. supervisor launch-session ID and generation;
6. direct driver-control endpoint ID and generation;
7. registry generation;
8. registry publication endpoint ID and generation;
9. published service/device generation; and
10. Interrupt object generation after DW1-D exists.

Every inbound event is checked against all identities relevant to that seam.
A numerically equal value of another identity type is not a match. Identity
allocators are monotonic within their owning current-boot scope, reject zero and
overflow, and do not reset merely because a dependent restarts.

## 6. Coordinator state machine

The coordinator is serialized and allocation-free. Its minimum phases are:

```text
Starting
  -> WaitingForRegistry
  -> WaitingForDeviceBundle
  -> Matched
  -> LaunchingDriver
  -> AwaitingDriverReady
  -> AwaitingPublication
  -> Published
  -> CleaningUp
  -> Backoff -> LaunchingDriver
  -> PermanentFailure
```

`CoordinatorOperational` is an outward C1 status, not a device phase. It means
only that startup roles and WRDM were validated and the process has reached a
bounded blocking wait. `DRIVER_READY` moves the exact current attempt only to
`AwaitingPublication`; registry publication must commit before `Published`.

One role owns at most one live driver attempt, control endpoint, resource
bundle, publication, and published generation. A replacement cannot begin
until old publication retirement, endpoint closure, driver terminal/reap, and
resource cleanup all complete. Cleanup failure is visible and forbids
overlapping replacement.

Registry replacement invalidates the old publication endpoint and numeric
correlation. It does not kill or renumber devmgr, its device role, a valid
driver attempt, or later hardware custody. A published driver becomes
unpublished and awaits a freshly controller-installed publication endpoint.
Old registry endpoints close and cannot satisfy the new generation.

## 7. Restart and failure policy

Driver attempts reuse the accepted WYR1 finite policy unless a later reached
contract supplies a narrower hardware reason:

- four attempts including the initial attempt;
- fixed `25_000_000 ns` backoff;
- checked monotonic-active deadlines;
- no overlapping generations; and
- explicit `PermanentFailure` after exhaustion.

Failures before any resource MOVE leave the complete bundle owned by devmgr.
The future DW1-D handoff contract must define ownership at and after each MOVE;
this contract does not guess it. Failed or stale READY, endpoint replay,
publication failure, driver exit, and cleanup failure all retire the old
attempt through `CleaningUp`. A clean retriable failure enters `Backoff`; an
exhausted budget or unprovable cleanup enters `PermanentFailure` and is reported
to supervisor recovery policy.

## 8. Direct driver-control protocol

`wyrmroot-device-proto` owns allocation-free `WRDC` version 1 framing for:

- `DEVMGR_CONFIGURE`;
- `RESOURCE_BUNDLE`;
- `DRIVER_READY`;
- `DRIVER_FAILURE`; and
- `RETIRE`.

Every message has a fixed bounded header with zero flags/reserved fields and
the exact role, driver attempt, and endpoint correlation needed for that
message. Configure, READY, failure, and retire carry zero handles.
`RESOURCE_BUNDLE` reserves exactly two transferred handles, but their public
Deepwyrm types, rights, order, generation evidence, and failed-MOVE ownership
remain uninhabitable until the paired DW1-D contract reaches them. C0 code must
not encode provisional object or right constants.

The direct control Channel is fresh per driver attempt. Init may construct the
driver process and transfer its reduced child endpoint under the future reached
startup profile, but init never receives the later hardware handles. The devmgr
peer remains outside init and registryd. Closing or replacing an endpoint
invalidates every message correlated to it.

The eventual post-resource WYR1-C acceptance actor validates exact handle
metadata, reports READY, accepts intentional failure/retirement, and performs
no UART I/O. C3's narrower synthetic pre-resource actor receives no resource
bundle: it validates WRLP 1.6, reports only `CONTROL_READY`, and intentionally
exits so init can prove terminal observation and reap. Post-resource
failure/RETIRE handling remains C4+ after DW1-D authority exists. The C3 actor
is not the production `uart16550d` implementation.

## 9. C1 startup and controller surface

C1 requires a new startup-profile identity and WRLP minor; WYR1-A/B
`EarlyBootStub` and `BootstrapRegistry` remain byte-for-byte and
meaning-for-meaning unchanged. The profile carries only:

- child self-root authority required by the established static loader;
- one controller-installed registry publication endpoint; and
- one read-only immutable WRDM object/view.

The private bootstrap Channel remains the supervisor control relationship. It
is not hardware custody. Devmgr validates all startup types, rights, counts,
manifest bytes, and correlation before sending READY. READY means
`CoordinatorOperational`, never device bound.

After READY, devmgr exposes only bounded structured status to init and blocks on
Channel/timer waits. It does not poll, busy-spin, enumerate bootfs, or retain
loader construction authority. The C1 implementation may report:

- operational and waiting for registry;
- operational and waiting for device bundle;
- current bounded phase and identity correlations;
- cleanup/backoff state; or
- permanent failure.

It cannot report successful match/publication before the later bundle seam is
implemented and validated.

## 10. C3 private driver construction

C3 adds WRLP 1.6 `DeviceDriver`, a new profile whose exact startup shape is
self-root plus one reduced direct device-control Channel. Its startup record
binds the supervisor generation, role, attempt, launch session, endpoint ID
and generation, and transaction. The bounded loader request independently
rejects every path except `/system/uart16550d`; the host launch model retains
the product-bound acceptance-actor identity. It is a private devmgr-to-init
construction request, not WYR1-B's public job protocol.

Devmgr creates each direct pair and retains the peer. Init receives and moves
only the child endpoint while constructing/reaping the process. It never sees a
future resource bundle. The acceptance actor reports `CONTROL_READY` directly
to devmgr after profile validation. That message alone has an explicit
zero-bundle exception; it is not `DRIVER_READY`, and no other WRDC message may
use a zero bundle. Stale endpoint, session, transaction, profile, or rights
cannot satisfy the attempt. An unsuccessful construction or a reaped child
therefore leaves the future bundle wholly with devmgr by construction.

The private construction exchange is two fixed messages on the existing
devmgr supervisor Channel. WRDL carries the complete correlation plus actor
identity and exactly one reduced Channel. Init distinguishes it from WRCS by
exact magic, validates both receive metadata and queried object identity,
revalidates the WRRM/WRDM/bootfs actor join, and commits a bounded native
attempt before replying. WRLA carries the same complete correlation and zero
handles; it acknowledges process construction only. Devmgr must still receive
the distinct correlation-exact `CONTROL_READY` from its retained direct peer.
Driver exit is a separate resident wait event. Init reaps that exact process,
task group, and loader Channel; devmgr/supervisor replacement cleans an old
driver attempt before constructing a replacement.

Construction acknowledgement and direct `CONTROL_READY` share one checked
absolute monotonic-active deadline using the accepted one-second readiness
interval. Completing WRLA late does not start a second readiness window.
Driver correlation allocators use a supervisor-generation high 32-bit
namespace already bound by WRLP 1.5 and WRDL. Within it, attempt, launch
session, endpoint, and transaction each own a distinct nonoverlapping 30-bit
lane. A replacement devmgr therefore starts above every previous per-type
high-water mark without reusing one generation value as another identity.

## 11. Required model and C1 gates

Before C0 closes, host tests must prove:

- canonical WRDM parse and the exact COM2 match;
- every fixed-policy rejection named in Section 3;
- distinct generation and endpoint correlation;
- intake through launch, READY, publication, retirement, and fresh restart;
- READY-before-publication;
- old endpoint/generation rejection;
- registry replacement without devmgr-generation collapse;
- fixed retry exhaustion and PermanentFailure; and
- cleanup-before-replacement.

C1 then adds a separate static no_std `system/devmgr` artifact. Its focused
host/native tests prove exact startup validation, operational READY, structured
waiting status, blocking wait behavior, and inability to claim device-bound
success. C2 adds a deterministic unselected product that binds the reviewed
source and canonical WRDM, real devmgr, retained acceptance actor, WRRM,
bootfs, production loader/kernel/bootstrap, observation policy, and ESP by
hash. It provides freeze, image, and inspect only; selector-29 reservation,
guest execution/evidence, hardware intake, and WYR1-C closure remain later work
packages.

## 12. Historical-product isolation and nonclaims

Selectors 25 and 27 retain their existing devmgr artifact, WRRM profile,
`EarlyBootStub` launch shape, bootfs bytes/meaning, and validation contracts.
The new real devmgr is selected only by a new WYR1-C product profile. No old
manifest value is reinterpreted.

Reaching this contract or passing its host model does not claim a live real
devmgr boot, device authority, COM2 binding, driver construction, registry
publication, restart-safe custody, UART behavior, selector 29, or WYR1-C
closure. Each claim requires its named later gate and exact product evidence.
