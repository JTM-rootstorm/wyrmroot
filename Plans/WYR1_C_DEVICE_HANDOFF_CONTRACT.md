# Wyrmroot WYR1-C Device Handoff Contract

**Status:** Reached paired DW1-D0/WYR1-C authority handoff contract
**Reached:** 2026-08-29
**Kernel contract:**
[`deepwyrm/Plans/DW1_D0_DEVICE_RESOURCE_INTERRUPT_CONTRACT.md`](../../deepwyrm/Plans/DW1_D0_DEVICE_RESOURCE_INTERRUPT_CONTRACT.md)
**Scope:** Resource-domain custody, exact q35 COM2 grant correlation, reduced
claim startup authority, direct driver-bundle MOVE, and cleanup-before-replace
ordering required by WYR1-C4

## 1. Reached seam and nonclaims

WYR1-C3 stops after a real `system/devmgr` generation constructs a synthetic
pre-resource driver actor over one fresh direct control Channel and receives
`CONTROL_READY`. That state remains truthful and unchanged.

This contract reaches the next ownership seam without implementing it. WYR1-C4
may begin only after DW1-D1 through D6 provide the exact generated ABI and
runtime authority defined by the paired kernel contract. D0 itself does not
add a startup profile, boot module, kernel handle, resource bundle, PIO access,
Interrupt delivery, selector 29, publication, or WYR1-C acceptance.

Real IRQ3 routing remains DW1-E. UART configuration/RX/TX, streams,
`uart16550d`, `consoled`, and shell behavior remain WYR1-D or later. Synthetic
Interrupt evidence in DW1-D does not prove physical q35 IRQ3.

## 2. Exact kernel ABI consumed by C4

Wyrmroot consumes only the exact generated Deepwyrm ABI revision containing:

- `DW_RIGHT_RESOURCE = 0x400`;
- `TASK_GROUP` compatible rights `0x7c0`;
- live `DEVICE_RESOURCE = 17`, compatible rights `0x3c3`;
- live `INTERRUPT = 16`, compatible rights `0x390`, with no `DUPLICATE`;
- `SIGNALED` compatibility for Interrupt;
- feature bit `DW_ABI_FEATURE_DEVICE_RESOURCE_INTERRUPT = 0x1`;
- syscalls `device_resource_claim = 0x00060001`,
  `device_pio_read = 0x00060002`, `device_pio_write = 0x00060003`,
  `interrupt_create = 0x00060010`, and
  `interrupt_ack = 0x00060011`;
- object-info topics `DEVICE_RESOURCE_V1 = 0x00030001` and
  `INTERRUPT_V1 = 0x00030002`; and
- boot module kind `DEEPWYRM_BOOT_DEVICE_TABLE_V1 = 4` with the exact layouts
  in the paired contract.

C4 checks the feature bit before using any device-family syscall. D1 generates
the bit identity, but Deepwyrm does not report it until D5 has made the complete
claim/PIO/Interrupt runtime usable. C4 does not
probe syscall gaps, reserve private object/right numbers, hand-copy generated
definitions, or infer support from boot-module presence.

## 3. Selected q35 product authority

The WYR1-C selected product adds one unique `READ_ONLY`, kernel-internal boot
device table module after the existing bootstrap, bootfs, and paging-handoff
modules. The loader retains a separate allocation for its exact logical bytes
and includes it in existing page-rounded physical overlap validation. The
table is never placed in bootfs and never mapped into userspace.

The table contains one 48-byte resource record under the exact 32-byte V1
header:

```text
resource_id            = 1
device_correlation_id  = 1
kind                   = X86_PIO_WITH_PLATFORM_INTERRUPT
pio_base               = 0x2f8
pio_length             = 8
interrupt_source       = 3
flags/reserved         = 0
```

The existing immutable WRDM remains Wyrmroot policy:

```text
role_id                 = 1
profile                 = canonical q35
resource kind           = PIO plus interrupt
PIO                     = [0x2f8,0x300)
IRQ                     = 3
driver                  = system/uart16550d
```

The kernel resource ID and Wyrmroot role ID are different types. Their equal
value in this one-role product is an explicit correlation, not a namespace
alias. C4 joins them only after querying the claimed DeviceResource and
matching every numeric field. A path, WRDM record, role, or content identity
cannot manufacture authority.

COM1 `[0x3f8,0x400)` and IRQ4 remain excluded loader/kernel diagnostics and are
never present in WRDM or the boot-device table.

## 4. Resource-domain lifetime and startup authority

When the selected boot table is present, Deepwyrm's primordial construction
creates an empty resource-domain TaskGroup as a child of init's own bootstrap
TaskGroup and binds every validated grant to it:

```text
bootstrap TaskGroup
├── /system/init
└── resource-domain TaskGroup         long-lived for this boot
    └── devmgr-generation TaskGroup   fresh per devmgr generation
        ├── /system/devmgr
        └── driver-attempt TaskGroup  fresh per driver attempt
            └── driver
```

Init receives four ordered bootstrap capabilities in the D5-selected product:

1. existing root AddressRegion with its existing rights;
2. existing read-only bootfs MemoryObject with its existing rights;
3. existing bootstrap TaskGroup with its existing rights; and
4. resource-domain TaskGroup with
   `MODIFY | DUPLICATE | TRANSFER | INSPECT | RESOURCE` (`0x7c0`).

This requires a new explicit bootstrap/runtime validation profile; historical
profiles and selectors retain their three-capability shape. The fourth handle
is not smuggled into a reserved field or reinterpreted from an old role.

Init stores the resource-domain handle separately from ordinary launch
authority. It never passes it to generic cleanup. Terminating the resource
domain is terminal fail-closed recovery for the boot, not a devmgr restart.

For each devmgr generation, init:

1. creates a fresh generation TaskGroup beneath the resource domain;
2. constructs devmgr in that generation group;
3. duplicates the exact resource-domain handle with only
   `RESOURCE | INSPECT` (`0x500`);
4. MOVEs that reduced handle through a new explicit DeviceCoordinator startup
   profile/minor; and
5. retains only the broad domain custodian and generation construction/reap
   handles.

Init is a member of the parent bootstrap group, not the resource domain, so its
own `device_resource_claim` returns `ACCESS_DENIED` even though it holds the
broad custodian. Each devmgr Process is a descendant and can claim when it also
possesses the reduced exact-domain handle.

`RESOURCE` is not created through `task_group_create`; it can only be reduced
from the kernel-minted resource-domain handle. No generic WYR1 launch profile
receives it.

## 5. Claim and devmgr custody

Current devmgr calls:

```text
device_resource_claim(
    exact_resource_domain_handle,
    resource_id = 1,
    requested_rights = READ | WRITE | MODIFY | DUPLICATE | TRANSFER | INSPECT,
    out_resource,
)
```

It then queries `DW_OBJECT_INFO_DEVICE_RESOURCE_V1` and requires exact:

```text
kind              X86_PIO_WITH_PLATFORM_INTERRUPT
resource_id       1
lease_generation  nonzero and fresh for this devmgr generation
PIO               [0x2f8,0x300)
interrupt source  3
flags/reserved    zero
```

Wyrmroot `BundleGeneration` is exactly the kernel lease generation. It is not
allocated by devmgr and cannot be substituted by supervisor, endpoint,
attempt, publication, role, or content generations.

Devmgr retains the broad claimed DeviceResource for its whole generation. It
does not transfer that parent handle to init, registryd, or a driver. For each
driver attempt it:

1. duplicates one reduced DeviceResource with
   `READ | WRITE | INSPECT` (`0x103`);
2. creates one fresh Interrupt from the broad parent with
   `WAIT | MODIFY | TRANSFER | INSPECT` (`0x390`);
3. prepares to MOVE that Interrupt with
   `WAIT | MODIFY | INSPECT` (`0x310`); and
4. binds both to the exact current role, bundle/lease generation, driver
   attempt, launch session, endpoint, and transaction.

Only one live Interrupt owns IRQ3 for one attempt. A driver-only restart first
finalizes the old Interrupt, then creates a new object/binding generation while
retaining the same devmgr lease/bundle generation. A devmgr replacement cannot
retain that generation; it claims a fresh lease after cleanup.

## 6. Exact WRDC bundle and MOVE transaction

The already-reserved `WRDC RESOURCE_BUNDLE` becomes inhabitable with exactly
two handles in this fixed order:

| Index | Type | Exact received rights |
| ---: | --- | --- |
| 0 | `DEVICE_RESOURCE` | `READ | WRITE | INSPECT` (`0x103`) |
| 1 | `INTERRUPT` | `WAIT | MODIFY | INSPECT` (`0x310`) |

Its payload carries the complete existing role/attempt/endpoint correlation
plus the exact `BundleGeneration = lease_generation`. No third handle, reordered
handle, broad right, omitted right, zero identity, or unrelated generation is
accepted.

Channel MOVE is failure-atomic:

- any validation, reservation, queue, or send failure leaves both handles
  owned by devmgr;
- devmgr may close or retry those exact retained handles according to the
  attempt state;
- successful send removes both sender handles exactly once;
- the receiver either validates and retains both or closes both before sending
  structured failure;
- devmgr must not close a successfully moved handle; and
- Channel teardown releases queued handles through Deepwyrm's typed finalizer.

The driver validates fresh queried metadata for both handles, then requires
the DeviceResource info to match WRDM and the bundle generation. Interrupt
info must name source 3, the same parent resource ID and lease generation, a
nonzero fresh object/binding generation, and `Armed` with zero flags before the
driver reports `DRIVER_READY`.

`CONTROL_READY` remains the C3 zero-handle pre-resource message. It cannot
advance to `Matched`, `AwaitingPublication`, or device-bound success.
`DRIVER_READY` is post-bundle and is the only driver message that advances the
current exact attempt to `AwaitingPublication`; `Published` still requires the
separate registry commit.

## 7. Failure precedence and cleanup

Before MOVE, failure leaves the complete per-attempt bundle with devmgr. After
MOVE, driver/process/Channel teardown owns its release. Malformed or stale
receiver metadata closes both received handles and reports failure if the
exact control endpoint remains usable.

Replacement cleanup is serialized in this order:

1. stop new publication and retire the exact published generation, if any;
2. close stale publication and direct-control endpoints;
3. request driver retirement or terminate the exact driver-attempt TaskGroup;
4. observe terminal driver state and reap its process, launch Channel, and
   attempt TaskGroup;
5. prove the old Interrupt masked/unbound/finalized and all reduced resource
   authority gone;
6. for a driver-only restart, derive a fresh attempt from the retained devmgr
   parent lease;
7. for a devmgr restart, terminate/reap the whole devmgr-generation TaskGroup,
   close the broad parent resource, wait until its grant is Available, then
   construct and claim from a fresh generation; and
8. only after complete cleanup enter Backoff or launch replacement.

An unprovable cleanup, live old handle, failed termination/reap, source still
bound, or grant still leased forbids overlap and becomes visible
`PermanentFailure` under the existing finite policy. Wyrmroot never asks the
kernel to force a grant Available while an old reference survives.

Resource-domain teardown immediately blocks claims and recursively terminates
all descendants. It is terminal for device authority until reboot and does not
create a replacement domain.

Failure classification follows the kernel contract. In Wyrmroot:

- malformed ABI/profile/WRDC/WRDM data is a permanent contract failure;
- missing feature support blocks C4 without probing;
- `ACCESS_DENIED`, wrong object/right/info, or identity mismatch is permanent;
- `ALREADY_EXISTS` while an old generation should be gone is cleanup failure,
  not permission to overlap;
- bounded transient construction failures use the accepted four-attempt,
  25,000,000 ns backoff only after cleanup is proved; and
- stale messages/endpoints are rejected without mutating current state.

## 8. Required C4/D5 tests inherited from D0

The implementation gates must preserve the passing Deepwyrm D0 custody model
and add Wyrmroot host/native cases proving:

- exact four-capability selected bootstrap intake and historical-profile
  isolation;
- init retains custody but cannot claim;
- current in-domain devmgr claims resource ID 1 and validates full info;
- broad parent never transits init, registryd, or driver;
- exact bundle handle order, types, rights, and generation;
- failed MOVE retains both sender handles;
- malformed receiver intake closes both handles and cannot send READY;
- successful MOVE transfers once with no sender double-close;
- driver death while devmgr lives permits a fresh Interrupt under the same
  lease generation only after old cleanup;
- devmgr death while driver handles live keeps the grant unavailable;
- old resource/Interrupt finalization precedes replacement claim;
- replacement lease generation differs from the old one;
- stale handle, bundle, endpoint, attempt, binding, READY, and publication
  correlations are rejected;
- cleanup failure blocks replacement and reports permanent failure;
- publication remains impossible before exact post-bundle `DRIVER_READY`; and
- no PIO, physical interrupt, UART, selector-29, or publication claim is made
  by a D0/D1/D5 host-only result.

## 9. Required-source disposition

The root recovery architecture, Wyrmroot platform conventions, WYR1
supervisor/registry/device contracts, C1/C2/C3 validations, Deepwyrm
object/wait/TaskGroup/boot contracts, and active DW1-D plan were read. The
current C3 direct-control, construction, loader, bootstrap, WRDM, resident
supervision, and C2 tooling paths were inspected.

The paired Deepwyrm contract records the exact pinned Fuchsia, xv6, and
rust-osdev source/license disposition. Wyrmroot adopts no upstream code. It
uses only the conceptual separation of coordinator/driver fault domains,
retire-before-replace ordering, and typed bounded PIO/Interrupt reasoning.

## 10. Closure and C4 entry condition

This document and the paired Deepwyrm D0 contract agree on every authority,
identity, layout, number, right, generation, MOVE boundary, failure, and
cleanup transition. Deepwyrm's bounded D0 host model passes.

The paired contract is reached, but WYR1-C4 remains blocked until DW1-D6 closes
on an exact generated/runtime/evidence tuple. At that handoff, C4 may implement
the startup claim handle, exact claim/info join, and current-generation bundle
intake without revising the authority model defined here.
