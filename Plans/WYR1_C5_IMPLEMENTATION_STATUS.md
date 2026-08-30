# WYR1-C5 Resource Delegation and Readiness Status

**Status:** Complete host/native implementation gate
**Repository:** `JTM-rootstorm/wyrmroot`
**Predecessor:** WYR1-C4 at `5d006c1c07af2b6657e25830f1d5278e78475700`

## 1. Closed scope

WYR1-C5 now implements the first production direct resource handoff from the
resident device coordinator to one separate static `uart16550d` acceptance
actor. The selected profile preserves the C4 resource-domain startup path and
parents the driver-attempt TaskGroup beneath the current devmgr-generation
TaskGroup.

For the exact COM2 claim, devmgr:

Before the resource bundle, the C5 construction hop stages the fresh child
control endpoint through init with `0x193` and the loader reduces it to the
actor's exact `0x113`. This is sender-only `TRANSFER` authority; it does not
change the actor startup profile or the C3 historical path.

1. retains the broad `DeviceResource` with rights `0x3c3`;
2. duplicates one sender-side staging resource with
   `READ | WRITE | TRANSFER | INSPECT = 0x183`, then requests the exact driver
   rights `READ | WRITE | INSPECT = 0x103` on MOVE;
3. creates one fresh `Interrupt` with
   `WAIT | MODIFY | TRANSFER | INSPECT = 0x390`;
4. freshly validates both objects and their resource, lease, source, state,
   object-generation, and binding-generation correlations;
5. atomically MOVEs the fixed two-handle WRDC bundle in the order
   `[DeviceResource 0x103, Interrupt 0x310]`; and
6. accepts only the exact generation-bound, zero-handle `DRIVER_READY` before
   sending registry `Publish` and requiring `Published`.

The earlier `OperationalResourceOwned` controller status remains a C4 custody
acknowledgement to init. It is emitted before driver construction and is not a
driver-readiness or publication claim. C5 publication truth is maintained by
the distinct WRDC `DRIVER_READY` and WRRG `Published` transitions.

## 2. Driver actor and cleanup

The C5 actor keeps the C3 startup profile: self root plus one direct control
Channel. No resource travels through init or the startup record. After startup,
the actor receives exactly two WRDC handles and validates:

- exact received types, rights, order, and zero reserved fields;
- COM2 resource ID 1, PIO `[0x2f8, 0x300)`, IRQ 3, and bundle lease generation;
- an Armed interrupt with nonzero object and binding generations;
- the same parent resource ID and lease generation; and
- zero interrupt flags and reserved fields.

Malformed or stale intake closes both authority handles and cannot emit READY.
After READY, the actor retains both handles until an exact WRDC `RETIRE` or
control-peer closure, then closes Interrupt, DeviceResource, and control in a
single cleanup path. Devmgr emits exact RETIRE during intentional controller
shutdown and publication failure; pre-MOVE failures retain and close both
sender handles, while successful MOVE never double-closes them.

The C3 `CONTROL_READY` route and C4 claim-only route remain separately
feature-gated and compile-tested. C5 has distinct `BundleTransferred` and
`DriverReady` launch states, so zero-bundle C3 readiness cannot satisfy the C5
gate.

## 3. Validation

Focused locked host tests cover:

- pre-claim launch rejection;
- construction-before-bundle ordering;
- exact bundle and READY correlation;
- stale bundle-generation rejection;
- READY-before-publication and publication replay rejection;
- distinct C3 and C5 driver-launch states;
- generation-exact RETIRE and reap cleanup;
- exact two-handle actor metadata validation and no device I/O;
- malformed intake cleanup; and
- driver-attempt parenting beneath the current devmgr generation.

The focused host command passed:

```text
tools/pinned-cargo test --locked \
  -p wyrmroot-devmgr \
  -p wyrmroot-device-proto \
  -p wyrmroot-wyr1-retained-stubs \
  -p wyrmroot-system-init
```

The accepted immutable product compiler, offline lockfile, warnings-denied
flags, isolated target, and exact C5 features compiled all four selected guest
binaries:

```text
tools/pinned-cargo xtask test host wyr1c5
```

That gate checks `wyrmroot-bootstrap`, `system-init`, `devmgr`, and
`uart16550d` for `x86_64-unknown-wyrmroot` with their exact
`wyr1c5-production` features.

## 4. Required-source disposition

Implementation followed the active WYR1-C plan, device coordinator contract,
paired device handoff contract, bootstrap/recovery architecture, C3/C4 status,
and accepted DW1-D contract/validation. The pinned Fuchsia driver-manager files
at revision `6a606ff7fd9b055edee6557566fb3f112df1a812` remain conceptual prior art
only: coordinator/driver fault-domain separation and retire-before-replace
ordering informed the result. No Fuchsia code, FIDL, component policy, or
driver-host assumptions were imported.

## 5. Explicit C6 boundary

WYR1-C5 does not claim selector 29, live VM/media acceptance, physical IRQ3
delivery, UART PIO, interrupt fire/wait/ack/rearm, serial bytes, console/TTY/
shell service, driver restart P1/P2, stale live endpoint rejection, devmgr
replacement, or live grant-recovery evidence. Those remain WYR1-C6 work.
