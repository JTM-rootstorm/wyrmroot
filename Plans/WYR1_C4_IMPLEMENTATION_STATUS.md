# Wyrmroot WYR1-C4 Implementation Status

**Status:** Implementation started; startup/claim-intake foundation reached,
native product intake not yet reached
**Date:** 2026-08-30
**Wyrmroot base:** `f63d9609cc230ad40d9d519513ddcb7c8dd61865`
**Current Deepwyrm:** `f2066970a407c2f3c355f6bc5eacd2b9a32fb098`
**Generated ABI consumer pin:** `085b184c32ae1fa3d5ec322c86957dd5d036595c`
**Rust:** `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`

## 1. Dependency gate

DW1-D is accepted by `deepwyrm/docs/DW1_D_VALIDATION.md`. Its frozen
pre-sign product tuple remains Deepwyrm `c153ab9...`, Wyrmroot `6aa6cc3...`,
and generated ABI `dc26df4...` / tree `a9b0671...`. The current signed-history
consumer pin `085b184...` preserves the accepted generated ABI content and is
the revision WYR1-C4 must consume.

The reached contracts remain:

- `deepwyrm/Plans/DW1_D0_DEVICE_RESOURCE_INTERRUPT_CONTRACT.md`;
- `Plans/WYR1_C_DEVICE_HANDOFF_CONTRACT.md`; and
- `Plans/WYR1_C_DEVICE_COORDINATOR_CONTRACT.md`.

## 2. First implementation checkpoint

This checkpoint adds the smallest production-facing foundation that can be
validated without selecting media or claiming live authority:

- a distinct WRLP 1.9 `DeviceCoordinatorResourceDomain` startup profile;
- exact four-handle order: self root, publication Channel, immutable WRDM,
  and reduced resource-domain TaskGroup;
- exact received claim rights `RESOURCE | INSPECT` (`0x500`);
- sender-side staging through a duplicate with
  `RESOURCE | INSPECT | TRANSFER` (`0x580`);
- failure-atomic loader ownership: a failed INIT MOVE closes only the staged
  duplicate and retains the caller's publication endpoint, WRDM, and broad
  domain custodian;
- historical WRLP 1.5 C1-C3 `DeviceCoordinator` meaning remains unchanged;
- generated-ABI-backed, allocation-free devmgr policy validation for the exact 48-byte V1 resource
  identity, resource ID 1, nonzero kernel lease, COM2 `[0x2f8,0x300)`, IRQ3,
  and zero flags/reserved fields; and
- `BundleGeneration` is taken only from the kernel lease generation.

## 3. Focused validation

The isolated pinned Rust 1.97.1 host target passed:

```text
tools/pinned-cargo test --locked \
  -p wyrmroot-loader -p wyrmroot-devmgr --lib --tests
```

The affected results were:

- devmgr library: 13 passed;
- devmgr native source contracts: 4 passed;
- loader launch protocol: 18 passed;
- loader process transactions: 30 passed; and
- all other selected loader suites passed.

The complete locked host workspace also passed; xtask reported 217 passed and
one toolchain-artifact test ignored by its explicit environment gate. The
complete workspace library/test Clippy gate passed with warnings denied.

The focused tests prove profile isolation, exact roles/rights, broad-parent
non-transit, failed-MOVE retention, staged-duplicate cleanup, exact resource
identity admission, COM1/IRQ4 rejection by mismatch, and lease-derived bundle
generation.

## 4. Required-source disposition

The active WYR1-C plan, root recovery/licensing/capability sources, Wyrmroot
architecture index and platform/supervisor/registry/device contracts, C1-C3
validation records, paired D0/handoff contracts, DW1-D closure record, and
current loader/devmgr/system-init/runtime/product seams were reviewed.

The pinned Fuchsia driver-manager files remain conceptual prior art under the
existing contract disposition. They were unavailable in the local source
checkouts for this checkpoint, and no remote retrieval or upstream code import
was performed. No Fuchsia ABI, FIDL, component, devfs, topology, or driver-host
policy was adopted.

## 5. Next bounded package

The next WYR1-C4 package is production startup and native claim intake:

1. add the selected WRBP V3 production bootstrap path while preserving every
   historical V2 profile;
2. retain the broad domain custodian only in init and construct each devmgr
   generation beneath that domain;
3. launch devmgr with WRLP 1.9;
4. query the ABI feature bit before the device syscall family;
5. claim resource ID 1 with `0x3c3`, query generated type/rights/info, and
   admit it through the policy checkpoint implemented here; and
6. retain the broad DeviceResource in devmgr without creating or transferring
   an Interrupt until WYR1-C5.

## 6. Nonclaims

This checkpoint does not yet prove a production bootstrap V3 path, native
claim syscall, devmgr replacement reclaim, selector 29, VM behavior, physical
IRQ3 routing, Interrupt creation/delegation, driver READY, publication, UART
I/O, console streams, shell behavior, or WYR1-C closure.
