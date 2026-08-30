# Wyrmroot WYR1-C4 Implementation Status

**Status:** Complete at the C4 production compile and host-model gate
**Date:** 2026-08-30
**Completion source base:** `1d3e091cb627803c424fc61e4348f1b3a83d0b41`
**Current Deepwyrm:** `f2066970a407c2f3c355f6bc5eacd2b9a32fb098`
**Generated ABI consumer pin:** `085b184c32ae1fa3d5ec322c86957dd5d036595c`
**Accepted Rust:** `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`

## 1. Dependency and authority boundary

DW1-D is accepted by `deepwyrm/docs/DW1_D_VALIDATION.md`. Its frozen
pre-sign product tuple remains Deepwyrm `c153ab9...`, Wyrmroot `6aa6cc3...`,
and generated ABI `dc26df4...` / tree `a9b0671...`. The current signed-history
consumer pin `085b184...` preserves that accepted generated ABI content.

Deepwyrm remains authoritative for boot-table validation and resource-domain
claim/revocation semantics. Wyrmroot does not manufacture authority from WRDM:
it validates the resulting generated DeviceResource object and correlates it
with the exact immutable COM2 manifest and current devmgr generation.

The reached contracts remain:

- `deepwyrm/Plans/DW1_D0_DEVICE_RESOURCE_INTERRUPT_CONTRACT.md`;
- `Plans/WYR1_C_DEVICE_HANDOFF_CONTRACT.md`; and
- `Plans/WYR1_C_DEVICE_COORDINATOR_CONTRACT.md`.

## 2. Completed production path

C4 now supplies one selected production path while preserving all historical
products:

1. primordial bootstrap accepts exact WRBP V3 with four ordered capabilities;
2. it freshly validates self root, bootfs, ordinary loader TaskGroup, and the
   distinct broad resource-domain TaskGroup;
3. `/system/init` starts with WRLP 1.7 `SupervisorResourceDomain` and retains
   broad resource-domain custody separately from ordinary `LoadAuthority`;
4. every current and replacement devmgr generation receives a TaskGroup whose
   parent is that retained resource domain;
5. init stages only a reduced `RESOURCE | INSPECT` duplicate into WRLP 1.9
   `DeviceCoordinatorResourceDomain`; and
6. devmgr queries the generated ABI feature family before any member syscall,
   claims resource ID 1 with exact broad rights `0x3c3`, validates fresh object
   type/rights and the generated 48-byte V1 resource record, then retains the
   DeviceResource for its process lifetime.

The accepted resource identity is exact:

- kind `X86_PIO_WITH_PLATFORM_INTERRUPT`;
- resource ID 1;
- nonzero kernel lease generation;
- COM2 PIO `[0x2f8, 0x300)`;
- IRQ3;
- zero flags and reserved fields; and
- `BundleGeneration` derived only from the kernel lease generation.

The devmgr controller reports `OperationalResourceOwned` only after the exact
current registry binding and resource admission are both present. This status
is deliberately not driver-bound or published-device readiness.

## 3. Ownership, replacement, and isolation

Broad resource-domain custody never enters generic init load authority and is
never usable by init itself. The only representable reduction is for a devmgr
generation descendant. Failed loader MOVEs close only the staged duplicate and
retain init's broad custodian.

The claimed DeviceResource remains local to the exact devmgr process. Existing
restart supervision requires task-group terminal cleanup before a replacement
generation is launched, and every replacement receives a fresh reduced startup
duplicate and a fresh generation TaskGroup. The implementation therefore uses
the reached Deepwyrm finalization/revocation contract; live proof that the old
lease is Available before the replacement claim remains a C6 validation item.
Controller supervisor, transaction, registry, endpoint, and generation checks
reject stale endpoints from the retired generation. A registry rebind within
the same devmgr generation preserves the admitted lease and cannot trigger a
second claim.

Historical isolation remains explicit:

- WRBP V2 continues to launch the three-capability WRLP 1.2 `Supervisor` path;
- WYR1-C1 through C3 continue to use WRLP 1.5 `DeviceCoordinator`;
- selector-private DW1-D6 behavior remains feature-gated and separate; and
- the C4 product feature cannot be combined with historical/test bootstrap
  variants.

## 4. Validation

The complete locked host workspace passed:

```text
tools/pinned-cargo test --locked --workspace
```

The xtask suite reported 217 passed and one explicitly environment-gated
toolchain-artifact test ignored. All other workspace, integration, source
contract, and doc tests passed.

The warnings-denied workspace gate passed:

```text
tools/pinned-cargo clippy --locked --workspace --lib --tests -- -D warnings
```

The native C4 profiles passed compile-only checks through the accepted
immutable product compiler, not the host compiler:

```text
tools/pinned-cargo xtask test host wyr1c4
```

That gate compiles the selected bootstrap, system-init, and devmgr binaries for
`x86_64-unknown-wyrmroot` with their exact `wyr1c4-production` features. The
task owns an isolated scratch target, verifies the accepted compiler bundle
before and after use, runs offline and locked, and retires the scratch output.

Focused coverage proves:

- exact WRBP V3 four-handle launch and V3 READY;
- WRBP V2 and D6 isolation;
- broad init custody and devmgr-descendant-only reduction;
- current and replacement devmgr TaskGroup parenting;
- WRLP 1.9 reduced-domain transfer and failed-MOVE retention;
- exact ABI framing/version/page-size validation and feature-before-family ordering;
- exact resource claim rights, type, rights, metadata, and lease generation;
- COM1/IRQ4 and other resource-identity mismatch rejection;
- `OperationalResourceOwned` binding requirements; and
- tracked claim cleanup on every subsequent fallible C4 transition;
- same-generation registry rebind without a second claim; and
- absence of C3 driver launch, Interrupt creation, or bundle delegation in the
  selected C4 path.

Formatting and diff-integrity checks also passed.

## 5. Required-source disposition

The active WYR1-C plan, root recovery/licensing/capability sources, Wyrmroot
architecture index and platform/supervisor/registry/device contracts, C1-C3
validation records, paired D0/handoff contracts, DW1-D closure record, and
current bootstrap/loader/devmgr/system-init/runtime seams were reviewed.

The pinned Fuchsia driver-manager files remain conceptual prior art under the
existing contract disposition. They were unavailable in the local source
checkouts for this implementation, and no remote retrieval or upstream code
import was performed. No Fuchsia ABI, FIDL, component, devfs, topology, or
driver-host policy was adopted.

## 6. C4 gate result and nonclaims

The C4 gate is reached: exactly one current devmgr generation owns the WYR1-C
COM2 coordination authority. Init, registryd, consoled, wyrmsh, and unrelated
jobs own none.

C4 does not claim a driver launch, Interrupt creation, reduced two-handle driver
delegation, driver resource validation/READY, device publication, selector 29,
VM behavior, physical IRQ3 delivery, UART I/O, console streams, shell behavior,
live restart evidence, or final WYR1-C closure. Those remain WYR1-C5/C6 work.
