# WYR1-D5 publication-generation handoff

**Date:** 2026-09-04  
**Status:** WRCS 1.1 codec and consumer contract; consumer integration and live D5 acceptance remain separate gates.

## Failure and ownership

The coordinator's A1-02 GDB diagnostic captured a normal D5 `ConnectStream`
request carrying publication generation `0xC10801`, while devmgr's connector
broker held publication generation `1`. The registry lifetime was `1`.
System-init had issued the service generation and installed it at registryd,
but WRCS 1.0 conveyed only the registry binding to devmgr. That omission let a
registry-lifetime value stand in for the service generation at the connector.
GDB is diagnostic evidence, not selector-32 acceptance.

The owner of service-generation issuance remains system-init's
`PublicationAllocator::issue`. One issued record supplies both registryd's
publication installation and the WRCS 1.1 handoff to devmgr. The latter must
carry exactly that record's nonzero `service_generation` paired with its
registry binding. No recipient derives it from, equates it with, or increments
the registry generation, endpoint ID, endpoint generation, driver attempt, or
any other identity namespace.

On U1 retirement, devmgr clears the active publication while retaining its
accepted service-generation high-water mark. U2 requires a newly issued
service generation from the actual system-init allocator, delivered with its
replacement binding. The resident consumer rejects zero, stale, reused, and
decreasing service generations, including after retirement, before changing
the accepted binding or connector publication. Existing binding-transition
checks still apply independently. Clearing current publication is not
permission to reset issuance or accept a lower generation.

## WRCS 1.1 wire contract

`wyrmroot_device_proto::controller_v1_1` provides `PublicationMessage`,
`encode`, and `parse`. It accepts only `InstallPublication` and
`RebindPublication`. Each message is exactly 80 little-endian bytes:

| Offset | Bytes | Meaning |
| ---: | ---: | --- |
| 0 | 4 | `WRCS` magic |
| 4 | 2 | major 1 |
| 6 | 2 | minor 1 |
| 8 | 4 | type 1 install or type 2 rebind |
| 12 | 4 | flags, zero |
| 16 | 4 | record size, exactly 80 |
| 20 | 4 | moved handles: 0 for install, 1 for rebind |
| 24 | 8 | nonzero devmgr supervisor generation |
| 32 | 8 | nonzero registry generation |
| 40 | 8 | nonzero registry publication endpoint ID |
| 48 | 8 | nonzero registry publication endpoint generation |
| 56 | 8 | nonzero controller transaction ID |
| 64 | 8 | reserved, zero |
| 72 | 8 | nonzero issued service generation |

Install activates the already transferred startup publication endpoint; rebind
transfers one replacement endpoint. The extension does not change handle
ownership or authorize additional handles. Native receive metadata must still
match the declared count and existing endpoint validation.

The implementation validates exact 1.1 framing, then copies the first 72 bytes
to a bounded stack header with minor 0 and size 72 solely to reuse the legacy
codec's common field checks. It independently validates the eight-byte service
generation. Reserved bytes 64 through 71 remain zero; they are not repurposed.

The old `controller` codec remains strictly WRCS 1.0: publication messages
are still 72 bytes and Status is still 88 bytes with its original grammar.
WRCS 1.1 does not define Status. Neither codec accepts the other's publication
version, truncated records, hidden trailing bytes, or version downgrades.
A D5 publication consumer must require 1.1 and reject a 1.0 handoff instead
of manufacturing a missing service generation. Selector 29 and selector 31
retain the historical 1.0 publication path; controller Status stays 1.0 for
all selectors.

## Source basis and integration boundary

The active root `DW1E_WYR1D_IMPLEMENTATION_PLAN.md` D5 phase requires the
initial native stream, stderr, driver-replacement, and child-replacement legs
on both default and SMP q35. Root `WYR1D5_PHASE_HANDOFF.md` preserves the
current join and diagnostic-only GDB boundary. Root
`BOOTSTRAP_AND_RECOVERY_ARCHITECTURE.md` requires fresh generations and
reconstructed topology, bounded recovery, and cleanup of affected clients.

The reached Wyrmroot source basis is:

- [WYR1-C coordinator contract, section 5](WYR1_C_DEVICE_COORDINATOR_CONTRACT.md):
  registry, endpoint, and published-service generations remain distinct.
- [WYR1-B registry contract](WYR1_B_REGISTRY_LAUNCH_CONTRACT.md):
  controller-owned installation and fresh service generation on replacement.
- [WYR1-D serial stream contract](WYR1_D_SERIAL_STREAM_CONSOLE_CONTRACT.md):
  connector requests must match the exact current publication, and driver
  replacement invalidates old streams and reconstructs console/child state.
- Existing `controller` codec: authoritative common WRCS header checks and
  unchanged 1.0 Status behavior.

The coordinator completed the active phase's required external-source review
before this bounded codec change. No external implementation was copied or
adapted; this extension reuses the project's existing codec and stays under
the crate's `GPL-3.0-or-later` license.

Native system-init issuance/handoff, devmgr resident storage and acceptance,
connector binding, and received-handle rejection cleanup are separate
coordinator-owned integration changes. They must preserve the single issued
generation across the registry and connector paths and prove U2 freshness.
The codec alone cannot establish those runtime properties.

## Codec validation

The codec lane starts from Wyrmroot
`6a0832fa6c4fbcfd38c9441a8a2ae7f0f2e59c16`. The pinned offline host wrapper
passed all 56 protocol unit tests (including nine new WRCS 1.1 tests) and nine
D0 model integration tests. The new fixture deliberately pairs registry
generation `1` with service generation `0xC10801`. Coverage includes both
message types and their handle counts, exact framing, all common identities,
zero service generation, full-width service generation, flags/reserved bytes,
wrong versions/types/sizes, legacy rejection, downgrade rejection, and
unchanged Status handling.

Commands use `WYRMROOT_PINNED_TARGET_DIR` set to the absolute lane-local
`.tmp/d5-publication` directory:

```text
tools/pinned-cargo test --locked --offline -p wyrmroot-device-proto
tools/pinned-cargo clippy --locked --offline -p wyrmroot-device-proto --lib --tests -- -D warnings
tools/pinned-cargo fmt -p wyrmroot-device-proto -- --check
git diff --check
```

All checks passed. The host wrapper rejects `--all-targets`; `--lib --tests`
is the supported scope for this protocol crate's Clippy check.

This is a Wyrmroot controller protocol extension. It changes neither the
Deepwyrm kernel/generated ABI nor public WRST grammar. No selector-32 live
acceptance, physical-UART result, D6 closure, or security-gate conclusion is
claimed by this handoff.
