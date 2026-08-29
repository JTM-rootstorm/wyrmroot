# Wyrmroot WYR1-C1 Validation

**Status:** WYR1-C1 host/native implementation gate reached
**Date:** 2026-08-29
**Scope:** Real resident `system/devmgr`, immutable WRDM intake, structured
controller status/rebind, independent registry/devmgr recovery, and an
unnumbered deterministic host product
**Not live acceptance:** No selector, ESP, guest run, VM evidence, hardware
bundle, driver launch, publication success, COM2 access, or WYR1-C closure is
claimed

## Reached product tuple

- Wyrmroot product revision:
  `1c86fe383a69f7626b709cdb2966053c4c343d5b`
- Rust fork revision:
  `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`
- accepted toolchain: `wyrmroot-1.97.1-a92dc7f7`
- product root:
  `../../artifacts/wyr1-c/c1-product-1c86fe3`
- build receipt:
  `../../artifacts/wyr1-c/c1-product-1c86fe3/product/build-receipt.toml`

This document and later documentation-only commits do not replace the exact
product revision above.

## Product identities

| Item | SHA-256 | Size |
| --- | --- | ---: |
| system-init | `007085c353b14e1ec2f42f9a5a04911353f24c9a237f4c3649586b256abdbf5a` | 272,064 |
| registryd | `b6ad333ed6a45f811fe33e14df7bf4dde8c1fd042928c4301373ace2572cdd00` | 67,344 |
| devmgr | `55726b3b97b8a9b0aa52509f2422deabe907888019dddf20bbcd1fc7d6e527fc` | 27,688 |
| retained uart16550d | `702662b7c03c0bc5f0d39ce6719f763e0d58f71721be48a35f6ac31e99d8a7e4` | 10,096 |
| retained consoled | `b25b8f009a9584f77de60217b5e654924fa04ea2b37ea1f64867df6e80c7f94f` | 10,096 |
| retained wyrmsh | `8494fb423460972dc63f2e16b707d1a7082dfe5cd5b6f35842b4bb3bd80972f3` | 10,096 |
| WRRM | `17a0260886d5d793075617a7dd17638c1646f225ded20f42dd0b39ceaa455003` | 1,143 |
| WRDM | `a8ffb1414969d0eb7b2d70a3690e6bc35b4f5c6a707e6cd5fc572266ef78cde3` | 176 |
| bootfs | `b5eacf52d94f52b7e7f1eb436b10fce234b5bd05b114e61c2fc41c236a7537bd` | 400,260 |

The receipt binds the exact Cargo lock, accepted compiler/Cargo/LLD binaries,
toolchain manifest and tree, boot generation, artifact inspections, WRRM,
WRDM, and bootfs. The WRDM expected-driver identity is cross-checked against
the independently hashed `system/uart16550d` WRRM executable identity.

## Implementation result

- `StartupProfile::DeviceCoordinator` is a new profile; historical WYR1-A/B
  profile values and selector products retain their meanings.
- The real static no-std devmgr validates only its exact startup roles and
  immutable WRDM view before operational READY.
- Its status vocabulary can report operational waiting states but cannot
  encode match, publication, COM2 binding, or another device-success claim.
- Registry publication authority is installed through the supervisor-owned
  route. Registry replacement preserves the resident devmgr generation and
  uses a correlated one-handle rebind.
- Registry and devmgr are supervised independently with finite restart,
  cleanup-before-replacement, stable degraded exhaustion, and no stale native
  owners left in the resident poll set.
- Publication IDs, service generations, and registry transactions are
  distinct monotonic allocations retained across both recovery classes. A
  failed install burns its tuple instead of permitting replay.

## Host and native gates

The integrated tree passed:

- 87 `wyrmroot-system-init` unit tests, 14 model tests, and 7 evidence-source
  tests;
- 93 `wyrmroot-runtime`, 23 `wyrmroot-device-proto`, 7 `wyrmroot-devmgr`,
  15 loader-launch, 21 loader-process, 16 WRRM, and the focused bootfs suites;
- 173 xtask tests with one expected accepted-toolchain fixture ignored, plus
  six toolchain-lane contract tests;
- warnings-denied Clippy for the affected packages, formatting, and diff
  checks; and
- accepted-toolchain static native builds and canonical ELF inspection for all
  six product artifacts.

Independent integration review found and cleared WRDM/WRRM identity binding,
stale registry ownership, devmgr supervision, product validation, and
publication-identity reuse defects. The broader recovery behavior is covered
by focused classification/correlation tests and the existing supervisor model;
future fault-injection work may add a deeper end-to-end native recovery mock
without reopening this reached functional gate.

## Reproduction

The product command requires a pre-existing project-owned output parent, one
fresh output directory name, a clean Wyrmroot revision, and an isolated pinned
host target:

```text
WYRMROOT_PINNED_TARGET_DIR=/home/mike/Documents/Programming/OS-Project/wyrmroot/.tmp/cargo-target/wyr1c1-product-host \
  tools/pinned-cargo xtask wyr1c1 product \
  --output /home/mike/Documents/Programming/OS-Project/artifacts/wyr1-c/c1-product-1c86fe3
```

The accepted run emitted `WYR1_C1_HOST_PRODUCT_PASS` with `selector=none`,
`evidence=not-produced`, and the bootfs identity above. A prior failed
self-inspection attempt is preserved at
`../../artifacts/wyr1-c/c1-product-1528ec0`; it is partial output and is not an
accepted product.

## Gate boundary and nonclaims

This reaches the C1 implementation and host/native product gate described by
the execution-order contract: the real devmgr exists, is selected only by a
new product, validates static policy, becomes operational, exposes bounded
waiting/rebind status, and cannot claim device success.

The product is deliberately unnumbered and host-only. C2 remains responsible
for guest-product/request/inspection isolation and any admitted intermediate
observation path. Selector 29 remains reserved for the later post-DW1-D device
authority gate. Selectors 25, 27, and 28 are not reinterpreted. No manual boot
or debugger observation is promoted to structured acceptance evidence.
