# Wyrmroot WYR1-C2 Validation

**Status:** WYR1-C2 deterministic unselected product gate reached  
**Date:** 2026-08-29  
**Scope:** Reviewed q35 COM2 role source, canonical WRDM, production loader,
kernel and bootstrap, C1 real-devmgr product, deterministic ESP, exact frozen
request/receipts, and independent host inspection  
**Not live acceptance:** No selector, guest run, VM evidence, hardware bundle,
driver launch, COM2 access, publication success, or WYR1-C closure is claimed

## Reached product tuple

- Wyrmroot product revision:
  `2d49d27e57f8dbe5f34fb60bd8e5a884f70d3cfc`
- Wyrmroot tree:
  `119e132fafa8bf6f489d0e1a3e9d2846ba98c5a8`
- Deepwyrm production-kernel revision:
  `2e06491472c80ef110f4adefac4c0d96079b2c8d`
- generated ABI revision:
  `cfc69bd8a49819ce1cda1a132cf56e55c93f92e4`
- generated ABI tree:
  `1c6a74f130e386eee95b3780c75950beefd0037d`
- Rust fork revision:
  `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`
- accepted toolchain: `wyrmroot-1.97.1-a92dc7f7`
- product root:
  `../../artifacts/wyr1-c/c2-product-2d49d27`
- request:
  `../../artifacts/wyr1-c/c2-product-2d49d27/wyr1-c2-request.toml`

The request and both receipts record `selector = "none"` and
`evidence = "not-produced"`. Later documentation-only commits do not replace
the exact product revision above.

## Frozen identities

| Item | SHA-256 | Size |
| --- | --- | ---: |
| request | `12570ee5b58943a340fc64a316cbebb7a56fe069e8388ade25a5880cfba6ef09` | 2,331 |
| C2 base receipt | `5a4601daef650450a623d33143433dfc0874dc68d0756cc6897d45d9897a2ed5` | 2,420 |
| C2 image receipt | `cc5329fcf9653484fc7bbee1ae4644d581ba1f7c2bac0da978663bd0289bfe6b` | 2,989 |
| reviewed q35 COM2 source | `ff5e05282e4f0686ec578c0ca7b30c0b26d06f4790126e4699b2263310849ddf` | 269 |
| canonical WRDM | `a8ffb1414969d0eb7b2d70a3690e6bc35b4f5c6a707e6cd5fc572266ef78cde3` | 176 |
| observation policy | `ddd7bc52a4d959b7896ad6eef39fd243e018066588b90b566ff3c2cdf0ead141` | 197 |
| devmgr | `55726b3b97b8a9b0aa52509f2422deabe907888019dddf20bbcd1fc7d6e527fc` | 27,688 |
| retained uart16550d acceptance actor | `702662b7c03c0bc5f0d39ce6719f763e0d58f71721be48a35f6ac31e99d8a7e4` | 10,096 |
| WRRM | `d074ebb83fd895abac83e36c3f20d77dc2ab2a155cfa970c0fca1df4228ee55f` | 1,143 |
| bootfs | `ca16f7578fe56bba55cba2d01770cee8277f866eace9ebec9859021aa1068b5c` | 400,260 |
| production loader | `dd2ab479245f4b11bcd96ac6234f96abbba6f43249fa5284c6bf59b1974cdb14` | 134,144 |
| production kernel | `6cb619ec165794eaca10384662a64f492232f809b4459a24cba32ce80864c08b` | 13,131,032 |
| production bootstrap | `1ed53a745edcadc33e49b9ac87b29616ca7c775df5281451fff96dfa7abf7fc1` | 57,568 |
| ESP | `0960e20ceb996ef81185ece3b0cdea17e3377c222987b34a71339e31506e7987` | 134,217,728 |

The 400,260-byte bootfs occupies 98 4-KiB pages and remains below the
existing 128-page functional ceiling, so no C2 capacity increase was needed.

The image receipt also binds the G3 inspection report
`10b569adf4c3700fc6a1ff45b3174d8bec5b61a56057d98a8d3aa3ee9b0ee72c`
and independently records the loader, kernel, bootstrap, and bootfs hashes
consumed by the ESP.

## Implementation and validation result

- `wyr1c2 freeze` creates only a fresh unselected product and canonical
  request. It does not allocate or infer selector 29.
- The reviewed TOML source is compiled to canonical allocation-free WRDM v1;
  both source and output identities enter the request and receipts.
- The request binds devmgr, the retained device-driver acceptance actor, WRRM,
  bootfs, production loader/kernel/bootstrap, loader inspection, provenance,
  observation policy, and exact source revisions.
- Producer-stage Cargo hard links are admitted only long enough to copy exact
  bytes into owned single-link frozen artifacts. Native and UEFI inspectors
  consume sealed exact-byte inputs under a fixed tool environment.
- Freeze, image, and inspect share one retained-descriptor acceptance boundary.
  It revalidates every accepted leaf, directory identity, exact mode and bytes,
  and rehashes the complete ESP before reporting success.
- Selectors 25 and 27, their request schemas, startup profiles, and media paths
  are unchanged. Selector 28 is also not reinterpreted.

Canonical validation at the reached product revision passed:

- `WYR1_C2_FREEZE_PASS`;
- `WYR1_C2_IMAGE_PASS`;
- `WYR1_C2_INSPECTION_PASS` with request SHA-256
  `12570ee5b58943a340fc64a316cbebb7a56fe069e8388ade25a5880cfba6ef09`;
- 206 xtask unit tests with one accepted-toolchain environment fixture ignored;
- all six toolchain-lane contract tests; and
- warnings-denied Clippy, formatting, shell syntax, and diff checks on the
  reviewed implementation candidate.

Independent integration and Daybreak soundness reviews cleared the exact tree
`119e132fafa8bf6f489d0e1a3e9d2846ba98c5a8`. The Daybreak review used
`gpt-daybreak-blue-latest`, high effort, on 2026-08-29. The reviewed lane tip
was `3c01754703b3f0edaff3750293877dd7ac78c9dd`; canonical revision
`2d49d27e57f8dbe5f34fb60bd8e5a884f70d3cfc` has the identical tree.

## Preserved non-accepting attempts

Three fresh partial outputs are retained as failure evidence and are not
accepted products:

- `c2-product-e736636`: production UEFI target root was rejected through the
  retained procfd path;
- `c2-product-8cbfb32`: the scoped Cargo target root was rejected through the
  retained procfd path; and
- `c2-product-abd687a`: a legitimate hard-linked Cargo loader output was
  incorrectly rejected as not single-link.

The accepted fourth attempt used the remediated fresh directory
`c2-product-2d49d27`. None of the failed directories was reused or deleted.

## Reproduction

```text
WYRMROOT_PINNED_TARGET_DIR=/home/mike/Documents/Programming/OS-Project/wyrmroot/.tmp/cargo-target/wyr1c2-product-2d49d27 \
  tools/pinned-cargo xtask wyr1c2 freeze \
  --output /home/mike/Documents/Programming/OS-Project/artifacts/wyr1-c/c2-product-2d49d27

WYRMROOT_PINNED_TARGET_DIR=/home/mike/Documents/Programming/OS-Project/wyrmroot/.tmp/cargo-target/wyr1c2-product-2d49d27 \
  tools/pinned-cargo xtask wyr1c2 image \
  --request /home/mike/Documents/Programming/OS-Project/artifacts/wyr1-c/c2-product-2d49d27/wyr1-c2-request.toml

WYRMROOT_PINNED_TARGET_DIR=/home/mike/Documents/Programming/OS-Project/wyrmroot/.tmp/cargo-target/wyr1c2-product-2d49d27 \
  tools/pinned-cargo xtask wyr1c2 inspect \
  --request /home/mike/Documents/Programming/OS-Project/artifacts/wyr1-c/c2-product-2d49d27/wyr1-c2-request.toml
```

## Gate boundary and nonclaims

This reaches the C2 deterministic host/product isolation gate. It does not
reach the selector-specific task because selector 29 is not formally admitted.
No VM was run and no guest observation or acceptance evidence was produced.
The device coordinator remains in its truthful pre-DW1-D operational waiting
state. WYR1-C3 launch-channel work, DW1-D hardware authority, WYR1-C4 and later
hardware intake, COM2 behavior, and WYR1-C live closure remain separate.
