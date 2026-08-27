# Wyrmroot WYR1-B Validation

**Status:** WYR1-B accepted
**Date:** 2026-08-27
**Scope:** Bootstrap registry, direct service routing, scoped launch/job service,
orphan reaping, selector-27 acceptance, and selector-25 regression only

## Accepted product tuple

- Deepwyrm: `d891f27d45cc6f2825e7527f5f5cc3410a29d1da`
- Wyrmroot product: `a47f7bf7e03f378abdc884bb61bc6fabef5d1a78`
- Rust: `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`
- evidence root:
  `../../artifacts/wyr1-b/candidate-d891f27-a47f7bf`

The Wyrmroot revision above is the accepted product revision. This validation
record and later documentation-only commits do not replace that identity.

## Capacity remediation and freeze

The first exact-current selector-25 regression attempt exposed a stale
selector-local budget: the accepted WYR1-A media used 42 pages, while the
integrated WYR1-B normal and degraded products use 76 pages. Deepwyrm
`d891f27d45cc6f2825e7527f5f5cc3410a29d1da` raises only selector 25 to a
functional-first 128-page ceiling. Ordinary, WYR0, selector-26, selector-27,
the 32 MiB loader intake, and public ABI limits are unchanged. Wyrmroot
`a47f7bf7e03f378abdc884bb61bc6fabef5d1a78` measures and rejects an oversized
selector-25 bootfs during freeze, before ESP assembly.

The fresh project-bound freeze passed on the exact tuple above. Selector 27 is
119 pages; selector-25 normal is 309,192 bytes / 76 pages and degraded recovery
is 308,576 bytes / 76 pages.

## Frozen artifact identities

| Product | Request SHA-256 | Bootfs SHA-256 | ESP SHA-256 | Receipt/result SHA-256 |
| --- | --- | --- | --- | --- |
| selector 27 | `03c255bfa73ad59a11a30efe6ba327d7b1263ae4aa1267e89d43ff76e39e82c8` | `cdf011dc5ae3785a914f10ba01d0bb4566dac3f359eadb8d18ac7311d82dedca` | `0def2d288c4539a52a6968988e4ca107de7f3bf3d275e66770624cbe9b4920fc` | run receipt `278a0285dbc087974fba200dc2e024cc9536f544767948ae145b969b2a29d640` |
| selector 25 normal | `670b42cf56b6e9343d0a63e49fb279665347595e8d16cc5f9f4ecbe75fc72b9e` | `51fb2a05f2817f0057f6542db7d54575084c749a001d169a3d7f0175bb1911bb` | `3bf154a0f05cfe44f9185229e65d3a233d5b96f4efa0227149d708383e82c30c` | paired result `9091bc68890b28e520c8b049b671f64437ef8c9c7c79c57dbf382847a2ceba37` |
| selector 25 degraded recovery | `2cdbf899fa3ee1e49163ceac6c2ae44f38aa6025c1b6afd088973df30cda5cf2` | `a8207d8c3e427edf0614299c4ee2b875e68a36210dc987b7a6b2695eb0923134` | `f86ea2e02cf0f2eb4d5efdc90816e8dc4d5f0d4be226fca90f13eb49625473cf` | paired result `1bf53ac7f8b4b4e795bcb0e56d471cd591d36d4beaa702e9d6ea6aafe941a629` |

## Host and product gates

- Deepwyrm passed all 28 x86_64 entry-contract tests, all 46 x86_64
  syscall-contract tests, warnings-denied library Clippy, formatting, and diff
  checks.
- Wyrmroot passed 158 xtask tests with the one expected accepted-toolchain
  artifact test ignored, all six launcher contract tests, warnings-denied
  xtask test-target Clippy, formatting, and diff checks.
- The exact freeze and selector-27 inspection passed source, toolchain, native
  artifact, stack-metadata, request, receipt, bootfs, ESP, and clean-tree
  qualification.
- Both selector-25 requests passed WYR1 receipt inspection and fresh
  project-bound default/SMP handoff preparation.

## Live boot matrix

| Selector/scenario | Profile | Result | Structured evidence |
| --- | --- | --- | --- |
| selector 27 registry/launch | one-vCPU q35/OVMF | PASS, detail `0`, terminal `normal` | 14 ordered `WRB1` records |
| selector 25 normal | default, 1 vCPU / 1024 MiB | PASS, detail `0`, terminal `NORMAL` | 5 ordered `WYR1` records |
| selector 25 normal | SMP, 4 vCPU / 2048 MiB | PASS, detail `0`, terminal `NORMAL` | same 5 records and identity |
| selector 25 degraded recovery | default, 1 vCPU / 1024 MiB | PASS, detail `0`, terminal `DEGRADED` | 9 ordered `WYR1` records |
| selector 25 degraded recovery | SMP, 4 vCPU / 2048 MiB | PASS, detail `0`, terminal `DEGRADED` | same 9 records and identity |

Selector 27 emitted
`WYR1_B_EVIDENCE_PASS records=14 test_id=27 detail=0 terminal=normal`.
Its serial SHA-256 is
`ec58a5d076542600947d30b157329a2c7119a9f7838cefdd271ab8605fc45849`;
QEMU exited with status 33, did not time out, and was reaped cleanly.

The canonical verified designated-VM runner accepted both selector-25 pairs.
Normal default and SMP serial logs are byte-identical at
`cef34f0460eb832724b6b7cead69e917af7b225fb3558443b34cb92761af61c2`;
their structured evidence SHA-256 is
`88cca5606530512514400ed1817346225979da3c5f1f39754a082c789adc9d4f`.
Degraded default and SMP serial logs are byte-identical at
`8f4c2c1b7ae65c9e681c2bf0f5ae0c14b9e03486396d04cfaa7562ba317b77f9`;
their structured evidence SHA-256 is
`07953691957c7932a26759375971998a31b3b0d0ed73728195fbe1f789897242`.
The independent Wyrmroot evidence join reported 5/5 `NORMAL` and 9/9
`DEGRADED` records.

## Required-source and provenance disposition

The root WYR1-B plan, WYR1-B registry/launch contract, reached WYR1-A
supervisor contract and validation, Bootstrap and Recovery Architecture,
Wyrmroot architecture index/platform conventions, WYR0 startup/loader and
generation/replay contracts, and Deepwyrm Channel/handle-transfer behavior were
used as authority. The phase's pinned Fuchsia source was used for conceptual
comparison only. No external code, wire ABI, or component policy was copied.

## Acceptance boundary and nonclaims

The selector-27 gate proves the bounded registry/publication/direct-routing and
launch/job lifecycle named by the WYR1-B contract. The selector-25 matrix proves
that the exact current product preserves WYR1-A normal supervision and degraded
recovery on default and SMP VM profiles. Incidental virtual devices and
libvirt defaults are not hardware certification.

WYR1-B does not claim DW1-C SMP scheduling, WYR1-C device coordination,
WYR1-D stream semantics, WYR1-E interactive shell behavior, full WYR1 milestone
closure, physical hardware, or the later final Daybreak gate.

## Disposition

WYR1-B is accepted at the exact product tuple and artifact identities above.
All phase implementation tasks, host/product gates, selector-27 live
acceptance, and exact-current selector-25 normal/degraded default/SMP
regressions are complete.
