# Wyrmroot WYR1-A Validation

**Status:** WYR1-A accepted
**Date:** 2026-08-26
**Scope:** Permanent `/system/init`, immutable RRC-A manifest, EARLY-role
supervision, finite restart, and degraded recovery only

## Accepted product tuple

- Deepwyrm: `44e60031d0b080459c8cd412a2f66a894896493d`
- Wyrmroot product: `35b11eefe8707a1a1e8da15477da1e4552346c62`
- Rust: `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`
- selector: `permanent-supervisor-rrc` (test ID `25`)
- normal evidence root:
  `../artifacts/wyr1-a/phase-a-normal-closure-44e6003-35b11ee/normal`
- degraded evidence root:
  `../artifacts/wyr1-a/phase-a-degraded-closure-44e6003-35b11ee/degraded_recovery`

The Wyrmroot revision above is the accepted product revision. This validation
record and later documentation-only commits are not a replacement product
identity.

## Frozen artifact identities

### Normal profile

| Item | SHA-256 |
| --- | --- |
| request | `3c70e0a6fbeefc6e3d40bed1f012df36ad49ea880abbd3147d73f14ce822855a` |
| provenance | `442fe4ad26a497c51a5139be80f0832f9a7ee204197574043544680b7c7652d4` |
| build receipt | `0e262b196279a537fac5a8351a78b150f9285df18869091ef9eabbb8216e967f` |
| bootfs | `356efea0f4b0a4d587ea0804f139f3e7247ee25db1df3e2da92a4788ac588afc` |
| RRC-A manifest | `dfea745ef159d27175564005dfbab19b4ec644f2d66182a555838c31c551c5e8` |
| ESP | `c1ccd7ba395bf340f96646e8da9860e009935a53d42da97502cca58d6b331604` |
| Deepwyrm kernel and symbols | `c8e77ad07adcb390424eb79c2705b2110f3a1f6d442b52fbe75a8a7b52df8266` |
| EFI loader | `8d5bc33b3a45e2e6345a6c373678020c0c489c19991137c88b35d658e236216d` |
| `/system/init` | `12302df1f75ee564c74d65d536621171aac384e9997ed494bbc52b45ec5d8324` |

The normal bootfs is 167,448 bytes and fits the accepted 41-page ceiling
(167,936 bytes).

### Degraded-recovery profile

| Item | SHA-256 |
| --- | --- |
| request | `2af5cb807d992e98fcfa4afc4a41525d0d94ae6cd9e118c5b874b2b58599ca16` |
| provenance | `fc01948c43be39b37e7f5bfadc3bdbb383c5fd47d3a9948783b1c293a9b8b0b5` |
| build receipt | `02b96c3f42bc279bbca47f101a4751456dcf65fdf635467b137381df85de31f7` |
| bootfs | `0a603de53f8707f2b585f36c57b1744d2dcbf6ddb71e08f34521e3e5189fef1b` |
| RRC-A manifest | `02d43db2a305b77a0d1408725f6eba8222c7f5b2a76b739ed50ea887c60397bd` |
| ESP | `4ae5c7b7ab23120ccaaab989ae2c380940416df18edcaabe20bcace4cd7d3193` |
| Deepwyrm kernel and symbols | `a2970bf8a7085b4cdabf9c5b0ee2a07fd743bc0bd58219f1025317396bf8920d` |
| `/system/init` | `12302df1f75ee564c74d65d536621171aac384e9997ed494bbc52b45ec5d8324` |
| selected failing registry stub | `ae00f05ce0c46d5be62ed05a13312aaf160b3d6b067d9ec45cf885e2e58ae39c` |

The degraded bootfs is 166,848 bytes and fits the same 41-page ceiling.

## Build and host gates

- Both profiles passed request, provenance, build-receipt, source-clean,
  bootfs, RRC-A, ESP, native-ELF inspection, and prepared-run validation.
- Wyrmroot focused validation passed: 15 selector-aware supervisor/runtime
  tests, 14 restart-model tests, 14 default library tests, the bootstrap-stub
  test, and focused Clippy with warnings denied.
- Deepwyrm replay passed 643 kernel library tests, 23 x86_64 entry-contract
  tests, and 43 x86_64 syscall-contract tests.
- The root VM runner and evidence verifier passed all 92 tests.
- No Deepwyrm ABI change was required for WYR1-A.

## Live boot matrix

| Scenario | Planned profile | Result | Structured evidence |
| --- | --- | --- | --- |
| normal | default, 1 vCPU / 1024 MiB | PASS, detail `0`, terminal `NORMAL` | 5 records; SHA-256 `2685586fc83baa4bd747d53c0f0c5ca270205a5d4f72723d9e13752349549a3f` |
| normal | SMP, 4 vCPU / 2048 MiB | PASS, detail `0`, terminal `NORMAL` | same 5 records and identity |
| degraded recovery | default, 1 vCPU / 1024 MiB | PASS, detail `0`, terminal `DEGRADED` | 9 records; SHA-256 `be559d6f15c1345e829b4be4ddbd6dc01ed51175e454686158fdba8811e92393` |
| degraded recovery | SMP, 4 vCPU / 2048 MiB | PASS, detail `0`, terminal `DEGRADED` | same 9 records and identity |

Both normal runs record exact READY and REAP outcomes for registryd generation
1 / transaction 4097 and devmgr generation 1 / transaction 4098. Both degraded
runs record REAP plus RESTART for registryd generations 1 through 3, REAP plus
PermanentFailure for generation 4, no fifth spawn, and one terminal DEGRADED
record. Every run ended through the expected QEMU guest-shutdown lifecycle and
left the designated VM shut off.

The default and SMP normal serial logs are byte-identical at
`5e94cff36c279e0e3634f96a0dd932492c2489ba8fde938478cba933d2f49650`.
The default and SMP degraded serial logs are byte-identical at
`559174c8f231b6979dc0b2b45b2c9cfc82be07c5fdbcf8b9ee17434762dafc2e`.

## Remediation during validation

Validation exposed and fixed three acceptance-path defects:

1. Successful WYR1 bootstrap stubs were mapped to the wrong terminal outcome;
   their deterministic completion is now a clean exit.
2. If Process `EXITED` won the initial READY/exit wait, a terminal-bearing
   observation was incorrectly passed to the nonterminal retry path. Initial
   READY/exit races now use the same terminal transition as later observations,
   with regression coverage for READY and pre-READY nonzero exits.
3. The runner treated QEMU debug-exit guest shutdown as a crash and then
   expected only restart dispositions, omitting required per-attempt REAP
   records. It now verifies the exact shutdown lifecycle and the complete
   generation/transaction evidence sequence.

Rejected runner attempts are retained under the evidence roots rather than
being represented as product failures.

## Required-source and prior-art disposition

The active WYR1-A plan, `WYR1_BOOTSTRAP_SUPERVISOR_CONTRACT.md`,
`WYR0_I_NATIVE_CAPABILITY_CONTRACT.md`, and root
`BOOTSTRAP_AND_RECOVERY_ARCHITECTURE.md` were used as the authoritative local
contracts. Pinned s6 revision
`4ea3aea9f7c7096e20b774cebbdf7d16f122e464` was reread for conceptual
supervision/permanent-failure comparison. No s6 code was copied or adapted.

## Acceptance boundary and nonclaims

The designated VM was used only to execute the claim-bearing boot path: q35
with OVMF, the planned vCPU/RAM profiles, the exact ESP, the selected guest
gate, serial evidence, and debug-exit lifecycle. Incidental virtual devices and
libvirt defaults were not audited, modified for acceptance, or certified. This
gate proves that the exact Wyrmroot/Deepwyrm pair boots and exhibits the required
supervision behavior; it is not a general VM hardware certification.

WYR1-A does not certify real registry publication/lookup, real device
coordination or hardware ownership, UART/console streams, shell launch or
interaction, VFS/persistent root, authentication, or physical hardware. Those
remain assigned to WYR1-B and later phases.

## Disposition

WYR1-A is accepted at the exact product tuple and artifact identities above.
The permanent `/system/init` path, immutable RRC-A manifest, exact EARLY-role
READY/reap sequence, finite restart policy, PermanentFailure, and structured
degraded recovery satisfy the Phase A gate. WYR1-B remains open.
