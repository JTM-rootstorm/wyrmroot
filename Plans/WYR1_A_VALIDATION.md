# Wyrmroot WYR1-A Validation

**Status:** WYR1-A accepted after adversarial remediation
**Date:** 2026-08-26
**Scope:** Permanent `/system/init`, immutable RRC-A manifest, EARLY-role
supervision, finite restart, and degraded recovery only

## Accepted product tuple

- Deepwyrm: `96155793c1c8d06dea0139832bd96d9572d40cd6`
- Wyrmroot product: `8f7d392f9d1e9bdba524565c0200ab267f487ce2`
- Rust: `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`
- selector: `permanent-supervisor-rrc` (test ID `25`)
- normal evidence root:
  `../../artifacts/wyr1-a/phase-a-remediation-release-9615579-8f7d392/normal`
- degraded evidence root:
  `../../artifacts/wyr1-a/phase-a-remediation-degraded-final-9615579-8f7d392/degraded_recovery`

The Wyrmroot revision above is the accepted product revision. This validation
record and later documentation-only commits are not a replacement product
identity.

This tuple supersedes the original 2026-08-26 Phase-A acceptance at Deepwyrm
`44e60031d0b080459c8cd412a2f66a894896493d` / Wyrmroot
`35b11eefe8707a1a1e8da15477da1e4552346c62`. Its frozen normal and degraded
evidence remains retained under
`phase-a-normal-closure-44e6003-35b11ee` and
`phase-a-degraded-closure-44e6003-35b11ee`; it is historical, not evidence for
the remediated product.

## Frozen artifact identities

### Normal profile

| Item | SHA-256 |
| --- | --- |
| request | `9887c6254b1723bf1803d0fc45b28c34106982d75cebad013a30a76d69e9d872` |
| provenance | `d26d7edde82515f0155a546cd7de963c11c81d58d15f252bd71ccd966c48a0cc` |
| build receipt | `4363861fe3eedda6489413f66d9f8335e161df310e86102b5c9b7666d68392c7` |
| bootfs | `6bacf3e187711262859975b0a9de82f17620f42697c7c492bd737d75a6b2bea6` |
| RRC-A manifest | `a4cbac05384f975e6672aee6fd0df069bd9a48dfa845fa2ef7704775a94d41d9` |
| ESP | `6c1a018f49b70855756055940c33fa6834b924e4dce0d667f0c876f02f385d39` |
| Deepwyrm kernel and symbols | `0d4ec1a98fc93bcce45c68a85679bff1af7dac65e0e23e3a3a53b42942690c30` |
| EFI loader | `8d5bc33b3a45e2e6345a6c373678020c0c489c19991137c88b35d658e236216d` |
| `/system/init` | `94cfb0eb36dc186e95c371b3a4da2c31c6dcaca7bf2cc920d938a564882c8e30` |
| paired result | `002e95e9567903568ba195a7c2546f5d5ec4c065b24f9c9404b74f232c4d7c18` |

The normal bootfs is 170,496 bytes and fits the selector-local 42-page ceiling
(172,032 bytes).

### Degraded-recovery profile

| Item | SHA-256 |
| --- | --- |
| request | `72ee0f17dd8d1c4f7f97feeacf5d8095b11742a916fc2aba0a5562b1e700069e` |
| provenance | `1a8c3689f5e8de1c316e376f60096160ecada58fd3323d88d5d8e96dd0dded52` |
| build receipt | `8722d251156fa5814fe524f8e0fb1be66251fa6331c4e761807bc819241d3ee5` |
| bootfs | `ea6c569248b831573f80f65dd2e5b08adc0bacc4ceaf17031a3c3b80221fcf42` |
| RRC-A manifest | `28102dc5d5835670d1281a76b12a613bd5e76bfb7024cbe64506c4d37a7779f8` |
| ESP | `97e3cdff4ec3ed8a6e7edf98e482bc508057b6a5c2abfef12120730d210c9a14` |
| Deepwyrm kernel and symbols | `e91bfb737ebfe1dd84f8e0c36df317e4ceb179945b4a01fd38fc0a6c30357136` |
| `/system/init` | `94cfb0eb36dc186e95c371b3a4da2c31c6dcaca7bf2cc920d938a564882c8e30` |
| selected failing registry stub | `ae00f05ce0c46d5be62ed05a13312aaf160b3d6b067d9ec45cf885e2e58ae39c` |
| paired result | `dad5a3934a11d7719da8643d1cd6f163d20a97d64eadadd46077b6dc6f146b14` |

The degraded bootfs is 169,896 bytes and fits the same 42-page ceiling.

## Build and host gates

- Both profiles passed request, provenance, build-receipt, source-clean,
  bootfs, RRC-A, ESP, native-ELF inspection, and prepared-run validation.
- Wyrmroot remediation validation passed 15 supervisor/runtime library tests,
  14 restart-model tests, all 122 xtask tests (with the existing accepted-
  toolchain test ignored), both focused Clippy lanes with warnings denied,
  formatting, and diff checks.
- Deepwyrm passed its locked workspace/all-targets suite, focused selector-25
  source-contract coverage, formatting, diff checks, and accepted-toolchain
  release builds for both request-bound scenario/nonce combinations.
- The canonical root runner and Wyrmroot evidence verifier accepted all four
  fresh default/SMP boots and both paired transcript joins.
- No Deepwyrm ABI change was required for WYR1-A.

## Live boot matrix

| Scenario | Planned profile | Result | Structured evidence |
| --- | --- | --- | --- |
| normal | default, 1 vCPU / 1024 MiB | PASS, detail `0`, terminal `NORMAL` | 5 records; SHA-256 `6e8e962324d8daa493b3a096316f9bff866c8af6296c14b132094def4b94dde0` |
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
`187c00bd9d8d5ac7916c50fab60914cfa777dbf4b38b10a6844e8ff0082697f6`.
The default and SMP degraded serial logs are byte-identical at
`559174c8f231b6979dc0b2b45b2c9cfc82be07c5fdbcf8b9ee17434762dafc2e`.

## Post-acceptance adversarial remediation

The independent adversarial review findings F1, F4, and F6 were confirmed and
remediated at Wyrmroot `8f7d392f9d1e9bdba524565c0200ab267f487ce2`:

1. **F1 - permanent-supervisor ownership.** Registryd READY now starts devmgr
   immediately; registryd clean exit is no longer a dependent-activation gate.
   `/system/init` retains and concurrently supervises both roles after READY,
   uses a zero-time signal preprobe plus a positive bounded terminal drain, and
   finalizes evidence only after all active Phase-A generations retire.
2. **F4 - independent identity joins.** Expected manifest, bootfs, and retained
   material identities now come from deterministic construction/verified
   receipts, while observed identities come from reread files and independently
   parsed archive material. Regressions reach receipt, archive, and observed-
   material mismatch paths.
3. **F6 - truthful guest closure claims.** Guest validation retains role-
   executable identity checks and `/system/init` presence/nonempty/executable
   checks, but removes self-derived hash comparisons for init and non-role edge
   targets where no independent guest comparator exists.

The larger resident init required 42 bootfs pages. Deepwyrm
`96155793c1c8d06dea0139832bd96d9572d40cd6` raises only selector 25's measured
ceiling from 41 to 42 pages; ordinary, I2, WRCAP, ABI, and production bounds are
unchanged. A `gpt-daybreak-blue-latest` medium-effort review on 2026-08-26 found
no F4/F6 identity-integrity issue and no correctness/soundness issue in the
selector-local capacity change. Fresh live default/SMP evidence, rather than
the review alone, establishes the acceptance result above.

Two rejected construction attempts remain preserved and are not product
evidence: `phase-a-remediation-9615579-8f7d392` used dev-profile kernels and
double-faulted on the oversized early stack frame; the degraded profile under
`phase-a-remediation-release-9615579-8f7d392` used the normal nonce and was
rejected as malformed evidence (`0x2510E006`). The accepted artifacts use
release kernels and each request's exact compiled scenario and nonce.

## Initial validation remediation

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
