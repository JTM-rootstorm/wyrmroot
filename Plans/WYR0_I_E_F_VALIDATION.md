# WYR0-I I-E / I-F and Wave 3 Validation

**Status:** I-E payload, I-F certificate, and Wave 3 default/SMP live gate accepted  
**Date:** 2026-08-25  
**Scope:** `native-userspace-capability`, test ID 24, schema 4, `WRCAP1` version 1

## Accepted tuple and evidence

- Deepwyrm: `1b976f3799a42a28b033ad5fa82ca80d9acd24ea`
- Wyrmroot: `c90de86e0707229facdf418b4b42506543f4611c`
- Rust: `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`
- accepted toolchain: `RUST-WYR0-I-B-SYSROOTS-007`, `wyrmroot-1.97.1-a92dc7f7`
- generated Deepwyrm ABI tree: `1c6a74f130e386eee95b3780c75950beefd0037d`
- paired evidence envelope: `../artifacts/wyr0-i/wave3/candidate-r33-remediated-dw-1b976f37__wyr-c90de86e__rust-a92dc7f7`
- candidate SHA-256: `5d13880f2910cb409ff36a346eb5197d07b391f6254b02a79117a2781b512336`
- request SHA-256: `15c872098b19f2f3685ab47604ffa4ee912d7081b2f1e03a7da01f83588af511`
- provenance SHA-256: `c56a46a3c2beea1d6463f471fb5c051bb7f23eeb89f9b4aef5ae2333090e965a`
- certificate SHA-256: `5b7f3532363b47904fef93c85b272657e11c78f67b3d84061d8d644e9c15ee3c`

The host-generated certificate is
`certificate/certificate.json` inside that envelope. Its human summary is
`certificate/capability.md`. The summary was created before the certificate;
the certificate was the final create-new authority marker.

## Artifact identity

| Artifact | SHA-256 |
| --- | --- |
| loader | `8d5bc33b3a45e2e6345a6c373678020c0c489c19991137c88b35d658e236216d` |
| kernel and symbols | `fe50c65e51deb92fdf54ba02ab80054916af071af1eb9b17003a6e156734a148` |
| bootstrap | `b7c362a2941cbea02b7a4c0a0a5c1cd4c473ef491d978a33c1afea70a9bf1820` |
| init0 | `588143338cbcf5a761d4ca9832bf2e8008658114b5a9729fd00344a4e5a31337` |
| capability payload | `5e51bcdce110ae37cd70232444a43935996c1a4b333db6ae8bbeb0cc32419b79` |
| selector config | `317ec71fb1628cab39d0085ce4000d996e4f2f6c60e0551af8fe7f61af34c051` |
| selector asset | `c0e83e5c67518828bc70fca24179f814687f0857dd9832fc61d159dd335282fa` |
| bootfs | `dcd158c22ac2a982eaef19ad7db52a1ffda175f2be6db0ae359e9cca80f2cf54` |
| ESP | `4fc748206da647ca986ee157ff843dc6da5e1179f67887cc048a8d99d5647351` |

The inspected profile is q35/OVMF with no host share and no network. The
bootfs carries the capability executable plus deterministic
`test/wyr0-i/config.toml` and `test/wyr0-i/asset.bin` content through the
ordinary boot/system-image path.

## Live results

The canonical paired command was:

```text
cargo xtask test integration wyr0 --request ../artifacts/wyr0-i/wave3/candidate-r33-remediated-dw-1b976f37__wyr-c90de86e__rust-a92dc7f7/request.toml
```

It revalidated the immutable media and ran both profiles:

| Profile | Geometry | Result | Evidence |
| --- | --- | --- | --- |
| default | 1 vCPU, 1024 MiB | PASS, detail 0, QEMU exit 33 | 15 ordered records, sequence 0..14, mask `0x000003ff` |
| SMP | 4 vCPU, 2048 MiB | PASS, detail 0, QEMU exit 33 | 15 ordered records, sequence 0..14, mask `0x000003ff` |

Both results bind the same candidate, request, provenance, bootfs, ESP, kernel,
and payload hashes. The validated records cover content delivery, lifecycle,
shared memory, Channel lifecycle/backpressure, waits/Event/Timer, cancellation,
restart replacement, restart exhaustion, overload/replay rejection, and final
cleanup/accounting baseline.

The certificate classifies controller-owned admission, reservation, replay,
and cleanup as Wyrmroot-enforced. It does not claim generic hostile-peer
TaskGroup quota containment, WYR0-GW, graphics, or Prismdrake readiness.

## First-live-candidate blocker record

Wave 3 preserved each immutable failed candidate and fixed only measured
blockers:

1. selector runtime capacities were raised only for observed object, handle,
   wait, and mapping peaks;
2. live cancellation exposed a Deepwyrm termination deadlock in which a
   blocked `WAIT_ANY` retained a process-operation lease after the operation
   gate entered quiescing; Deepwyrm now terminally drains that wait and retries
   the already-selected termination, with a real suspended-wait regression;
3. the controller passed logical peer identity 4 to a zero-based four-slot
   readiness ledger; the Wyrmroot mapping now proves identities 1..4 map to
   slots 0..3;
4. bootstrap/init0 supervision diagnostics were refined so a descendant exit
   racing cleanup remains observable without replacing the primary failure;
5. GDB on the exact r29 bootstrap proved `BootstrapError::Native(NO_RESOURCES)`
   and failed operation 4 (`map_bootfs_read_only`). The accounting fix had
   grown the controller ELF, moving the selector bootfs from 36 to 38 pages.
   Deepwyrm commit `b50846c914e6f71f379454e71c5c8e3d4fab9a12`
   raises only the selector-24 mapping bound to the measured 38 pages and locks
   that value in both x86_64 source-contract suites.
6. post-acceptance dirty-tree review found that terminal cleanup could retain
   more than one generic or atomic wait resource even though the live adapter
   held only one of each, and that process exit, fatal exception, final-thread,
   and TaskGroup paths did not all consume blocked waits before teardown;
   Deepwyrm commits `62e116feee682f5e7cc3167e537d9df446a8bfc2`
   and `8186944a0e9bb4bbf81860314a9058d29c375aa0` batch all resources and split
   logical terminal cleanup from physical reclamation;
7. exact CPU1 regressions now hold a foreign continuation suspended before
   `complete_switch_on`, require its generation-bound stop acknowledgement,
   and cover ProcessTerminate, ProcessExit, fatal exception, ThreadTerminate,
   and TaskGroupTerminate. Suspended physical ownership wins over a logical
   replacement until handoff completion;
8. Wyrmroot commit `df5d6568d86900e7fc598a8331120d5a698bcc5c`
   re-queries terminal state after a racing failed termination so cleanup no
   longer masks controller exit detail or the primary supervision failure;
9. Wyrmroot commit `c90de86e0707229facdf418b4b42506543f4611c`
   measures exact revisions and tracked/untracked cleanliness before emitting
   certificate claims, reserves the implicit `.staged` certificate path, and
   rejects all equal or ancestor/descendant output overlaps; and
10. immutable remediation candidate r32 reproduced `0xB041000D` on both
    profiles because the init0 fix moved bootfs from 153,436 bytes (38 pages)
    to 155,764 bytes (39 pages). Deepwyrm commit
    `1b976f3799a42a28b033ad5fa82ca80d9acd24ea` raises only selector 24's
    measured mapping window to 39 pages; r33 then passed both profiles.

No new syscall, object type, right, scheduler policy, evidence protocol, or
kernel personality branch was introduced.

## Focused validation

- Deepwyrm `x86_64_entry_contract`: 19 passed.
- Deepwyrm `x86_64_syscall_contract`: 40 passed.
- Deepwyrm kernel package: 624 unit tests plus all integration/contract targets
  passed; 3 target-artifact tests remained explicitly ignored as designed.
- Wyrmroot locked workspace check, full host suite, and capability-feature
  init0 tests: PASS; xtask reported 105 passed and 1 accepted ignored gate.
- accepted-toolchain selector-24 `x86_64-unknown-none` release build: PASS.
- canonical image construction and independent ESP inspection: PASS.
- standalone default and SMP runs: PASS before paired closure.
- paired same-media default/SMP closure and certificate publication: PASS.

The repository-wide formatting check reports pre-existing rustfmt differences
in untouched assertions in `x86_64_syscall_contract.rs`; the Wave 3 diff itself
passes whitespace checks and does not include those unrelated rewrites.

## Disposition

I-E, I-F, and Wave 3 are accepted on the tuple above. This is not WYR0-I final
milestone closure. Wave 4 ordinary validation, Wave 5 exact-candidate Daybreak,
and Wave 6 security/completion/root certificate records remain open.
