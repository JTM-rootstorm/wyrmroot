# WYR0-I I-E / I-F and Wave 3 Validation

**Status:** I-E payload, I-F certificate, and Wave 3 default/SMP live gate accepted  
**Date:** 2026-08-25  
**Scope:** `native-userspace-capability`, test ID 24, schema 4, `WRCAP1` version 1

## Accepted tuple and evidence

- Deepwyrm: `b50846c914e6f71f379454e71c5c8e3d4fab9a12`
- Wyrmroot: `a5d8bdd3f0d83625f77e72bacefdb05637f9d7db`
- Rust: `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`
- accepted toolchain: `RUST-WYR0-I-B-SYSROOTS-007`, `wyrmroot-1.97.1-a92dc7f7`
- generated Deepwyrm ABI tree: `1c6a74f130e386eee95b3780c75950beefd0037d`
- paired evidence envelope: `../artifacts/wyr0-i/wave3/candidate-r30-paired-dw-b50846c9__wyr-a5d8bdd3__rust-a92dc7f7`
- candidate SHA-256: `2584d601fa1130d2b477f88a3cbed8af50c3ad768b7174a8520fccb4f863a760`
- request SHA-256: `c26d5ff6b66ec3448bd98873fc1f441cd64cd287a9a64cc155a82f69bd897a51`
- provenance SHA-256: `478600c402e6f7b262a553d4d0bed77ff48d9c56bb503c886d5fe4777264481b`
- certificate SHA-256: `7edbf42f043e69d448c183433615db00a9f03454e3a808e0fcff0bf0ae90d92f`

The host-generated certificate is
`certificate/certificate.json` inside that envelope. Its human summary is
`certificate/capability.md`. The summary was created before the certificate;
the certificate was the final create-new authority marker.

## Artifact identity

| Artifact | SHA-256 |
| --- | --- |
| loader | `8d5bc33b3a45e2e6345a6c373678020c0c489c19991137c88b35d658e236216d` |
| kernel and symbols | `f8ef9953cb8b2397ca23c0321feb1dc9e9e591fc7c297d7f9f63ad4bf5741e59` |
| bootstrap | `b7c362a2941cbea02b7a4c0a0a5c1cd4c473ef491d978a33c1afea70a9bf1820` |
| init0 | `8815c0a44a8806f294a2ec015422ad4334f51b5b7e0c34305d279a4899706cac` |
| capability payload | `5e51bcdce110ae37cd70232444a43935996c1a4b333db6ae8bbeb0cc32419b79` |
| selector config | `317ec71fb1628cab39d0085ce4000d996e4f2f6c60e0551af8fe7f61af34c051` |
| selector asset | `c0e83e5c67518828bc70fca24179f814687f0857dd9832fc61d159dd335282fa` |
| bootfs | `e817559172e11cff5797444ef575ad2c3e7bf340d0d3738960ff11e40baa3687` |
| ESP | `36079e35b55830da3dbf24f1933e2ad5536b12d9a22dd48ff95bb18008426c6f` |

The inspected profile is q35/OVMF with no host share and no network. The
bootfs carries the capability executable plus deterministic
`test/wyr0-i/config.toml` and `test/wyr0-i/asset.bin` content through the
ordinary boot/system-image path.

## Live results

The canonical paired command was:

```text
cargo xtask test integration wyr0 --request ../artifacts/wyr0-i/wave3/candidate-r30-paired-dw-b50846c9__wyr-a5d8bdd3__rust-a92dc7f7/request.toml
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

No new syscall, object type, right, scheduler policy, evidence protocol, or
kernel personality branch was introduced.

## Focused validation

- Deepwyrm `x86_64_entry_contract`: 19 passed.
- Deepwyrm `x86_64_syscall_contract`: 40 passed.
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
