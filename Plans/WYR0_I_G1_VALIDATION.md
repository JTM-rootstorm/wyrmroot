# WYR0-I I-G1 / Wave 4 Ordinary-Matrix Validation

**Status:** I-G1 ordinary matrix accepted; exact candidate frozen for Wave 5  
**Date:** 2026-08-25  
**Scope:** WYR0-I Wave 4 only; Wave 5 Daybreak and Wave 6 completion records remain open

## Frozen tuple and evidence root

- Deepwyrm: `117a8b590c427f988a02b26514f5adf897165de7`
- Wyrmroot product: `b753a3b24461209b89e7b394844889c74fd7a14b`
- Rust: `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`
- accepted toolchain: `RUST-WYR0-I-B-SYSROOTS-007`, `wyrmroot-1.97.1-a92dc7f7`
- generated Deepwyrm ABI revision: `cfc69bd8a49819ce1cda1a132cf56e55c93f92e4`
- evidence root: `../artifacts/wyr0-i/wave4/candidate-r37-i2-deadline-dw-117a8b59__wyr-b753a3b2__rust-a92dc7f7`

This is the candidate frozen for the separate Wave 5 exact-revision security
review. It is not a final WYR0-I completion or security disposition.

## Contract-drift remediation

The first Wave 4 media reused a Cargo output from the capability-feature init0
build in the ordinary selector-18 image. That binary sent the 64-byte,
three-handle capability INIT envelope while ordinary hello correctly expected
the 40-byte, zero-handle envelope; Deepwyrm therefore returned
`BUFFER_TOO_SMALL`.

Wyrmroot now embeds one selector-profile marker in every init0 artifact and
`xtask` rejects a missing, competing, or selector-incompatible marker before
building or running media. Deepwyrm's ordinary selector-18 bootfs mapping bound
was returned from the contaminated 18-page measurement to the isolated 17-page
measurement. Its regression sends and receives the exact ordinary 40-byte,
zero-handle datagram across the moved child bootstrap Channel.

The first repeated I2 attempt also exposed a pre-existing five-millisecond
lifecycle oracle: an exception child could lose the race between vCPU dispatch,
terminal publication, and the parent's finite `EXITED` wait under concurrent
host load (`0x2206002A`, lifecycle operation 42). No deterministic Deepwyrm or
profile drift was found. Wyrmroot commit `b753a3b24461209b89e7b394844889c74fd7a14b`
uses a named one-second active-monotonic bound only for the four lifecycle waits
that require another vCPU to run. The intentional nanosecond/millisecond timeout
probes are unchanged.

## Build and host gates

- Complete locked Deepwyrm workspace/all-target tests passed, including 624
  kernel unit tests and all integration/source-contract targets.
- Deepwyrm Clippy and rustdoc passed with warnings denied; formatting and ABI
  regeneration/drift checks passed.
- The ignored accepted-toolchain Deepwyrm production/six-memory-selector
  artifact gate passed with the exact manifest-selected Rust 007 and LLVM 22
  binaries.
- Complete locked Wyrmroot workspace/all-target tests passed; `xtask` reported
  107 passed and one accepted environment-gated test ignored.
- Wyrmroot workspace Clippy and rustdoc passed with warnings denied; formatting
  and diff checks passed.
- The accepted-toolchain positive identity gate passed, and the canonical
  native inspector accepted ordinary, I2, and capability payloads.
- The unchanged ordinary production inputs retained the preceding two-clean-lane
  byte identities. The affected I2 payload was rebuilt in both clean detached
  Wyrmroot lanes at the exact product revision; both outputs and the consumed
  payload are byte-identical at
  `ea013cf08c9f5618857fb3625f176dfd60ee8e5fe2903774bab425c6515353e0`.
- The r37 closure-A/closure-B audit returned `ARTIFACT_AUDIT_PASS`; ordinary
  bootfs and ESP bytes are identical across both roots.
- Host GDB connected to `127.0.0.1:1234` using exact kernel symbols SHA-256
  `f49f79e841ad71d12e07d0352fec5b553b22fff24df12d5cc0564d229cdeaa80`.
- Independent request-bound inspection passed for all ten final media variants.

## Live matrix

| Gate | Profile | Result | Frozen candidate SHA-256 |
| --- | --- | --- | --- |
| ordinary I0 selector 18 | default, 1 vCPU / 1024 MiB | PASS, detail 0, QEMU 33 | `dc8bff8f6c4d95b295de0cac58099f8f90ce52b6e88b762dace3002ba132ebbc` |
| malformed ELF/startup and capability count/type/rights | default | all five exact expected failures PASS, details `0xB0000001`..`0xB0000005`, QEMU 35 | request-bound per-case identities under the evidence root |
| I1 selector 23 | SMP, 4 vCPU / 2048 MiB | PASS, 17 ordered events, mask `0x000000ff`, QEMU 33 | `e0243b2f432368431bed4e03139d74bf7b3ff0cde8a968a283682a0327e2aa79` |
| I2 selector 22 | SMP, 4 vCPU / 2048 MiB | five consecutive PASS results, detail 0, QEMU 33 | `beac0e6628132f95354d16b768e41d7ccf351589d7dc5bcb2f7f1ca8832315bb` |
| native-userspace-capability selector 24 | paired default and SMP on the same media | both PASS, 15 ordered records each, mask `0x000003ff`, QEMU 33 | `cc7391c7b5b10a5f65da206a7fbecdfff9fbe5018c5f58c42ef82cbaaf1476af` |

The five I2 results are preserved as `i2/repeats/pass-1` through `pass-5`.
The capability certificate is `i-capability/certificate/certificate.json`,
SHA-256 `ed10031f614f4fefa53c6b93c0517b17a2ddbd0392fb8d9944947358e82728ef`.
Every accepted run records no host share and the exact tuple above.

## Disposition

Wave 4 / I-G1 is accepted and its hashes are frozen. Wave 5 must use the
workspace-mandated exact Daybreak model against this candidate; that review was
not run or claimed here. Wave 6 validation/security/completion records, root
capability certificate, integration, and final lane cleanup remain open.
