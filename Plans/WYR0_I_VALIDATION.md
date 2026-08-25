# WYR0-I Final Validation and Milestone Closure

**Status:** Final — PASS  
**Date:** 2026-08-25  
**Scope:** WYR0-I phases I-A through I-H and Wave 6 records closure

## Accepted product tuple

- Deepwyrm product: `5a8bb0a75979bb3ecde9bd7209619e924ec5e36d`
  - tree: `1cf3e99af8675c5ebdb6cd190463dbb25bbb48df`
- Wyrmroot product: `ec84cc6441db15de83d55329ac442a01988c52e9`
  - tree: `c72de62540fbaa38d567079795952a39327fe592`
- Rust: `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`
  - tree: `aa3d5f9d1311772c99e385067d07641c01b8d203`
- generated Deepwyrm ABI pin: `cfc69bd8a49819ce1cda1a132cf56e55c93f92e4`
  - generated ABI identity: `1c6a74f130e386eee95b3780c75950beefd0037d`
  - `crates/deepwyrm-abi`: `3c4b82b4253d7d21d0f578d8d5b966304472cd8f`
  - `crates/deepwyrm-syscall`: `a64290953ccc0548e908be88586969ac0b70b589`

All product checkouts were clean before and after the final build and validation.
Wyrmroot `ae9a1d58789f0e36e4b2f5891e6d196e7a244640` is the pre-Wave-6
documentation descendant that adds the final security record; it is not the
tested Wyrmroot product revision. This record and later closure-only descendants
do not change the product tuple above.

## Authoritative evidence

The final post-remediation evidence root is:

`artifacts/wyr0-i/wave5/candidate-r38-daybreak-dw-5a8bb0a7__wyr-ec84cc64__rust-a92dc7f7`

Paths in this document are relative to the OS-Project coordination root unless
otherwise stated. Historical `Plans/WYR0_H_VALIDATION.md` and
`Plans/WYR0_I2_STRESS_PAYLOAD.md` remain reached-contract and inherited-baseline
records. They do not replace the fresh Wave 5 ordinary, I1, I2, capability, and
negative results used for final acceptance.

The host-generated capability certificate is
`artifacts/wyr0-i/wave5/candidate-r38-daybreak-dw-5a8bb0a7__wyr-ec84cc64__rust-a92dc7f7/i-capability/certificate/certificate.json`:

- schema: `2`;
- SHA-256: `dd4c4af0bd3149823131ac2f68645f0307ea6d794f3cb656e77de7d912b2e760`;
- status/acceptance: `PASS` / `true`;
- selector/test: `native-userspace-capability` / `24`;
- protocol/version: `WRCAP1` / `1`;
- required and observed masks: `0x000003ff`;
- evidence events: `15` per profile; and
- `wyr0_gw_claimed`: `false`.

## Toolchain and build identity

- accepted request: `RUST-WYR0-I-B-SYSROOTS-007`;
- target/toolchain: `x86_64-unknown-wyrmroot` / `wyrmroot-1.97.1-a92dc7f7`;
- request SHA-256: `4c404f6f47197fff4cc8d7486ea784a02a0701206ee3d5ee39e5f47ef7efa3ee`;
- manifest SHA-256: `cc78368219552cce8fdaad38ab419040cab945fe175aa774d6dca51eece84fd2`;
- toolchain-tree SHA-256: `dce57d31def1f509ce537f96ae6b6dd320da11c9f321382cb93d142f558a32ca`;
- rustc SHA-256: `65bd51e9ecb8e1185524471a8cbc4af1e6ac4e37e7d446c7a127bda0fa431c70`;
- Cargo SHA-256: `a73b2c25573d251489101c0d8f19ad3702eb9761166de5ed8437b472b6c038ce`;
- rust-lld SHA-256: `38a9f28404309892f9c9afe02fa4979a0d9e8bc866979cde09f5bb7ec17e5721`;
- LLVM identity: `22.1.6`, SHA-256
  `ed4f320c4e1ed6de7d2db6fd89faccf764d63186c2f877057ddf31065b1fac09`.

The accepted Rust toolchain supplies the product compiler and rust-lld. The
final Deepwyrm artifact oracle additionally attested direct regular LLVM 22.1.8
host tools. A Wave 6 read-only recheck of those exact paths produced:

| Host tool | SHA-256 |
| --- | --- |
| `/usr/lib/llvm/22/bin/clang-22` | `02ee323c47e4647fec0ecafe250d96597d41826a56507fb2d6fcc553393d5d7c` |
| `/usr/lib/llvm/22/bin/llvm-nm` | `a800ac982555ad87c0e00e1e403c3d12c1bfc173d1be96be0aeace54d97f0aab` |
| `/usr/lib/llvm/22/bin/llvm-objdump` | `62b4f73958bc93a1f9618d4c35b4459d8563a60f11d22af313f7bb639e440f0b` |
| `/usr/lib/llvm/22/bin/llvm-readobj` | `8074c683dc2c5bfebd5e68245b9d435a3a44ff7e232f20b6a1d01a22f5d7caf8` |
| `/usr/lib/llvm/22/bin/ld.lld` | `fe90dca7f3c3703b8313e74d4c97602250a43effbcb1a52d75a35c71eb88048a` |

The host-tool hashes are closure-time verification of the retained direct paths;
the Rust 007 manifest hashes above and the oracle's retained build-input manifest
and normalized-environment hashes are the candidate-bound identities.

Two isolated clean source lanes rebuilt the production loader and every native
ordinary, I1, I2, capability, and negative input. The corresponding artifacts,
four selector kernels/symbol files, ordinary bootfs, and ordinary ESP were
byte-identical. The request-bound audit returned `ARTIFACT_AUDIT_PASS`:

- ordinary candidate: `9c5b71df681fc0b9722fc7c6d596d52761440f3b91440a02210ad2eb5fb6d3d5`;
- ordinary bootfs: `22dc889e487cb1e70a72ad61a205870c2acca1cec1233907e08d07d4fa3619ed`;
- ordinary ESP: `6eeb2b5751e3907e2c84e298d0a7d740a3d2d908775af28b6f3721a81628c73e`;
- loader: `8d5bc33b3a45e2e6345a6c373678020c0c489c19991137c88b35d658e236216d`.

The exact capability candidate identities are:

| Member | SHA-256 |
| --- | --- |
| candidate | `6786037dd11ff8ff5c0a28e54f67128c50540fc7b93ce879caf3334ebf63adf8` |
| request | `a78e550711ff3504ae83eed144f87810aea03544b4d76a66d8215c0a9e50be18` |
| build receipt | `cbb38e7def3e08219ea0015069a389f3910860f8de1d021a5ffcd7770eb4cfdc` |
| provenance | `ec2a32908371b61f5291b6ffde9c1aca75b9b96ddab5cba91281e9acf40caa77` |
| kernel/symbols | `14b5c4dc8c59fcc8a5fc00863b890e230d8e672b8e7164b77d3074d872ce6a0a` |
| bootstrap | `b7c362a2941cbea02b7a4c0a0a5c1cd4c473ef491d978a33c1afea70a9bf1820` |
| init0 | `67dc6ee42b9bccdbc4985c2640b34d3133fee384fccc4ba671ea43cbb4e225d0` |
| capability payload | `de3b5f63e64a3312d6cbc1b3d721c8a7e08eaf162fe12363e50b118e2b033724` |
| selector config | `317ec71fb1628cab39d0085ce4000d996e4f2f6c60e0551af8fe7f61af34c051` |
| selector asset | `c0e83e5c67518828bc70fca24179f814687f0857dd9832fc61d159dd335282fa` |
| bootfs | `a3bc058ad6b5865573d9c2669f730a6938bcbc16eeafdb1b628707ac4492b9c6` |
| ESP | `1e75731b30572205ded50ee2ea55664708233ab8c3fa3b53a15dcc9898bc46bb` |
| OVMF code | `f3ff7e73448ed2845ee15356f394882f5618eb5dab92c9a30ec6ee0e1468553a` |
| OVMF vars template | `6ed987af3a3c155be71665f510eae3e007eda9b8b94afd59d45e91c4a11565cc` |

## Commands and validation results

The final source gates used these exact repository-local commands:

```sh
# deepwyrm/
cargo fmt --all -- --check
cargo xtask abi check
git diff --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked

# wyrmroot/
cargo fmt --all -- --check
git diff --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked
```

Deepwyrm passed 625 kernel unit tests plus all integration/source-contract
targets. Wyrmroot `xtask` passed 110 tests with one intentionally ignored
accepted-toolchain environment gate. The positive toolchain gate was run
separately with the exact Rust 007 compiler:

```sh
WYRMROOT_RUSTC=/home/mike/Documents/Programming/OS-Project/artifacts/toolchains/accepted/RUST-WYR0-I-B-SYSROOTS-007/toolchains/wyrmroot-1.97.1-a92dc7f7/bin/rustc \
  cargo test --locked -p xtask \
  toolchain_artifact::tests::accepted_toolchain_positive_gate \
  -- --ignored --exact --nocapture
```

The accepted Deepwyrm production/six-selector artifact oracle was the ignored
`production_and_six_memory_selector_artifacts_are_separated` test in
`x86_64_memory_target_artifact`. Its accepted fourth invocation used the exact
Rust 007 binaries, direct regular LLVM 22 binaries, offline locked Cargo, fresh
temporary state, and a project-owned target directory. The identity-bearing
command was:

```sh
DEEPWYRM_ACCEPTED_CARGO=/home/mike/Documents/Programming/OS-Project/artifacts/toolchains/accepted/RUST-WYR0-I-B-SYSROOTS-007/toolchains/wyrmroot-1.97.1-a92dc7f7/bin/cargo \
DEEPWYRM_ACCEPTED_RUSTC=/home/mike/Documents/Programming/OS-Project/artifacts/toolchains/accepted/RUST-WYR0-I-B-SYSROOTS-007/toolchains/wyrmroot-1.97.1-a92dc7f7/bin/rustc \
DEEPWYRM_ACCEPTED_RUST_LLD=/home/mike/Documents/Programming/OS-Project/artifacts/toolchains/accepted/RUST-WYR0-I-B-SYSROOTS-007/toolchains/wyrmroot-1.97.1-a92dc7f7/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld \
DEEPWYRM_CLANG=/usr/lib/llvm/22/bin/clang-22 \
DEEPWYRM_LLVM_NM=/usr/lib/llvm/22/bin/llvm-nm \
DEEPWYRM_LLVM_OBJDUMP=/usr/lib/llvm/22/bin/llvm-objdump \
DEEPWYRM_LLVM_READELF=/usr/lib/llvm/22/bin/llvm-readobj \
  /usr/bin/cargo test --offline --locked \
  --target-dir /home/mike/Documents/Programming/OS-Project/.tmp/WYR0-I-WAVE5/deepwyrm-artifact-host-r4 \
  -p deepwyrm-kernel --test x86_64_memory_target_artifact -- \
  --ignored --exact production_and_six_memory_selector_artifacts_are_separated --nocapture
```

The final image, inspection, and live command set used
`WYR0I_EVIDENCE_ROOT=../artifacts/wyr0-i/wave5/candidate-r38-daybreak-dw-5a8bb0a7__wyr-ec84cc64__rust-a92dc7f7`
from `wyrmroot/`:

```sh
for WYR0I_CASE in closure-a closure-b i1 i2 i-capability \
  negative-malformed-elf negative-malformed-startup \
  negative-capability-count negative-capability-type negative-capability-rights
do
  cargo xtask image --request "$WYR0I_EVIDENCE_ROOT/$WYR0I_CASE/request.toml"
done

cargo xtask audit-i-b \
  "$WYR0I_EVIDENCE_ROOT/closure-a/request.toml" \
  "$WYR0I_EVIDENCE_ROOT/closure-b/request.toml"

for WYR0I_CASE in closure-a closure-b i1 i2 i-capability \
  negative-malformed-elf negative-malformed-startup \
  negative-capability-count negative-capability-type negative-capability-rights
do
  cargo xtask inspect-image --request "$WYR0I_EVIDENCE_ROOT/$WYR0I_CASE/request.toml"
done

cargo xtask test integration wyr0 default \
  --request "$WYR0I_EVIDENCE_ROOT/closure-a/request.toml"

for WYR0I_CASE in negative-malformed-elf negative-malformed-startup \
  negative-capability-count negative-capability-type negative-capability-rights
do
  cargo xtask test integration wyr0 default \
    --request "$WYR0I_EVIDENCE_ROOT/$WYR0I_CASE/request.toml"
done

cargo xtask test integration wyr0 smp \
  --request "$WYR0I_EVIDENCE_ROOT/i1/request.toml"

for WYR0I_REPEAT in 1 2 3 4 5
do
  cargo xtask test integration wyr0 smp \
    --request "$WYR0I_EVIDENCE_ROOT/i2/request.toml"
  mv "$WYR0I_EVIDENCE_ROOT/i2/runs/smp" \
    "$WYR0I_EVIDENCE_ROOT/i2/repeats/pass-$WYR0I_REPEAT"
done

cargo xtask test integration wyr0 \
  --request "$WYR0I_EVIDENCE_ROOT/i-capability/request.toml"

cargo xtask gdb default \
  --request "$WYR0I_EVIDENCE_ROOT/closure-b/request.toml"
```

The preserved I2 results are moved to `i2/repeats/pass-1` through `pass-5` as
part of evidence collection. The paired capability invocation runs default and
SMP sequentially and issues the certificate only after both results revalidate
against the same immutable media.

Final q35/OVMF results:

| Gate | Profile | Final result | Candidate SHA-256 |
| --- | --- | --- | --- |
| ordinary selector 18 | default, 1 vCPU / 1024 MiB | PASS, detail 0, QEMU 33 | `9c5b71df681fc0b9722fc7c6d596d52761440f3b91440a02210ad2eb5fb6d3d5` |
| five malformed/startup/capability negatives | default | exact expected failures `0xB0000001` through `0xB0000005`, QEMU 35 | request-bound per case |
| I1 selector 23 | SMP, 4 vCPU / 2048 MiB | PASS, 17 events, mask `0x000000ff`, QEMU 33 | `17ca9edfb361cd800796c250faeab12aae24ddbc78edb2e81b50ecf074b75cfa` |
| I2 selector 22 | SMP, 4 vCPU / 2048 MiB | five consecutive PASS, detail 0, QEMU 33 | `3ecca7888ce31912e5dd68e1f74def8cee8c49f1a2be19fae551c217010157c4` |
| capability selector 24 | paired default and SMP | both PASS, 15 events/profile, mask `0x000003ff`, QEMU 33 | `6786037dd11ff8ff5c0a28e54f67128c50540fc7b93ce879caf3334ebf63adf8` |

Exact retained result-file identities under the evidence root are:

| Result path | SHA-256 |
| --- | --- |
| `closure-a/runs/default/result.json` | `e3c9390ceb7325fa297d276bb1bd3f7bbba97255803b482ea0a9114ce8df2587` |
| `negative-malformed-elf/runs/default/result.json` | `76319985904cf25dadc0d8c9461c5610b769f058b97898ce012cc289d3f91abc` |
| `negative-malformed-startup/runs/default/result.json` | `d9560f9c0518a2c1ad7761963d5697a455a4216b255863dd28d8f88241336a86` |
| `negative-capability-count/runs/default/result.json` | `02b6ab7a7f67c4e618311b1d3ddd63e8f2cc293ef125f7bb9ec10d7117d9d96b` |
| `negative-capability-type/runs/default/result.json` | `1391c6957654af89e86f4ce84e30e2a7b653ac3b2d24faa91282aad82bbcc4e1` |
| `negative-capability-rights/runs/default/result.json` | `1c2e25bc056cb4d43bd3d138782b81aba69be269f551f2d917c0e415445b8fad` |
| `i1/runs/smp/result.json` | `4f8aa7f107a8a98baea88f911a175af6ae3b52215f00bb2759d18e7efd99e13b` |
| `i2/repeats/pass-{1..5}/result.json` (each) | `dd3822cb31eb7e4299aac8ba54c44e0226259a9d2e13d6173db057754d3f3bec` |
| `i-capability/runs/default/result.json` | `2a47333698ef43b9cc3e5076216b139b7ac759422384396634b188246dc2dd00` |
| `i-capability/runs/smp/result.json` | `69345cf15542b859df88daa324b4dcded6030359d3bfc48a7a7e76a910b5effb` |

The GDB command made a real host connection to the canonical gdbstub using
symbols SHA-256 `41d1b699543f4cab737547ded26d72ff310ca87ebce30c7c966826263ab3dee9`.
It is diagnostic evidence and is not counted as acceptance.

Every accepted run used q35/OVMF, no host filesystem share, and no guest
network. Production correctness did not depend on QEMU debug-exit support.

## Phase and security disposition

- I-A accepted the generic native capability contract without a Deepwyrm ABI
  addition.
- I-B accepted deterministic clean builds, generated-ABI consumption,
  libc/toolchain independence, malformed-input rejection, artifact inspection,
  and exact-symbol diagnostics.
- I-C accepted the finite generation-safe restart state machine.
- I-D accepted bounded controller-owned admission accounting with explicit
  `KERNEL`, `WYRMROOT`, and `FUTURE` classifications.
- I-E/I-F accepted the native capability payload, deterministic config/asset
  delivery, fail-closed `WRCAP1` parser, paired default/SMP proof, and
  host-generated certificate.
- I-G accepted the post-remediation ordinary matrix and exact-model Daybreak
  review.
- I-H accepts the consolidated records and exact root certificate at Wave 6.

The final `security/WYR0_SECURITY_REVIEW.md` review used
`gpt-daybreak-blue-latest` at high/xhigh effort. Initial C0/H1/M3/L2 findings
were remediated, the affected complete matrix was rerun, and four exact-model
final rereviews closed at C0/H0/M0/L0. No unresolved release-blocking finding
remains.

The earlier accepted Deepwyrm DW0-H security record remains inherited paired
baseline evidence. The WYR0-I review and Wave 5 results above are the security
and functional authority for this later exact product tuple.

## Resource-enforcement boundary and nonclaims

Deepwyrm enforces its generated Channel envelope and native object rights,
geometry, lifetime, and bounded-resource invariants. Wyrmroot enforces only the
controller-owned admission, reservation, replay, delegation, and cleanup paths
for which it withholds authority until admission succeeds.

There is no generic hostile-process TaskGroup quota containment for directly
created MemoryObjects, Channels, Events, Timers, handles, mappings, waits,
process/thread resources after authority delegation, CPU time, I/O, or device
resources. Those remain a later admitted resource-control milestone if a
consumer threat model requires them.

WYR0-I does not accept WYR0-GW, Glasswyrm workload topology/readiness, graphical
Wyrmroot, Prismdrake, a final service manager, VFS/persistent root, libc, vDSO,
physical hardware, or freestanding sanitizer coverage.

## Final disposition

WYR0-I validation is accepted on the exact tuple and evidence set above. The
generic native-userspace capability prerequisite is complete. Workload-specific
Glasswyrm readiness remains gated by a separate WYR0-GW certificate on a
compatible exact tuple.
