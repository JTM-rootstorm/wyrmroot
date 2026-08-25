# WYR0-I-B implementation and validation closure

**Date:** 2026-08-24  
**Status:** I-B accepted on the exact product tuple below

## I-A design recheck

WYR0-I-A remains complete at Wyrmroot `b856079fe4a480930b68f425167c271a1397ae03`. Rechecking the frozen native capability contract against the newer root `BOOTSTRAP_AND_RECOVERY_ARCHITECTURE.md` reinforces fresh-generation isolation, finite restart policy, and temporary-`init0` boundaries. It neither admits a new Deepwyrm primitive nor changes the I-A capability split. No I-A contract or architecture-index edit is required.

## Exact accepted product tuple

| Component | Identity |
| --- | --- |
| Deepwyrm product | `a6db870e1f0123cfb46491c583a3a8d7bf08e9a2` |
| Wyrmroot product | `f246dd7a7d37d3e1c73791a24f5a73ddb71c3979` |
| Rust fork | `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d` |
| Accepted immutable toolchain | `RUST-WYR0-I-B-SYSROOTS-007` |
| Toolchain manifest SHA-256 | `cc78368219552cce8fdaad38ab419040cab945fe175aa774d6dca51eece84fd2` |
| Toolchain tree SHA-256 | `dce57d31def1f509ce537f96ae6b6dd320da11c9f321382cb93d142f558a32ca` |

This validation document is an evidence-only descendant of the Wyrmroot product revision. The generated Deepwyrm ABI object identities remain `abi=1c6a74f130e386eee95b3780c75950beefd0037d`, `crates/deepwyrm-abi=3c4b82b4253d7d21d0f578d8d5b966304472cd8f`, and `crates/deepwyrm-syscall=a64290953ccc0548e908be88586969ac0b70b589`.

## Accepted toolchain extension

The immutable 007 bundle supplies matching sysroots for:

- `x86_64-unknown-linux-gnu`;
- `x86_64-unknown-wyrmroot`;
- `x86_64-unknown-uefi`; and
- `x86_64-unknown-none`.

It was built without Rust source changes from the exact accepted revision. Its accepted compiler SHA-256 is `65bd51e9ecb8e1185524471a8cbc4af1e6ac4e37e7d446c7a127bda0fa431c70`, Cargo SHA-256 is `a73b2c25573d251489101c0d8f19ad3702eb9761166de5ed8437b472b6c038ce`, and `rust-lld` SHA-256 is `38a9f28404309892f9c9afe02fa4979a0d9e8bc866979cde09f5bb7ec17e5721`. The positive accepted-toolchain identity gate passed after hashing the full immutable bundle.

The production UEFI loader uses `/Brepro` and no CodeView record. A separate full-debug PE/PDB pair uses `/Brepro` plus `/pdbaltpath:loader.pdb`; the canonical inspector validates its GUID/age and globals/publics. Those retained debug bytes may differ between clean lanes and are not guest media or a production-equality requirement.

## Independent clean-build evidence

Two detached, clean Deepwyrm and Wyrmroot worktrees at the exact product commits used distinct Cargo homes, target roots, product roots, and candidate roots. Rust remained clean at the exact accepted commit. The lane receipts are:

- `artifacts/wyr0-i-b/candidate-dw-a6db870e__wyr-f246dd7a__rust-a92dc7f7/closure-a/clean-build-receipt.toml`;
- `artifacts/wyr0-i-b/candidate-dw-a6db870e__wyr-f246dd7a__rust-a92dc7f7/closure-b/clean-build-receipt.toml`.

Every production input was rebuilt with the accepted Rust 007 compiler/sysroots. The kernel recipe used explicit path remapping so full retained DWARF/symbol bytes are reproducible across the two source paths. No stale loader or kernel artifact was substituted.

| Consumed artifact | SHA-256 |
| --- | --- |
| production loader | `611f0f673dc3b5a2ce66a19f73f1eaef091c2615a21c55be14592a728b858d52` |
| kernel and exact symbols | `2455d86a6b8c5c83e0a99dfb898030a22a09e0996c9a6a3ad8e5725ee545fa3c` |
| bootstrap | `fc2959b5c896d13eed8eeebaed959d0532b34bab1950913f4b2ad12ff5adc79b` |
| init0 | `c99edc75bf993bef2f5b023e7641e86ab41f4fee4d7b479d5e330190ab688d5a` |
| hello | `fa17fb5882c7f500575cfea9bf272c54277107a3dcda54823f6a5b56204830b0` |
| bootfs | `89149d6eebafef788a8ae3957e49f57fad489b04ad4a3e85849eb46a152337df` |
| ESP | `c96dad57531c80222673ee6619d5bf4cbdc1b12e63a41ea603be4b2e7549a914` |
| OVMF code | `f3ff7e73448ed2845ee15356f394882f5618eb5dab92c9a30ec6ee0e1468553a` |
| OVMF variables template | `6ed987af3a3c155be71665f510eae3e007eda9b8b94afd59d45e91c4a11565cc` |

The durable candidate requests have SHA-256 `c1dc9aad25b1be472811ab04091e8862b49c6a73f09c1a53a08797612b3b640d` and `6c17210dc15fd427d9502737adeb3799d490b20430e9205d6b40a4bec9cb24ae`. Their request-bound provenance hashes are `7deb121210a9811b372ca02c26cf76eab9733690c9feda472299002a592434d6` and `ef82f2c2db2fc8c473256730f0f255c7bba88e4441f55d90162a491274f6f37d`; the different request/candidate identities are expected and independently validated.

## Validation results

- Deepwyrm formatting, ABI drift, the full locked workspace, focused migration contracts, and the exact accepted-toolchain freestanding artifact gate: PASS. The accepted gate re-proved fixed stack paths; Rust 007 required the private terminal-reaper carrier to grow by one page to retain its locked 32 KiB safety spare.
- Wyrmroot full host gate through the exact local Deepwyrm transport: PASS, including xtask `90 passed, 1 accepted environment-gated test ignored`, the separate positive accepted-toolchain gate, malformed ELF/startup/capability suites, bootfs truncation/overflow/traversal suites, and authority/close-after-use suites.
- Canonical native inspection for bootstrap, init0, and hello: PASS. All are static ET_EXEC files with no `PT_INTERP`, `PT_DYNAMIC`, relocations, undefined symbols, writable-executable segment, host libc, or duplicated syscall veneer.
- Bounded ABI source scan: 91 files / 1,462,902 bytes, zero heuristic findings. Manual structural review found no hand-copied Deepwyrm syscall numbers, object types, rights, statuses, or wire layouts.
- Durable double-build audit: `ARTIFACT_AUDIT_PASS`, all comparable production bytes identical, bootfs executable set exactly `bin/hello` and `system/init0`.
- Canonical QEMU/GDB diagnostic: real connection to `127.0.0.1:1234`, exact symbols SHA-256 `2455d86a6b8c5c83e0a99dfb898030a22a09e0996c9a6a3ad8e5725ee545fa3c`.
- Paired live integration: PASS on the same durable candidate/media for default (1 vCPU / 1024 MiB) and SMP (4 vCPU / 2048 MiB), selector 18, structured `pass` / detail 0, QEMU exit status 33.

The authority checks preserve the primordial bootstrap's narrow handoff, close-after-use and reverse-order cleanup behavior, temporary `init0`, and separation between production correctness and test-only debug-exit signaling. No Deepwyrm ABI/schema expansion was needed.

## Post-acceptance non-Daybreak review

A 2026-08-24 non-security review of the I-B closure machinery found and corrected two validator gaps, one host-tool identity reporting gap, and stale operator documentation. Runtime dependency validation now examines the complete RUNPATH search order: the first local match must be the manifest-pinned component, lower-priority duplicate copies are accepted only when byte-identical to that pinned component, divergent duplicates fail, and ambient system dependencies remain forbidden from being shadowed inside the accepted toolchain. The toolchain request's per-component SHA-256 fields are also now checked against the hashes in the already-pinned artifact manifest instead of remaining redundant unchecked claims. The host-tool probe now extracts the actual LLVM version line for LLVM utilities instead of recording their generic banner as the version identity.

The accepted Rust 007 bundle still passes the strengthened positive identity gate. Its two RUNPATH-visible copies of the pinned LLVM shared library are byte-identical, so no accepted toolchain bytes or hashes changed. Wyrmroot formatting and clippy with warnings denied pass; the full host gate passes with xtask `92 passed, 1 accepted environment-gated test ignored`; the host-tool probe reports LLVM utilities as `LLVM version 22.1.8`; and Deepwyrm `cargo xtask abi check` remains clean. The review also re-read the active phase's required prior-art set and found no newly applicable pattern requiring an I-B architecture or ABI change. The exact accepted product tuple and original double-build/guest evidence above remain unchanged.

## Post-signing revision identity

On 2026-08-24, the unpublished Deepwyrm and Wyrmroot histories were rewritten solely to add GPG signatures while preserving every rewritten commit's tree, message, author identity/date, committer identity/date, and topology. The acceptance evidence above intentionally retains the pre-sign identities embedded in the durable request/provenance bytes. Their canonical signed equivalents are Deepwyrm product `a6db870e1f0123cfb46491c583a3a8d7bf08e9a2` -> `cfc69bd8a49819ce1cda1a132cf56e55c93f92e4`, Wyrmroot I-A `b856079fe4a480930b68f425167c271a1397ae03` -> `afa55d32086d3fddc9a5554238e7c42ab6b7e5fe`, and Wyrmroot I-B product `f246dd7a7d37d3e1c73791a24f5a73ddb71c3979` -> `26a4049f8cab0b2de0213d3ed76fcf2c7c9d82a8`. The complete Wyrmroot mapping is recorded in `Plans/SIGNED_HISTORY_MAP_2026-08-24.md`; Deepwyrm carries its corresponding map in `docs/SIGNED_HISTORY_MAP_2026-08-24.md`.

Live Wyrmroot dependency/toolchain pins use the canonical signed Deepwyrm identity. Existing durable I-B artifacts are not rewritten, because changing their embedded revision fields would invalidate the request/provenance hashes they are evidence for.

## Required-source and example disposition

The root WYR0-I plan, I-A native capability contract, image-delivery addendum, bootfs contract, WYR0-H validation contract, architecture indices, and bootstrap/recovery architecture materially governed this implementation.

The plan's Fuchsia/Zircon examples support the I-A capability/bootstrap boundary but do not provide a competing I-B build-closure mechanism. The s6 examples apply to I-C bounded supervision/backoff, not I-B reproducibility. No upstream source was copied or substantially adapted for I-B; the implementation is first-party and preserves existing license boundaries.

## Gate disposition

WYR0-I-B is accepted on the exact product tuple above. This closes only canonical hardening and clean-build closure. The reusable supervision payload, capability probe/certificate, final ordinary matrix, and final Daybreak review remain I-C through I-H work.
