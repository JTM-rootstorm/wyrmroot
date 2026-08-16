# WYR0-B validation record

This document records changing WYR0-B implementation and validation evidence. It is not a
substitute for the repository README and does not claim that the WYR0-B phase gate has closed.

## Loader implementation checkpoint

- Wyrmroot base: `a35246850eb5c35e9a950cd148b2f9678a2dca1a`
- Tested Wyrmroot loader revision: `25219686b87630d3a3cd6b3996cc56d521e72a39`
- Pinned Deepwyrm revision: `07140ca7da26fad7173b80ed1cdf26c98b50aaab`
- Accepted Rust source revision: `8bab26f4f68e0e26f0bb7960be334d5b520ea452`
- Accepted toolchain manifest SHA-256:
  `553cbfe6eb5cd9976c4f078a3731269f2a2ecd4f3ff5d574ab3813bae8fcf1f1`

The pinned Deepwyrm revision is the final DW0-B evidence checkpoint. It contains the canonical
generated ABI and x86_64 layout contract consumed by this loader, plus the reviewed source/tooling
and deterministic artifact evidence for the paired handoff.

The checkpoint contains the ownership-complete WYR0-B loader transaction. It includes:

- deterministic artifact paths and bounded configuration/file admission;
- hostile-input Deepwyrm ELF validation with exact generated link-base policy;
- generated-ABI BootInfo, module, and bounded memory-map construction;
- exact transition preflight sizing, four-level page-table encoding, and raw x86_64 handoff;
- retained-page zeroing, bounded RSDP-only ACPI handling, entropy provenance, and allocation
  ownership scaffolding;
- explicit bounded COM1 initialization for post-firmware diagnostics;
- exact Deepwyrm layout discovery/generation and accepted-toolchain manifest verification;
- path-neutral loader artifact provenance.
- one consuming pre-EBS rollback owner, one `ExitBootServices` surface, release-less post-EBS
  allocation tokens, and fatal local handling for every post-EBS construction failure;
- final-map normalization, retained table/module coherence, page-table population, bounded COM1
  marker emission, verified raw entry state, and the nonreturning kernel jump on the live entry path.

Evidence collected against the tested clean revision:

- complete loader host suite: 85 passed, 0 failed;
- loader strict host Clippy with warnings denied: passed;
- accepted `x86_64-unknown-uefi` target check: passed;
- accepted `x86_64-unknown-uefi` target build and PE inspection: passed;
- xtask unit tests: 29 passed, 0 failed, with the explicit real-artifact acceptance test ignored in
  the ordinary hermetic suite;
- real immutable-toolchain trust gate: passed, including whole-tree,
  internal runtime-library, interpreter/dependency, and pre/post identity verification;
- xtask strict Clippy with warnings denied: passed;
- workspace formatting and diff hygiene: passed.

The accepted build produced these path-neutral artifact identities:

- `target/wyr0-b/x86_64-unknown-uefi/debug/loader.efi`: SHA-256
  `deb041b224af53a97a674543fd566c691a47d0d71edf35ec2a6a59a03a02edda`;
- `target/wyr0-b/x86_64-unknown-uefi/debug/loader.pdb`: SHA-256
  `489d89804fbdc085db7a9bf9b0f908c91582680b3d8f701ab36a09e0f2d4ea2a`;
- PE inspection report identity:
  `f616d99b1385ed13d3d59091f5c02db5966c0228532ea632868794831f151b11`;
- `target/wyr0-b/provenance/wyr0-b-loader.toml`: SHA-256
  `e94a703664b2e201c1c27e8a8e4697aa794b3ae2dea5657b6c0612c5b141e07a`.

The provenance records a clean Wyrmroot tree, the exact Deepwyrm and Rust revisions, the accepted
toolchain manifest and whole-tree identities, the selected compiler/runtime component hashes, and
repository-relative artifact paths. PDB-guided disassembly of the PE artifact verified the emitted
16-byte raw handoff stub as `cli; cld; mov cr3; mov rsp; mov rdi; xor rbp; jmp rdx`, with no call or
return edge.

## Gate disposition

WYR0-B implementation, host security, accepted loader build, PE inspection, and path-neutral
artifact provenance gates are complete for the tested revision pair.

No VM or QEMU/OVMF acceptance claim exists for this checkpoint. The manager-owned paired Q35/UEFI
serial and handoff gate remains required before WYR0-B phase closure.

## Layout-v2 paging-handoff descendant

The clean descendant `bee49a19a8c4c341b8fd6ed71606f9473b00ae64` consumes the canonical
Deepwyrm paging-handoff contract at `79c2e365901ab95d04e5f6877b87b109f61f7ca4`. The accepted Rust
source revision remains `8bab26f4f68e0e26f0bb7960be334d5b520ea452`, using immutable artifact
request `RUST-PHASE0B-TOOLCHAIN-001`, configuration `63e532b52e6d4c2e`, and manifest SHA-256
`553cbfe6eb5cd9976c4f078a3731269f2a2ecd4f3ff5d574ab3813bae8fcf1f1`.

This descendant adds the bounded fixed point for the complete used transition-table graph, an
identity-mapped supervisor-RW/NX table prefix, a reserved temporary PML4 slot with an exactly zero
leaf, consuming plan-bound graph attestation, and the generated kind-3 paging carrier. The carrier
publishes the exact 112-byte header plus the sorted used-frame prefix, remains owned across
`ExitBootServices`, and is mapped read-only/NX. The raw transfer observes PAT entry zero as `0x06`,
clears CR4.PGE, loads the aligned attested CR3 with PCID zero, then clears CR4.PCIDE. This records
PAT-selection consistency only and makes no MTRR-derived effective write-back claim.

Clean-revision evidence:

- focused paging/module/BootInfo/UEFI host tests: 59 passed, 0 failed;
- complete loader host suite: 95 passed, 0 failed;
- unfiltered `cargo xtask test host`: 184 passed, 0 failed, 1 accepted environment-gated ignored;
- `cargo test --locked -p xtask`: 39 passed, 0 failed, 1 accepted environment-gated ignored;
- the ignored immutable-toolchain positive gate, run separately with the accepted compiler: passed;
- strict loader and xtask Clippy with warnings denied: passed;
- workspace formatting and repository diff hygiene: passed;
- accepted immutable-toolchain verification, generated-policy target check/build, PE inspection, and
  clean schema-v2 provenance generation: passed.

The clean accepted build produced:

- `target/wyr0-b/x86_64-unknown-uefi/debug/loader.efi`: SHA-256
  `c6ec39a427754475616cab6cdd62c3f5cfd67a64a6cf34b8fe65ac4c9e142cdb`;
- `target/wyr0-b/x86_64-unknown-uefi/debug/loader.pdb`: SHA-256
  `3dbfb3019f4ca0cbf3bb5ef5c674707c6c74951640f9b26f0918a4c42cc52f89`;
- PE inspection report identity:
  `f616d99b1385ed13d3d59091f5c02db5966c0228532ea632868794831f151b11`;
- `target/wyr0-b/provenance/wyr0-b-loader.toml`: SHA-256
  `62ceb648996d1e18088e66d67800ece60aefc8b53d4e959cdfa1c1a73608da65`.

The provenance records `wyrmroot_dirty = false`, the exact Wyrmroot/Deepwyrm/Rust revisions, both
layout hashes, the accepted toolchain identities, and an explicit statement that build provenance
does not itself claim behavioral handoff conformance. PDB public symbols place
`__wyrmroot_handoff_start` and `__wyrmroot_handoff_end` 37 bytes apart. PE disassembly verifies
`cld; read CR4; clear PGE; write CR4; load CR3; read CR4; clear PCIDE; write CR4; set RSP/RDI;
clear RBP; jmp RDX`, with no call or return edge.

The source, host, accepted-build, PE, provenance, and adversarial-review gates pass for this clean
descendant. The root-coordinator-owned exact-pair VM BootInfo/carrier handoff gate remains pending;
this record does not claim VM, QEMU/OVMF, or physical-hardware acceptance.

## 128-KiB kernel boot-stack descendant

The clean descendant `6230d2c26b0260add3fad1e1cc55c878c0362ab5` consumes Deepwyrm
`b263a7a912c79b9e7d4b2439370417d7ae2ee076`. The Deepwyrm ABI and layout schema version are
unchanged; its locked x86_64 layout enlarges the kernel-owned immediate-entry `.bss.boot_stack`
from 64 KiB to 128 KiB. The loader-owned 16 KiB transition stack and all handoff wire structures
remain unchanged. The accepted Rust source, configuration, and manifest identities remain those
recorded above.

Clean-revision evidence:

- strict layout ingestion accepts `kernel_boot_stack_size = 131072` and rejects stale `65536`;
- the complete loader host suite passed 97 tests, including a 128-KiB writable NOBITS-tail
  regression that verifies exact `0x21_000` page rounding, undersized-allocation rejection,
  materialization extent, non-overlap, and read/write non-executable transition mapping;
- `cargo test --locked -p xtask` passed 40 tests with the one accepted environment-gated test
  ignored, and that immutable-toolchain positive gate passed separately;
- unfiltered `cargo xtask test host`, strict loader and xtask Clippy, workspace formatting, and
  repository diff hygiene passed;
- accepted immutable-toolchain verification, target check/build, generated-layout checks, PE
  inspection, and clean schema-v2 provenance generation passed.

The clean accepted build produced:

- `target/wyr0-b/x86_64-unknown-uefi/debug/loader.efi`: SHA-256
  `c2d15d31db924a235a46730aca3e9dbf4b8edf58c2d6ceddb7bae9e82f776675`;
- `target/wyr0-b/x86_64-unknown-uefi/debug/loader.pdb`: SHA-256
  `810489525e70d3f57447709b523444ea018738d2b22876ed2cd9b1a5de486e6f`;
- PE inspection report identity:
  `f616d99b1385ed13d3d59091f5c02db5966c0228532ea632868794831f151b11`;
- `target/wyr0-b/provenance/wyr0-b-loader.toml`: SHA-256
  `47e7627da08fc783c74c21d705ed5c01e55fced4f9da320e876025865b51fe5a`.

The provenance records `wyrmroot_dirty = false`, the exact Wyrmroot, Deepwyrm, and Rust revisions,
Deepwyrm layout SHA-256 `aaebb83203efaaae5b495e59484f9e0003bae6a30067ee63f02c9ea48db54e5d`,
and generated layout-policy SHA-256
`7c557c7460b815615c73a0dc298814772c43ae1e1797775a8b10324b60bfd72f`. The final Daybreak
review found no Critical, High, Medium, or Low findings in this bounded acknowledgment. Exact-pair
VM execution remains root-coordinator-owned and is not claimed here.

## Guarded-IST kernel-pin descendant

The clean descendant `15fa42dda23834a80197161249738f001bb2d76f` consumes Deepwyrm
`9c7d65d3df83ce44b2ce1f15c2ae88587f9b570b`. The Deepwyrm change adds guarded
terminal IST stacks and corrects their artifact oracle. The ABI/schema,
`kernel/arch/x86_64/layout.toml`, `DwBootInfoV1`, loader handoff, three-`PT_LOAD`
policy, primordial startup, bootstrap Channel, and bootfs `MemoryObject` rights
contracts are unchanged. The Rust revision and accepted immutable-toolchain
identity remain those recorded above.

Clean-revision evidence:

- the exact Deepwyrm Git revision agrees across `Cargo.toml`, `Cargo.lock`,
  `toolchain/versions.toml`, and the build-provenance template, and locked Cargo
  metadata resolves only that canonical Git source;
- unfiltered `cargo xtask test host` passed 187 tests with no failures and one
  accepted immutable-toolchain test ignored in the normal suite;
- the complete loader host suite passed 97 tests; focused kernel-ELF and
  transition suites passed 20 and 18 tests respectively;
- the bootfs builder/parser suite passed 30 tests, and focused runtime,
  protocol, bootstrap, `init0`, and `hello` checks passed;
- `cargo test --locked -p xtask` passed 40 tests with one accepted test ignored;
  the ignored immutable-toolchain positive gate passed separately in 131.17
  seconds against the accepted compiler;
- strict loader and xtask Clippy with warnings denied, workspace formatting,
  repository diff hygiene, immutable-toolchain verification, target check/build,
  PE inspection, and clean schema-v2 provenance generation passed.

An exploratory workspace-wide host Clippy invocation with every feature forced
was not used as an acceptance gate: that unsupported composition combines the
UEFI firmware panic handler with host `std` and fails on duplicate/incompatible
panic implementations. The canonical host component checks and accepted
`x86_64-unknown-uefi` target build above passed.

The clean accepted build produced:

- `target/wyr0-b/x86_64-unknown-uefi/debug/loader.efi`: SHA-256
  `e47f6aaae15d5e4f8cf34fcfa827cf95ff43e5ec1bab288b02bc65b98800c031`;
- `target/wyr0-b/x86_64-unknown-uefi/debug/loader.pdb`: SHA-256
  `7655e2c3102d54268703617132aaf86acf47484c4ec7595e6cafdac67d26e911`;
- PE inspection report identity:
  `f616d99b1385ed13d3d59091f5c02db5966c0228532ea632868794831f151b11`;
- `target/wyr0-b/provenance/wyr0-b-loader.toml`: SHA-256
  `384841ca8c3c867a87e23e27d8ec5420ce47fc2db0b1ce3aafa276f9e90047be`.

The provenance records `wyrmroot_dirty = false`, the exact Wyrmroot,
Deepwyrm, and Rust revisions, Deepwyrm layout SHA-256
`aaebb83203efaaae5b495e59484f9e0003bae6a30067ee63f02c9ea48db54e5d`,
and generated layout-policy SHA-256
`7c557c7460b815615c73a0dc298814772c43ae1e1797775a8b10324b60bfd72f`.
PE/PDB inspection found a PE32+ AMD64 EFI application with no imports and
matching PDB identity. PDB symbols delimit the 37-byte handoff stub; disassembly
verifies PGE clear, CR3 load, PCID clear, RSP/RDI installation, RBP clear, and
an indirect jump with no call or return edge.

The final `gpt-daybreak-blue-latest` high-reasoning review dated 2026-08-16
found no new Critical, High, Medium, or Low findings for the exact source and
artifact pair. The existing accepted Medium limitations remain in force.
Exact-pair VM execution remains root-coordinator-owned and unavailable at this
phase; this record claims no VM, QEMU/OVMF, BootInfo/carrier execution, or
physical-hardware acceptance.

## Signed-publication evidence mapping

No build, test, artifact generation, or artifact rehash was performed for this
publication mapping. The loader, PDB, PE-inspection report, and generated
provenance identities in the guarded-IST descendant above remain historical
evidence generated for clean Wyrmroot
`15fa42dda23834a80197161249738f001bb2d76f` paired with Deepwyrm
`9c7d65d3df83ce44b2ce1f15c2ae88587f9b570b`.

The historical Wyrmroot source commit and signed rewrite
`ee1b899045a3294f140945e013ba42a60f57aa84` share Git tree
`7472f8151aaf5312b9d28fef4f8002f56af8abb6`. Historical evidence commit
`89235c7feef2a89ef2882ee096428b456496fa39` and signed rewrite
`2b16b94818632f562a0551205d94e62bba847502` likewise share tree
`619fb9f232796f8b3fd963b3487f084f6bd82fb2`. The old chain remains reachable
in this publication-preparation checkout at
`refs/backup/wyrmroot/pre-publication-main-20260816-89235c7`.

Coordinator verification establishes that Deepwyrm
`9c7d65d3df83ce44b2ce1f15c2ae88587f9b570b` and signed rewrite
`b424d7d89d9acc57ceff8d966c3931e26a51f614` share tree
`4053153adfaca4a3582d53768c2a6fc11572ee7f`. Signed live-quartet commit
`eaaba1491c2f45d4fbd8b02358989547e9a8d98a`, whose parent is
`2b16b94818632f562a0551205d94e62bba847502`, changes only the canonical
Deepwyrm revision in `Cargo.toml`, `Cargo.lock`, `toolchain/versions.toml`, and
`toolchain/templates/build-provenance.toml`.

The historical artifact provenance therefore continues to name its original
generating revisions and must not be read as freshly generated evidence for
`eaaba1491c2f45d4fbd8b02358989547e9a8d98a`. Exact-pair VM execution remains
root-coordinator-owned and pending; this mapping claims no VM, QEMU/OVMF,
BootInfo/carrier execution, or physical-hardware acceptance.
