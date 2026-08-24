# WYR0-I-B implementation and validation checkpoint

**Date:** 2026-08-24  
**Status:** implementation checkpoint complete; I-B gate not yet accepted

## I-A design recheck

WYR0-I-A remains complete at `b856079fe4a480930b68f425167c271a1397ae03` after rechecking the frozen native capability contract against the newer root `BOOTSTRAP_AND_RECOVERY_ARCHITECTURE.md` direction. The newer design reinforces fresh-generation isolation and finite restart policy; it does not change the generic WYR0-I capability split, admit a new Deepwyrm primitive, or turn temporary `init0` into the permanent supervisor. No I-A contract or architecture-index edit is required.

## Implemented I-B surface

The Wyrmroot implementation checkpoint is `1ed639503d32545193c573ede7046ad48ed54236`, consisting of:

- exact Deepwyrm `5da17d0d2460936e171d0874ffd2262ad4a5cc97` and Rust `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d` dependency/toolchain pin synchronization;
- `cargo xtask audit-i-b <first-request> <second-request>`, an explicitly artifact-only, fail-closed audit that reuses canonical request/image inspection, invokes `toolchain/inspect-native-artifact.sh`, compares every comparable consumed artifact, validates request-bound provenance independently, and emits all consumed hashes;
- a bounded defense-in-depth ELF geometry parser and heuristic source-copy scan, without claiming those replace the canonical inspector or manual structural audit; and
- `toolchain/cargo-with-local-deepwyrm.sh`, which verifies the exact unpublished Deepwyrm commit and ABI/syscall object identities before applying a process-scoped local Git URL transport. It does not use a path dependency, copy ABI definitions, or modify global Git configuration.

The audit intentionally reports `ARTIFACT_AUDIT_PASS`, `proves_independent_clean_builds:false`, and `clean_build_process_evidence:"REQUIRED_SEPARATELY"`. It cannot be mistaken for the complete phase gate.

## Exact pre-readiness candidate

| Component | Identity |
| --- | --- |
| Wyrmroot | `1ed639503d32545193c573ede7046ad48ed54236` |
| Deepwyrm product and generated ABI/syscall dependency | `5da17d0d2460936e171d0874ffd2262ad4a5cc97` |
| Rust fork | `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d` |
| Loader | `09427a9574979a6e1f64f493ebe0c50896e419e625ed3cd614992746d74d9beb` |
| I0 test-support kernel and exact symbols | `d4175ce4e7b88718b99cbd44e947d14c6cf093e757fd5dc2e332d7be5bde74bd` |
| Bootstrap | `03e7b91dbaa7db5dee029d0d3540cd264a20025550e51da7bde9fd83498dda42` |
| init0 | `fbb15279b3f3df9ea04a4b5848d2afc5c6c9b3bc49d58c24b2d663d837df750c` |
| hello | `8d4dd6dfa3d08300274478a9e0635e1ea879433b9841004ca1e3ee709b51eb3c` |
| bootfs | `42c908fffa492529a18899339f647dad77d96d185fc8a54880e5eeec1d3033e3` |
| ESP | `59b630d97feb2db3e321acfde8a4cea1ffcd1d53794f1209cff6a09b0063d982` |
| OVMF code | `f3ff7e73448ed2845ee15356f394882f5618eb5dab92c9a30ec6ee0e1468553a` |
| OVMF variables template | `6ed987af3a3c155be71665f510eae3e007eda9b8b94afd59d45e91c4a11565cc` |

Two clean detached source checkouts at the exact Wyrmroot and Deepwyrm revisions, plus the clean exact Rust checkout, produced the native payloads into separate `final-a-target` and `final-b-target` roots through the pinned `x86_64-unknown-wyrmroot` target. Separate canonical image invocations produced `final-a` and `final-b`. Bootstrap, init0, hello, bootfs, and ESP bytes were identical across the two builds. The local Git transport independently verified these Deepwyrm object identities on each invocation:

- `abi`: `1c6a74f130e386eee95b3780c75950beefd0037d`
- `crates/deepwyrm-abi`: `3c4b82b4253d7d21d0f578d8d5b966304472cd8f`
- `crates/deepwyrm-syscall`: `a64290953ccc0548e908be88586969ac0b70b589`

The two request-bound provenance records correctly differ only in request/candidate identity. Their hashes are `7da361ad2d024552ab4d18d81c5f7313f0c214ebf211e040ce13b0abdd60ecb7` and `d5712f664a3973ec018044e965c96019d0afef1f82a2585df848a7dee193d477`; canonical inspection validated both.

## Toolchain identities

- accepted Rust compiler: `rustc 1.97.1-dev`, LLVM `22.1.6`, binary SHA-256 `65bd51e9ecb8e1185524471a8cbc4af1e6ac4e37e7d446c7a127bda0fa431c70`;
- accepted Cargo: `cargo 1.96.1 (356927216 2026-06-26)`, binary SHA-256 `a73b2c25573d251489101c0d8f19ad3702eb9761166de5ed8437b472b6c038ce`;
- Clang/Clang++ and LLD `22.1.8`, LLVM object tools from LLVM 22, compiler-rt resource root `/usr/lib/clang/22`; and
- host GDB `17.2`.

The native build used explicit `RUSTC`, `RUSTDOC`, `CARGO_TARGET_DIR`, `--locked`, `--release`, and `--target x86_64-unknown-wyrmroot` inputs with the accepted toolchain first in `PATH`. The recipe did not invoke GCC or GNU binutils. The canonical native inspector verified static ET_EXEC shape, the primordial program-header subset, W^X/NX, no dynamic dependencies, no relocations or undefined symbols, exact `_start`, bounded nonoverlapping mappings, and the sole generated syscall veneer for bootstrap, init0, and hello in both candidates.

## Validation results

- `cargo xtask abi check` at exact Deepwyrm `5da17d0`: PASS.
- Full Wyrmroot host gate through the exact local transport: PASS, including xtask `89 passed, 1 accepted environment-gated test ignored`, malformed ELF/startup/capability suites, bootfs truncation/overflow/traversal suites, and runtime/authority/close-after-use suites.
- Manual structural ABI search across `bootstrap`, `crates`, `loader`, and `userspace`: no numeric `DW_*` definitions, raw numeric `dw_syscall6` calls, or local `Dw*` ABI type declarations found. The bounded heuristic scan covered 91 files / 1,454,922 bytes with zero findings.
- `cargo xtask audit-i-b final-a/request.toml final-b/request.toml`: `ARTIFACT_AUDIT_PASS` with byte-identical comparable artifacts and independent request-bound provenance validation.
- `cargo xtask gdb default --request final-b/request.toml`: GDB connected through the canonical QEMU gdbstub and emitted `DIAGNOSTIC` with exact symbols SHA-256 `d4175ce4e7b88718b99cbd44e947d14c6cf093e757fd5dc2e332d7be5bde74bd`.
- `cargo xtask test integration wyr0 --request final-a/request.toml`: PASS for both default (1 vCPU / 1024 MiB) and SMP (4 vCPU / 2048 MiB), same candidate/media, selector 18, exact structured PASS/detail 0, QEMU exit status 33.

The authority checks retain the primordial bootstrap's existing narrow handoff, verify close-after-use and reverse-order cleanup behavior for bootstrap/init0/hello, keep `init0` explicitly temporary, and keep production paths separate from debug-exit/test-only terminal behavior. No Deepwyrm ABI/schema change was needed.

## Gate disposition and remaining work

This is a substantial I-B implementation and evidence checkpoint, not I-B acceptance. The two Wyrmroot native/image builds are reproducible, but the accepted immutable Rust bundle contains the Wyrmroot target sysroot only; it does not contain `x86_64-unknown-uefi` or `x86_64-unknown-none` core sysroots. Consequently this run deliberately reused, copied into distinct output roots, and hash-verified the accepted loader and exact Deepwyrm `5da17d0` I0 kernel/symbol artifact instead of silently presenting them as newly rebuilt outputs.

I-B remains open until the exact accepted toolchain workflow can clean-rebuild those loader/kernel inputs (or the coordination plan explicitly accepts immutable exact-input reuse as satisfying I-B1). The "new WYR0-I payload" inspection also becomes applicable only when I-C introduces that payload; bootstrap/init0/hello are the complete current native payload set.
