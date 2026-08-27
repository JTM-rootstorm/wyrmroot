# WYR0 toolchain and provenance bootstrap

This directory records the immutable source revisions and canonical tool
families selected for WYR0. It does not build a toolchain or add a Rust target;
the root dependency graph and build gate control Deepwyrm ABI consumption.

## Version authority

`versions.toml` is the machine-readable WYR0 pin. Builds and artifact manifests
must identify the exact Deepwyrm and Wyrmroot Rust revisions from that file;
branch names are not reproducibility inputs.

The pinned Deepwyrm revision must publish the canonical `deepwyrm-abi` crate.
Wyrmroot consumes it through the canonical repository URL and exact revision;
the build gate rejects a missing lockfile resolution or consumer. Never replace
that dependency with copied ABI definitions, a floating branch, or a committed
host-local path.

The pinned Wyrmroot Rust fork implements `x86_64-unknown-wyrmroot` as a built-in
static ELF target. It does not claim `cfg(unix)`, provide `std`, or authorize a
target JSON substitute. The accepted R0 request record binds the target source,
focused tests, `core`/compiler-builtins artifacts, and no-libc smoke ELF.

## Rust toolchain activation

All operator-facing Cargo entry points use `tools/pinned-cargo`. The launcher pins
the installed host Rust 1.97.1 identity recorded in
`host-rust-toolchain.toml`, supplies the shared offline project Cargo home, and
uses a reusable host-only target directory. Callers must omit `CARGO_HOME`,
`WYRMROOT_RUSTC`, compiler wrappers, target selection, and Rust flags. The
launcher rejects host invocations that could implicitly admit native, UEFI, or
other freestanding binaries; product builds remain centralized inside `xtask`,
which selects and verifies the accepted Wyrmroot fork itself.

The reusable default target directory avoids rebuilding unchanged host tools
and tests. Concurrent or disposable lanes may set
`WYRMROOT_PINNED_TARGET_DIR` only to an already-normalized absolute path beneath
`wyrmroot/.tmp` or `/tmp`; the launcher's identity marker prevents cross-
toolchain reuse.

The repository intentionally has no active root `rust-toolchain.toml` during
bootstrap. A Rust commit cannot be selected accurately with an official
moving-channel name, while activating a custom name before its compiler has
been built and registered would make every Cargo command fail.

Accepted WYR0 builds consume the immutable toolchain through an explicit
`WYRMROOT_RUSTC` path bound by the active coordinator request. `xtask` verifies
that path is inside the request-declared accepted artifact root, that its
manifest and full toolchain tree match the pinned hashes, and that the compiler
identity matches `rust.wyrmroot_revision`. A rustup registration under
`local_toolchain_name` may be convenient on a capable host, but it is not an
acceptance identity and a root `rust-toolchain.toml` is not required.

Do not replace the accepted compiler with `stable`, `nightly`, or a host-default
toolchain. A later Rust update requires an intentional revision change and the
corresponding immutable-artifact rebuild and validation.

## Build-profile authority

`profiles.toml` is the machine-readable WYR0 profile policy. It keeps the
host, UEFI-loader, and native-guest environments distinct without activating a
guest Cargo target prematurely. The native target is available at the exact
fork revision in `versions.toml`; no target JSON, `cfg(unix)` compatibility
setting, or host-default fallback is authorized.

The UEFI profile names the standard 64-bit UEFI Rust target, but it too must be
confirmed against the accepted pinned fork before it is used to build an
artifact. Its locked target contract is PE32+ COFF for AMD64, with the Rust
target's `rust-lld` MSVC-LLD/link-flavor selection and its EFI application
entry/subsystem arguments. A host `ld`, GNU linker, or host-libc fallback is
not permitted. The canonical `xtask` loader build consumes this policy centrally and records
the effective configuration and accepted toolchain identities in build
provenance.

Validate an accepted compiler's target specification without substituting the
host compiler:

```text
sh toolchain/verify-uefi-toolchain.sh --rustc <accepted-wyrmroot-rustc>
```

The canonical loader build emits a `/Brepro` production EFI without a CodeView
record and a separate full-debug EFI/PDB pair. Validate all three together:

```text
sh toolchain/inspect-uefi-artifact.sh <loader.efi> <debug-loader.efi> <loader.pdb>
```

UEFI uses PE/COFF rather than ELF, so this inspection intentionally checks the
PE machine/subsystem/import table, the production reproducibility record, and
the exact CodeView GUID/age linkage of the retained debug pair. It does not
rewrite PDB content. The native-userspace `PT_INTERP` rule remains mandatory
for later `bootstrap.elf`, `init0`, and `hello` inspection.

## Host LLVM environment

Clang, LLD, compiler-rt, LLVM binary utilities, and host GDB are the canonical
tool family. Their exact adopted host versions remain deliberately unset at
bootstrap and must be captured when the first build environment is accepted.
Guest and UEFI build settings must be explicit and centrally owned; they must
not inherit Gentoo target, include, library-search, or linker defaults.

Probe the currently available host family with:

```text
sh toolchain/verify-host-tools.sh --json
```

The JSON report is machine-readable availability evidence only. It reports
`observed-not-adopted` and does not modify `versions.toml`; an accepted build
must capture exact versions in its generated provenance record before any host
version becomes a WYR0 reproducibility input. The probe also requires the
x86_64 compiler-rt builtins archive exposed by Clang's resource directory.
`llvm-readobj` and `llvm-pdbutil` are required for the UEFI PE/COFF and retained
debug-pair inspection path.

`templates/build-provenance.toml` defines the minimum provenance fields for a
future generated build record. Generated records belong with build artifacts,
not as edits to this source template. Hash the effective build configuration
and each accepted artifact, and preserve full-symbol host artifacts separately
from any image copy that may later be stripped.

For native guest artifacts, provenance must identify the compiler-rt objects
actually linked and the LLVM inspection result proving both an absent
`PT_INTERP` and no guest libc dependency. Host-tool libc dependencies are
recorded separately and are not guest-runtime failures.

Inspect each completed native executable without running it:

```text
sh toolchain/inspect-native-artifact.sh <native-elf>
```

The machine-readable report verifies the fixed x86-64 `ET_EXEC` shape, bounded
program-header and load-segment counts, W^X, NX stack, entry symbol, absence of
dynamic metadata, relocations, and undefined symbols, and that the only raw
`syscall` instruction belongs to the Deepwyrm binding veneer.

The explicit primordial invalid-return test artifact is the sole exception:

```text
sh toolchain/inspect-native-artifact.sh --primordial-invalid-return-test <native-elf>
```

That mode requires exactly two raw `syscall` instructions: the ordinary binding
veneer and one terminal test tail that loads `u32::MAX`, zeros every syscall
argument plus `RSP`, executes `syscall`, and falls through only to `UD2`. It does
not relax the production invocation above.

The host-only deterministic bootfs encoder accepts the exact native `init0` and
`hello` artifacts and writes a new output without following or replacing an
existing path:

```text
tools/pinned-cargo xtask build bootfs
```

## WYR1-B acceptance freeze

The selector-27 acceptance product is created only through the one-shot,
request-bound pipeline:

```text
tools/pinned-cargo xtask wyr1b freeze --output ../artifacts/wyr1-b/candidate-fresh
tools/pinned-cargo xtask wyr1b inspect --request ../artifacts/wyr1-b/candidate-fresh/selector27/request.toml
tools/pinned-cargo xtask wyr1b run --request ../artifacts/wyr1-b/candidate-fresh/selector27/request.toml
tools/pinned-cargo xtask wyr1b evidence --request ../artifacts/wyr1-b/candidate-fresh/selector27/request.toml
```

Freeze requires exact clean Wyrmroot and canonical sibling Deepwyrm revisions,
the accepted Rust artifact, an offline dependency graph, pinned OVMF inputs,
and no ambient compiler, target, selector, or evidence overrides. Its output
contains the measured selector-27 bootfs, the kernel built with the matching
`DEEPWYRM_WYR1B_EVIDENCE_NONCE` and
`DEEPWYRM_WYR1B_BOOTFS_MAX_PAGES`, an independently inspected ESP, and exact
source, kernel, product, and run receipts. Outputs and runs are one-shot.
All request-bound artifacts are admitted through artifact-specific size caps
before hashing. A run snapshots its request, source/build receipts, bootfs,
firmware, and ESP into the fresh run directory; after QEMU exits it compares
every immutable live input with the exact snapshot, repeats clean-source
inspection, and renders the run receipt only from snapshot identities. Timeout
receipts retain the exact kill/reap disposition, and an unconfirmed reap is a
distinct failure rather than an ordinary timeout.
The outer launcher's `CARGO` path and exact project `CARGO_HOME` are admitted
only as host-launch state: native and UEFI product commands select the accepted
product Cargo and canonical home explicitly, while the Deepwyrm launcher
receives no inherited `CARGO_HOME` and selects its own accepted target-lane
home.

Selector 27 additionally compiles `system-init` with rustc's
`-Zemit-stack-sizes` metadata and fails the freeze unless pinned LLVM 22.1.8
`llvm-readobj` can decode the compiler-emitted stack sizes. Every named frame
must be at most 64 KiB, and the designated native main, product activation,
registry/job gate, and resident control-loop frames must each resolve to one
unambiguous entry. The source receipt binds the compiler flag, analysis method,
exact LLVM path/version/hash, cap, each designated frame size, and the global
maximum named frame; later inspect/run entry points repeat the artifact
analysis. This is a conservative artifact-level per-frame preflight, not an
aggregate call-chain proof. The exact selector-27 execution together with
Deepwyrm's bounded-RSP enforcement and 128 KiB RW-NX stack/absent-guard
invariant is the exercised-chain runtime proof; the tooling receipt does not
substitute for it.

The same freeze also creates disjoint
`selector25/normal/request.toml` and
`selector25/degraded_recovery/request.toml` products. Each has its own
selector-25 kernel scenario and nonce. Prepare their paired default/SMP run
bundles with `tools/pinned-cargo xtask wyr1 prepare --request <request>`;
selector-27 media and evidence identities are never reused for those
regressions. Both selector-25 requests bind the byte-identical WYR1-B source
receipt through their existing provenance input. WYR1 receipt inspection and
VM handoff preparation therefore rejoin the accepted toolchain, every native
build command, the selected scenario's native artifacts, kernel, nonce, and
scenario before snapshotting that shared receipt into each handoff.

Claim-bearing selector-25 handoffs must remain inside the resolved OS-Project
boundary because the verified persistent-VM runner rejects external paths.
Freeze directly into the project-root `artifacts/` tree as shown above. If an
older frozen candidate was created elsewhere, copy only its immutable request,
artifact, and product inputs into a fresh project-bound evidence directory and
verify their hashes before running `wyr1 prepare`; never reuse an external
prepared handoff as closure evidence.

The `native-bootstrap` binary is a no-std Wyrmroot target and must not be
host-linked by `cargo test`. When changing its feature-selected library path,
the corresponding compile-only developer check is:

```text
cargo check --locked --package wyrmroot-bootstrap --lib --features native-bootstrap,wyr0-init0-integration
```

Run that command only in an accepted host-toolchain environment. The canonical
selector product remains the request-bound `wyr1b freeze` pipeline above.
