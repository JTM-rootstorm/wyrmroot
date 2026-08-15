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

The native Rust target name is reserved for coordinated work in the Wyrmroot
Rust fork. The metadata does not claim that `x86_64-unknown-wyrmroot` exists at
the pinned commit, and build configuration must not emulate it with an
unreviewed target JSON or mark it as `cfg(unix)`.

## Rust toolchain activation

The repository intentionally has no active root `rust-toolchain.toml` during
bootstrap. A Rust commit cannot be selected accurately with an official
moving-channel name, while activating a custom name before its compiler has
been built and registered would make every Cargo command fail.

After the pinned fork is built and its artifacts are accepted, register that
installation under the exact `local_toolchain_name` from `versions.toml` and
activate a root copy of `templates/rust-toolchain.toml`. The registered
compiler must be checked with `rustc -vV`; its commit hash must match
`rust.wyrmroot_revision` before it is used for guest artifacts.

Do not replace the custom name with `stable`, `nightly`, or a host-default
toolchain. A later Rust update requires an intentional revision change and the
corresponding rebuild and validation.

## Build-profile authority

`profiles.toml` is the machine-readable WYR0 profile policy. It keeps the
host, UEFI-loader, and native-guest environments distinct without activating a
guest Cargo target prematurely. In particular, the native target remains
reserved until the pinned Wyrmroot Rust fork implements it; no target JSON,
`cfg(unix)` compatibility setting, or host-default fallback is authorized.

The UEFI profile names the standard 64-bit UEFI Rust target, but it too must be
confirmed against the accepted pinned fork before it is used to build an
artifact. Its locked target contract is PE32+ COFF for AMD64, with the Rust
target's `rust-lld` MSVC-LLD/link-flavor selection and its EFI application
entry/subsystem arguments. A host `ld`, GNU linker, or host-libc fallback is
not permitted. When `xtask` gains its real build implementation, it must
consume this policy centrally and record the effective configuration hash in
build provenance.

Validate an accepted compiler's target specification without substituting the
host compiler:

```text
sh toolchain/verify-uefi-toolchain.sh --rustc <accepted-wyrmroot-rustc>
```

After a real loader build, validate the produced EFI file and its retained
debug-symbol artifact with:

```text
sh toolchain/inspect-uefi-artifact.sh <loader.efi> <loader.pdb-or-equivalent>
```

UEFI uses PE/COFF rather than ELF, so this inspection intentionally checks the
PE machine/subsystem/import table instead of applying the native userspace
`PT_INTERP` rule. The latter remains mandatory for later `bootstrap.elf`,
`init0`, and `hello` inspection.

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
`llvm-readobj` is required for the UEFI PE/COFF inspection path.

`templates/build-provenance.toml` defines the minimum provenance fields for a
future generated build record. Generated records belong with build artifacts,
not as edits to this source template. Hash the effective build configuration
and each accepted artifact, and preserve full-symbol host artifacts separately
from any image copy that may later be stripped.

For native guest artifacts, provenance must identify the compiler-rt objects
actually linked and the LLVM inspection result proving both an absent
`PT_INTERP` and no guest libc dependency. Host-tool libc dependencies are
recorded separately and are not guest-runtime failures.
