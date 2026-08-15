# WYR0 toolchain and provenance bootstrap

This directory records the immutable source revisions and canonical tool
families selected for WYR0. It is bootstrap metadata only: it does not build a
toolchain, add a Rust target, or make the planned Deepwyrm ABI crate available.

## Version authority

`versions.toml` is the machine-readable WYR0 pin. Builds and artifact manifests
must identify the exact Deepwyrm and Wyrmroot Rust revisions from that file;
branch names are not reproducibility inputs.

The pinned Deepwyrm revision is a planning baseline. Until that revision (or a
coordinated successor) actually publishes the canonical `deepwyrm-abi` crate,
Wyrmroot must not add a placeholder Git dependency, copy ABI definitions, or
claim that ABI consumption passes.

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
artifact. When `xtask` gains its real build implementation, it must consume
this policy centrally and record the effective configuration hash in build
provenance.

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

`templates/build-provenance.toml` defines the minimum provenance fields for a
future generated build record. Generated records belong with build artifacts,
not as edits to this source template. Hash the effective build configuration
and each accepted artifact, and preserve full-symbol host artifacts separately
from any image copy that may later be stripped.

For native guest artifacts, provenance must identify the compiler-rt objects
actually linked and the LLVM inspection result proving both an absent
`PT_INTERP` and no guest libc dependency. Host-tool libc dependencies are
recorded separately and are not guest-runtime failures.
