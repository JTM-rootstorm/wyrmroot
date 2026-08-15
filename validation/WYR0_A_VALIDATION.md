# WYR0-A Validation Record

**Date:** 2026-08-15
**Scope:** WYR0-A workspace, reproducible tooling, and Deepwyrm ABI consumption
**Wyrmroot implementation revision:** `9c7beee2174e49c70a2738a82147a832284ab646`
**Deepwyrm ABI revision:** `37338e8d44c08ef039eb34a01292a6b6cb5cac3a`
**Deepwyrm schema parent:** `8f6425fbcecb82a39fc2266544464b0d7ac192de`
**Rust upstream/fork revision:** `8bab26f4f68e0e26f0bb7960be334d5b520ea452` (`1.97.1`)

## Disposition

WYR0-A passes for the exact local Deepwyrm/Wyrmroot revision pair above. The generated
`deepwyrm-abi` crate is consumed through the canonical GitHub repository URL and exact revision,
and Cargo resolves that same source and commit in `Cargo.lock`.

The Deepwyrm commit is intentionally unpushed under the current publication boundary. Local
validation used a command-scoped Git URL rewrite to the clean sibling Deepwyrm repository. No
rewrite, local path, or path dependency is persisted in Wyrmroot. A fresh environment cannot
fetch the dependency from GitHub until the separately authorized Deepwyrm push occurs.

This record closes only WYR0-A. It is not evidence for a bootable loader, native guest artifact,
image, VM run, or any WYR0-B-and-later gate.

## Implemented gate surface

- The workspace has a stable `cargo xtask build` and focused `cargo xtask test host [filter]`
  interface.
- Build readiness fails closed unless version metadata, the canonical exact Git dependency,
  lockfile resolution, a real consumer, provenance metadata, host tool availability, and reserved
  native-target policy agree.
- `wyrmroot-efi-loader` directly consumes and re-exports the generated `DW_ABI_VERSION`,
  `DwBootInfoV1`, and its generated size constant. Its host test checks the generated Rust layout
  rather than maintaining a parallel definition.
- Host, x86_64 UEFI, and future native-guest profiles are separated in machine-readable policy.
  The native `x86_64-unknown-wyrmroot` target remains explicitly reserved and is not emulated by a
  target JSON, host fallback, or `cfg(unix)`.
- Runtime, bootstrap protocol, bootfs, userspace loader, bootstrap, `init0`, and `hello` remain
  `no_std` phase boundaries. Later-phase behavior was not pulled into WYR0-A.
- Image, run, inspect-image, GDB, guest-test, and integration-test commands remain explicit
  unavailable failures for this phase.

## Validation evidence

The following completed successfully against the exact revisions above:

```text
cargo fmt --all -- --check
cargo xtask build
cargo xtask test host
cargo clippy --locked --workspace --all-targets -- -D warnings
RUSTDOCFLAGS=-Dwarnings cargo doc --locked --workspace --no-deps
cargo tree --locked -p wyrmroot-efi-loader -e normal
```

Observed results:

- The host build compiled `deepwyrm-abi` at `37338e8...` and every Wyrmroot workspace target.
- Host tests passed, including two loader profile/ABI-consumption tests and seven `xtask` tests.
- The loader's only normal dependency is the exact generated `deepwyrm-abi` crate.
- Clippy and rustdoc completed with warnings denied.
- `cargo xtask image` returned exit code `1` with the WYR0-A unavailable diagnostic.
- An option-like host-test filter returned usage exit code `2`.

The host availability probe observed Rust `1.96.1`, Clang/LLD `22.1.8`, the required x86_64
compiler-rt builtins, LLVM object utilities, and GDB `17.2`. These are observed host inputs, not a
claim that the reserved Wyrmroot native target has been built or registered.

## Security and reproducibility review

An intermediate manual review covered WYR0-A's dependency, generated-boundary, and reproducibility
surface. The full WYR0 release-candidate security review remains mandatory later.

- Tracked source, manifests, lockfile, profile policy, provenance template, and generated-output
  inputs contain no host-local absolute workspace path or `file://` dependency.
- Source scans found no hand-maintained `Dw*` type or `DW_STATUS`/rights/object/syscall definition in
  Wyrmroot.
- The dependency tree contains no libc, POSIX compatibility layer, or unrelated transitive crate.
- Native scaffold crates deny or forbid unsafe code. Host-only `xtask` uses `cfg(unix)` solely for
  its symlink-regression test; reserved-target validation excludes host tooling and rejects such a
  setting in guest/configuration lanes.
- Recursive policy and manifest scans reject symlinks rather than following them outside the
  repository.
- No Critical, High, or Medium WYR0-A security finding remains open.

## Deferred work and blockers

- The Wyrmroot Rust fork is pinned but its native target remains unimplemented and unregistered.
  No WYR0-A host-build claim treats that future guest target as available.
- WYR0-B must coordinate an explicit raw kernel-entry machine-state contract covering initial
  stack validity/alignment/ownership, return behavior, direction and interrupt state, and the
  assembly-shim versus direct SysV boundary. WYR0-A deliberately defines none of these.
- UEFI firmware behavior, artifact loading, `ExitBootServices`, BootInfo population, image
  construction, QEMU/VM execution, and guest linkage inspection remain later phase gates.
