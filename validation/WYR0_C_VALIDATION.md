# WYR0-C validation record

This document records changing WYR0-C implementation and validation evidence. It is not a
substitute for the repository README and makes no runtime, image, or VM acceptance claim.

## Deterministic bootfs checkpoint

- Wyrmroot base: `83b9f831a17003f1d712bd08f4af82447242ded9`
- Bootfs implementation commit: `b21df563d18c5a8bdf7dd2a98646a65ff741eecf`
- Central tooling commit: `cdd33aa3d629d01b65f511ceee79cb3db0f4c65e`
- Pinned Deepwyrm revision: `07140ca7da26fad7173b80ed1cdf26c98b50aaab`

The bootfs crate does not consume the Deepwyrm ABI. The existing repository pin was intentionally
left unchanged while DW0-C continues independently; this checkpoint neither copies ABI constants
nor claims acceptance against an unpinned Deepwyrm descendant.

The checkpoint implements:

- the stable WYR0 `cpio newc` subset recorded in
  `Plans/WYR0_BOOTFS_FORMAT_CONTRACT.md`;
- an allocation-free `no_std` parser over one exact borrowed archive slice;
- canonical byte-path validation and zero-copy lookup with explicit UTF-8 conversion;
- a feature-gated host builder with deterministic order and metadata, checked size arithmetic,
  fallible allocation, exact trailer handling, and parser round trips;
- one shared 32 MiB archive, 4096-record, and 4096-byte encoded-name policy;
- a source-neutral content rule naming `bin/hello` and `system/init0` while rejecting missing,
  duplicate, extra, or empty real artifact inputs;
- central `cargo xtask build bootfs` and `cargo xtask test host bootfs` commands, plus builder
  coverage in unfiltered build and host-test orchestration.

No placeholder `init0` or `hello` bytes, bootfs image, ESP, image assembly, runtime parser wiring,
QEMU profile, or guest behavior was added.

## Validation evidence

Evidence collected on the committed source tree:

- `cargo test --locked -p wyrmroot-bootfs --features builder`: 30 passed, 0 failed;
- `cargo clippy --locked -p wyrmroot-bootfs --all-targets --features builder -- -D warnings`:
  passed;
- `cargo check --locked -p wyrmroot-bootfs --no-default-features --lib`: passed;
- `RUSTDOCFLAGS='-D warnings' cargo doc --locked -p wyrmroot-bootfs --features builder --no-deps`:
  passed;
- default and builder-feature normal dependency trees contain only `wyrmroot-bootfs`;
- `cargo test --locked -p xtask`: 31 passed, 0 failed, 1 accepted environment-gated ignored;
- `cargo clippy --locked -p xtask --all-targets -- -D warnings`: passed;
- `cargo xtask build bootfs`: passed;
- `cargo xtask test host bootfs`: 30 passed, 0 failed;
- unfiltered `cargo xtask test host`: 166 passed, 0 failed, 1 accepted environment-gated ignored;
- workspace formatting, rustdoc, and repository diff hygiene: passed.

Dependency resolution used a command-scoped Git URL rewrite from the canonical Deepwyrm URL to the
local checkout at the exact pinned revision. No rewrite, absolute local path, path dependency, or
generated host path was persisted in the repository.

## Gate disposition

The WYR0-C deterministic builder/parser, hostile-input host validation, no-std boundary, and central
tooling gates are complete for the named Wyrmroot commits. WYR0-C requires no VM run, and none is
claimed.

The following remain intentionally deferred:

- read-only `MemoryObject` authority and exact module-length enforcement at the WYR0-F runtime
  boundary;
- real `init0` and `hello` artifacts and primordial-process integration;
- canonical bootfs artifact creation, image/ESP assembly, and QEMU/OVMF evidence in their assigned
  later phases;
- coverage-guided fuzzing as release-candidate hardening beyond the deterministic mutation and
  minimized regression suite used here.
