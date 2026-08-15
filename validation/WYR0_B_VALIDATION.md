# WYR0-B validation record

This document records changing WYR0-B implementation and validation evidence. It is not a
substitute for the repository README and does not claim that the WYR0-B phase gate has closed.

## Component-groundwork checkpoint

- Wyrmroot base: `77e112ee96dc016ec037bf60b10910f57ab14e9d`
- Pinned Deepwyrm revision: `652b14b09c0d060cc04a5a335a60eb15856d30ad`
- Accepted Rust source revision: `8bab26f4f68e0e26f0bb7960be334d5b520ea452`
- Accepted toolchain manifest SHA-256:
  `553cbfe6eb5cd9976c4f078a3731269f2a2ecd4f3ff5d574ab3813bae8fcf1f1`

Deepwyrm publication rewrote commit identities only to add GPG signatures. The signed source commit
`ac11fd769c4111d9525a0ae6a934c40099b94f99` has the same tree as the validated unsigned source
revision, and the pinned `652b14b09c0d060cc04a5a335a60eb15856d30ad` descendant adds validation
records only. The source, layout, and artifact evidence below is therefore unchanged.

The checkpoint contains host-tested WYR0-B components and keeps the firmware entry fail-closed
before `ExitBootServices`. It includes:

- deterministic artifact paths and bounded configuration/file admission;
- hostile-input Deepwyrm ELF validation with exact generated link-base policy;
- generated-ABI BootInfo, module, and bounded memory-map construction;
- exact transition preflight sizing, four-level page-table encoding, and raw x86_64 handoff;
- retained-page zeroing, bounded RSDP-only ACPI handling, entropy provenance, and allocation
  ownership scaffolding;
- explicit bounded COM1 initialization for post-firmware diagnostics;
- exact Deepwyrm layout discovery/generation and accepted-toolchain manifest verification;
- path-neutral loader artifact provenance.

Focused evidence collected before the checkpoint commit:

- loader parser/component tests: 61 passed, 0 failed;
- loader strict host Clippy with warnings denied: passed;
- accepted `x86_64-unknown-uefi` target check: passed;
- xtask unit tests: 22 passed, 0 failed;
- xtask strict Clippy with warnings denied: passed;
- workspace formatting and diff hygiene: passed.

## Gate disposition

WYR0-B remains open. The checked-in entry deliberately releases retained pages and returns
`ABORTED` before `ExitBootServices`; it is not a boot-ready loader.

The remaining implementation blockers are:

1. finish the trusted-tool/layout positive gate, including single-buffer binding of the exact
   committed Deepwyrm layout bytes to generated policy and provenance;
2. wire one ownership-complete pre-EBS allocation transaction through final memory-map
   normalization, canonical BootInfo construction, transition-table population, bounded COM1
   marker emission, and the nonreturning kernel jump.

No VM request or QEMU/OVMF acceptance claim exists for this checkpoint. The manager-owned VM gate
must wait for a committed boot-ready loader and exact paired artifacts with hashes.
