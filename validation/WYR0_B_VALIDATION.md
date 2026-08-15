# WYR0-B validation record

This document records changing WYR0-B implementation and validation evidence. It is not a
substitute for the repository README and does not claim that the WYR0-B phase gate has closed.

## Loader implementation checkpoint

- Wyrmroot base: `a35246850eb5c35e9a950cd148b2f9678a2dca1a`
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

Focused evidence collected before the checkpoint commit:

- loader parser/component tests: 73 passed, 0 failed;
- loader strict host Clippy with warnings denied: passed;
- accepted `x86_64-unknown-uefi` target check: passed;
- xtask unit tests: 29 passed, 0 failed, with the explicit real-artifact acceptance test ignored in
  the ordinary hermetic suite;
- real immutable-toolchain trust test: passed before final integration, including whole-tree,
  internal runtime-library, interpreter/dependency, and pre/post identity verification;
- xtask strict Clippy with warnings denied: passed;
- workspace formatting and diff hygiene: passed.

## Gate disposition

WYR0-B implementation and host security gates are complete. The exact accepted loader build, PE
inspection, and path-neutral artifact provenance gate must still be rerun from the clean committed
tree before a VM request is eligible.

No VM request or QEMU/OVMF acceptance claim exists for this checkpoint. The manager-owned VM gate
must wait for a committed boot-ready loader and exact paired artifacts with hashes.
