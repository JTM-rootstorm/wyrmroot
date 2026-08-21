# Wyrmroot Architecture and Plan Index

**Status:** Canonical source-of-truth index  
**Repository:** `JTM-rootstorm/wyrmroot`

This file defines the minimum architecture reading set for Wyrmroot implementation work. Codex coordinators and human contributors should read the applicable documents before changing kernel/userspace contracts.

## Mandatory pre-WYR0 reading order

1. [`README.md`](../README.md) - project identity and broad system goals.
2. [`Plans/WYRMROOT_PLATFORM_CONVENTIONS.md`](WYRMROOT_PLATFORM_CONVENTIONS.md) - system-wide conventions and pre-phase-0 locks.
3. [`Plans/WYR0_IMPLEMENTATION_PLAN.md`](WYR0_IMPLEMENTATION_PLAN.md) - WYR0 milestone scope, phases, and shared DW0 contract.
4. [`Plans/WYR0_IMPLEMENTATION_PLAN_IMAGE_DELIVERY_ADDENDUM.md`](WYR0_IMPLEMENTATION_PLAN_IMAGE_DELIVERY_ADDENDUM.md) - VM sizing, disk-image-only delivery, bootfs/ESP workflow.
5. [`Plans/WYR0_IMPLEMENTATION_PLAN_LIBC_POLICY_ADDENDUM.md`](WYR0_IMPLEMENTATION_PLAN_LIBC_POLICY_ADDENDUM.md) - native libc independence and optional POSIX/libc boundary.
6. [`Plans/WYR0_IMPLEMENTATION_PLAN_TOOLCHAIN_ADDENDUM.md`](WYR0_IMPLEMENTATION_PLAN_TOOLCHAIN_ADDENDUM.md) - LLVM/Clang/LLD/compiler-rt policy and host GDB workflow.
7. [`Plans/WYR0_IMPLEMENTATION_PLAN_NATIVE_CONTROL_SURFACES_ADDENDUM.md`](WYR0_IMPLEMENTATION_PLAN_NATIVE_CONTROL_SURFACES_ADDENDUM.md) - native control-plane direction versus Linux pseudo-filesystems/utilities.
8. Deepwyrm's corresponding `Plans/DEEPWYRM_PRE_PHASE0_INVARIANTS.md`, DW0 plan, and addenda for any cross-repository ABI/handoff work.
9. When work touches compatibility personalities, personality hosting, or uses Linux/Windows/DOS/POSIX requirements to justify a native service or kernel change, the OS-Project coordination doctrine `../personality-plan/CROSS_PERSONALITY_KERNEL_MECHANISM_DOCTRINE.md` and the affected family plan are mandatory reading.

## Reached subsystem contracts

- [`Plans/WYR0_BOOTFS_FORMAT_CONTRACT.md`](WYR0_BOOTFS_FORMAT_CONTRACT.md) defines the canonical
  deterministic archive subset implemented by WYR0-C. Read it before changing bootfs builder,
  parser, lookup, content-manifest, or archive-intake behavior.

## Authority rules

- Deepwyrm owns kernel ABI, `DwBootInfo`, syscall/object/right/status definitions, and kernel-facing feature contracts.
- Wyrmroot owns platform conventions, EFI loader behavior, bootfs contents, native service protocols, userspace process-loading policy, system-service policy, and compatibility personalities.
- `WYRMROOT_PLATFORM_CONVENTIONS.md` applies to later milestones unless an explicit architecture revision changes it.
- A milestone plan may add stricter requirements but may not silently weaken a platform convention.
- If implementation reveals a conflict, stop local invention and route the change through the coordinator/architecture documents.
- For compatibility-motivated native growth, the cross-personality doctrine is a hard admission overlay: an older statement that compatibility may influence or generalize a native abstraction cannot authorize personality-aware Wyrmroot policy or a broader Deepwyrm primitive. Prefer personality adapters and shared restartable userspace helpers; any kernel change must independently satisfy the stricter privileged-mechanism admission test.

## Phase-0 freeze policy

The pre-phase-0 architecture is now considered sufficiently locked to begin implementation.

Do not add speculative architecture documents merely because a distant subsystem will eventually exist. Create or revise architecture only when:

1. a concrete implementation blocker exposes a missing contract;
2. security review demonstrates an existing convention is unsafe;
3. a later milestone reaches a subsystem that was intentionally deferred; or
4. implementation evidence shows a pinned ABI-0 choice should be revised before stabilization.

This policy is intended to keep Wyrmroot from designing version 7 before version 0 can boot.
