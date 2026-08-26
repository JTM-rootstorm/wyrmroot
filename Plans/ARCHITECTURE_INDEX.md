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

- [`Plans/WYR1_BOOTSTRAP_SUPERVISOR_CONTRACT.md`](WYR1_BOOTSTRAP_SUPERVISOR_CONTRACT.md) defines the reached WYR1-A permanent `/system/init` handoff, immutable bootfs/RRC-A manifest, fixed bootstrap graph, generation-exact READY/restart/reap behavior, capability distribution, and finite degraded-recovery transition. Read it before implementing or changing WYR1 supervision and recovery-residency behavior.
- [`Plans/WYR1_A_VALIDATION.md`](WYR1_A_VALIDATION.md) records the accepted WYR1-A product tuple, artifact identities, host gates, paired default/SMP live boot matrix, remediation, and explicit VM-hardware/nonclaim boundary.
- [`Plans/WYR1_B_REGISTRY_LAUNCH_CONTRACT.md`](WYR1_B_REGISTRY_LAUNCH_CONTRACT.md) defines the bounded separate bootstrap registry, controller-installed publication/client authority, direct endpoint routing, startup ABI v2 and WRLP 1.3 profiles, supervisor-owned scoped launch/job protocol, orphan/reap policy, immutable launch policy, and WYR1-B host/live gates.
- [`Plans/WYR0_BOOTFS_FORMAT_CONTRACT.md`](WYR0_BOOTFS_FORMAT_CONTRACT.md) defines the canonical
  deterministic archive subset implemented by WYR0-C. Read it before changing bootfs builder,
  parser, lookup, content-manifest, or archive-intake behavior.
- [`Plans/WYR0_D0_PRIMORDIAL_STARTUP_CONTRACT.md`](WYR0_D0_PRIMORDIAL_STARTUP_CONTRACT.md) defines the paired native startup stack/register, bootstrap Channel wire/role, capability-validation, bootfs mapping/lifetime, and READY/exit contract. Read it before WYR0-D implementation.
- [`Plans/WYR0_E0_USERSPACE_PROCESS_LOADING_CONTRACT.md`](WYR0_E0_USERSPACE_PROCESS_LOADING_CONTRACT.md) defines the paired static ELF subset, userspace child-construction transaction, capability delegation, rollback, readiness, and exit-observation contract. Read it before WYR0-E/F/G implementation.
- [`Plans/WYR0_I_NATIVE_CAPABILITY_CONTRACT.md`](WYR0_I_NATIVE_CAPABILITY_CONTRACT.md) defines the generic WYR0-I native capability, bounded supervision/restart, readiness accounting/enforcement classification, peer/generation, and evidence contract. Read it before WYR0-I B/C/D/E/F implementation or any later consumer relies on the DW0-H/WYR0-I capability certificate.
- [`Plans/WYR0_I_VALIDATION.md`](WYR0_I_VALIDATION.md),
  [`Plans/WYR0_COMPLETION_REPORT.md`](WYR0_COMPLETION_REPORT.md), and
  [`security/WYR0_SECURITY_REVIEW.md`](../security/WYR0_SECURITY_REVIEW.md)
  are the accepted WYR0-I validation, WYR0 completion, and exact-candidate
  security records. Later consumers require their exact certified tuple and
  evidence; the generic contract alone is not an acceptance certificate.

## Forward subsystem architecture

- [`Plans/WYRMROOT_STORAGE_FILESYSTEM_DIRECTION.md`](WYRMROOT_STORAGE_FILESYSTEM_DIRECTION.md) pins the reached storage/filesystem roles: FAT32 for guest-side EFI System Partition management, ext4 as the initial persistent root required for full userspace onlining, and a later XFS-led/ext4-tempered/NTFS-informed native-filesystem track. Read it before post-WYR0 block/VFS/filesystem/root work or native-filesystem planning.

## Authority rules

- Deepwyrm owns kernel ABI, `DwBootInfo`, syscall/object/right/status definitions, and kernel-facing feature contracts.
- Wyrmroot owns platform conventions, EFI loader behavior, bootfs contents, native service protocols, userspace process-loading policy, system-service policy, and compatibility personalities.
- `WYRMROOT_PLATFORM_CONVENTIONS.md` applies to later milestones unless an explicit architecture revision changes it. Its current locked direction includes FIDL as WyrmIDL's principal prior-art lineage, a post-WYR0 kernel-matched native vDSO consumption boundary, the rule that personality adapters route resulting native operations either directly to Deepwyrm, through typed WyrmIDL services, or keep them personality-local rather than creating a universal foreign-syscall IPC bus, and the post-WYR0 bootstrap spine of small permanent supervisor -> separate discovery -> device/storage drivers -> VFS/filesystem -> ext4 persistent root -> ordinary services while preserving separate fault/policy domains. FAT32 is the early guest-side ESP/boot-management filesystem, not the root filesystem.
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
