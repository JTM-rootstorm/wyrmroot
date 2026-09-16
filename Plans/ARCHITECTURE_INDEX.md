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
- [`Plans/WYR1_B_VALIDATION.md`](WYR1_B_VALIDATION.md) records the accepted WYR1-B product tuple, capacity remediation, frozen identities, host/product gates, selector-27 live result, exact-current selector-25 default/SMP regression matrix, and nonclaims.
- [`Plans/WYR1_C_DEVICE_COORDINATOR_CONTRACT.md`](WYR1_C_DEVICE_COORDINATOR_CONTRACT.md) defines the reached hardware-independent device-coordinator boundary: exact static q35 COM2 policy, allocation-free manifest and state model, distinct generation identities, READY-before-publication, direct driver-control framing, cleanup-before-replacement, and the truthful pre-DW1-D waiting state. Read it before changing real `devmgr`, device-role product policy, driver matching/lifecycle, or later device-resource delegation.
- [`Plans/WYR1_C1_VALIDATION.md`](WYR1_C1_VALIDATION.md) records the reached WYR1-C1 real-devmgr host/native product tuple, accepted Rust-fork toolchain, inspected artifact and manifest identities, recovery/product gates, and the explicit no-selector/no-live-acceptance boundary.
- [`Plans/WYR1_C2_VALIDATION.md`](WYR1_C2_VALIDATION.md) records the reached WYR1-C2 deterministic unselected product tuple, reviewed source-to-WRDM compilation, production loader/kernel/bootstrap and ESP identities, retained publication-hardening gate, and the explicit no-selector/no-VM/no-live-acceptance boundary.
- [`Plans/WYR1_C3_VALIDATION.md`](WYR1_C3_VALIDATION.md) records the reached WYR1-C3 hardware-free supervisor construction seam, direct per-attempt driver-control Channel, bounded construction/readiness handshake, exact actor/profile correlation, process reap and replacement behavior, accepted native-toolchain builds, and the explicit DW1-D block before hardware authority.
- [`Plans/WYR1_C_DEVICE_HANDOFF_CONTRACT.md`](WYR1_C_DEVICE_HANDOFF_CONTRACT.md) defines the paired DW1-D0/WYR1-C resource-domain startup custody, exact q35 COM2 grant correlation, reduced devmgr claim authority, fixed two-handle resource bundle, generation identity, MOVE ownership, and cleanup-before-replacement seam. Read it before implementing WYR1-C4 resource claim, driver delegation, or post-resource readiness.
- [`Plans/WYR1_C_VALIDATION.md`](WYR1_C_VALIDATION.md) records the accepted WYR1-C selector-29 product tuple, exact two-handle COM2 delegation, U1/P1 to U2/P2 driver restart, D1-to-D2 custody recovery, stale and malformed live negatives, non-escaping authority/no-I/O evidence, default/SMP acceptance, selector-25/27/28 regressions, and explicit physical-I/O boundary.
- [`Plans/WYR1_D_SERIAL_STREAM_CONSOLE_CONTRACT.md`](WYR1_D_SERIAL_STREAM_CONSOLE_CONTRACT.md) freezes WYR1-D's WRST v1 byte grammar, connector 1.1 and staged production UART handoff, fixed pressure bounds, q35 UART baseline, CR/LF translation, generation replacement/restart policy, selector-32 identity, structured WRD1 joins, and D0 host-model gate while preserving selector-29/WRDC-1.0 behavior.
- [`Plans/WYR1_D1_IMPLEMENTATION_STATUS.md`](WYR1_D1_IMPLEMENTATION_STATUS.md) records the reached WYR1-D1 production WRST codec, bounded native stream wrappers, JobV2 role validation, and native-stdout hello seam.
- [`Plans/WYR1_D2_IMPLEMENTATION_STATUS.md`](WYR1_D2_IMPLEMENTATION_STATUS.md) records the reached WYR1-D2 no-std, fake-register 16550 core: silent staged initialization, bounded interrupt draining, fixed rings, diagnostics, and the released D3 adapter seam without live I/O claims.
- [`Plans/WYR1_D3A_D3C_IMPLEMENTATION_STATUS.md`](WYR1_D3A_D3C_IMPLEMENTATION_STATUS.md) records the reached D3A split DeviceResource/quiescence gate and D3C minor-1 direct-connector host/model gate, including separate WRDC 1.1/WRSC codecs, explicit endpoint-MOVE ownership, one-client reconnect, and preservation of selector-29 WRDC 1.0.
- [`Plans/WYR1_D3B_D3D_IMPLEMENTATION_STATUS.md`](WYR1_D3B_D3D_IMPLEMENTATION_STATUS.md) records the reached D3B exact post-quiescence Interrupt activation and D3D bounded UART/WRST loop, including resident-owned correlation reservation, drain-before-ack PIO health, commit-after-send RX ownership, stream isolation/reconnect, and explicit product/live nonclaims.
- [`Plans/WYR1_D4_IMPLEMENTATION_STATUS.md`](WYR1_D4_IMPLEMENTATION_STATUS.md) records the reached production `consoled` startup profile, generation-exact serial/child supervision model, bounded and fair native WRST/JobV2 brokerage, cleanup-before-replacement joins, accepted native-target build, and explicit selector-32/live nonclaims.
- [`Plans/WYR1_D5_IMPLEMENTATION_STATUS.md`](WYR1_D5_IMPLEMENTATION_STATUS.md) preserves the historical D5 selector-32 UP/SMP checkpoint, replacement joins, GDB-guided broad regression repairs and exact A5 evidence.
- [`Plans/WYR1_D_VALIDATION.md`](WYR1_D_VALIDATION.md) records accepted WYR1-D6 and WYR1-D closure: exact selector31/32 UP/SMP products, selector30/29/28/27 regressions, independently recomputed certificates and actual COM2 sends, scoped review, cleanup and the released WYR1-E seam. It does not claim shell, physical-hardware, final security or DW1-wide closure.

## Active implementation status

- [`Plans/WYR1_E4AB_VALIDATION.md`](WYR1_E4AB_VALIDATION.md) records the separate production wyrmsh startup/READY/release/editor runtime, local help/echo/clear/exit, shared startup-version accessor, stateful WRST harness, partial-output correction and accepted native compilation at the E4A/B checkpoint.
- [`Plans/WYR1_E4C_VALIDATION.md`](WYR1_E4C_VALIDATION.md) closes E4 with scoped services/tasks/status, canonical LIST_JOBS encoding, finite inspection deadlines and their reviewed correction, 73 shell/core plus 250 protocol/server tests, and accepted native compilation.
- [`Plans/WYR1_E5_VALIDATION.md`](WYR1_E5_VALIDATION.md) closes E5A/B/C with the shared ShellJobs adapter, foreground stream bridge, spawn/wait/terminate, controller eviction/orphan regressions, reviewed custody/fairness/deadline corrections, 98 shell/core tests, 445 broader regressions and accepted native compilation. Reached E6 product/stack integration is recorded below; guest acceptance remains later.
- [`Plans/WYR1_E_VALIDATION.md`](WYR1_E_VALIDATION.md) accepts WYR1-E and releases `F0A.1`: five E8 UP/SMP pairs at 33/69 records and `DWTEST1 33 0`, the six E8D.4 regression rows, independently recomputed evidence, frozen E6 ancestry, and five resolved defects — three of them one class, code no routinely-run gate compiled, now closed by aggregate selector gates in both repositories. It does not claim physical hardware, a flake rate, final security review, or a selector34 run.
- [`Plans/WYR1_E6_PRODUCT_INTEGRATION_CONTRACT.md`](WYR1_E6_PRODUCT_INTEGRATION_CONTRACT.md) freezes production CONNECT lifetime, exact publication readiness, and driver/registry recovery joins without new IPC wire values.
- [`Plans/WYR1_E6_VALIDATION.md`](WYR1_E6_VALIDATION.md) closes E6A/B with two identical normal native bootfs freezes, standalone inspection, exact selected-shell stack proof, all ten native variants, scoped review, and historical selector32 isolation. Selector33 media and guest acceptance remain E7.

- [`Plans/WYR1_E3AB_LAUNCH_VALIDATION.md`](WYR1_E3AB_LAUNCH_VALIDATION.md) records additive ShellV1 wire/session scopes and the six-role Wyrmsh loader boundary at the E3A/B checkpoint.
- [`Plans/WYR1_E3CD_VALIDATION.md`](WYR1_E3CD_VALIDATION.md) records transactional shell construction, bounded registry preflight, WRCN/consoled status, fresh replacement identities, scoped review and host/native checks; production resident-loop selection remains E6 and guest acceptance remains E7/E8.
- [`Plans/WYR1_E2_EDITOR_CONTRACT.md`](WYR1_E2_EDITOR_CONTRACT.md) fixes incremental input resynchronization, printable-scalar policy, editor/history submission state and bounded viewport redraw.
- [`Plans/WYR1_E2_EDITOR_VALIDATION.md`](WYR1_E2_EDITOR_VALIDATION.md) records E2A/E2B host tests, scoped review, source provenance and measured fixed-state/stack-frame evidence; native integration remains later work.
- [`Plans/WYR1_E1_PARSER_VALIDATION.md`](WYR1_E1_PARSER_VALIDATION.md) records the E1A/E1B pure parser and typed command model, exact grammar/path/arity decisions, bounded property corpus and validation limits. Runtime/product integration remains later work.
- [`Plans/WYR1_E_WYRMSH_CONTRACT.md`](WYR1_E_WYRMSH_CONTRACT.md) defines the frozen E0B shell scopes, ShellV1 WRLJ 1.1, six-role WRLP 1.11, WRCN status protocol, transactional registry/session ownership, immutable product reservations and parser/editor/job semantics. Reached codec/scope/loader and controller/status implementation is recorded in the E3A/B and E3C/D validations; E4A/B startup/local runtime is recorded separately; inspection/job adapters and selected-product work remain later cards.
- [`Plans/WYR1_E0_TRANSITION_INVENTORY.md`](WYR1_E0_TRANSITION_INVENTORY.md) records E0A's source-bound transition inventory, measured toolchain/revision preflight, required-source dispositions, current gaps and the accepted E0B host-model validation and scoped review receipt.

- [`Plans/WYR1_C4_IMPLEMENTATION_STATUS.md`](WYR1_C4_IMPLEMENTATION_STATUS.md) records completed WYR1-C4 production/native intake: exact WRBP V3 and WRLP 1.7/1.9 custody, devmgr-generation resource-domain parenting, generated ABI feature and COM2 claim validation, restart ownership, accepted-product-compiler checks, and explicit C5/C6 nonclaims.
- [`Plans/WYR1_C5_IMPLEMENTATION_STATUS.md`](WYR1_C5_IMPLEMENTATION_STATUS.md) records completed WYR1-C5 direct resource delegation: exact reduced DeviceResource plus fresh Interrupt MOVE, typed actor validation, generation-bound DRIVER_READY before registry publication, explicit retire/cleanup behavior, accepted-product-compiler checks, and the selector-29/live-I/O/restart boundary retained for C6.
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
- Any new payload-bearing error variant, exit-code encoder, or evidence field is subject to the workspace [`../../DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md`](../../DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md): a status may collapse causes whose recovery action is identical, a collapse owes the instance to the reader's channel in the same change, and a `match` converting an error type into an exit code or status must be exhaustive over it.

## Phase-0 freeze policy

The pre-phase-0 architecture is now considered sufficiently locked to begin implementation.

Do not add speculative architecture documents merely because a distant subsystem will eventually exist. Create or revise architecture only when:

1. a concrete implementation blocker exposes a missing contract;
2. security review demonstrates an existing convention is unsafe;
3. a later milestone reaches a subsystem that was intentionally deferred; or
4. implementation evidence shows a pinned ABI-0 choice should be revised before stabilization.

This policy is intended to keep Wyrmroot from designing version 7 before version 0 can boot.
