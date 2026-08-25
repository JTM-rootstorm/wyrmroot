# WYR0 Completion Report

**Status:** WYR0 complete — phases A through I accepted  
**Date:** 2026-08-25  
**Milestone:** WYR0 — UEFI loader, primordial userspace, and native process bootstrap

## Accepted closure

WYR0 is complete on the product tuple:

- Deepwyrm `5a8bb0a75979bb3ecde9bd7209619e924ec5e36d`;
- Wyrmroot `ec84cc6441db15de83d55329ac442a01988c52e9`;
- Rust `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`; and
- generated Deepwyrm ABI pin
  `cfc69bd8a49819ce1cda1a132cf56e55c93f92e4`, identity
  `1c6a74f130e386eee95b3780c75950beefd0037d`.

The authoritative final validation is `Plans/WYR0_I_VALIDATION.md`; the final
exact-candidate security disposition is `security/WYR0_SECURITY_REVIEW.md`.
The coordination root certificate binds this product tuple to the exact
toolchain, media, capability certificate, evidence, and paired Deepwyrm record.

## A-I milestone summary

| Phase | Accepted result |
| --- | --- |
| WYR0-A | reproducible Rust-first workspace, pinned Deepwyrm ABI consumer, and accepted Wyrmroot target/toolchain path |
| WYR0-B | 64-bit UEFI loader, checked kernel/bootstrap/bootfs loading, `DwBootInfoV1`, and `ExitBootServices` handoff |
| WYR0-C | deterministic bounded bootfs builder/parser with fail-closed hostile-input handling |
| WYR0-D | native startup/runtime and capability-validated primordial bootstrap protocol |
| WYR0-E | transactional static userspace ELF loading, rights reduction, W^X, rollback, and process/thread publication |
| WYR0-F | real primordial bootstrap receives bootfs and launches ordinary Wyrmroot userspace |
| WYR0-G | temporary `init0` launches separate `hello`, observes READY/exit, and closes the real userspace chain |
| WYR0-H | deterministic ESP construction, q35/OVMF request-bound integration, structured results, artifact inspection, and exact-symbol diagnostics |
| WYR0-I | clean-build hardening, reusable bounded supervision/accounting, native capability probe/certificate, final ordinary matrix, and Daybreak security closure |

The accepted real path is:

```text
UEFI -> Wyrmroot loader -> Deepwyrm -> primordial bootstrap
     -> bootfs + userspace ELF loader -> init0 -> hello -> EXITED/0
```

The final closure additionally proves a reusable generic native substrate for
process/thread lifecycle, MemoryObject mapping/sharing/lifetime, Channels and
handle transfer/backpressure/peer close, waits/Events/Timers, cancellation,
bounded restart/exhaustion, deterministic configuration/asset delivery,
controller-owned overload/replay rejection, and cleanup to baseline.

## Security and accepted limits

The final WYR0-I product review is PASS at C0/H0/M0/L0. All confirmed Wave 5
findings were remediated, revalidated, and rereviewed. The accepted q35/OVMF
evidence is not physical-hardware acceptance.

The resource claim remains deliberately narrow. Deepwyrm enforces existing
native object and Channel bounds. Wyrmroot enforces admission only where its
controller owns and withholds authority. Generic hostile-process TaskGroup
quotas for directly minted objects, mappings, waits, handles, CPU, I/O, or
device resources do not exist yet and must not be inferred from the readiness
ledger.

WYR0 completion does not claim WYR0-GW, Glasswyrm or Prismdrake readiness,
graphics/input, a final service manager, persistent VFS/root, package
management, networking, libc/POSIX, dynamic linking, or the post-WYR0 vDSO.
The current `init0` remains temporary proof machinery.

## WYR1 prerequisites and dependency order

The next implementation plan must preserve this post-WYR0 dependency spine
unless demonstrated evidence justifies an explicit architecture revision:

1. Replace temporary `init0` with a small bootfs-resident permanent
   init/supervisor, while keeping minimum bootstrap discovery separate from
   general registry, dependency-control, and activation policy.
2. Bring up the device coordinator and essential userspace driver servers,
   including the block-storage path required to expose the ESP and selected
   persistent-root device.
3. Bring up VFS/filesystem services. FAT32 provides guest-side ESP boot
   management where required; it is not the root filesystem. Discover and mount
   ext4 as the initial persistent root before ordinary persistent userspace is
   considered fully online.
4. After root, add durable `/system`, `/config`, `/state`, `/cache`, `/run`,
   `/home`, and `/tmp` category implementations plus structured logging/crash
   handling, console/TTY/PTY, a useful shell, and a bounded recovery/admin path.
   General service registry, dependency control, activation, and supervision
   remain distinct responsibilities.
5. Add remaining driver/service families such as networking, audio, USB,
   graphics, and input only as their reached dependencies permit.
6. Add login/session management and eventually the graphical desktop path after
   its independent readiness gates.

Bootfs remains sufficient to reach or recover from failure to reach ext4 root.
The supervisor and storage/VFS bootstrap path must not require persistent
`/config` merely to start; immutable boot-generation policy supplies early
configuration.

The later Root Recovery Closure must retain immutable restart material in RAM
for the transitive components required to reacquire the selected root and reach
the promised degraded-recovery control plane. Recovery escalates finitely from
local restart through subsystem reconstruction and root reacquisition to
degraded recovery. Reboot is reserved for loss of trust, safe isolation, or the
ability to reconstruct the recovery substrate. Arbitrary third-party
applications are not promised transparent continuity.

Additional reached milestones must separately design any required general
TaskGroup/resource quotas, WyrmIDL/schema generation, native vDSO/loader ABI,
dynamic linking/libc/POSIX surfaces, and later native filesystem work.

## Final disposition

WYR0 phases A-I are complete on the exact accepted tuple. The generic
DW0-H/WYR0-I prerequisite for later native consumers is satisfied. WYR0-GW and
all workload-, graphics-, persistence-, and desktop-specific gates remain
independent.

