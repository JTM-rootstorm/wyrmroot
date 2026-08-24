# Wyrmroot Storage and Filesystem Direction

**Status:** Canonical reached architecture direction; implementation details remain milestone-owned
**Repository:** `JTM-rootstorm/wyrmroot`
**Applies to:** post-WYR0 storage/VFS/root bring-up and later native-filesystem planning
**Companion:** `WYRMROOT_PLATFORM_CONVENTIONS.md`

This document pins the filesystem roles needed to bring Wyrmroot from bootfs-only native userspace to a persistent operating system. It deliberately separates the boot filesystem role, the first production root filesystem, and the eventual Wyrmroot-native filesystem.

The governing direction is:

> **FAT32 owns the EFI System Partition role, ext4 is the initial persistent root required for full userspace onlining, and an eventual native filesystem is designed later from implementation evidence rather than made a kernel-bootstrap dependency.**

This is a Wyrmroot policy/implementation choice. Deepwyrm supplies generic block-device, memory, IPC, capability, and device-resource mechanisms and does not learn FAT32, ext4, mount policy, or native filesystem semantics.

---

## 1. Three filesystem roles, not one temporary ladder

The project must not describe FAT32 as an interim root filesystem.

1. **FAT32 / ESP:** boot artifact storage and later boot-management/update access.
2. **ext4 / persistent root:** the first serious Unix-like persistent filesystem for the installed system.
3. **future native filesystem:** a later independent on-disk format informed by experience with the first two and by selected prior art.

Bootfs remains a fourth, separate thing: a small deterministic read-only bootstrap/recovery transport loaded by the Wyrmroot loader. It is not the ESP filesystem service and it is not the persistent root.

---

## 2. FAT32 is an early boot-management filesystem

The WYR0 host tooling already constructs a real FAT32 EFI System Partition. During WYR0, firmware/loader file services are sufficient because the guest does not yet manage its own persistent filesystems.

Once ordinary Wyrmroot userspace is responsible for inspecting or changing installed boot artifacts, a native FAT32 filesystem service/driver must be available through the real storage/VFS path. Expected uses include:

- reading the mounted EFI System Partition;
- staging or replacing loader, kernel, bootstrap, bootfs, manifest, and recovery artifacts under the ESP's EFI/boot paths;
- validating an installed boot generation before activation; and
- recovery tooling that needs to inspect or repair boot artifacts without depending on host image tools.

The FAT32 service must therefore be bootfs-loadable and usable before the persistent root is a hard dependency whenever the boot/update path requires it.

FAT32 is **not** the normal Wyrmroot root filesystem. Native permission, link, durable-state, package, configuration, and general Unix-like semantics must not be distorted to make FAT32 carry the installed operating system.

Normal running-system boot management must not depend on host-side `mtools`, a mounted host image, or UEFI runtime filesystem services as a substitute for Wyrmroot's own block/VFS/filesystem stack.

---

## 3. ext4 is the initial persistent root

The first persistent root filesystem is **ext4**.

Ext4 is part of the dependency chain for bringing the normal post-bootstrap userspace fully online, rather than an optional compatibility filesystem added after the base system already exists.

For this architecture, **full userspace onlining** means the system has crossed from the bootfs-only recovery/bootstrap environment into the normal persistent namespace where `/system`, `/config`, `/state`, `/cache`, `/run`, `/home`, and related services can operate according to the platform conventions. The exact split of read-only versus writable trees may evolve later; the persistent-root dependency does not.

The ext4 filesystem service/driver must be launchable from bootfs after the required block/storage driver is available. Root discovery and mount policy remain Wyrmroot userspace responsibilities.

A failed ext4 root mount must leave the bootfs-resident supervisor, discovery path, essential storage/VFS pieces, diagnostics, and recovery path usable enough to report/recover from the failure. It must not force Deepwyrm to gain filesystem-aware execution or make a reboot the only response.

Ext4 is selected because it provides a mature, conventional Unix filesystem target against which Wyrmroot can validate real path, metadata, allocation, durability, recovery, and file-lifetime behavior before defining a new on-disk format.

The ext4 implementation milestone must still pin exact external specifications/reference revisions and license-compatible prior art before source adaptation. Selecting ext4 as the initial root does not authorize blindly importing Linux kernel implementation internals into Wyrmroot.

---

## 4. Bring-up dependency order

The default storage/filesystem portion of the post-WYR0 spine is:

```text
bootfs-resident permanent supervisor + discovery
        -> device coordinator
        -> essential block/storage driver server(s)
        -> VFS namespace/core service
        -> FAT32 service for ESP access when boot management requires it
        -> ext4 service + persistent-root discovery/mount
        -> normal persistent configuration/state/logging/admin services
```

FAT32 and ext4 work may proceed in parallel after their common VFS/block prerequisites are stable. The ordering above describes dependencies, not a requirement to serialize unrelated implementation lanes.

---

## 5. Eventual native filesystem: design later, preserve room now

The eventual Wyrmroot-native filesystem is intentionally **not** a prerequisite for kernel bootstrap, WYR0 closure, or first persistent-root bring-up. Its on-disk format, name, exact algorithms, and implementation milestone remain unfrozen.

Begin that work only after the FAT32/ESP and ext4-root paths have exercised the real block layer, VFS, userspace driver/service model, mount/recovery policy, and persistent service workloads. Those implementations are expected to expose which abstractions are genuinely useful and which are paper architecture.

Current donor direction is approximately:

- **XFS:** primary structural/design donor;
- **ext4:** simplicity, Unix semantics, and general-purpose operational donor; and
- **NTFS:** selective metadata/change-tracking donor.

The informal 50/30/20 XFS/ext4/NTFS weighting records design emphasis only. It is not an on-disk compatibility requirement and does not authorize source copying.

Concepts that should remain feasible in the VFS/storage contracts include:

- allocation-group or similarly sharded allocation/repair domains;
- scalable tree-based metadata/free-space indexing;
- self-describing checksummed metadata;
- reverse extent-to-owner mappings or equivalent independently checkable ownership metadata;
- reflink/copy-on-write cloning;
- online scrub and targeted repair as first-class design requirements;
- optional transparent compression and per-file/per-tree encryption;
- optional ordinary file-data integrity/checksumming modes without requiring them for every workload; and
- online growth plus a design that can evacuate/remove trailing allocation regions for practical shrinking.

Selective NTFS-inspired features may include stable object identity, a persistent filesystem change sequence/journal for incremental consumers, and explicit typed/named auxiliary streams or forks. If auxiliary streams are adopted, they must use an explicit native API/namespace and must not import NTFS alternate-data-stream pathname magic.

A persistent change sequence is particularly desirable for indexers, backup/synchronization, package verification, and desktop search so they can resume from a durable change cursor rather than repeatedly crawl the entire namespace.

The native filesystem should preserve ordinary Wyrmroot pathname semantics from the platform conventions: case-sensitive native names, byte-safe low-level components, explicit links, open-object lifetime independent of later namespace changes, and same-filesystem atomic replacement.

---

## 6. Baggage we do not inherit

The native filesystem must not gain compatibility features solely because a donor filesystem has them.

Do not inherit by default:

- NTFS drive-letter, DOS 8.3, Windows case-folding/collation, or opaque reparse-point semantics;
- NTFS alternate-stream pathname syntax or Windows security-descriptor encoding as native policy;
- ext2/ext3 on-disk upgrade compatibility or historical JBD2 quirks merely to resemble ext4;
- XFS complexity that is justified only by extreme-scale workloads and provides no useful Wyrmroot invariant; or
- Linux VFS/internal kernel APIs as the Wyrmroot filesystem-service ABI.

XFS and NTFS support remain useful later interoperability/secondary-filesystem targets, but neither is a prerequisite for bringing the base userspace online.

---

## 7. Kernel and service boundary

Filesystem implementations are userspace Wyrmroot services unless a later concrete hardware/safety requirement proves that a narrowly scoped Deepwyrm mechanism is unavoidable.

Deepwyrm should see capabilities, memory, block I/O/device resources, waits/IPC, and generic protection/lifetime operations. It must not branch on filesystem type, parse paths for normal execution, own mount policy, or embed ext4/FAT32/native filesystem code simply because those filesystems are boot-critical.

The VFS/filesystem layer must expose/query backing-filesystem capabilities instead of assuming every mounted filesystem supports reflink, xattrs, hard links, encryption, compression, snapshots, or the future native change journal.

The FAT32, ext4, and later native filesystem services should remain separately testable fault/policy domains where practical. A filesystem service failure should be surfaced to supervision/recovery policy rather than silently converted into kernel corruption or permanent machine death.

---

## 8. Prior art, provenance, and licensing

Before implementing FAT32, ext4, XFS/NTFS interoperability, or the native filesystem, follow the workspace prior-art policy: consult relevant external specifications and implementations, pin exact revisions, record file-level licenses, and adapt compatible source only when it materially reduces duplicated effort without importing an unsuitable architecture.

At minimum, later implementation plans should evaluate current license-compatible FAT/ext4 implementations and authoritative format documentation before designing parsers, allocators, journals, or repair logic from scratch.

Linux filesystem source is useful required/reference material but is **not automatically reusable under the license of a new Wyrmroot component**. Check the exact SPDX/license of every source file considered for copying or substantial adaptation. Conceptual study alone does not change the license of independently written Wyrmroot code.

The native-filesystem milestone should likewise pin exact XFS, ext4, and NTFS design/reference sources at that time rather than treating today's moving upstream trees as immutable specifications.

---

## 9. Locked direction and deferred details

Locked now:

- FAT32 is the native guest filesystem used for EFI System Partition access once running userspace manages boot artifacts.
- ext4 is the initial persistent root filesystem and is required before the normal persistent userspace is considered fully online.
- FAT32 and ext4 drivers/services must fit the Wyrmroot userspace VFS/storage architecture and remain bootfs-loadable where required for bootstrap/recovery.
- root-mount failure remains a recoverable Wyrmroot userspace event.
- the eventual native filesystem is post-bootstrap/post-ext4 work, not an early boot dependency.
- the native filesystem should be XFS-led, ext4-tempered, and selectively NTFS-informed while preserving native Wyrmroot semantics.

Deferred to reached implementation milestones:

- exact VFS protocol/API and process decomposition;
- exact FAT32/ext4 implementation or reused-source choices;
- partition-discovery/mount configuration schemas;
- exact system-disk layout and root partitioning;
- native filesystem name, disk format, allocator/tree algorithms, journal/log format, checksum algorithms, compression/encryption formats, and compatibility promises; and
- exact milestone names and parallel implementation lanes.

Do not infer those deferred details merely from the donor filesystems named above.
