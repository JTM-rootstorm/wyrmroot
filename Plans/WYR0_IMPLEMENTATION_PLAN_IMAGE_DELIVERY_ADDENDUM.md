# Wyrmroot WYR0 Implementation Plan Addendum: VM and Image Delivery

**Status:** Canonical locked addendum to `Plans/WYR0_IMPLEMENTATION_PLAN.md`  
**Repository:** `JTM-rootstorm/wyrmroot`  
**Milestone:** WYR0  
**Scope:** Reference VM sizing, image construction, and host-to-guest software delivery

This document is part of the WYR0 implementation contract. Codex and human contributors must treat the decisions below as **locked** unless an explicit architecture revision updates this addendum and the matching Deepwyrm DW0 addendum together.

The central rule is:

> **The canonical Wyrmroot boot, integration-test, and early software-delivery path must not require a host filesystem share.**

WYR0 must boot from real virtual media. 9p, VirtioFS, host-mounted source trees, NFS convenience mounts, or equivalent mechanisms may not be required for milestone completion.

---

# 1. Locked WYR0 reference VM profile

The canonical WYR0 development VM is:

```text
Machine:        QEMU q35
Firmware:       x86_64 UEFI / OVMF
vCPU:           1
RAM:            1024 MiB
ESP image:      256 MiB FAT32
System disk:    4 GiB sparse qcow2, reserved for later milestones
Serial:         COM1
Networking:     absent for DW0/WYR0 canonical path
Graphics:       not required for DW0/WYR0
```

Standard tool-managed profiles should include:

| Profile | vCPU | RAM | Disk | Purpose |
|---|---:|---:|---:|---|
| `default` | 1 | 1024 MiB | 4 GiB | Canonical WYR0 development and acceptance |
| `minimal` | 1 | 256 MiB | 1 GiB or same sparse 4 GiB disk | Detect accidental large-memory assumptions |
| `smp` | 4 | 2048 MiB | 4 GiB | Early SMP/concurrency smoke testing |
| `debug` | 1 | 2048 MiB | 4 GiB | GDB, verbose diagnostics, instrumentation |

The `default` profile is authoritative for WYR0 acceptance. Other profiles are validation tools rather than alternate machine contracts.

---

# 2. Canonical host-to-guest artifact pipeline

The normal development path is:

```text
Gentoo development host
        |
        +-- build loader.efi
        +-- obtain/build pinned deepwyrm.elf
        +-- build bootstrap.elf
        +-- build /system/init0
        +-- build /bin/hello
        |
        v
build deterministic bootfs.img
        |
        v
build deterministic wyrmroot-esp.img
        |
        v
QEMU attaches ESP as virtual block media
        |
        v
UEFI firmware
        |
        v
/EFI/Wyrmroot/loader.efi
        |
        +-- reads deepwyrm.elf
        +-- reads bootstrap.elf
        +-- reads bootfs.img
        |
        v
DwBootInfoV1
        |
        v
Deepwyrm -> primordial Wyrmroot userspace
```

The guest must not observe or depend on the host source tree. From Wyrmroot's perspective, its boot files exist on disk media and are loaded through UEFI/the normal boot contract.

---

# 3. Locked ESP layout

For WYR0, `wyrmroot-esp.img` is a real FAT32 EFI System Partition image containing at least:

```text
/EFI/Wyrmroot/
├── loader.efi
├── deepwyrm.elf
├── bootstrap.elf
└── bootfs.img
```

A minimal loader configuration file may also be present.

The canonical image builder must place these artifacts into the FAT image itself. QEMU must not obtain them from an attached host directory.

The image should be directly analogous to media that could later be written/copied to a physical EFI System Partition.

---

# 4. Locked WYR0 bootfs role

`bootfs.img` remains WYR0's primordial read-only userspace transport, not the permanent filesystem design.

The pipeline is:

```text
Wyrmroot host tooling builds bootfs.img
        |
places bootfs.img on ESP
        |
loader.efi loads it with UEFI file services
        |
DwBootInfoV1 identifies the module
        |
Deepwyrm exposes it as a read-only MemoryObject
        |
bootstrap.elf receives the capability
        |
Wyrmroot bootfs parser locates /system/init0
        |
init0 later locates /bin/hello through delegated access
```

For WYR0 the bootfs contents include at minimum:

```text
/system/init0
/bin/hello
```

The bootfs parser remains userspace-owned. No persistent root filesystem or disk driver is required merely to prove WYR0 process loading.

---

# 5. `xtask` owns image construction and QEMU configuration

The canonical user-facing workflow should stabilize around:

```text
cargo xtask build
cargo xtask image
cargo xtask run
```

with focused test commands as already defined by the main WYR0 plan.

`cargo xtask image` or its canonical equivalent owns:

1. verifying pinned Deepwyrm and Wyrmroot build revisions
2. collecting `loader.efi`
3. collecting the exact pinned `deepwyrm.elf`
4. building/collecting `bootstrap.elf`
5. building the deterministic bootfs archive
6. constructing the FAT32 ESP image
7. placing all required artifacts at canonical paths
8. validating the resulting image manifest
9. preparing/locating the sparse system disk if the chosen profile includes one

`cargo xtask run` owns the canonical QEMU arguments for:

- `q35`
- UEFI/OVMF
- vCPU count
- RAM
- ESP attachment
- system-disk attachment
- COM1 serial
- GDB/debug options
- test-only devices where appropriate

Codex agents must not maintain conflicting private QEMU profiles in subsystem scripts.

---

# 6. Ordinary image construction must not require root

Normal WYR0 development should not depend on a workflow such as:

```text
sudo losetup ...
sudo mount ...
sudo cp ...
sudo umount ...
```

Prefer Rust or conventional unprivileged host tooling that reads/writes FAT/image files directly.

External host utilities may be used during early implementation where sensible, but the stable `xtask image` interface must remain unprivileged and deterministic.

Do not make a mounted host directory the shortcut around implementing the image builder.

---

# 7. Separate boot ESP and persistent system disk

The VM topology is intentionally split:

```text
QEMU
├── wyrmroot-esp.img
│   └── loader + Deepwyrm + bootstrap + bootfs
│
└── wyrmroot-system.qcow2
    └── persistent Wyrmroot storage in later milestones
```

The system disk should begin as a **4 GiB sparse qcow2** image. WYR0 does not need to consume it. When the post-WYR0 storage/VFS milestone brings up the first persistent root, that root is ext4; the eventual Wyrmroot-native filesystem is a later replacement/research track rather than a prerequisite for first persistent userspace.

Reasons for the split:

- rebuilding boot artifacts does not wipe persistent guest state
- storage/VFS work later gets a real block device
- kernel-update/rollback testing can evolve independently from the root filesystem
- the boot path remains physically realistic

WYR0 image regeneration must not inherently recreate the system disk.

## 7.1 Later guest-side ESP access

WYR0 host tooling constructs and inspects the FAT32 ESP because the guest filesystem stack is intentionally out of scope. That host-side role does not define the later running-system update path.

Once Wyrmroot userspace is expected to inspect, stage, replace, validate, or recover installed EFI/boot artifacts, the guest must use a FAT32 filesystem service/driver over its own partition/block/VFS path. Normal boot/update management must not depend on host image tools, a host filesystem share, or UEFI runtime file services as a substitute for the operating system's storage stack.

FAT32 remains the EFI System Partition filesystem. It is not the persistent root filesystem; the first persistent root is ext4 as pinned by `WYRMROOT_STORAGE_FILESYSTEM_DIRECTION.md`.

---

# 8. Wyrmroot software-delivery progression

Pin this milestone progression:

```text
DW0 / WYR0
===========
Host-built FAT32 ESP
        +
read-only bootfs loaded into RAM

        |
        v

Persistent root bring-up
========================
FAT32 ESP through the guest storage/VFS path when boot management needs it
        +
ext4 root on the real Wyrmroot virtual system disk

        |
        v

Package manager
===============
FAT32 ESP
        +
ext4 system root
        +
packages delivered through virtual removable media or Wyrmroot networking

        |
        v

Self-hosting
============
Wyrmroot installs/builds its own packages,
updates, kernels, and boot artifacts
```

A host filesystem share is not a stage in this progression.

---

# 9. Optional removable development/package media

After Wyrmroot has the required storage/filesystem layer, host tooling may build an additional ordinary disk image such as:

```text
dev-media.img
├── packages/
│   ├── foo.pkg
│   └── bar.pkg
└── test-data/
```

QEMU may attach this as removable/secondary block media.

Wyrmroot accesses it through its **own block and filesystem stack**. This is an approved development mechanism because the same basic artifact could be put on real removable media.

This mechanism is especially useful before networking exists and later for offline package-management tests.

---

# 10. Networking becomes a software-delivery path only after networking exists

DW0/WYR0 should run with no virtual NIC in the canonical profile.

When Wyrmroot has a native networking stack and package manager, a Gentoo-hosted local package repository may be used over ordinary guest networking:

```text
Gentoo host package repository
        |
virtual network
        |
Wyrmroot networking stack
        |
Wyrmroot package manager
```

This is legitimate because Wyrmroot is exercising its own networking and package protocols rather than seeing host files directly.

Do not pull networking into WYR0 merely to accelerate artifact transfer.

---

# 11. QEMU-only test injection is strictly test plumbing

QEMU-specific channels such as firmware configuration entries, debug-exit devices, or tiny test-control transports may be used for:

- guest-test selector
- deterministic test seed
- explicit test completion/result
- other small harness metadata

They may **not** become the normal delivery mechanism for:

- `deepwyrm.elf`
- `bootstrap.elf`
- bootfs contents
- `/system/init0`
- `/bin/hello`
- package files
- normal system configuration

The rule is:

> If a physical x86_64 machine would ordinarily need to obtain the data from storage/networking, the canonical VM path should do the same.

---

# 12. Disposable system-disk overlays

Once persistent storage tests begin, the harness should support qcow2 overlays:

```text
wyrmroot-system-base.qcow2
          |
          v
test-overlay.qcow2
          |
          v
QEMU
          |
          v
discard overlay after test
```

Use this for future:

- filesystem corruption tests
- failed update tests
- package rollback tests
- crash recovery
- destructive security/adversarial storage tests

This is not required for WYR0 execution, but the initial image/QEMU tooling should not make the pattern difficult to add.

---

# 13. Image inspection requirements

Provide an image-inspection command or equivalent capability, conceptually:

```text
cargo xtask inspect-image
```

It should be capable of proving which artifacts are actually in the generated media, for example:

```text
ESP:
  /EFI/Wyrmroot/loader.efi
  /EFI/Wyrmroot/deepwyrm.elf
  /EFI/Wyrmroot/bootstrap.elf
  /EFI/Wyrmroot/bootfs.img

Bootfs:
  /system/init0
  /bin/hello
```

Where practical, the image manifest should include hashes/build identifiers so an integration failure can be tied to the exact artifacts consumed by QEMU.

Do not assume that because a host binary compiled successfully, the regenerated guest image necessarily contains that binary.

---

# 14. Determinism and reproducibility

The WYR0 image path should strive for deterministic output:

- stable bootfs file ordering
- normalized metadata where the archive/image format permits
- explicitly pinned Deepwyrm revision
- explicitly pinned Wyrmroot/Rust toolchain revision
- no dependency on host mount timestamps or random directory traversal order
- image manifest identifies source revisions and artifacts

Exact FAT filesystem metadata may require normalization rules before byte-for-byte image reproducibility is practical. WYR0 must at least guarantee deterministic logical contents and provide verification tooling.

---

# 15. Security implications

The existing WYR0 security gate applies to the image pipeline too.

Review/test at minimum:

- image builder path sanitization
- no traversal outside the intended staging tree
- artifact size/range checks
- exact artifact/revision pinning
- stale-image detection
- bootfs/ESP manifest consistency
- loader rejection of malformed/truncated artifacts
- accidental writable host-path dependencies
- QEMU test-injection channels accidentally exposed as production data paths

A malformed or stale host image must fail clearly rather than causing the test harness to report success against the wrong build.

---

# 16. WYR0 image-delivery acceptance gate

WYR0 must not be considered complete until:

- the canonical `default` VM profile is centrally defined as 1 vCPU / 1024 MiB RAM / q35 / UEFI
- host tooling constructs a real 256 MiB FAT32 `wyrmroot-esp.img`
- the ESP contains the exact `loader.efi`, pinned `deepwyrm.elf`, `bootstrap.elf`, and `bootfs.img` expected by the build manifest
- the bootfs contains the exact `/system/init0` and `/bin/hello` artifacts used by the end-to-end test
- ordinary image construction/run does not require root privileges
- QEMU reaches WYR0 with 9p, VirtioFS, NFS host shares, and equivalent host-directory injection disabled/not configured
- the complete `UEFI -> loader -> Deepwyrm -> bootstrap -> init0 -> hello` acceptance path succeeds using only the generated media plus test-only control channels
- rebuilding the ESP does not inherently destroy/recreate the reserved persistent system disk
- image inspection can identify/verify the artifacts actually consumed by the VM
- QEMU profile definitions are centralized under Wyrmroot tooling
- any experimental host-share support is optional, clearly noncanonical, and excluded from milestone acceptance

The intended result is that the canonical VM boot path remains structurally transferable to physical x86_64 hardware rather than depending on conveniences that only exist because the guest happens to run under QEMU.
