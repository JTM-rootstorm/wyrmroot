# Wyrmroot as built

Status: **as-built description**, written 2026-11-13 at Wyrmroot `617d743` with Deepwyrm `a34928e` (root `OS_STACK_ARCHITECTURE_PLAN.md` G1). It says what the code does, not what any plan intends. Where it and a governing document in [`ARCHITECTURE_INDEX.md`](ARCHITECTURE_INDEX.md) disagree, the governing document states the intent and this one the fact; report the disagreement rather than resolving it here. Update this document in the change that alters what it describes.

## 1. Shape

Wyrmroot is the platform over the Deepwyrm kernel: the EFI loader, the first userspace process, the system roles, their protocols, the product build and the canonical QEMU workflow. It runs on q35 UEFI under QEMU; nothing has run on physical hardware.

| Part | What it is |
|---|---|
| `loader/` | The UEFI application: reads the kernel, bootstrap, bootfs and boot device table from the ESP, builds `DwBootInfoV1`, leaves boot services, enters the kernel (`loader/LOADER_KERNEL_HANDOFF.md`) |
| `bootstrap/` | The first process, which the kernel loads; checks its ABI against the kernel's, loads `system/init` from the bootfs, passes it authority and retires |
| `userspace/` | 13 programs: `system-init`, `registryd`, `devmgr`, `uart16550d`, `virtio-blkd`, `blockmgr`, `fat32d`, `ext4d`, `vfsd`, `consoled`, `wyrmsh`, `hello`, `cpu-hog` |
| `crates/` | 22 libraries: the loader, the runtime (startup, syscalls, supervision), one codec crate per protocol, the bootfs and RRC manifest builders, ext4, FAT and partition parsers, the shell's grammar |
| `tools/xtask` | `dev-boot [--smp] [--check] [--sdk]`, `product --output`, `test [all|fmt|clippy|unit|root]` |
| `toolchain/versions.toml` | The one pin record: Deepwyrm revision and ABI fingerprint, the Rust fork and its `x86_64-unknown-wyrmroot` target |

Native programs are Rust, static ET_EXEC x86-64, linked against `deepwyrm-syscall` at the pinned revision, which stamps each with the ABI fingerprint note.

## 2. Boot chain

1. **Loader → kernel.** The EFI loader loads `deepwyrm.elf` and passes `bootstrap.elf`, `bootfs.img` and the boot device table as modules.
2. **Kernel → bootstrap.** The kernel parses bootstrap with its own parser and starts it. Bootstrap compares its fingerprint with the kernel's (`require_kernel_abi`), loads `system/init` with the resource-domain supervisor profile, waits for READY, retires its authority and reports READY.
3. **Init** (`userspace/system-init`), the permanent supervisor:
   1. checks the product marker;
   2. launches `registryd` and `devmgr`;
   3. lets `devmgr` start the drivers the device manifest names (`uart16550d` for COM2, `virtio-blkd` per disk), delegating each its exact resources;
   4. stages the storage roles (`blockmgr` for the boot and root volumes, `fat32d`, `ext4d`, `vfsd`);
   5. starts `consoled` and `wyrmsh`;
   6. serves jobs.
4. **The bootfs** holds the eleven system executables, `bin/hello`, `bin/cpu-hog`, the RRC-A manifest, the product marker, the device manifest and the launch policy (`crates/wyrmroot-bootfs/src/product.rs`).
5. **Recovery.** A resident tick restarts `registryd` and `devmgr` and rebinds drivers within a bounded budget; when the budget runs out init stays up, degraded, still serving the console and jobs (`userspace/system-init/src/recovery.rs`). The storage roles are not restarted. If `ext4d` cannot mount, `/` is `vfsd`'s synthetic directory with `/boot` beneath it.

## 3. Roles and protocols

Every protocol is a little-endian datagram with a four-byte magic and a major.minor version, codec in its own crate.

| Magic | Version | Between |
|---|---|---|
| WRBP | 1.0 | bootstrap ↔ init |
| WRLP | 1.x, a minor per startup profile (1.2–1.13) | loader → every child, at startup |
| WRRG | 1.0 | `registryd` and its clients (32 services) |
| WRLJ | 1.0, shell envelope 1.1 | init's job and launch service; `wyrmsh` and `consoled` are clients |
| WRDC, WRSC, WRCS, WRDP, WRPG, WRDM | 1.0–1.2 | `devmgr`, drivers, the serial connector, the device manifest |
| WRST | 1.0 | byte streams: console, shell, job stdin/stdout/stderr |
| WRCN | 1.0 | console status, read by `wyrmsh` |
| WRSV | 1.0 | init's one STAGE message to each storage role |
| WRBD | 1.0 | block service: `virtio-blkd` and `blockmgr` serve, `blockmgr`, `fat32d` and `ext4d` use |
| WRFS | 1.3 | one open file or directory: `fat32d`, `ext4d` and `vfsd` serve |
| WRNS | 1.3 | the namespace: `vfsd` serves OPEN, MOUNT, UNMOUNT |

The storage chain: `virtio-blkd` per disk → `blockmgr` per volume (the ESP's FAT as `volume.boot0`, the root as `volume.root0`) → `fat32d` read-only at `/boot`, `ext4d` read-write at `/` → `vfsd`. Decoders accept exactly their own minor today; OS stack plan X1 relaxes that.

## 4. Loading and limits

- `wyrmroot-loader` accepts static ET_EXEC x86-64 only: at most 16 MiB, 16 program headers, 8 PT_LOADs (2 for job images), 32 MiB mapped, never W+X, and exactly one PT_NOTE carrying this build's ABI fingerprint (V1; `crates/wyrmroot-loader/src/elf.rs`). The product build runs every image it ships through the same parser.
- A child gets a 128 KiB stack with a guard page, a startup block and an auxiliary vector (PHDR, PHENT, PHNUM, PAGESZ, ENTRY) (`image.rs`); construction is failure-atomic (`process.rs`).
- Job limits (`userspace/system-init/src/jobs.rs`):
  - per-job TaskGroup limits of 10 Channel endpoints, 4 MemoryObjects, 4 waits, 16 MiB, and no Events, Timers, Threads, Processes or TaskGroups;
  - at most 4 jobs, 3 per shell, 2 orphans.
- The product's peak demand on the kernel's pools is `tools/xtask/src/kernel_demand.rs` (C1). The product build reads the paired kernel's `pools.toml` and refuses a product that does not fit, naming the pool.

## 5. Shell and jobs

- `wyrmsh` commands: `help echo clear exit shutdown services tasks status run spawn wait terminate ls cat write mkdir rm` (`crates/wyrmroot-wyrmsh-core/src/command.rs`).
- `run` launches a bootfs program, or with an absolute path an ELF read through `vfsd`; init reads at most 8 MiB, in under 10 s.
- `spawn` starts a bootfs program in the background.
- SDK programs (musl, zlib, Lua, SQLite) come from `wyrmroot-sdk`, built against the same Deepwyrm pin.

## 6. Product and checks

- `xtask product` builds the loader, kernel, bootstrap and natives, and checks:
  - the kernel's ABI fingerprint equals the pin;
  - the kernel demand fits;
  - every image carries the note.

  It then writes a FAT32 ESP, a 64 MiB ext4 root and OVMF.
- `dev-boot --check` boots that product twice on the same disks under QEMU q35 (TCG, 2 GiB, one CPU, or four with `--smp`, VT-d on) and drives the shell over COM2 (`tools/xtask/src/dev_boot.rs`).
  - **First boot:**
    - services listed;
    - the root and the ESP listed and read;
    - background jobs started and terminated;
    - `hello` in its normal, on-demand and exhaustion modes;
    - a program run from disk;
    - with `--sdk`, the five SDK programs;
    - a file written.
  - **Second boot:** the file is still there and is removed.
  - Both end in a clean power-off.

## 7. What it does not do yet

Each has an owner in root `OS_STACK_ARCHITECTURE_PLAN.md` or `CARRIED_OPEN_ITEMS.md`:

- init is the launcher (SV1–SV4);
- the storage chain is outside recovery (RC1–RC4);
- there is no service description (SD1–SD4);
- protocols are hand-written with exact-match minors (X1–X4);
- VFS clients get read-write `/` (A1–A5);
- `consoled` is shaped around one serial port (CT1–CT5);
- no root of trust (TR0–TR4);
- no ASLR (MT3);
- no physical hardware (`HARDWARE_BRINGUP_PLAN.md`).
