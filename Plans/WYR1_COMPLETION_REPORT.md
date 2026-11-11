# Wyrmroot WYR1 Completion Report

**Status:** WYR1 complete, 2026-11-10.

WYR1 closes on Wyrmroot `45a45e05631104ccb4ad145cc502f73b9907dca8` (code identical to `5f00b55`) paired with Deepwyrm `831e2ad3d40c530d0182938b19844f13f579b2f7`. The pinned `deepwyrm-abi` is Deepwyrm `c7d7aae`. The product's ESP SHA-256 is `fe76c14ab9481a7a5035ad52eebfa96d9493d085e5604a64847400b558129a71`. The paired certificate is the OS-Project root's `DW1_WYR1_INTERACTIVE_SHELL_CAPABILITY_CERTIFICATE.md`, and the live and reproducibility record is the root's `DW1F_WYR1F_F3_RECORD.md` §6. That record and this report are the WYR1 validation record; there is no separate `WYR1_VALIDATION.md`.

## What WYR1 delivers

- `/system/init`, the permanent supervisor, with its immutable RRC-A manifest and bounded restart;
- `registryd`, the bootstrap registry, and the scoped launch/job service in init;
- `devmgr`, which takes the typed boot-device intake and delegates exact COM2 authority;
- `uart16550d`, an interrupt-driven userspace UART driver that publishes `device.serial.console0`;
- `consoled`, which binds that stream and runs the shell under bounded generations;
- `wyrmsh`, the bootfs recovery and admin shell (`help`, `echo`, `clear`, `services`, `status`, `tasks`, `run`, `spawn`, `wait`, `terminate`, `exit`, `shutdown`), with a bounded line editor;
- job bounds: three jobs per shell and four in total, with TaskGroup limits on each job.

## Evidence

- Phase records: the `WYR1_*_VALIDATION.md` and `*_IMPLEMENTATION_STATUS.md` files indexed in `ARCHITECTURE_INDEX.md`.
- Security: [`../security/WYR1_SECURITY_REVIEW.md`](../security/WYR1_SECURITY_REVIEW.md). No Critical or High findings. The one Medium is fixed, and the residual risks are fixed or accepted as Low.
- Final pair: `xtask test` passes, the product runs the shell scenario on one and four vCPUs, and two builds are byte-identical (root F3 record §6).

## Nonclaims and next work

- Programs come only from bootfs; adding one means rebuilding the image.
- No storage, VFS, libc or package manager yet. The next spine is a block driver, then the BlockDevice protocol, partitions, VFS, FAT32 and ext4 (master plan §20). The cross toolchain is planned in parallel (root `TOOLCHAIN_PLAN.md`).
- The shell has no authentication and must not be exposed beyond the local serial console.
