# Wyrmroot EFI loader

The UEFI application that boots Wyrmroot. It reads `deepwyrm.elf`,
`bootstrap.elf`, `bootfs.img` and the boot device table from
`/EFI/Wyrmroot/` on the EFI system partition (`src/artifacts.rs`), parses the
kernel ELF (`src/kernel_elf.rs`), captures the final memory map, leaves boot
services, builds `DwBootInfoV1` with the generated Deepwyrm ABI, and enters
the kernel through the handoff in
[`LOADER_KERNEL_HANDOFF.md`](LOADER_KERNEL_HANDOFF.md). `xtask product` builds
it; `xtask dev-boot` boots it under OVMF.
