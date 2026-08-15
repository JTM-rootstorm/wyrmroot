# WYR0-B Security Review

## Scope and disposition

This record covers the Wyrmroot UEFI loader, hostile kernel-ELF intake,
`DwBootInfoV1` production, transition mappings, accepted-toolchain consumption,
and loader artifact provenance for WYR0-B. It does not review or authorize
WYR0-C bootfs-format/runtime behavior.

The source and host-test review is complete with no Critical or High findings.
WYR0-B remains open until the accepted-toolchain artifact gate and
manager-owned paired VM gate pass against exact committed revisions.

## Closed findings

- Kernel ELF input is restricted to the generated Deepwyrm fixed-base
  `ET_EXEC` contract. Arithmetic overflow, unsupported program headers,
  page-rounded overlap, writable-executable mappings, invalid entry placement,
  and authoritative use of `p_paddr` fail closed.
- Transition planning rejects page zero, noncanonical ranges, aliasing,
  framebuffer identity mapping, released allocations, and incorrect page-table
  sizing. ACPI identity mapping is derived only from the retained validated
  RSDP record and cannot be supplied as an arbitrary page list.
- Retained module, entropy, and RSDP allocations distinguish exact payload
  length from page-rounded ownership extent, and retained slack is zeroed.
- The x86_64 page-table encoder independently enforces bit-47 sign extension,
  reserved physical-address bits, W^X/NX permissions, and exact table-page
  consumption.
- COM1 initialization is bounded and checked before the final post-firmware
  marker. The raw handoff is a nonreturning jump with a dedicated transition
  stack and validated BootInfo/CR3 inputs.
- The accepted toolchain manifest and Deepwyrm layout are read through bounded
  single-buffer trust boundaries. Selected components reject symlink ancestry
  and are identity/hash checked around execution.
- The only `ExitBootServices` surface consumes pre-EBS rollback authority into
  release-less post-EBS page tokens. Final-map, BootInfo, page-table, serial,
  retained-address, and transfer gates must all succeed before the sole raw
  jump wrapper can be authorized.
- Host regressions cover exact-once rollback, fatal post-EBS dispatch, retained
  table/module/entropy/RSDP address coherence, the absence of a second EBS or
  post-EBS release surface, and the linked `cli`/`cld`/CR3/RSP/RDI/`jmp` order.

## Open findings and accepted limitations

- **Medium, accepted for WYR0-B:** a same-user replacement restored between
  pre- and post-child identity checks is not prevented without descriptor-based
  execution or stronger parent-filesystem immutability. Atomic opened-file
  hashing, no-symlink checks, and immediate pre/post verification reduce this
  risk; a future distributable toolchain should provide a stronger immutable
  execution boundary.
- **Medium, accepted for WYR0-B:** Cargo and the accepted compiler use ambient
  Gentoo kernel and system runtime libraries, including libc/libgcc and Cargo's
  networking/parser dependencies. These are host-platform dependencies, not
  guest runtime dependencies or Wyrmroot ABI.
- **Medium, artifact hygiene:** the immutable developer toolchain contains two
  non-executed absolute source-tree symlinks and a historical absolute build
  command in its manifest. They are outside the selected build-component trust
  boundary and must not be traversed, copied into media, or included in product
  provenance. A future distributable toolchain package must be path-neutral and
  source-symlink-free.
- **Medium, accepted for WYR0-B:** the trusted build depends on fixed GNU tar
  and ambient system dynamic-loader/runtime libraries. Runtime dependency
  metadata, toolchain-local `librustc_driver`/LLVM, the manifest-selected
  target libraries, and the whole toolchain tree are verified; the host kernel
  and system libraries remain platform dependencies.

## Required closure evidence

- focused hostile-input and ownership regressions, strict Clippy, rustdoc,
  formatting, and diff hygiene;
- accepted `x86_64-unknown-uefi` check/build plus PE inspection and path-neutral
  provenance;
- exact compatible Deepwyrm/Wyrmroot commit pair and artifact hashes; and
- manager-owned Q35/UEFI serial and handoff evidence. No QEMU or VM evidence is
  claimed by this document yet.
