# WYR0-B Security Review

## Scope and disposition

This record covers the Wyrmroot UEFI loader, hostile kernel-ELF intake,
`DwBootInfoV1` production, transition mappings, accepted-toolchain consumption,
and loader artifact provenance for WYR0-B. It does not review or authorize
WYR0-C bootfs-format/runtime behavior.

The source, host-test, and accepted-toolchain artifact reviews are complete
with no Critical or High findings. WYR0-B remains open until the manager-owned
paired VM gate passes against the exact committed revisions and artifacts.

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
  post-EBS release surface, and the linked CR4.PGE/CR3/CR4.PCIDE/RSP/RDI/`jmp` order.
- The accepted PE/COFF artifact passed structural inspection. PDB-guided
  disassembly independently verified the emitted 37-byte raw stub clears PGE,
  loads the aligned attested CR3 with PCID zero, clears PCIDE, installs RSP/RDI,
  clears RBP, and performs an indirect `jmp`, with no call or return edge.
- The complete used table graph is a bounded fixed point. The encoder reserves
  the whole generated temporary PML4 slot, leaves its leaf exactly zero, rejects
  cycles, shared/unreachable/unused tables, missing or extra leaves, and every
  forbidden user/cache/huge/global/accessed/dirty bit, and attests exact plan
  equality before releasing transfer authority.
- Production attestation is non-copyable, retains an immutable borrow of the
  exact table allocation and plan through the nonreturning jump, and has no raw
  CR3 or unbound finalization path. The kind-3 carrier is serialized only from
  this evidence and remains in a release-less post-EBS allocation.
- PAT entry zero is observed as architectural write-back (`0x06`) before
  transfer. All transition structures and aliases select PAT0 with zero cache
  bits. This establishes alias consistency only; it does not claim effective
  write-back after MTRR interaction.

## Open findings and accepted limitations

- **Medium, accepted for this developer checkpoint:** Deepwyrm source identity
  uses exact HEAD, porcelain cleanliness, tracked-layout blob identity, and
  pre/post hashes. Same-user `assume-unchanged`/`skip-worktree` state or a
  transient modify-and-restore race can still evade a complete crate-tree
  identity claim. Accepted artifacts must be built from a trusted single-writer
  checkout/cache. Future hardening should materialize and hash the complete
  pinned crate input in an immutable build tree.
- **Medium, accepted for this developer checkpoint:** bounded Cargo/Git process
  capture enforces output limits and deadlines, but portable safe standard
  library APIs terminate only the direct child. A malicious same-user
  descendant can survive with inherited pipes. Builds therefore require trusted
  Cargo/Git executables and external host process isolation; future hardening
  should kill a dedicated process group and test a forked descendant.
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

## Closure evidence

- Complete: focused hostile-input and ownership regressions, strict Clippy,
  formatting, and diff hygiene.
- Complete: accepted `x86_64-unknown-uefi` check/build, PE inspection,
  path-neutral provenance, and raw-stub disassembly.
- Complete: exact compatible Deepwyrm/Wyrmroot revision pair and loader artifact
  hashes recorded in `validation/WYR0_B_VALIDATION.md`.
- Complete: final Daybreak adversarial review found no Critical or High findings
  for Wyrmroot `bee49a19a8c4c341b8fd6ed71606f9473b00ae64` paired with Deepwyrm
  `79c2e365901ab95d04e5f6877b87b109f61f7ca4`; the two additional Medium
  findings from this final review are explicitly accepted, and the three
  previously recorded Medium limitations remain accepted as documented.
- Complete: the bounded 128-KiB boot-stack acknowledgment at Wyrmroot
  `6230d2c26b0260add3fad1e1cc55c878c0362ab5` paired with Deepwyrm
  `b263a7a912c79b9e7d4b2439370417d7ae2ee076` passed strict layout, hostile
  NOBITS-tail, exact-allocation, RW/NX, non-overlap, accepted-build, provenance,
  and final Daybreak review gates with no new Critical, High, Medium, or Low
  findings. The existing accepted limitations above remain in force.
- Pending: manager-owned Q35/UEFI serial and handoff evidence. No QEMU or VM
  evidence is claimed by this document yet.
