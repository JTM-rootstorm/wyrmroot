# DW1-B selector-26 Wyrmroot product contract

Selector `normal-preemption-up` (ID 26) is a test-only one-CPU preemption
product. It does not extend Deepwyrm's public ABI. Wyrmroot's global generated
ABI/syscall consumers remain pinned to `cfc69bd8a49819ce1cda1a132cf56e55c93f92e4`
and ABI tree `1c6a74f130e386eee95b3780c75950beefd0037d`.
The selector product separately requires kernel candidate
`b203ba6d6a69443b9c51750369272446cb9604d9`; this is the canonical selector-26
kernel candidate. This contract does not claim that a Wyrmroot revision which
has not yet been integrated and committed is final.

The exact selector-specific bootfs has four executable entries: `system/init0`, `bin/hello`,
`test/dw1-b/cpu-hog`, and `test/dw1-b/progress`. The CPU hog completes ordinary
handle-free WRLP 1.0 READY, closes that launch endpoint, and only then enters
its audited steady spin loop. That executed loop has no syscall, yield, block,
memory access, or function call. The progress peer instead uses test-private
WRLP 1.4 profile `Dw1bProgress`: INIT transfers exactly one data Channel with
`CHILD_CHANNEL_RIGHTS`; READY remains handle-free on the separate launch
Channel. The launch endpoint is then closed and all eight fixed DWP1 exchanges
occur only on the data Channel. The progress raw operation is submitted once
after the eighth validated request and reply.

Init0 creates/starts the hog and accepts its READY before creating/starting the
progress peer. After progress READY it submits exact ARM arguments, performs
the eight exchanges, observes and queries progress normal exit, and closes its
three retained progress handles. It then launches and fully supervises the
unchanged `bin/hello`, terminates the hog once, waits for EXITED, queries its
terminal record, and closes the hog handles before sending init0 READY.
Failure cleanup follows the same terminate, wait, query, close ownership order,
attempts every remaining cleanup operation, and preserves the first cleanup
failure without falsely reporting a later cleanup as successful.

Schema 5 uses canonical request-relative paths with no traversal, symlink
ancestry, hard-link substitution, or input/output/run-directory aliases. It
binds nonzero exact revisions, the candidate and ABI tree, accepted Rust
revision `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`, and the exact clean current
Wyrmroot HEAD. Before a request is authored, `cargo xtask dw1b freeze --output
<new-directory>` refuses existing output and a dirty source tree, then produces
the six request input artifacts plus the builder-owned Wyr source-build
receipt. It uses the central deterministic UEFI builder for isolated release
and retained-debug loader builds, the accepted Rust007 sysroot and `rust-lld`,
repository/Cargo-home/target remaps, `/Brepro`, and production `/debug:none`.
The central UEFI inspector must report a production loader with Repro metadata,
no CodeView record, and no import directory. The freeze retains the audited
debug EFI/PDB pair and normalized effective UEFI configuration and inspector
reports for provenance, but those retained-debug files do not enter the ESP.

The canonical `image` path independently rebuilds loader, bootstrap, init0,
hello, CPU hog, and progress with the same isolated accepted workflow and
requires byte-for-byte equality with the frozen inputs before it writes a
product. It refuses pre-existing Wyrmroot outputs. The canonical `run` path
requires that completed product, revalidates it through the same strict
inspection path before and after execution, and never rebuilds already-proven
artifacts. Source-build receipt schema 2 binds the clean source revision, Cargo lock, accepted toolchain identities,
generated Deep layout and policy hashes, normalized effective UEFI
configuration digest, inspector and inspection-report hashes, exact separate
release commands/profile, and all six production output hashes. The retained
debug EFI/PDB pair is freshly built and inspector-validated at every freeze and
rebuild, but its build-local identity is not production evidence. The two
DW1-B native payloads use the canonical native linker
script; all native artifacts have numeric ELF OSABI 0 and ABI version 0. The
request also binds SHA-256 identities for loader, kernel, symbols, bootstrap,
all four payloads, provenance, OVMF code and OVMF variables, the deterministic
bootfs and ESP outputs, nonce, frozen digest
`5E4E054B5C244ACE`, bounded timeout, and measured page ceiling. The canonical
template intentionally leaves the not-yet-integrated Wyrmroot revision and
artifact digests as replacement fields; it is not itself an acceptance
request.

The strict provenance record binds the exact candidate and ABI tree, accepted
Rust revision, kernel and symbols hashes, and the three
`DEEPWYRM_DW1B_*` build values, including the measured page value used for the
kernel build. Its hash is itself request-bound. This proves agreement between
the accepted build record and inspected artifacts; it does not claim to infer
an unrecorded compiler invocation from an ELF file.

`cargo xtask dw1b run --request <request>` is the canonical bounded execution
command. It reuses the central one-CPU q35/OVMF Wyrmroot runner, creates fresh
run-local snapshots of the inspected ESP and exact OVMF code/variables, owns
the serial and stderr outputs, observes timeout/process status, and only then
writes an exact run receipt. The legacy `evidence` spelling performs the same
fresh run; it does not accept a caller-supplied receipt. Pre-existing run
products are rejected.

The run receipt binds the frozen request and both the main build receipt and
Wyr source-build receipt hashes, the actually booted ESP and bootfs hashes,
initial OVMF identities, serial-log hash and request-relative path, run
directory, timeout, observed QEMU debug-exit status 33, and `timed_out = false`.
The runner snapshots both receipts and bootfs before execution, derives the run
receipt only from those immutable run-local inputs, and after execution
revalidates that the live request, products, receipts, and G3 relations remain
unchanged. Mid-run mutation therefore fails closed without an evidence receipt.
A caller assertion or serial text alone is never evidence. Before execution,
the canonical G3 image inspector must prove that the request-bound ESP contains
the exact loader, kernel, bootstrap, and bootfs.
Product validation applies the native loader's ELF planning invariants to the
bootstrap and four ELF payloads, validates the loader as a bounded x86_64
PE32+ EFI application, proves loaded profile markers, and audits the exact
request-hashed hog steady-loop bytes. Acceptance additionally requires the
exact 122-byte `DWPRE1` with facts `000000FF` and an immediately following PASS
`DWTEST1` ID 26/detail zero.

The accepted separate-release four-entry archive measured 123840 bytes, 31
pages, and SHA-256
`08febb6e14463fa5c5d8c846ace725336eb6cac0bfd0a93370685076e3115f95` after
the native-linkage checkpoint `1ef846073970e0ec9c367fc14bd4c15a4478d15f`.
The frozen build contract is
the 31-page ceiling; a final acceptance request records the exact rebuilt
archive byte count and hash for its own clean Wyrmroot revision. This host
contract and tooling prepare the canonical checks but make no live selector-26
run claim.
