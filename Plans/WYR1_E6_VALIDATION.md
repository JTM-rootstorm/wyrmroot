# WYR1-E6 production shell product integration

**Date:** 2026-09-05
**Status:** E6A/E6B complete at the selector-free native product gate.
**Scope:** E6A artifact/RRC/launch-policy freeze and E6B production console child
integration. Selector 33, EFI/ESP media and guest execution remain E7.

## Baseline and authority

Root baseline: `8cf126fede5588fb7934367a4ea244d6aac53a14`.
Wyrmroot baseline: `92698905fc5bb20ed735a9d5ee26641c2c5dfeaf`.
Deepwyrm remains `18c5b6abf52deb08d2d5ccc45b40896329dc8650`; Rust remains
`a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`; generated ABI remains
`085b184c32ae1fa3d5ec322c86957dd5d036595c`. All four repositories were clean
at entry. Operator evidence is beneath `.tmp/wyr1e-e6-20260905/`.

Required reading reconciles the active E6 card, the frozen Wyrmsh product and
stack contracts, architecture indexes, bootstrap/recovery authority, reached
manifest/bootfs/native-product builders and resident console/driver/registry
lifecycles. The independent authority lane reconciled all 21 named section-2
sources: only the architecture index changed since E5, to index reached E5.
Its ordered source manifest digest is
`e96720b5fed1251fd8f346e004af646f621e1c6cebec3ea0b6a38c392760dab5`.
Ion and linenoise remain concept-only provenance for unchanged parser/editor
code; they supply no native product or stack algorithm. No third-party code
is adapted by E6.

## Product and acceptance boundary

The frozen contract prohibits selector-33 registration, test-ID dispatch and
media before E7. E6 therefore freezes the normal native bootfs product and
explicit production shell ELF. E7 owns selector-only CPU-hog/nonzero/fault
actors and media. Normal `bin/hello` is the reached three-stream JobV2 hello,
with no fixture or directory-prefix authorization.

The canonical optional shell CPU-hog spelling remains `bin/cpu-hog`. The
historical selector-26 ELF uses a fixed Hello startup transaction and cannot
be repackaged as a dynamic JobV2 child. E7 needs an additive startup adapter
in the existing payload package that reuses the accepted no-yield body;
E6 does not modify its source or claim that the historical ELF is shell-ready.

The E6 gate also requires an exact selected-ELF call-chain bound within the
108 KiB downward working stack: 128 KiB mapped, less 20 KiB occupied by ABI2
startup. The active card now states this previously assigned obligation
explicitly. Host structure totals or a separately built diagnostic ELF cannot
satisfy it.

## Validation corrections and preserved evidence

A broad bootstrap test could not compile because its fake launcher omitted
`LaunchProfile::Wyrmsh` from the explicit unsupported-profile match. The
one-line test-only correction retains that rejection behavior. The failing
compile and the passing 29-test bootstrap run are preserved separately;
production bootstrap code is unchanged.

The historical xtask digest test assumed a pre-existing `target/` parent,
while the pinned launcher owns a different output directory in a fresh lane.
The fixture now creates its unique project-local parent. The complete xtask
suite passed after that execution-context correction.

Native stack analysis initially rejected real compiler patterns rather than
producing a partial pass. Independent review distinguished LLVM fixed-frame
metadata from transient outgoing argument pushes and required exact instruction
accounting. The accepted compiler supports `-Cjump-tables=no`; the production
shell uses this setting with `-Zemit-stack-sizes` to expose direct control flow.
A further machine-code cycle in precompiled core's detailed string-index panic
diagnostic cannot be ignored by assuming a Rust invariant. A bounded first-party
change replaces invariant-only string range indexing with `get(...).expect`
and a static message, preserving normal behavior and fail-stop semantics while
removing that diagnostic dependency. Its unchanged behavior suites and exact
native graph must pass before closure. Accepted Rust/core are not rebuilt.

## Production lifecycle join

The first selected native checks exposed one cross-file feature-propagation
failure class across init and devmgr. After the third compile failure, the
coordinator paused the fourth build and assigned complementary Daybreak lanes
to the immediate adapter and broader init/registry/product seams. The review
found reachable lifecycle defects that host source-string checks had missed:
driver detach did not independently prove client release, registry rebind reused
stale broker state, and driver construction preceded the required serial-ready
start edge.

The [E6 integration addendum](WYR1_E6_PRODUCT_INTEGRATION_CONTRACT.md) freezes
the coordinated remedy. The new production pair retains the existing CONNECT
direct control Channel as its exact client-lifetime witness, independently of
raw WRST handles and STREAM_DETACHED. Cleanup completes both sides under one
absolute deadline before accepting offers or replacing publication. Init
asynchronously observes the exact reserved serial publication through a fresh
scope-None WATCH, rechecks the exact driver is running, and closes the observer
before constructing consoled. Existing wire values and selector32 lifetime
selection remain separate. Executable evidence below binds the final source.

Independent review of the first witness implementation found three further
integration defects: the observer admitted any non-exited driver instead of
requiring RUNNING; co-ready publication READABLE/PEER_CLOSED handled an offer
before retiring the old registry generation; and fatal consoled loop exits
relied on process teardown instead of explicit raw-before-witness cleanup.
All three were corrected with executable regressions and independently
cleared before the accepted native attempt. The fourth native attempt compiled the normal component
set, then exposed historical consoled import/mutability cfg omissions. Those
are execution-context corrections. Later native checks exposed only borrowed
reference binding and historical devmgr cfg warnings; narrow reviewed fixes
completed the full ten-component matrix on the seventh attempt.

## Build-source derivation

The product producer received a separate independent review. Its receipt binds
the actual offline dependency bytes consumed, both ABI and syscall crate
paths, the accepted compiler, and the effective Cargo configuration. A Git
revision or clean status alone does not establish the actual checkout bytes:
the verifier accounts for hidden index flags and ignored extras. The
accepted local Cargo checkout uses a checkout-local Git directory, so testing
only a simulated shared database layout was insufficient. Final evidence
includes the read-only actual-checkout preflight, and the producer rejects
ambient configuration before build subprocesses run. Fixed Git calls disable
fsmonitor and ambient attributes, reject local configuration includes and
`info/attributes`, and reject unexpected successful-command stderr. The
regressions prove helper nonexecution as well as source-byte rejection. These
findings concern the verifier; no corruption of the accepted checkout was observed.

## Development stack result

The shaped accepted-compiler ELF is
`9d7f3ab7462488dd3f4db6226ef119516de7a2933c4441eeb331fc4f07f72101`.
An independent Daybreak reviewer regenerated the LLVM outputs and exact
analysis: 69,496 bytes of 110,592, leaving 41,096 bytes; 134 reachable functions,
123 with stack metadata and 11 accounted from disassembly. All 22,019
instruction lines parsed, with no unresolved reachable edge or stack cycle.
The report hash is
`7eab648da90518331e95650becba6013158cb2edc3c5f5126beaabb6eb83ea7f`.
The final freeze below reproduces and binds this exact selected ELF and report.

## Integrated source and executable gates

The combined source candidate is
`cca32f764e2b1b1532c0eabf00c66c2b1d19c94a`, clean before the freeze. Its resident
paths match reviewed `10b9fa5f4d3abb2bba741be0b9dcac98991d89a2`; its producer
paths match reviewed `2f12361027fccbf1296e92f8e928cab9a7f42b00`. Both independent
reviews explicitly used `gpt-daybreak-blue-latest`, high effort, 2026-09-05,
and closed their scoped findings. These are scoped E6 reviews, not final-F
security closure. Detailed review and log hashes are retained in
`review-receipts.json` and the preserved lane evidence directories.

Host gates use pinned Rust/Cargo 1.98.1. Native builds consume accepted
`RUST-WYR0-I-B-SYSROOTS-007`, toolchain `wyrmroot-1.97.1-a92dc7f7`, with exact
compiler/sysroot hashes in the source receipt. LLVM 22.1.8 tool identities
and the analyzer hash are bound in the stack report. No compiler, sysroot,
Deepwyrm source or generated ABI change is part of E6.

| Gate | Result |
| --- | --- |
| Integrated E6 model | 435 passing test executions; 1 intentionally ignored |
| Production init/devmgr controller model | 168 passed |
| E3 construction/registry/console regressions | 268 passed |
| Default init/devmgr/consoled/registryd/bootstrap | 302 passed |
| Launch protocol/runtime/loader/console-echo | 238 passed |
| Selected and historical native matrix | All 10 entries passed |
| Stack analyzer regression suite | 13 passed |
| E6, controller and E3 Clippy; formatting | Passed |

Rows overlap in package coverage and are test executions, not a count of
unique tests. The E6 total includes an isolated child-process regression. The
ignored host test requires an explicit accepted-compiler path; the native and
product gates exercise accepted-toolchain verification separately. Runtime host suites ran on `9bfccaf`; subsequent resident
commits only qualify native-bin mutable/conditional bindings and preserve
the tested library behavior. The final E6 model, Clippy and format gates ran
on the combined source candidate above. Native compilation ran on the exact
resident candidate with identical final runtime sources. The seventh native
attempt is accepted; earlier failures remain separately preserved. Its log
SHA-256 is `646f08b08a21d8523dc2aaefeaeca9331239cc0389556a19fa79a8451b23a105`.

Canonical host commands run from `wyrmroot/` through `tools/pinned-cargo`:

```text
tools/pinned-cargo xtask test host wyr1e6-model
tools/pinned-cargo xtask test host wyr1e6-clippy
tools/pinned-cargo xtask test host wyr1e6-controller-model
tools/pinned-cargo xtask test host wyr1e6-controller-clippy
tools/pinned-cargo xtask test host wyr1e3-model
tools/pinned-cargo xtask test host wyr1e3-clippy
tools/pinned-cargo xtask test host wyr1e6-native
```

Run the Python stack tests with `PYTHONDONTWRITEBYTECODE=1` to keep disposable
bytecode outside tracked source directories. Host gates have 180-second
bounds; formatting and Python tests have 60-second bounds. Product generation
has a 900-second outer bound and inspection has a 180-second bound.

Product output must be outside the Wyrmroot source checkout and inside
OS-Project. An initial source-local output request was rejected before build;
its log is retained as an execution-context failure. The accepted command
shape is:

```text
tools/pinned-cargo xtask wyr1e6 product --output ../.tmp/wyr1e-e6-20260905-products/freeze-a
tools/pinned-cargo xtask wyr1e6 inspect --product ../.tmp/wyr1e-e6-20260905-products/freeze-a
```

The second build uses fresh `freeze-b`. Both builds and inspections must use
the exact clean source candidate; a later documentation commit is a delivery
descendant, not the frozen source revision.

## Frozen product identity

Both fresh products and both standalone inspections passed at exact source
`cca32f764e2b1b1532c0eabf00c66c2b1d19c94a`. The bootfs is 756,460 bytes:
seven executable entries with mode 0555 and five immutable manifest/policy
inputs with mode 0444. The normal archive contains exactly 12 entries, and
only the two reached shell launch-policy entries. There are 21 published
files across artifacts, inspections and product receipts.

| Selected ELF | Bytes | SHA-256 |
| --- | ---: | --- |
| `artifacts/consoled.elf` | 102,104 | `16f9874dd2c09a484c9019bc3b4a3cab0a2deae533e113ca08920a78f627fd09` |
| `artifacts/devmgr.elf` | 83,944 | `0b4599c277038582879cab7d96ec2cd553155f815e750128148093788928b00b` |
| `artifacts/hello.elf` | 21,368 | `5acb3922032f522de84d6378af837260d8fbcb63fff22bd26299a8642bcd5ba6` |
| `artifacts/registryd.elf` | 73,736 | `3c75e3edaf27dd5457e433fdc1a5368c985a25469d6c70cdd954cb1646f3973b` |
| `artifacts/system-init.elf` | 310,928 | `22d8aa132c6a80768f72631b879fe40a48618938054b618467e9f5be4d424105` |
| `artifacts/uart16550d.elf` | 44,432 | `a6518f0293f7c88d816201d53661432345a8aa722409a25a9720c17972359a27` |
| `artifacts/wyrmsh.elf` | 116,592 | `9d7f3ab7462488dd3f4db6226ef119516de7a2933c4441eeb331fc4f07f72101` |

| Product record | SHA-256 |
| --- | --- |
| `inspections/wyrmsh-stack.json` | `7eab648da90518331e95650becba6013158cb2edc3c5f5126beaabb6eb83ea7f` |
| `product/bootfs.img` | `e65c49c78c99a9f39976de9c65384bc6743f14e55e4d0fc06a40dc8cc7737c33` |
| `product/e6-source-build.toml` | `7df2550df8b16a316ac9d30246f4a59f7e7f88db6977da8090a5b4c83717a819` |
| `product/freeze-receipt.toml` | `0507062b98e26ef62f1d65dcff73ffd3b0418935c1f08ad42b128579115c10bc` |
| `product/launch-policy-e6-v1.bin` | `c6fdfdb2ac69c62cad2acbd287c15de3e937393c24800e711ca95f707561888e` |
| `product/rrc-e6-v1.bin` | `cebdcc2ac92fb217406666aa45198bdd6e71dc80cd42a0fb854374eba594ad16` |
| `product/wrdm-e6-v1.bin` | `dad5ae4786416464ebe3b571bb434dad4721dd172ed47c378d7bced2ca5e97ac` |

The selected shell matches the independently measured development ELF exactly.
The exact bound is **69,496 / 110,592 bytes**, with **41,096 bytes** remaining.
The independent reviewer repeated the analyzer on the selected bytes within
project-owned scratch and reproduced the 47,191-byte report exactly. WRRM role
5/profile 4 binds this shell, and WRJP binds the ordered `bin/hello`
profile 1/ABI2 and `system/wyrmsh` profile 2/ABI2 entries, each with three
streams and its exact ELF hash. Independent raw archive parsing also verified
entry order, modes and embedded bytes against the published artifacts.

## Workflow deviation

The independent reviewer initially created three copied scratch files in a
host temporary directory outside the project write boundary. Those files are
excluded from acceptance evidence. The analyzer was rerun inside OS-Project
and produced the identical report; that project-local run supplies the final
review evidence. The external scratch remains untouched pending Mike's exact
cleanup authorization. No network transfer or guest execution was involved.

## Closure and handoff

Both fresh freezes passed their own reopen verification and standalone
inspection. Direct comparison and independent review prove the exact same
21-file set, every byte, size and 0400 publication mode. Both inspect logs are
byte-identical with SHA-256
`b2ec5cf41a21a14a27b48dd8317300e94c3e4c3ddd55e4b41497f7a269fa0187`.
`freeze-comparison.json` records every file and the four successful gates.

Implementation lanes are retired, their evidence is preserved, and the strict
Wyrmroot/Deepwyrm/Rust audit reports clean canonical checkouts and zero lanes.
All E6 implementation and integration commits are unsigned. This validation
record and architecture-index update form a documentation-only delivery
descendant of the exact frozen source revision; they do not change its code,
Cargo configuration, ABI pin, compiler, or accepted artifact bytes.

E7 is next: add the selector-33 actors/media and canonical COM2 interactive
runner, then execute the named UP/SMP guest sequence and later recovery gates.
Use the frozen E6 source/product identity above as the reached prerequisite.
No selector-33 registration or guest acceptance is implied by E6 closure.

## Nonclaims

No VM is inspected or operated. No kernel, Rust-fork, selector registry,
physical hardware, guest command behavior, interactive acceptance, final-F
security closure or DW1/WYR1 completion is claimed by this static phase.
