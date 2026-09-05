# WYR1-E4A/E4B production shell runtime and local builtins

**Date:** 2026-09-05
**Status:** E4A/E4B complete; E4C and full E4 remain pending.
**Scope:** Separate production wyrmsh crate, validated startup/READY/release,
WRST editor loop, normal EOF/exit, and help/echo/clear. E4C inspection commands,
E5 jobs, E6 product assembly and E7/E8 guest acceptance are later cards.

## Baseline and scope authority

Root baseline: `30ed9cc1bcd2df532cc3d8b69ebd85ebd0518354`.
Wyrmroot baseline: `5e7aeb642cfa76d8617f6fd97978261a994e4056`.
Deepwyrm remains `18c5b6abf52deb08d2d5ccc45b40896329dc8650`; Rust remains
`a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`. Generated ABI remains pinned to
`085b184c32ae1fa3d5ec322c86957dd5d036595c`. Affected repositories were clean
at entry; the preflight receipt records subsequent coordinator tooling edits.

The active plan's section 7.3 fine-grained cards define this request. Its older
high-level graph mislabeled E4A/E4B; the graph now agrees with the card table. Full E4 remains pending until E4C services/tasks/status is complete.
The frozen shell and E2 editor contracts, E3 construction/release contract and
root bootstrap/recovery architecture govern the runtime integration.

The retained stub remains historical product source. Creating the production
crate does not install it into a selected product or replace a selector32 input.
No kernel, ABI schema, compiler, product or VM change is required for this slice.

## Canonical validation commands

Tooling commit `17c960b73d3ed539aac22143f1ecf07616025535` adds:

```text
tools/pinned-cargo xtask test host wyr1e4-model
tools/pinned-cargo xtask test host wyr1e4-clippy
tools/pinned-cargo xtask test host wyr1e4-native
```

The model/lint commands select the production shell library/harness and pure
shell core without a native binary feature. The native command uses the existing
accepted-compiler helper with package `wyrmroot-wyrmsh`, binary `wyrmsh`, feature
`native-wyrmsh`, no default features and the exact Wyrmroot target. It retains
accepted-artifact verification, isolated scratch, offline/locked dependencies
and warnings denied. This is compilation, not a guest execution or media build.
Host commands have a 60-second bound; native verification has a 600-second bound.
The two focused tooling tests, strict xtask Clippy and formatting pass.

## Required-source disposition

Required-source receipt: root `30ed9cc...`, Deepwyrm `18c5b6a...`, and Wyrmroot
`5e7aeb6...`, with subsequent tooling-only canonical `17c960b...`. All local
sources named in active section 2 were reconciled as architecture/reached
context: root AGENTS/licensing/recovery and predecessor plans; development
workflow/D6 boundary; Deepwyrm architecture, scheduler/resource/interrupt
contracts and C/D/E validations; Wyrmroot platform and supervisor/registry/
coordinator/console contracts and reached validation records. No required E4A/B
source was unavailable. Deepwyrm is a reached dependency, with no new primitive.

The source-reading lane reconciled the active-plan sections 2/3/7.3, root
bootstrap/recovery and reached dependency records with the frozen shell, E2
editor and current E3 interfaces. `hello::run_job_hello` supplies the existing
post-READY peer-close release precedent; console-echo's immediate bootstrap
close is not the Wyrmsh release contract. The runtime stream wrappers and
current pure parser/editor are reused directly.

The exact clean linenoise checkout at
`a473823d74b93eab2ba83480df16ed37617493f2` was read again for this integration:
`linenoise.c` SHA-256 `4bc28faf2a46ccaea11d07aa056e21aa2e9a748b4dc6962346a3f658593103a8`,
`linenoise.h` SHA-256 `5f94c6295e3b62e0f8b4b62b0a2f351433d0b6b21029607aec0c9abbc60acff7`.
It is concept-only precedent for edit/feed boundaries, history/cursor behavior,
minimal ANSI and clear/redraw sequencing. No code is adapted. Its file
descriptors, termios/ioctl, heap growth, terminal-width probing, blocking partial
escape reads and one-shot writes are not imported. E4 instead retains the E2
incremental decoder and preserves output suffixes through NativeOutput.
Ion's named parser files are E1-only prior art; E4 consumes the reached E1 core
without a new parser or adaptation. Existing core Unicode provenance is unchanged.

## Shared runtime seam

The existing native entry parser validates startup ABI1/ABI2 but discarded that
version from the safe `StartupBlock` view. The coordinator authorized a narrow
accessor in the existing runtime startup module so wyrmsh can require ABI2 before
READY. The shell uses the shared entry path; it does not duplicate an unsafe
entry shim or alter the ABI. The runtime keeps its existing GPL-2.0-or-later
license, while the new first-party shell uses GPL-3.0-or-later.

## Implementation and validation

Implementation commit `502b362524e9f5666febd8a713469fe6c9ea08db` adds the
separate `wyrmroot-wyrmsh` package and the narrow runtime accessor. The library
is no-std and forbids unsafe code. Its native binary is a thin adapter to the
existing entry/syscall runtime; fixed parser/editor/history and stream storage
are reused. No dynamic allocation, libc, host terminal or new service dependency
is added to shell execution.

Startup requires ABI2, exactly `system/wyrmsh` argv0, no extra arguments or
environment, exact Wyrmsh INIT and six final-role Channels, and fresh capability
metadata. It retains the full correlation tuple for later scoped commands.
After constructing bounded local state it sends exact READY, observes clean
bootstrap peer close, closes its bootstrap endpoint and only then emits the
first prompt. Each generation owns and closes its received endpoints.

The editor consumes NativeInput without losing a following submission in the
same WRST record. Decoder state spans fragments. A bounded receive facade caps
empty-record processing at eight per turn so health checks regain control.
Redraw and builtin output retain the uncommitted suffix through NativeOutput
backpressure, with combined waits including required control/output peers.
Ctrl-D on an empty line and `exit` return success; physical stdin EOF and required
endpoint loss are typed generation failures. Submission/parser/usage errors
redraw without a registry, status or launch command side effect.

`help` iterates the compiled command metadata; `echo` writes parser-produced
arguments separated by one space plus LF, preserving empty operands and doing
no second escape pass; `clear` writes ANSI clear/home then a fresh editor frame.
Inspection and job commands report unavailable until E4C/E5. The eleven-command
help table is a usage inventory, not a claim those later adapters are implemented.

The coordinator's initial joined suite on `502b362...` passed **55 tests**
(11 shell harness and 44 core tests), strict shell/core Clippy and formatting.
The wider runtime/loader/hello/console-echo/system-init regression passed
**377 tests**, zero failed/ignored, including runtime compile-fail documentation
tests. Runtime's own accessor suite passed 116 tests in the implementation lane.

The native package initially used a global `unsafe_code=forbid` lint, which
rejected the shared entry macro's existing scoped allowance (E0453). The package
now uses the established `deny` setting, while the library still has its own
`forbid`. No new unsafe implementation was introduced. A host Clippy
collapsible-if diagnostic was also corrected. Both were operational build/lint
corrections; no host runtime test failure was observed at that checkpoint.

The author's native check passed after that correction. Its failure/success
records are explicitly labeled tool-output transcripts reconstructed after the
calls, not direct process-redirection logs. The coordinator recorded separate directly captured checks against committed
source; the final-source result below is authoritative.

## Independent review and correction

Implementation and independent review used explicitly selected
`gpt-daybreak-blue-latest`, reasoning **high**, on **2026-09-05**. Source scope
is `17c960b..502b362` and follow-up `502b362..e3ec381`; tooling scope is
`5e7aeb6..17c960b`. This is a bounded E4A/B review, not the final E8/F gate.

The initial short-output test exercised zero-progress WOULD_BLOCK, but did not
exercise a short successful return after a previous WRST packet committed.
Both coordinator inspection and independent review identified that missing
integration case. A new 4091-byte echo fixture blocks its second DATA packet.
Its failing-first result exposed a Medium contract defect: `write_all` advanced
the committed offset and retried immediately without the required combined
capacity/control wait. Output remained byte-correct. A persistent capacity
failure would wait on the next zero-progress attempt, so this was one eager
retry per partial-progress race, not an unbounded-spin or duplication finding.

Correction `e3ec381ad938959735fc50d7bda504d26f36bbf3` waits whenever a positive
return leaves an uncommitted suffix. Two added regressions compare the complete
output after second-packet backpressure and prove registry-peer loss wins at
that partial-progress wait. The direct failing log SHA-256 is
`967ca3ea12c83d999b83a8d9dd90ae327052310e915977ae1a3d46feb67ff53d`;
the focused two-test passing log is
`7ba43d8b4375bce3853b2e7be4471ad522a41f7911eac3ba30ce934c23a90903`.
Independent exact-diff review closed the Medium finding with no further source
finding. Final reviewed lib/test hashes are
`991b4877c74376c2bac15a35b953e86ba8997df5f73d1760fc80d65f75c60a56` and
`8bcf11a39816620d3da27d0c35bb7d08c9428038e73e5bfd93fa34b0d8321d09`.

The final source candidate is `e3ec381ad938959735fc50d7bda504d26f36bbf3`.
Its coordinator model suite passes **57 tests** (13 shell + 44 core), zero
failed/ignored, and strict Clippy passes. The unaffected broader 377-test suite
was not repeated after the two-file output correction. The initial directly
captured native check passed on `502b362` in 127.55 seconds; the production
library correction invalidated it as final-source evidence, so it is retained
as an earlier checkpoint. The fresh native check on `e3ec381` passed in **127.76 seconds**, using the same
accepted compiler and 600-second bound. Final formatting also passed.
The implementation worker's duplicate final-native attempt was canceled with
exit130 and no output; that empty log is incomplete, never a passing result.

## Closure

The final native check and formatting pass. All changes are local and unsigned
with the configured author and exact Codex trailer. The worker lane was clean,
integrated and inactive; logs were copied/hash-verified before retiring it and
deleting its merged branch. Strict Wyrmroot/Deepwyrm audit reports zero lanes.
Historical retained stub, consoled source/feature identity and frozen contract
hashes match the preflight preservation manifest.

`final-receipt.json` records exact source/pins, source hashes, command arguments,
exit codes and log hashes. No selected ELF/media identity is asserted for a
Cargo-check gate. The safe startup accessor's runtime regressions and existing
loader/hello/console-echo/init tests preserve both historical startup versions.
The real loader queues INIT before starting the child thread; independent review
confirmed that immediate INIT receive is compatible with that reached sequence.
Only output after READY and clean peer-close release is accepted by the harness.

Local operator evidence is under `.tmp/wyr1e-e4ab-20260905/`; it is excluded from
commits. The native shell's complete stack/call-chain and selected artifact
acceptance remain E6; host memory or compiler checks alone do not establish them.
No VM state is inspected, no guest payload is host-executed, and no interactive,
physical-hardware, final security-gate or WYR1 completion claim is made.

| Evidence | SHA-256 |
| --- | --- |
| `final-model-r2.log` | `e4cadac1356057f701d0caad6c262e76ebaa2de91c59f928f183f3cdd3d4ca43` |
| `final-clippy-r2.log` | `83fd3260a0fb9d701bc672b322538cd96d8de79fcd26f28f6612e67d54f0a409` |
| `final-native-r2.log` | `4a22ac52e1a68700eeb1acba1f9d260997f8f02e2863e6c8920553df89aa88d3` |
| `final-regression.log` | `c69b021800470580d99b72892607c9f8143facc963585f70f3c5ff7568fc71c0` |
| `final-fmt-r2.log` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `lane-audit.log` | `126175e997da0624df322a00e4321d2f0644ca9196931c80e38545e3ac400111` |
| `final-receipt.json` | `56df43003faa1ca94a0d305fc7547a96953cf677077c5f26765376444fafeb3f` |
