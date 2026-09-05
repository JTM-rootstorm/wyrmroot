# WYR1-E3A/E3B launch protocol and loader validation

**Date:** 2026-09-05
**Status:** E3A/E3B complete; full E3 remains E3C/E3D.
**Scope:** WRLJ 1.1 ShellV1 and immutable launch-session scopes (E3A), plus
WRLP 1.11 Wyrmsh and the dedicated six-role loader boundary (E3B).

## Baseline and authority

Root baseline: `9074a392da359fb55fc264d9e1aef05a1710c129`.
Wyrmroot baseline: `526da0950d7caa3f3212ecddfb14283e4ca3b206`.
Deepwyrm: `18c5b6abf52deb08d2d5ccc45b40896329dc8650`.
Root, Wyrmroot and Deepwyrm were clean at entry. The source-bound
[E0 transition inventory](WYR1_E0_TRANSITION_INVENTORY.md) and sections 1-3 of
the [frozen wyrmsh contract](WYR1_E_WYRMSH_CONTRACT.md) govern these cards.
Preflight found WRLJ type 16, WRLP minor 11 and role 16 still unconsumed.
No kernel ABI or generated dependency pin changes are required by this scope.
Generated bindings remain pinned to Deepwyrm
`085b184c32ae1fa3d5ec322c86957dd5d036595c`; the Rust fork remains
`a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`.

The host launcher remains `tools/pinned-cargo`, using hash-verified Rust 1.98.1
and locked/offline dependencies. Each implementation lane owns its target/log
outputs. Native compiler and guest validation are separate evidence classes.
E3 preflight corrected the E2 validation's recorded Clippy invocation from
`--all-targets` to the actual `--lib --tests`; the E2 result/hash is unchanged.

## Required-source receipt

All local authority was consumed at the baseline identities above. The active
plan and frozen E0 contract resolve all new IDs; no local convention replaces
them. The source-reading lane reconciled the wider set while implementation
lanes consumed the actual protocol, dispatcher, loader and caller paths.

| Required set | Disposition |
| --- | --- |
| Root `AGENTS.md`, `LICENSING_POLICY.md`, active WYR1E/DW1F/WYR1F plan | Binding scope, repository/lane and execution boundaries; component licenses retained |
| `BOOTSTRAP_AND_RECOVERY_ARCHITECTURE.md`, Wyrmroot platform conventions | RRC-A static closure, capability possession, exact generations and finite recovery; no new kernel mechanism |
| Root interactive-shell and DW1E/WYR1D plans; development-workflow and D6-boundary records | Native shell/console split, historical-product preservation, host/native evidence separation |
| Deepwyrm architecture, scheduler/resource/IRQ contracts and permanent C/D/E validations | Reached dependencies only, preserving their exact tuple and QEMU-only claims |
| Wyrmroot architecture, bootstrap-supervisor, WYR1-B registry/launch, WYR1-C coordinator and WYR1-D stream/console contracts and D validation | Controller-owned scope, replay/job bounds, READY/reap and historical profile/stream semantics |
| E0 contract and source-bound transition inventory | Separate WRLJ1.1 entries, six-role WRLP1.11, all hidden capacity sites, MOVE ownership and E3C/E3D boundaries |
| Current launch/registry/stream protocols, loader/runtime, system-init/registryd/consoled | Existing wire and transaction composition; no replacement protocol or ambient authority |
| Retained wyrmsh stub and selected-product identity | Preservation only; no production shell template |
| linenoise `a473823d74b93eab2ba83480df16ed37617493f2`; Ion `1440704f7456fa4c9f873b7b17dd4f0369b0c4ab` | E1/E2 parser/editor prior art is not applicable to these launch/loader cards; no adaptation |

No external code is adapted. Launch protocol and system-init retain
GPL-3.0-or-later; loader retains its existing GPL-2.0-or-later boundary.
No required E3A/B source was unavailable.

## Implementation and validation

### E3A protocol and scope candidate

E3A commit: `9251a1ce4dda93823cefb3eac8449cd5cef0fba7`. It changes only
the launch-protocol library and system-init's session/dispatcher modules.
Minor-1 request/reply entry points are separate from the unchanged minor-0
job protocol. ShellV1 request encoding fixes type 16, 128 bytes, four roles,
`system/wyrmsh`, ABI2 and WRJP profile2. Replies are 56 bytes and handle-free.

Installed sessions store an immutable Historical, ConsoleLauncher or ShellJobs
scope. Historical callers retain the existing installation wrapper and behavior;
ConsoleLauncher rejects ordinary LAUNCH, while ShellJobs admits only the named
payload paths before the existing immutable policy/content checks. Scope comes
from installed controller state, never request bytes. Intake admits four handles
for ShellV1 without changing ordinary zero/three-stream launch semantics.

The dispatcher uses the corresponding versioned reservation/reply path,
records fresh correlatable transactions before semantic rejection, validates
received/fresh handle metadata, and closes received endpoints on rejection.
A well-shaped ConsoleLauncher ShellV1 currently ends in minor-1 LoaderFailure
after cleanup: E3C policy/content verification and construction are absent.
It does not publish a job or claim successful shell admission. One-live-shell
and authority mint/install/READY/replacement enforcement remain E3C.

Lane package tests passed (13 launch-protocol unit, 15 E0 model, 108 init unit,
and 14/7/16 init integration tests), along with pinned formatting and strict
Clippy. Local copied logs are `.tmp/wyr1e-e3ab-20260905/e3a-*.log`.

### E3B loader candidate

Initial E3B commit: `f788b3bf83d49ce85480d0347635bfb58d4d6e7e`, integrated
by fast-forward from the baseline. It changes only loader source/tests; the
native runtime adapter already forwards explicit byte/transfer slices and
requires no change.

`LaunchProfile::Wyrmsh` selects WRLP 1.11, a 160-byte INIT with roles
`[8, 9, 10, 16, 6, 7]`, nine nonzero correlations, and the existing 40-byte
profile-exact READY envelope. Generic INIT cannot manufacture a Wyrmsh record
without correlations. `WyrmshLoadRequest` names all six endpoints and fixes
ABI2 argv to `["system/wyrmsh"]` with an empty environment. The dedicated
error reports custody for each of the six endpoints across the atomic INIT MOVE.

Capacity changes include the six-entry launch maximum, delegated-channel
transaction storage, transfer descriptors and rollback traversal, plus INIT
scratch sized for 160 bytes. Existing profiles retain their individual counts,
role order and bytes; ordinary JobV2 streams remain zero or three.

The lane passed 71 loader tests, pinned format check, loader check and strict
Clippy (`--lib --tests -- -D warnings`), plus runtime lib/tests compatibility
check. Local copied logs are under `.tmp/wyr1e-e3ab-20260905/e3b-*.log`.
Independent cross-review and final combined checks are recorded below.


## Joined review and regression

Initial joined candidate: `ee99005747bd60c5b4466d313067b8f7bd191872`.
The initial seven-package combined suite passed, but independent Daybreak
cross-review identified a Medium correctness defect in the E3B candidate:
it rejected equal numeric values for the independently allocated WRLP and
outer-WRLJ transaction namespaces. Two legitimate allocators can both issue 1.
`TransactionAlias` and its equality checks incorrectly rejected that case before
construction; the initial test suite froze the same mistaken requirement.

The failing-first equal-counter encoder/parser and loader regressions both
failed with `TransactionAlias`. Correction
`38c18e4f9554db9efd3900cee8207a4db5e015c0` removed the enum variant and three
equality rejection sites while retaining all nonzero checks. Both regressions
then passed and assert the exact `(WRLP transaction, outer WRLJ transaction)`
wire tuple `(1, 1)` at offsets 24/152. Distinct namespaces require independent
controller binding, not numerical inequality; E3C remains responsible for binding.

The final source candidate is
`c1cffb32181645bdffd446fe5cd70bee2afdb2b2`, joining E3A, E3B and this correction.
An independent recheck of `f788b3b..38c18e4` on that candidate resolved the Medium
finding. No open concrete finding remains in the E3A/B scopes.

All substantive security implementation/review used exact
`gpt-daybreak-blue-latest`, reasoning **high**, on **2026-09-05**. The E3A author
self-reviewed `526da09..9251a1c`; the E3B author independently reviewed the same
E3A diff on `ee990057`. The E3A author independently reviewed E3B
`526da09..f788b3b`, identified the Medium issue, and rechecked `38c18e4` on final
`c1cffb3` after the E3B author implemented/reviewed the correction. Reviews were
bounded to these source/contracts, not the final E8/F gate.

One nonblocking coverage gap is explicit: native dispatcher tests do not directly
mutate ShellV1 major/minor or zero outer identity and assert uncorrelatable
cleanup/no reply. Codec tests cover these parser cases; the reviewed dispatcher
uses those parser paths. No exhaustive malformed-input coverage is claimed.

## Final combined checks

The coordinator ran the following on `c1cffb3`, with task-local
`WYRMROOT_PINNED_TARGET_DIR`, pinned Rust 1.98.1, locked/offline dependencies,
and a 60-second timeout per command:

```text
tools/pinned-cargo test --locked --offline -p wyrmroot-launch-proto -p wyrmroot-loader -p wyrmroot-runtime -p wyrmroot-system-init -p wyrmroot-consoled -p wyrmroot-console-echo -p wyrmroot-bootfs
tools/pinned-cargo clippy --locked --offline -p wyrmroot-launch-proto -p wyrmroot-loader -p wyrmroot-runtime -p wyrmroot-system-init -p wyrmroot-consoled -p wyrmroot-console-echo -p wyrmroot-bootfs --lib --tests -- -D warnings
tools/pinned-cargo fmt -p wyrmroot-launch-proto -p wyrmroot-loader -p wyrmroot-system-init -- --check
```

All passed: **452 tests, zero failed and zero ignored**, including four runtime
compile-fail documentation tests; strict Clippy and formatting also passed.
The package/model/loader/source-contract suite covers additive golden and malformed
vectors, historical profile counts/order/rights, ABI2 geometry, six-role transfer
and pre/post-MOVE failure custody, old launch policy and console behavior. These
are host checks; no native target build, product or VM run is claimed.

Full local evidence lives in `.tmp/wyr1e-e3ab-20260905/`; `final-checks.json`
records exact commands, source HEAD, return codes and log hashes. Logs/targets
are local operator evidence and are excluded from commits.


| Evidence file | SHA-256 |
| --- | --- |
| `preflight.json` | `88e86fff88406babaf86fb09ae82d065c8ed498a3eb4d8e15f3c920cf239aac6` |
| `e3a-package-tests.log` | `b42749b6b0f0a01d252c0b91bd72e4138944da77864c62fbcc39fe0f10199673` |
| `e3a-clippy.log` | `ac98105dee17b0c4750caed026ef53faeed8b5d1d109d6de6387a6d2d6f474df` |
| `e3b-fix-red-launch-equal-namespaces.log` | `cc3171d8385ba026e28af2204485461dc3a58b1e96feb9d8937121350ebbb982` |
| `e3b-fix-red-process-equal-namespaces.log` | `acc2e34c17d4e4649998525e065ce71d93ed34b8c68439e296d33ffbbc37979b` |
| `e3b-fix-green-launch-equal-namespaces.log` | `3697c8a08a549358fb5af0c80de81252e7150f45fb8106c39b011f8e5072d90e` |
| `e3b-fix-green-process-equal-namespaces.log` | `5b0baf0fb8e928752fec7e1525670df6fa6e420c659760ccdfeb9de5a3d916b7` |
| `e3b-fix-package-test.log` | `2ad5cc3acb359a403bedbdc1b41092d940cba063bd53de9a18da142628e2904a` |
| `final-combined-tests.log` | `a960063f1a04fe6215620975cd9be32684f7eaa34d84c90e58fcfde28b85427e` |
| `final-clippy.log` | `c7c11f6bd521955e4ec1e9417eb1afa5848b8ef73f34ae8f3af28cafd1a94331` |
| `final-fmt.log` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `final-checks.json` | `024077531af9d14ac4be4aead75c7ac26f36b732278634e180ce24a9212cd3c8` |
| `lane-audit.log` | `6386522aef76a155c32d1d94a871d47e9c41eae626ddc28e000d82caddf2f80e` |

### Reviewed source identities

| Source/test file | SHA-256 |
| --- | --- |
| `crates/wyrmroot-launch-proto/src/lib.rs` | `1f479ebd4b4d8ca9caf8fab1550198c1c39d51bf49b34190f0424bcdd8a00361` |
| `crates/wyrmroot-loader/src/launch.rs` | `02f7f79cdaa304baf33a0b860303b1d10df83c54c7380f5884d959607a13b0e3` |
| `crates/wyrmroot-loader/src/process.rs` | `134e7b833a64c172ad3e0c065110f1344232afd79054aca64356fe6027e7e1ae` |
| `crates/wyrmroot-loader/tests/launch.rs` | `b122dd13a7c3db65e5c11ce14903266cc674fb2f834a4757a3a777902fc8f4ba` |
| `crates/wyrmroot-loader/tests/process.rs` | `e4d79238fb2b1cd57317c89e34c308dca6832bf88fd8269f8caca5cbb5a03329` |
| `crates/wyrmroot-loader/tests/source_contract.rs` | `e976d35afd7e2c2d7853894f5675ea18e13525af983e96e756e32cb25bf62d28` |
| `userspace/system-init/src/wyr1b_job.rs` | `c8ecf16ea2b30c64ee269cd3517907a2c11b0a956b55b6c064bf8775131c3d76` |
| `userspace/system-init/src/wyr1b_native.rs` | `0230c807ed59aef263dba386ca9019353f6b7603abb294a3e1cf7ef200fb1548` |

The frozen E0 contract remains unchanged at SHA-256
`ad8827658368dca9b8bb077acdf4f44bd7c2c7eea494b3007e2add81b82e39aa`.
The later delivery commit adds documentation only; the source identity above
is the exact reviewed and tested candidate.

## Integration and cleanup

Both lanes were integrated without source conflicts. Source commits and merges
are unsigned, retain the configured author and include the required Codex
coauthor trailer. Their logs, including red/green regression evidence, were copied
and verified before retirement. Both clean inactive lanes and merged branches
were retired; pruning found no stale registration, and strict `--expect-none`
Wyrmroot audit passed. Empty lane directories were removed. Deepwyrm, generated
ABI pins, Rust, runtime adapter, products and historical shell actor are unchanged.

## Scope boundary

E3A/B do not mint/install the shell's registry or nested launch endpoints,
construct the complete E3C controller transaction, implement WRCN/consoled E3D,
replace the retained shell, select a product, or run a VM. Full E3 acceptance
requires E3C/E3D and the six-authority READY/reap/replacement model on their
joined candidate. This record must not be treated as full E3 or WYR1-E closure.
