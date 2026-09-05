# WYR1-E3C/E3D construction and console-status validation

**Date:** 2026-09-05
**Status:** E3C/E3D and the E3 host/controller gate complete.
**Scope:** Transactional ShellV1 construction, registry preflight and cleanup,
WRCN status, and product-selectable consoled child behavior. E4 shell execution,
E6 product assembly and E7/E8 guest acceptance are separate gates.

## Baseline and authority

Root baseline: `16d70c447af582e09a413e434f94dfb00dba250c`.
Wyrmroot baseline: `eca3fd3c92c1e9d376e5fe1cb8d983a4a8fc9ba4`.
Deepwyrm remains `18c5b6abf52deb08d2d5ccc45b40896329dc8650` and generated ABI
pin `085b184c32ae1fa3d5ec322c86957dd5d036595c`. Rust remains
`a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`.
Root/Wyrmroot/Deepwyrm were clean at entry. The local preflight snapshot includes
later coordinator-only tooling edits, explicitly qualified in that record.

The [frozen wyrmsh contract](WYR1_E_WYRMSH_CONTRACT.md), especially sections 1-6,
the [E0 inventory](WYR1_E0_TRANSITION_INVENTORY.md) and reached
[E3A/B validation](WYR1_E3AB_LAUNCH_VALIDATION.md) govern the exact wire,
scopes, custody and card boundaries. Root bootstrap/recovery architecture and
Wyrmroot platform/bootstrap/registry/launch contracts remain binding. Reached
C/D and kernel validation records constrain preservation, not new guest claims.
No external source is adapted; parser/editor prior art is outside these cards.
New console protocol code follows GPL-3.0-or-later; existing bootfs GPL-2.0-or-later
and application component declarations remain unchanged.

## Implementation and join

| Change | Exact commit |
| --- | --- |
| Canonical model/native gates | `af550bf8db9c1a614957943e4bed9bffbf283fc5` |
| Registry receiver prerequisite | `d79496195dafbb58527049f2462bfcc1a111f454` |
| Controller gate subsets | `c684c50b963f9a7cd100376cfa723d5581dd23e1` |
| E3C controller and policy | `63daaf55d7cd5daf1969fa097ea92dd5cd64b7dc` |
| E3D status and consoled | `240f19dcf1cac57847301a05737aba5e0fe1c422` |
| Initial joined candidate | `46d7973449e131b1c849a56afc60bafd1375efa5` |
| Controller feature correction and poll regression | `a92d6f12677ac0921264b4829cf63ff78d97081f` |

The final source candidate is `a92d6f12677ac0921264b4829cf63ff78d97081f`.
All listed commits are unsigned; Wyrmroot author identity and Codex trailer are
preserved. Subsequent validation/licensing/index documentation does not alter
this tested source. No kernel ABI or dependency-pin change is involved.

### Registry receiver prerequisite

Before a valid INSTALL_CLIENT, registryd snapshots at most 64 installed
endpoints, probes each exact handle once with an immediate deadline, and then
retires every observed closed peer before installing the incoming endpoint.
READABLE cannot mask simultaneous PEER_CLOSED. State/probe/close/notification
cleanup failure terminates the generation and cleans the newly received endpoint.
There is no install acknowledgement or WRRG byte change.

The lane passed 15 tests, check, strict Clippy and formatting. Independent review
checked the native wait adapter against generated ABI revision `085b184c...`:
zero deadline means immediate evaluation and full signal state preserves
simultaneous readability and closure. Only TIMED_OUT is interpreted as an open
endpoint. Native compilation is separate from runtime guest validation.

### E3C controller

WRJP 1.1 adds the exact Wyrmsh profile2 entry, startup ABI2, fixed path and
content SHA-256 binding. Historical 1.0 policy encoding and ordinary launch
admission remain unchanged. The supplied controller context owns current registry
control, topology and finite poison/replacement state; request bytes cannot
select that authority.

ShellV1 reserves replay/job state, validates the four received endpoint roles,
installs a fresh BootstrapMetadata registry client, and drains its entire ordinary
ENUMERATE transaction1 before sending INIT. The preflight checks exact correlation,
page totals, consecutive indices, canonical records and absence of handles under
one bounded absolute deadline. It then installs an unpublished non-owning
ShellJobs connection, constructs the six-role Wyrmsh request, validates exact
READY and fresh RUNNING state, publishes the outer job, sends LAUNCH_ACCEPTED,
and releases bootstrap. The outer job remains the sole Process/TaskGroup owner.

Custody-aware rollback handles pre/post-MOVE failure, accepted-response loss and
cleanup failures. Failure after committed registry installation poisons that
generation. Terminal reap closes the old nested session before replacement;
old background jobs remain controller-owned orphans on their original connection.
Fresh registry, launch, status and child identities cannot rebind old authority.
Registry replacement state has a finite budget and requires a newer generation.

The host matrix exercises successful S1 construction, exact six-role INIT/READY,
terminal reap and fresh S2; registry precommit/postcommit failures; malformed
preflight; loader/READY/accepted-response failures; wrong request shape and
policy/scope; nested peer loss; independent identity freshness; orphan retention;
and bounded replacement exhaustion. A feature-selected test calls the actual
poll adapter through bootfs mapping, manifest/policy parsing and dispatch.

`wyr1e-shell-controller` selects the separate shell-aware adapter seam.
The historical resident loop remains selected by existing products. Choosing
this adapter, supplying its context and connecting the new registry/console
recovery path in the production resident loop remain E6 product assembly.
E3 proves the host actor/controller gate and native compilation, not a selected
production shell or guest recovery sequence.

### E3D status and consoled

The new GPL-3.0-or-later `wyrmroot-console-proto` crate is no-std,
allocation-free and syscall-independent. WRCN query/snapshot/error records are
exactly 48/160/56 bytes with zero handles. It validates explicit IDs, reserved
fields, generation relationships, canonical snapshots and transaction high-water
state. Correlatable malformed requests consume fresh transactions and produce
bounded errors; uncorrelatable input terminates the relationship.

Consoled creates one status pair per shell attempt and atomically MOVEs the child
endpoint with the three WRST endpoints. A failed send retains sender ownership;
a committed send never reclaims moved endpoints. Snapshots derive from one exact
local model observation. Old status peers close before replacement, and current
status loss is child-fatal. `wyr1e-wyrmsh` selects Wyrmsh behavior; the default and
historical selector32 select ConsoleEcho with the unchanged three-stream request.
WRCN is a separate endpoint, not a fourth WRST stream or a recovery command API.

## Review and correction

Scoped implementation and independent cross-review were dispatched to exact
`gpt-daybreak-blue-latest`, reasoning **high**, on **2026-09-05**. Reviews record
that explicit routing selection, not an independently introspected runtime model.
The registry implementation worker reported a conflicting generic self-description;
its output counts only as implementation/test evidence. A separate explicitly
routed Daybreak reviewer reviewed registry `d794961...` and found no open findings.

The same independent reviewer checked E3C `af550bf..63daaf5` and tooling
`da05270..c684c50` on joined `46d7973`. It confirmed one High acceptance-blocking
functional/tooling defect: the controller feature transitively selected the
freestanding native binary during host tests. The actual joined run failed with
allocator/unwind diagnostics; literal command-argument tests had missed the
Cargo feature closure. The unused staged poll entrypoint also needed an explicit
E6-boundary annotation for strict compilation.

Correction `a92d6f1` separates that feature from `native-init` while native checks
still explicitly select both. It adds an actual feature-selected poll-adapter
regression and the narrow staging annotation. The independent exact-diff recheck
resolved the finding without another source finding. E3C's author separately
reviewed E3D `af550bf..240f19d` on `46d7973` and found no concrete defect.
These are scoped E3 reviews, not the final E8/F security gate.

One nonblocking coverage limit remains explicit: consoled's native syscall
retry/timeout and correlatable-malformed adapter paths use codec/model coverage
plus source-contract checks, rather than a fully injected syscall transport test.
Native compilation does not turn those checks into guest execution evidence.

## Canonical validation

All checks use the canonical `tools/pinned-cargo` entry point, pinned host
Rust 1.98.1, locked/offline dependencies and project-owned outputs. Native checks
reuse the existing accepted Rust `a92dc7f...` verification, Wyrmroot target,
isolated scratch and exact flags. Each native feature selection uses a separate
Cargo invocation; no shell/selector32 feature union is tested as a substitute.

```text
tools/pinned-cargo xtask test host wyr1e3-model
tools/pinned-cargo xtask test host wyr1e3-clippy
tools/pinned-cargo xtask test host wyr1e3-native
```

The model suite passes **254 tests, zero failed/ignored** on `a92d6f1`, with
strict Clippy and scoped formatting also passing. All five native checks passed
in 181.32 seconds on that exact source candidate under the 600-second bound.
The five native selections are init with shell controller, registryd,
consoled with Wyrmsh, historical consoled selector32, and historical init selector32.

A broader seven-package regression on `46d7973` passed system-init, loader,
launch protocol, runtime, registry protocol, bootfs and xtask tests: **696 passed**
and one explicitly ignored accepted-toolchain probe (it requires an explicitly
supplied accepted compiler). The inspector ambient-PATH test separately runs
in a child process and produces one additional passing result line. No failure
occurred. Accepted compiler verification is covered by the canonical native gate,
not inferred from that child-process test. The final controller feature correction was
then covered by the joined suite above; the broader unrelated suite was not
repeated. The exact broad command is:

```text
tools/pinned-cargo test --locked --offline --lib --tests -p wyrmroot-system-init -p wyrmroot-loader -p wyrmroot-launch-proto -p wyrmroot-runtime -p wyrmroot-registry-proto -p wyrmroot-bootfs -p xtask
```

Tooling's three focused dispatch/selection tests and strict xtask Clippy passed.
The binary-only xtask lint command uses `--tests`; an initial incorrect `--lib`
was rejected and its log retained. Initial 60-second native checks timed out
before diagnostics while verifying the accepted compiler. The corrected registry
and consoled gates passed with 180-second limits; final joined native validation
uses a 600-second bound. This changes the timeout only, not verification rules.
Host checks remain bounded to 60 seconds. The rejected controller host selection
and its successful correction have separate preserved logs.

## Evidence and closure

Local logs, target state and preflight are under `.tmp/wyr1e-e3cd-20260905/`.
Worker logs were copied and hash-verified before retiring all three clean,
integrated lanes and deleting their merged branches. Strict affected-repository
lane audit reports zero lanes. These outputs are operator evidence, not tracked
source. `final-checks.json` records the exact source/pins, commands, exit codes,
source hashes and log hashes. No executable or media identity is asserted for a
Cargo check gate.

No VM was inspected or operated, and no persistent disk or domain configuration
was changed. No executable guest payload was host-executed. No new production
shell ELF, WRRM/product selection, selector33, E4 shell command behavior,
E6 assembly, E7/E8 guest acceptance or physical-hardware validation is claimed.

| Evidence file | SHA-256 |
| --- | --- |
| `wyr1e3-model.log` | `4ee4426d01d42431ba845ff850f1008f5177edd016eb6048ef6d304bc1101d02` |
| `wyr1e3-model-r2.log` | `5f4130c790ecedb094b20ba03a0835036cf1f21355a335b0512c0b55f73801af` |
| `wyr1e3-clippy-r2.log` | `9b524fc2e2e6293189cd0c6140caa73f13b045f6713405e9b9fbc543b76d9419` |
| `wyr1e3-native-r2.log` | `47fb4b36f305209f501cd1c9b6f171244a8bbeb9d2b9d8a528ce721de2d5bb76` |
| `default-regression.log` | `206fa6602378638388ab4b5afd6f349fb53791d21f8dc0793f8c5d1bc11fb0d3` |
| `final-fmt.log` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `lane-audit.log` | `5f45f923cbf08d03a2f943d5da2ebd45e1dd6a68dd144cd58036de79268dbab2` |
| `final-checks.json` | `a042c546e182ecb6eb6b398094c7b3bb87dadf197eea34c363d6db2c24bcc5b5` |
