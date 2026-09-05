# WYR1-E0 transition inventory and validation

**Date:** 2026-09-05
**Scope:** E0A source/ownership inventory, then E0B contract and host model.
**Status:** E0A and E0B complete; contract/model gate accepted on 2026-09-05.

The [wyrmsh contract](WYR1_E_WYRMSH_CONTRACT.md) freezes the next behavior.
This record identifies the reached source paths and gaps that informed it.
All source anchors below refer to the baseline revision, not future E3 code.

## 1. Measured preflight

| Input | Measured identity |
| --- | --- |
| Root | `d242293d7ca4fb9d2a8dae4d693c332288e79ce5`, clean at start |
| Deepwyrm | `18c5b6abf52deb08d2d5ccc45b40896329dc8650`, clean |
| Wyrmroot | `6e7830c83806ac39f22840e8983d68591041a053`, clean at start |
| Accepted implementation pair | Deepwyrm `784adb253ff4c0065b8b85e05b938f374a139e96` + Wyrmroot `f95262f832f0efbe42cf9359462bca261a6a5b58`; both verified ancestors |
| Generated ABI revision | `085b184c32ae1fa3d5ec322c86957dd5d036595c` in current dependency manifest |
| Generated ABI tree | `a9b067107ec38e2be44630f4dce428dab0f48de8`, independently resolved from Deepwyrm Git |
| Rust fork | `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`, clean |
| Accepted native compiler | `rustc 1.97.1-dev (a92dc7f74 2026-08-22)`, LLVM 22.1.6 |
| Host compiler | `rustc 1.98.1 (48a229cea 2026-09-01)`, full commit `48a229ceaefd4985c50990b14116b6d856af0985`, LLVM 22.1.8 |
| Host Cargo | pinned `1.98.1 (797e8a9bc 2026-08-05)` |
| Host launcher | `tools/pinned-cargo`, identity `toolchain/host-rust-toolchain.toml`, offline project Cargo home |
| Worktree preflight | strict zero-lane audit passed for Deepwyrm/Wyrmroot; no retained unregistered exception |

The accepted native manifest is
`../../artifacts/toolchains/accepted/RUST-WYR0-I-B-SYSROOTS-007/manifest.toml`,
SHA-256 `cc78368219552cce8fdaad38ab419040cab945fe175aa774d6dca51eece84fd2`.
All 20 artifact hashes listed by that manifest were independently recomputed
and matched; its stored `passed` strings were not treated as new evidence.
The E0 check did not recompute the manifest's entire toolchain-directory tree
hash or build any guest artifacts. Current host-tool identities are verified
by the pinned launcher before every test run. The native compiler is separate
from the host 1.98.1 repin.

Task-local log: `.tmp/wyr1e-e0-20260905/preflight.log`. That later log includes
the coordinator's new untracked contract draft; the initial repository status
was clean, with no overlapping user edits in planned paths. No VM inspection
or operation occurred. Historical accepted guest results remain bound to the
older exact pair, not these maintenance descendants.

## 2. E0A current transition table

Paths in this table are relative to Wyrmroot. Functions identify the boundary
more durably than line numbers; numbers are baseline navigation aids.

| Transition | Source and current behavior | E0/E3 consequence |
| --- | --- | --- |
| Issue registry/launch identity | `userspace/system-init/src/wyr1b.rs:23-87`, `RegistryTopology::issue/restart`; fresh endpoint IDs, current endpoint generation 1 and caller role generation | Preserve distinct registry/endpoint/connection/child generations; no role-selected scope |
| Mint/install registry client | `wyr1b_native.rs:596-642`, `install_client`; encodes WRRG INSTALL_CLIENT and MOVEs one registry-side Channel | Current helper hardcodes enumeration scope None. Add an explicit BOOTSTRAP_METADATA shell helper/argument without changing historical callers |
| Registry accepts/rejects install | `userspace/registryd/src/service.rs:145-193`, `receive_control`; `src/lib.rs:453-489`, `install_client` | One-way install; success stores peer, rejection closes it. Neither sends an acknowledgement |
| Registry metadata access | `registryd/src/lib.rs:703-727`, ENUMERATE scope gate; protocol SERVICE_LIST pages | Fresh shell needs BootstrapMetadata scope and complete preflight page drain |
| Registry peer retirement | `registryd/src/lib.rs:789-817`, `peer_closed`; `service.rs:118-132` and endpoint receive cleanup | Removes client/watches and closes server peer asynchronously; current service has no pre-install cleanup sweep |
| Generic registry actor launch | `wyr1b_native.rs:1248-1445`, `launch_peer` | Pair/install/load/READY chain; source explicitly requires registry poison on later ambiguous install failure |
| Generic launch-client construction | `wyr1b_native.rs:1603-1723` | Grant/pair, child load/MOVE, READY, local session install and owning standalone actor |
| Session install/disconnect | `userspace/system-init/src/wyr1b_job.rs:10-22,59-140`, `install_session`, `disconnect_owned_session` | Current state has grant, controller Channel and optional owning SessionOwner, no scope. New nested ShellJobs must not duplicate ownership of the outer shell Process/TaskGroup |
| Consoled endpoint installation | `wyr1d_native.rs:150-198`, `launch_console` | Installs local launch controller before loading consoled because consoled launches its child before its own READY |
| Reserve/stage/commit/abort job | `wyr1b.rs:424-570`; `prepare_reserved_job:1139-1250`, `commit_prepared_job:1263-1288`, `abort_prepared_job:1290-1298` | Reserve replay/capacity first; Reserved jobs invisible; track moved endpoints; exact READY permits publication; abort only exact reservation |
| Receive/parse/reserve | `wyr1b_native.rs:2430-2567`, native dispatcher | Request/handles are already received before semantic validation. Fresh envelope reservation precedes full body parsing; received rejection cleanup belongs to init |
| Load/READY/accepted | `wyr1b_native.rs:1883-2045`, `accept_reserved_launch`; `1789-1820`, `publish_launch_accepted` | Begin/load/stage, exact READY + fresh RUNNING proof, internal commit, accepted send, bootstrap peer release. Failed response uses forced exact cleanup |
| READY evidence | `wyr1b.rs:308-381` | Exact profile, transaction, Process generation and current RUNNING state; READY+EXITED is not successful startup |
| Current console child | `userspace/consoled/src/main.rs:49,788-980`, `CHILD_PATH`, `launch_child_once` | Exact `bin/console-echo`, three pairs and WRLJ 1.0 LAUNCH. Accepted precedes consoled's own READY and long-lived WAIT |
| Request stream custody | `consoled/src/main.rs:2013-2035`, `stream_transfer.rs:1-16`; `lib.rs:272-340`, transaction model | Three retained/three moved endpoints, sender staging has TRANSFER, final child does not. Status requires a distinct fourth control peer with explicit ownership |
| Loader delegation | `crates/wyrmroot-loader/src/process.rs:640`, JobV2 load path; `1477-1523`, INIT MOVE | Atomic all-or-none delegated handle consumption. E3 grows launch capacity4, transaction delegated channels3, transfer descriptors4 (`1363`), INIT scratch128 (`1105`) and explicit rollback indexes0..2 (`519-526`) to cover the six-role/160-byte profile |
| Child startup release | `userspace/console-echo/src/lib.rs:86-140`; runtime launch startup | Child sends READY, waits for bootstrap launch-peer close, then begins functional operation. Shell preserves this sequence |
| Normal console child result | `consoled/src/main.rs:1452-1486` | Completed job cleanup/reap before a fresh child |
| Child peer failure | `consoled/src/main.rs:1488-1533` | Retire, cancel pending wait, close peers, terminate/wait/close-job, then replace |
| Serial replacement | `consoled/src/main.rs:1536-1606` | Invalidate serial/child peers, terminate/reap child, clean old serial, reconnect and allocate fresh generations |
| Exact job cleanup | `consoled/src/main.rs:1608-1646,1662-1679`; `lib.rs:962-1120,1380-1399` | Endpoint close + terminal/termination + exact reap gate replacement; do not infer distributed completion from a local flag |
| Launch peer loss/orphans | `wyr1b_native.rs:2570-2684`; `wyr1b.rs:894-934` | Disconnect, hide/orphan jobs, close session owner if present, retain/reap jobs and reclaim connection only when possible. Fresh shell never inherits old IDs |
| Registry replacement | `wyr1b_native.rs:3491-3688`, base replacement; `wyr1c_native.rs:3309-3400`, integrated coordinator path | Finite generation replacement; closes/drains old sessions/roles, advances topology, rebuilds registry/publication. Full fresh console/shell chain is not yet integrated |

The source prefix `wyr1b*.rs`/`wyr1c*.rs`/`wyr1d*.rs` in abbreviated rows is
`userspace/system-init/src/`.

## 3. Reconciled gaps and decisions

1. **Committed transfer cannot be undone by policy rejection.** The active
   plan's phrase "before handle ownership changes" is narrowed to before
   injected authority, loader delegation and job publication. Init must close
   all received request endpoints after a committed rejected MOVE. No sender
   recovery of the old handle numbers is allowed.
2. **No registry acknowledgement exists.** A new endpoint's successful query
   alone does not prove an old slot retired in a 32-client registry. The E0B
   contract requires old shell destruction before new install, a bounded
   registry receiver cleanup sweep before installing, and a complete ordinary
   txn-1 metadata query before INIT. This establishes ordering compositionally.
   It does not claim init directly observed a slot-retirement acknowledgement.
3. **Current D5 cleanup is not a shell template.** `launch_console` after its
   committed registry install currently performs local cleanup on later failure
   (`wyr1d_native.rs:166-277`), without the complete shell poison/replacement
   path. Consoled treats registry peer closure as fatal (`main.rs:1139-1142`),
   while the D5 controller treats consoled exit as a failure. E3C/D must explicitly
   join registry replacement through console/shell teardown and fresh endpoints.
4. **One shell process owner.** An outer job and an owning nested SessionOwner
   cannot both own the same Process/TaskGroup/launch handle. Nested ShellJobs
   owns its controller peer and job namespace; the outer job alone reaps S1.
5. **Two publication points.** Internal job publication follows validated READY;
   external acceptance commits on response send. Clean launch-peer release
   separately permits the child to operate. Failure injection covers all three.
6. **Fatal diagnostic peer loss.** The six-role profile promises a current
   status relationship. Status closure ends the shell generation; no degraded
   interactive shell silently keeps incomplete startup authority.
7. **Stack geometry is 108 KiB working space.** The 128 KiB child stack contains
   a 20 KiB ABI-2 startup block. E0 records bounds but does not measure E2/E6
   native stack usage.

## 4. Wire/profile/product registry at baseline

| Registry | Current | E0B reservation only |
| --- | --- | --- |
| WRLP | `loader/src/launch.rs`: minors 0..10, roles 1..15, max capabilities 4 | Wyrmsh minor 11; roles `[8,9,10,16,6,7]`; only role 16 is new; INIT 160 / READY 40 bytes |
| WRLJ | `launch-proto/src/lib.rs`: major1/minor0, types1..15, 40-byte envelope/48-byte header | Minor1/type16 ShellV1; request128/four handles, replies type2/15 at56 bytes; historical minor0 remains exact |
| WRCN | No current magic/protocol implementation | Version1.0, query1/snapshot2/error3, 48/160/56 bytes, handle-free |
| WRJP | `bootfs/src/launch_policy.rs`: 1.0, 64-byte header/record, ABI2/profile1/category1, modes1/2 only | Additive1.1 profile2, existing category1/mode2, exact shell-path enforcement |
| WRRM | `rrc-manifest/src/format.rs`: role5 Wyrmsh, startup profiles0..3 | Wyrmsh profile4 selected for new ConsoleBound product; historical stub remains0 |
| Registry | WRRG1.0, 32 clients, 64 issued client IDs per generation, explicit metadata scope | No new wire; explicit metadata scope + receiver cleanup/preflight implementation obligation |
| Launch sessions | Controller capacity16, exact per-connection replay/job accounting | Explicit immutable scope; retain bounded disconnected orphan tombstones |
| Selector/test IDs | `deepwyrm/tooling/guest-harness.toml`, kernel `test_support/identity.rs`: reached25..32 | Documentation reserves33 interactive-wyrmsh;34 final F remains reserved, no runtime dispatch |

WRLJ historical LAUNCH has a 72-byte fixed prefix and valid complete sizes
82..17,760 bytes, zero or three handles;
types2/3/5/7/8/11/12/13/14/15 56 bytes; JOB_STATE64; JOB_RESULT88;
LIST_JOBS48; JOB_LIST56+8N, N<=32. The 1.1 fixed ShellV1 operation does not
reuse the variable argv/environment encoder or alter type1 meaning.

The active product inputs are traced in `tools/xtask/src/wyr1c.rs`:
build specifications/build at225-275/884-955, `assemble_d5_product`1460-1577,
and `inspect_d5_archive`1887-1928. D5 selects `wyrmroot-wyr1-retained-stubs`,
binary `wyrmsh`, feature `native-retained`, for `system/wyrmsh`. That stub
immediately exits `0xAF05_0000` (`userspace/wyr1-retained-stubs/src/wyrmsh.rs`).
It is read only to preserve identity, never as a shell implementation template.

The separate `wyrmroot-console-echo` actor is installed at `bin/console-echo`
and is the sole D5 launch-policy entry, with three streams. `tools/xtask/src/wyr1.rs`
562-635 builds the five-role RRC graph and Wyrmsh->Consoled READY edge;
720-786 hashes exact selected role bytes. `rrc-manifest/src/product.rs:190-262`
validates role order/edges. `tools/xtask/src/wyr1d5.rs:33` exports console-echo,
WRRM/WRDM/policy/bootfs but no standalone wyrmsh ELF. The historical stub is
bound transitively through WRRM/bootfs. E6 adds an explicit production wyrmsh
ELF/hash in the new product, leaving historical selectors' selection intact.

WRST remains 1024-byte DATA, handle-free, with drain-before-EOF semantics.
Consoled uses three 4096-byte queues and 1024-byte fairness quanta; four child
or serial failures in a rolling 60-second window exhaust retry. ConsoleSnapshot
(`consoled/src/lib.rs:596`) provides the WRCN facts: its failure counters are
rolling-window counts, not invented lifetime restart totals.

## 5. Required-source receipt

All local source material was read at the preflight heads above. `concept`
means applied as authority/design constraints or conceptual comparison; no
external code was adapted. References for future phases inside these sources
were not recursively treated as new E0 implementation work.

| Required set read | Disposition and use |
| --- | --- |
| Root `AGENTS.md`, `LICENSING_POLICY.md` | concept: repository/write/VM/review authority; new model follows its GPL-3.0-or-later component |
| Root `BOOTSTRAP_AND_RECOVERY_ARCHITECTURE.md` | concept: RRC-A transitive independence, fresh topology, bounded escalation |
| Root active WYR1E/DW1F/WYR1F plan | concept: E0 scope and all reached shell locks |
| Root `DW1_WYR1_INTERACTIVE_SHELL_IMPLEMENTATION_PLAN.md` | concept: native grammar/editor/job boundaries; active plan supersedes old display path and 4096-byte WRST sketch |
| Root `DW1E_WYR1D_IMPLEMENTATION_PLAN.md` | concept: reached console/driver split and historical product preservation |
| Root `validations/DEVELOPMENT_WORKFLOW.md`, `validations/WYR1D_D6_BOUNDARY_REVIEW.md` | concept: current host/native compiler split, exact evidence and scoped review nonclaims |
| Deepwyrm `Plans/ARCHITECTURE_INDEX.md`, `DW1_A0_PREEMPTIVE_SCHEDULER_CONTRACT.md`, `DW1_D0_DEVICE_RESOURCE_INTERRUPT_CONTRACT.md`, `DW1_E0_Q35_EXTERNAL_INTERRUPT_CONTRACT.md` | concept: reached primitives/fairness/generations, no new kernel mechanism; device authority does not enter shell |
| Deepwyrm `docs/DW1_C_VALIDATION.md`, `DW1_D_VALIDATION.md`, `DW1_E_VALIDATION.md` | concept: accepted exact tuples and QEMU-only dependency evidence, no new validation claim |
| Wyrmroot architecture index and `WYRMROOT_PLATFORM_CONVENTIONS.md` | concept: explicit little-endian versions/IDs, native capability topology, static-first execution |
| `WYR0_IMPLEMENTATION_PLAN_NATIVE_CONTROL_SURFACES_ADDENDUM.md` | concept: typed inspection, no proc/sys/ioctl foundation or omnibus init |
| `WYR1_BOOTSTRAP_SUPERVISOR_CONTRACT.md` | concept: sole child owner, READY/reap, WRRM profile0 retained-but-not-launchable |
| `WYR1_B_REGISTRY_LAUNCH_CONTRACT.md` | concept: WRRG/WRLJ, scopes, one-way install/poison, ABI2 and orphan accounting |
| `WYR1_C_DEVICE_COORDINATOR_CONTRACT.md` | concept: independent generation replacement and publication chain |
| `WYR1_D_SERIAL_STREAM_CONSOLE_CONTRACT.md`, `WYR1_D_VALIDATION.md` | concept: exact WRST/console behavior, accepted pair, selector32 preservation |
| Current launch/registry/stream protocol, loader/runtime, consoled, registryd, system-init sources | concept: source-bound inventory above, actual gaps versus future behavior |
| Current retained wyrmsh stub, console-echo, bootfs/WRRM/product tools | concept: identity/policy/RRC preservation only; not applicable as production shell templates |
| linenoise `a473823d74b93eab2ba83480df16ed37617493f2`, `linenoise.c`, `linenoise.h` | concept: editor state, incremental feed, history/cursor and CR/erase/cursor redraw; BSD-2-Clause. Reject libc/termios/fds, allocation, width queries, folding/completion and different Ctrl-D semantics |
| Ion `1440704f7456fa4c9f873b7b17dd4f0369b0c4ab`, `src/lib/parser/mod.rs`, `lexers/arguments.rs`, `terminator.rs` | concept: separate termination/argument/quote/error state; negative prior art for expansions, nested structures and multiline input. No Ion semantics or source copied |

Linenoise was read from the clean existing pinned external-source checkout
at root `.tmp/e2-d3-prior-art/linenoise-src` with HEAD independently verified.
Ion's exact three raw GitHub files were read directly. The web connector was
unavailable and sandbox DNS failed; the same pinned unauthenticated read via
the approved network boundary succeeded. No external source is unavailable
for this E0 receipt. Required E1/E2 prior art must still be re-applied to their
actual parser/editor implementation; E0 does not implement either.

## 6. E0B validation and handoff

E0A and E0B are complete. The frozen contract and abstract host model agree on
the scoped ownership, generation, transaction, publication and cleanup boundaries.
Production wire/profile/runtime sources are unchanged. E1/E2/E3 remain separate
later cards; selector33/live tests are not released before their joins.

### Exact candidate and checks

- Model commits: `0d6d00f13d32ac106603dd27e222bba6859206e1`, then
  `8489d3ea2a0f3a2f5274a3f4d64ef6ee0065bc95`, integrated in order into
  canonical Wyrmroot. Both are unsigned (`%G? = N`) and change only
  `crates/wyrmroot-launch-proto/tests/wyr1e_e0_model.rs`.
- Final model SHA-256:
  `e9d185ae3721b3157fa66143ceb5988f53d9288c683b1a5b0ab506a402a47859`.
- Frozen contract SHA-256:
  `f47207a6d236791ee05f0872dc28f0a9d61acb28e1fa8e6b7bd8ba74c9f33d0e`.
- Pinned format check, package check with `--tests`, and model Clippy with
  `-D warnings` all exited 0. Focused model tests passed 15/15. The coordinator
  independently reran the full package on canonical commit `8489d3e`: existing
  tests 9/9, model tests 15/15, doc tests 0; exit 0.
- Three targeted regressions first failed against the intermediate model
  (12 pass, 3 intended fail), then passed after the final fixes. This preserves
  evidence that the checks distinguish the rejected behavior.

Reproduce the final package check from canonical `wyrmroot/` with:

```sh
WYRMROOT_PINNED_TARGET_DIR="$PWD/.tmp/wyr1e-e0-20260905/target" \
  tools/pinned-cargo test --locked --offline --package wyrmroot-launch-proto
```

The same pinned launcher ran `fmt -p wyrmroot-launch-proto -- --check`,
`check --locked --offline -p wyrmroot-launch-proto --tests`, and
`clippy --locked --offline -p wyrmroot-launch-proto --test wyr1e_e0_model -- -D warnings`.
The host/native compiler split is the measured split in section 1.

Local evidence is retained outside Git under
`wyrmroot/.tmp/wyr1e-e0-20260905/`, including the initial checks and final
`lane-r2-*` logs copied out before lane retirement. Key receipts:

| Log | SHA-256 |
| --- | --- |
| `coordinator-package-test-r2.log` | `26655578df3bfe1f5f55341c1e9cd43fe592f5151a70fc60bbfbcdb63b4ea1d0` |
| `lane-r2-red-medium-regressions.log` | `d7d801f00249bce1636b47d717736e144e3c1b340f7f56553b507a733f2c7dc1` |
| `lane-r2-fmt-check.log` | `d85f402a690aff7df771a005b18e2cd80b9e33ba6306ea4543bbafae2b96180a` |
| `lane-r2-check-tests.log` | `f831885170bf6800849e18bf12215b46652faaaa2d3909e2e589d2998cb82e10` |
| `lane-r2-clippy.log` | `09305022454a5f4b6b2ae2661d94b34549a9b85b46fbf825041cfdd5e1c7e1af` |
| `lane-r2-focused-test.log` | `88561b88efd0a1adf1acbde03144df3b0e05dcc55d8f6139fb6a94cb02ad23e4` |
| `lane-r2-package-test.log` | `cf99c03f315d009c5edb45af3299f69d53da9eb83a09f891e1086d33d08ef372` |

### Scoped Daybreak review

Review identity: exact model `gpt-daybreak-blue-latest` (`daybreak-latest`),
reasoning effort `high`, date 2026-09-05. The read-only review used the source
baselines in section 1, the exact final contract/model hashes above, and inventory
snapshot `ad73e4553cd42475de04059d1ff1995c003f4c4005eb0ea506f041c3222a42de`
before this completion receipt/status update. **No remaining Critical, High,
or Medium findings** in the final E0 contract/model join.

Rejected model lineage is retained explicitly: initial model
`bb208e5ec246124474ff8c898984891252d8adf5e2886931dcf80522b0b2eae9`
(11 green tests), then intermediate model
`bcb614448aafca31adfa40bdbccf0a376774014181869e6ea45dd4e4266d5c56`
at commit `0d6d00f` (12 green tests). Green tests alone did not establish the gate.
The review prompted these reconciliations:

- Distinct outer connection and WRLP transaction identity, exact READY correlation,
  post-MOVE custody, complete Process/TaskGroup/accounting teardown, preservation
  of open registry endpoints, and healthy-C1 console continuity.
- Pre-registry rejection no longer blocks a later install: the terminal/reap
  predecessor requirement applies to committed registry authority.
- Registry replacement blocks new shell launch until console and outer launcher
  authority are rebuilt with fresh identities.
- The receiver sweep counts only the installed 64-endpoint snapshot; new client
  admission separately observes the 32-client bound after closed-slot retirement.

The final review accepts the composite no-ack proof in the contract: complete old
child teardown and destruction of its unique client peer precede INSTALL send;
registryd performs a bounded PEER_CLOSED-only sweep before install; a complete
canonical metadata query proves new install/scope/receiver progress; six-role
INIT follows. No retirement acknowledgement is invented.

### Closure and limits

The clean `wyr1e-e0-model` lane was retired after integration and confirmed worker
inactivity; its merged branch was deleted. Deepwyrm/Wyrmroot registrations were
pruned and `tools/worktree-lanes.py audit --strict --expect-none deepwyrm wyrmroot`
passed. The local `final-lane-audit.log` records zero lanes with only the pending
Wyrmroot documentation changes at that point.

The model is abstract design evidence, not an exhaustive proof. Its synthetic
full-64 endpoint fixture does not execute real publication/client kind behavior,
native deadline or READABLE/PEER_CLOSED semantics, codec bytes, loader custody
arrays, or registry/service adapters. Those remain E3B/C/D obligations. No E3
runtime, selector33, VM run, physical hardware, E8/final security gate, or paired
DW1-F/WYR1-F closure is established here. Deepwyrm and the Rust fork are unchanged.
