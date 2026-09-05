# Wyrmroot WYR1-D validation and closure record

**Status:** Accepted. WYR1-D6 and the WYR1-D native byte-transport seam are
closed on the exact implementation pair below. WYR1-E may begin.

**Validation date:** 2026-09-04 (America/Chicago).

## Exact accepted implementation

Wyrmroot `f95262f832f0efbe42cf9359462bca261a6a5b58` with Deepwyrm
`784adb253ff4c0065b8b85e05b938f374a139e96`. Generated ABI revision
`085b184c32ae1fa3d5ec322c86957dd5d036595c`, tree
`a9b067107ec38e2be44630f4dce428dab0f48de8`. Rust revision
`a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`.

The publication commits are documentation-only descendants, not substitutes
for the exact frozen source identities. Independent repository commits are
not an atomic cross-repository commit.

## Reached seam

The production userspace UART driver owns the exact q35 COM2 DeviceResource
and Interrupt roles; native WRST byte streams connect it through consoled to
the console-echo child. The live selector32 product proves stdin/stdout/stderr,
driver replacement, fresh console/stream generation, child-only replacement,
and reuse of the surviving stream identity. Selector31 separately proves the
physical q35 IRQ3 route, two raw binary exchanges and generation-exact rebind.

COM1 remains the trusted structured-certificate transport and is excluded
from delegable device resources. COM2 is independently checked functional
data, never a replacement for the COM1 certificate. Console children receive
stream Channels, not PIO/Interrupt or debug-write authority.

## Host and build gates

- Wyrmroot workspace: 1086 passes, 0 failures, 1 existing ignored test.
- consoled/devmgr/init selected libraries: 37/37/109 passes.
- Wyrmroot warnings-denied workspace Clippy and formatting pass; selector32
  native actors and neighboring selector31 native init/devmgr checks pass.
- Deepwyrm workspace: 1116 passes, 0 failures, 4 accepted ignored tests.
- Deepwyrm selector32/31 libraries: 934/936 passes; ABI drift, formatting and
  warnings-denied workspace Clippy pass. Target31/32/29 checks pass with
  13/9/25 existing target dead-code warnings, not warnings-denied target claims.
- Root verifier/runner: 222 tests pass after fragmented frame, independent
  transport/EOF ordering and exact virsh-footer regression additions.

Logs: `../.tmp/d6-host/`, `../../deepwyrm/.tmp/d6-kernel-validation/logs/30-*`
through `38-*`, and `../../.tmp/d6-root-tests-r6.log`.

Use the exact canonical invocations and project-root offline home in
[`D5_VALIDATION.md`](../userspace/system-init/D5_VALIDATION.md), together with
the preserved [development workflow](../../validations/DEVELOPMENT_WORKFLOW.md):
separate fresh target directories from logs, pass absolute manifest paths,
serialize image preparation, and place selector28's campaign result beside
`campaign.toml`. Reusing a consumed output directory is not a valid retry.

The deterministic preparation paths inspect bootfs and ESP, bind every
guest-consumed artifact to source/build receipts, validate WRRM/WRDM and
selector policy, and freeze exact profile handoffs. Product checks confirm
selector31's 12 entries and selector32's 13 entries, including the distinct
console-echo and private gate payloads. These are not claims of two independent
clean reproducible builds required later by the final hardening phase.

## Live matrix

All roots below are relative to `../../artifacts/`.

| Selector | Frozen directory | Profiles | Accepted aggregate SHA-256 |
| --- | --- | --- | --- |
| 31 | `wyr1d6-20260904-a2/s31` | UP and SMP | `0d8107b0a99708d34e2a82b659958217fb481e01f2806248ecb7e666c73a2dbf` |
| 32 | `wyr1d6-20260904-a1/s32` | UP and SMP | `05409bf78855b829f666f4c5d447ad45b2b85febf870448c3a08d7e1bd174713` |
| 30 | `wyr1d6-20260904-a1/s30` | one-vCPU smoke, four-vCPU coexist | `38a1403bec091796182efa19fc4aa8e06e793ed4a176322fcd0ba31afb561ec9` |
| 29 | `wyr1d6-20260904-a1/s29` | UP and SMP | `ca8a822eccafbc88e960b6256bbb6feb23e4ff2380239159175aad1c15aca756` |
| 28 | `wyr1d6-20260904-a1/s28` | SMP smoke and stress-1 through stress-5 | `07b4913b03adbb4cab469dba74a97b766cc4236ca78e97f04ac24f294bd0151f` |
| 27 | `wyr1d6-20260904-a1/s27/selector27` | canonical direct one-vCPU QEMU | `4b8d7645b1adf7b7d1e9356e54624364e3d5cedd7c620ad4a772402d5f5217eb` |

Aggregate files are `profile-pair-result.json` for 31/32/30/29,
`campaign/campaign-result.json` for 28, and `run/run-receipt.toml` for 27.
Selectors 31/32/30/29/28 use the leased `OS-Project` domain on
`qemu:///system`; selector27 uses its existing canonical task-owned direct
QEMU runner, not a private substitute profile or persistent-domain operation.
All runs use project-local disposable guest state, with no NIC, host share,
passthrough or system-disk attachment.

Root runner `e78f087d5bcefe18a61a61f2a8ede710bddc7559` ran selectors32/30;
`77f5ca425eac9a8c004173f48fab75f7dd953a3d` ran selectors29/28/31. The latter
change affects only E3B footer handling and its tests. Selector27 uses the
canonical Wyrmroot runner at the exact Wyrmroot revision above.

### Primary selector32 identity

| Item | SHA-256 |
| --- | --- |
| request | `81e4d795f007194d5858ea26da76ceab69d4af28f287214338298ae7f5602922` |
| profile pair | `04cb9a1c1e71a970319fef5e6ffaf417f0720009a9d4de72b130027687ec5204` |
| freeze receipt | `8b35a4a2706c6ea78396da83a7dfb7fd7413f169b3cc9453d1b75a9545409275` |
| kernel and symbols | `ed7429cd1cb2b226fae8612c27b63e9afc8ff727bd8aad0d4a834456f0a65ce3` |
| bootfs | `06a2568fdd410bf5fb87533a9fbcfad3c2702ffd87c9f4ea45330490ef142bbc` |
| ESP | `5fc5ec90f3e8239ed9ee020a6b1145de10d955a2404669ff06713c96791c906e` |
| UP receipt | `dcede42e4cd7ba9555a9de1c0c9204aa3b262fd0e279b80e10e8752bfaf1b350` |
| SMP receipt | `1d3e63b4eb26eaaa9c50c46a44467860032ef6d24be2c0a2881253a67969054e` |
| UP actual-send audit | `c6120a55e8a6b88924d486567e0888b2323213159ffd47ce2eda8c62c2cf965e` |
| SMP actual-send audit | `8385d29aa5620933c2e58a077123c330eeb92d1a5122c52d6dc4b89adb1de836` |

Evidence nonce: `D600000000000201`. Both profiles have COM1 SHA-256
`a88ed0477be218342b9dd97654f08e31bbf50a9d7435a9034499e42552ed292e`,
COM2 SHA-256 `e4d97e93fbe176432956933e63a69ac561c0979a6cf82fa1805c5a6ea3f12096`,
and certificate SHA-256
`41359f2fb9ca116836afa81504791060b2a182b3238257e821c238fe4dabf4e6`.

Both profiles carry these exact readiness/replacement joins (hexadecimal).
Role and bundle remain `1`; each distinct endpoint retains its local
generation `1`. Driver replacement changes the driver/stream/console/child
identities; child-only replacement changes only the child identity.

| Join | Attempt | Endpoint | Attach transaction | Stream | Console | Child |
| --- | --- | --- | --- | --- | --- | --- |
| Initial C1 | `100000001` | `180000001` | `1C0000005` | `100000002` | `1` | `2` |
| Driver replacement C2 | `100000002` | `180000002` | `1C0000006` | `100000003` | `3` | `4` |
| Child replacement C3 | `100000002` | `180000002` | `1C0000006` | `100000003` | `3` | `5` |

Challenge tokens for legs1–4 are `267A61617B803DD8`, `0A6BEC09D595229B`,
`4B227C92F358099C`, and `EAAFB43CA36BEFBA`. Leg2 is stderr; the remaining
legs are stdout. The audits bind actual completed sends, not only derived
command hashes.

### Fresh selector31 regression identity

Evidence nonce: `D600000000000111`; challenge nonces:
`D600000000000112` and `D600000000000113`.

| Item | SHA-256 |
| --- | --- |
| request | `53bb5cd2afd6ce65bf4389928263b3386eb3469523ffe509160f824a8d0ca35b` |
| profile pair | `fba40e5e7f5409286801697500935a522e09dc548f6d807d0c986dd6bd2dcbb0` |
| freeze receipt | `df51d071acf3c19d356880567f187fb2de224087680cc5e25a855f590b7274ee` |
| kernel and symbols | `642bcbfd9eb1a7be2367384434b9e79f5ff7feade0b37cccd32b1f357d15e36e` |
| bootfs | `85fbda805efe87a36cb8b127d620e268662352dd213647008220f9d6e2bfc284` |
| ESP | `e76d26363ac9e640d6fec6e1e2f207d663e090b48b022038ba8e95787e6d6d27` |
| UP COM1 | `ab12106a874b58e12bd21c1de9d82a612eaa81eb9ddc3e71cbadb2a8a3b3151c` |
| SMP COM1 | `77c9690855918b5723578c01b83d5cde2b158d8435d7f7c33d785a95e87946ae` |
| COM2, both profiles | `e4d6c1b04f9edb207cdff315e64781a967774885f7f5b246a097f886c5832bf0` |
| UP certificate | `353327a51b51d211d3ad590831193e54d3c5712c46420f2e8c9af63bee7cbccc` |
| SMP certificate | `775ded79eab8206d6afee042c45a0eb4176a0e8e96e274b8ef0909f74946bf3e` |
| UP actual-send audit | `62feef09b96a6a7d34c86bc97612f425c6376e08c0dc6052554bbd4a6a421738` |
| SMP actual-send audit | `fc43a03dba94b7f5023aa5eca67e36b8bd64291a14b45c2e5e8c4217ec0fefac` |
| UP receipt | `5b40da6e03fb25fc7b7df1d75c8db2ea51b944e1646f505e0e13509b9db3bfb0` |
| SMP receipt | `a2369c6a73ae1998f34c7f3c6fe2fa099eac3c201fc26c2a772a13502520996a` |

Independent recomputation verifies all 26 records, both readiness markers,
the retirement/fresh-generation/stale joins, checksums, accounting and exact
challenge/response FNV values. Both captures retain the exact host CRLF after
the strict selector31 terminal.
The two binary challenges are actual completed 24-byte sends, separately
bound to their exact corresponding COM2 responses. The failed a1 pair remains
preserved and is not substituted for either accepted a2 profile.

### Independently recomputed older-selector certificates

| Selector/profile | Record count | Certificate SHA-256 |
| --- | --- | --- |
| 30 both | 40 | `16667e2fd32d9882651aabc3020a9988c463f848c89323884f126610bb1fe5d7` |
| 29 both | 27 | `cc98c37364ea4cae7c511f2a1933ddf1f0ac6a57de12755dee4703f63bcb2c30` |
| 28 smoke | 46 | `6cdca61a9830225adc2ba65e5ea581872e00f68bca802547feaf8638e2cd8735` |
| 28 stress-1 | 46 | `33b4d57ae8e6161fb001bf2190979704a426e995586553a4e61cdb0c67b61c87` |
| 28 stress-2 | 46 | `e2475acf08c531a3d75955dd8c0ad4ba9f98b0c439578a2a466f65583a1c1568` |
| 28 stress-3 | 46 | `59de6159936e701eacfde234cbce0ccea905d7228c9b9822ec86e55540cb1da2` |
| 28 stress-4 | 46 | `7341d12ee07105f16ab391068f786c856aafce9406d69ec63dbc1c687a09bbc2` |
| 28 stress-5 | 46 | `1d13df27b22b248c003a8ad7f9ed5d9dfb477237484ae1153702803f4a6ef0ea` |
| 27 | 14 | `92902e6dbef16ae3790c552d5a2fc6d5d97ca169a801ae34e827aa8dc85f564f` |

Independent audits recomputed fixed-width record checksums, sequence/nonce,
actor/CPU/generation joins, challenges, terminal checksums and file hashes;
stored PASS fields alone were not evidence. Selector30 proved five delivery
cycles and replacement lease/binding 1/1 to 2/2. Selector29 proved driver and
devmgr restart/stale publication without claiming physical I/O. Each of the
six selector28 passes proved actor progress, four-CPU joins, migration,
remote wake, race mask31, exit/reap and final accounting. Selector27 proved
registry/launch/owner cleanup with exit33 and a recorded normal reaped exit.

Selector32 raw recomputation confirms twelve 192-byte WRD1 records, three
readiness tuples, all nonce/generation joins, four exact COM2 responses and
five successful actual sends totaling 97 bytes, including `exit\r\n`.
Raw COM1 contains one host LF after its strict 38-byte terminal, retained in
the raw hash. Selector30's corresponding cooked-PTY host footer is CRLF.

Every acceptance still requires the strict guest certificate, exact complete
COM2 exchange where applicable, immutable input bindings, canonical cleanup
and accepted receipt. Transport-audit `validated-capture` alone is not PASS.

## Historical actor and conditional-gate integrity

Selector27 retains real registryd with its historical init27/gate actors and
retained driver/console/shell stubs. Selector28 retains its init0 and ten
historical actors. Selector29 retains the six-role coordinator/restart product;
selector30 retains owner, trigger and replacement-owner. Product hashes must
be checked against these exact source bindings, not inferred from file names.

Normal/degraded selector25 still use retained-stub consoled; their scenario
switch selects registryd versus registryd-fail, not the production D5 console.
The conditional selector25 D6 gate is therefore not triggered. No new live
normal/degraded production-console acceptance is claimed.

## D6 repairs and negative evidence

Deepwyrm changes during D6 are comment/test-only: `31fa345` supplies two local
SAFETY proofs at selector32 completion calls; `784adb2` repairs three stale
cfg/source-contract expectations and adds the exact selector32 capacity test.
Neither changes runtime behavior.

The initial selector31 a1 pair passed UP but failed SMP because the host
reader parsed a 28-byte prefix of the 38-byte terminal before its newline.
The failed run is preserved unchanged. Complementary review widened into
E3A fixed frames, cross-channel response/readiness observation order, generic
child-exit/PTY drainage and the actual console-tool closing footer. Root
`e78f087` fixes fragmentation and drainage; `77f5ca4` accounts for exactly one
host CRLF footer without stripping raw bytes. Fresh full selector31 acceptance
must replace, not relabel, that failed attempt.

The canonical selector31/32 runner also records bounded actual completed
sends and monotonic send/capture times. Missing or failed sends, publication
failure, extra COM2 bytes, truncated proof, unexpected peers, and malformed
terminal/suffix cases suppress acceptance. Failed-send partial progress is
not falsely labelled a completed command.

## Review and provenance

The scoped D6 unsafe-boundary and host-capture reviews used exact
`gpt-daybreak-blue-latest`, high reasoning, on 2026-09-04. Exact revision/diff
hashes, resolved low-severity documentation finding and follow-up results are
in `../../validations/WYR1D_D6_BOUNDARY_REVIEW.md`. Complementary functional
reviews independently reproduced capture races and recomputed live records.
This is not the final DW1-F/WYR1-F security gate.

Required sources and design decisions remain in the D1-D5 status records,
the serial/stream/console contract, root paired plan and bootstrap/recovery
architecture. Pinned Fuchsia, xv6 and uart_16550 informed the original boundary
and lifecycle work. Linenoise's incremental-input and raw-mode restoration
examples were consulted; line-editing features and reuse remain deferred to
WYR1-E. The D6 host footer correction additionally consulted libvirt12.0.0
[`virshRunConsole` final TTY restoration](https://github.com/libvirt/libvirt/blob/v12.0.0/tools/virsh-console.c),
[`vshCommandRun` closing newline](https://github.com/libvirt/libvirt/blob/v12.0.0/tools/vsh.c#L1412-L1418),
and [`vshTTYRestore`/`vshTTYMakeRaw`](https://github.com/libvirt/libvirt/blob/v12.0.0/tools/vsh.c#L2090-L2131).
These explain the single CRLF footer admitted for the cooked E3B PTY. No
upstream code was copied for these D6 changes.

## Cleanup and nonclaims

The coordinator's final leased read-only VM audit on 2026-09-04 confirms
`OS-Project` shut off with shutdown reason, restored inactive XML SHA-256
`a823095e2182f848be0c15fe1a88728fce9f126fbc55e7d9aab30d84a6c5d3c3`,
and the original `vda` attachment `/var/lib/libvirt/images/OSProj.qcow2`.
The lease was released without replacing its inode. No test COM2 socket
remains. Log: `../../.tmp/d6-final-vm-audit.log`.

Both mutable Deepwyrm lanes were integrated and retired. Pruning found no
stale registrations; only canonical Deepwyrm/Wyrmroot worktrees remain.
`audit --strict --expect-none deepwyrm wyrmroot` returns 2 solely for the
pre-existing unregistered `.worktrees/deepwyrm/.tmp` directory, preserved as
unrelated state rather than removed to force a clean audit. Logs:
`../../.tmp/d6-final-lanes-prune.log` and `../../.tmp/d6-final-lanes-audit.log`.
No active or unnecessary registered lane remains. Unrelated Glasswyrm files
were preserved, and no remote was added or pushed.

This record closes only WYR1-D's native interactive byte-transport seam and
releases WYR1-E implementation. It does not implement real wyrmsh, an interactive
admin shell, POSIX TTY/descriptors, a Linux device layer, general IOAPIC/MSI,
physical hardware support, final security closure, or all of DW1/WYR1.
