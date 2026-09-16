# WYR1-E validation

Written for card E8D.6. This is the permanent record for WYR1-E. It states what
was validated, at which exact revisions, by what evidence, and — with equal
care — what it does not claim.

## 1. Disposition

**WYR1-E is accepted.** `F0A.1` is released by this record. F0A is not executed
here.

Acceptance rests on an E8 UP/SMP profile pair passing at the current head, the
six E8D.4 regression rows passing, and an independent recomputation of the
accepted pair's evidence (E8D.5) agreeing with the recorded values. The
qualifications in §8 are part of the acceptance, not footnotes to it.

## 2. Exact identities

| Component | Revision |
| --- | --- |
| Root coordination repository | `16749e9fd07708cb718ead65b6e701d456d64871` |
| Wyrmroot | `00253dfc1410f8f2a3a3ffb288b35652b5c341cd` |
| Deepwyrm | `70e3c9aeb33640efde03a735f51431bf9dd7e672` |
| Rust | `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d` |
| Generated ABI | `085b184c32ae1fa3d5ec322c86957dd5d036595c`, tree `a9b067107ec38e2be44630f4dce428dab0f48de8` |

Host toolchain is the pinned launcher's (`tools/pinned-cargo`); target builds
use the accepted toolchain at
`artifacts/toolchains/accepted/RUST-WYR0-I-B-SYSROOTS-007`, whose `rust-lld`
was verified against its recorded digest during this work.

### E6 ancestry

E8 is built on a frozen E6 product, not a rebuilt one:

- E6 Wyrmroot revision `cca32f764e2b1b1532c0eabf00c66c2b1d19c94a`
- E6 source receipt `7df2550df8b16a316ac9d30246f4a59f7e7f88db6977da8090a5b4c83717a819`
- E6 freeze receipt `0507062b98e26ef62f1d65dcff73ffd3b0418935c1f08ad42b128579115c10bc`
- Product directory `.tmp/wyr1e-e6-20260905-products/freeze-a`

Every E8 product named below consumed that same E6 input. `wyr1e8 prepare`
enforces the three identities above as constants, so a substituted E6 fails to
prepare rather than producing a differently-descended product.

## 3. E8 pairs

Four accepted pairs, each its own frozen product, each UP+SMP:

| Pair | Nonce | Wyrmroot | UP | SMP | Terminal |
| --- | --- | --- | --- | --- | --- |
| R7F (first accepted) | `E80000000000011C` | `ffa0c59` | 33 | 69 | `DWTEST1 33 0`, exit 33 |
| D1e | `E80000000000011D` | `3e8880e` | 33 | 69 | `DWTEST1 33 0`, exit 33 |
| D1c | `E80000000000011E` | `b0cd8f9` | 33 | 69 | `DWTEST1 33 0`, exit 33 |
| D1b (part) | `E80000000000011F` | `00253df` | 33 | 69 | `DWTEST1 33 0`, exit 33 |

Artifacts: `artifacts/e8-r7f-260915`, `artifacts/e8-d1e-260915`,
`artifacts/e8-d1c-260915`, `artifacts/e8-d1b-260915`.

The record counts, terminal line and exit status are identical across all four.
That is the point of running a pair per card: each of D1e, D1c and D1b-part
touched the held-wait barrier or the trigger path, and the pinned values in the
root verifier's `E8_FIXED_SEMANTICS` did not move.

### Record and transcript results (accepted pair, E8D.5)

Independently recomputed rather than re-read from the runner's own output:

- Both legs decode to whole 192-byte records; magic `WRE1`, major 1, minor 1,
  length field 192 on every record.
- Nonce `E80000000000011C` on every record of both legs.
- Sequences contiguous 1..33 (UP) and 1..69 (SMP).
- Kind histograms `{1:4, 2:24, 3:4, 255:1}` and `{1:4, 2:60, 3:4, 255:1}`.
  Exactly one terminal record, kind 255, last, at sequence 33 and 69.
- All 44 epoch tuple fields identical across UP and SMP.
- Retired causes 1, 2, 3, 4 across scenario epochs S1–S4; registry generations
  1, 1, 1, 2.
- 19 artifact digests recomputed from the files and agreeing; 0 disagreeing.
  Both legs consumed the same ESP, bootfs and source receipt.

### Pressure and fairness

262,144 bytes at payload digest `df1878ce…a4dcf79`; 254 `WOULD_BLOCK`s on each
leg against the admitted range 1..4095; a real no-read interval of 501.1 ms on
each leg. Pause and resume COM2 offsets are equal on both legs — 707,508 UP and
719,742 SMP — so the reader made no progress across the stall. This is an
observed interval, not a simplification to "all exit codes zero". Sends 222 UP
and 267 SMP; shutdown byte `04`.

## 4. The six E8D.4 regression rows

All pass. Full record in root `DW1_WYR1_E8D4_REGRESSION_ROWS.md`.

| Row | Selector | Profiles | Result |
| --- | --- | --- | --- |
| E8D.4-32 | 32 `native-console-streams` | UP + SMP | PASS — 12 WRD1 records, digest identical both legs |
| E8D.4-31 | 31 `q35-com2-interrupt` | UP + SMP | PASS — 26 DWE3E1 records, 14 generation counters identical |
| E8D.4-29 | 29 `device-coordinator-restart` | UP + SMP | PASS — 27 WRC6E1 records, byte-identical digest |
| E8D.4-28 | 28 `normal-preemption-smp` | SMP smoke + 5 stress | PASS 6/6 — 46 records per pass |
| E8D.4-27 | 27 `bootstrap-registry-launch` | canonical UP, direct QEMU | PASS — 14 WRB1 records, no timeout |
| E8D.4-30 | 30 `device-resource-interrupt-synthetic` | smoke + coexist | PASS — 40 records, 5 cycles, identical both profiles |

Selector 27 kept its direct-QEMU path. Selector 28's campaign result sits beside
its `campaign.toml`. Rows were serialized because the generated native layout is
shared, and each row prepared its own exact product: no artifact stood in for
another selector and no older PASS was promoted.

## 5. Defects found and resolved

Five, all found by this validation rather than reported into it.

1. **Selector 32 unbuildable** since 2026-09-15. R7B-1 gave every recovery-
   deadline caller `wyr1e::recovery_deadline`, but two sites in
   `wyr1d_native.rs` lacked the cfg pair, and `mod wyr1e` is gated on a feature
   selector 32 does not select. Fixed in Wyrmroot `b80a832`.
2. **Selector 34 unbuildable** since 2026-09-15, same week, same mechanism.
   R7B-2 removed `failure_kind`'s wildcard, leaving three cfg-gated R1 variants
   uncovered; two further breaks sat behind it. Fixed in Wyrmroot `8b178fb`.
3. **`ipc-blocking-smoke` unbuildable** since 2026-09-14. R5D renamed
   `into_parts`/`merge_cleanup` and missed two call sites in the file it was
   editing. Fixed in Deepwyrm `b114ea3`.
4. **Cause erasure on the syscall-boundary install path.**
   `installation_cpu_state_is_valid` joined a ring-0 check and an
   interrupts-masked check under one `bool`, and its only caller reported either
   failure as `InterruptsEnabled` — so a privilege violation was reported as the
   one thing that was not wrong. Split and reported separately in Deepwyrm
   `b598302`.
5. **R7B-4 classes D1e, D1c and D1b (part).** Recorded in §6.

### The class, not the instances

Three of the five are one defect: **code that no routinely-run gate compiles.**
Selector-gated and target-gated code was built only by the product paths that
mint VM images, so a refactor could break it and nothing would say so for days.
Every feature gate in Wyrmroot was an opt-in named filter; Deepwyrm's routine
`check` compiled only the host workspace.

Fixed structurally, not instance by instance:

- Wyrmroot `8b178fb` compiles all 26 selector library configurations on an
  unfiltered `xtask test host`. 7s warm.
- Deepwyrm `70e3c9a` compiles all 29 implemented guest selectors plus the E8
  configuration on `xtask check`, with the selector list read from
  `tooling/guest-harness.toml` so a new selector is gated the day it exists.
  1m41s, and it does not warm-cache.

Both were mutation-checked: reintroducing the original break makes the default
gate fail, naming the selector.

## 6. R7B-4 disposition

| Card | State | Pair |
| --- | --- | --- |
| D1e | Done, **narrowed** | `E80000000000011D` |
| D1c | Done | `E80000000000011E` |
| D1b | **Partly done** | `E80000000000011F` |

**D1e** retired one of its three predicates, not three.
`job_dispatcher_poll_allowed` bundled a parked WAIT reply with an evidence
tuple awaiting its serial line; only the first is what R6C's argument retires.
The other two predicates are console-lifecycle ownership during an episode: the
recovery coordinator retires the console in a documented order, and letting the
ordinary path relaunch concurrently races it. Retiring them would change which
loss E8 records. That coordination is a separate card.

**D1c** removed two fields from `E8HeldWait` that duplicated state their owners
already hold — the episode deadline, ordinary since R7B-1, and a result the
admission guard pins to a constant — along with the consistency check that
policed the deadline copy. The card's premise that parking should move onto
`LaunchTransactions` does not apply: the reply was already parked in ordinary
`pending_waits` storage. What remains is the WRC8 quiesce handshake, which is
the scenario rather than machinery around it.

**D1b** is the one card not finished, and §8 carries it as a qualification.

## 7. Required-source disposition

Read for this work: the reset plan, `plans/specs/WYR1E_E8D_VALIDATION_CLOSURE_SPEC.md`,
`AGENTS.md`, `Plans/WYR1_B_REGISTRY_LAUNCH_CONTRACT.md` §9/§9.5,
`DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md`, and the E6/E7 lineage receipts.
`WYR1_E8_HANDOFF.md` was treated as a command-reference template and not as
proof of prior execution, per E8D.4.

## 8. Qualifications — what this record does not claim

1. **D1b is not finished.** The trigger check no longer re-parses bytes the
   dispatch path already parsed, but the episode still opens from a ShellJobs
   launch. Moving it off one requires the episode to be installed before the
   launch is accepted while carrying that launch's transaction, and every other
   source changes the E8 request wire or the evidence sequence — both pinned in
   `E8_FIXED_SEMANTICS` and both attested by the pairs above. That is a contract
   decision. **Completing D1b invalidates the baseline this record publishes**
   and requires a fresh pair and new pins.
2. **No physical-hardware validation.** Every result here is QEMU. §9 forbids
   inferring hardware acceptance from it.
3. **One pair is one pair.** A25–A27 failed differently each time before R7F
   passed, which is the profile of an intermittent fault. Four passing pairs
   close the gate; they are not a flake-rate claim.
4. **Not claimed:** final DW1/WYR1 completion, final security review, a
   two-clean-build proof, a selector-34 run result, persistent-root recovery,
   or any hard real-time guarantee. Selector 34 is now *buildable* and gated;
   it has not been run.
5. **Deepwyrm's `#[ignore]`d target-artifact tests still gate link, disassembly
   and boot.** The new aggregate gate proves compilation only.
6. **The bundled-predicate sweep was not exhaustive.** Two further candidates
   in `carrier_admission.rs` and `primordial.rs` are suspected and untraced; one
   confirmed candidate, `current_native_usercopy_is_quiescent`, is unfixed.

## 9. Review identities

Implementation and review by Claude Opus 5, reasoning effort proportionate to
risk, 2026-09-15, against the revisions in §2. Security-relevant work in this
record is defect 4, the syscall-boundary cause erasure: reviewed and fixed at
Deepwyrm `b598302`, verified by target compilation under
`x86_64-unknown-none`, which was itself confirmed by mutation because the
routine host check does not compile that file.

No Critical or High security finding is open. Defect 4 is the only security-
classed item and it is resolved.

## 10. Cleanup and audit

`tools/worktree-lanes.py audit --strict --expect-none` is clean. Historical E7
artifacts and the failed E8 attempts A25–A27 are preserved, not retired. No
unrelated files were retired and no final F5 cleanup was performed.

All commits in this record are unsigned, per `AGENTS.md` §3.
