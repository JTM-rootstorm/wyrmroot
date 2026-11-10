# WYR1 Security Review (F4)

**Status:** Final.

- No Critical or High findings.
- Three Low findings, all fixed.
- One Medium (WYR1-F4-M1), dispositioned below.

**Review date:** 2026-11-10

**Reviewers:** Claude Opus 5.5 (`claude-opus-5-5`), as independent read-only subagents that did not write the code:

- the initial review;
- a targeted rereview of the fixes.

**Reasoning effort:** low (the session setting).

**Companion record:** `deepwyrm/security/DW1_SECURITY_REVIEW.md`

## Revisions

- Reviewed: Wyrmroot `4d9ac48ed9d0399f86d84fbb15ed16093deab8bb`, paired with Deepwyrm `d09d3f4e1286cc133c593c4d086809d488584d3f`.
- Fixes:
  - `a0cdf88`: fixes L1–L3.
  - `37c818e`: fixes rereview finding D1.
- Final compatible pair: Wyrmroot `37c818e` with Deepwyrm `d09d3f4`.
- Baseline: the F3 freeze `ce71302`. The post-F3 cleanup removed about 169k lines:
  - system-init was pruned to the product path and split by responsibility;
  - the WYR1-A/B gate code and the D5 relay were deleted;
  - the bootfs marker paths were renamed;
  - large modules were split into submodules.

  This cleanup, together with the L2 fix, means F3 needs a new candidate freeze.

## Method

The initial review was read-only and built nothing. The reviewer extracted both trees into scratch space.

It compared each function in the new code with the old production arm, not with the no-selector arm. It rebuilt the old production arm with a cfg evaluator from the exact F3 product feature sets in `WYR1F_PRODUCT_NATIVE_SPECS`.

Sources:

- plan §F4;
- the F2B4 unsafe audit;
- the F2B hardening record;
- `WYR1_B_REGISTRY_LAUNCH_CONTRACT.md` §9.4;
- `WYR1_E_WYRMSH_CONTRACT.md`.

## Findings and remediation

### WR-F4-L1: launch-scope admission had no regression test (Low; fixed in `a0cdf88` and `37c818e`)

The refactor deleted the only test that checked which launches each session scope admits. These rules back two of the mandatory probes:

- ConsoleLauncher admits only ShellV1;
- ShellJobs admits only `bin/hello` and `bin/cpu-hog`, and never ShellV1.

`a0cdf88` added dispatch tests. The rereview (D1) found they could not detect a widened allowlist. With no policy loaded, a refused scope and a missing policy give the same reply.

`37c818e` added a direct table test of both predicates, covering accepted and refused paths. All three mutants fail it:

- console launcher admits LAUNCH;
- ShellJobs allowlist widened;
- ShellJobs admits ShellV1.

The dispatch tests still pin handle cleanup and the reply.

### WR-F4-L2: the closed recovery-trigger grammar was still accepted (Low; fixed in `a0cdf88`)

The launch-policy parser accepted WRJP minors 0 and 2 and the E8 recovery-trigger profile 3, and `authorize` admitted profile 3.

The parser and encoder now accept only minor 1 and refuse every other minor and profile. `authorize` admits only JobV2. A regression test covers both refusals.

The rereview confirmed that minor-1 semantics are unchanged and that nothing previously rejected is now accepted.

### WR-F4-L3: xtask read build outputs by path after checking them (Low; fixed in `a0cdf88`)

The product builder checked a file and then read it by path, leaving a window to swap the file.

It now opens each file once with `O_NOFOLLOW|O_NONBLOCK`, then checks it with `fstat` and reads it with a bound, on the same descriptor. The read length is checked against the stat result. A regression test confirms that symlinks are refused.

The rereview confirmed that no legitimate input stops working: the OVMF images are regular files and Cargo outputs are hard links.

### WYR1-F4-M1: orphaned non-exiting jobs fill the connection slots (Medium; accepted with a target)

The repro is to run `spawn bin/cpu-hog` and then `exit`, repeated:

1. `exit` leaves the job running, as the WYR1-E contract and B §9.4 retain-and-reap require.
2. Init marks the job orphaned.
3. A closed ShellJobs connection is reclaimed only after all of its orphans exit (`jobs.rs` `reclaim_closed_sessions`), and `cpu-hog` never exits.

After about 15 shell generations, `open_connection` fails because `MAX_CONNECTIONS = 16`, so no new shell can start until reboot. Each orphan also keeps a CPU busy.

**Disposition:** accepted for WYR1. The behavior follows the contract, and only the local console operator, who can already shut the system down, can trigger it.

**Target:** add an orphan policy before packages, or before any non-console session. Options are terminating the orphans of a closed connection after a grace period, or a per-connection orphan quota. This pairs with the kernel's TaskGroup quotas (DW1-F4-M1).

## Risks and questions

- **Shell stream handles.** Init checks the four ShellV1 stream handles only for object type and rights, not direction or role. This relies on consoled being trusted, and is unchanged since F3.
- **dev-boot markers.** `dev-boot --check` accepts any COM2 output that contains the prompt. It is development tier and gates nothing. The kernel review confirms that userspace cannot write COM1.
- **Payload identities.** The bootfs builder takes payload identities from its caller. This fails safe, because system-init and the registry recheck SHA-256 before every launch. The device manifest and product marker are trusted as boot media, as they were at F3.
- **Symlinked directories.** `O_NOFOLLOW` covers only the last path component, so a symlinked parent directory is still followed, as before.
- **Leftover system-temp writes.** Other xtask tests (`secure_fs`, `elf_runtime`) still write under the system temp directory. The new tests use the project's `.tmp`.

## Areas reviewed with no finding

- **Protocol crates and the shell parser and editor.** The protocol crates are launch, registry, device, stream, console, `wyrmsh-core` and `uart16550-core`. Their tests were moved and the dead D5 module was deleted. Parser, editor, ANSI, UTF-8 and quote handling are byte-identical to F3.
- **Loader and EFI loader splits.** These were mechanical, and the removed functions had no callers. The EFI loader went from 97 `unsafe` sites to 92; every one removed was in dead code.
- **system-init.** Against the old production arm, it keeps every close, abort, poison and disconnect cleanup, every rights check, replay check and handle-count bound, in the original order. The admit-everything `Historical` scope is gone.
- **devmgr.** Removing the D5 relay matches the old production behavior, and every count, rights and close check in `receive_controller` remains.
- **uart16550d, consoled, wyrmsh and bootstrap.** Only dead selector arms were removed. In wyrmsh, the six-role startup check is unchanged: exact argv, init parse, then a fresh object-type and rights check on all six handles.
- **runtime.** All test-evidence features and raw syscalls are gone, and no selector features remain in any manifest.
- **Widened visibility.** Every `pub(crate)` widening stays inside one process binary.
- **Mandatory probes, traced as holding:**
  - ConsoleLauncher cannot launch anything but the shell;
  - ShellJobs cannot launch RRC services or ShellV1;
  - job IDs are scoped to their owner and orphan state, and replay is checked per connection;
  - stale sessions are refused;
  - a shell replacement gets fresh registry and launch grants;
  - only one shell session can exist.

## Validation of the fixes (development tier)

- `a0cdf88`:
  - tests, clippy with `-D warnings` and fmt pass for `wyrmroot-bootfs`, `wyrmroot-system-init` and `xtask`;
  - `xtask dev-boot --check` passes, with both changed crates recompiled.
- `37c818e` is test-only:
  - the system-init and xtask tests pass;
  - clippy passes;
  - the three mutants above were each run and each fails the new test.

These are development-tier results. They are not cited as passing the F3 matrix.
