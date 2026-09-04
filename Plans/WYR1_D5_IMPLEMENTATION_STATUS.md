# WYR1-D5 implementation status

**Status:** Reached WYR1-D5 selector-32 live gate on both canonical profiles

**Reached:** 2026-09-04

**Scope:** native console stdin/stdout/stderr, driver replacement, child-only
replacement, exact generation evidence, and canonical VM cleanup. WYR1-D6
and overall WYR1-D closure remain pending.

## Accepted compatible source pair

| Component | Exact revision |
| --- | --- |
| Wyrmroot product source | `a989b34f7ee405fe3c3a6530d234f0846f3d30c7` |
| Deepwyrm kernel source | `58f61b8ad89fa6dbf9a6911bc8d502bda883dcbd` |
| Generated Deepwyrm ABI | `085b184c32ae1fa3d5ec322c86957dd5d036595c` |
| Generated ABI tree | `a9b067107ec38e2be44630f4dce428dab0f48de8` |
| Accepted Rust fork | `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d` |

The independent repositories are not an atomic commit. This record and its
index link are documentation-only descendants of the accepted Wyrmroot
product revision; they do not replace that tested source identity.

## Reached behavior and broad debugging corrections

The selected static `/bin/console-echo` parses exact JobV2 stream roles,
consumes bounded commands through `NativeInput`, and responds through native
stdout or stderr with `NativeOutput`. Source/build contracts exclude debug-write
and privileged driver/registry/control roles from the child. Trusted COM1
records are separate from the actual COM2 application response.

The native path is host COM2 -> interrupt-driven `uart16550d` -> raw WRST ->
`consoled` -> child stdin, returning through child stdout/stderr and the same
bounded transport. Driver replacement retires the old child, then creates a
fresh driver/stream/console/child join. Child-only replacement retains the
healthy raw UART session and console generation while replacing native child
streams and the child generation.

GDB localized successive failures, while complementary reviews examined
callers, shared stream helpers, kernel waits, publication lifetime, launch and
cleanup races, UART completion, and the canonical host exchange. Repairs cover
the joined state space rather than accepting only each observed schedule:

- WRCS 1.1 carries the owner-issued service publication generation separately
  from registry incarnation; normal connector errors do not terminate devmgr.
- Selector 32 has 32 wait registrations for its source-derived
  20/21-registration lower bound, with a regression against the actual kernel
  registry. This is not a native peak-usage measurement.
- Driver retirement joins the actually committed client-release notification
  before rebind while ordinary supervision continues. Delayed observations
  rejoin the retained exact READY tuple after child reap.
- The intermediary consoled-to-init stream MOVE retains the required transfer
  right; the loader performs the unchanged final reduction into the child.
- Shared stream observers accept the ABI's full Channel signal snapshot,
  including the opposite-direction readiness bit. Native peer-close preserves
  earlier committed progress, then reports EOF/Broken without replay.
- Capture joins raw RX, committed stdin, child output and raw TX independently
  of arrival order. CR/LF input state belongs to the surviving console, not
  the replaceable child. Coalesced prior-LF/next-command prefixes are covered.
- Exact-owner visible completed jobs and staged terminal jobs reject TERMINATE
  with InvalidState, allowing the existing client to finish WAIT/CLOSE after
  the CANCEL/reap race. Foreign/hidden/unknown cases retain their rejection;
  shared QUERY/LIST lookup and client acceptance were not broadened.

The selector-private [drain fence](WYR1_D5_DRAIN_FENCE.md) holds U1 retirement
until leg 2/45 bytes, and terminal submission until U2 leg 4/46 bytes. It joins
exact driver/attach/stream identity, empty software TX, hardware TEMT and a
fresh would-block/ack cycle. A raw Channel send alone is not wire completion.
The public WRST grammar and kernel ABI were not expanded for this fence.

## Live evidence

Immutable request directory, relative to the OS-Project root:
`artifacts/wyr1d5-20260904-a5/`; nonce `D500000000000105`.

Both q35/OVMF profiles use the same frozen product, 2048 MiB, and a 120-second
bound. The canonical runner returned PASS/acceptance pass for both default
(1 vCPU) and SMP (4 vCPUs). Each raw capture independently contains:

- 3 complete 178-byte D5READY joins;
- 12 contiguous 192-byte WRD1 records, sequence/type 1 through 12;
- `DWTEST1|01|00000020|00000000|282B09D8` with a verified checksum;
- 3404 COM1 bytes and 445 COM2 bytes: the pinned 354-byte firmware prelude
  followed by exact application responses of 23, 22, 23 and 23 bytes.

An independent reviewer decoded raw records, recomputed FNV challenges and
response hashes, checked all replacement tuples and SHA-256 result fields,
then compared with canonical extraction. No discrepancy was found. Stored
PASS fields alone were not used as evidence. `terminal_qemu_exit = 33` is the
derived expected ISA-debug-exit status, not a captured QEMU process exit code;
the runner separately verified the guest shutdown reason.
Command hashes are derived from the challenge algorithm, not separate host
transmit logs; the corresponding response bytes were observed directly.

The exact tuples below are hexadecimal. Role and bundle remain `1`, and each
distinct endpoint legitimately retains its endpoint-local generation `1`.

| Join | Attempt | Endpoint | Attach transaction | Stream | Console | Child |
| --- | --- | --- | --- | --- | --- | --- |
| Initial C1 | `100000001` | `180000001` | `1C0000005` | `100000002` | `1` | `2` |
| Driver replacement C2 | `100000002` | `180000002` | `1C0000006` | `100000003` | `3` | `4` |
| Child replacement C3 | `100000002` | `180000002` | `1C0000006` | `100000003` | `3` | `5` |

The four independently recomputed challenge tokens are
`2BEE0B9AFB316544`, `0FDF964355464A07`, `58BFEE841B8EE000`, and
`A02C41E3D95BA226`. Leg 2 is stderr; the other three are stdout.

### SHA-256 identities

| Artifact | SHA-256 |
| --- | --- |
| Request | `a40ebaca5d35d0d86e66ec09f430169c3db6c75d9ba7238cc81c6ec474433fb8` |
| Freeze receipt | `9f17a7ebc69293d987650d0e346935ec317bc41377e9e2953645409243ae37e0` |
| Source-build receipt | `0cb0f8c18dcc15fc0581416c136d6daf1f109cc97768827695b17939a9ac2fd8` |
| Profile pair | `427b1870fdbd6c062db9aee666ccaf87256c78a7323ef0e0f007e9a269266c68` |
| Pair result | `7797f99ebcfc3630e7dd79cb8865aa22250941af242faae4c1bf9345cf843501` |
| ESP | `14432cef698d398033141dce8e7056fb68d6333f3a948d244b819ad27aa3fae5` |
| Bootfs | `856a704d4e9ad4186ebcc01f94da800d0cc0c065bb091c5855d83bfca6c72cbb` |
| Kernel and symbols | `a85d6a906e4f61110cc9426da15dbfba87eabd279335bf0a34cb8c4efbca7cde` |
| Both COM1 captures | `77017d2da95570ffba988cdbc70175ab69809b343dda859226db9fe64ef2bfb9` |
| Both COM2 captures | `b6ff96696574e2b4db89a8e3a31143175faa7c5cb21f89701abe35258364c272` |
| Both evidence certificates | `37d2b514acd66c985e7262bbf726c484ecaf32be6f896dde854e7fb756e0d173` |
| Default result and acceptance receipt | `ad8e6f726c26e3dbfc7f450fcb2cd4bc9e80d68ac7eaa1e9676e2278f208804b` |
| SMP result and acceptance receipt | `b62efe63487d4289b2681f01bd66af076c030a099821bc33a0fa62dee7bc4765` |

All request-listed artifact hashes were recomputed after execution. The source
receipt records every constituent ELF/manifest/firmware hash and the accepted
compiler, Cargo and linker hashes. Its toolchain manifest is
`cc78368219552cce8fdaad38ab419040cab945fe175aa774d6dca51eece84fd2`;
toolchain tree is
`dce57d31def1f509ce537f96ae6b6dd320da11c9f321382cb93d142f558a32ca`.

The accepted runner completed retained-input, socket and baseline cleanup.
A subsequent leased read-only VM preflight confirmed `OS-Project` on
`qemu:///system` shut off with inactive XML SHA-256
`a823095e2182f848be0c15fe1a88728fce9f126fbc55e7d9aab30d84a6c5d3c3`.
Both COM2 sockets are absent and the lease was released. Post-run manifest
rechecks passed while allowing only the designated NVRAM contents to change.

For post-run auditing, use `recheck_d5_handoff(..., "post-run")`, not initial
handoff verification, which requires absent outputs and template NVRAM. A seal
has format `SHA256:device:inode`, not a digest alone. A newly captured audit
seal checks current files against the recorded manifest; only the runner's
original seal establishes its retained run-time manifest continuity.

## Host and construction validation

Pinned Rust/Cargo 1.97.1, locked offline dependencies, project-local mutable
state and accepted native sysroot were used. Exact feature/environment rules
are in [D5_VALIDATION.md](../userspace/system-init/D5_VALIDATION.md).

| Gate | Result |
| --- | --- |
| Default workspace `test --workspace --lib --tests` | 1086 passing executions across 76 summaries; 0 failed, 1 existing ignore |
| Selector-32 consoled/devmgr/init libraries | 37 / 37 / 109 passed |
| Workspace Clippy, formatting | Passed; Clippy warnings denied |
| All five native D5 actors | Passed, warnings denied; console-echo native feature explicitly enabled |
| Neighbor selector-31 init/devmgr native checks | Passed, warnings denied; exact `dw1e3-selector31` features |
| Root verifier/runner suite | 206 passed; source unchanged since the A2 check |
| Selected kernel library and entry contracts | 934 + 35 passed; kernel unchanged since that join |
| Selector-32 product preparation and pair preverification | Passed; kernel product build retains 9 existing dead-code warnings |

Logs: Wyrmroot `.tmp/d5-final-host/workspace-a5.log`,
`join-selector-a5.log`, `join-native-a5.log`,
`join-native31-a5-corrected.log`, `freeze-a5.log`, `live-a5.log`, and
`.tmp/d5-final-clippy/workspace-a5.log`; root `.tmp/d5-root-tests-a2.log`,
`.tmp/d5-a5-postcheck.json`, and `.tmp/d5-a5-vm-cleanup.log`.

Preparation used `tools/pinned-cargo xtask wyr1-d5-prepare` with the exact
kernel revision, fresh A5 directory and nonce above. Live acceptance used root
`tools/run-verified-vm-request.py --mode d5-pair` with its canonical exclusive
lease, verified retained artifacts and baseline restoration. GDB runs were
diagnostic only, never acceptance substitutes.

## Required-source receipt and provenance

All external use was conceptual; no external code, ABI or wire format was
copied or adapted. New first-party code remains GPL-3.0-or-later.

| Required source | Exact revision / authority | D5 use |
| --- | --- | --- |
| Root active paired plan and bootstrap/recovery architecture; both architecture indexes; locked WYR1-D and WYR1-B contracts; native ABI and DW0-F0 IPC/wait contract | Reached source state and exact generated ABI above | Ownership, finite recovery, full signal snapshots, stream transfers, publication and terminal-job lifetime, evidence and phase boundaries |
| Fuchsia Zircon interrupt/resource and driver-manager lifetime sources | `6a606ff7fd9b055edee6557566fb3f112df1a812` | Dependency-first retirement and distinct lifetime generations; FIDL/devfs/component policy not adopted |
| xv6 UART/console/trap/PLIC sources | `35b088427ef37611c38afdeed5a52a278cae38f9` | Drain/interrupt/retirement ordering; kernel console and descriptor model not adopted |
| rust-osdev uart_16550 implementation/configuration/README | `176b07b076bdc1fe999a5e757ab53a0e24b4005c` | Register and drain semantics; direct-port and spin APIs not adopted |
| linenoise C source/header | `a473823d74b93eab2ba83480df16ed37617493f2` | Re-read during broad investigation; POSIX terminal editing, history and allocation remain inapplicable |

## Released D6 join and nonclaims

This reaches D5 only. D6 still requires the exact-current canonical regression
matrix and permanent WYR1-D validation record. No overall WYR1-D or DW1
closure, WYR1-E/wyrmsh, interactive shell, POSIX TTY/descriptors, physical
hardware, general IOAPIC/MSI/MSI-X support, or final Daybreak/security-gate
conclusion is claimed. General registry-only broker refresh remains the
separate limitation in [the publication handoff](WYR1_D5_PUBLICATION_HANDOFF.md).

The 40 KiB selector resident partition is a documented soft-budget increase;
the 128 KiB stack is unchanged, and no measured maximum-stack claim is made.
Consolidating mutually exclusive dispatcher storage remains optimization debt.

All D5 worktree lanes were integrated and retired. Strict zero-lane audit finds
no registered lane but reports the pre-existing unregistered
`.worktrees/deepwyrm/.tmp`; it was preserved, so the strict audit is not claimed
clean. Unrelated Glasswyrm files and previous failed A1-A4/GDB evidence remain
untouched. The root `WYR1D5_PHASE_HANDOFF.md` retains the investigation lineage.
