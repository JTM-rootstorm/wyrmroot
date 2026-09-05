# WYR1-E2 input/editor validation

**Date:** 2026-09-05
**Scope:** E2A incremental decoder and E2B editor/history/redraw host model.
**Status:** E2A/E2B complete. Host-model checks and scoped reviews accepted.

## Authority and source receipt

Baseline root: `9145483823be6c9740c5a513e496c7ee48e8aeb4`.
Baseline Wyrmroot: `85883ff447aad1547bb18230825e217a9835641a`.
Both were clean at entry. The existing [E1 parser gate](WYR1_E1_PARSER_VALIDATION.md)
is the consumed pure-model prerequisite. Root `AGENTS.md`, licensing policy,
active implementation plan E2A/B and sections 3.8-3.10, the frozen wyrmsh contract
section 7, Wyrmroot architecture index/platform UTF-8 conventions, and the original
interactive-shell plan's editor/control rules were read and applied.

The [E2 contract](WYR1_E2_EDITOR_CONTRACT.md) explicitly resolves decoder
resynchronization, Unicode filtering, history draft restoration, submission custody
and viewport semantics. The root plan and reached wyrmsh contract carry the same
clarifications. No kernel, wire/profile, service, product or historical-stub path
is changed by these pure input/editor modules.

Linenoise `a473823d74b93eab2ba83480df16ed37617493f2` was read from the clean,
verified pinned checkout at root `.tmp/e2-d3-prior-art/linenoise-src`.
Both required files, `linenoise.c` and `linenoise.h`, were consumed completely.
Disposition: **concept only**. Useful concepts were explicit edit state, mutations
separate from redraw, scalar editing, saved draft during history navigation,
clamping/oldest eviction and batched CR/erase/rewrite/cursor movement. No C source
was copied or adapted. Allocation, termios/fds/ioctl/libc, width discovery,
blocking ESC reads, hints/completion, paste folding, multiline semantics and
linenoise's broader controls/different nonempty Ctrl-D behavior were rejected.

The extra 4096-byte draft is a recorded storage addition, preserving typed input
without competing for the 16 KiB committed-history arena. The fixed 80-column
viewport resolves the earlier full-line wording without terminal queries or
vertical-cursor controls; it retains the entire 4096-byte logical line.

## Implementation and checks

The initial decoder was `cdeb020777223a802c4ab4338179c77d673877d6`.
Daybreak remediations were `cb7ee542d2379f7426b100ff82a6696d5f78fb1a` and
`87dfaca24fc9aa74f645ef3f7ee00cbbe6da7ab9`. Editor/history/redraw was
`549e4dac1470a0158348e088bcfd6d02be5c4400`; the integrated production-source
candidate is `d3c4367a7973eebbaccd44dcc6680372bdecf8e2`. Joined properties were
added in `ed5d4be5581f730474b74f8af8a5fcfbade83c3e`; the host measurement helper
and its licensing row are `0e99afa27c50e20b9996a6077534e3dc10586222`.
Final measurement-tool hardening is `ffa9c20422f7b84e723586abbf9993cc30ef4f56`.
Later delivery documentation does not change those measured production sources.
Deepwyrm remains `18c5b6abf52deb08d2d5ccc45b40896329dc8650`; Rust remains
`a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`. Neither repository was modified.

All production core modules remain no-std and unsafe-forbidden, with no allocator,
syscall or host-terminal dependency. Host tests may allocate reference models and
collected output. The borrowed line/redraw views and explicit submission
acknowledgement keep input stable while the caller consumes it. Runtime adapters
must stop consuming transport input on submission until acknowledgement.

The pinned Rust 1.98.1 host test suite passes **44 tests**: 1 parser unit,
10 E1 corpus, 6 E1 properties, 8 decoder, 12 editor and 7 joined properties.
The joined suite covers 386 uniformly generated/control-biased byte streams of
lengths 0..192, all byte values, and whole/byte/random fragmentation including
zero-length chunks (seed `0xe2d05ca1a7e52026`). It also checks every split of a
meaningful mixed stream, 80 sessions against an independent scalar/history model
(seed `0x71570a175eed0032`), line/history limits and eviction, submission custody,
nested controls, redraw determinism and progress. Boundary checks include a
4096-byte saved draft with cursor at 2048 and an exact 302-byte maximum redraw.

Commands from Wyrmroot, with a task-local `WYRMROOT_PINNED_TARGET_DIR` and a
60-second timeout each:

```text
tools/pinned-cargo test --locked --offline -p wyrmroot-wyrmsh-core --test e2_properties
tools/pinned-cargo fmt -p wyrmroot-wyrmsh-core -- --check
tools/pinned-cargo clippy --locked --offline -p wyrmroot-wyrmsh-core --lib --tests -- -D warnings
tools/pinned-cargo test --locked --offline -p wyrmroot-wyrmsh-core
tools/pinned-cargo check --locked --offline -p wyrmroot-wyrmsh-core --lib
```

The Clippy command was corrected during E3A/B preflight to match the actual
E2 invocation (`--lib --tests`); the launcher rejects `--all-targets`. This is a
command-receipt correction, not a new E2 test run.

All passed on the joined lane; the coordinator independently repeated the full
44-test suite successfully on canonical `0e99afa`. Logs were copied before lane
retirement to `.tmp/wyr1e-e2-20260905/` in Wyrmroot. They are local evidence,
not repository content. SHA-256 receipts:

| Evidence file | SHA-256 |
| --- | --- |
| `coordinator-tests.log` | `611f4816550ec0717110b85d17bd1c3f615c0a3668f071e0a97bc928244a8c67` |
| `joined-01-e2-properties.log` | `3a507323a90f1346337c0945df4efe517dc2bfce34edac8deec51bdddcc470bf` |
| `joined-02-fmt-check.log` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `joined-03-clippy.log` | `57a952b8f05a61c328f1de6b8b76319a74c736c91f101bed4be521f3849b7e77` |
| `joined-04-full-tests.log` | `62988f549fa433d8b3b46330146809908cb4b4ef5fa09eef421efebb53f37813` |
| `joined-05-library-check.log` | `cec9a83ca2d8adcd56e414d8ebfc99304883ae8d72bd6a482c9ce4606597b424` |
| `lane-audit.log` | `f34ecc72c6edaf21afcd0ac2d0289686931ee5ec15956644e6981343605ae28f` |

## Scoped review and regression receipt

All substantive security work below used exact model
`gpt-daybreak-blue-latest`, reasoning **high**, on **2026-09-05**.

The initial four green decoder tests were insufficient. Review of `cdeb020`
found SS3 `ESC O A` leaking its final byte, missing Unicode Cf/Zl/Zp filtering,
and malformed/nested escape recovery allowing control constituents through.
`cb7ee54` fixed the initial cases, but the narrower first-final discard rule
still leaked the trailing `A` in an overlong CSI followed by nested `ESC [ A`.
Further focused regression work also exposed nested OSC payload leakage.
`87dfaca` completed quarantine-only nested sequence handling, including CSI,
SS3, intermediate escapes, strings and bracketed paste. Rejected candidates
were not accepted as E2. Failing-first observations are retained in the task
transcript, not archived red-log files; the committed regressions and final
passing logs are durable reproducible evidence.

The immediate decoder review and joined-property lane accepted production
candidate `d3c4367` with the seven property tests subsequently committed in
`ed5d4be`; no remaining Critical, High or Medium finding was reported. An
independent static Daybreak lane reviewed editor/history/redraw and editor tests
at the same `d3c4367`, also with no Critical, High or Medium finding. It did not
run tests or review the decoder. Its two requested boundary coverage additions
(maximum redraw and maximum draft restoration) are included in joined properties.
These are scoped E2 reviews, not the final E8/F security gate.

Reviewed content hashes (SHA-256):

| File | SHA-256 |
| --- | --- |
| `src/input.rs` | `115ee5d57a0453c4bddabb34af95ad4e9767ba9f3c42baeae2c412e3296262f6` |
| `src/editor.rs` | `97c32e406a5e8fd09dc53f2e04549cf7d1ec6837a2715fc589cb560be9f971d7` |
| `src/history.rs` | `1388ae65cbd50c674dbc0c5a7069152abf891afcc0c8cf5b5fb5c2efe6e95d62` |
| `src/redraw.rs` | `4da70036c1f5dbc668f4ec6fedae43add970cbcb8fa241bb7928d214d0e7cb96` |
| `tests/editor.rs` | `c3b9901da6de1f22829b4919b1c6e024601a25d8581dd08e609cc09685a79774` |
| `tests/e2_properties.rs` | `0603dd13cdbded9f37404c5d28fb6f94890f22bef9b8cdc3c4e5570fed85b1f6` |
| `Plans/WYR1_E2_EDITOR_CONTRACT.md` | `3ae1c087a37fc45aee4cead256e985179d47f776f3f5766c5628478d1b9e1d0f` |
| `Plans/WYR1_E_WYRMSH_CONTRACT.md` | `ad8827658368dca9b8bb077acdf4f44bd7c2c7eea494b3007e2add81b82e39aa` |

Source/test paths in this table are under `crates/wyrmroot-wyrmsh-core/`.
The complete Unicode 17.0.0 Cf category table (170 code points, 21 ranges), plus
Zl/Zp exclusion, was adapted from the Unicode Consortium's
[DerivedGeneralCategory.txt](https://www.unicode.org/Public/17.0.0/ucd/extracted/DerivedGeneralCategory.txt),
dated 2025-07-24. Unicode-3.0 attribution and the full notice are retained in
`src/input/unicode_format.rs` and `LICENSES/Unicode-3.0.txt`; the crate license
expression and `LICENSING.md` identify the mixed boundary. The incorporated
table hash is `0e0ce24cd22ab8d98ddca0639fef430b5c28a1ffa4ce5f3d1bc751f203555cd0`;
notice hash is `abf84f74dea2812799e1dbef7f0581adf7db244881e4febb8684f441568da0ad`.
Interrupted full-file fetches are not claimed as a verified upstream file hash.

## Memory measurement method and result

From the workspace root:

```text
python3 wyrmroot/tools/wyrmsh-core-measure.py wyrmroot/.tmp/wyr1e-e2-measure-r3
```

The helper first checks the core with pinned Rust 1.98.1, locked/offline. The
measurement itself uses accepted Rust **1.97.1-dev**, commit
`a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`, explicit **host Linux** target,
`-Zemit-stack-sizes`, optimization level 2, one codegen unit and aborting panics.
This follows the supported stack-metadata mechanism in `tools/xtask/src/wyr1b.rs`,
without changing the compiler or native product gate. A first operational attempt
with stable `-Cllvm-args=--stack-size-section` yielded empty metadata and was
rejected; `.tmp/wyr1e-e2-measure-r1` is retained as failed evidence.

The tool binds the accepted `RUST-WYR0-I-B-SYSROOTS-007/manifest.toml`, compiler,
driver, LLVM and required host libraries by hash, before and after execution.
It owns flags, uses fresh project-local output/state and verifies recursive source
and artifact hashes. LLVM readobj 22.1.8 must return named frames, including the
measurement entry. The fixture is a host ELF; no guest payload is host-executed.
The output report records exact tools, inputs, flags and artifact identities.

| Observed quantity | Bytes |
| --- | ---: |
| Editor, including committed history and draft | 24,792 |
| Incremental decoder | 64 |
| Parser | 5,120 |
| Combined state including 4096-byte output buffer | 34,072 |
| Borrowed redraw cursor | 56 |
| Maximum reported named frame: `measurement_entry` | 50,616 |
| Host thread stack requested by fixture | 110,592 (108 KiB) |

The successful bounded exercise covers maximum lines, cursor/edit/redraw/parser
paths, history byte and entry eviction, draft restoration and decoder inputs.
The stack size is the fixture's request, not an observed usable stack extent.
Fixed `size_of` state does not establish placement, and individual frame metadata
does not establish the aggregate worst-case call-chain peak. This host evidence
closes the E2 model measurement; actual native shell layout, adapter call chains
and the 108 KiB working-stack acceptance remain E6 obligations.

The final report `.tmp/wyr1e-e2-measure-r3/report.json` SHA-256 is
`d249a5dc313d709aa6abcf8c144004c91ecde7c3e2f19a21bb6fac605a7f42b5`.
Its artifact hashes are:

| Artifact | SHA-256 |
| --- | --- |
| Core rlib | `b62f8fe10c5996f6536b89eee40ffb87dd851287bbcb3b0006e074b2d223f791` |
| Core object | `35ce671eabdaf8716557be447ad3dc421ccb99059ac473682446ba64ca7ecbdc` |
| Host fixture | `bedf4d3659581882792f41d1250d7861647802506539287c50b46243b8ee5ec1` |
| Fixture object | `65c7f400c58ab59ea909e80b43274417607f5629047999feea8c83938d8dc9d7` |

## Measurement-tool review

The independent Daybreak lane also reviewed helper revision `0e99afa` on
2026-09-05 with high reasoning. It verified the saved r2 report against all
12 recorded source hashes, four artifacts and 35 named frame entries without
rerunning the successful fixture. No Critical, High or Medium finding was
reported. Three Low findings were identified: timeout cleanup reached only the
direct subprocess, the hard-coded stack field could be mistaken for an observed
extent, and the executed pinned-cargo launcher was absent from source hashes.

All three were remediated in `ffa9c20422f7b84e723586abbf9993cc30ef4f56`.
Commands now run in fresh process groups and timeout kills the whole group;
the fixture derives `requested_host_thread_stack_bytes` from the same constant
used for thread creation; and the launcher is checked and hash-bound before/after
preflight and at completion. The Daybreak lane self-reviewed the exact
`0e99afa..ffa9c20` diff with the same model/effort/date and reported no remaining
Critical, High, Medium or Low finding. A focused two-second timeout regression
proved both a parent and its descendant were gone after cleanup. Its local
`.tmp/wyr1e-e2-timeout-regression-r1/result.json` SHA-256 is
`84663dac693c1580eeda7fc391c5ed293c6f1c2e377e0e374db51622cee7d49c`.
Python parsing, pinned rustfmt check and diff whitespace check also passed.

Final helper SHA-256 identities:

- Python: `57e9266d2c68cb8673dd4ba658912025248e429e0221f4fae169a4aac9766773`.
- Rust fixture: `4f3c4cdd969f8f3864e98e73e699bcad7cdcb4591bfdb1236d9b89c4e5867137`.
- Executed pinned-cargo launcher: `dbd49bb3e317fda95f400d40009cd0797a3cfdb7d112a6384f64924e3002ac7e`.

The coordinator reran the full measurement on committed `ffa9c20` into fresh r3,
then independently verified all reported source/artifact hashes. It passed with
the same fixed-state and maximum-frame values. The earlier r2 output remains
historical evidence rather than being overwritten (report SHA-256
`2f4b4e118c7680c03233a68bd16a89d873443cd2e9448b1e5f4793d67bb3d9da`).

## Integration and cleanup

Both implementation lanes were integrated, verified clean and inactive, and
retired with their merged branches after copying their logs. Worktree pruning
reported no stale registrations; strict `--expect-none` audit passed for Wyrmroot.
No VM was inspected or operated; there is no VM state/result claim for E2.

## Limits

E2 does not implement the WRST/runtime adapter, builtin I/O, native shell process,
launch/registry/status protocols, product selection, selector33, VM acceptance or
final WYR1-E/DW1-F/WYR1-F security gate. The viewport has a deliberate scalar-width
model: ASCII positioning is defined for terminals at least 80 columns wide;
non-ASCII storage is valid and edits preserve scalar boundaries, while full
combining/grapheme/wide-character rendering remains deferred.
