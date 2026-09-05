# WYR1-E1 parser and command model validation

**Date:** 2026-09-05
**Scope:** E1A tokenizer/unescape/argv command model and E1B property corpus.
**Status:** E1A and E1B complete; pure parser gate accepted on 2026-09-05.

## Reached implementation

`crates/wyrmroot-wyrmsh-core` is a dependency-free, `no_std`, unsafe-forbidden
library with no allocator, syscall, terminal or command-execution dependency.
`Parser` owns one reusable 4096-byte scratch buffer and 64 argument descriptors.
`parse(&[u8])` accepts at most 4096 input bytes, validates UTF-8 and rejects NUL,
then scans the grammar without recursion. Each scanner iteration consumes at
least one byte; escape handling consumes two bytes and never expands output.
UTF-8 validation and final argument-range checks are separate bounded passes.

`Arguments` borrows validated UTF-8 scratch and immutable half-open ranges.
The borrow prevents reusing the parser while its previous result is still in
use. Errors return no partial argument view; a subsequent parse starts fresh.
Empty quoted arguments have zero-length ranges. The parser validates each
argument boundary and rejects scratch overflow through a checked write helper.
The public grammar cannot expand beyond the input bound; a focused internal test
exercises that write guard directly.

`Arguments::command()` returns typed command data or a typed usage error.
The fixed eleven-entry `COMMANDS` table provides names, arity and usage text
for later help/dispatch integration. Runtime effects remain deferred.

### Exact interpretation details

These implement the active plan and frozen E0 contract; they do not change either
wire protocol or the authority of system-init:

- ASCII separators are space, tab, LF, CR, vertical tab and form feed. Non-ASCII
  whitespace stays literal. Submitted-line length excludes the editor's Enter
  event; the byte parser itself treats embedded LF as an ordinary separator.
- Single quotes copy literally; double quotes admit only backslash, quote,
  `n`, `r`, and `t` escapes. Outside quotes a backslash consumes exactly the next
  byte. Mixed quoted/unquoted spans form one argument; empty quoted spans survive.
- Pipes, redirects, semicolons, dollars, backticks, braces, parentheses, hashes,
  glob characters and ampersands have no operator or comment interpretation.
- `help`, `clear`, `exit`, `services`, `tasks` and `status` take no operands;
  `wait` and `terminate` take exactly one; `echo` is variadic; `run`/`spawn` require
  one path plus optional arguments. Extra operands produce a typed usage error.
  Exact arity makes the usage syntax explicit where the plan did not separately
  state an extra-operand rule.
- Run/spawn command data includes the path as child argv[0], excluding the shell
  verb. Empty later child arguments are preserved. At most 64 total shell tokens
  means at most 63 child argv entries for these commands.
- Job IDs are nonzero canonical unsigned decimal u64. No sign, leading zero,
  surrounding whitespace, separator or non-ASCII digit is accepted. Overflow
  returns a typed error; u64::MAX is accepted.
- A path must satisfy both existing launch transport and archive naming rules:
  nonempty ASCII, at most 256 bytes, relative, no empty or dot/dot-dot components,
  NUL or backslash, and not the exact reserved path `TRAILER!!!`.
  `bin/TRAILER!!!` remains valid under the archive's existing whole-path rule.
  Spaces or metacharacters within a quoted canonical component are literal;
  nonexistent/disallowed payloads are not authorized by successful parsing.
  System-init retains immutable launch-policy enforcement.

## Source and provenance receipt

Baseline root: `ddaf8eed206ae742e10772da67dd924ed3e26e36`.
Baseline Wyrmroot: `77fb1ab21e72de9785e5a5b34672f696f2f32cd0`.
Both were clean at E1 entry. Deepwyrm, the Rust fork, wire/runtime/service sources,
products, historical stub and VM state are outside this change.

The unchanged dependency reading and accepted source tuple from
[the E0 inventory](WYR1_E0_TRANSITION_INVENTORY.md) remain the prerequisite.
The following sources were specifically applied to E1:

| Source | Disposition |
| --- | --- |
| Root `AGENTS.md`, `LICENSING_POLICY.md`; Wyrmroot `LICENSING.md` | Authority: scoped lanes, pinned execution, new component GPL-3.0-or-later |
| Active `WYR1E_DW1F_WYR1F_IMPLEMENTATION_PLAN.md`, sections 3.8, 3.10, 3.12, E1 and E1A/B cards | Binding grammar, fixed data/command bounds, typed errors, property gate |
| [Frozen E0 contract](WYR1_E_WYRMSH_CONTRACT.md), section 7 | Binding quote/escape, literal metacharacter, job-ID and storage decisions |
| Wyrmroot architecture index and platform conventions | Native UTF-8 text, case-sensitive `/` paths, capability separation |
| Root `DW1_WYR1_INTERACTIVE_SHELL_IMPLEMENTATION_PLAN.md` | Concept: native shell/command direction; active plan supersedes older unsupported-metacharacter prose |
| Current `wyrmroot-launch-proto/src/lib.rs::validate_path`, bootfs `src/path.rs` and `src/launch_policy.rs` | Integration constraints: independent small path predicate is the intersection of the existing validators; no validator changed |
| Redox Ion `1440704f7456fa4c9f873b7b17dd4f0369b0c4ab`: `src/lib/parser/mod.rs`, `src/lib/parser/lexers/arguments.rs`, `src/lib/parser/terminator.rs` | Concept only: all three exact raw GitHub files read; separate scanning/termination and quote/error state, focused parser tests. No source adapted |
| Linenoise pinned E0 receipt | Not applicable to E1; editor prior art must be applied in E2 |
| Retained wyrmsh stub | Not applicable as a parser template; historical artifact remains unchanged |

Ion's allocation, panic-on-invalid-UTF8 terminator, multiline/comment/operator
semantics, arrays, substitutions, brace/nesting methods and differing single-quote
behavior do not fit the frozen grammar. An independent fixed-storage Rust scanner
avoids importing those semantics or its allocation model. No external code was
copied or substantially adapted. Package metadata, SPDX notices and the component
license map identify the new code as GPL-3.0-or-later.

## Validation

E1A implementation commit: `a9b990d35dd5a68247646656605d0c9af8ccdab6`, unsigned,
configured author and Codex coauthor. Initial deterministic gate: 1 internal
scratch-guard test plus 10 integration corpus tests passed. Strict Clippy passed.

The pinned host launcher verified Rust 1.98.1 commit
`48a229ceaefd4985c50990b14116b6d856af0985`, Cargo 1.98.1
`797e8a9bc`, and the repository's locked offline dependency graph. Host `--lib`
check and release build passed. This is separate from the accepted native
Rust-fork/toolchain and is not a guest executable build.

LLVM `llvm-nm` 22.1.8 inspection of the release rlib found only core UTF-8,
slice/memchr and checked-index panic support as undefined symbols, with no
allocator, std or syscall reference. Together with the dependency-free `no_std`
implementation and fixed arrays, this supports allocation-free parser operation.
Checked-index panic routines still exist in the object; this is not a claim that
all panic symbols were removed. The corpus checks absence of observed panics and
the implementation bounds its input/output indices.

Local logs and the host rlib are retained under
`wyrmroot/.tmp/wyr1e-e1-20260905/`; no build outputs or logs enter Git.
E1B tests are committed at `3b714cf84436204f31530495085e8fee4b71757b`, on the
unchanged E1A implementation. The tests commit is unsigned with configured author
and the exact Codex coauthor trailer. Its sole changed file is
`crates/wyrmroot-wyrmsh-core/tests/properties.rs`, SHA-256
`3402b1cbb2b07b449a217c0079f9c383e4c75851620101b860794ce67d54d360`.

### E1B corpus and final checks

The deterministic, dependency-free property harness uses explicit XorShift64
seeds and independent generated expected values; no external fuzz engine or
coverage-guided campaign is claimed.

| Corpus | Bound / oracle |
| --- | --- |
| Arbitrary-byte input | 8,197 cases: unrestricted and grammar-focused streams at every length 0 through 4097, then 8192-byte oversize; seed `d1ceba5ecafef00d` |
| Exact-limit malformed input | NUL and invalid UTF-8 at every position of a 4096-byte line; 8,192 rejection cases, plus recovery checks |
| Valid argv generation | 2,048 independently serialized expected-argv roundtrips; Unicode, escapes, metacharacters, empty arguments and 64-argument cases; seed `6b6f626f6c642131` |
| Job IDs | 2,624 generated decimal cases at lengths 0 through 40 compared with a wider u128 oracle, plus explicit boundary/negative cases; seed `7573697a655f3634` |
| Command/path boundaries | Fixed command shapes, 64/65 tokens, 256/257 path bytes, ASCII component cases and exact versus nested archive sentinel |

Successful arbitrary-input results must have contiguous ranges, valid UTF-8
boundaries, no NUL and aggregate scratch length no greater than input length or
4096. Both successful and rejected input are followed by successful parser reuse.
Valid roundtrips compare actual argv with values generated before serialization.
The command tests preserve metacharacters as one command's data and return typed
arity/path/job errors without invoking any runtime operation.

Final suite: **17 passed, 0 failed** (1 internal + 10 corpus + 6 property tests;
0 doc tests). Property-only run: 6 passed. Pinned format, check `--tests`, and
Clippy `--tests -- -D warnings` passed. The coordinator independently reran the
full suite and format check after fast-forward integration into canonical
Wyrmroot; all 17 passed, with the property group finishing in 0.08 seconds.
E1B corpus invocations were bounded by a 60-second timeout. No panic or nontermination
was observed. Test-side Vec/String allocations belong to the host generators;
they are not the allocation model of the no-std library.

Reproduce from canonical `wyrmroot/`:

```sh
export WYRMROOT_PINNED_TARGET_DIR="$PWD/.tmp/wyr1e-e1-20260905/target"
timeout 60 tools/pinned-cargo test --locked --offline -p wyrmroot-wyrmsh-core
tools/pinned-cargo fmt -p wyrmroot-wyrmsh-core -- --check
tools/pinned-cargo check --locked --offline -p wyrmroot-wyrmsh-core --tests
tools/pinned-cargo clippy --locked --offline -p wyrmroot-wyrmsh-core --tests -- -D warnings
tools/pinned-cargo build --locked --offline -p wyrmroot-wyrmsh-core --lib --release
```

### Scoped review and exact evidence

Adversarial parser review and property-test development used exact model
`gpt-daybreak-blue-latest`, reasoning effort `high`, on 2026-09-05. Reviewed base:
`a9b990d35dd5a68247646656605d0c9af8ccdab6`; final candidate:
`3b714cf84436204f31530495085e8fee4b71757b`. Review found **no concrete parser
defect**: scanner progress is monotonic/nonrecursive, input/output indices remain
bounded, errors do not expose stale results, and job arithmetic is checked.
This is the scoped E1 parser review, not an E8 or final-F security gate.

Tools were the repository's hash-verified pinned Rust/Cargo 1.98.1 launcher,
Rust test harness, rustfmt, check and Clippy with warnings denied. Inputs were
the frozen grammar/command contract and the exact deterministic corpora above;
no external scanner, libFuzzer or service was involved. Bounded corpus success
and source reasoning are not an exhaustive proof for every possible input.

Final implementation SHA-256 identities:

| File | SHA-256 |
| --- | --- |
| `src/command.rs` | `bc6140755f586dd9a1dd10e6bc9603132c91720fd5141052d5c2ceb9cbd2acbd` |
| `src/lib.rs` | `bcab8aad76806c7ba029ae41d03f0665e1a3599e90ab503816c6387267272ad7` |
| `src/parser.rs` | `b515164ca6115d586d1a79078bfd335de302c8f8ce4b5e66bc2e2887d3be0bf9` |
| `tests/corpus.rs` | `7515997046c24dccb178b542361e8657870b308a6b7013350182ae5152aa5ba2` |

The `wyr1e-e1-properties` lane was clean, integrated and inactive before retirement;
its merged branch was deleted, registrations pruned, and strict zero-lane audit
passed. Logs were copied to the canonical evidence directory before removal.
The audit log records zero lanes with only completion-document changes pending.

Local evidence hashes:

| Log | SHA-256 |
| --- | --- |
| `coordinator-test.log` | `6857bd384ccfe301d6cc0ea49a4086f029dcae34ba44d004ede58270198f3688` |
| `lane-full-test.log` | `05a265f6c66fc6e880c74529420110c861615808b5e32411071a7070a3e7a552` |
| `lane-properties-test.log` | `1d5dc1cb9a44db54d544a81ad0d6fb3b678700764736028ffcc75f50130259ee` |
| `lane-fmt-check.log` | `f8a0efb5b50ed1665d78a8b2b34368b0531555bf754d62215241403fc66d3c4e` |
| `lane-check.log` | `4c01eb23cb95d17a19e6d6c620feecff4f7f93107a2c7c704cb7184abb9b7c58` |
| `lane-clippy.log` | `c9d8ded1cced1f55318c0a31998f10b6d9382e07027b3a41761977060d3ed507` |
| `lane-audit.log` | `bb462549ac8ff91090cf3c31cb5119a0765bf2b04e3364529155f47cdb1fb4a2` |

## Limits and next handoff

E1 implements pure grammar and command data only. It does not implement E2 input
or editor handling, E3 wire/startup changes, builtin I/O, job launching, an actual
shell executable, product selection, selector33, VM/native acceptance, stack
measurement for the complete shell, or E8/final DW1-F/WYR1-F security closure.
