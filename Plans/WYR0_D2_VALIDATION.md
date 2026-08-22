# WYR0-D2 Native Bootstrap Validation

**Status:** Host gate passed; live G3/G4 integration remains open

**Review date:** 2026-08-22

**Artifact source revision:** `bd2343bd8db5f539d4dbadfec8b3cc9138016f7c`

**Artifact-oracle revision:** `bd2343bd8db5f539d4dbadfec8b3cc9138016f7c`

## Scope and result

The D2 checkpoint now produces a real freestanding primordial bootstrap for the built-in
`x86_64-unknown-wyrmroot` target. It enters through the shared native startup boundary, validates
the actual bootstrap Channel, receives and revalidates the exact INIT capability set, maps only the
logical bootfs bytes read-only, validates the two required executable paths, sends READY, closes its
temporary capabilities, and exits deterministically.

Minimal native `system/init0` and `bin/hello` executables use the same startup boundary and exit
deterministically. They are genuine ELF payload fixtures for the G bootfs, not sentinel bytes and
not a claim that the later userspace-loader chain is implemented.

This closes the WYR0-D2 host gate. It does not close WYR0-F, G3 artifact acceptance, production
Deepwyrm boot-path wiring, or the designated-VM gate.

## Exact inputs

- Wyrmroot source: `bd2343bd8db5f539d4dbadfec8b3cc9138016f7c`
- pinned/consumed Deepwyrm source: `9954cbc053874c3076640c8cd9dc1c5bf5cf0647`
- Rust target source: `fc555b0e2ef86b8037b6069ef3157c4862fa028d`
- stage-1 `rustc`: `rustc 1.97.1-dev`, LLVM 22.1.6,
  SHA-256 `65bd51e9ecb8e1185524471a8cbc4af1e6ac4e37e7d446c7a127bda0fa431c70`
- host Cargo driver: `cargo 1.96.1 (356927216 2026-06-26)`
- inspection tools: LLVM 22.1.8
- target `core` archive SHA-256:
  `2be4d4a78f50902f6cef050e663516e6969bc99a815f599133ac4e731b4e594b`
- target `compiler_builtins` archive SHA-256:
  `d1678aeeef897d644bc05ecd245a884e012c8fb384847eec3ca9bc6b0a81f1e1`

The bootstrap link map has SHA-256
`07125a553abe722023e8c633f3a05bf87b4906828ef1b87e5929b9d5861cebc7`. It records selected
objects from the target `core` archive and no selected `compiler_builtins` member. The latter is a
separately identified compiler-runtime input, not a libc dependency.

## Artifact inspection

`toolchain/inspect-native-artifact.sh` passed each production native executable. The oracle checks
the complete program-header table against the G1 primordial subset, including file and mapped-size
caps, allowed header kinds, load range/congruence, page overlap, W^X, NX stack, executable entry
placement, absent dynamic metadata and relocations, no undefined symbols, and exactly one raw
`syscall` instruction in the Deepwyrm-owned `dw_syscall6` veneer.

| Artifact | SHA-256 | Bytes | Shape |
|---|---|---:|---|
| `bootstrap.elf` (`wyrmroot-bootstrap`) | `5a825d6da2345f94659efdb5c7627cfcc35c212c88495d67f2dd5f15c599e995` | 17,520 | fixed static ELF64 `ET_EXEC`; one RX `PT_LOAD`; non-executable stack |
| `system/init0` (`wyrmroot-init0`) | `937464a104782ca8da3c99199e6866ce5779b0e274e0c0912656bc363b972907` | 8,312 | fixed static ELF64 `ET_EXEC`; one RX `PT_LOAD`; non-executable stack |
| `bin/hello` (`wyrmroot-hello`) | `5f5246a222670530e14ced2bf6bb2f442d47763d9298280fef4e845b859e127e` | 8,312 | fixed static ELF64 `ET_EXEC`; one RX `PT_LOAD`; non-executable stack |

No writable static content was retained, so LLD correctly omitted an empty RW `PT_LOAD`; no
writable-executable segment or executable stack is present.

## Bootfs determinism and content

Two independent invocations of `wyrmroot-bootfs-build` over the native payloads produced identical
archives:

- bootfs SHA-256: `0a7722b4c9fe6f4fa6e194a4eeedad84b292f1a0f4b69c16fc0bdaab8333e8da`
- `system/init0`: executable, 8,312 bytes, extracted SHA-256 exactly matches the native artifact
- `bin/hello`: executable, 8,312 bytes, extracted SHA-256 exactly matches the native artifact
- archive metadata and ordering remain the normalized deterministic WYR0-C `cpio newc` form

## Host verification

- locked workspace/all-target tests: passed, including the new synthetic bootstrap transaction,
  failure cleanup paths, startup callback boundary, source contracts, and bootfs encoder target
- strict workspace/all-target Clippy with warnings denied: passed
- warning-denied workspace documentation: passed
- native release build with `-D warnings`: passed for bootstrap, init0, and hello
- native artifact oracle: passed for all three executables
- deterministic bootfs double-build and extracted-content hash comparison: passed
- formatting and diff checks: passed

The synthetic fixture exercises the same shared transaction used by the native entry: exact
Channel metadata, exact INIT bytes and received/fresh capability metadata, logical-size mapping,
bootfs parsing, READY encoding, and deterministic handle cleanup. Negative cases cover malformed
protocol data and missing/non-executable required entries.

## Sol review and hardening

The 2026-08-22 one-over found two D2-specific contract gaps and closed them in
`bd2343bd8db5f539d4dbadfec8b3cc9138016f7c`. First, the generic WRBP V1 decoder correctly
permits arbitrary nonzero transaction identifiers for future protocol users, but the locked G0
primordial exchange requires INIT transaction id exactly `1`. The D2 bootstrap now enforces that
specialization before capability use or READY, closes both received capabilities on rejection, and
has a regression test proving txid `2` cannot receive READY.

Second, the native artifact oracle did not fully mirror two G1 ELF rejection rules. A bootstrap with
ELF `e_ehsize = 63` and one with an unknown `PT_GNU_STACK` permission bit both passed the old
oracle even though Deepwyrm rejects them. The oracle now requires the exact 64-byte ELF header and
56-byte program-header entry sizes and consumes `llvm-readobj` raw numeric flags so unknown load or
stack permission bits cannot disappear behind `readelf`'s display formatting. Both hostile mutated
fixtures are rejected while the production artifacts still pass.

The fixed source was rebuilt with the same recorded stage-1 rustc whose SHA-256 is
`65bd51e9ecb8e1185524471a8cbc4af1e6ac4e37e7d446c7a127bda0fa431c70`. The reviewed bootstrap
remains 17,520 bytes and now hashes to
`5a825d6da2345f94659efdb5c7627cfcc35c212c88495d67f2dd5f15c599e995`; `init0` and `hello`
reproduce their pre-review hashes exactly. A fresh double bootfs build remains byte-identical at
`0a7722b4c9fe6f4fa6e194a4eeedad84b292f1a0f4b69c16fc0bdaab8333e8da`. The locked full workspace
test suite, strict Clippy, warning-denied documentation, shell syntax, formatting, diff checks, and
hardened native oracle all pass. This remains a project-local D2 host validation result rather than
an immutable G3 promotion.

## Remaining gates

The files under `artifacts/wyr0-d2/` are project-local validation outputs, not immutable G3 accepted
artifacts. G3 must rebuild and promote a named Wyrmroot/Deepwyrm/Rust revision set with immutable
artifact identities. Production loader/kernel wiring and the exact designated-VM gate remain open.
The minimal stage-0 payloads do not yet create, load, start, or wait for child processes.
