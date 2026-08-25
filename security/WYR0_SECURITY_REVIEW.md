# WYR0-I Final Security Review

**Status:** Final — PASS  
**Review date:** 2026-08-25  
**Reviewer model:** `gpt-daybreak-blue-latest`  
**Reasoning effort:** high and xhigh independent lanes

## Reviewed candidate

Final product tuple:

- Deepwyrm: `5a8bb0a75979bb3ecde9bd7209619e924ec5e36d`
  - tree: `1cf3e99af8675c5ebdb6cd190463dbb25bbb48df`
- Wyrmroot: `ec84cc6441db15de83d55329ac442a01988c52e9`
  - tree: `c72de62540fbaa38d567079795952a39327fe592`
- Rust: `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`
  - tree: `aa3d5f9d1311772c99e385067d07641c01b8d203`
- coordination root at review start: `48378f6d8eb54b8ff137f97895d8560c8fd2ac74`
- generated Deepwyrm ABI revision: `cfc69bd8a49819ce1cda1a132cf56e55c93f92e4`
- generated Deepwyrm ABI tree: `1c6a74f130e386eee95b3780c75950beefd0037d`

The initial frozen Wave 4 product tuple was Deepwyrm
`117a8b590c427f988a02b26514f5adf897165de7`, Wyrmroot
`b753a3b24461209b89e7b394844889c74fd7a14b`, and the same Rust revision.
Security-sensitive remediation invalidated that candidate. This review's final
disposition applies only to the exact remediated tuple above.

Remediation commits:

- Deepwyrm `5a8bb0a75979bb3ecde9bd7209619e924ec5e36d` — final external-thread process teardown
- Wyrmroot `affed0ba50d5be8d22864ff6af1b96ae0abc2f86` — mapped-memory unsafe boundary and rights minimization
- Wyrmroot `0e4ac0b158d42c34e9232e3e36f84487adefce8f` — attempt-start READY deadlines
- Wyrmroot `ec84cc6441db15de83d55329ac442a01988c52e9` — build-lineage receipts and observed-mask derivation

All product checkouts were clean for the final build, validation, and targeted
rereview. Later security and coordination records are documentation descendants,
not different product candidates.

## Scope and authority

The review covered the WYR0-I supervision/restart state machine; readiness
accounting; generation, transaction, timer, cleanup, and peer-close races;
capability derivation and rights; MemoryObject mapping/share/lifetime behavior;
Channel transfer/backpressure; final-thread process/root teardown; hostile
startup/ELF/bootfs input; WRCAP1 parsing and semantic joins; request, receipt,
artifact, media, result, and certificate substitution resistance; new unsafe
boundaries; accepted toolchain identity; and the kernel/Wyrmroot/future resource
enforcement boundary.

Deepwyrm owns kernel objects, rights, task lifetime, memory, IPC, waits, timers,
and bounded native mechanisms. Wyrmroot owns loading, supervision, controller
admission/accounting, platform policy, media construction, and capability
evidence. WYR0-I does not claim generic hostile-peer TaskGroup quotas,
preemptive scheduling, WYR0-GW acceptance, graphics, or Prismdrake readiness.

## Finding disposition

Initial product findings were C0/H1/M3/L2. All confirmed product findings are
closed:

| ID | Initial severity | Finding | Final disposition |
| --- | --- | --- | --- |
| DB-WYR0I-WR-001 | High | Safe mapped-memory byte views could form aliased or dangling Rust references | Closed |
| DB-WYR0I-DW-001 | Medium | External final `ThreadTerminate` could skip inactive Process root teardown | Closed |
| DB-WYR0I-WR-002 | Medium | `Starting` had no fixed attempt-start READY deadline | Closed |
| DB-WYR0I-EV-001 | Medium | Request-supplied artifacts lacked exact build-lineage admission | Closed |
| DB-WYR0I-WR-003 | Low | Controller-created Channel and TaskGroup rights exceeded use | Closed |
| DB-WYR0I-EV-002 | Low | Certificate wrote the required mask instead of the parsed observed mask | Closed |

Two Low documentation/authority observations are also dispositioned. The root
plan checklist and tuple header are updated with the final Wave 5 state. The
certificate's `inherited_evidence.i0_i1_i2` path names historical inherited
WYR0-H evidence; it is not the exact post-remediation acceptance record. The
evidence root in this review is authoritative for the fresh ordinary, I1, I2,
and capability reruns. Wave 6 must preserve that distinction in the consolidated
validation and completion records.

### DB-WYR0I-WR-001 — mapped-memory safe-API unsoundness

**Disposition:** Closed

Mapped byte-view creation is now explicitly unsafe and documents the complete
liveness, access, initialization, inter-mapping, process, thread, and device
aliasing obligations. Higher-ranked callbacks prevent returned references from
escaping the bounded view. Safe callers can no longer create Rust slices from a
mapping without acknowledging the global proof obligation.

The three capability-controller call sites establish that obligation: initial
writes occur before duplication or publication; protection becomes read-only
before transfer; transferred rights omit `WRITE`; the writable owner is closed
before the controller's shared read; and all views end before unmap. Source and
compile-fail regressions preserve the unsafe declarations, HRTB callback shape,
Safety text, and audited call-site count.

### DB-WYR0I-DW-001 — final external-thread root teardown

**Disposition:** Closed

Deepwyrm preserves the generation-bound target Process through prepared Thread
completion. Remote-stop completion, terminal wait cleanup, and claim/pin
retirement precede inactive-root teardown. The teardown path is restricted to a
successful external `ReturnToCaller` final-thread completion, excludes the
caller Process, and cannot be reached by current-thread termination or a
multithreaded surviving Process.

Regressions cover blocked remote completion, real mapped-root teardown and
constrained-pool recycling, survivor exclusion, and source-order enforcement.
Five live I2 SMP repeats and the paired capability topology passed with the
remediated kernel.

### DB-WYR0I-WR-002 — attempt-start READY deadline

**Disposition:** Closed

`Starting` carries one checked absolute deadline created at initial or
replacement attempt start. `child_started` preserves that deadline; equality or
lateness selects READY timeout and TaskGroup termination. Timer expiry while
still unpublished selects bounded partial-state closure. Generation,
transaction, and exact-deadline joins reject stale events before mutation.

Boundary, replacement, overflow, Starting-expiry, stale-timer, and cleanup
identity regressions pass. The five I2 SMP repeats and both capability profiles
provide live coverage of the surrounding lifecycle and restart topology.

### DB-WYR0I-EV-001 and DB-WYR0I-EV-002 — evidence integrity

**Disposition:** Closed

Every request now requires a strict sibling build receipt before media
construction. Receipt schema 1 binds exact source revisions and trees, clean
checkout assertions, accepted toolchain request/manifest/tree/component hashes,
canonical targets/profiles/recipes, selector/test identity, firmware, and every
admitted artifact hash. Capability receipts additionally bind selector config
and asset hashes.

The receipt hash is carried through provenance schema 3, candidate identity v2,
run-local snapshots, results, and capability certificate schema 2. Substitution
regressions reject changed artifacts, revisions, toolchain identities, or
receipts before media construction.

Certificate generation independently parses both default and SMP result masks,
requires agreement with the requested mask and exact event count, and writes the
parsed value. The final certificate therefore records observed mask `1023` from
validated results rather than copying the requirement.

### DB-WYR0I-WR-003 — excess local authority

**Disposition:** Closed

Controller-created Channels now receive only `READ | WRITE`. Child TaskGroups
receive only `MODIFY`. Their use sites require no duplicate, transfer, wait, or
inspection authority. Exact source-contract coverage preserves the reduced
masks.

## Final validation evidence

Evidence root:

`artifacts/wyr0-i/wave5/candidate-r38-daybreak-dw-5a8bb0a7__wyr-ec84cc64__rust-a92dc7f7`

Accepted toolchain:

- request: `RUST-WYR0-I-B-SYSROOTS-007`
- request SHA-256: `4c404f6f47197fff4cc8d7486ea784a02a0701206ee3d5ee39e5f47ef7efa3ee`
- manifest SHA-256: `cc78368219552cce8fdaad38ab419040cab945fe175aa774d6dca51eece84fd2`
- toolchain tree SHA-256: `dce57d31def1f509ce537f96ae6b6dd320da11c9f321382cb93d142f558a32ca`
- rustc SHA-256: `65bd51e9ecb8e1185524471a8cbc4af1e6ac4e37e7d446c7a127bda0fa431c70`
- Cargo SHA-256: `a73b2c25573d251489101c0d8f19ad3702eb9761166de5ed8437b472b6c038ce`
- rust-lld SHA-256: `38a9f28404309892f9c9afe02fa4979a0d9e8bc866979cde09f5bb7ec17e5721`
- LLVM 22.1.6 identity SHA-256: `ed4f320c4e1ed6de7d2db6fd89faccf764d63186c2f877057ddf31065b1fac09`

Host validation passed for both complete locked workspaces, formatting, diff
hygiene, generated ABI drift, warning-denied Clippy and rustdoc, focused runtime,
payload, task teardown, receipt substitution, and observed-mask regressions.
Deepwyrm reported 625 kernel unit tests plus all integration/source-contract
targets; Wyrmroot `xtask` reported 110 passed with its one explicit accepted-
toolchain environment gate ignored in the ordinary workspace run. The separate
accepted-toolchain positive identity gate passed.

The external-host Deepwyrm production/six-memory-selector artifact oracle passed
with exact direct tool identities. Its production artifact SHA-256 was
`71835f6e141a51d2189381c005fd32acd6a841cb24979f404873ae6278ed4359`;
the six selector hashes were `c6877ba22ec94b8623b2015f5635e6340064201f110e2b7a2974963e32abdf15`,
`40f2261694e09336b30e91d9f474da5c311a7a276f4433d774a997c09fbe9cdd`,
`efb7788a4eeb4858d2a8834539ced7b6acca558927d83c592be6b86ab35d620d`,
`38a274ec1c507ae32d92e8f6ec4f62c171ac206bcfef85a872fbe24d01eda16b`,
`c9e97eb32305a70df7603ab1ca71176cf5327170649c9bdc1b1c7d879eb4aa98`,
and `98c9d71a38d612f2daba4734ac511bf397d59e2e423fc5719c6246d0dead58f7`.
Its build-input manifest and normalized-environment hashes were
`fb6e8e39ea8287f1f9a053a3ba7db9bc1d88c09a1b026911d19019230cd1ae5c`
and `154a1c6fe67684221b2dc317db63e79c5eb9537f1deee6f72589fcae64e9abaa`.

The oracle's first three invocations stopped in identity preflight because the
managed sandbox remapped root-owned host tools to UID/GID 65534, symlinked LLVM
front names were supplied instead of direct regular binaries, and one attempted
rust-lld path contained an operator typo. Two independent Daybreak escalation
reviews reread the oracle contract and active validation sources before the
successful fourth invocation. No failed attempt compiled or implicated product
code.

Two isolated clean source builds produced byte-identical native artifacts,
selector kernels, production loader, bootfs, and ESP. The request-bound audit
returned `ARTIFACT_AUDIT_PASS`:

- ordinary candidate: `9c5b71df681fc0b9722fc7c6d596d52761440f3b91440a02210ad2eb5fb6d3d5`
- ordinary bootfs: `22dc889e487cb1e70a72ad61a205870c2acca1cec1233907e08d07d4fa3619ed`
- ordinary ESP: `6eeb2b5751e3907e2c84e298d0a7d740a3d2d908775af28b6f3721a81628c73e`
- loader: `8d5bc33b3a45e2e6345a6c373678020c0c489c19991137c88b35d658e236216d`

Live q35/OVMF results:

| Gate | Profile | Result | Candidate SHA-256 |
| --- | --- | --- | --- |
| ordinary selector 18 | default | PASS, detail 0, QEMU 33 | `9c5b71df681fc0b9722fc7c6d596d52761440f3b91440a02210ad2eb5fb6d3d5` |
| malformed ELF/startup and capability count/type/rights | default | all five exact expected failures `0xB0000001`..`0xB0000005`, QEMU 35 | request-bound per case |
| I1 selector 23 | SMP, 4 vCPU | PASS, 17 events, mask `0x000000ff`, QEMU 33 | `17ca9edfb361cd800796c250faeab12aae24ddbc78edb2e81b50ecf074b75cfa` |
| I2 selector 22 | SMP, 4 vCPU | five consecutive PASS results, detail 0, QEMU 33 | `3ecca7888ce31912e5dd68e1f74def8cee8c49f1a2be19fae551c217010157c4` |
| capability selector 24 | paired default and SMP | both PASS, 15 events/profile, observed mask `0x000003ff`, QEMU 33 | `6786037dd11ff8ff5c0a28e54f67128c50540fc7b93ce879caf3334ebf63adf8` |

The exact-symbol GDB diagnostic attached to the canonical gdbstub using symbols
SHA-256 `41d1b699543f4cab737547ded26d72ff310ca87ebce30c7c966826263ab3dee9`.
It remains diagnostic and is not counted as acceptance.

Capability certificate:

- path: `i-capability/certificate/certificate.json`
- schema: 2
- SHA-256: `dd4c4af0bd3149823131ac2f68645f0307ea6d794f3cb656e77de7d912b2e760`
- request SHA-256: `a78e550711ff3504ae83eed144f87810aea03544b4d76a66d8215c0a9e50be18`
- build receipt SHA-256: `cbb38e7def3e08219ea0015069a389f3910860f8de1d021a5ffcd7770eb4cfdc`
- provenance SHA-256: `ec2a32908371b61f5291b6ffde9c1aca75b9b96ddab5cba91281e9acf40caa77`
- ESP SHA-256: `1e75731b30572205ded50ee2ea55664708233ab8c3fa3b53a15dcc9898bc46bb`

Independent evidence rereview recomputed all ten request/receipt/media variants,
all 16 retained integration results, 60 capability evidence records across the
two preserved standalone and two paired transcripts, all terminal checksums,
the five I2 repeats, certificate joins, and absence of symlinks or special files
in the evidence root.

## Targeted final rereview

Four independent exact-model Daybreak lanes rereviewed the final diffs and
fresh evidence:

- Deepwyrm teardown: xhigh — PASS, C0/H0/M0/L0
- mapped memory, payload, and rights: xhigh — PASS, C0/H0/M0/L0
- restart deadlines and cleanup races: high — PASS, C0/H0/M0/L0
- evidence, provenance, certificate, and authority: xhigh — PASS, C0/H0/M0/L0

## Accepted residuals and prohibited claims

- Mapped byte access is intentionally unsafe. Future call sites require the same
  global liveness and aliasing audit.
- There is no generic hostile-process containment for directly minted objects,
  mappings, handles, waits, CPU time, or general TaskGroup resources. Wyrmroot's
  controller accounting is not kernel quota containment.
- Cooperative scheduling makes no preemption, fairness, or real-time guarantee.
- Build receipts and run snapshots assume a trusted single-writer host. They are
  not signatures or a hostile-same-UID security boundary.
- Historical WYR0-B ambient host-runtime, process-isolation, and distributable-
  toolchain limitations remain accepted.
- The five deterministic I2 repeat records have no per-run guest nonce;
  separation is established by distinct preserved directories and sequential
  executions.
- This evidence is q35/OVMF validation, not physical-hardware acceptance or a
  freestanding sanitizer claim.
- WYR0-I does not claim WYR0-GW, a final service manager, final VFS/libc/vDSO,
  graphics, Glasswyrm workload acceptance, or Prismdrake readiness.

## Final disposition

| Severity | Open product findings |
| --- | ---: |
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |

WYR0-I Wave 5 / I-G2 passes on the exact final product tuple. No unresolved
release-blocking finding remains. Wave 6 durable validation, completion, root
capability-certificate, integration, and final cleanup records remain separate
work.
