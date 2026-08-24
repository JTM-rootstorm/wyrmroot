# WYR0-H image and integration tooling validation

Date: 2026-08-23

## Scope and disposition

WYR0-H is complete at Wyrmroot revision
`f72eaac5638c634cd58bd2e8f822ceeb4f13fcdd`. The canonical `xtask`
surface now builds and inspects one exact candidate image, launches it under
the locked 1-vCPU and 4-vCPU q35/OVMF profiles, supports GDB with the exact
kernel symbols, captures serial output, and returns structured per-profile
results. The paired integration command always runs both profiles before it
decides the overall result.

`run` and `gdb` are diagnostic-only commands. Their structured output is
explicitly marked `DIAGNOSTIC` with `acceptance: false`; only `test integration
wyr0` writes gate-shaped per-profile evidence or closes a WYR0 acceptance gate.
Acceptance commands require a schema-v2 request; schema-v1 requests and their
outputs are retained only as historical evidence.

This closes the WYR0-H tooling gate. It does not close the separate I0 or I1
guest-acceptance gates. The current exact candidate deterministically exposes
one I0 failure and one I1 failure, recorded below.

## Exact candidate

- Deepwyrm: `1d6b7f4d06d3621bc739d9db4528f37f004bce06`
- Wyrmroot tooling: `f72eaac5638c634cd58bd2e8f822ceeb4f13fcdd`
- Rust fork: `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`
- review request: `target/wyr0-h/candidate-dw-1d6b7f4d__wyr-f72eaac5__rust-a92dc7f7-prei0review/request.toml`
- accepted loader source: `artifacts/dw0-g3/accepted/dw-91d9b204c1ed__wyr-f433baf36d67__rust-a92dc7f7464/artifacts/loader.efi`
- machine: q35 plus OVMF, no virtual network, no host filesystem sharing
- default profile: 1 vCPU, 1024 MiB
- SMP profile: 4 vCPUs, 2048 MiB

The final Wyrmroot commits after the initial H implementation only changed
`xtask` and native diagnostic reporting. Pre-I0 review found that the H runner
had drifted the canonical `default` profile to 2048 MiB and also hard-coded that
stale geometry into inspection/provenance output. Commits `f2e4baa` and
`f72eaac` restore the locked 1-vCPU/1024-MiB default and derive all reported
profile geometry from the same constants used to launch QEMU. Rebuilding the
image with unchanged guest payloads retained the exact payload identities below.

## Canonical interface

From the Wyrmroot repository, with the project-local offline Cargo home:

```text
cargo xtask image --request <request.toml>
cargo xtask inspect-image --request <request.toml>
cargo xtask run <default|smp> --request <request.toml>
cargo xtask gdb <default|smp> --request <request.toml>
cargo xtask test integration wyr0 [default|smp] --request <request.toml>
```

Calling `test integration wyr0` without a profile is the canonical paired
gate. It uses the same ESP for both launches, runs both even if the first
fails, writes `runs/default/result.json` and `runs/smp/result.json`, and returns
success only if both structured guest results pass.

## Artifact inspection

The final image build and independent inspection both passed:

| Artifact | SHA-256 |
| --- | --- |
| `loader.efi` | `09427a9574979a6e1f64f493ebe0c50896e419e625ed3cd614992746d74d9beb` |
| Deepwyrm kernel and symbols | `8f5a980ab463ed5dbc59f9f27d0883ff6ed228da2895cefa7fa0292e35c9e261` |
| primordial bootstrap | `e03f0c2486847239be5d2a76ca8c0d00c5ba390e582e70bc754802ffb75d536f` |
| `system/init0` | `ea2ba32f91a6d5ef97e39c38de660a11e6fda5866966c47589a2b77963051c32` |
| `bin/hello` | `7918ccce644c96a391a457a03f7e060d9ada42cc58ab8c984de594e190ceaf51` |
| bootfs | `67e821d7df67a58395b3f72153aa78e59243a5ac777e9e8270763533c2f31014` |
| ESP | `49e33754430a1a341014f89fd05fdd162e71bf3adb2b7a48ac4377ca02b36060` |

The request-bound provenance record repeats the exact three repository
revisions, profile geometry, OVMF code/template hashes, and all guest-consumed
hashes. Inspection and every integration result include stable request,
candidate, and provenance digests plus the full loader/kernel/bootstrap/init0/
hello/bootfs/ESP manifest, so the default and SMP records are independently
bound to the same image. GDB is rejected unless its unstripped symbols file has
the exact SHA-256 of the kernel placed on the ESP. Output paths also reject a
pre-existing parent symlink that escapes the request root, including a
pre-existing `run_directory` itself. The tooling repeats containment checks at
each create/open boundary and re-admits the request, artifacts, ESP, and
provenance before publishing a PASS result. Every attempted integration profile
writes a structured ERROR result for QEMU spawn, timeout, terminal-record, or
serial-log failures.
Timeout and wait-failure records also carry an explicit cleanup disposition,
with independently confirmed `cleanup_killed` and `cleanup_reaped` fields; a
failed kill or unconfirmed reap is never reported as successful cleanup.

The current V0 tooling residual is an explicit native toolchain-manifest schema;
this hardening batch deliberately does not introduce one. Fresh request output
sets are required for the schema-v2 provenance/evidence format; older
candidates remain historical evidence.

## Host validation

The following checks pass at the Wyrmroot revision above:

- full locked workspace tests across all targets using an exact project-local transport for the pinned Deepwyrm Git revision;
- 59 `xtask` tests, with 58 passing and the accepted-toolchain environment gate
  intentionally ignored by the ordinary host suite;
- strict workspace Clippy across all targets with warnings denied;
- warning-denied workspace rustdoc without dependencies;
- formatting and diff checks; and
- accepted-toolchain native builds of bootstrap, init0, and hello for
  `x86_64-unknown-wyrmroot`.

The H-specific tests cover strict request parsing, immutable exact-artifact
inspection, deterministic FAT32 construction, shared-media profile geometry,
absence of host shares, exact-symbol GDB arguments, checksummed terminal-record
parsing, paired join behavior, and structured host-side failure results.

## Historical pre-I0 paired guest result

The pre-I0 review reran the canonical paired command after correcting the VM
geometry. Both profiles consumed the same unchanged ESP
`49e33754430a1a341014f89fd05fdd162e71bf3adb2b7a48ac4377ca02b36060`
and correctly returned nonzero:

- `default` at the canonical 1 vCPU / 1024 MiB: structured guest `FAIL`, test ID 18, detail `0xB0410005`,
  QEMU debug-exit status 35. The diagnostic identifies bootstrap operation 4
  (`bootfs` mapping) returning native status 5 (`BAD_STATE`). This is the next
  I0 integration blocker.
- `smp` at 4 vCPUs / 2048 MiB: both firmware and Deepwyrm entry completed, then the guest shut down
  without a valid terminal record. The harness wrote structured host result
  `ERROR / terminal_record_invalid`, with QEMU status 0. This remains an I1
  live-runtime blocker rather than a WYR0-H tooling ambiguity.

The two results name the same ESP hash and exact Deepwyrm, Wyrmroot tooling, and Rust
revisions. The corrected inspection report and provenance record both state
`default = 1 vCPU / 1024 MiB` and `smp = 4 vCPUs / 2048 MiB`, matching the
actual QEMU launch arguments. No host-only result is claimed as I0 or I1 guest acceptance.

## Deferred gates

- I0 must fix the 1-vCPU live address-region publication collision and prove
  `bootstrap -> init0 -> hello` plus exact child wait/exit behavior.
- I1 must enable the shared multi-CPU userspace runtime and produce the required
  CPU-participation, remote-wake, and address-space-rendezvous evidence.
- Daybreak remains deferred until the plan's dedicated final D0 security gate.

## I1 host evidence contract

The host integration harness admits the I1 selector only through a schema-v3
request. The selector is `smp-runtime-acceptance`, its stable test ID is 23,
and the request adds the exact fields `evidence_protocol = "dwevid1"`,
`evidence_nonce = "0123456789ABCDEF"`, and `required_evidence_mask = 255`.
The nonce is a nonzero fixed-width uppercase hexadecimal u64. Schema-v2
requests remain the terminal-only contract for non-I1 selectors; test ID 22
remains reserved for I2.
Schema-v3 requests require `expected_outcome = "pass"` and
`expected_detail = 0`; an observed FAIL or PANIC can never produce host PASS or
validated evidence. I1 execution also requires an explicit `smp` profile.
The `default` profile and unprofiled paired integration command are rejected
for schema v3, so an I1 result cannot be wrapped in the schema-v2 paired result.

An I1 serial transcript contains no more than 64 checksummed evidence records
before its single unchanged `DWTEST1` terminal record. Evidence records are
exactly 85 bytes and use this wire form:

```text
DWEVID1|01|NONCE16HEX|SEQ8HEX|KIND2HEX|CPU8HEX|TOKEN8HEX|ARG08HEX|ARG18HEX|CHECKSUM8HEX\n
```

All hexadecimal fields are uppercase and fixed width. The checksum is FNV-1a-32
over the record through the delimiter immediately before the checksum. Sequence
numbers start at zero and are contiguous, the nonce must exactly match the
request, and CPU IDs are limited to 0 through 3. Human diagnostics may surround
or appear between protocol records, but malformed protocol records, duplicate
terminals, evidence after the terminal, unknown kinds, and missing I1 evidence
fail closed.
For schema v3, a line whose beginning case-insensitively resembles either
`DWEVID1` or `DWTEST1` is protocol input, not a human diagnostic. It must use
the exact uppercase magic and complete valid framing. Schema-v2 transcript
handling retains its terminal-only compatibility behavior.

Kind assignments are `01 CPU_ONLINE`, `02 CPL3_SYSCALL`, `03 PARENT_BLOCKED`,
`04 DESCENDANT_RUNNING`, `05 RUNNING_INVARIANT`, `06 WAKE_SENT`,
`07 WAKE_OBSERVED`, `08 CHILD_EXIT`, `09 CHILD_CLEANUP`, `0A TLB_PUBLISH`,
`0B TLB_ACK`, `0C RENDEZVOUS_ACK`, and `0D RECLAIM_ALLOWED`.

The validator requires the complete CPU-online, cross-CPU CPL3, blocked-parent
and running-descendant, running-invariant, remote-wake, child-cleanup, TLB
acknowledgement, rendezvous acknowledgement, and reclaim-order proofs. It
rejects duplicate or inconsistent CPUs, tokens, ordering, joins, and masks.
All four `CPU_ONLINE` records must precede every participation or activity
record. The CPL3 proof uses at least two distinct CPUs and at least two distinct
nonzero execution tokens. `RUNNING_INVARIANT` is pinned as the final evidence
record after all scheduler and lifecycle activity; it may be emitted by any
participating CPU, human diagnostics may follow it, and the terminal record
remains after all evidence. `TLB_PUBLISH` carries the nonempty
operation-specific residency target mask, and TLB acknowledgements cover
exactly that mask. Rendezvous acknowledgements carry and cover their own
nonempty operation-specific stop target mask, which need not match the TLB
mask. `RECLAIM_ALLOWED` repeats the two masks actually observed; neither proof
requires acknowledgements from uninvolved CPUs.
Only after the normal request/artifact/media revalidation accepts a terminal
PASS does the schema-v3 integration result publish the protocol, nonce,
required and observed evidence masks, event count, and first/last sequence.
The observed evidence mask is assembled from the eight proofs actually
validated and must exactly equal the request mask `255`; it is not a constant
success value.
This host-side validation capability is not evidence that a guest candidate
emitted the protocol and does not by itself close I1.

## Accepted I1 and I2 live results

I1 is closed on Deepwyrm `f8117bbe8943ca79d8815061a1a9e09ca0032929`,
Wyrmroot `b90b05602319c5ee89a5ab04e763bdc2bdede453`, and Rust
`a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`. The default schema-v2 regression
passed with candidate SHA-256
`00fb641e7e3b9af4a7de6be95cb7d758d04a24edca77855e2911bb8c0dd545ca`.
The four-vCPU schema-v3 run passed with all 18 evidence events, observed mask
255, candidate SHA-256
`05f075a5c3081f2954f819843baa8bbf3c5c7cffb13ababbfcbe50905a25ba42`,
and exact operation-specific TLB/rendezvous acknowledgement validation.
Results are preserved at
`artifacts/dw0-i1/accepted-dw-f8117bbe__wyr-b90b056__rust-a92dc7f7/default/runs/default/result.json`
and
`artifacts/dw0-i1/checkpoint-dw-f8117bbe__wyr-b90b056__rust-a92dc7f7-evidence-live/runs/smp/result.json`.

I2 is closed on Deepwyrm `18b59ef6f7b20e3ebf1abc8b793452cb22c5f2c6`,
Wyrmroot `e6072c94c678f97ea5993285346408537e5c28a0`, and the same Rust revision.
Five consecutive unchanged four-vCPU runs passed with candidate SHA-256
`56670e4a01b6d766c45bfd27a858ae671cbd12066fef439209287e5c253ef2fc`.
Their structured results are preserved under
`artifacts/dw0-i2/checkpoint-dw-18b59ef__wyr-e6072c9__rust-a92dc7f7-live-7/repeats/pass-1`
through `pass-5`.

## I2 deterministic stress contract

I2 uses selector `smp-adversarial-stress`, stable test ID 22, and a
schema-v4 request. The request is accepted only by the explicit `smp`
integration command and requires PASS/detail zero, a nonzero `stress_seed`,
`stress_run_count` from 1 through 64, `stress_operations_per_run` from 32
through 4096, and schedule identity `dw-i2-splitmix64-v1`. The request also
names the contained create-new V0 manifest path. Schema-v2 and schema-v3
behavior remains the non-I2 terminal and I1 evidence contract respectively.
In addition to the schema-v2 candidate/artifact keys, schema v4 has exactly
these I2 fields and no I1 evidence fields:

```text
stress_seed = NONZERO_U64_DECIMAL
stress_run_count = 1_THROUGH_64
stress_operations_per_run = 32_THROUGH_4096
stress_schedule_version = "dw-i2-splitmix64-v1"
v0_manifest = "request-relative/create-new/path"
```

Each zero-based run seed is the SplitMix64 finalizer applied to the wrapping
sum of the base seed and golden gamma multiplied by the one-based run number.
A zero result is mapped to golden gamma. The integration-only QEMU launch
passes the run index, base seed, derived seed, and operation bound through
`opt/org.deepwyrm.test.stress.*` fw_cfg names. These are test inputs and are
not a production Wyrmroot or native ABI.

Runs are create-new at
`runs/i2/run-NNNNNN/{OVMF_VARS.fd,serial.log,qemu.stderr.log,result.json}`.
The runner stops at the first failure, preserves that run's structured error,
and then writes one create-new `runs/i2/summary.json` recording requested and
completed runs, the failing index, and ordered result digests. A summary is
PASS only after every requested run passes and the complete candidate is
re-admitted unchanged. Guest-reported failure remains `FAIL`; preparation,
launch, collection, or revalidation failure is `ERROR`. Once the I2 output
directory has been created, preparation/hash failures also produce a durable
ERROR summary, and a run that has started gets a per-run ERROR result whenever
its create-new result path remains writable.

Every run requires exactly one checksummed 140-byte stress record before one
unchanged terminal record:

```text
DWSTRESS1|01|TESTID8|RUN8|BASESEED16|SEED16|CONFIGOPS8|DONEOPS8|CPUMASK8|FAMILYMASK8|OUTCOME2|DETAIL8|FAILOP8|STAGE8|CHECKSUM8\n
```

The fixed-width hexadecimal fields and checksum are uppercase; FNV-1a-32
covers the bytes through the delimiter before the checksum. Near-magic,
malformed, duplicate, reordered, or request-mismatched records fail closed.
A passing record requires ID 22, the exact run/configuration, all configured
operations complete, CPU mask `0000000F`, family mask `000001FF`, PASS/detail
zero, failing operation `FFFFFFFF`, and stage zero. The nine family bits bind
handles; channels; waits/timers/terminal retirement; task lifecycle;
mapping/protection/teardown; MemoryObject finalization; subtree authority;
idle/wake/PM timer; and shootdown. Schema-v4 per-run results additionally bind
the serial, QEMU stderr, and per-run OVMF variables hashes.

## V0 evidence freeze

The separate command is:

```text
cargo xtask freeze v0 --request <v0-freeze-request.toml>
```

The freeze request has this exact flat key set (values shown schematically):

```text
schema_version = 1
manifest_kind = "wyr0-v0-freeze-request"
deepwyrm_revision = "FULL40"
wyrmroot_revision = "FULL40"
rust_revision = "FULL40"
candidate_request = "candidate/request.toml"
default_result = "evidence/default/result.json"
i1_result = "evidence/i1/result.json"
i2_summary = "runs/i2/summary.json"
geometry_report = "evidence/geometry.json"
geometry_report_sha256 = "LOWERCASE64"
qemu_argument_report = "evidence/qemu-arguments.json"
qemu_argument_report_sha256 = "LOWERCASE64"
version_report = "evidence/versions.json"
version_report_sha256 = "LOWERCASE64"
host_matrix = "evidence/host-matrix.toml"
manifest = "evidence/v0-manifest.toml"
```

Its strict schema-v1 request has kind `wyr0-v0-freeze-request` and names the
exact three revisions, schema-v4 candidate request, default/I1/I2 results,
locked geometry report, QEMU argument-shape report, version report, host-matrix
manifest, and create-new output manifest. All paths are request-relative,
contained regular files with no symlink traversal; report hashes and every
host-matrix evidence hash must match the coordinator-supplied values. The
host-matrix manifest has kind `wyr0-v0-host-matrix`, a bounded nonzero entry
count, and contiguous `entry_NNN_{name,status,evidence,sha256}` fields; every
status must be `pass`.

The freeze re-admits source revisions and the complete candidate, validates
the schema identities and PASS bindings of default, I1, the I2 summary, and
every ordered I2 result, and writes all artifact, firmware, evidence, schedule,
seed, bound, and matrix hashes. Its disposition is
`BOUND_EVIDENCE_COMPLETE`: it did not rerun guest tests, and cannot publish
`v0_pass = true` unless all supplied matrix evidence and revalidation checks
pass. Required generated-result fields are read directly; missing or mismatched
profile, selector/test, revision, artifact/media/firmware, provenance, stress,
or per-run digest bindings are rejected. The V0 output path must not alias or
contain any input, and the schema-v4 `v0_manifest` must not overlap the
generated candidate or I2 output trees.
