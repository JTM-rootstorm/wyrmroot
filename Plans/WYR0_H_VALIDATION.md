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
revisions, profile geometry, and all guest-consumed hashes. Inspection rebuilds
the expected bootfs bytes from the exact current `init0` and `hello` inputs and
rejects stale image or provenance content.

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

## Current paired guest result

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
