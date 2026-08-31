# Wyrmroot WYR1-C Validation and Closure Record

**Status:** Accepted on the exact selector-29 default/SMP candidate
**Validation date:** 2026-08-31
**Deepwyrm implementation revision:** `6ba05d6706a0f376c0af0b4ce86305af01748cce`
**Wyrmroot product revision:** `b872e3bd465e3f6d9c9e90adbceb3756dc490dc2`
**Rust revision:** `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`
**Selector:** `device-coordinator-restart` / test ID 29

This record closes WYR1-C's hardware-independent device-coordinator scope.
The accepted product is the Wyrmroot revision above; this validation commit
does not replace that frozen product identity.

## Accepted source and ABI tuple

The accepted selector-29 product consumes:

| Component | Exact identity |
| --- | --- |
| Deepwyrm selected kernel | `6ba05d6706a0f376c0af0b4ce86305af01748cce` |
| Wyrmroot selected product | `b872e3bd465e3f6d9c9e90adbceb3756dc490dc2` |
| accepted Rust fork | `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d` |
| Cargo-locked generated ABI revision | `085b184c32ae1fa3d5ec322c86957dd5d036595c` |
| accepted generated ABI content tree | `a9b067107ec38e2be44630f4dce428dab0f48de8` |
| accepted compiler | `wyrmroot-1.97.1-a92dc7f7`, rustc SHA-256 `65bd51e9ecb8e1185524471a8cbc4af1e6ac4e37e7d446c7a127bda0fa431c70` |

The generated ABI tree is the same content accepted at canonical DW1-D ABI
revision `dc26df4a3d701e2cdf8b495e2c87ce979969a9c4`. The lockfile's
`085b184c...` identity is recorded rather than silently relabeled; both map to
the exact tree above. The accepted DW1-D implementation baseline remains
`c153ab9af4d80c3b51c0140fb4ad1f6be962bb35`, with Wyrmroot integration
baseline `6aa6cc38595dad805af07d89e78393943b835490`.

## Reached lifecycle

The selector-29 product admits only q35 COM2 resource identity 1, PIO range
`[0x2f8, 0x300)`, platform interrupt source 3, and the statically selected
`uart16550d` acceptance actor. COM1 is absent from the device manifest.

The live path proved:

1. devmgr generation D1 claims the broad DeviceResource at rights `0x3c3`;
2. U1 receives exactly `[DeviceResource 0x103, Interrupt 0x310]` by atomic
   MOVE after the Interrupt was created with custody rights `0x390`;
3. U1 validates exact received object types, rights, resource/lease identity,
   fresh Interrupt object and binding generations, then sends READY;
4. registry publication P1 occurs only after READY;
5. the selector triggers one structured U1 failure, retires P1, reaps U1, and
   releases the old Interrupt;
6. U2 starts under the same D1 lease with a fresh Interrupt binding, validates
   the same exact bundle contract, reaches READY, and publishes P2;
7. P2 is newer than P1, while stale U1 control and P1 publication operations
   are rejected;
8. a live malformed bundle probe places a second reduced DeviceResource in
   the Interrupt slot and receives exact `MalformedResource` without
   disturbing U2;
9. D1 then fails intentionally, P2 retires, U2 reaps, D1's generation cleans,
   and its grant becomes available before D2 obtains a distinct lease; and
10. D2 starts, claims the same manifest identity under the fresh lease, and
    reaches coordinator READY.

Driver restart is bounded to four attempts with a 25,000,000 ns backoff.
The run observed one driver failure and one devmgr failure without exhausting
either budget.

## Selector-29 product identities

The retained local evidence root is:

```text
../../.tmp/wyr1c6-candidate-30
```

| Item | SHA-256 |
| --- | --- |
| request | `4c0c1cba3216e4c2e13f85847d6b295e0cb9e5215ea7d783750c8f275fd8e101` |
| source-build receipt | `1efb9ce40065e14b7ec0f288839448a27d101e1390760a88489b4a445a298f78` |
| build receipt | `08ca00aa65d30d754b7bfdcb7728a0513e83884e33f4bb9d51c3f68fd1d48022` |
| kernel and symbols | `5a1ed1789a02e8d6044d8d19c3a2fca2c075f008b8e1ecc6f9acfe3854aa80e9` |
| bootfs | `9f0725d8c3946cf4543f50762f1e7e7e03f20c15d20d4fce4b782f288a94cbbd` |
| ESP | `d5df549597d44f7688fb5749f8cb112db15cd8d811d72220f3184483a9e3fcba` |
| boot-device table | `0b65678aba6f7b9241ecef0469536835ff7bad90f8348e268609a1abf0194962` |
| RRC-C6 manifest | `ad76d34f830ee075709ed550311141ccb3c1df67bacbba5364798613bc1e3ef8` |
| WRDM-C6 manifest | `aa3a1a3cdceac5412f989ca15d3d12ffe7d8bd648cccdc2a8426b9e9d9ff5be5` |
| profile-pair result | `3aea22392632fe3e02e1068ff9c69dd49e3495d91c5ea3f8f018ead566c43179` |
| evidence receipt | `4553fb0cc773fae318c6866e8bf61fc3974c78713f4291452461df5b57b90ae2` |
| OVMF code | `f3ff7e73448ed2845ee15356f394882f5618eb5dab92c9a30ec6ee0e1468553a` |
| initial OVMF variables | `6ed987af3a3c155be71665f510eae3e007eda9b8b94afd59d45e91c4a11565cc` |

The request binds evidence nonce `C600000000000042`, challenge
`C600000000000043`, the WRC6E1 protocol, and the no-I/O scenario
`driver-and-devmgr-restart-no-io`.

## Live default/SMP acceptance

The canonical verified `qemu:///system` runner accepted both profiles on the
designated `OS-Project` domain and restored the approved inactive definition
SHA-256 `a823095e2182f848be0c15fe1a88728fce9f126fbc55e7d9aab30d84a6c5d3c3`.

| Profile | Machine | Result | Structured evidence |
| --- | --- | --- | --- |
| default | q35/OVMF, 1 vCPU, 1024 MiB | PASS, test 29, detail 0 | 27 records, terminal `FF` |
| SMP | q35/OVMF, 4 vCPUs, 2048 MiB | PASS, test 29, detail 0 | identical 27 records, terminal `FF` |

Both serial logs are byte-identical at SHA-256
`777af7b5eb6f11b85c68390100576d14ded3a0425aff7347f4bfabf7188857f6`.
Both WRC6E1 transcripts are byte-identical at SHA-256
`570aef9dc493555f89c2204f084f94afee972e503f7147a824dfdb42f5b8902e`.

The exact joined identities are:

- D1 lease 1 and D2 lease 2;
- U1 Interrupt binding 1 and U2 Interrupt binding 2;
- P1 publication generation 12,650,497 and P2 generation 12,650,498;
- ordered events 1 through 26 followed by the zero-tuple `FF` terminal;
- three non-coordinator principals with no direct device authority;
- zero physical device-I/O operations; and
- bounded accounting of one driver failure, one devmgr failure, four-attempt
  policy, and 25,000,000 ns backoff.

The post-run OVMF variables SHA-256 is
`802952f5c62d1e25e632477b935d63fcfea8d787dbcb58391ab83af00a640e82`.
The evidence command verifies the immutable initial profile binding, so the
mutated per-run variables were first preserved as `OVMF_VARS.post-run.fd` and
the frozen initial template was restored to `OVMF_VARS.fd`. Every
post-build `tools/pinned-cargo` command used its own task-owned
`WYRMROOT_PINNED_TARGET_DIR`; omitting that binding can select a non-marker
target directory and is not an implementation failure.

## Exact-current regressions

The regression evidence root is:

```text
../../.tmp/wyr1c6-regression-wyr1b-6ba05d6
```

| Selector/scenario | Result | Request / product / result identities |
| --- | --- | --- |
| selector 25 normal, default + SMP | PASS; 5/5 records; terminal `NORMAL`; identical serial SHA-256 `cef34f0460eb832724b6b7cead69e917af7b225fb3558443b34cb92761af61c2` | request `89a77f08de3afe8da62dbe6239fd363eb8389fe56498ce4d24bb2b2fb156ab4d`; bootfs `2abb261ed9b4105e69bef923110acf00d9c6c8953494815dfbcfcb8aed68e843`; ESP `82788c03ca76ac0fd3d3c2d750c66499814d3477af3fc4879e9fd09a9ee4878f`; pair result `009c1db24138ae1da0b05cd43139d01f145fc44aa808140d69d7c48cb450a074` |
| selector 25 degraded recovery, default + SMP | PASS; 9/9 records; terminal `DEGRADED`; identical serial SHA-256 `8f4c2c1b7ae65c9e681c2bf0f5ae0c14b9e03486396d04cfaa7562ba317b77f9` | request `dad37f79bb1c9b669f0b7b560980c294aaf8fd4e82419fa7161e182e6f5ce71d`; bootfs `4b0353f0b69f49de4d4d91ecacb82781bec802b73d249d48c80d7ee363636518`; ESP `7ba0c85c85786d8ff2574f1c426ee5dde12bf207007bc55186e33d50d97f5878`; pair result `e7de4550c6d2fbe7bc7eb8180bee11b2e4915e918ca8ce9280739dcfaa50dfb3` |
| selector 27 registry/launch | PASS; 14 ordered WRB1 records; terminal `normal`; serial SHA-256 `ec58a5d076542600947d30b157329a2c7119a9f7838cefdd271ab8605fc45849` | request `86821981334e9a436cec7ab2d4ea19c38b96fd62611898193b546ad34fd0565d`; bootfs `3e0b0be3dff4d87470646733e50b67f8b01f91eb4fc5fadf7a142ac918759ed2`; ESP `3be1b3ac719c19e5f17e07f2a99201f22a35f6af2c927937d87657ea56a0ac6f`; run receipt `c617e7786fa3af8a2308f5595c57af5984059bf037a40f8757868a432e93ac38` |

The current selector-28 regression used retained root
`../../.tmp/wyr1c6-regression-dw1c-6ba05d6`, request SHA-256
`f9f021ab8deab107e60272314ce9c250ca3bb479301c0f75ee190645ed132619`,
and progress digest `D1C6A11CE5EED041`. The verified six-pass campaign
(smoke plus five stress boots) passed with exactly 46 records per boot; its
campaign-result SHA-256 is
`b78b8e06d4738e4058597a56768dd5e9471ba7c70a809beab14dcea1b610c7b1`.

## Debugger-led regression remediation

The first selector-28 regression of the stronger terminal-root synchronization
candidate reached a `DWTEST1` panic at `primordial.rs:1185`. Before any retry
or source change, active GDB used the exact booted symbols and showed CPU2 in
`complete_remote_stop` while the logical current already owned the exact
active root. The helper had incorrectly treated a valid no-op
`prepare_scheduler_root_switch()` result as a lost claim.

Deepwyrm `6ba05d6706a0f376c0af0b4ce86305af01748cce` accepts that exact-root no-op
after remote stops while preserving the physical terminal-owner invariant.
The durable trace is
`../../.tmp/wyr1c6-regression-dw1c-ca8b83c/gdb-smoke/active.gdb.log`, SHA-256
`113a41b65e2c007564cd2b917b9c65588e7b00429cf05fab65ce706f5a0cdcae`;
its symbols SHA-256 is
`d9ecb019a3bf3d23e56b8e729fd1b6dcbe3823311e8c545a75291deb4e76223f`.
The fixed selector-28 six-pass campaign and the selector-29 default/SMP pair
then passed without a panic.

## Host, model, product, and hygiene gates

At the accepted product revisions:

- the full locked Wyrmroot workspace/all-target suite passed, including 228
  xtask tests with the one accepted-toolchain artifact test intentionally
  ignored;
- the focused C6 model passed 38 device-protocol, 19 devmgr, and 104
  system-init tests;
- the accepted product compiler checked the exact C6 feature sets for
  bootstrap, system-init, devmgr, and `uart16550d`;
- warnings-denied Clippy passed for the C6 device-protocol, devmgr, and
  system-init libraries;
- formatting and `git diff --check` passed in both repositories; and
- Deepwyrm's full workspace/all-target suite, 770 kernel tests, 53 syscall
  contract tests, warnings-denied Clippy, formatting, ABI/tooling checks, and
  accepted selector-29 freestanding build passed before the final live pair.

## Required-source and provenance disposition

Implementation and closure followed the root DW1-C/WYR1-C plan, the Wyrmroot
architecture index and platform conventions, the device-coordinator and
device-handoff contracts, WYR1-C3/C4/C5 status records, the bootstrap and
recovery architecture, accepted DW1-D contract/validation, and Deepwyrm's
selector-29 WRC6 seam. The pinned Fuchsia driver-manager sources at revision
`6a606ff7fd9b055edee6557566fb3f112df1a812` were used only for conceptual
comparison of coordinator/driver separation and retire-before-replace order.
Their BSD headers were checked. No Fuchsia code, FIDL, component policy, wire
ABI, or driver-host assumptions were imported.

## Acceptance boundary

WYR1-C proves typed COM2 DeviceResource/Interrupt custody, direct reduced
driver delegation, READY-before-publication, intentional driver and devmgr
restart, cleanup-before-replacement, stale-generation rejection, live malformed
resource rejection, non-escaping authority, and bounded accounting on the
selected q35 default/SMP product.

It does **not** claim physical IRQ3 delivery, IOAPIC routing, Interrupt
fire/wait/ack/rearm behavior, UART PIO/register/RX/TX behavior, serial bytes,
console/TTY/shell service, physical hardware, MMIO, DMA, IOMMU, WYR1-D,
DW1-E, full WYR1 closure, or a final Daybreak security gate. No UART I/O was
performed or used as acceptance evidence.

At the exact identities and evidence above, WYR1-C is accepted.
