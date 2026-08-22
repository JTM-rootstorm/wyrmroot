# DW0-G3 Paired Artifact Validation

**Status:** G3 re-promoted, G4 accepted, and G5 Daybreak remediation accepted; P0 accounting remains open

**Review date:** 2026-08-22

**Deepwyrm artifact revision:** `91d9b204c1ed0bdd4cef934e1be6203d41e9e5c3`

**Wyrmroot artifact revision:** `f433baf36d671f3f8b515adf5f613bd01dc8bbb9`

**Rust source revision:** `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d`

## Result

DW0-G3 now has one exact, project-local paired artifact set re-promoted after G4 and G5 fixes. The production Deepwyrm kernel enters
the real primordial launch path, and Wyrmroot provides the exact loader, native bootstrap, minimal
native payloads, bootfs, and deterministic FAT32 ESP consumed by that path. Canonical G4 run 19
then booted the paired test ESP through the designated VM and passed selector 18 with detail zero.
The subsequent G5 Daybreak gate found and remediated terminal lifecycle and target-feature defects,
then passed exact-diff rereview. P0 remains a separate accounting gate, so this does not yet claim
DW0-G full acceptance.

The revision-named accepted root is:

`artifacts/dw0-g3/accepted/dw-91d9b204c1ed__wyr-f433baf36d67__rust-a92dc7f7464/`

Its `G3_EVIDENCE.toml` records source trees, toolchain identities, artifact sizes and hashes,
inspection results, licensing boundaries, and host gates. `MANIFEST.sha256` verifies every promoted
compiler/runtime input and guest-consumed artifact without relying on a mutable `target` or `latest`
path.

## Pin and source equivalence

Wyrmroot continues to consume the exact Git pin
`9954cbc053874c3076640c8cd9dc1c5bf5cf0647` for `deepwyrm-abi` and
`deepwyrm-syscall`; both `Cargo.toml` and `Cargo.lock` name that revision. The later G3 kernel
candidate changes kernel implementation and documentation, but its three consumed interface trees
are byte-identical to the pin:

- `abi`: `1c6a74f130e386eee95b3780c75950beefd0037d`;
- `crates/deepwyrm-abi`: `3c4b82b4253d7d21d0f578d8d5b966304472cd8f`;
- `crates/deepwyrm-syscall`: `554b61417fc21b2da4b1c9c8f20694be86e02740`.

Cargo resolved the dependency as its canonical pinned Git source. A process-local Git URL rewrite
populated the project-local Cargo cache from the clean Deepwyrm repository without changing the
manifest, lockfile, source identity, or accepted dependency graph. No Cargo path patch or host path
dependency was used for accepted artifacts.

For host-local replay, set `DEEPWYRM_REPO` to the clean Deepwyrm checkout and use a disposable Git
configuration only for the Cargo process tree:

```sh
rewrite="$(mktemp)"
git config --file "$rewrite" \
  url."file://$DEEPWYRM_REPO".insteadOf \
  https://github.com/JTM-rootstorm/deepwyrm.git
GIT_CONFIG_GLOBAL="$rewrite" CARGO_NET_GIT_FETCH_WITH_CLI=true \
  cargo test --locked --workspace --all-targets
rm -f "$rewrite"
```

The rewrite changes transport only. Cargo still resolves the GitHub source identity and exact locked
revision `9954cbc053874c3076640c8cd9dc1c5bf5cf0647`; it does not create a path dependency or patch.

## Accepted artifacts

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| production `deepwyrm.elf` | 11,098,264 | `51372c6f5b73a7a31d77133086205a9bd2b65c179c0c2a5f0e827bc36136b8b0` |
| selector-18 kernel | 11,189,304 | `638d23bbaf7ff4b8f627728f0c33a23d4e03238aaef0599cc30c69bf11af15e3` |
| selector-19 kernel | 11,189,288 | `25df039fc9b3330b0c910968c31445e5104d5a9e2ea3ec4163650ebd6cb621af` |
| selector-20 kernel | 11,189,336 | `664c01294cc063757160a2808903bf25c6e82672e3250b75904062ad6c4594c2` |
| selector-21 kernel | 11,189,320 | `751578ca069552c105d090e8e9973de2c93a23e7a7ef2b04f39b2ee48274c61a` |
| `loader.efi` | 138,752 | `09427a9574979a6e1f64f493ebe0c50896e419e625ed3cd614992746d74d9beb` |
| retained `loader.pdb` | 8,056,832 | `58f209ad2369bee1a378532046c04a9ed3fe24f596ea9056e231a6295519088d` |
| `bootstrap.elf` | 17,936 | `59cca570d52400dfa7dc3aef469b9c4cfafbf03db9e9675195c3fcc6913077b5` |
| selector-19 bootstrap | 22,264 | `bb0aa46bf9de6a3baee709c0f7f85efde3c79d29791093b1394dee325cc00703` |
| selector-20 bootstrap | 17,776 | `320280cc3fc186995bfa24be16d4711c97943495090838c66112158ef51c35dd` |
| selector-21 bootstrap | 17,792 | `b23dd9ad787d36efffc029646d69399d16e50b71a68a40fe64f6dd04719f0664` |
| `system/init0` input | 8,184 | `a99077f134b83021a0f7ebd770de5ec02e26795329d9f50823ac53ba456f1d58` |
| `bin/hello` input | 8,184 | `6866ad9deaf0c62407a39fec48cd5f7c5f1fd4e6d28d95a6d2cde459f40dcd4e` |
| bootfs | 16,736 | `2ac3969bc9ebbce062888f3a213b8fff8d707764b19e4a69924f83261d4abf51` |
| production FAT32 ESP | 134,217,728 | `8f92820b42ca9baa1499ae507f2c028d34faedbd96fbae5a325b9000ef7fa897` |
| selector-18 FAT32 ESP | 134,217,728 | `23c72ace79ea9e1c754c6d57e2c0455b4c5cec7da6d19a2ccd41d46b9c6a49e1` |
| selector-19 FAT32 ESP | 134,217,728 | `03181b3bddfe0273d881ff2269575b98d9c05ef8e4e14b046c53c35d752553fe` |
| selector-20 FAT32 ESP | 134,217,728 | `b78223e35118bb2b0816036aea1383146fa820c21cb31d08ee7ec362a871ea82` |
| selector-21 FAT32 ESP | 134,217,728 | `8921fcff071189688a8bd58351862c1f70fe216810ffd2e094e40f39b6794f6a` |

The native bootstrap, init0, hello, and bootfs were rebuilt with the corrected soft-float target.
Two independent bootfs builds and two independent production ESP builds are byte-identical.

## Artifact inspection

- All Deepwyrm production/selector kernels are ELF64 x86-64 `ET_EXEC` images with three W^X-separated `PT_LOAD`
  segments, no dynamic section, and no undefined symbols. The production image contains no
  test-support selector or debug-exit marker.
- `loader.efi` is PE32+ AMD64 with EFI application subsystem, no PE imports, and retained PDB.
- Each native Wyrmroot executable passes the hardened G1-compatible oracle: fixed static `ET_EXEC`,
  W^X/NX segments, no dynamic metadata, relocations, undefined symbols, libc, or interpreter.
  Production and ordinary test variants contain exactly one Deepwyrm syscall veneer. The explicit
  invalid-return oracle accounts for one veneer plus one exact test-only `RSP=0` syscall tail.
  Disassembly contains no x87, FXSR, MMX, SSE, or AVX instruction.
- Extracting bootfs proves `system/init0` and `bin/hello` are byte-identical to the accepted native
  inputs.
- The G3 image inspector re-extracts and compares the exact loader, production kernel, bootstrap,
  and bootfs bytes. `fsck.fat` 4.2 accepts the filesystem read-only, and mtools 4.0.49 resolves
  `EFI/BOOT/BOOTX64.EFI`, `EFI/Wyrmroot/deepwyrm.elf`,
  `EFI/Wyrmroot/bootstrap.elf`, and `EFI/Wyrmroot/bootfs.img`.

## Toolchain identity

The revision-named artifact root contains the promoted `rustc 1.97.1-dev`/LLVM 22.1.6 compiler,
Cargo 1.96.1, `rust-lld`, and the corrected Wyrmroot `core` and `compiler_builtins`. The built-in
target selects `RustcAbi::Softfloat` and explicitly disables x87/FXSR/MMX/SSE/AVX generation. No accepted
toolchain path is a symlink or depends on the mutable implementation worktree. Exact component
hashes are in `G3_EVIDENCE.toml` and `MANIFEST.sha256`.

## Host gates

- Deepwyrm locked workspace tests, 484 test-support kernel unit tests plus integration suites, ABI generation check, strict Clippy,
  formatting, production freestanding target build, and primordial test-support target build pass.
- Wyrmroot locked workspace/all-target tests pass, including 50 xtask tests with the pre-existing
  accepted-environment gate ignored; strict workspace/all-target Clippy and warning-denied docs pass.
- Production native and UEFI rebuilds pass with warnings denied; all artifact, bootfs, image,
  formatting, diff, manifest-hash, and independent FAT checks pass.
- Deepwyrm, Wyrmroot, and Rust worktrees were clean when the accepted set was recorded.

## Licensing disposition

The live runtime is new first-party code inside Deepwyrm's existing GPL-2.0-or-later kernel
component, so that explicit component declaration controls. The image tooling is new first-party
code inside Wyrmroot's explicitly GPL-3.0-or-later xtask package. No third-party source was copied
into either project, no component was relicensed, and no mixed-license tree was mechanically
normalized. Toolchain inputs retain their upstream licenses and are recorded separately as build
provenance.


## Review remediation and re-promotion

The first accepted G3 host set was reviewed after promotion and was superseded rather than silently
left current. Deepwyrm `65e4cb52cfe47d754f684da99edf8a9eb1622e94` closes the live primordial
mapping findings: recoverable table-candidate exhaustion now returns `DW_STATUS_NO_RESOURCES`,
publisher-preparation failure returns `DW_STATUS_BAD_STATE`, every unused table candidate is recycled
on construction and syscall error paths, and failed zeroed backing/table transitions return their
linear grant. A source-contract regression prevents the reviewed panic paths from returning.

Wyrmroot `c5925a28d876935cd20a7a3f9d9df1c0800989fb` makes mandatory post-build ESP
inspection failure delete the newly created image and adds a regression for that poisoned-output
case. The validation record also now contains the exact disposable Git URL-rewrite recipe used to
replay the canonical pinned Deepwyrm Git dependency from a local clean checkout.

Before rebuilding the fixed kernels, the accepted Rust/Cargo build recipe was replayed at the old
Deepwyrm revision and reproduced both prior accepted kernel artifacts byte-for-byte. The same recipe
then produced the fixed kernels above. Wyrmroot's `Cargo.toml`, `Cargo.lock`, loader, bootstrap,
runtime, bootfs, `init0`, and `hello` producing trees are byte-identical between the previous artifact
revision `3d7ff88b2c9ba6d17eada92fc185a37fff12fcfa` and the fixed G3 tooling revision, so those
unchanged accepted guest artifacts were retained. The ESP was regenerated three times from the fixed
kernel and unchanged paired Wyrmroot inputs; all three images are byte-identical.

The previous artifact root
`artifacts/dw0-g3/superseded/dw-d3a21cc0e12a__wyr-3d7ff88b2c9b__rust-fc555b0e2ef8/`
is retained only as superseded evidence. It is no longer an accepted G3 candidate.

## G4 live remediation and final re-promotion

The first G4 attempts exposed defects that host composition could not exercise. Deepwyrm
`d9d81c3102c662926d073f58cb1caa041e66a6ed` prevents LLVM from folding aliased emergency-stack
linker boundaries as distinct extern statics and sizes initial primordial publication journals for
the complete 64 KiB stack. Deepwyrm `7e70cf4f31cea89168bc0a54f1c55eef24b0c8cf` applies the same
bounded journal capacity to native map/unmap syscalls, which allowed the real bootfs mapping to
publish instead of returning `DW_STATUS_BAD_STATE`.

Rust `532159d837cadeb7d00e35eacb7f31bf0b640c3d` corrects the built-in Wyrmroot target after the
live kernel's deliberate CR0.TS policy caught compiler-emitted SSE in bootstrap. It selects the
soft-float ABI and disables hardware FP/vector features. Wyrmroot
`be2a14435bd3256a535e49aaba0ad03c5e818dd4` pins and records that exact correction. All affected
kernel, native, bootfs, and ESP artifacts were rebuilt and re-inspected before canonical G4.

Accordingly, the formerly accepted root
`artifacts/dw0-g3/superseded/dw-65e4cb52cfe4__wyr-c5925a28d876__rust-fc555b0e2ef8/` is retained as
historical evidence. The `accepted/` namespace now contains only the revision-named G4 candidate at
the top of this record.

## G4 live disposition

Canonical `artifacts/dw0-g4/run-19-canonical/` booted this exact test ESP in the designated
`OS-Project` VM and emitted `DWTEST1|01|00000012|00000000|1B75A741`. That record proves selector 18
PASS/detail zero after capability-bearing INIT, read-only bootfs validation, READY, and normal exit.
Libvirt observed guest-request shutdown. The inactive domain XML was restored byte-for-byte to
SHA-256 `a823095e2182f848be0c15fe1a88728fce9f126fbc55e7d9aab30d84a6c5d3c3`; UUID, shutoff state,
disabled autostart, absent managed save/NVRAM, primary disk identity, and empty network set reproduce.
`G4_EVIDENCE.toml` records the exact profile and hashes. A post-acceptance Sol review also closed the
evidence-hygiene findings without changing the candidate: the older G3 root was moved out of
`accepted/`; primary-disk continuity is now recorded as an explicit campaign bookend from run 01
preflight through run 19 post-run and the current restored domain, while the empty `qemu-img` probe
files are explicitly excluded from that proof. The libvirt-effective profile synthesized an xHCI
controller, PS/2 inputs, `audio type=none`, and an ITCO watchdog, but still had no network interface,
host filesystem share, graphics device, functional audio backend, or attached USB device. Under
libvirt the direct-QEMU numeric status 33 was not captured; the retained evidence instead records the
unique checksum-valid PASS serial record followed immediately by `Shutdown Finished after guest
request`, matching the test transport's serial-before-`isa-debug-exit` ordering.

## G5 Daybreak remediation and disposition

The initial exact `gpt-daybreak-blue-latest` review found two High and one Medium Deepwyrm terminal
lifecycle defects, one Medium Rust target-feature defect, and one Low manifest-closure defect.
Deepwyrm `37ef1aba7a0006af194796c58782adabb1536f09` closes structured exception/invalid-return
termination, production blocking suspend/resume, and complete terminal quiescence. Deepwyrm
`91d9b204c1ed0bdd4cef934e1be6203d41e9e5c3` adds production-path selectors 19 through 21.
Wyrmroot `f433baf36d671f3f8b515adf5f613bd01dc8bbb9` supplies mutually exclusive test bootstrap variants
and strict artifact oracles. Rust `a92dc7f7464ad6ddfece4402bd7b86dbfa86166d` removes `x87` and
`fxsr` from the resolved target features.

Canonical campaign `artifacts/dw0-g5/run-01-canonical/` passed selectors 18, 19, 20, and 21 with
checksum-valid records, guest-request shutdown, byte-identical restoration after every run, and
unchanged primary-disk bookends. Final independent Deepwyrm and cross-boundary Daybreak rereviews
report C0/H0/M0/L0. The final manifest covers 97/97 entries, including both evidence TOMLs, and
hashes to `67c88666079db335d5aa81414c553c140e394a5ebdee2706267ae6e8bd58aac0`.
Wyrmroot `21e4c1a05a62a00ee7a97babdcecea97bba909f1` commits the exact
`RUST-WYR0-G5-X87-003` provenance record and closes the final evidence-only Low.

G5 is accepted. P0 remains open, so this record does not claim DW0-G full acceptance or progression
to DW0-H. It also makes no general-exec, SMP, preemption, real-time, i386, physical-hardware, or
full-Wyrmroot claim.
