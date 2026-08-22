# DW0-G3 Paired Artifact Validation

**Status:** Re-promoted host artifact gate; designated-VM G4 accepted; G5 remains open

**Review date:** 2026-08-22

**Deepwyrm artifact revision:** `7e70cf4f31cea89168bc0a54f1c55eef24b0c8cf`

**Wyrmroot artifact revision:** `be2a14435bd3256a535e49aaba0ad03c5e818dd4`

**Rust source revision:** `532159d837cadeb7d00e35eacb7f31bf0b640c3d`

## Result

DW0-G3 now has one exact, project-local paired artifact set re-promoted after live G4 defect fixes. The production Deepwyrm kernel enters
the real primordial launch path, and Wyrmroot provides the exact loader, native bootstrap, minimal
native payloads, bootfs, and deterministic FAT32 ESP consumed by that path. Canonical G4 run 19
then booted the paired test ESP through the designated VM and passed selector 18 with detail zero.
G5 remains a separate exact-candidate security gate.

The revision-named accepted root is:

`artifacts/dw0-g3/accepted/dw-7e70cf4f31ce__wyr-be2a14435bd3__rust-532159d837ca/`

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
| production `deepwyrm.elf` | 10,486,568 | `8eb955ca5b088677fb2d6f45d39d52cbc9e96508e1cc609ec5ddf0d765e1702b` |
| primordial test kernel | 10,621,472 | `1544b7f83a1d7de26d3b0be9d17db29194f2a196c20c712edea269656cf6a122` |
| `loader.efi` | 138,752 | `09427a9574979a6e1f64f493ebe0c50896e419e625ed3cd614992746d74d9beb` |
| retained `loader.pdb` | 8,056,832 | `58f209ad2369bee1a378532046c04a9ed3fe24f596ea9056e231a6295519088d` |
| `bootstrap.elf` | 17,936 | `3c6f3be6dc92f99a36201fec77952c2eebcaa39aba30ffa7931c917813b5fd42` |
| `system/init0` input | 8,184 | `a99077f134b83021a0f7ebd770de5ec02e26795329d9f50823ac53ba456f1d58` |
| `bin/hello` input | 8,184 | `6866ad9deaf0c62407a39fec48cd5f7c5f1fd4e6d28d95a6d2cde459f40dcd4e` |
| bootfs | 16,736 | `2ac3969bc9ebbce062888f3a213b8fff8d707764b19e4a69924f83261d4abf51` |
| production FAT32 ESP | 134,217,728 | `8529ec0e036e83a43f817f8e22d8d8a1a864745026b041ae862e3c8fa6f4edfb` |
| G4 test FAT32 ESP | 134,217,728 | `cad9477b8b929679905fd9bda64ed09971e9fea780597ab58f1bee62f7142187` |

The native bootstrap, init0, hello, and bootfs were rebuilt with the corrected soft-float target.
Two independent bootfs builds and two independent production ESP builds are byte-identical.

## Artifact inspection

- Both Deepwyrm kernels are ELF64 x86-64 `ET_EXEC` images with three W^X-separated `PT_LOAD`
  segments, no dynamic section, and no undefined symbols. The production image contains no
  test-support selector or debug-exit marker.
- `loader.efi` is PE32+ AMD64 with EFI application subsystem, no PE imports, and retained PDB.
- Each native Wyrmroot executable passes the hardened G1-compatible oracle: fixed static `ET_EXEC`,
  one RX load segment, NX stack, no dynamic metadata, relocations, undefined symbols, libc, or
  interpreter, and exactly one Deepwyrm syscall veneer. Disassembly contains no x87, MMX, SSE, or
  AVX instruction.
- Extracting bootfs proves `system/init0` and `bin/hello` are byte-identical to the accepted native
  inputs.
- The G3 image inspector re-extracts and compares the exact loader, production kernel, bootstrap,
  and bootfs bytes. `fsck.fat` 4.2 accepts the filesystem read-only, and mtools 4.0.49 resolves
  `EFI/BOOT/BOOTX64.EFI`, `EFI/Wyrmroot/deepwyrm.elf`,
  `EFI/Wyrmroot/bootstrap.elf`, and `EFI/Wyrmroot/bootfs.img`.

## Toolchain identity

The revision-named artifact root contains the promoted `rustc 1.97.1-dev`/LLVM 22.1.6 compiler,
Cargo 1.96.1, `rust-lld`, and the corrected Wyrmroot `core` and `compiler_builtins`. The built-in
target selects `RustcAbi::Softfloat` and explicitly disables x87/MMX/SSE/AVX generation. No accepted
toolchain path is a symlink or depends on the mutable implementation worktree. Exact component
hashes are in `G3_EVIDENCE.toml` and `MANIFEST.sha256`.

## Host gates

- Deepwyrm locked workspace tests, 508 test-support kernel unit tests, ABI generation check, strict Clippy,
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
`artifacts/dw0-g3/accepted/dw-65e4cb52cfe4__wyr-c5925a28d876__rust-fc555b0e2ef8/` is retained as
historical evidence but is superseded by the revision-named root at the top of this record.

## G4 live disposition

Canonical `artifacts/dw0-g4/run-19-canonical/` booted this exact test ESP in the designated
`OS-Project` VM and emitted `DWTEST1|01|00000012|00000000|1B75A741`. That record proves selector 18
PASS/detail zero after capability-bearing INIT, read-only bootfs validation, READY, and normal exit.
Libvirt observed guest-request shutdown. The inactive domain XML was restored byte-for-byte to
SHA-256 `a823095e2182f848be0c15fe1a88728fce9f126fbc55e7d9aab30d84a6c5d3c3`; UUID, shutoff state,
disabled autostart, absent managed save/NVRAM, primary disk identity, and empty network set reproduce.
`G4_EVIDENCE.toml` records the exact profile and hashes. G5 remains open, so this does not yet claim
DW0-G full acceptance or progression to DW0-H.
