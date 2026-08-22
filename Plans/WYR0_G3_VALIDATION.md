# DW0-G3 Paired Artifact Validation

**Status:** Accepted host artifact gate; designated-VM G4 remains open

**Review date:** 2026-08-22

**Deepwyrm artifact revision:** `d3a21cc0e12a33f03efe30f2868f10c5ff9afe3d`

**Wyrmroot artifact revision:** `3d7ff88b2c9ba6d17eada92fc185a37fff12fcfa`

**Rust source revision:** `fc555b0e2ef86b8037b6069ef3157c4862fa028d`

## Result

DW0-G3 now has one exact, project-local paired artifact set. The production Deepwyrm kernel enters
the real primordial launch path, and Wyrmroot provides the exact loader, native bootstrap, minimal
native payloads, bootfs, and deterministic FAT32 ESP consumed by that path. This closes the G3 host
artifact gate only. No designated-VM lifecycle or guest execution was performed; that is G4.

The revision-named accepted root is:

`artifacts/dw0-g3/accepted/dw-d3a21cc0e12a__wyr-3d7ff88b2c9b__rust-fc555b0e2ef8/`

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
| production `deepwyrm.elf` | 9,699,104 | `b0882e6e849c31b1881f286733a8c50831051080cdcf00d657de108253a7aa01` |
| primordial test kernel | 10,074,288 | `f7682f796af2ab1245e1ec63a8224f3e492730a8838f988c844985e7873edaad` |
| `loader.efi` | 138,752 | `09427a9574979a6e1f64f493ebe0c50896e419e625ed3cd614992746d74d9beb` |
| retained `loader.pdb` | 8,056,832 | `58f209ad2369bee1a378532046c04a9ed3fe24f596ea9056e231a6295519088d` |
| `bootstrap.elf` | 17,520 | `5a825d6da2345f94659efdb5c7627cfcc35c212c88495d67f2dd5f15c599e995` |
| `system/init0` input | 8,312 | `937464a104782ca8da3c99199e6866ce5779b0e274e0c0912656bc363b972907` |
| `bin/hello` input | 8,312 | `5f5246a222670530e14ced2bf6bb2f442d47763d9298280fef4e845b859e127e` |
| bootfs | 16,992 | `0a7722b4c9fe6f4fa6e194a4eeedad84b292f1a0f4b69c16fc0bdaab8333e8da` |
| FAT32 ESP | 134,217,728 | `775426b47a7f95fe45e0344e51205548b5ad5655f2e985ab5d28f0a685eca937` |

The native bootstrap, init0, hello, and bootfs reproduce the reviewed D2 hashes under the promoted
G3 compiler. Two independent bootfs builds and two independent ESP builds are byte-identical.

## Artifact inspection

- Both Deepwyrm kernels are ELF64 x86-64 `ET_EXEC` images with three W^X-separated `PT_LOAD`
  segments, no dynamic section, and no undefined symbols. The production image contains no
  test-support selector or debug-exit marker.
- `loader.efi` is PE32+ AMD64 with EFI application subsystem, no PE imports, and retained PDB.
- Each native Wyrmroot executable passes the hardened G1-compatible oracle: fixed static `ET_EXEC`,
  one RX load segment, NX stack, no dynamic metadata, relocations, undefined symbols, libc, or
  interpreter, and exactly one Deepwyrm syscall veneer.
- Extracting bootfs proves `system/init0` and `bin/hello` are byte-identical to the accepted native
  inputs.
- The G3 image inspector re-extracts and compares the exact loader, production kernel, bootstrap,
  and bootfs bytes. `fsck.fat` 4.2 accepts the filesystem read-only, and mtools 4.0.49 resolves
  `EFI/BOOT/BOOTX64.EFI`, `EFI/Wyrmroot/deepwyrm.elf`,
  `EFI/Wyrmroot/bootstrap.elf`, and `EFI/Wyrmroot/bootfs.img`.

## Toolchain identity

The revision-named artifact root contains the promoted `rustc 1.97.1-dev`/LLVM 22.1.6 compiler,
Cargo 1.96.0, `rust-lld`, the R0 Wyrmroot `core` and `compiler_builtins`, and the exact host
`proc_macro` support required to build the UEFI dependency graph. The latter was compiled from
Rust's `library/proc_macro` at the pinned Rust revision plus `rustc-literal-escaper` 0.0.7; it is a
toolchain input, not copied project source. Exact component hashes are in `G3_EVIDENCE.toml` and
`MANIFEST.sha256`.

## Host gates

- Deepwyrm locked workspace tests, 483 kernel unit tests, ABI generation check, strict Clippy,
  formatting, production freestanding target build, and primordial test-support target build pass.
- Wyrmroot locked workspace/all-target tests pass, including 49 xtask tests with the pre-existing
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

## Remaining gate

G4 must boot this exact ESP in the designated `OS-Project` VM and validate the structured
primordial success path, serial evidence, guest-consumed identities, and restoration rules. G3 does
not claim live boot acceptance.
