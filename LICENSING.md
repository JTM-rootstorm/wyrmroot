# Wyrmroot licensing policy

## Current repository state

Wyrmroot currently uses a component-aware mixed-license map. Its repository fallback remains `GPL-2.0-or-later`, while several explicitly identified applications and host tools are `GPL-3.0-or-later`. Existing SPDX notices, package declarations, and the component map below remain authoritative until an intentional relicensing change updates them.

This current fallback is **not** the workspace selection default for new first-party code. The project-wide rule in `../LICENSING_POLICY.md` is authoritative for future license selection: new wholly first-party code defaults to `GPL-3.0-or-later`. Use or retain a GPLv2-compatible lane when a component already has that declaration or when actual imported/adapted source or combination requirements call for it.

The full license texts carried by this repository are:

- `LICENSES/GPL-2.0-or-later.txt`
- `LICENSES/GPL-3.0-or-later.txt`

## Current GPL-3.0-or-later components

The following paths are explicitly licensed `GPL-3.0-or-later`:

- `loader/**` — the Wyrmroot EFI loader package and its package-local tests/docs;
- `bootstrap/**` — the primordial Wyrmroot bootstrap application;
- `userspace/init0/**` — the temporary WYR0 init application;
- `userspace/hello/**` — the WYR0 hello smoke-test application;
- `userspace/i-capability/**` — the WYR0-I native capability controller and probe payload;
- `tools/xtask/**` — Wyrmroot host-side repository orchestration tooling;
- `toolchain/inspect-uefi-artifact.sh`;
- `toolchain/verify-host-tools.sh`; and
- `toolchain/verify-uefi-toolchain.sh`.

Cargo packages in this list use explicit `license = "GPL-3.0-or-later"` declarations. Standalone scripts should carry an SPDX identifier.

## Current GPL-2.0-or-later components

The following foundations currently remain `GPL-2.0-or-later`:

- `crates/wyrmroot-runtime/**`;
- `crates/wyrmroot-bootstrap-proto/**`;
- `crates/wyrmroot-loader/**` — the native userspace executable-loading library, distinct from the EFI loader at `loader/**`;
- `crates/wyrmroot-bootfs/**`; and
- files not covered by a more specific declaration.

This list records the current legal/component state, not a permanent architectural rule. Wholly first-party components may be moved to GPL-3.0-or-later after a provenance review. Conversely, components that actually incorporate GPLv2-constrained source may remain or become GPLv2-compatible.

## Guidance for Codex and contributors

Do not infer a component's license solely from the repository root or a neighboring component. Use this order for existing code:

1. explicit SPDX notice on the file, if present;
2. explicit package/component license declaration;
3. the current component map in this document; and
4. otherwise the repository fallback, `GPL-2.0-or-later`.

For **new wholly first-party code**, however, start from `GPL-3.0-or-later`. Do not choose 2+ merely because Linux-derived code might be useful later. If the new code belongs inside an existing 2+-licensed component, follow that component until an intentional component-wide relicensing change is made.

When GPLv2-family third-party material is actually incorporated or substantially adapted, record its provenance and exact license before import. Use the narrowest sensible GPLv2-compatible boundary for project-owned surrounding code. Imported `GPL-2.0-only` source remains GPL-2.0-only and must not be relabeled `GPL-2.0-or-later` without a broader upstream grant.

Non-GPL dependencies or copied/adapted source require a compatibility review against the intended GPL-3.0-or-later or GPLv2-compatible destination. Preserve all required notices, attribution, patent terms, reciprocal-file boundaries, source obligations, and other upstream conditions.

## Architecture guidance

License boundaries should follow actual provenance and combination requirements rather than speculative future compatibility:

- a new first-party runtime, SDK, protocol, service, application, driver, or host tool defaults to `GPL-3.0-or-later`;
- an existing component keeps its current declared license until intentionally relicensed;
- actual GPLv2-constrained imports may justify or require a GPLv2-compatible component/file boundary; and
- process/service separation may provide a useful license boundary for independently authored code, but it never authorizes relicensing copied third-party source.

When a GPL-3.0-or-later executable links a `GPL-2.0-or-later` library from this repository, distribution of the combined executable must satisfy the applicable compatible terms. The underlying 2+-licensed library source retains its own broader grant.

## Relicensing first-party code

Where the project owns the relevant copyright, first-party components may be relicensed as implementation provenance evolves. Update package metadata, SPDX identifiers, this component map, and provenance records together.

That authority does not extend to third-party material. Imported source retains the license granted by its upstream copyright holders.

## Generated code

Check both generators and generated outputs when changing a licensing boundary. Generated files should have an explicit, documented license source and must not accidentally inherit a broader grant than their inputs permit.
