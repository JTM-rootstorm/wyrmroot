# Wyrmroot licensing policy

## Repository default

Unless a file or component explicitly says otherwise, Wyrmroot is licensed under `GPL-2.0-or-later`.

The repository intentionally uses a broad default for reusable platform foundations and a `GPL-3.0-or-later` floor for selected, clearly separable applications and host utilities. This keeps GPL-2.0-only compatibility paths open where they are useful without preventing stronger copyleft on leaf components.

The full license texts carried by this repository are:

- `LICENSES/GPL-2.0-or-later.txt`
- `LICENSES/GPL-3.0-or-later.txt`

## Current GPL-3.0-or-later components

The following paths are explicitly licensed `GPL-3.0-or-later`:

- `loader/**` — the Wyrmroot EFI loader package and its package-local tests/docs;
- `bootstrap/**` — the primordial Wyrmroot bootstrap application;
- `userspace/init0/**` — the temporary WYR0 init application;
- `userspace/hello/**` — the WYR0 hello smoke-test application;
- `tools/xtask/**` — Wyrmroot host-side repository orchestration tooling;
- `toolchain/inspect-uefi-artifact.sh`;
- `toolchain/verify-host-tools.sh`; and
- `toolchain/verify-uefi-toolchain.sh`.

Cargo packages in this list must use an explicit `license = "GPL-3.0-or-later"` rather than inheriting the workspace default. Standalone scripts should carry an SPDX identifier.

## Components that remain GPL-2.0-or-later

The following reusable foundations deliberately retain the broader repository default:

- `crates/wyrmroot-runtime/**`;
- `crates/wyrmroot-bootstrap-proto/**`;
- `crates/wyrmroot-loader/**` — the native userspace executable-loading library, distinct from the EFI loader at `loader/**`;
- `crates/wyrmroot-bootfs/**`;
- shared platform/ABI-facing definitions and future reusable SDK/runtime/protocol libraries unless explicitly reviewed otherwise; and
- files not covered by a specific exception above, including plans, validation/security records, machine-readable toolchain policy/configuration, and repository metadata.

Keeping these foundations at `GPL-2.0-or-later` is intentional so future GPL-2.0-only-compatible imports or consumers are not blocked unnecessarily.

## Guidance for Codex and contributors

Do not infer a component's license solely from the repository root or from a neighboring component. Use this order:

1. explicit SPDX notice on the file, if present;
2. explicit package/component license declaration;
3. the path exception list in this document;
4. otherwise the repository default, `GPL-2.0-or-later`.

A new or existing component may be changed to `GPL-3.0-or-later` when all of the following are true:

1. the project has authority to apply that license to the component;
2. every incorporated dependency or copied/adapted source permits the resulting work to be distributed under GPLv3-or-later terms;
3. the component is sufficiently separable that tightening it does not unintentionally narrow a reusable foundation or block a planned GPL-2.0-only compatibility/import path;
4. package metadata and/or SPDX notices are updated explicitly; and
5. this component map is updated in the same change.

Prefer `GPL-3.0-or-later`, not `GPL-3.0-only`, when a 3.x floor is appropriate.

Do not silently relicense imported third-party code. A GPL-2.0-only source cannot simply be copied into a GPL-3.0-or-later combined program; route that situation for a licensing/architecture review before implementation.

## Architecture guidance

As a default design rule:

- reusable native runtime, ABI, SDK, protocol, and foundational libraries should remain `GPL-2.0-or-later` unless there is a concrete reason to narrow them;
- independent Wyrmroot applications/services and host-only tools are good candidates for `GPL-3.0-or-later` when their provenance allows it; and
- process/service separation does not by itself authorize relicensing copied source, but it often provides a clean boundary for differently licensed original components.

When a GPL-3.0-or-later executable links a `GPL-2.0-or-later` library from this repository, distribution of the combined executable must satisfy the applicable GPLv3-or-later terms. The underlying 2+-licensed library source retains its own broader grant.

## Generated code

Do not change a generator to `GPL-3.0-or-later` without checking the intended licensing of its generated output. Generated files should have an explicit, documented license source rather than accidentally inheriting a generator's package metadata.
