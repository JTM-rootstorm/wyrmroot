#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Verify that an explicitly supplied, accepted Wyrmroot rustc implements the
# locked UEFI target contract.  There is deliberately no default to `rustc`:
# using the host compiler would conceal a missing pinned Wyrmroot toolchain.

set -u

if [ "$#" -ne 2 ] || [ "$1" != "--rustc" ] || [ ! -x "$2" ]; then
    printf '%s\n' 'usage: sh toolchain/verify-uefi-toolchain.sh --rustc <accepted-wyrmroot-rustc>' >&2
    exit 2
fi

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/[[:cntrl:]]/ /g'
}

compiler=$2
manifest=toolchain/versions.toml
expected_revision=$(awk '
    $0 == "[rust]" { in_rust = 1; next }
    /^\[/ { in_rust = 0 }
    in_rust && /^wyrmroot_revision = / {
        value = $0
        sub(/^[^"]*"/, "", value)
        sub(/".*$/, "", value)
        print value
        exit
    }
' "$manifest")

identity=$($compiler -vV 2>&1)
identity_status=$?
actual_revision=""
if [ "$identity_status" -eq 0 ]; then
    actual_revision=$(printf '%s\n' "$identity" | awk -F': ' '$1 == "commit-hash" { print $2; exit }')
fi

spec=""
spec_status=1
if [ "$identity_status" -eq 0 ]; then
    spec=$(RUSTC_BOOTSTRAP=1 "$compiler" -Z unstable-options --print target-spec-json --target x86_64-unknown-uefi 2>&1)
    spec_status=$?
fi

has_spec_value() {
    printf '%s\n' "$spec" | grep -F -q "$1"
}

target_spec_conforms=false
if [ "$spec_status" -eq 0 ] \
    && has_spec_value '"arch": "x86_64"' \
    && has_spec_value '"os": "uefi"' \
    && has_spec_value '"binary-format": "coff"' \
    && has_spec_value '"exe-suffix": ".efi"' \
    && has_spec_value '"linker": "rust-lld"' \
    && has_spec_value '"linker-flavor": "msvc-lld"' \
    && has_spec_value '"lld-flavor": "link"' \
    && has_spec_value '"/subsystem:efi_application"'; then
    target_spec_conforms=true
fi

accepted_toolchain=false
if [ -n "$expected_revision" ] && [ "$actual_revision" = "$expected_revision" ]; then
    accepted_toolchain=true
fi

verified=false
if [ "$accepted_toolchain" = true ] && [ "$target_spec_conforms" = true ]; then
    verified=true
fi

printf '{\n'
printf '  "schema_version": 1,\n'
printf '  "report_kind": "wyrmroot-wyr0-uefi-toolchain-validation",\n'
printf '  "compiler": "%s",\n' "$(json_escape "$compiler")"
printf '  "expected_rust_revision": "%s",\n' "$(json_escape "$expected_revision")"
printf '  "actual_rust_revision": "%s",\n' "$(json_escape "$actual_revision")"
printf '  "accepted_toolchain": %s,\n' "$accepted_toolchain"
printf '  "target": "x86_64-unknown-uefi",\n'
printf '  "target_spec_conforms": %s,\n' "$target_spec_conforms"
printf '  "verified": %s\n' "$verified"
printf '}\n'

if [ "$verified" = true ]; then
    exit 0
fi
exit 1
