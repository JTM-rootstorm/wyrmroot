#!/bin/sh
# Resolve the exact accepted Deepwyrm Git object through a scoped local transport.
#
# The accepted revision and its semantic ABI fingerprint come from the one
# canonical pin record, the [deepwyrm] table of toolchain/versions.toml. This
# script restates neither: the commit identity binds every tree beneath it, and
# the fingerprint is checked against the commit's generated
# abi/generated/abi_fingerprint.toml.
set -eu

remote=https://github.com/JTM-rootstorm/deepwyrm.git
fingerprint_schema=deepwyrm-abi-fingerprint-v1
fingerprint_path=abi/generated/abi_fingerprint.toml

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
versions="$script_directory/versions.toml"
if [ -L "$versions" ] || [ ! -f "$versions" ]; then
    printf '%s\n' 'toolchain/versions.toml is missing or is not a regular file' >&2
    exit 1
fi

# Print the single value of KEY in the [deepwyrm] table, without quotes.
pin_value() {
    awk -F ' = ' -v key="$1" '
        /^\[/ { section = $0; next }
        section == "[deepwyrm]" && $1 == key {
            value = $2
            sub(/^"/, "", value)
            sub(/"$/, "", value)
            print value
            found++
        }
        END { if (found != 1) exit 1 }
    ' "$versions"
}

revision=$(pin_value revision) || {
    printf '%s\n' 'toolchain/versions.toml [deepwyrm] must name exactly one revision' >&2
    exit 1
}
abi_fingerprint=$(pin_value abi_fingerprint) || {
    printf '%s\n' 'toolchain/versions.toml [deepwyrm] must name exactly one abi_fingerprint' >&2
    exit 1
}
case "$revision" in
    *[!0-9a-f]*|'') revision_valid=false ;;
    *) revision_valid=true ;;
esac
if [ "$revision_valid" != true ] || [ "${#revision}" -ne 40 ]; then
    printf '%s\n' 'pinned Deepwyrm revision must be 40 lowercase hexadecimal digits' >&2
    exit 1
fi
case "$abi_fingerprint" in
    *[!0-9a-f]*|'') fingerprint_valid=false ;;
    *) fingerprint_valid=true ;;
esac
if [ "$fingerprint_valid" != true ] || [ "${#abi_fingerprint}" -ne 64 ]; then
    printf '%s\n' 'pinned Deepwyrm ABI fingerprint must be 64 lowercase hexadecimal digits' >&2
    exit 1
fi

usage() {
    printf '%s\n' 'usage: sh toolchain/cargo-with-local-deepwyrm.sh <sibling-deepwyrm-git-repository> -- <cargo-arguments...>' >&2
    printf '%s\n' 'The helper verifies the exact commit and ABI fingerprint pinned in toolchain/versions.toml, emits local-transport provenance, and changes no global Git configuration.' >&2
}

if [ "$#" -lt 3 ] || [ "$2" != '--' ]; then
    usage
    exit 2
fi

repository_input=$1
shift 2

for tool in cargo git realpath; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'required local-transport tool unavailable: %s\n' "$tool" >&2
        exit 1
    }
done

if [ -L "$repository_input" ] || [ ! -d "$repository_input" ]; then
    printf '%s\n' 'supplied Deepwyrm repository must be a real directory, not a symbolic link' >&2
    exit 1
fi
repository=$(realpath -e -- "$repository_input")
case "$repository" in
    *[!A-Za-z0-9_./-]*)
        printf '%s\n' 'canonical Deepwyrm repository path contains characters unsupported by the file transport' >&2
        exit 1
        ;;
esac

top_level=$(git -C "$repository" rev-parse --show-toplevel 2>/dev/null) || {
    printf '%s\n' 'supplied Deepwyrm path is not a readable Git repository' >&2
    exit 1
}
if [ "$top_level" != "$repository" ]; then
    printf '%s\n' 'supplied Deepwyrm path is not the canonical Git repository root' >&2
    exit 1
fi

object_type=$(git -C "$repository" cat-file -t "$revision" 2>/dev/null) || {
    printf 'supplied Deepwyrm repository does not contain exact commit %s\n' "$revision" >&2
    exit 1
}
resolved_revision=$(git -C "$repository" rev-parse "$revision^{commit}" 2>/dev/null) || {
    printf '%s\n' 'supplied Deepwyrm revision cannot be resolved as a commit' >&2
    exit 1
}
if [ "$object_type" != commit ] || [ "$resolved_revision" != "$revision" ]; then
    printf '%s\n' 'supplied Deepwyrm revision identity is not the exact accepted commit' >&2
    exit 1
fi

object_id() {
    path=$1
    expected_type=$2
    actual_type=$(git -C "$repository" cat-file -t "$revision:$path" 2>/dev/null) || {
        printf 'accepted Deepwyrm commit omits required path: %s\n' "$path" >&2
        exit 1
    }
    if [ "$actual_type" != "$expected_type" ]; then
        printf 'accepted Deepwyrm path %s is a %s, expected a %s\n' "$path" "$actual_type" "$expected_type" >&2
        exit 1
    fi
    git -C "$repository" rev-parse "$revision:$path"
}

abi_tree=$(object_id abi tree)
abi_crate_tree=$(object_id crates/deepwyrm-abi tree)
syscall_crate_tree=$(object_id crates/deepwyrm-syscall tree)
object_id crates/deepwyrm-abi/Cargo.toml blob >/dev/null
object_id crates/deepwyrm-syscall/Cargo.toml blob >/dev/null
object_id "$fingerprint_path" blob >/dev/null

fingerprint_record=$(git -C "$repository" cat-file blob "$revision:$fingerprint_path")
schema_lines=$(printf '%s\n' "$fingerprint_record" | grep -c -x "schema = \"$fingerprint_schema\"" || true)
fingerprint_lines=$(printf '%s\n' "$fingerprint_record" | grep -c '^fingerprint = ' || true)
recorded_fingerprint=$(printf '%s\n' "$fingerprint_record" | sed -n 's/^fingerprint = "\([0-9a-f]\{64\}\)"$/\1/p')
if [ "$schema_lines" != 1 ] || [ "$fingerprint_lines" != 1 ] || [ "$recorded_fingerprint" != "$abi_fingerprint" ]; then
    printf 'accepted Deepwyrm ABI fingerprint drifted: %s\n' "${recorded_fingerprint:-unreadable}" >&2
    exit 1
fi

printf '{"schema_version":2,"report_kind":"wyrmroot-local-deepwyrm-cargo-transport","transport":"local-git-url-rewrite","repository":"%s","remote_identity":"%s","revision":"%s","abi_fingerprint":"%s","abi_tree":"%s","abi_crate_tree":"%s","syscall_crate_tree":"%s","global_git_config_mutated":false}\n' \
    "$repository" "$remote" "$revision" "$abi_fingerprint" "$abi_tree" "$abi_crate_tree" "$syscall_crate_tree" >&2

exec env \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_COUNT=1 \
    "GIT_CONFIG_KEY_0=url.file://$repository/.insteadOf" \
    "GIT_CONFIG_VALUE_0=$remote" \
    CARGO_NET_GIT_FETCH_WITH_CLI=true \
    cargo "$@"
