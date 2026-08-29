#!/bin/sh
# Resolve the exact accepted Deepwyrm Git object through a scoped local transport.
set -eu

revision=dc26df4a3d701e2cdf8b495e2c87ce979969a9c4
abi_tree=a9b067107ec38e2be44630f4dce428dab0f48de8
abi_crate_tree=6f3d546436e10df79a17db610fe9a8383cc26abc
syscall_crate_tree=a64290953ccc0548e908be88586969ac0b70b589
abi_manifest_blob=0ccaa86fb6fa77a75ffb9a11d2115593ccd29700
syscall_manifest_blob=3c0a564fe976320447649ae1882e59cf4382f460
remote=https://github.com/JTM-rootstorm/deepwyrm.git

usage() {
    printf '%s\n' 'usage: sh toolchain/cargo-with-local-deepwyrm.sh <sibling-deepwyrm-git-repository> -- <cargo-arguments...>' >&2
    printf '%s\n' 'The helper verifies the exact accepted commit and ABI/syscall trees, emits local-transport provenance, and changes no global Git configuration.' >&2
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

verify_object() {
    path=$1
    expected=$2
    actual=$(git -C "$repository" rev-parse "$revision:$path" 2>/dev/null) || {
        printf 'accepted Deepwyrm commit omits required path: %s\n' "$path" >&2
        exit 1
    }
    if [ "$actual" != "$expected" ]; then
        printf 'accepted Deepwyrm object identity drifted for %s: %s\n' "$path" "$actual" >&2
        exit 1
    fi
}

verify_object abi "$abi_tree"
verify_object crates/deepwyrm-abi "$abi_crate_tree"
verify_object crates/deepwyrm-syscall "$syscall_crate_tree"
verify_object crates/deepwyrm-abi/Cargo.toml "$abi_manifest_blob"
verify_object crates/deepwyrm-syscall/Cargo.toml "$syscall_manifest_blob"

printf '{"schema_version":1,"report_kind":"wyrmroot-local-deepwyrm-cargo-transport","transport":"local-git-url-rewrite","repository":"%s","remote_identity":"%s","revision":"%s","abi_tree":"%s","abi_crate_tree":"%s","syscall_crate_tree":"%s","global_git_config_mutated":false}\n' \
    "$repository" "$remote" "$revision" "$abi_tree" "$abi_crate_tree" "$syscall_crate_tree" >&2

exec env \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_COUNT=1 \
    "GIT_CONFIG_KEY_0=url.file://$repository/.insteadOf" \
    "GIT_CONFIG_VALUE_0=$remote" \
    CARGO_NET_GIT_FETCH_WITH_CLI=true \
    cargo "$@"
