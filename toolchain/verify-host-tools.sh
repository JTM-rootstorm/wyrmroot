#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Report the current host's WYR0 toolchain prerequisites without adopting them
# as a WYR0 version pin.  The output is intentionally JSON for CI/provenance
# consumers; a successful probe is availability evidence only.

set -u

if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != "--json" ]; }; then
    printf '%s\n' 'usage: sh toolchain/verify-host-tools.sh [--json]' >&2
    exit 2
fi

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/[[:cntrl:]]/ /g'
}

tool_json=""
all_tools_available=true
first=true
for tool in rustc cargo clang clang++ ld.lld llvm-ar llvm-readelf llvm-readobj llvm-objdump llvm-nm llvm-objcopy llvm-pdbutil llvm-symbolizer gdb; do
    if [ "$first" = true ]; then
        first=false
    else
        tool_json="${tool_json},"
    fi

    tool_path=$(command -v "$tool" 2>/dev/null || true)
    if [ -n "$tool_path" ]; then
        tool_version=$("$tool" --version 2>&1 | sed -n '1p')
        tool_json="${tool_json}\n    {\"name\": \"$(json_escape "$tool")\", \"available\": true, \"path\": \"$(json_escape "$tool_path")\", \"version\": \"$(json_escape "$tool_version")\"}"
    else
        all_tools_available=false
        tool_json="${tool_json}\n    {\"name\": \"$(json_escape "$tool")\", \"available\": false}"
    fi
done

clang_resource_dir=""
compiler_rt_builtins=""
compiler_rt_available=false
if command -v clang >/dev/null 2>&1; then
    clang_resource_dir=$(clang --print-resource-dir 2>/dev/null || true)
    if [ -n "$clang_resource_dir" ]; then
        candidate="$clang_resource_dir/lib/linux/libclang_rt.builtins-x86_64.a"
        if [ -f "$candidate" ]; then
            compiler_rt_builtins=$candidate
            compiler_rt_available=true
        fi
    fi
fi

if [ "$compiler_rt_available" != true ]; then
    all_tools_available=false
fi

printf '{\n'
printf '  "schema_version": 1,\n'
printf '  "report_kind": "wyrmroot-wyr0-host-toolchain-availability",\n'
printf '  "adoption_state": "observed-not-adopted",\n'
printf '  "available": %s,\n' "$all_tools_available"
printf '  "tools": [%b\n  ],\n' "$tool_json"
printf '  "compiler_rt": {"available": %s, "clang_resource_dir": "%s", "x86_64_builtins": "%s"}\n' \
    "$compiler_rt_available" "$(json_escape "$clang_resource_dir")" "$(json_escape "$compiler_rt_builtins")"
printf '}\n'

if [ "$all_tools_available" = true ]; then
    exit 0
fi
exit 1
