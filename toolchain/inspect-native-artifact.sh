#!/bin/sh
# Inspect one completed WYR0 native ELF without executing it.
set -eu

if [ "$#" -ne 1 ]; then
    printf '%s\n' 'usage: sh toolchain/inspect-native-artifact.sh <native-elf>' >&2
    exit 2
fi

artifact=$1
if [ -L "$artifact" ] || [ ! -f "$artifact" ] || [ ! -s "$artifact" ]; then
    printf '%s\n' 'native artifact must be a nonempty regular file, not a symbolic link' >&2
    exit 1
fi

for tool in llvm-readelf llvm-nm llvm-objdump sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'required inspection tool unavailable: %s\n' "$tool" >&2
        exit 1
    }
done

headers=$(llvm-readelf --file-header --program-headers --wide "$artifact")
dynamic=$(llvm-readelf --dynamic "$artifact")
relocations=$(llvm-readelf --relocations "$artifact")
undefined=$(llvm-nm --undefined-only "$artifact")
symbols=$(llvm-nm --defined-only "$artifact")
disassembly=$(llvm-objdump --disassemble "$artifact")

require_header() {
    printf '%s\n' "$headers" | grep -Eq "$1" || {
        printf 'native artifact failed ELF requirement: %s\n' "$2" >&2
        exit 1
    }
}

require_header 'Class:[[:space:]]+ELF64$' 'ELF64'
require_header 'Data:[[:space:]]+2.s complement, little endian$' 'little-endian data'
require_header 'Version:[[:space:]]+1 \(current\)$' 'current ELF version'
require_header 'Type:[[:space:]]+EXEC \(Executable file\)$' 'fixed ET_EXEC'
require_header 'Machine:[[:space:]]+Advanced Micro Devices X86-64$' 'x86-64 machine'

programs=$(printf '%s\n' "$headers" | awk '$1 ~ /^(LOAD|PHDR|GNU_STACK)$/ { print }')
program_count=$(printf '%s\n' "$programs" | awk 'NF { count++ } END { print count + 0 }')
load_count=$(printf '%s\n' "$programs" | awk '$1 == "LOAD" { count++ } END { print count + 0 }')
if [ "$program_count" -gt 16 ] || [ "$load_count" -lt 1 ] || [ "$load_count" -gt 8 ]; then
    printf 'native artifact has invalid program/load segment counts: %s/%s\n' \
        "$program_count" "$load_count" >&2
    exit 1
fi
if printf '%s\n' "$programs" | awk '$1 == "LOAD" && /W/ && /E/ { found=1 } END { exit !found }'; then
    printf '%s\n' 'native artifact contains a writable-executable PT_LOAD' >&2
    exit 1
fi
if printf '%s\n' "$programs" | awk '$1 == "GNU_STACK" && /E/ { found=1 } END { exit !found }'; then
    printf '%s\n' 'native artifact requests an executable stack' >&2
    exit 1
fi

if [ -n "$dynamic" ]; then
    printf '%s\n' 'native artifact contains a dynamic section or dependencies' >&2
    exit 1
fi
printf '%s\n' "$relocations" | grep -Fq 'There are no relocations in this file.' || {
    printf '%s\n' 'native artifact contains relocations requiring fixup' >&2
    exit 1
}
if [ -n "$undefined" ]; then
    printf '%s\n' 'native artifact contains undefined symbols' >&2
    exit 1
fi

entry=$(printf '%s\n' "$headers" | awk '/Entry point address:/ { print $4 }')
start=$(printf '%s\n' "$symbols" | awk '$3 == "_start" { print "0x" $1 }')
if [ -z "$entry" ] || [ -z "$start" ] || [ "$((entry))" -ne "$((start))" ]; then
    printf '%s\n' 'native artifact entry point is not its defined _start symbol' >&2
    exit 1
fi
printf '%s\n' "$symbols" | awk '$3 == "dw_syscall6" { found=1 } END { exit !found }' || {
    printf '%s\n' 'native artifact does not contain the Deepwyrm-owned syscall veneer' >&2
    exit 1
}
syscall_count=$(printf '%s\n' "$disassembly" | awk '$0 ~ /[[:space:]]syscall([[:space:]]|$)/ { count++ } END { print count + 0 }')
if [ "$syscall_count" -ne 1 ]; then
    printf 'native artifact has %s syscall instructions; expected the single binding veneer\n' \
        "$syscall_count" >&2
    exit 1
fi

sha256=$(sha256sum "$artifact" | awk '{ print $1 }')
size=$(wc -c < "$artifact" | tr -d ' ')
printf '{"schema_version":1,"report_kind":"wyrmroot-wyr0-native-artifact-inspection","verified":true,"artifact":"%s","sha256":"%s","size":%s,"program_headers":%s,"load_segments":%s,"syscall_veneers":1}\n' \
    "$(basename "$artifact")" "$sha256" "$size" "$program_count" "$load_count"
