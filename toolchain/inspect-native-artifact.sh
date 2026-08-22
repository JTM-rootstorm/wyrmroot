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

for tool in awk llvm-readelf llvm-readobj llvm-nm llvm-objdump sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'required inspection tool unavailable: %s\n' "$tool" >&2
        exit 1
    }
done

headers=$(llvm-readelf --file-header --program-headers --wide "$artifact")
raw_programs=$(llvm-readobj --program-headers "$artifact")
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
require_header 'Size of this header:[[:space:]]+64 \(bytes\)$' '64-byte ELF header'
require_header 'Size of program headers:[[:space:]]+56 \(bytes\)$' '56-byte program headers'

size=$(wc -c < "$artifact" | tr -d ' ')
if [ "$size" -gt $((16 * 1024 * 1024)) ]; then
    printf '%s\n' 'native artifact exceeds the 16 MiB primordial module cap' >&2
    exit 1
fi

programs=$(printf '%s\n' "$headers" | awk '
    /Program Headers:/ { table=1; next }
    /Section to Segment mapping:/ { table=0 }
    table && $2 ~ /^0x[[:xdigit:]]+$/ { print }
')
program_count=$(printf '%s\n' "$programs" | awk 'NF { count++ } END { print count + 0 }')
load_count=$(printf '%s\n' "$programs" | awk '$1 == "LOAD" { count++ } END { print count + 0 }')
reported_count=$(printf '%s\n' "$headers" | awk '/Number of program headers:/ { print $5 }')
if [ "$program_count" -ne "$reported_count" ] \
    || [ "$program_count" -gt 16 ] \
    || [ "$load_count" -lt 1 ] \
    || [ "$load_count" -gt 8 ]; then
    printf 'native artifact has invalid program/load segment counts: %s/%s\n' \
        "$program_count" "$load_count" >&2
    exit 1
fi
if printf '%s\n' "$programs" | awk '$1 !~ /^(LOAD|PHDR|GNU_STACK)$/ { found=1 } END { exit !found }'; then
    printf '%s\n' 'native artifact contains a program-header type outside the primordial subset' >&2
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
if printf '%s\n' "$raw_programs" | awk '
    /^[[:space:]]*Type: / { type=$2; next }
    type != "" && /^[[:space:]]*Flags \[ \(0x/ {
        raw=$3
        gsub(/[()]/, "", raw)
        flags=strtonum(raw)
        if (type == "PT_LOAD" && flags != 4 && flags != 5 && flags != 6) bad=1
        if (type == "PT_GNU_STACK" && (flags > 7 || and(flags, 1) != 0)) bad=1
        type=""
    }
    END { exit !bad }
'; then
    printf '%s\n' 'native artifact contains raw program-header permission bits outside the primordial subset' >&2
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
if ! printf '%s\n' "$programs" | awk \
    -v entry="$((entry))" -v file_size="$size" '
    function hex(value) { return strtonum(value) }
    function align_down(value) { return value - (value % 4096) }
    function align_up(value) { return value % 4096 == 0 ? value : value + 4096 - (value % 4096) }
    BEGIN { mapped=0; loads=0; phdrs=0; stacks=0; entry_ok=0 }
    $1 == "PHDR" {
        phdrs++
        if (hex($2) + hex($5) > file_size) bad=1
    }
    $1 == "GNU_STACK" { stacks++ }
    $1 == "LOAD" {
        offset=hex($2); address=hex($3); filesz=hex($5); memsz=hex($6); alignment=hex($NF)
        flags=""
        for (field=7; field<NF; field++) flags=flags $field
        if (flags != "R" && flags != "RW" && flags != "RE") bad=1
        if (filesz > memsz || memsz == 0 || offset + filesz > file_size) bad=1
        if (alignment > 1 && (and(alignment, alignment - 1) != 0 || offset % alignment != address % alignment)) bad=1
        page_start=align_down(address); page_end=align_up(address + memsz)
        if (page_start < 4096 || page_end > 140737488355328) bad=1
        for (prior=0; prior<loads; prior++) {
            if (page_start < ends[prior] && starts[prior] < page_end) bad=1
        }
        starts[loads]=page_start; ends[loads]=page_end; loads++
        mapped += page_end - page_start
        if (flags == "RE" && entry >= address && entry < address + memsz) entry_ok=1
    }
    END {
        if (phdrs > 1 || stacks > 1 || mapped > 33554432 || !entry_ok || bad) exit 1
    }
'; then
    printf '%s\n' 'native artifact violates primordial load-range, permission, alignment, or entry policy' >&2
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
printf '{"schema_version":1,"report_kind":"wyrmroot-wyr0-native-artifact-inspection","verified":true,"artifact":"%s","sha256":"%s","size":%s,"program_headers":%s,"load_segments":%s,"syscall_veneers":1}\n' \
    "$(basename "$artifact")" "$sha256" "$size" "$program_count" "$load_count"
