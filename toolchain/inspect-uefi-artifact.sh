#!/bin/sh
# Validate a completed UEFI loader and its retained debug-symbol artifact.
# This is deliberately a PE/COFF check; native guest ELF policy is separate.

set -u

if [ "$#" -ne 2 ] || [ ! -f "$1" ] || [ ! -s "$1" ] || [ ! -f "$2" ] || [ ! -s "$2" ]; then
    printf '%s\n' 'usage: sh toolchain/inspect-uefi-artifact.sh <loader.efi> <debug-symbol-artifact>' >&2
    exit 2
fi

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/[[:cntrl:]]/ /g'
}

loader=$1
debug_symbols=$2
if ! command -v llvm-readobj >/dev/null 2>&1; then
    printf '%s\n' '{"schema_version":1,"report_kind":"wyrmroot-wyr0-uefi-artifact-inspection","verified":false,"failure":"llvm-readobj unavailable"}'
    exit 1
fi

headers=$(llvm-readobj --file-headers "$loader" 2>&1)
header_status=$?
imports=$(llvm-readobj --coff-imports "$loader" 2>&1)
imports_status=$?

has_header_value() {
    printf '%s\n' "$headers" | grep -F -q "$1"
}

pe32_plus=false
amd64=false
efi_application=false
no_imports=false
if [ "$header_status" -eq 0 ] \
    && { has_header_value 'Magic: 0x20B' || has_header_value 'Magic: PE32+ (0x20B)'; }; then
    pe32_plus=true
fi
if [ "$header_status" -eq 0 ] && has_header_value 'Machine: IMAGE_FILE_MACHINE_AMD64 (0x8664)'; then amd64=true; fi
if [ "$header_status" -eq 0 ] && has_header_value 'Subsystem: IMAGE_SUBSYSTEM_EFI_APPLICATION (0xA)'; then efi_application=true; fi
if [ "$imports_status" -eq 0 ] && ! printf '%s\n' "$imports" | grep -F -q 'Import {'; then no_imports=true; fi

debug_symbols_present=true
verified=false
if [ "$pe32_plus" = true ] && [ "$amd64" = true ] && [ "$efi_application" = true ] && [ "$no_imports" = true ]; then
    verified=true
fi

printf '{\n'
printf '  "schema_version": 1,\n'
printf '  "report_kind": "wyrmroot-wyr0-uefi-artifact-inspection",\n'
printf '  "loader": "%s",\n' "$(json_escape "$loader")"
printf '  "debug_symbol_artifact": "%s",\n' "$(json_escape "$debug_symbols")"
printf '  "pe32_plus": %s,\n' "$pe32_plus"
printf '  "amd64": %s,\n' "$amd64"
printf '  "efi_application": %s,\n' "$efi_application"
printf '  "no_pe_imports": %s,\n' "$no_imports"
printf '  "debug_symbols_present": %s,\n' "$debug_symbols_present"
printf '  "verified": %s\n' "$verified"
printf '}\n'

if [ "$verified" = true ]; then
    exit 0
fi
exit 1
