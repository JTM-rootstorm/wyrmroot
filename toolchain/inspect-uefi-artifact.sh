#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Validate the deterministic production UEFI loader and retained debug pair.

set -u

if [ "$#" -ne 3 ] || [ ! -f "$1" ] || [ ! -s "$1" ] \
    || [ ! -f "$2" ] || [ ! -s "$2" ] || [ ! -f "$3" ] || [ ! -s "$3" ]; then
    printf '%s\n' 'usage: sh toolchain/inspect-uefi-artifact.sh <loader.efi> <debug-loader.efi> <loader.pdb>' >&2
    exit 2
fi

loader=$1
debug_loader=$2
debug_symbols=$3
for tool in llvm-readobj llvm-pdbutil sha256sum wc; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf '{"schema_version":2,"report_kind":"wyrmroot-wyr0-uefi-artifact-inspection","verified":false,"failure":"%s unavailable"}\n' "$tool"
        exit 1
    fi
done

loader_sha256=$(sha256sum "$loader" | awk '{ print $1 }')
loader_size=$(wc -c < "$loader" | tr -d ' ')
debug_loader_sha256=$(sha256sum "$debug_loader" | awk '{ print $1 }')
debug_loader_size=$(wc -c < "$debug_loader" | tr -d ' ')
debug_symbol_sha256=$(sha256sum "$debug_symbols" | awk '{ print $1 }')
debug_symbol_size=$(wc -c < "$debug_symbols" | tr -d ' ')

headers=$(llvm-readobj --file-headers "$loader" 2>&1)
header_status=$?
imports=$(llvm-readobj --coff-imports "$loader" 2>&1)
imports_status=$?
production_debug=$(llvm-readobj --coff-debug-directory "$loader" 2>&1)
production_debug_status=$?
retained_debug=$(llvm-readobj --coff-debug-directory "$debug_loader" 2>&1)
retained_debug_status=$?
pdb_summary=$(llvm-pdbutil dump -summary "$debug_symbols" 2>&1)
pdb_status=$?

has_header_value() {
    printf '%s\n' "$headers" | grep -F -q "$1"
}

pe32_plus=false
amd64=false
efi_application=false
no_imports=false
production_reproducible=false
production_codeview_absent=false
debug_pair_linked=false
pdb_has_symbols=false
if [ "$header_status" -eq 0 ] \
    && { has_header_value 'Magic: 0x20B' || has_header_value 'Magic: PE32+ (0x20B)'; }; then
    pe32_plus=true
fi
if [ "$header_status" -eq 0 ] && has_header_value 'Machine: IMAGE_FILE_MACHINE_AMD64 (0x8664)'; then amd64=true; fi
if [ "$header_status" -eq 0 ] && has_header_value 'Subsystem: IMAGE_SUBSYSTEM_EFI_APPLICATION (0xA)'; then efi_application=true; fi
if [ "$imports_status" -eq 0 ] && ! printf '%s\n' "$imports" | grep -F -q 'Import {'; then no_imports=true; fi
if [ "$production_debug_status" -eq 0 ] && printf '%s\n' "$production_debug" | grep -F -q 'Type: Repro (0x10)'; then
    production_reproducible=true
fi
if [ "$production_debug_status" -eq 0 ] && ! printf '%s\n' "$production_debug" | grep -F -q 'Type: CodeView (0x2)'; then
    production_codeview_absent=true
fi

codeview_guid=$(printf '%s\n' "$retained_debug" | sed -n 's/^[[:space:]]*PDBGUID: //p' | sed -n '1p')
codeview_age=$(printf '%s\n' "$retained_debug" | sed -n 's/^[[:space:]]*PDBAge: //p' | sed -n '1p')
codeview_name=$(printf '%s\n' "$retained_debug" | sed -n 's/^[[:space:]]*PDBFileName: //p' | sed -n '1p')
pdb_guid=$(printf '%s\n' "$pdb_summary" | sed -n 's/^[[:space:]]*GUID: //p' | sed -n '1p')
pdb_age=$(printf '%s\n' "$pdb_summary" | sed -n 's/^[[:space:]]*Age: //p' | sed -n '1p')
if [ "$retained_debug_status" -eq 0 ] && [ "$pdb_status" -eq 0 ] \
    && [ -n "$codeview_guid" ] && [ "$codeview_guid" = "$pdb_guid" ] \
    && [ -n "$codeview_age" ] && [ "$codeview_age" = "$pdb_age" ] \
    && [ "$codeview_name" = "loader.pdb" ]; then
    debug_pair_linked=true
fi
if [ "$pdb_status" -eq 0 ] \
    && printf '%s\n' "$pdb_summary" | grep -F -q 'Has Globals: true' \
    && printf '%s\n' "$pdb_summary" | grep -F -q 'Has Publics: true'; then
    pdb_has_symbols=true
fi

verified=false
if [ "$pe32_plus" = true ] && [ "$amd64" = true ] && [ "$efi_application" = true ] \
    && [ "$no_imports" = true ] && [ "$production_reproducible" = true ] \
    && [ "$production_codeview_absent" = true ] && [ "$debug_pair_linked" = true ] \
    && [ "$pdb_has_symbols" = true ]; then
    verified=true
fi

printf '{\n'
printf '  "schema_version": 2,\n'
printf '  "report_kind": "wyrmroot-wyr0-uefi-artifact-inspection",\n'
printf '  "loader": "loader.efi",\n'
printf '  "debug_loader": "loader.efi",\n'
printf '  "debug_symbol_artifact": "loader.pdb",\n'
printf '  "loader_sha256": "%s",\n' "$loader_sha256"
printf '  "loader_size": %s,\n' "$loader_size"
printf '  "debug_loader_sha256": "%s",\n' "$debug_loader_sha256"
printf '  "debug_loader_size": %s,\n' "$debug_loader_size"
printf '  "debug_symbol_sha256": "%s",\n' "$debug_symbol_sha256"
printf '  "debug_symbol_size": %s,\n' "$debug_symbol_size"
printf '  "pe32_plus": %s,\n' "$pe32_plus"
printf '  "amd64": %s,\n' "$amd64"
printf '  "efi_application": %s,\n' "$efi_application"
printf '  "no_pe_imports": %s,\n' "$no_imports"
printf '  "production_reproducible": %s,\n' "$production_reproducible"
printf '  "production_codeview_absent": %s,\n' "$production_codeview_absent"
printf '  "debug_pair_linked": %s,\n' "$debug_pair_linked"
printf '  "pdb_has_symbols": %s,\n' "$pdb_has_symbols"
printf '  "verified": %s\n' "$verified"
printf '}\n'

if [ "$verified" = true ]; then
    exit 0
fi
exit 1
