#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO / "tools/wyrmsh-native-stack.py"
SPEC = importlib.util.spec_from_file_location("wyrmsh_native_stack", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
stack = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = stack
SPEC.loader.exec_module(stack)


def function(address, size, name, metadata, instructions):
    return stack.Function(
        address=address,
        size=size,
        names=[name],
        metadata_size=metadata,
        instructions=[stack.Instruction(*item) for item in instructions],
    )


class StackProofTests(unittest.TestCase):
    def test_counts_frames_return_addresses_and_red_zone(self):
        functions = {
            0x1000: function(0x1000, 8, "_start", None, [
                (0x1000, "callq", "0x1100 <worker>"),
                (0x1005, "ud2", ""),
            ]),
            0x1100: function(0x1100, 16, "worker", 32, [
                (0x1100, "pushq", "%rbp"),
                (0x1101, "movq", "%rsp, %rbp"),
                (0x1104, "subq", "$0x18, %rsp"),
                (0x1108, "pushq", "0x8(%rsp)"),
                (0x1109, "addq", "$0x8, %rsp"),
                (0x110A, "callq", "0x1200 <leaf>"),
                (0x110D, "addq", "$0x18, %rsp"),
                (0x1111, "popq", "%rbp"),
                (0x1112, "retq", ""),
            ]),
            0x1200: function(0x1200, 8, "leaf", 0, [
                (0x1200, "movq", "%rax, -0x10(%rsp)"),
                (0x1205, "retq", ""),
            ]),
        }
        result = stack._prove(functions, 0x1000)
        self.assertEqual(result["maximum_stack_bytes"], 64)
        self.assertEqual([item.get("edge") for item in result["witness"]], ["call", "call", None])
        self.assertEqual(result["reachable_functions"][2]["red_zone_bytes"], 16)

    def test_tail_call_does_not_add_return_address(self):
        functions = {
            0x1000: function(0x1000, 5, "_start", None, [(0x1000, "jmpq", "0x1100 <leaf>")]),
            0x1100: function(0x1100, 5, "leaf", 0, [
                (0x1100, "movq", "%rax, -0x20(%rsp)"),
                (0x1104, "retq", ""),
            ]),
        }
        result = stack._prove(functions, 0x1000)
        self.assertEqual(result["maximum_stack_bytes"], 32)
        self.assertEqual(result["witness"][0]["edge"], "tail")
        self.assertEqual(result["witness"][0]["edge_stack_bytes"], 0)

    def test_rejects_indirect_call(self):
        functions = {0x1000: function(0x1000, 3, "_start", None, [(0x1000, "callq", "*%rax")])}
        with self.assertRaisesRegex(stack.ProofFailure, "indirect control transfer") as caught:
            stack._prove(functions, 0x1000)
        self.assertEqual(caught.exception.code, "unresolved_indirect_edge")

    def test_rejects_dynamic_stack_adjustment(self):
        functions = {0x1000: function(0x1000, 4, "_start", None, [
            (0x1000, "subq", "%rax, %rsp"),
            (0x1003, "ud2", ""),
        ])}
        with self.assertRaises(stack.ProofFailure) as caught:
            stack._prove(functions, 0x1000)
        self.assertEqual(caught.exception.code, "unsupported_stack_instruction")

        exchanged = {0x1000: function(0x1000, 4, "_start", None, [
            (0x1000, "xchgq", "%rsp, %rax"),
            (0x1003, "ud2", ""),
        ])}
        with self.assertRaises(stack.ProofFailure) as caught:
            stack._prove(exchanged, 0x1000)
        self.assertEqual(caught.exception.code, "dynamic_stack_adjustment")

    def test_rejects_recursion(self):
        functions = {0x1000: function(0x1000, 6, "_start", None, [
            (0x1000, "callq", "0x1000 <_start>"),
            (0x1005, "ud2", ""),
        ])}
        with self.assertRaises(stack.ProofFailure) as caught:
            stack._prove(functions, 0x1000)
        self.assertEqual(caught.exception.code, "recursive_call_chain")

    def test_rejects_metadata_mismatch_and_allows_exact_disassembly_fallback(self):
        mismatch = {0x1000: function(0x1000, 5, "named", 24, [
            (0x1000, "subq", "$0x10, %rsp"),
            (0x1004, "ud2", ""),
        ])}
        with self.assertRaises(stack.ProofFailure) as caught:
            stack._prove(mismatch, 0x1000)
        self.assertEqual(caught.exception.code, "stack_metadata_mismatch")
        missing = {0x1000: function(0x1000, 1, "named", None, [(0x1000, "retq", "")])}
        result = stack._prove(missing, 0x1000)
        self.assertEqual(result["disassembly_only_function_count"], 1)
        self.assertEqual(result["reachable_functions"][0]["stack_evidence"], "disassembly")

    def test_rejects_limit_excess(self):
        functions = {0x1000: function(0x1000, 5, "_start", None, [
            (0x1000, "subq", f"${stack.WORKING_STACK_LIMIT + 8}, %rsp"),
            (0x1004, "ud2", ""),
        ])}
        with self.assertRaises(stack.ProofFailure) as caught:
            stack._prove(functions, 0x1000)
        self.assertEqual(caught.exception.code, "stack_limit_exceeded")

    def test_rejects_inconsistent_branch_stack_state(self):
        functions = {0x1000: function(0x1000, 16, "_start", None, [
            (0x1000, "je", "0x1008 <_start+0x8>"),
            (0x1002, "pushq", "%rax"),
            (0x1003, "jmpq", "0x1008 <_start+0x8>"),
            (0x1008, "ud2", ""),
        ])}
        with self.assertRaises(stack.ProofFailure) as caught:
            stack._prove(functions, 0x1000)
        self.assertEqual(caught.exception.code, "inconsistent_stack_merge")

    def test_accepts_exact_fixed_llvm_stack_probe(self):
        functions = {0x1000: function(0x1000, 40, "_start", 0x3020, [
            (0x1000, "movq", "%rsp, %r11"),
            (0x1003, "subq", "$0x3000, %r11"),
            (0x100A, "subq", "$0x1000, %rsp"),
            (0x1011, "movq", "$0x0, (%rsp)"),
            (0x1019, "cmpq", "%r11, %rsp"),
            (0x101C, "jne", "0x100a <_start+0xa>"),
            (0x101E, "subq", "$0x20, %rsp"),
            (0x1022, "ud2", ""),
        ])}
        result = stack._prove(functions, 0x1000)
        self.assertEqual(result["maximum_stack_bytes"], 0x3020)

    def test_real_elf_cli_is_location_independent(self):
        clang = Path("/usr/lib/llvm/22/bin/clang")
        self.assertTrue(clang.is_file())
        source_text = """
__attribute__((noinline)) int leaf(int x) {
    volatile char red_zone[32]; red_zone[0] = (char)x; return red_zone[0];
}
int _start(void) { return leaf(3); }
"""
        temporary_root = REPO / ".tmp"
        temporary_root.mkdir(exist_ok=True)
        reports = []
        with tempfile.TemporaryDirectory(dir=temporary_root) as first, \
                tempfile.TemporaryDirectory(dir=temporary_root) as second:
            first = Path(first)
            second = Path(second)
            source = first / "fixture.c"
            source.write_text(source_text)
            elf = first / "fixture.elf"
            subprocess.run([
                clang, "-O1", "-fno-stack-protector", "-fstack-size-section",
                "-nostdlib", "-fuse-ld=lld", "-no-pie", "-Wl,-e,_start",
                "-o", elf, source,
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            second_elf = second / "fixture.elf"
            shutil.copyfile(elf, second_elf)
            for directory, candidate in ((first, elf), (second, second_elf)):
                report = directory / "report.json"
                completed = subprocess.run([
                    sys.executable, MODULE_PATH, "--elf", candidate, "--report", report,
                ], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                reports.append(report.read_bytes())
        self.assertEqual(reports[0], reports[1])
        document = json.loads(reports[0])
        self.assertEqual(document["status"], "pass")
        self.assertEqual(document["analysis"]["maximum_stack_bytes"], 8)
        self.assertEqual(document["llvm_tools"][0]["version"], "LLVM version 22.1.8")

    def test_parser_binds_header_symbols_stack_sizes_and_disassembly(self):
        stack_record = (4096).to_bytes(8, "little") + b"\x00"
        elf_bytes = b"\x00" * 64 + stack_record
        document = [{
            "FileSummary": {"Format": "elf64-x86-64", "Arch": "x86_64", "AddressSize": "64bit"},
            "ElfHeader": {
                "Ident": {"DataEncoding": {"Name": "LittleEndian", "Value": 1}},
                "Type": "Executable (0x2)", "Machine": {"Name": "EM_X86_64", "Value": 62},
                "Entry": 4096,
            },
            "Sections": [
                {"Section": {"Name": {"Name": ".text", "Value": 1}}},
                {"Section": {"Name": {"Name": ".stack_sizes", "Value": 2},
                             "Offset": 64, "Size": len(stack_record)}},
            ],
            "Symbols": [{"Symbol": {
                "Name": {"Name": "_start", "Value": 1}, "Value": 4096, "Size": 2,
                "Type": {"Name": "Function", "Value": 2},
            }}],
            "StackSizes": [{"Entry": {"Functions": ["_start"], "Size": 0}}],
        }]
        facts, functions = stack._parse_readobj(json.dumps(document).encode(), elf_bytes)
        stack._parse_disassembly(b"0000000000001000 <_start>:\n  1000:\tretq\n", functions)
        self.assertEqual(facts["entry"], 4096)
        self.assertEqual(functions[4096].instructions[0].mnemonic, "retq")


if __name__ == "__main__":
    unittest.main()
