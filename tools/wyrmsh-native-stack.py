#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prove a bounded native Wyrmsh stack call chain from one exact ELF.

The analyzer never executes the input. It combines LLVM stack-size metadata
with instruction-level x86-64 stack-pointer dataflow and fails closed when a
reachable edge or stack adjustment cannot be resolved exactly.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
from typing import NoReturn


REPO = Path(__file__).resolve().parent.parent
READOBJ = Path("/usr/lib/llvm/22/bin/llvm-readobj")
OBJDUMP = Path("/usr/lib/llvm/22/bin/llvm-objdump")
LLVM_VERSION = "22.1.8"
TOOL_HASHES = {
    READOBJ: "8074c683dc2c5bfebd5e68245b9d435a3a44ff7e232f20b6a1d01a22f5d7caf8",
    OBJDUMP: "62b4f73958bc93a1f9618d4c35b4459d8563a60f11d22af313f7bb639e440f0b",
}
WORKING_STACK_LIMIT = 108 * 1024
MAPPED_STACK_BYTES = 128 * 1024
STARTUP_BLOCK_BYTES = 20 * 1024
MAX_ELF_BYTES = 32 * 1024 * 1024
MAX_TOOL_OUTPUT_BYTES = 128 * 1024 * 1024
TOOL_TIMEOUT_SECONDS = 60

HEADING = re.compile(r"^([0-9a-fA-F]+) <(.+)>:$")
INSTRUCTION = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+)*\s*([A-Za-z][A-Za-z0-9.]*)\s*(.*?)\s*$"
)
MEMORY_BASE = re.compile(
    r"(?P<disp>[+-]?(?:0x[0-9a-fA-F]+|[0-9]+))?"
    r"\(%(?P<base>rsp|rbp)(?P<index>,[^)]*)?\)"
)


class ProofFailure(Exception):
    """A stable fail-closed proof outcome."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Instruction:
    address: int
    mnemonic: str
    operands: str


@dataclass
class Function:
    address: int
    size: int
    names: list[str]
    instructions: list[Instruction] = field(default_factory=list)
    metadata_size: int | None = None

    @property
    def name(self) -> str:
        return sorted(self.names, key=lambda item: (len(item), item))[0]


@dataclass(frozen=True)
class State:
    depth: int
    rbp_depth: int | None


@dataclass(frozen=True)
class Edge:
    source_address: int
    target: int
    kind: str
    depth: int


@dataclass
class LocalAnalysis:
    peak: int
    maximum_rsp_depth: int
    red_zone_bytes: int
    edges: list[Edge]


def _digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


def _regular(path: Path, *, unique: bool = True) -> None:
    info = path.lstat()
    if path.resolve() != path or not stat.S_ISREG(info.st_mode):
        raise ValueError(f"expected resolved regular file: {path}")
    if unique and info.st_nlink != 1:
        raise ValueError(f"expected one-link file: {path}")


def _inside_repo(path: Path) -> bool:
    try:
        path.relative_to(REPO)
        return True
    except ValueError:
        return False


def _run(command: list[str], *, cwd: Path) -> bytes:
    environment = {
        "PATH": "/usr/lib/llvm/22/bin:/usr/bin:/bin",
        "LC_ALL": "C",
    }
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    assert process.stdout is not None and process.stderr is not None
    streams = selectors.DefaultSelector()
    streams.register(process.stdout, selectors.EVENT_READ, "stdout")
    streams.register(process.stderr, selectors.EVENT_READ, "stderr")
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + TOOL_TIMEOUT_SECONDS
    try:
        while streams.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            events = streams.select(remaining)
            if not events:
                raise TimeoutError
            for key, _ in events:
                captured_bytes = sum(len(value) for value in captured.values())
                read_limit = min(65536, MAX_TOOL_OUTPUT_BYTES - captured_bytes + 1)
                chunk = os.read(key.fileobj.fileno(), read_limit)
                if not chunk:
                    streams.unregister(key.fileobj)
                    continue
                captured[key.data].extend(chunk)
                if sum(len(value) for value in captured.values()) > MAX_TOOL_OUTPUT_BYTES:
                    raise OverflowError
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        process.wait(timeout=remaining)
    except (TimeoutError, subprocess.TimeoutExpired, OverflowError) as error:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        if isinstance(error, OverflowError):
            raise RuntimeError("LLVM tool output exceeded bounded size") from error
        raise RuntimeError(f"LLVM tool exceeded {TOOL_TIMEOUT_SECONDS}s") from error
    finally:
        streams.close()
        process.stdout.close()
        process.stderr.close()
    stdout = bytes(captured["stdout"])
    stderr = bytes(captured["stderr"])
    if process.returncode:
        message = stderr.decode("utf-8", "replace").strip().splitlines()
        suffix = message[0] if message else "no diagnostic"
        raise RuntimeError(f"LLVM tool exited {process.returncode}: {suffix}")
    if stderr:
        raise RuntimeError("LLVM tool produced unexpected stderr")
    return stdout


def _int(value: object, field_name: str) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as error:
            raise ProofFailure("malformed_llvm_json", f"invalid {field_name}") from error
    raise ProofFailure("malformed_llvm_json", f"invalid {field_name}")


def _name(value: object, field_name: str) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("Name"), str):
        return value["Name"]
    raise ProofFailure("malformed_llvm_json", f"invalid {field_name}")


def _parse_readobj(
    raw: bytes, elf_bytes: bytes
) -> tuple[dict[str, object], dict[int, Function]]:
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProofFailure("malformed_llvm_json", "llvm-readobj output is not JSON") from error
    if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
        raise ProofFailure("malformed_llvm_json", "expected one ELF document")
    root = document[0]
    header = root.get("ElfHeader")
    summary = root.get("FileSummary")
    if not isinstance(header, dict) or not isinstance(summary, dict):
        raise ProofFailure("malformed_llvm_json", "missing ELF header")
    ident = header.get("Ident")
    if not isinstance(ident, dict):
        raise ProofFailure("malformed_llvm_json", "missing ELF identification")
    facts = {
        "format": summary.get("Format"),
        "architecture": summary.get("Arch"),
        "address_size": summary.get("AddressSize"),
        "type": header.get("Type"),
        "machine": _name(header.get("Machine"), "machine"),
        "entry": _int(header.get("Entry"), "entry"),
        "data_encoding": _name(ident.get("DataEncoding"), "data encoding"),
    }
    if facts != {
        "format": "elf64-x86-64",
        "architecture": "x86_64",
        "address_size": "64bit",
        "type": "Executable (0x2)",
        "machine": "EM_X86_64",
        "entry": facts["entry"],
        "data_encoding": "LittleEndian",
    }:
        raise ProofFailure("unsupported_elf", "requires little-endian x86-64 executable ELF")

    sections = root.get("Sections")
    if not isinstance(sections, list):
        raise ProofFailure("malformed_llvm_json", "missing sections")
    section_records = [
        item["Section"] for item in sections
        if isinstance(item, dict) and isinstance(item.get("Section"), dict)
    ]
    section_names = {_name(item.get("Name"), "section name") for item in section_records}
    stack_sections = [
        item for item in section_records
        if _name(item.get("Name"), "section name") == ".stack_sizes"
    ]
    if len(stack_sections) != 1 or ".text" not in section_names:
        raise ProofFailure("missing_required_section", "requires .text and .stack_sizes")

    functions: dict[int, Function] = {}
    symbols = root.get("Symbols")
    if not isinstance(symbols, list):
        raise ProofFailure("malformed_llvm_json", "missing symbols")
    for item in symbols:
        symbol = item.get("Symbol") if isinstance(item, dict) else None
        if not isinstance(symbol, dict):
            raise ProofFailure("malformed_llvm_json", "invalid symbol")
        if _name(symbol.get("Type"), "symbol type") != "Function":
            continue
        symbol_name = _name(symbol.get("Name"), "symbol name")
        address = _int(symbol.get("Value"), "symbol address")
        size = _int(symbol.get("Size"), "symbol size")
        if not symbol_name or address == 0 or size <= 0:
            continue
        current = functions.setdefault(address, Function(address, size, []))
        if current.size != size:
            raise ProofFailure("ambiguous_symbol", f"function aliases differ in size at 0x{address:x}")
        current.names.append(symbol_name)

    stack_section = stack_sections[0]
    offset = _int(stack_section.get("Offset"), "stack section offset")
    size = _int(stack_section.get("Size"), "stack section size")
    end = offset + size
    if offset < 0 or size <= 0 or end > len(elf_bytes):
        raise ProofFailure("malformed_stack_metadata", "stack section lies outside ELF")
    records = memoryview(elf_bytes)[offset:end]
    cursor = 0
    while cursor < len(records):
        if len(records) - cursor < 9:
            raise ProofFailure("malformed_stack_metadata", "truncated stack-size record")
        address = int.from_bytes(records[cursor:cursor + 8], "little")
        cursor += 8
        frame_size = 0
        shift = 0
        while True:
            if cursor >= len(records) or shift >= 64:
                raise ProofFailure("malformed_stack_metadata", "invalid stack-size ULEB128")
            byte = records[cursor]
            cursor += 1
            frame_size |= (byte & 0x7F) << shift
            if byte & 0x80 == 0:
                break
            shift += 7
        function = functions.get(address)
        if function is None:
            raise ProofFailure(
                "orphan_stack_metadata", f"stack record 0x{address:x} has no function symbol"
            )
        if function.metadata_size not in (None, frame_size):
            raise ProofFailure("ambiguous_stack_metadata", f"conflicting stack size for {function.name}")
        function.metadata_size = frame_size
    return facts, functions


def _parse_disassembly(raw: bytes, functions: dict[int, Function]) -> None:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ProofFailure("malformed_disassembly", "llvm-objdump output is not UTF-8") from error
    current: Function | None = None
    for line in lines:
        heading = HEADING.match(line.strip())
        if heading:
            current = functions.get(int(heading.group(1), 16))
            continue
        instruction = INSTRUCTION.match(line)
        if not instruction or current is None:
            continue
        address = int(instruction.group(1), 16)
        if current.address <= address < current.address + current.size:
            operands = instruction.group(3).split("#", 1)[0].strip()
            current.instructions.append(
                Instruction(address, instruction.group(2).lower(), operands)
            )
    for function in functions.values():
        function.instructions.sort(key=lambda item: item.address)


def _parse_immediate(value: str) -> int:
    value = value.strip()
    if value.startswith("$"):
        value = value[1:]
    try:
        return int(value, 0)
    except ValueError as error:
        raise ProofFailure("unsupported_stack_instruction", f"nonconstant immediate {value}") from error


def _direct_target(operands: str, instruction: Instruction) -> int:
    if operands.startswith("*"):
        raise ProofFailure(
            "unresolved_indirect_edge", f"indirect control transfer at 0x{instruction.address:x}"
        )
    match = re.match(r"^(?:0x)?([0-9a-fA-F]+)(?:\s+<.*>)?$", operands)
    if not match:
        raise ProofFailure(
            "unresolved_control_edge", f"unparsed control target at 0x{instruction.address:x}"
        )
    return int(match.group(1), 16)


def _writes_register(operands: str, register: str) -> bool:
    if not operands:
        return False
    return operands.split(",")[-1].strip() == register


def _writes_stack_pointer(operands: str) -> bool:
    if not operands:
        return False
    return operands.split(",")[-1].strip() in {"%rsp", "%esp", "%sp", "%spl"}


def _memory_peak(instruction: Instruction, state: State) -> int:
    peak = state.depth
    for match in MEMORY_BASE.finditer(instruction.operands):
        if match.group("index"):
            continue
        displacement = _parse_immediate(match.group("disp") or "0")
        base_depth = state.depth if match.group("base") == "rsp" else state.rbp_depth
        if base_depth is not None:
            peak = max(peak, base_depth - displacement)
    return peak


def _stack_probe_branches(function: Function) -> dict[int, int]:
    """Recognize LLVM's fixed-size page-touch loop without accepting a dynamic probe."""
    probes: dict[int, int] = {}
    instructions = function.instructions
    for index in range(len(instructions) - 5):
        move, target_sub, page_sub, touch, compare, branch = instructions[index:index + 6]
        move_parts = [part.strip() for part in move.operands.split(",")]
        target_parts = [part.strip() for part in target_sub.operands.split(",")]
        compare_parts = [part.strip() for part in compare.operands.split(",")]
        if (
            not move.mnemonic.startswith("mov")
            or len(move_parts) != 2
            or move_parts[0] != "%rsp"
            or not re.fullmatch(r"%r(?:[a-z]{2}|1[0-5])", move_parts[1])
            or not target_sub.mnemonic.startswith("sub")
            or len(target_parts) != 2
            or target_parts[1] != move_parts[1]
            or not page_sub.mnemonic.startswith("sub")
            or page_sub.operands != "$0x1000, %rsp"
            or not touch.mnemonic.startswith("mov")
            or touch.operands != "$0x0, (%rsp)"
            or not compare.mnemonic.startswith("cmp")
            or compare_parts != [move_parts[1], "%rsp"]
            or branch.mnemonic not in ("jne", "jnz")
        ):
            continue
        total = _parse_immediate(target_parts[0])
        if total < 4096 or total % 4096:
            continue
        if _direct_target(branch.operands, branch) != page_sub.address:
            continue
        probes[branch.address] = total
    return probes


def _stack_effect(function: Function, instruction: Instruction, state: State) -> State:
    mnemonic = instruction.mnemonic
    operands = instruction.operands
    depth = state.depth
    rbp_depth = state.rbp_depth
    if mnemonic.startswith("enter") or mnemonic.startswith(("iret", "lret")):
        raise ProofFailure(
            "dynamic_stack_adjustment", f"unsupported implicit stack write at 0x{instruction.address:x}"
        )
    if mnemonic.startswith("xchg") and any(
        register in operands for register in ("%rsp", "%esp", "%sp", "%spl")
    ):
        raise ProofFailure(
            "dynamic_stack_adjustment", f"exchange with stack pointer at 0x{instruction.address:x}"
        )
    if mnemonic.startswith("push"):
        depth += 8
    elif mnemonic.startswith("pop"):
        if operands.strip() == "%rsp" or "(" in operands:
            raise ProofFailure(
                "dynamic_stack_adjustment", f"unsupported pop destination at 0x{instruction.address:x}"
            )
        depth -= 8
        if operands.strip() == "%rbp":
            rbp_depth = None
    elif mnemonic.startswith("leave"):
        if rbp_depth is None:
            raise ProofFailure("dynamic_stack_adjustment", f"leave without frame base at 0x{instruction.address:x}")
        depth = rbp_depth - 8
        rbp_depth = None
    elif _writes_stack_pointer(operands) and not mnemonic.startswith(("cmp", "test")):
        parts = [part.strip() for part in operands.split(",")]
        if parts[-1] != "%rsp":
            raise ProofFailure(
                "dynamic_stack_adjustment", f"partial stack-pointer write at 0x{instruction.address:x}"
            )
        if mnemonic.startswith("sub") and len(parts) == 2:
            depth += _parse_immediate(parts[0])
        elif mnemonic.startswith("add") and len(parts) == 2:
            depth -= _parse_immediate(parts[0])
        elif mnemonic.startswith("lea") and len(parts) == 2:
            match = re.fullmatch(
                r"([+-]?(?:0x[0-9a-fA-F]+|[0-9]+))?\(%rsp\)", parts[0]
            )
            if not match:
                raise ProofFailure("dynamic_stack_adjustment", f"dynamic lea into rsp at 0x{instruction.address:x}")
            depth -= _parse_immediate(match.group(1) or "0")
        elif mnemonic.startswith("mov") and len(parts) == 2 and parts[0] == "%rbp":
            if rbp_depth is None:
                raise ProofFailure("dynamic_stack_adjustment", f"unknown rbp restore at 0x{instruction.address:x}")
            depth = rbp_depth
        elif (
            mnemonic.startswith("and")
            and "_start" in function.names
            and depth == 0
            and len(parts) == 2
            and _parse_immediate(parts[0]) == -16
        ):
            # ABI v2 enters with a 16-byte-aligned RSP, so this exact shim instruction is a no-op.
            depth = 0
        else:
            raise ProofFailure("dynamic_stack_adjustment", f"unsupported rsp write at 0x{instruction.address:x}")
    if _writes_register(operands, "%rbp") and not mnemonic.startswith(("cmp", "test")):
        parts = [part.strip() for part in operands.split(",")]
        if mnemonic.startswith("mov") and len(parts) == 2 and parts[0] == "%rsp":
            rbp_depth = depth
        elif not mnemonic.startswith("pop"):
            rbp_depth = None
    if depth < 0:
        raise ProofFailure("unbalanced_stack", f"stack rises above entry at 0x{instruction.address:x}")
    return State(depth, rbp_depth)


def _local_analysis(function: Function, functions: dict[int, Function]) -> LocalAnalysis:
    if not function.instructions:
        raise ProofFailure("missing_disassembly", f"no instructions for {function.name}")
    by_address = {instruction.address: index for index, instruction in enumerate(function.instructions)}
    states: dict[int, State] = {function.instructions[0].address: State(0, None)}
    work = [function.instructions[0].address]
    peak = 0
    maximum_rsp_depth = 0
    red_zone = 0
    edges: list[Edge] = []
    stack_probes = _stack_probe_branches(function)
    while work:
        address = work.pop()
        state = states[address]
        index = by_address[address]
        instruction = function.instructions[index]
        memory_peak = _memory_peak(instruction, state)
        peak = max(peak, memory_peak)
        red_zone = max(red_zone, memory_peak - state.depth)
        after = _stack_effect(function, instruction, state)
        maximum_rsp_depth = max(maximum_rsp_depth, after.depth)
        peak = max(peak, after.depth)
        mnemonic = instruction.mnemonic
        next_address = (
            function.instructions[index + 1].address
            if index + 1 < len(function.instructions)
            else None
        )
        successors: list[int] = []
        if mnemonic.startswith("call"):
            target = _direct_target(instruction.operands, instruction)
            if target not in functions:
                raise ProofFailure("unresolved_control_edge", f"call target 0x{target:x} has no function")
            edges.append(Edge(instruction.address, target, "call", after.depth))
            if next_address is not None:
                successors.append(next_address)
        elif mnemonic in ("jmp", "jmpq"):
            target = _direct_target(instruction.operands, instruction)
            if target in by_address:
                successors.append(target)
            else:
                if target not in functions:
                    raise ProofFailure("unresolved_control_edge", f"jump target 0x{target:x} has no function")
                if after.depth != 0:
                    raise ProofFailure("unrestored_tail_call", f"tail call retains stack at 0x{instruction.address:x}")
                edges.append(Edge(instruction.address, target, "tail", 0))
        elif instruction.address in stack_probes:
            # One pass already accounted for the first page. Collapse the proven fixed loop to
            # its exact total allocation and continue only after the loop.
            after = State(after.depth + stack_probes[instruction.address] - 4096, after.rbp_depth)
            maximum_rsp_depth = max(maximum_rsp_depth, after.depth)
            peak = max(peak, after.depth)
            if next_address is None:
                raise ProofFailure("unterminated_function", "stack probe has no continuation")
            successors.append(next_address)
        elif mnemonic.startswith("j"):
            target = _direct_target(instruction.operands, instruction)
            if target in by_address:
                successors.append(target)
            elif target in functions and after.depth == 0:
                edges.append(Edge(instruction.address, target, "tail", 0))
            else:
                raise ProofFailure("unresolved_control_edge", f"conditional target 0x{target:x} is unresolved")
            if next_address is not None:
                successors.append(next_address)
        elif mnemonic.startswith("ret"):
            if instruction.operands or after.depth != 0:
                raise ProofFailure("unbalanced_stack", f"unbalanced return at 0x{instruction.address:x}")
        elif mnemonic in ("ud2", "hlt", "int3"):
            pass
        elif next_address is not None:
            successors.append(next_address)
        else:
            raise ProofFailure("unterminated_function", f"reachable fallthrough from {function.name}")
        for successor in successors:
            previous = states.get(successor)
            if previous is None:
                states[successor] = after
                work.append(successor)
            elif previous != after:
                raise ProofFailure(
                    "inconsistent_stack_merge", f"different stack states meet at 0x{successor:x}"
                )
    if function.metadata_size is not None and function.metadata_size > maximum_rsp_depth:
        raise ProofFailure(
            "stack_metadata_mismatch",
            f"{function.name}: metadata {function.metadata_size} exceeds instruction peak "
            f"{maximum_rsp_depth}",
        )
    return LocalAnalysis(peak, maximum_rsp_depth, red_zone, edges)


def _prove(functions: dict[int, Function], root_address: int) -> dict[str, object]:
    local: dict[int, LocalAnalysis] = {}
    totals: dict[int, tuple[int, list[dict[str, object]]]] = {}
    visiting: list[int] = []

    def visit(address: int) -> tuple[int, list[dict[str, object]]]:
        if address in totals:
            return totals[address]
        if address in visiting:
            cycle = visiting[visiting.index(address):] + [address]
            names = " -> ".join(functions[item].name for item in cycle)
            raise ProofFailure("recursive_call_chain", names)
        visiting.append(address)
        function = functions[address]
        analysis = local.setdefault(address, _local_analysis(function, functions))
        maximum = analysis.peak
        witness = [{
            "function": function.name,
            "address": f"0x{address:x}",
            "local_peak_bytes": analysis.peak,
            "maximum_rsp_depth_bytes": analysis.maximum_rsp_depth,
            "red_zone_bytes": analysis.red_zone_bytes,
        }]
        for edge in analysis.edges:
            child_peak, child_witness = visit(edge.target)
            candidate = child_peak if edge.kind == "tail" else edge.depth + 8 + child_peak
            if candidate > maximum:
                maximum = candidate
                witness = [{
                    "function": function.name,
                    "address": f"0x{address:x}",
                    "local_peak_bytes": analysis.peak,
                    "maximum_rsp_depth_bytes": analysis.maximum_rsp_depth,
                    "red_zone_bytes": analysis.red_zone_bytes,
                    "edge": edge.kind,
                    "edge_address": f"0x{edge.source_address:x}",
                    "edge_stack_bytes": edge.depth + (8 if edge.kind == "call" else 0),
                }, *child_witness]
        visiting.pop()
        totals[address] = maximum, witness
        return totals[address]

    maximum, witness = visit(root_address)
    reachable = sorted(totals)
    metadata_count = sum(functions[address].metadata_size is not None for address in reachable)
    if maximum > WORKING_STACK_LIMIT:
        raise ProofFailure(
            "stack_limit_exceeded", f"maximum {maximum} exceeds {WORKING_STACK_LIMIT} bytes"
        )
    return {
        "maximum_stack_bytes": maximum,
        "slack_bytes": WORKING_STACK_LIMIT - maximum,
        "reachable_function_count": len(reachable),
        "stack_metadata_function_count": metadata_count,
        "disassembly_only_function_count": len(reachable) - metadata_count,
        "reachable_functions": [
            {
                "address": f"0x{address:x}",
                "name": functions[address].name,
                "maximum_rsp_depth_bytes": local[address].maximum_rsp_depth,
                "red_zone_bytes": local[address].red_zone_bytes,
                "stack_metadata_bytes": functions[address].metadata_size,
                "stack_evidence": (
                    "metadata_and_disassembly"
                    if functions[address].metadata_size is not None
                    else "disassembly"
                ),
            }
            for address in reachable
        ],
        "witness": witness,
        "return_address_bytes_per_call": 8,
    }


def _tool_identities() -> list[dict[str, str]]:
    identities = []
    for tool, expected_hash in TOOL_HASHES.items():
        _regular(tool)
        if _digest(tool) != expected_hash:
            raise ValueError(f"LLVM tool identity mismatch: {tool}")
        version = _run([str(tool), "--version"], cwd=REPO).decode("utf-8", "strict")
        version_lines = [line.strip() for line in version.splitlines() if line.strip()]
        version_line = next(
            (line for line in version_lines if line.startswith("LLVM version ")),
            "",
        )
        if f"LLVM version {LLVM_VERSION}" not in version:
            raise ValueError(f"LLVM version mismatch: {tool}")
        identities.append({
            "path": str(tool),
            "sha256": expected_hash,
            "version": version_line,
        })
    return identities


def _write_report(path: Path, report: dict[str, object]) -> None:
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(encoded)
            destination.flush()
            os.fsync(destination.fileno())
    except Exception:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _die(message: str) -> NoReturn:
    raise SystemExit(message)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    arguments = parser.parse_args()
    elf = arguments.elf.absolute()
    report_path = arguments.report.absolute()
    try:
        _regular(elf)
        if not _inside_repo(elf) or elf.stat().st_size > MAX_ELF_BYTES:
            raise ValueError("ELF must be a bounded file inside the Wyrmroot repository")
        if elf.name.startswith("-"):
            raise ValueError("ELF basename must not begin with a dash")
        if report_path.exists() or report_path.is_symlink():
            raise ValueError("report path must be fresh")
        if report_path.parent.resolve() != report_path.parent or not _inside_repo(report_path.parent):
            raise ValueError("report parent must be a resolved directory inside the repository")
        if not report_path.parent.is_dir():
            raise ValueError("report parent must exist")
        analyzer = Path(__file__).resolve()
        _regular(analyzer)
        analyzer_hash = _digest(analyzer)
        elf_bytes = elf.read_bytes()
        elf_hash = hashlib.sha256(elf_bytes).hexdigest()
        elf_size = len(elf_bytes)
        tools = _tool_identities()
        readobj = _run([
            str(READOBJ), "--elf-output-style=JSON", "--file-header", "--sections",
            "--stack-sizes", "--symbols", elf.name,
        ], cwd=elf.parent)
        objdump = _run([
            str(OBJDUMP), "--disassemble", "--no-show-raw-insn", "--print-imm-hex",
            "--x86-asm-syntax=att", elf.name,
        ], cwd=elf.parent)
        raw_hashes = {
            "llvm_objdump_sha256": hashlib.sha256(objdump).hexdigest(),
            "llvm_readobj_sha256": hashlib.sha256(readobj).hexdigest(),
        }
        base: dict[str, object] = {
            "kind": "wyrmsh-native-stack-v1",
            "analyzer_sha256": analyzer_hash,
            "elf": {"name": elf.name, "sha256": elf_hash, "size": elf_size},
            "limits": {
                "mapped_stack_bytes": MAPPED_STACK_BYTES,
                "startup_block_bytes": STARTUP_BLOCK_BYTES,
                "working_stack_bytes": WORKING_STACK_LIMIT,
            },
            "llvm_tools": tools,
            "raw_output_hashes": raw_hashes,
        }
        try:
            facts, functions = _parse_readobj(readobj, elf_bytes)
            _parse_disassembly(objdump, functions)
            starts = [item for item in functions.values() if "_start" in item.names]
            if len(starts) != 1 or facts["entry"] != starts[0].address:
                raise ProofFailure("invalid_entry", "ELF entry must be the unique _start symbol")
            base["elf"] = {**base["elf"], **facts, "entry": f"0x{starts[0].address:x}"}
            base["analysis"] = _prove(functions, starts[0].address)
            base["status"] = "pass"
            exit_code = 0
        except ProofFailure as error:
            base["status"] = "fail"
            base["failure"] = {"code": error.code, "detail": error.detail}
            exit_code = 1
        if _digest(elf) != elf_hash or elf.stat().st_size != elf_size:
            raise ValueError("ELF changed during analysis")
        if _digest(analyzer) != analyzer_hash:
            raise ValueError("analyzer changed during analysis")
        for tool, expected_hash in TOOL_HASHES.items():
            if _digest(tool) != expected_hash:
                raise ValueError("LLVM tool changed during analysis")
        _write_report(report_path, base)
        print(json.dumps({
            "elf_sha256": elf_hash,
            "report": str(report_path),
            "status": base["status"],
            **({"maximum_stack_bytes": base["analysis"]["maximum_stack_bytes"]}
               if "analysis" in base else {"failure": base["failure"]}),
        }, sort_keys=True))
        raise SystemExit(exit_code)
    except (OSError, RuntimeError, ValueError) as error:
        _die(f"wyrmsh-native-stack: {error}")


if __name__ == "__main__":
    main()
