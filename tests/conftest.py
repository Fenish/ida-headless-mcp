"""Shared test fixtures and mock IDA bridge for the IDA Headless MCP test suite.

Provides:
- ``MockIdaBridge`` — simulates IDA script execution with in-memory state
- ``MockSession`` — simulates an IDA session without spawning real processes
- ``MockSessionManager`` — manages mock sessions and dispatches scripts
- Shared pytest fixtures for use across unit and property tests
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Literal

import pytest

from ida_headless_mcp.config import ServerConfig
from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import (
    BookmarkInfo,
    CallGraphNode,
    CommentInfo,
    DataTypeInfo,
    DecompileResult,
    EnumInfo,
    EnumMember,
    ExportInfo,
    FieldDef,
    FunctionDetails,
    FunctionInfo,
    FunctionRef,
    FunctionXrefs,
    ImportInfo,
    InstructionInfo,
    NameInfo,
    OperationResult,
    PatchInfo,
    SegmentInfo,
    SessionInfo,
    SignatureResult,
    StringInfo,
    StringResults,
    TypeInfo,
    XrefInfo,
)


# ---------------------------------------------------------------------------
# ScriptResult (mirrors ida_bridge.ScriptResult before it's implemented)
# ---------------------------------------------------------------------------

@dataclass
class ScriptResult:
    """Result of executing an IDAPython script."""

    success: bool
    data: Any = None
    stdout: str = ""
    stderr: str = ""
    return_value: Any = None


# ---------------------------------------------------------------------------
# Session state enum
# ---------------------------------------------------------------------------

class SessionState(str, Enum):
    STARTING = "starting"
    ANALYZING = "analyzing"
    READY = "ready"
    BUSY = "busy"
    ERROR = "error"
    CLOSED = "closed"


# ---------------------------------------------------------------------------
# MockIdaBridge — in-memory IDA state simulation
# ---------------------------------------------------------------------------

class MockIdaBridge:
    """Simulates IDA script execution against an in-memory binary database.

    Maintains state for functions, types, comments, patches, strings,
    segments, imports, exports, bookmarks, enums, names, data types,
    call graph relationships, signatures, and scripting results.

    All addresses are stored as ``int`` internally and converted to/from
    hex strings (``"0x..."`` format) at the boundary.
    """

    def __init__(self) -> None:
        # Functions: ea (int) -> FunctionDetails
        self.functions: dict[int, FunctionDetails] = {}

        # Types/structs: name -> {"info": TypeInfo, "fields": list[FieldDef]}
        self.types: dict[str, dict[str, Any]] = {}

        # Comments: ea (int) -> CommentInfo
        self.comments: dict[int, CommentInfo] = {}

        # Memory / patches: ea (int) -> byte value (int 0-255)
        self.memory: dict[int, int] = {}
        # Patch tracking: ea (int) -> {"original": int, "patched": int}
        self.patches: dict[int, dict[str, int]] = {}

        # Strings: ea (int) -> StringInfo
        self.strings: dict[int, StringInfo] = {}

        # Segments: name -> SegmentInfo
        self.segments: dict[str, SegmentInfo] = {}

        # Imports: (library, name) -> ImportInfo
        self.imports: dict[tuple[str, str], ImportInfo] = {}

        # Exports: name -> ExportInfo
        self.exports: dict[str, ExportInfo] = {}

        # Bookmarks: ea (int) -> description
        self.bookmarks: dict[int, str] = {}

        # Enums: name -> {"info": EnumInfo, "members": list[EnumMember]}
        self.enums: dict[str, dict[str, Any]] = {}

        # Names: ea (int) -> NameInfo
        self.names: dict[int, NameInfo] = {}

        # Data types at addresses: ea (int) -> DataTypeInfo
        self.data_types: dict[int, DataTypeInfo] = {}

        # Call graph: ea (int) -> {"callers": list[int], "callees": list[int]}
        self.call_graph: dict[int, dict[str, list[int]]] = {}

        # Applied signatures: list of sig file names
        self.applied_signatures: list[str] = []

        # Available signature files (simulated directory listing)
        self.available_signatures: list[str] = []

        # Decompilation results: ea (int) -> pseudocode string
        self.decompile_results: dict[int, str] = {}

        # Script execution capture
        self.last_script: str | None = None
        self.script_stdout: str = ""
        self.script_return_value: Any = None

    # -- Helpers --

    @staticmethod
    def _ea_str(ea: int) -> str:
        return f"0x{ea:x}"

    @staticmethod
    def _parse_ea(ea_str: str) -> int:
        return int(ea_str, 0)

    # -- Functions --

    def add_function(
        self,
        ea: int,
        name: str,
        size: int,
        *,
        num_blocks: int = 1,
        calling_convention: str = "cdecl",
        frame_size: int = 0,
    ) -> FunctionDetails:
        end_ea = ea + size
        fd = FunctionDetails(
            ea=self._ea_str(ea),
            name=name,
            end_ea=self._ea_str(end_ea),
            size=size,
            num_blocks=num_blocks,
            calling_convention=calling_convention,
            frame_size=frame_size,
        )
        self.functions[ea] = fd
        # Also register in names
        self.names[ea] = NameInfo(ea=self._ea_str(ea), name=name, type="func")
        return fd

    def list_functions(self, filter_pattern: str | None = None) -> list[FunctionInfo]:
        funcs = list(self.functions.values())
        if filter_pattern:
            funcs = [f for f in funcs if fnmatch.fnmatch(f.name, filter_pattern)]
        return funcs

    def get_function_details(self, ea: int) -> FunctionDetails | None:
        return self.functions.get(ea)

    def rename_function(self, ea: int, new_name: str) -> OperationResult:
        if ea not in self.functions:
            return OperationResult(success=False, message=f"No function at {self._ea_str(ea)}")
        self.functions[ea].name = new_name
        if ea in self.names:
            self.names[ea].name = new_name
        return OperationResult(success=True, message=f"Renamed to {new_name}")

    def create_function(self, ea: int) -> OperationResult:
        if ea in self.functions:
            return OperationResult(success=False, message="Function already exists")
        self.add_function(ea, f"sub_{ea:x}", 16)
        return OperationResult(success=True, message=f"Created function at {self._ea_str(ea)}")

    def delete_function(self, ea: int) -> OperationResult:
        if ea not in self.functions:
            return OperationResult(success=False, message="Function not found")
        del self.functions[ea]
        return OperationResult(success=True, message="Function deleted")

    # -- Decompilation --

    def decompile_function(self, ea: int, var_hints: dict[str, str] | None = None) -> DecompileResult | None:
        func = self.functions.get(ea)
        if func is None:
            return None
        pseudocode = self.decompile_results.get(ea, f"int {func.name}() {{ return 0; }}")
        if var_hints:
            for old_name, new_name in var_hints.items():
                pseudocode = pseudocode.replace(old_name, new_name)
        return DecompileResult(
            ea=func.ea,
            name=func.name,
            pseudocode=pseudocode,
            parameter_types=["int", "char**"],
        )

    # -- Disassembly --

    def disassemble_at(self, ea: int) -> InstructionInfo:
        byte_val = self.memory.get(ea, 0x90)
        return InstructionInfo(
            ea=self._ea_str(ea),
            raw_bytes=f"{byte_val:02x}",
            mnemonic="nop" if byte_val == 0x90 else "unknown",
            operands="",
            comment=self.comments.get(ea, CommentInfo(ea=self._ea_str(ea))).regular,
        )

    def disassemble_range(self, start_ea: int, end_ea: int) -> list[InstructionInfo]:
        instructions = []
        ea = start_ea
        while ea < end_ea:
            instructions.append(self.disassemble_at(ea))
            ea += 1
        return instructions

    # -- Cross-references --

    def add_xref(self, source_ea: int, target_ea: int) -> None:
        if source_ea not in self.call_graph:
            self.call_graph[source_ea] = {"callers": [], "callees": []}
        if target_ea not in self.call_graph:
            self.call_graph[target_ea] = {"callers": [], "callees": []}
        if target_ea not in self.call_graph[source_ea]["callees"]:
            self.call_graph[source_ea]["callees"].append(target_ea)
        if source_ea not in self.call_graph[target_ea]["callers"]:
            self.call_graph[target_ea]["callers"].append(source_ea)

    def get_xrefs_to(self, ea: int) -> list[XrefInfo]:
        entry = self.call_graph.get(ea, {"callers": [], "callees": []})
        result = []
        for src in entry["callers"]:
            src_func = self.functions.get(src)
            tgt_func = self.functions.get(ea)
            result.append(XrefInfo(
                source_ea=self._ea_str(src),
                target_ea=self._ea_str(ea),
                xref_type="code_call",
                source_function=src_func.name if src_func else None,
                target_function=tgt_func.name if tgt_func else None,
            ))
        return result

    def get_xrefs_from(self, ea: int) -> list[XrefInfo]:
        entry = self.call_graph.get(ea, {"callers": [], "callees": []})
        result = []
        for tgt in entry["callees"]:
            src_func = self.functions.get(ea)
            tgt_func = self.functions.get(tgt)
            result.append(XrefInfo(
                source_ea=self._ea_str(ea),
                target_ea=self._ea_str(tgt),
                xref_type="code_call",
                source_function=src_func.name if src_func else None,
                target_function=tgt_func.name if tgt_func else None,
            ))
        return result

    def get_function_xrefs(self, ea: int) -> FunctionXrefs:
        return FunctionXrefs(
            callers=self.get_xrefs_to(ea),
            callees=self.get_xrefs_from(ea),
        )

    # -- Strings --

    def add_string(self, ea: int, value: str, string_type: str = "ascii") -> StringInfo:
        si = StringInfo(ea=self._ea_str(ea), value=value, length=len(value), string_type=string_type)
        self.strings[ea] = si
        return si

    def list_strings(
        self,
        filter_pattern: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> StringResults:
        all_strings = list(self.strings.values())
        if filter_pattern:
            all_strings = [s for s in all_strings if fnmatch.fnmatch(s.value, filter_pattern)]
        total = len(all_strings)
        page = all_strings[offset : offset + limit]
        return StringResults(strings=page, total_count=total, offset=offset, limit=limit)

    # -- Segments --

    def add_segment(
        self,
        name: str,
        start_ea: int,
        size: int,
        *,
        permissions: str = "rwx",
        seg_class: str = "CODE",
        bitness: int = 64,
    ) -> SegmentInfo:
        end_ea = start_ea + size
        si = SegmentInfo(
            name=name,
            start_ea=self._ea_str(start_ea),
            end_ea=self._ea_str(end_ea),
            size=size,
            permissions=permissions,
            seg_class=seg_class,
            bitness=bitness,
        )
        self.segments[name] = si
        return si

    def list_segments(self) -> list[SegmentInfo]:
        return list(self.segments.values())

    def get_segment(self, name_or_ea: str) -> SegmentInfo | None:
        if name_or_ea in self.segments:
            return self.segments[name_or_ea]
        # Try as EA
        try:
            ea = int(name_or_ea, 0)
        except (ValueError, TypeError):
            return None
        return self.get_segment_at(ea)

    def get_segment_at(self, ea: int) -> SegmentInfo | None:
        for seg in self.segments.values():
            seg_start = self._parse_ea(seg.start_ea)
            seg_end = self._parse_ea(seg.end_ea)
            if seg_start <= ea < seg_end:
                return seg
        return None

    # -- Imports / Exports --

    def add_import(self, library: str, name: str, ordinal: int, ea: int) -> ImportInfo:
        ii = ImportInfo(library=library, name=name, ordinal=ordinal, ea=self._ea_str(ea))
        self.imports[(library, name)] = ii
        return ii

    def list_imports(self, library: str | None = None) -> list[ImportInfo]:
        imps = list(self.imports.values())
        if library:
            imps = [i for i in imps if i.library == library]
        return imps

    def add_export(self, name: str, ordinal: int, ea: int) -> ExportInfo:
        ei = ExportInfo(name=name, ordinal=ordinal, ea=self._ea_str(ea))
        self.exports[name] = ei
        return ei

    def list_exports(self) -> list[ExportInfo]:
        return list(self.exports.values())

    # -- Types / Structs --

    def create_struct(self, name: str, fields: list[FieldDef]) -> OperationResult:
        if name in self.types:
            return OperationResult(success=False, message=f"Type '{name}' already exists")
        total_size = sum(self._field_size(f.type_str) for f in fields) if fields else 0
        definition = f"struct {name} {{ " + "; ".join(f"{f.type_str} {f.name}" for f in fields) + "; }"
        self.types[name] = {
            "info": TypeInfo(name=name, size=total_size, definition=definition),
            "fields": list(fields),
        }
        return OperationResult(success=True, message=f"Created struct '{name}'")

    def add_struct_field(self, struct_name: str, fld: FieldDef) -> OperationResult:
        if struct_name not in self.types:
            return OperationResult(success=False, message=f"Struct '{struct_name}' not found")
        entry = self.types[struct_name]
        entry["fields"].append(fld)
        entry["info"].size += self._field_size(fld.type_str)
        return OperationResult(success=True, message=f"Added field '{fld.name}'")

    def delete_type(self, name: str) -> OperationResult:
        if name not in self.types:
            return OperationResult(success=False, message=f"Type '{name}' not found")
        del self.types[name]
        return OperationResult(success=True, message=f"Deleted type '{name}'")

    def list_types(self) -> list[TypeInfo]:
        return [entry["info"] for entry in self.types.values()]

    def apply_type(self, ea: int, type_str: str) -> OperationResult:
        self.data_types[ea] = DataTypeInfo(
            ea=self._ea_str(ea),
            type_name=type_str,
            size=self._field_size(type_str),
        )
        return OperationResult(success=True, message=f"Applied type '{type_str}' at {self._ea_str(ea)}")

    @staticmethod
    def _field_size(type_str: str) -> int:
        sizes = {"int": 4, "char": 1, "short": 2, "long": 8, "float": 4, "double": 8, "void*": 8}
        return sizes.get(type_str, 4)

    # -- Comments --

    def set_comment(self, ea: int, comment: str, comment_type: str = "regular") -> OperationResult:
        if ea not in self.comments:
            self.comments[ea] = CommentInfo(ea=self._ea_str(ea))
        ci = self.comments[ea]
        if comment_type == "regular":
            ci.regular = comment
        elif comment_type == "repeatable":
            ci.repeatable = comment
        elif comment_type == "function":
            ci.function_comment = comment
        else:
            return OperationResult(success=False, message=f"Unknown comment type: {comment_type}")
        return OperationResult(success=True, message="Comment set")

    def get_comments(self, ea: int) -> CommentInfo:
        return self.comments.get(ea, CommentInfo(ea=self._ea_str(ea)))

    def get_comments_range(self, start_ea: int, end_ea: int) -> list[CommentInfo]:
        return [
            ci for ea, ci in sorted(self.comments.items())
            if start_ea <= ea < end_ea
        ]

    # -- Patching --

    def read_bytes(self, ea: int, length: int) -> str:
        return "".join(f"{self.memory.get(ea + i, 0):02x}" for i in range(length))

    def patch_bytes(self, ea: int, hex_values: str) -> OperationResult:
        byte_vals = bytes.fromhex(hex_values)
        for i, b in enumerate(byte_vals):
            addr = ea + i
            original = self.memory.get(addr, 0)
            self.memory[addr] = b
            self.patches[addr] = {"original": original, "patched": b}
        return OperationResult(success=True, message=f"Patched {len(byte_vals)} bytes")

    def list_patches(self) -> list[PatchInfo]:
        return [
            PatchInfo(
                ea=self._ea_str(ea),
                original_byte=f"{info['original']:02x}",
                patched_byte=f"{info['patched']:02x}",
            )
            for ea, info in sorted(self.patches.items())
        ]

    # -- Search --

    def search_bytes(
        self,
        pattern: str,
        start_ea: int | None = None,
        end_ea: int | None = None,
        max_results: int = 100,
    ) -> list[str]:
        """Search memory for a byte pattern. ``??`` is a wildcard byte."""
        parts = pattern.strip().split()
        if not parts:
            return []
        results: list[str] = []
        addrs = sorted(self.memory.keys())
        if not addrs:
            return []
        search_start = start_ea if start_ea is not None else (min(addrs) if addrs else 0)
        search_end = end_ea if end_ea is not None else (max(addrs) + 1 if addrs else 0)
        for addr in range(search_start, search_end):
            if len(results) >= max_results:
                break
            match = True
            for i, p in enumerate(parts):
                if p == "??":
                    continue
                mem_byte = self.memory.get(addr + i, 0)
                try:
                    pat_byte = int(p, 16)
                except ValueError:
                    match = False
                    break
                if mem_byte != pat_byte:
                    match = False
                    break
            if match:
                results.append(self._ea_str(addr))
        return results

    def search_text(
        self,
        text: str,
        start_ea: int | None = None,
        end_ea: int | None = None,
        max_results: int = 100,
    ) -> list[str]:
        results: list[str] = []
        for ea, si in sorted(self.strings.items()):
            if len(results) >= max_results:
                break
            if start_ea is not None and ea < start_ea:
                continue
            if end_ea is not None and ea > end_ea:
                continue
            if text in si.value:
                results.append(self._ea_str(ea))
        return results

    def search_immediate(
        self,
        value: int,
        start_ea: int | None = None,
        end_ea: int | None = None,
        max_results: int = 100,
    ) -> list[str]:
        results: list[str] = []
        for ea, byte_val in sorted(self.memory.items()):
            if len(results) >= max_results:
                break
            if start_ea is not None and ea < start_ea:
                continue
            if end_ea is not None and ea > end_ea:
                continue
            if byte_val == (value & 0xFF):
                results.append(self._ea_str(ea))
        return results

    # -- Signatures --

    def apply_signature(self, sig_file: str) -> SignatureResult:
        if sig_file not in self.applied_signatures:
            self.applied_signatures.append(sig_file)
        matched = sum(1 for f in self.functions.values() if f.name.startswith("sub_"))
        return SignatureResult(sig_file=sig_file, functions_matched=matched)

    def list_applied_signatures(self) -> list[str]:
        return list(self.applied_signatures)

    def list_available_signatures(self) -> list[str]:
        return list(self.available_signatures)

    # -- Bookmarks --

    def add_bookmark(self, ea: int, description: str) -> OperationResult:
        self.bookmarks[ea] = description
        return OperationResult(success=True, message="Bookmark added")

    def list_bookmarks(self) -> list[BookmarkInfo]:
        return [
            BookmarkInfo(ea=self._ea_str(ea), description=desc)
            for ea, desc in sorted(self.bookmarks.items())
        ]

    def delete_bookmark(self, ea: int) -> OperationResult:
        if ea not in self.bookmarks:
            return OperationResult(success=False, message="Bookmark not found")
        del self.bookmarks[ea]
        return OperationResult(success=True, message="Bookmark deleted")

    # -- Enums --

    def create_enum(self, name: str, members: list[EnumMember], width: int = 4) -> OperationResult:
        if name in self.enums:
            return OperationResult(success=False, message=f"Enum '{name}' already exists")
        self.enums[name] = {
            "info": EnumInfo(name=name, member_count=len(members), width=width),
            "members": list(members),
        }
        return OperationResult(success=True, message=f"Created enum '{name}'")

    def add_enum_member(self, enum_name: str, member_name: str, value: int) -> OperationResult:
        if enum_name not in self.enums:
            return OperationResult(success=False, message=f"Enum '{enum_name}' not found")
        entry = self.enums[enum_name]
        entry["members"].append(EnumMember(name=member_name, value=value))
        entry["info"].member_count = len(entry["members"])
        return OperationResult(success=True, message=f"Added member '{member_name}'")

    def list_enums(self) -> list[EnumInfo]:
        return [entry["info"] for entry in self.enums.values()]

    # -- Names / Data types --

    def list_names(self) -> list[NameInfo]:
        return list(self.names.values())

    def rename_location(self, ea: int, new_name: str) -> OperationResult:
        if ea in self.names:
            self.names[ea].name = new_name
        else:
            self.names[ea] = NameInfo(ea=self._ea_str(ea), name=new_name)
        # Also update function name if applicable
        if ea in self.functions:
            self.functions[ea].name = new_name
        return OperationResult(success=True, message=f"Renamed to '{new_name}'")

    def get_data_type(self, ea: int) -> DataTypeInfo:
        return self.data_types.get(
            ea,
            DataTypeInfo(ea=self._ea_str(ea), type_name="byte", size=1),
        )

    def set_data_type(self, ea: int, type_str: str) -> OperationResult:
        self.data_types[ea] = DataTypeInfo(
            ea=self._ea_str(ea),
            type_name=type_str,
            size=self._field_size(type_str),
        )
        return OperationResult(success=True, message=f"Set type to '{type_str}'")

    # -- Call graph --

    def get_callers(self, ea: int) -> list[FunctionRef]:
        entry = self.call_graph.get(ea, {"callers": [], "callees": []})
        refs = []
        for caller_ea in entry["callers"]:
            func = self.functions.get(caller_ea)
            refs.append(FunctionRef(
                ea=self._ea_str(caller_ea),
                name=func.name if func else f"sub_{caller_ea:x}",
            ))
        return refs

    def get_callees(self, ea: int) -> list[FunctionRef]:
        entry = self.call_graph.get(ea, {"callers": [], "callees": []})
        refs = []
        for callee_ea in entry["callees"]:
            func = self.functions.get(callee_ea)
            refs.append(FunctionRef(
                ea=self._ea_str(callee_ea),
                name=func.name if func else f"sub_{callee_ea:x}",
            ))
        return refs

    def get_call_graph(self, ea: int, depth: int = 3) -> CallGraphNode:
        return self._build_call_graph(ea, depth, set())

    def _build_call_graph(self, ea: int, depth: int, visited: set[int]) -> CallGraphNode:
        func = self.functions.get(ea)
        name = func.name if func else f"sub_{ea:x}"
        if depth <= 0 or ea in visited:
            return CallGraphNode(ea=self._ea_str(ea), name=name)
        visited.add(ea)
        children = []
        entry = self.call_graph.get(ea, {"callers": [], "callees": []})
        for callee_ea in entry["callees"]:
            children.append(self._build_call_graph(callee_ea, depth - 1, visited))
        visited.discard(ea)
        return CallGraphNode(ea=self._ea_str(ea), name=name, children=children)

    # -- Scripting --

    def execute_script(self, script: str) -> ScriptResult:
        """Simulate script execution by capturing the script text."""
        self.last_script = script
        stdout_lines: list[str] = []
        # Simple simulation: extract print() calls
        for line in script.splitlines():
            stripped = line.strip()
            if stripped.startswith("print(") and stripped.endswith(")"):
                content = stripped[6:-1].strip("\"'")
                stdout_lines.append(content)
        # Check for raise statements to simulate exceptions
        for line in script.splitlines():
            stripped = line.strip()
            if stripped.startswith("raise "):
                return ScriptResult(
                    success=False,
                    data={"exception": {"type": "RuntimeError", "message": "simulated error", "traceback": ""}},
                    stdout="\n".join(stdout_lines),
                    stderr="",
                )
        return ScriptResult(
            success=True,
            data=None,
            stdout="\n".join(stdout_lines),
            stderr="",
            return_value=self.script_return_value,
        )

    # -- Script building / parsing (mirrors IdaBridge interface) --

    def build_script(self, operation: str, params: dict) -> str:
        """Build a simulated IDAPython script string."""
        return json.dumps({"operation": operation, "params": params})

    def parse_result(self, result_path: Path) -> ScriptResult:
        """Parse a JSON result file."""
        with open(result_path) as f:
            data = json.load(f)
        return ScriptResult(
            success=data.get("success", False),
            data=data.get("data"),
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", ""),
            return_value=data.get("return_value"),
        )


# ---------------------------------------------------------------------------
# MockSession — simulates an IDA session without real processes
# ---------------------------------------------------------------------------

class MockSession:
    """Simulates an IDA analysis session without spawning real IDA processes.

    Each mock session has its own :class:`MockIdaBridge` for isolated state.
    """

    def __init__(
        self,
        binary_path: str,
        architecture: Literal["32", "64"] = "64",
        session_id: str | None = None,
    ) -> None:
        self.session_id: str = session_id or uuid.uuid4().hex[:12]
        self.binary_path: str = binary_path
        self.idb_path: str = binary_path + (".i64" if architecture == "64" else ".idb")
        self.architecture: Literal["32", "64"] = architecture
        self.state: SessionState = SessionState.READY
        self.process: None = None  # No real process
        self.created_at: float = time.time()
        self.command_dir: Path = Path(f"/tmp/ida_mcp_{self.session_id}")
        self.bridge: MockIdaBridge = MockIdaBridge()

    def to_session_info(self) -> SessionInfo:
        return SessionInfo(
            session_id=self.session_id,
            binary_path=self.binary_path,
            architecture=self.architecture,
            state=self.state.value,
            created_at=self.created_at,
        )


# ---------------------------------------------------------------------------
# MockSessionManager — manages mock sessions
# ---------------------------------------------------------------------------

class MockSessionManager:
    """Manages :class:`MockSession` instances without spawning IDA processes.

    Provides the same interface as the real ``SessionManager`` so tool
    handlers can be tested against it.
    """

    def __init__(self, config: ServerConfig | None = None) -> None:
        self.config = config or ServerConfig(ida_path="/fake/ida")
        self.sessions: dict[str, MockSession] = {}
        self._lock = asyncio.Lock()

    async def create_session(
        self,
        binary_path: str,
        reuse_idb: bool = True,
        architecture: Literal["32", "64"] | None = None,
    ) -> MockSession:
        arch: Literal["32", "64"] = architecture or self._detect_architecture(binary_path)
        session = MockSession(binary_path=binary_path, architecture=arch)
        self.sessions[session.session_id] = session
        return session

    async def close_session(self, session_id: str, save: bool = True) -> None:
        if session_id not in self.sessions:
            raise KeyError(f"Session not found: {session_id}")
        session = self.sessions.pop(session_id)
        session.state = SessionState.CLOSED

    async def close_all_sessions(self) -> None:
        for sid in list(self.sessions.keys()):
            await self.close_session(sid)

    async def execute_script(self, session_id: str, script: str) -> ScriptResult:
        session = self.get_session(session_id)
        session.state = SessionState.BUSY
        result = session.bridge.execute_script(script)
        session.state = SessionState.READY
        return result

    def get_session(self, session_id: str) -> MockSession:
        if session_id not in self.sessions:
            raise KeyError(f"Session not found: {session_id}")
        return self.sessions[session_id]

    def list_sessions(self) -> list[SessionInfo]:
        return [s.to_session_info() for s in self.sessions.values()]

    @staticmethod
    def _detect_architecture(binary_path: str) -> Literal["32", "64"]:
        """Simple heuristic: paths containing '32' are 32-bit, else 64-bit."""
        if "32" in binary_path:
            return "32"
        return "64"


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_bridge() -> MockIdaBridge:
    """A fresh :class:`MockIdaBridge` with no pre-loaded state."""
    return MockIdaBridge()


@pytest.fixture
def populated_bridge() -> MockIdaBridge:
    """A :class:`MockIdaBridge` pre-loaded with sample data for testing.

    Contains:
    - 3 functions (main, helper, sub_1000)
    - 2 segments (.text, .data)
    - 3 strings
    - 2 imports, 1 export
    - 1 struct type
    - 2 comments
    - Some memory bytes and patches
    - 1 bookmark
    - 1 enum
    - Call graph edges
    """
    bridge = MockIdaBridge()

    # Functions
    bridge.add_function(0x401000, "main", 256, num_blocks=5, calling_convention="cdecl", frame_size=64)
    bridge.add_function(0x401100, "helper", 128, num_blocks=3, calling_convention="cdecl", frame_size=32)
    bridge.add_function(0x401200, "sub_1000", 64, num_blocks=1, calling_convention="fastcall", frame_size=16)

    # Decompilation results
    bridge.decompile_results[0x401000] = "int main(int argc, char** argv) { helper(); return 0; }"
    bridge.decompile_results[0x401100] = "void helper() { sub_1000(); }"

    # Segments
    bridge.add_segment(".text", 0x401000, 0x1000, permissions="r-x", seg_class="CODE", bitness=64)
    bridge.add_segment(".data", 0x402000, 0x1000, permissions="rw-", seg_class="DATA", bitness=64)

    # Strings
    bridge.add_string(0x402000, "Hello, World!", "ascii")
    bridge.add_string(0x402100, "Error: %s", "ascii")
    bridge.add_string(0x402200, "Usage: prog [options]", "ascii")

    # Imports
    bridge.add_import("libc.so", "printf", 0, 0x600000)
    bridge.add_import("libc.so", "malloc", 1, 0x600008)

    # Exports
    bridge.add_export("main", 0, 0x401000)

    # Types
    bridge.create_struct("my_struct", [
        FieldDef(name="x", type_str="int", offset=0),
        FieldDef(name="y", type_str="int", offset=4),
    ])

    # Comments
    bridge.set_comment(0x401000, "Entry point", "regular")
    bridge.set_comment(0x401000, "Main function", "function")
    bridge.set_comment(0x401100, "Helper function", "repeatable")

    # Memory and patches
    for i in range(16):
        bridge.memory[0x401000 + i] = 0x90  # NOP sled
    bridge.patch_bytes(0x401000, "cc")  # INT3

    # Bookmarks
    bridge.add_bookmark(0x401000, "Entry point")

    # Enums
    bridge.create_enum("Color", [
        EnumMember(name="RED", value=0),
        EnumMember(name="GREEN", value=1),
        EnumMember(name="BLUE", value=2),
    ])

    # Call graph
    bridge.add_xref(0x401000, 0x401100)  # main -> helper
    bridge.add_xref(0x401100, 0x401200)  # helper -> sub_1000
    bridge.add_xref(0x401000, 0x401200)  # main -> sub_1000

    # Signatures
    bridge.available_signatures = ["libc.sig", "msvcrt.sig", "openssl.sig"]

    return bridge


@pytest.fixture
def mock_session() -> MockSession:
    """A single :class:`MockSession` in READY state."""
    return MockSession(binary_path="/bin/ls", architecture="64")


@pytest.fixture
def mock_session_32() -> MockSession:
    """A 32-bit :class:`MockSession` in READY state."""
    return MockSession(binary_path="/bin/ls32", architecture="32")


@pytest.fixture
def mock_session_manager() -> MockSessionManager:
    """A :class:`MockSessionManager` with no active sessions."""
    return MockSessionManager()


@pytest.fixture
def populated_session() -> MockSession:
    """A :class:`MockSession` whose bridge is pre-loaded with sample data."""
    session = MockSession(binary_path="/bin/ls", architecture="64")
    bridge = session.bridge

    # Functions
    bridge.add_function(0x401000, "main", 256, num_blocks=5, calling_convention="cdecl", frame_size=64)
    bridge.add_function(0x401100, "helper", 128, num_blocks=3, calling_convention="cdecl", frame_size=32)

    # Segments
    bridge.add_segment(".text", 0x401000, 0x1000, permissions="r-x", seg_class="CODE", bitness=64)
    bridge.add_segment(".data", 0x402000, 0x1000, permissions="rw-", seg_class="DATA", bitness=64)

    # Strings
    bridge.add_string(0x402000, "Hello, World!", "ascii")

    # Call graph
    bridge.add_xref(0x401000, 0x401100)

    return session


@pytest.fixture
def sample_functions() -> list[FunctionInfo]:
    """A list of sample :class:`FunctionInfo` instances."""
    return [
        FunctionInfo(ea="0x401000", name="main", end_ea="0x401100", size=256),
        FunctionInfo(ea="0x401100", name="helper", end_ea="0x401180", size=128),
        FunctionInfo(ea="0x401200", name="sub_401200", end_ea="0x401240", size=64),
        FunctionInfo(ea="0x401300", name="init_module", end_ea="0x401380", size=128),
        FunctionInfo(ea="0x401400", name="cleanup", end_ea="0x401440", size=64),
    ]


@pytest.fixture
def sample_segments() -> list[SegmentInfo]:
    """A list of sample :class:`SegmentInfo` instances."""
    return [
        SegmentInfo(name=".text", start_ea="0x401000", end_ea="0x402000", size=4096, permissions="r-x", seg_class="CODE", bitness=64),
        SegmentInfo(name=".data", start_ea="0x402000", end_ea="0x403000", size=4096, permissions="rw-", seg_class="DATA", bitness=64),
        SegmentInfo(name=".rodata", start_ea="0x403000", end_ea="0x404000", size=4096, permissions="r--", seg_class="CONST", bitness=64),
    ]


@pytest.fixture
def sample_xrefs() -> list[XrefInfo]:
    """A list of sample :class:`XrefInfo` instances."""
    return [
        XrefInfo(source_ea="0x401000", target_ea="0x401100", xref_type="code_call", source_function="main", target_function="helper"),
        XrefInfo(source_ea="0x401050", target_ea="0x402000", xref_type="data_read", source_function="main", target_function=None),
        XrefInfo(source_ea="0x401100", target_ea="0x401200", xref_type="code_jump", source_function="helper", target_function="sub_401200"),
    ]


@pytest.fixture
def sample_imports() -> list[ImportInfo]:
    """A list of sample :class:`ImportInfo` instances."""
    return [
        ImportInfo(library="libc.so", name="printf", ordinal=0, ea="0x600000"),
        ImportInfo(library="libc.so", name="malloc", ordinal=1, ea="0x600008"),
        ImportInfo(library="libm.so", name="sin", ordinal=0, ea="0x600010"),
    ]


@pytest.fixture
def sample_exports() -> list[ExportInfo]:
    """A list of sample :class:`ExportInfo` instances."""
    return [
        ExportInfo(name="main", ordinal=0, ea="0x401000"),
        ExportInfo(name="init", ordinal=1, ea="0x401300"),
    ]
