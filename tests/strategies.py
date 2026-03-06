"""Hypothesis strategies for generating valid test data matching IDA Headless MCP models.

Provides reusable strategies for property-based tests (Properties 1–30).
Each strategy generates data conforming to the dataclasses in
``ida_headless_mcp.models``.
"""

from __future__ import annotations

import string
from typing import Any

from hypothesis import strategies as st

from ida_headless_mcp.models import (
    BookmarkInfo,
    CallGraphNode,
    CommentInfo,
    EnumInfo,
    EnumMember,
    ExportInfo,
    FieldDef,
    FunctionDetails,
    FunctionInfo,
    FunctionRef,
    ImportInfo,
    InstructionInfo,
    PatchInfo,
    SegmentInfo,
    StringInfo,
    TypeInfo,
    XrefInfo,
)

# ---------------------------------------------------------------------------
# Primitive strategies
# ---------------------------------------------------------------------------

# Valid effective addresses as hex strings (e.g. "0x401000")
ea_integers = st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF)
ea_strings = ea_integers.map(lambda n: f"0x{n:x}")

# Function / symbol names — C-identifier-like
_ident_start = string.ascii_letters + "_"
_ident_chars = string.ascii_letters + string.digits + "_"

function_names = st.from_regex(r"[a-zA-Z_][a-zA-Z0-9_]{0,49}", fullmatch=True)

# Type definition strings (simplified C types)
_base_types = st.sampled_from([
    "int", "char", "short", "long", "float", "double",
    "void*", "unsigned int", "unsigned char", "uint8_t",
    "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t",
    "int32_t", "int64_t", "size_t", "DWORD", "BYTE", "WORD",
])

type_definitions = _base_types

# Byte patterns with optional wildcards (e.g. "90 CC ?? 41")
_hex_byte = st.integers(min_value=0, max_value=255).map(lambda b: f"{b:02x}")
_wildcard = st.just("??")
_pattern_element = st.one_of(_hex_byte, _wildcard)

byte_patterns = st.lists(
    _pattern_element, min_size=1, max_size=16
).map(lambda parts: " ".join(parts))

# Comment strings — printable text, non-empty
comment_strings = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "Z"), blacklist_characters="\x00"),
    min_size=1,
    max_size=200,
).filter(lambda s: len(s.strip()) > 0)

# Enum names — uppercase C identifiers
enum_names = st.from_regex(r"[A-Z][A-Z0-9_]{0,29}", fullmatch=True)

# Enum member names — uppercase identifiers
enum_member_names = st.from_regex(r"[A-Z][A-Z0-9_]{0,29}", fullmatch=True)

# File paths (simplified)
file_paths = st.from_regex(
    r"[/\\]?[a-zA-Z0-9_.\-]+(/[a-zA-Z0-9_.\-]+){0,4}", fullmatch=True
)

# Address ranges — (start_ea, end_ea) where start < end, as hex strings
address_ranges = st.tuples(
    st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFF0),
    st.integers(min_value=1, max_value=0xFF),
).map(lambda t: (f"0x{t[0]:x}", f"0x{t[0] + t[1]:x}"))

# Filter patterns — glob-style patterns for function/string filtering
filter_patterns = st.one_of(
    st.just("*"),
    st.from_regex(r"[a-zA-Z_*?]{1,20}", fullmatch=True),
    function_names.map(lambda n: f"*{n}*"),
    function_names.map(lambda n: f"{n}*"),
)

# Segment permissions strings
permissions_strings = st.sampled_from(["rwx", "r-x", "rw-", "r--", "---"])

# Segment class strings
seg_class_strings = st.sampled_from(["CODE", "DATA", "CONST", "BSS", "STACK", "XTRN"])

# Segment bitness
bitness_values = st.sampled_from([16, 32, 64])

# Xref type literals
xref_types = st.sampled_from(["code_call", "code_jump", "data_read", "data_write", "data_offset"])

# String type identifiers
string_types = st.sampled_from(["ascii", "utf8", "utf16", "utf32", "pascal"])

# Calling conventions
calling_conventions = st.sampled_from([
    "cdecl", "stdcall", "fastcall", "thiscall", "vectorcall", "ms_abi", "sysv_abi",
])

# Library names for imports
library_names = st.from_regex(r"[a-z][a-z0-9_]{0,19}\.(so|dll|dylib)", fullmatch=True)


# ---------------------------------------------------------------------------
# Composite strategies — model instances
# ---------------------------------------------------------------------------

@st.composite
def function_infos(draw: st.DrawFn) -> FunctionInfo:
    """Generate a valid ``FunctionInfo`` with consistent ea/end_ea/size."""
    ea_int = draw(st.integers(min_value=0x1000, max_value=0xFFFFFFFF))
    size = draw(st.integers(min_value=1, max_value=0x10000))
    end_ea_int = ea_int + size
    name = draw(function_names)
    return FunctionInfo(
        ea=f"0x{ea_int:x}",
        name=name,
        end_ea=f"0x{end_ea_int:x}",
        size=size,
    )


@st.composite
def function_details_st(draw: st.DrawFn) -> FunctionDetails:
    """Generate a valid ``FunctionDetails`` with consistent fields."""
    ea_int = draw(st.integers(min_value=0x1000, max_value=0xFFFFFFFF))
    size = draw(st.integers(min_value=1, max_value=0x10000))
    end_ea_int = ea_int + size
    return FunctionDetails(
        ea=f"0x{ea_int:x}",
        name=draw(function_names),
        end_ea=f"0x{end_ea_int:x}",
        size=size,
        num_blocks=draw(st.integers(min_value=1, max_value=500)),
        calling_convention=draw(calling_conventions),
        frame_size=draw(st.integers(min_value=0, max_value=0x10000)),
    )


@st.composite
def xref_infos(draw: st.DrawFn) -> XrefInfo:
    """Generate a valid ``XrefInfo``."""
    return XrefInfo(
        source_ea=draw(ea_strings),
        target_ea=draw(ea_strings),
        xref_type=draw(xref_types),
        source_function=draw(st.one_of(st.none(), function_names)),
        target_function=draw(st.one_of(st.none(), function_names)),
    )


@st.composite
def segment_infos(draw: st.DrawFn) -> SegmentInfo:
    """Generate a valid ``SegmentInfo`` with consistent start/end/size."""
    start = draw(st.integers(min_value=0x1000, max_value=0xFFFFFFFF))
    size = draw(st.integers(min_value=1, max_value=0x100000))
    return SegmentInfo(
        name=draw(st.from_regex(r"\.[a-z]{1,10}", fullmatch=True)),
        start_ea=f"0x{start:x}",
        end_ea=f"0x{start + size:x}",
        size=size,
        permissions=draw(permissions_strings),
        seg_class=draw(seg_class_strings),
        bitness=draw(bitness_values),
    )


@st.composite
def import_infos(draw: st.DrawFn) -> ImportInfo:
    """Generate a valid ``ImportInfo``."""
    return ImportInfo(
        library=draw(library_names),
        name=draw(function_names),
        ordinal=draw(st.integers(min_value=0, max_value=9999)),
        ea=draw(ea_strings),
    )


@st.composite
def export_infos(draw: st.DrawFn) -> ExportInfo:
    """Generate a valid ``ExportInfo``."""
    return ExportInfo(
        name=draw(function_names),
        ordinal=draw(st.integers(min_value=0, max_value=9999)),
        ea=draw(ea_strings),
    )


@st.composite
def string_infos(draw: st.DrawFn) -> StringInfo:
    """Generate a valid ``StringInfo``."""
    value = draw(st.text(
        alphabet=st.characters(whitelist_categories=("L", "N", "P", "Z"), blacklist_characters="\x00"),
        min_size=1,
        max_size=100,
    ).filter(lambda s: len(s.strip()) > 0))
    return StringInfo(
        ea=draw(ea_strings),
        value=value,
        length=len(value),
        string_type=draw(string_types),
    )


@st.composite
def type_infos(draw: st.DrawFn) -> TypeInfo:
    """Generate a valid ``TypeInfo``."""
    name = draw(function_names)
    size = draw(st.integers(min_value=1, max_value=1024))
    return TypeInfo(
        name=name,
        size=size,
        definition=f"struct {name} {{ /* {size} bytes */ }}",
    )


@st.composite
def field_defs(draw: st.DrawFn) -> FieldDef:
    """Generate a valid ``FieldDef``."""
    return FieldDef(
        name=draw(function_names),
        type_str=draw(type_definitions),
        offset=draw(st.integers(min_value=0, max_value=1024)),
    )


@st.composite
def comment_infos(draw: st.DrawFn) -> CommentInfo:
    """Generate a valid ``CommentInfo``."""
    return CommentInfo(
        ea=draw(ea_strings),
        regular=draw(st.one_of(st.none(), comment_strings)),
        repeatable=draw(st.one_of(st.none(), comment_strings)),
        function_comment=draw(st.one_of(st.none(), comment_strings)),
    )


@st.composite
def patch_infos(draw: st.DrawFn) -> PatchInfo:
    """Generate a valid ``PatchInfo``."""
    return PatchInfo(
        ea=draw(ea_strings),
        original_byte=draw(st.integers(min_value=0, max_value=255).map(lambda b: f"{b:02x}")),
        patched_byte=draw(st.integers(min_value=0, max_value=255).map(lambda b: f"{b:02x}")),
    )


@st.composite
def bookmark_infos(draw: st.DrawFn) -> BookmarkInfo:
    """Generate a valid ``BookmarkInfo``."""
    return BookmarkInfo(
        ea=draw(ea_strings),
        description=draw(comment_strings),
    )


@st.composite
def enum_members(draw: st.DrawFn) -> EnumMember:
    """Generate a valid ``EnumMember``."""
    return EnumMember(
        name=draw(enum_member_names),
        value=draw(st.integers(min_value=0, max_value=0xFFFFFFFF)),
    )


@st.composite
def enum_infos(draw: st.DrawFn) -> EnumInfo:
    """Generate a valid ``EnumInfo``."""
    member_count = draw(st.integers(min_value=0, max_value=50))
    return EnumInfo(
        name=draw(enum_names),
        member_count=member_count,
        width=draw(st.sampled_from([1, 2, 4, 8])),
    )


@st.composite
def instruction_infos(draw: st.DrawFn) -> InstructionInfo:
    """Generate a valid ``InstructionInfo``."""
    mnemonics = st.sampled_from([
        "nop", "mov", "push", "pop", "call", "ret", "jmp", "je", "jne",
        "add", "sub", "xor", "and", "or", "cmp", "test", "lea", "int",
    ])
    return InstructionInfo(
        ea=draw(ea_strings),
        raw_bytes=draw(st.integers(min_value=0, max_value=0xFFFFFFFF).map(lambda n: f"{n:02x}")),
        mnemonic=draw(mnemonics),
        operands=draw(st.text(alphabet=string.ascii_letters + string.digits + ", []+-*", min_size=0, max_size=30)),
        comment=draw(st.one_of(st.none(), comment_strings)),
    )


# ---------------------------------------------------------------------------
# List strategies — for generating collections of model instances
# ---------------------------------------------------------------------------

function_info_lists = st.lists(function_infos(), min_size=0, max_size=20)
xref_info_lists = st.lists(xref_infos(), min_size=0, max_size=20)
segment_info_lists = st.lists(segment_infos(), min_size=0, max_size=10)
import_info_lists = st.lists(import_infos(), min_size=0, max_size=20)
export_info_lists = st.lists(export_infos(), min_size=0, max_size=20)
string_info_lists = st.lists(string_infos(), min_size=0, max_size=20)


# ---------------------------------------------------------------------------
# Call graph tree strategy
# ---------------------------------------------------------------------------

@st.composite
def call_graph_nodes(draw: st.DrawFn, max_depth: int = 3) -> CallGraphNode:
    """Generate a valid ``CallGraphNode`` tree up to *max_depth* levels."""
    ea = draw(ea_strings)
    name = draw(function_names)
    if max_depth <= 0:
        return CallGraphNode(ea=ea, name=name)
    num_children = draw(st.integers(min_value=0, max_value=3))
    children = [draw(call_graph_nodes(max_depth=max_depth - 1)) for _ in range(num_children)]
    return CallGraphNode(ea=ea, name=name, children=children)
