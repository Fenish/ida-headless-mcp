"""Data models for IDA Headless MCP Server.

All effective addresses (EAs) are represented as hex strings (e.g. ``"0x401000"``)
in the MCP interface.  The :func:`parse_ea` helper converts them to Python ``int``
for internal use.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


# ---------------------------------------------------------------------------
# EA parsing utility
# ---------------------------------------------------------------------------

def parse_ea(ea_str: str) -> int:
    """Parse an EA string to int.

    Supports ``0x``-prefixed hexadecimal and plain decimal strings.

    Args:
        ea_str: The address string to parse.

    Returns:
        The integer value of the address.

    Raises:
        ValueError: If *ea_str* is not a valid numeric string.
    """
    try:
        return int(ea_str, 0)  # Supports 0x prefix and decimal
    except (ValueError, TypeError):
        raise ValueError(f"Invalid address: {ea_str}")


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

@dataclass
class SessionInfo:
    """Summary of an active analysis session."""

    session_id: str
    binary_path: str
    architecture: Literal["32", "64"]
    state: str
    created_at: float


# ---------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------

@dataclass
class FunctionInfo:
    """Basic function information."""

    ea: str
    name: str
    end_ea: str
    size: int


@dataclass
class FunctionDetails(FunctionInfo):
    """Extended function details including block count and frame info."""

    num_blocks: int = 0
    calling_convention: str = ""
    frame_size: int = 0


# ---------------------------------------------------------------------------
# Decompilation
# ---------------------------------------------------------------------------

@dataclass
class DecompileResult:
    """Result of decompiling a function via Hex-Rays."""

    ea: str
    name: str
    pseudocode: str
    parameter_types: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Disassembly
# ---------------------------------------------------------------------------

@dataclass
class InstructionInfo:
    """A single disassembled instruction."""

    ea: str
    raw_bytes: str
    mnemonic: str
    operands: str
    comment: str | None = None


# ---------------------------------------------------------------------------
# Cross-References
# ---------------------------------------------------------------------------

@dataclass
class XrefInfo:
    """A single cross-reference entry."""

    source_ea: str
    target_ea: str
    xref_type: Literal["code_call", "code_jump", "data_read", "data_write", "data_offset"]
    source_function: str | None = None
    target_function: str | None = None


@dataclass
class FunctionXrefs:
    """Callers and callees of a function."""

    callers: list[XrefInfo] = field(default_factory=list)
    callees: list[XrefInfo] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Strings
# ---------------------------------------------------------------------------

@dataclass
class StringInfo:
    """A string found in the binary."""

    ea: str
    value: str
    length: int
    string_type: str


@dataclass
class StringResults:
    """Paginated string listing result."""

    strings: list[StringInfo] = field(default_factory=list)
    total_count: int = 0
    offset: int = 0
    limit: int = 100


# ---------------------------------------------------------------------------
# Segments
# ---------------------------------------------------------------------------

@dataclass
class SegmentInfo:
    """Binary segment / section metadata."""

    name: str
    start_ea: str
    end_ea: str
    size: int
    permissions: str
    seg_class: str
    bitness: int


# ---------------------------------------------------------------------------
# Imports / Exports
# ---------------------------------------------------------------------------

@dataclass
class ImportInfo:
    """An imported symbol."""

    library: str
    name: str
    ordinal: int
    ea: str


@dataclass
class ExportInfo:
    """An exported symbol."""

    name: str
    ordinal: int
    ea: str


# ---------------------------------------------------------------------------
# Types / Structs
# ---------------------------------------------------------------------------

@dataclass
class TypeInfo:
    """A locally defined type."""

    name: str
    size: int
    definition: str


@dataclass
class FieldDef:
    """A struct field definition."""

    name: str
    type_str: str
    offset: int


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------

@dataclass
class CommentInfo:
    """Comments at a given address."""

    ea: str
    regular: str | None = None
    repeatable: str | None = None
    function_comment: str | None = None


# ---------------------------------------------------------------------------
# Patching
# ---------------------------------------------------------------------------

@dataclass
class PatchInfo:
    """A patched byte record."""

    ea: str
    original_byte: str
    patched_byte: str


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------

@dataclass
class SignatureResult:
    """Result of applying a FLIRT signature file."""

    sig_file: str
    functions_matched: int


# ---------------------------------------------------------------------------
# Bookmarks
# ---------------------------------------------------------------------------

@dataclass
class BookmarkInfo:
    """A marked position / bookmark."""

    ea: str
    description: str


# ---------------------------------------------------------------------------
# Batch
# ---------------------------------------------------------------------------

@dataclass
class BatchJobInfo:
    """Summary of a batch analysis job."""

    job_id: str
    total: int
    state: str


@dataclass
class BatchStatus:
    """Detailed status of a batch analysis job."""

    job_id: str
    state: str
    completed: int
    in_progress: int
    pending: int
    errors: dict[str, str] = field(default_factory=dict)
    session_ids: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

@dataclass
class EnumInfo:
    """An enumeration type."""

    name: str
    member_count: int
    width: int


@dataclass
class EnumMember:
    """A single enum member."""

    name: str
    value: int


# ---------------------------------------------------------------------------
# Data / Names
# ---------------------------------------------------------------------------

@dataclass
class NameInfo:
    """A named location in the binary."""

    ea: str
    name: str
    type: str | None = None


@dataclass
class DataTypeInfo:
    """Data type information at an address."""

    ea: str
    type_name: str
    size: int


# ---------------------------------------------------------------------------
# Call Graph
# ---------------------------------------------------------------------------

@dataclass
class FunctionRef:
    """A lightweight function reference (EA + name)."""

    ea: str
    name: str


@dataclass
class CallGraphNode:
    """A node in a call graph tree."""

    ea: str
    name: str
    children: list["CallGraphNode"] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Generic result
# ---------------------------------------------------------------------------

@dataclass
class OperationResult:
    """Generic success/failure result for mutating operations."""

    success: bool
    message: str
