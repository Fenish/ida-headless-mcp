"""Unit tests for ida_headless_mcp.models."""

from __future__ import annotations

import pytest

from ida_headless_mcp.models import (
    BatchJobInfo,
    BatchStatus,
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
    parse_ea,
)


# -----------------------------------------------------------------------
# parse_ea
# -----------------------------------------------------------------------

class TestParseEa:
    """Tests for the parse_ea utility function."""

    def test_hex_with_prefix(self):
        assert parse_ea("0x401000") == 0x401000

    def test_hex_uppercase(self):
        assert parse_ea("0xDEADBEEF") == 0xDEADBEEF

    def test_decimal_string(self):
        assert parse_ea("4198400") == 4198400

    def test_zero(self):
        assert parse_ea("0") == 0

    def test_hex_zero(self):
        assert parse_ea("0x0") == 0

    def test_octal_prefix(self):
        assert parse_ea("0o17") == 15

    def test_binary_prefix(self):
        assert parse_ea("0b1010") == 10

    def test_invalid_string_raises(self):
        with pytest.raises(ValueError, match="Invalid address"):
            parse_ea("not_a_number")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="Invalid address"):
            parse_ea("")

    def test_none_raises(self):
        with pytest.raises(ValueError, match="Invalid address"):
            parse_ea(None)  # type: ignore[arg-type]

    def test_float_string_raises(self):
        with pytest.raises(ValueError, match="Invalid address"):
            parse_ea("3.14")

    def test_negative_hex(self):
        assert parse_ea("-0x1") == -1

    def test_large_64bit_address(self):
        assert parse_ea("0xFFFFFFFFFFFFFFFF") == 0xFFFFFFFFFFFFFFFF


# -----------------------------------------------------------------------
# SessionInfo
# -----------------------------------------------------------------------

class TestSessionInfo:
    def test_fields(self):
        s = SessionInfo(
            session_id="abc",
            binary_path="/bin/ls",
            architecture="64",
            state="ready",
            created_at=1000.0,
        )
        assert s.session_id == "abc"
        assert s.binary_path == "/bin/ls"
        assert s.architecture == "64"
        assert s.state == "ready"
        assert s.created_at == 1000.0


# -----------------------------------------------------------------------
# FunctionInfo / FunctionDetails
# -----------------------------------------------------------------------

class TestFunctionInfo:
    def test_fields(self):
        f = FunctionInfo(ea="0x401000", name="main", end_ea="0x401100", size=256)
        assert f.ea == "0x401000"
        assert f.name == "main"
        assert f.end_ea == "0x401100"
        assert f.size == 256


class TestFunctionDetails:
    def test_inherits_function_info(self):
        d = FunctionDetails(
            ea="0x401000",
            name="main",
            end_ea="0x401100",
            size=256,
            num_blocks=5,
            calling_convention="cdecl",
            frame_size=64,
        )
        assert isinstance(d, FunctionInfo)
        assert d.num_blocks == 5
        assert d.calling_convention == "cdecl"
        assert d.frame_size == 64

    def test_defaults(self):
        d = FunctionDetails(ea="0x0", name="f", end_ea="0x10", size=16)
        assert d.num_blocks == 0
        assert d.calling_convention == ""
        assert d.frame_size == 0


# -----------------------------------------------------------------------
# DecompileResult
# -----------------------------------------------------------------------

class TestDecompileResult:
    def test_fields(self):
        r = DecompileResult(
            ea="0x401000",
            name="main",
            pseudocode="int main() { return 0; }",
            parameter_types=["int", "char**"],
        )
        assert r.pseudocode == "int main() { return 0; }"
        assert r.parameter_types == ["int", "char**"]

    def test_default_parameter_types(self):
        r = DecompileResult(ea="0x0", name="f", pseudocode="void f() {}")
        assert r.parameter_types == []


# -----------------------------------------------------------------------
# InstructionInfo
# -----------------------------------------------------------------------

class TestInstructionInfo:
    def test_fields(self):
        i = InstructionInfo(
            ea="0x401000",
            raw_bytes="55",
            mnemonic="push",
            operands="rbp",
            comment="prologue",
        )
        assert i.mnemonic == "push"
        assert i.comment == "prologue"

    def test_comment_default_none(self):
        i = InstructionInfo(ea="0x0", raw_bytes="90", mnemonic="nop", operands="")
        assert i.comment is None


# -----------------------------------------------------------------------
# XrefInfo / FunctionXrefs
# -----------------------------------------------------------------------

class TestXrefInfo:
    def test_fields(self):
        x = XrefInfo(
            source_ea="0x401000",
            target_ea="0x402000",
            xref_type="code_call",
            source_function="main",
            target_function="printf",
        )
        assert x.xref_type == "code_call"

    def test_optional_functions_default_none(self):
        x = XrefInfo(source_ea="0x0", target_ea="0x1", xref_type="data_read")
        assert x.source_function is None
        assert x.target_function is None


class TestFunctionXrefs:
    def test_defaults(self):
        fx = FunctionXrefs()
        assert fx.callers == []
        assert fx.callees == []


# -----------------------------------------------------------------------
# StringInfo / StringResults
# -----------------------------------------------------------------------

class TestStringInfo:
    def test_fields(self):
        s = StringInfo(ea="0x500000", value="Hello", length=5, string_type="ascii")
        assert s.value == "Hello"
        assert s.string_type == "ascii"


class TestStringResults:
    def test_defaults(self):
        sr = StringResults()
        assert sr.strings == []
        assert sr.total_count == 0
        assert sr.offset == 0
        assert sr.limit == 100

    def test_with_data(self):
        si = StringInfo(ea="0x0", value="x", length=1, string_type="ascii")
        sr = StringResults(strings=[si], total_count=1, offset=0, limit=10)
        assert len(sr.strings) == 1


# -----------------------------------------------------------------------
# SegmentInfo
# -----------------------------------------------------------------------

class TestSegmentInfo:
    def test_fields(self):
        s = SegmentInfo(
            name=".text",
            start_ea="0x401000",
            end_ea="0x402000",
            size=4096,
            permissions="r-x",
            seg_class="CODE",
            bitness=64,
        )
        assert s.permissions == "r-x"
        assert s.bitness == 64


# -----------------------------------------------------------------------
# ImportInfo / ExportInfo
# -----------------------------------------------------------------------

class TestImportInfo:
    def test_fields(self):
        i = ImportInfo(library="libc.so", name="printf", ordinal=0, ea="0x600000")
        assert i.library == "libc.so"


class TestExportInfo:
    def test_fields(self):
        e = ExportInfo(name="main", ordinal=1, ea="0x401000")
        assert e.ordinal == 1


# -----------------------------------------------------------------------
# TypeInfo / FieldDef
# -----------------------------------------------------------------------

class TestTypeInfo:
    def test_fields(self):
        t = TypeInfo(name="my_struct", size=16, definition="struct my_struct { int x; int y; }")
        assert t.size == 16


class TestFieldDef:
    def test_fields(self):
        f = FieldDef(name="x", type_str="int", offset=0)
        assert f.offset == 0


# -----------------------------------------------------------------------
# CommentInfo
# -----------------------------------------------------------------------

class TestCommentInfo:
    def test_defaults(self):
        c = CommentInfo(ea="0x401000")
        assert c.regular is None
        assert c.repeatable is None
        assert c.function_comment is None

    def test_with_values(self):
        c = CommentInfo(ea="0x0", regular="hi", repeatable="rep", function_comment="fn")
        assert c.regular == "hi"


# -----------------------------------------------------------------------
# PatchInfo
# -----------------------------------------------------------------------

class TestPatchInfo:
    def test_fields(self):
        p = PatchInfo(ea="0x401000", original_byte="90", patched_byte="CC")
        assert p.original_byte == "90"
        assert p.patched_byte == "CC"


# -----------------------------------------------------------------------
# SignatureResult
# -----------------------------------------------------------------------

class TestSignatureResult:
    def test_fields(self):
        s = SignatureResult(sig_file="libc.sig", functions_matched=42)
        assert s.functions_matched == 42


# -----------------------------------------------------------------------
# BookmarkInfo
# -----------------------------------------------------------------------

class TestBookmarkInfo:
    def test_fields(self):
        b = BookmarkInfo(ea="0x401000", description="entry point")
        assert b.description == "entry point"


# -----------------------------------------------------------------------
# BatchJobInfo / BatchStatus
# -----------------------------------------------------------------------

class TestBatchJobInfo:
    def test_fields(self):
        j = BatchJobInfo(job_id="j1", total=10, state="pending")
        assert j.total == 10


class TestBatchStatus:
    def test_defaults(self):
        bs = BatchStatus(
            job_id="j1", state="in_progress", completed=3, in_progress=2, pending=5
        )
        assert bs.errors == {}
        assert bs.session_ids == {}

    def test_with_errors(self):
        bs = BatchStatus(
            job_id="j1",
            state="completed",
            completed=9,
            in_progress=0,
            pending=0,
            errors={"/bad/bin": "crash"},
            session_ids={"/good/bin": "s1"},
        )
        assert "/bad/bin" in bs.errors


# -----------------------------------------------------------------------
# EnumInfo / EnumMember
# -----------------------------------------------------------------------

class TestEnumInfo:
    def test_fields(self):
        e = EnumInfo(name="Color", member_count=3, width=4)
        assert e.member_count == 3


class TestEnumMember:
    def test_fields(self):
        m = EnumMember(name="RED", value=0)
        assert m.value == 0


# -----------------------------------------------------------------------
# NameInfo / DataTypeInfo
# -----------------------------------------------------------------------

class TestNameInfo:
    def test_fields(self):
        n = NameInfo(ea="0x401000", name="main", type="func")
        assert n.type == "func"

    def test_type_default_none(self):
        n = NameInfo(ea="0x0", name="x")
        assert n.type is None


class TestDataTypeInfo:
    def test_fields(self):
        d = DataTypeInfo(ea="0x500000", type_name="dword", size=4)
        assert d.type_name == "dword"


# -----------------------------------------------------------------------
# FunctionRef / CallGraphNode
# -----------------------------------------------------------------------

class TestFunctionRef:
    def test_fields(self):
        r = FunctionRef(ea="0x401000", name="main")
        assert r.name == "main"


class TestCallGraphNode:
    def test_leaf_node(self):
        n = CallGraphNode(ea="0x401000", name="leaf")
        assert n.children == []

    def test_nested_tree(self):
        child = CallGraphNode(ea="0x402000", name="child")
        root = CallGraphNode(ea="0x401000", name="root", children=[child])
        assert len(root.children) == 1
        assert root.children[0].name == "child"


# -----------------------------------------------------------------------
# OperationResult
# -----------------------------------------------------------------------

class TestOperationResult:
    def test_success(self):
        r = OperationResult(success=True, message="done")
        assert r.success is True

    def test_failure(self):
        r = OperationResult(success=False, message="failed")
        assert r.success is False
