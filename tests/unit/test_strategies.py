"""Verification tests for Hypothesis strategies in tests/strategies.py.

Ensures all strategies produce valid data matching the IDA Headless MCP models.
"""

from __future__ import annotations

from hypothesis import given, settings

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
    ImportInfo,
    InstructionInfo,
    PatchInfo,
    SegmentInfo,
    StringInfo,
    TypeInfo,
    XrefInfo,
)
from tests.strategies import (
    bookmark_infos,
    byte_patterns,
    call_graph_nodes,
    calling_conventions,
    comment_infos,
    comment_strings,
    ea_strings,
    enum_infos,
    enum_members,
    enum_member_names,
    enum_names,
    export_infos,
    export_info_lists,
    field_defs,
    file_paths,
    filter_patterns,
    function_details_st,
    function_info_lists,
    function_infos,
    function_names,
    import_infos,
    import_info_lists,
    instruction_infos,
    library_names,
    patch_infos,
    segment_info_lists,
    segment_infos,
    string_info_lists,
    string_infos,
    type_definitions,
    type_infos,
    xref_info_lists,
    xref_infos,
    xref_types,
)


# ---------------------------------------------------------------------------
# Primitive strategy validation
# ---------------------------------------------------------------------------


class TestPrimitiveStrategies:
    """Verify primitive strategies produce well-formed values."""

    @settings(max_examples=50)
    @given(ea=ea_strings)
    def test_ea_strings_are_hex(self, ea: str) -> None:
        assert ea.startswith("0x")
        int(ea, 16)  # must parse

    @settings(max_examples=50)
    @given(name=function_names)
    def test_function_names_are_identifiers(self, name: str) -> None:
        assert name.isidentifier()

    @settings(max_examples=50)
    @given(t=type_definitions)
    def test_type_definitions_non_empty(self, t: str) -> None:
        assert len(t) > 0

    @settings(max_examples=50)
    @given(pat=byte_patterns)
    def test_byte_patterns_format(self, pat: str) -> None:
        parts = pat.split()
        assert len(parts) >= 1
        for p in parts:
            assert p == "??" or (len(p) == 2 and all(c in "0123456789abcdef" for c in p))

    @settings(max_examples=50)
    @given(c=comment_strings)
    def test_comment_strings_non_empty(self, c: str) -> None:
        assert len(c.strip()) > 0

    @settings(max_examples=50)
    @given(name=enum_names)
    def test_enum_names_uppercase_ident(self, name: str) -> None:
        assert name[0].isupper()

    @settings(max_examples=50)
    @given(name=enum_member_names)
    def test_enum_member_names_uppercase(self, name: str) -> None:
        assert name[0].isupper()

    @settings(max_examples=50)
    @given(fp=file_paths)
    def test_file_paths_non_empty(self, fp: str) -> None:
        assert len(fp) > 0

    @settings(max_examples=50)
    @given(fp=filter_patterns)
    def test_filter_patterns_non_empty(self, fp: str) -> None:
        assert len(fp) > 0

    @settings(max_examples=50)
    @given(xt=xref_types)
    def test_xref_types_valid(self, xt: str) -> None:
        assert xt in {"code_call", "code_jump", "data_read", "data_write", "data_offset"}

    @settings(max_examples=50)
    @given(lib=library_names)
    def test_library_names_have_extension(self, lib: str) -> None:
        assert lib.endswith((".so", ".dll", ".dylib"))

    @settings(max_examples=50)
    @given(cc=calling_conventions)
    def test_calling_conventions_non_empty(self, cc: str) -> None:
        assert len(cc) > 0


# ---------------------------------------------------------------------------
# Composite strategy validation
# ---------------------------------------------------------------------------


class TestCompositeStrategies:
    """Verify composite strategies produce valid model instances."""

    @settings(max_examples=50)
    @given(fi=function_infos())
    def test_function_info_consistency(self, fi: FunctionInfo) -> None:
        assert isinstance(fi, FunctionInfo)
        start = int(fi.ea, 16)
        end = int(fi.end_ea, 16)
        assert fi.size == end - start
        assert fi.size > 0

    @settings(max_examples=50)
    @given(fd=function_details_st())
    def test_function_details_consistency(self, fd: FunctionDetails) -> None:
        assert isinstance(fd, FunctionDetails)
        assert isinstance(fd, FunctionInfo)
        start = int(fd.ea, 16)
        end = int(fd.end_ea, 16)
        assert fd.size == end - start
        assert fd.num_blocks >= 1
        assert fd.frame_size >= 0

    @settings(max_examples=50)
    @given(xi=xref_infos())
    def test_xref_info_fields(self, xi: XrefInfo) -> None:
        assert isinstance(xi, XrefInfo)
        assert xi.xref_type in {"code_call", "code_jump", "data_read", "data_write", "data_offset"}
        int(xi.source_ea, 16)
        int(xi.target_ea, 16)

    @settings(max_examples=50)
    @given(si=segment_infos())
    def test_segment_info_consistency(self, si: SegmentInfo) -> None:
        assert isinstance(si, SegmentInfo)
        start = int(si.start_ea, 16)
        end = int(si.end_ea, 16)
        assert si.size == end - start
        assert si.name.startswith(".")

    @settings(max_examples=50)
    @given(ii=import_infos())
    def test_import_info_fields(self, ii: ImportInfo) -> None:
        assert isinstance(ii, ImportInfo)
        assert len(ii.library) > 0
        assert len(ii.name) > 0
        int(ii.ea, 16)

    @settings(max_examples=50)
    @given(ei=export_infos())
    def test_export_info_fields(self, ei: ExportInfo) -> None:
        assert isinstance(ei, ExportInfo)
        assert len(ei.name) > 0
        int(ei.ea, 16)

    @settings(max_examples=50)
    @given(si=string_infos())
    def test_string_info_fields(self, si: StringInfo) -> None:
        assert isinstance(si, StringInfo)
        assert si.length == len(si.value)
        assert si.length > 0

    @settings(max_examples=50)
    @given(ti=type_infos())
    def test_type_info_fields(self, ti: TypeInfo) -> None:
        assert isinstance(ti, TypeInfo)
        assert ti.size > 0
        assert ti.name in ti.definition

    @settings(max_examples=50)
    @given(fd=field_defs())
    def test_field_def_fields(self, fd: FieldDef) -> None:
        assert isinstance(fd, FieldDef)
        assert fd.offset >= 0

    @settings(max_examples=50)
    @given(ci=comment_infos())
    def test_comment_info_fields(self, ci: CommentInfo) -> None:
        assert isinstance(ci, CommentInfo)
        int(ci.ea, 16)

    @settings(max_examples=50)
    @given(pi=patch_infos())
    def test_patch_info_fields(self, pi: PatchInfo) -> None:
        assert isinstance(pi, PatchInfo)
        assert len(pi.original_byte) == 2
        assert len(pi.patched_byte) == 2
        int(pi.original_byte, 16)
        int(pi.patched_byte, 16)

    @settings(max_examples=50)
    @given(bi=bookmark_infos())
    def test_bookmark_info_fields(self, bi: BookmarkInfo) -> None:
        assert isinstance(bi, BookmarkInfo)
        int(bi.ea, 16)
        assert len(bi.description.strip()) > 0

    @settings(max_examples=50)
    @given(em=enum_members())
    def test_enum_member_fields(self, em: EnumMember) -> None:
        assert isinstance(em, EnumMember)
        assert em.value >= 0

    @settings(max_examples=50)
    @given(ei=enum_infos())
    def test_enum_info_fields(self, ei: EnumInfo) -> None:
        assert isinstance(ei, EnumInfo)
        assert ei.width in {1, 2, 4, 8}

    @settings(max_examples=50)
    @given(ii=instruction_infos())
    def test_instruction_info_fields(self, ii: InstructionInfo) -> None:
        assert isinstance(ii, InstructionInfo)
        assert len(ii.mnemonic) > 0
        int(ii.ea, 16)


# ---------------------------------------------------------------------------
# List strategy validation
# ---------------------------------------------------------------------------


class TestListStrategies:
    """Verify list strategies produce lists of correct types."""

    @settings(max_examples=20)
    @given(fns=function_info_lists)
    def test_function_info_list(self, fns: list) -> None:
        assert isinstance(fns, list)
        for f in fns:
            assert isinstance(f, FunctionInfo)

    @settings(max_examples=20)
    @given(xrefs=xref_info_lists)
    def test_xref_info_list(self, xrefs: list) -> None:
        assert isinstance(xrefs, list)
        for x in xrefs:
            assert isinstance(x, XrefInfo)

    @settings(max_examples=20)
    @given(segs=segment_info_lists)
    def test_segment_info_list(self, segs: list) -> None:
        assert isinstance(segs, list)
        for s in segs:
            assert isinstance(s, SegmentInfo)

    @settings(max_examples=20)
    @given(imps=import_info_lists)
    def test_import_info_list(self, imps: list) -> None:
        assert isinstance(imps, list)
        for i in imps:
            assert isinstance(i, ImportInfo)

    @settings(max_examples=20)
    @given(exps=export_info_lists)
    def test_export_info_list(self, exps: list) -> None:
        assert isinstance(exps, list)
        for e in exps:
            assert isinstance(e, ExportInfo)

    @settings(max_examples=20)
    @given(strs=string_info_lists)
    def test_string_info_list(self, strs: list) -> None:
        assert isinstance(strs, list)
        for s in strs:
            assert isinstance(s, StringInfo)


# ---------------------------------------------------------------------------
# Call graph tree validation
# ---------------------------------------------------------------------------


class TestCallGraphStrategy:
    """Verify call graph tree strategy produces valid trees."""

    @settings(max_examples=30)
    @given(node=call_graph_nodes())
    def test_call_graph_node_structure(self, node: CallGraphNode) -> None:
        assert isinstance(node, CallGraphNode)
        int(node.ea, 16)
        assert len(node.name) > 0
        self._verify_tree(node, max_depth=4)

    def _verify_tree(self, node: CallGraphNode, max_depth: int) -> None:
        """Recursively verify tree structure."""
        assert isinstance(node.children, list)
        if max_depth <= 0:
            return
        for child in node.children:
            assert isinstance(child, CallGraphNode)
            self._verify_tree(child, max_depth - 1)
