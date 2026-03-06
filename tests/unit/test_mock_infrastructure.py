"""Unit tests for the mock test infrastructure in conftest.py.

Validates that MockIdaBridge, MockSession, and MockSessionManager
behave correctly and can support the property tests (Properties 1-30).
"""

from __future__ import annotations

import pytest

from tests.conftest import (
    MockIdaBridge,
    MockSession,
    MockSessionManager,
    ScriptResult,
    SessionState,
)
from ida_headless_mcp.models import (
    EnumMember,
    FieldDef,
    FunctionDetails,
    FunctionInfo,
    OperationResult,
)


# -----------------------------------------------------------------------
# MockIdaBridge — Functions
# -----------------------------------------------------------------------

class TestMockBridgeFunctions:
    def test_add_and_list(self, mock_bridge: MockIdaBridge):
        mock_bridge.add_function(0x1000, "main", 64)
        funcs = mock_bridge.list_functions()
        assert len(funcs) == 1
        assert funcs[0].name == "main"
        assert funcs[0].size == 64

    def test_filter_functions(self, mock_bridge: MockIdaBridge):
        mock_bridge.add_function(0x1000, "main", 64)
        mock_bridge.add_function(0x2000, "sub_2000", 32)
        assert len(mock_bridge.list_functions("main")) == 1
        assert len(mock_bridge.list_functions("sub_*")) == 1
        assert len(mock_bridge.list_functions("*")) == 2

    def test_rename_function(self, mock_bridge: MockIdaBridge):
        mock_bridge.add_function(0x1000, "old_name", 64)
        result = mock_bridge.rename_function(0x1000, "new_name")
        assert result.success
        assert mock_bridge.get_function_details(0x1000).name == "new_name"

    def test_rename_nonexistent(self, mock_bridge: MockIdaBridge):
        result = mock_bridge.rename_function(0xDEAD, "name")
        assert not result.success

    def test_create_and_delete(self, mock_bridge: MockIdaBridge):
        result = mock_bridge.create_function(0x5000)
        assert result.success
        assert mock_bridge.get_function_details(0x5000) is not None
        result = mock_bridge.delete_function(0x5000)
        assert result.success
        assert mock_bridge.get_function_details(0x5000) is None

    def test_function_details_fields(self, mock_bridge: MockIdaBridge):
        mock_bridge.add_function(0x1000, "f", 128, num_blocks=3, calling_convention="fastcall", frame_size=32)
        d = mock_bridge.get_function_details(0x1000)
        assert d.num_blocks == 3
        assert d.calling_convention == "fastcall"
        assert d.frame_size == 32
        assert d.size == 128


# -----------------------------------------------------------------------
# MockIdaBridge — Types
# -----------------------------------------------------------------------

class TestMockBridgeTypes:
    def test_create_and_list(self, mock_bridge: MockIdaBridge):
        fields = [FieldDef(name="x", type_str="int", offset=0)]
        result = mock_bridge.create_struct("my_struct", fields)
        assert result.success
        types = mock_bridge.list_types()
        assert len(types) == 1
        assert types[0].name == "my_struct"

    def test_duplicate_type_fails(self, mock_bridge: MockIdaBridge):
        mock_bridge.create_struct("s", [])
        result = mock_bridge.create_struct("s", [])
        assert not result.success

    def test_add_field(self, mock_bridge: MockIdaBridge):
        mock_bridge.create_struct("s", [FieldDef(name="a", type_str="int", offset=0)])
        result = mock_bridge.add_struct_field("s", FieldDef(name="b", type_str="char", offset=4))
        assert result.success
        assert mock_bridge.types["s"]["info"].size == 5  # 4 + 1

    def test_delete_type(self, mock_bridge: MockIdaBridge):
        mock_bridge.create_struct("s", [])
        result = mock_bridge.delete_type("s")
        assert result.success
        assert len(mock_bridge.list_types()) == 0

    def test_apply_type(self, mock_bridge: MockIdaBridge):
        result = mock_bridge.apply_type(0x1000, "int")
        assert result.success
        dt = mock_bridge.get_data_type(0x1000)
        assert dt.type_name == "int"


# -----------------------------------------------------------------------
# MockIdaBridge — Comments
# -----------------------------------------------------------------------

class TestMockBridgeComments:
    def test_set_and_get_regular(self, mock_bridge: MockIdaBridge):
        mock_bridge.set_comment(0x1000, "hello", "regular")
        ci = mock_bridge.get_comments(0x1000)
        assert ci.regular == "hello"
        assert ci.repeatable is None

    def test_set_and_get_repeatable(self, mock_bridge: MockIdaBridge):
        mock_bridge.set_comment(0x1000, "rep", "repeatable")
        ci = mock_bridge.get_comments(0x1000)
        assert ci.repeatable == "rep"

    def test_set_and_get_function_comment(self, mock_bridge: MockIdaBridge):
        mock_bridge.set_comment(0x1000, "fn comment", "function")
        ci = mock_bridge.get_comments(0x1000)
        assert ci.function_comment == "fn comment"

    def test_range_query(self, mock_bridge: MockIdaBridge):
        mock_bridge.set_comment(0x1000, "a", "regular")
        mock_bridge.set_comment(0x2000, "b", "regular")
        mock_bridge.set_comment(0x3000, "c", "regular")
        result = mock_bridge.get_comments_range(0x1000, 0x2500)
        assert len(result) == 2


# -----------------------------------------------------------------------
# MockIdaBridge — Patching
# -----------------------------------------------------------------------

class TestMockBridgePatching:
    def test_patch_and_read(self, mock_bridge: MockIdaBridge):
        mock_bridge.patch_bytes(0x1000, "deadbeef")
        result = mock_bridge.read_bytes(0x1000, 4)
        assert result == "deadbeef"

    def test_list_patches(self, mock_bridge: MockIdaBridge):
        mock_bridge.patch_bytes(0x1000, "cc")
        patches = mock_bridge.list_patches()
        assert len(patches) == 1
        assert patches[0].patched_byte == "cc"


# -----------------------------------------------------------------------
# MockIdaBridge — Strings
# -----------------------------------------------------------------------

class TestMockBridgeStrings:
    def test_add_and_list(self, mock_bridge: MockIdaBridge):
        mock_bridge.add_string(0x5000, "Hello", "ascii")
        result = mock_bridge.list_strings()
        assert result.total_count == 1
        assert result.strings[0].value == "Hello"

    def test_filter_strings(self, mock_bridge: MockIdaBridge):
        mock_bridge.add_string(0x5000, "Hello", "ascii")
        mock_bridge.add_string(0x5100, "World", "ascii")
        result = mock_bridge.list_strings(filter_pattern="Hel*")
        assert result.total_count == 1

    def test_pagination(self, mock_bridge: MockIdaBridge):
        for i in range(10):
            mock_bridge.add_string(0x5000 + i * 0x100, f"str_{i}", "ascii")
        page1 = mock_bridge.list_strings(offset=0, limit=3)
        page2 = mock_bridge.list_strings(offset=3, limit=3)
        assert len(page1.strings) == 3
        assert len(page2.strings) == 3
        assert page1.total_count == 10


# -----------------------------------------------------------------------
# MockIdaBridge — Segments
# -----------------------------------------------------------------------

class TestMockBridgeSegments:
    def test_add_and_list(self, mock_bridge: MockIdaBridge):
        mock_bridge.add_segment(".text", 0x1000, 0x1000)
        segs = mock_bridge.list_segments()
        assert len(segs) == 1
        assert segs[0].name == ".text"

    def test_get_by_name(self, mock_bridge: MockIdaBridge):
        mock_bridge.add_segment(".text", 0x1000, 0x1000)
        seg = mock_bridge.get_segment(".text")
        assert seg is not None
        assert seg.name == ".text"

    def test_get_segment_at(self, mock_bridge: MockIdaBridge):
        mock_bridge.add_segment(".text", 0x1000, 0x1000)
        seg = mock_bridge.get_segment_at(0x1500)
        assert seg is not None
        assert seg.name == ".text"

    def test_get_segment_at_outside(self, mock_bridge: MockIdaBridge):
        mock_bridge.add_segment(".text", 0x1000, 0x1000)
        seg = mock_bridge.get_segment_at(0x3000)
        assert seg is None


# -----------------------------------------------------------------------
# MockIdaBridge — Bookmarks
# -----------------------------------------------------------------------

class TestMockBridgeBookmarks:
    def test_add_list_delete(self, mock_bridge: MockIdaBridge):
        mock_bridge.add_bookmark(0x1000, "entry")
        bmarks = mock_bridge.list_bookmarks()
        assert len(bmarks) == 1
        assert bmarks[0].description == "entry"
        mock_bridge.delete_bookmark(0x1000)
        assert len(mock_bridge.list_bookmarks()) == 0


# -----------------------------------------------------------------------
# MockIdaBridge — Enums
# -----------------------------------------------------------------------

class TestMockBridgeEnums:
    def test_create_and_list(self, mock_bridge: MockIdaBridge):
        members = [EnumMember(name="A", value=0), EnumMember(name="B", value=1)]
        mock_bridge.create_enum("MyEnum", members)
        enums = mock_bridge.list_enums()
        assert len(enums) == 1
        assert enums[0].member_count == 2

    def test_add_member(self, mock_bridge: MockIdaBridge):
        mock_bridge.create_enum("E", [])
        mock_bridge.add_enum_member("E", "X", 42)
        assert mock_bridge.enums["E"]["info"].member_count == 1


# -----------------------------------------------------------------------
# MockIdaBridge — Names / Data types
# -----------------------------------------------------------------------

class TestMockBridgeNames:
    def test_rename_location(self, mock_bridge: MockIdaBridge):
        mock_bridge.rename_location(0x1000, "my_var")
        names = mock_bridge.list_names()
        assert any(n.name == "my_var" for n in names)

    def test_set_and_get_data_type(self, mock_bridge: MockIdaBridge):
        mock_bridge.set_data_type(0x1000, "dword")
        dt = mock_bridge.get_data_type(0x1000)
        assert dt.type_name == "dword"

    def test_default_data_type(self, mock_bridge: MockIdaBridge):
        dt = mock_bridge.get_data_type(0xFFFF)
        assert dt.type_name == "byte"


# -----------------------------------------------------------------------
# MockIdaBridge — Call graph
# -----------------------------------------------------------------------

class TestMockBridgeCallGraph:
    def test_callers_and_callees(self, mock_bridge: MockIdaBridge):
        mock_bridge.add_function(0x1000, "main", 64)
        mock_bridge.add_function(0x2000, "helper", 32)
        mock_bridge.add_xref(0x1000, 0x2000)
        callers = mock_bridge.get_callers(0x2000)
        callees = mock_bridge.get_callees(0x1000)
        assert len(callers) == 1
        assert callers[0].name == "main"
        assert len(callees) == 1
        assert callees[0].name == "helper"

    def test_call_graph_depth(self, mock_bridge: MockIdaBridge):
        mock_bridge.add_function(0x1000, "a", 16)
        mock_bridge.add_function(0x2000, "b", 16)
        mock_bridge.add_function(0x3000, "c", 16)
        mock_bridge.add_xref(0x1000, 0x2000)
        mock_bridge.add_xref(0x2000, 0x3000)
        graph = mock_bridge.get_call_graph(0x1000, depth=1)
        assert graph.name == "a"
        assert len(graph.children) == 1
        assert graph.children[0].name == "b"
        # depth=1 means children of root only, no grandchildren
        assert len(graph.children[0].children) == 0

    def test_call_graph_full_depth(self, mock_bridge: MockIdaBridge):
        mock_bridge.add_function(0x1000, "a", 16)
        mock_bridge.add_function(0x2000, "b", 16)
        mock_bridge.add_function(0x3000, "c", 16)
        mock_bridge.add_xref(0x1000, 0x2000)
        mock_bridge.add_xref(0x2000, 0x3000)
        graph = mock_bridge.get_call_graph(0x1000, depth=3)
        assert len(graph.children) == 1
        assert len(graph.children[0].children) == 1
        assert graph.children[0].children[0].name == "c"


# -----------------------------------------------------------------------
# MockIdaBridge — Scripting
# -----------------------------------------------------------------------

class TestMockBridgeScripting:
    def test_execute_print(self, mock_bridge: MockIdaBridge):
        result = mock_bridge.execute_script('print("hello")')
        assert result.success
        assert "hello" in result.stdout

    def test_execute_raise(self, mock_bridge: MockIdaBridge):
        result = mock_bridge.execute_script('raise RuntimeError("boom")')
        assert not result.success
        assert result.data["exception"]["type"] == "RuntimeError"

    def test_build_script(self, mock_bridge: MockIdaBridge):
        script = mock_bridge.build_script("list_functions", {"filter": "*"})
        assert "list_functions" in script


# -----------------------------------------------------------------------
# MockIdaBridge — Search
# -----------------------------------------------------------------------

class TestMockBridgeSearch:
    def test_search_bytes(self, mock_bridge: MockIdaBridge):
        mock_bridge.memory[0x1000] = 0xDE
        mock_bridge.memory[0x1001] = 0xAD
        results = mock_bridge.search_bytes("de ad", start_ea=0x1000, end_ea=0x1002)
        assert len(results) == 1
        assert results[0] == "0x1000"

    def test_search_bytes_wildcard(self, mock_bridge: MockIdaBridge):
        mock_bridge.memory[0x1000] = 0xDE
        mock_bridge.memory[0x1001] = 0xAD
        results = mock_bridge.search_bytes("de ??", start_ea=0x1000, end_ea=0x1002)
        assert len(results) == 1

    def test_search_text(self, mock_bridge: MockIdaBridge):
        mock_bridge.add_string(0x5000, "Hello World", "ascii")
        results = mock_bridge.search_text("Hello")
        assert len(results) == 1

    def test_search_max_results(self, mock_bridge: MockIdaBridge):
        for i in range(10):
            mock_bridge.memory[0x1000 + i] = 0x90
        results = mock_bridge.search_bytes("90", start_ea=0x1000, end_ea=0x100A, max_results=3)
        assert len(results) == 3


# -----------------------------------------------------------------------
# MockIdaBridge — Signatures
# -----------------------------------------------------------------------

class TestMockBridgeSignatures:
    def test_apply_and_list(self, mock_bridge: MockIdaBridge):
        mock_bridge.available_signatures = ["libc.sig"]
        result = mock_bridge.apply_signature("libc.sig")
        assert result.sig_file == "libc.sig"
        assert "libc.sig" in mock_bridge.list_applied_signatures()


# -----------------------------------------------------------------------
# MockSession
# -----------------------------------------------------------------------

class TestMockSession:
    def test_initial_state(self, mock_session: MockSession):
        assert mock_session.state == SessionState.READY
        assert mock_session.architecture == "64"
        assert mock_session.process is None

    def test_session_info(self, mock_session: MockSession):
        info = mock_session.to_session_info()
        assert info.session_id == mock_session.session_id
        assert info.state == "ready"

    def test_32bit_session(self, mock_session_32: MockSession):
        assert mock_session_32.architecture == "32"
        assert mock_session_32.idb_path.endswith(".idb")

    def test_64bit_idb_path(self, mock_session: MockSession):
        assert mock_session.idb_path.endswith(".i64")

    def test_has_own_bridge(self, mock_session: MockSession):
        assert isinstance(mock_session.bridge, MockIdaBridge)


# -----------------------------------------------------------------------
# MockSessionManager
# -----------------------------------------------------------------------

class TestMockSessionManager:
    @pytest.mark.asyncio
    async def test_create_session(self, mock_session_manager: MockSessionManager):
        session = await mock_session_manager.create_session("/bin/ls")
        assert session.state == SessionState.READY
        assert len(mock_session_manager.list_sessions()) == 1

    @pytest.mark.asyncio
    async def test_close_session(self, mock_session_manager: MockSessionManager):
        session = await mock_session_manager.create_session("/bin/ls")
        await mock_session_manager.close_session(session.session_id)
        assert len(mock_session_manager.list_sessions()) == 0

    @pytest.mark.asyncio
    async def test_close_nonexistent_raises(self, mock_session_manager: MockSessionManager):
        with pytest.raises(KeyError):
            await mock_session_manager.close_session("nonexistent")

    @pytest.mark.asyncio
    async def test_close_all(self, mock_session_manager: MockSessionManager):
        await mock_session_manager.create_session("/bin/a")
        await mock_session_manager.create_session("/bin/b")
        assert len(mock_session_manager.list_sessions()) == 2
        await mock_session_manager.close_all_sessions()
        assert len(mock_session_manager.list_sessions()) == 0

    @pytest.mark.asyncio
    async def test_execute_script(self, mock_session_manager: MockSessionManager):
        session = await mock_session_manager.create_session("/bin/ls")
        result = await mock_session_manager.execute_script(session.session_id, 'print("hi")')
        assert result.success
        assert "hi" in result.stdout

    @pytest.mark.asyncio
    async def test_get_session(self, mock_session_manager: MockSessionManager):
        session = await mock_session_manager.create_session("/bin/ls")
        found = mock_session_manager.get_session(session.session_id)
        assert found.session_id == session.session_id

    @pytest.mark.asyncio
    async def test_get_nonexistent_raises(self, mock_session_manager: MockSessionManager):
        with pytest.raises(KeyError):
            mock_session_manager.get_session("nope")

    @pytest.mark.asyncio
    async def test_unique_session_ids(self, mock_session_manager: MockSessionManager):
        s1 = await mock_session_manager.create_session("/bin/a")
        s2 = await mock_session_manager.create_session("/bin/b")
        assert s1.session_id != s2.session_id

    @pytest.mark.asyncio
    async def test_architecture_detection(self, mock_session_manager: MockSessionManager):
        s64 = await mock_session_manager.create_session("/bin/ls64")
        s32 = await mock_session_manager.create_session("/bin/ls32")
        assert s64.architecture == "64"
        assert s32.architecture == "32"


# -----------------------------------------------------------------------
# Populated fixtures
# -----------------------------------------------------------------------

class TestPopulatedBridge:
    def test_has_functions(self, populated_bridge: MockIdaBridge):
        funcs = populated_bridge.list_functions()
        assert len(funcs) == 3

    def test_has_segments(self, populated_bridge: MockIdaBridge):
        segs = populated_bridge.list_segments()
        assert len(segs) == 2

    def test_has_strings(self, populated_bridge: MockIdaBridge):
        result = populated_bridge.list_strings()
        assert result.total_count == 3

    def test_has_imports(self, populated_bridge: MockIdaBridge):
        imps = populated_bridge.list_imports()
        assert len(imps) == 2

    def test_has_exports(self, populated_bridge: MockIdaBridge):
        exps = populated_bridge.list_exports()
        assert len(exps) == 1

    def test_has_types(self, populated_bridge: MockIdaBridge):
        types = populated_bridge.list_types()
        assert len(types) == 1

    def test_has_bookmarks(self, populated_bridge: MockIdaBridge):
        bmarks = populated_bridge.list_bookmarks()
        assert len(bmarks) == 1

    def test_has_enums(self, populated_bridge: MockIdaBridge):
        enums = populated_bridge.list_enums()
        assert len(enums) == 1

    def test_has_call_graph(self, populated_bridge: MockIdaBridge):
        callees = populated_bridge.get_callees(0x401000)
        assert len(callees) == 2  # main -> helper, main -> sub_1000

    def test_decompile(self, populated_bridge: MockIdaBridge):
        result = populated_bridge.decompile_function(0x401000)
        assert result is not None
        assert "main" in result.pseudocode

    def test_decompile_with_hints(self, populated_bridge: MockIdaBridge):
        result = populated_bridge.decompile_function(0x401000, var_hints={"argc": "num_args"})
        assert "num_args" in result.pseudocode

    def test_has_signatures(self, populated_bridge: MockIdaBridge):
        avail = populated_bridge.list_available_signatures()
        assert len(avail) == 3
