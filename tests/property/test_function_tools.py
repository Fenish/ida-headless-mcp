"""Property-based tests for function tool handlers.

Properties 4–7 from the IDA Headless MCP design document.
"""

from __future__ import annotations

import fnmatch

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from ida_headless_mcp.ida_bridge import ScriptResult
from ida_headless_mcp.models import FunctionDetails, FunctionInfo
from ida_headless_mcp.tools.functions import list_functions
from tests.conftest import MockIdaBridge, MockSessionManager
from tests.strategies import (
    filter_patterns,
    function_details_st,
    function_info_lists,
    function_names,
    ea_strings,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeBridge:
    """Minimal bridge that records build_script calls."""

    def build_script(self, operation: str, params: dict, result_path: str = "") -> str:
        return f"__script__:{operation}"


class _FakeSessionManager:
    """Session manager returning a pre-configured ScriptResult."""

    def __init__(self, result: ScriptResult) -> None:
        self._result = result

    async def execute_script(self, session_id: str, script: str) -> ScriptResult:
        return self._result


# ===================================================================
# Property 4: Function filter correctness
# ===================================================================


class TestFunctionFilterCorrectness:
    """Property 4: Function filter correctness.

    *For any* function list and filter pattern, every function in the
    filtered result must have a name matching the pattern, and no function
    matching the pattern should be excluded from the result.

    **Validates: Requirements 4.2**
    """

    @settings(max_examples=100)
    @given(funcs=function_info_lists, pattern=filter_patterns)
    @pytest.mark.asyncio
    async def test_filter_includes_only_matching(
        self, funcs: list[FunctionInfo], pattern: str
    ) -> None:
        # Feature: ida-headless-mcp, Property 4: Function filter correctness
        raw = [
            {"ea": f.ea, "name": f.name, "end_ea": f.end_ea, "size": f.size}
            for f in funcs
        ]
        result = ScriptResult(success=True, data={"functions": raw})
        sm = _FakeSessionManager(result)
        bridge = _FakeBridge()

        filtered = await list_functions(sm, bridge, "sess1", filter_pattern=pattern)

        # Every returned function must match the pattern
        for f in filtered:
            assert fnmatch.fnmatch(f.name, pattern), (
                f"Function '{f.name}' does not match pattern '{pattern}'"
            )

    @settings(max_examples=100)
    @given(funcs=function_info_lists, pattern=filter_patterns)
    @pytest.mark.asyncio
    async def test_filter_excludes_no_matching(
        self, funcs: list[FunctionInfo], pattern: str
    ) -> None:
        # Feature: ida-headless-mcp, Property 4: Function filter correctness
        raw = [
            {"ea": f.ea, "name": f.name, "end_ea": f.end_ea, "size": f.size}
            for f in funcs
        ]
        result = ScriptResult(success=True, data={"functions": raw})
        sm = _FakeSessionManager(result)
        bridge = _FakeBridge()

        filtered = await list_functions(sm, bridge, "sess1", filter_pattern=pattern)
        filtered_names = {f.name for f in filtered}

        # No function matching the pattern should be missing
        expected_names = {f.name for f in funcs if fnmatch.fnmatch(f.name, pattern)}
        assert filtered_names == expected_names


# ===================================================================
# Property 5: Function details completeness
# ===================================================================


class TestFunctionDetailsCompleteness:
    """Property 5: Function details completeness.

    *For any* function details response, the result must contain all
    required fields and size must equal end_ea - start_ea.

    **Validates: Requirements 4.1, 4.3**
    """

    @settings(max_examples=100)
    @given(details=function_details_st())
    def test_all_required_fields_present(self, details: FunctionDetails) -> None:
        # Feature: ida-headless-mcp, Property 5: Function details completeness
        assert isinstance(details.ea, str) and details.ea.startswith("0x")
        assert isinstance(details.name, str) and len(details.name) > 0
        assert isinstance(details.end_ea, str) and details.end_ea.startswith("0x")
        assert isinstance(details.size, int) and details.size > 0
        assert isinstance(details.num_blocks, int) and details.num_blocks >= 1
        assert isinstance(details.calling_convention, str) and len(details.calling_convention) > 0
        assert isinstance(details.frame_size, int) and details.frame_size >= 0

    @settings(max_examples=100)
    @given(details=function_details_st())
    def test_size_equals_end_minus_start(self, details: FunctionDetails) -> None:
        # Feature: ida-headless-mcp, Property 5: Function details completeness
        start = int(details.ea, 16)
        end = int(details.end_ea, 16)
        assert details.size == end - start


# ===================================================================
# Property 6: Function rename round-trip
# ===================================================================


class TestFunctionRenameRoundTrip:
    """Property 6: Function rename round-trip.

    *For any* existing function and any valid new name, renaming the
    function and then querying its details should return the new name
    at the same EA.

    **Validates: Requirements 4.4**
    """

    @settings(max_examples=100)
    @given(
        ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
        original_name=function_names,
        new_name=function_names,
    )
    def test_rename_persists_in_bridge(
        self, ea: int, original_name: str, new_name: str
    ) -> None:
        # Feature: ida-headless-mcp, Property 6: Function rename round-trip
        bridge = MockIdaBridge()
        bridge.add_function(ea, original_name, 64)

        result = bridge.rename_function(ea, new_name)
        assert result.success

        details = bridge.get_function_details(ea)
        assert details is not None
        assert details.name == new_name
        assert details.ea == f"0x{ea:x}"

    @settings(max_examples=50)
    @given(
        ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
        original_name=function_names,
        new_name=function_names,
    )
    def test_rename_reflected_in_list(
        self, ea: int, original_name: str, new_name: str
    ) -> None:
        # Feature: ida-headless-mcp, Property 6: Function rename round-trip
        bridge = MockIdaBridge()
        bridge.add_function(ea, original_name, 64)

        bridge.rename_function(ea, new_name)

        funcs = bridge.list_functions()
        matching = [f for f in funcs if f.ea == f"0x{ea:x}"]
        assert len(matching) == 1
        assert matching[0].name == new_name


# ===================================================================
# Property 7: Function create/delete round-trip
# ===================================================================


class TestFunctionCreateDeleteRoundTrip:
    """Property 7: Function create/delete round-trip.

    *For any* valid EA where a function can be created, creating a
    function and then listing functions should include it. Subsequently
    deleting that function and listing again should exclude it.

    **Validates: Requirements 4.6, 4.7**
    """

    @settings(max_examples=100)
    @given(ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF))
    def test_create_adds_to_list(self, ea: int) -> None:
        # Feature: ida-headless-mcp, Property 7: Function create/delete round-trip
        bridge = MockIdaBridge()

        result = bridge.create_function(ea)
        assert result.success

        funcs = bridge.list_functions()
        eas = [f.ea for f in funcs]
        assert f"0x{ea:x}" in eas

    @settings(max_examples=100)
    @given(ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF))
    def test_delete_removes_from_list(self, ea: int) -> None:
        # Feature: ida-headless-mcp, Property 7: Function create/delete round-trip
        bridge = MockIdaBridge()

        bridge.create_function(ea)
        result = bridge.delete_function(ea)
        assert result.success

        funcs = bridge.list_functions()
        eas = [f.ea for f in funcs]
        assert f"0x{ea:x}" not in eas

    @settings(max_examples=50)
    @given(ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF))
    def test_create_then_delete_round_trip(self, ea: int) -> None:
        # Feature: ida-headless-mcp, Property 7: Function create/delete round-trip
        bridge = MockIdaBridge()

        # Create
        create_result = bridge.create_function(ea)
        assert create_result.success
        assert len(bridge.list_functions()) == 1

        # Delete
        delete_result = bridge.delete_function(ea)
        assert delete_result.success
        assert len(bridge.list_functions()) == 0

    @settings(max_examples=50)
    @given(ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF))
    def test_delete_nonexistent_fails(self, ea: int) -> None:
        # Feature: ida-headless-mcp, Property 7: Function create/delete round-trip
        bridge = MockIdaBridge()

        result = bridge.delete_function(ea)
        assert not result.success
