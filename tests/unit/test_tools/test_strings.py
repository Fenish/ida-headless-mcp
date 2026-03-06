"""Unit tests for string tool handlers.

Tests the tool handler functions in ``ida_headless_mcp.tools.strings``
using a mock session manager that returns pre-configured ScriptResult data.
"""

from __future__ import annotations

import pytest

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.ida_bridge import ScriptResult
from ida_headless_mcp.models import StringInfo, StringResults, XrefInfo
from ida_headless_mcp.tools.strings import get_string_xrefs, list_strings


# ---------------------------------------------------------------------------
# Helpers — lightweight mock session manager and bridge for tool tests
# ---------------------------------------------------------------------------


class FakeBridge:
    """A bridge that records build_script calls and returns a fixed script."""

    def __init__(self) -> None:
        self.last_operation: str | None = None
        self.last_params: dict | None = None

    def build_script(self, operation: str, params: dict, result_path: str = "") -> str:
        self.last_operation = operation
        self.last_params = params
        return f"__script__:{operation}"


class FakeSessionManager:
    """A session manager that returns pre-configured ScriptResult values."""

    def __init__(self, result: ScriptResult) -> None:
        self._result = result
        self.last_session_id: str | None = None
        self.last_script: str | None = None

    async def execute_script(self, session_id: str, script: str) -> ScriptResult:
        self.last_session_id = session_id
        self.last_script = script
        return self._result


# ---------------------------------------------------------------------------
# list_strings
# ---------------------------------------------------------------------------


class TestListStrings:
    """Tests for list_strings tool handler."""

    @pytest.mark.asyncio
    async def test_returns_all_strings(self):
        result = ScriptResult(
            success=True,
            data={
                "strings": [
                    {"ea": "0x500000", "value": "Hello", "length": 5, "string_type": "ascii"},
                    {"ea": "0x500010", "value": "World", "length": 5, "string_type": "ascii"},
                    {"ea": "0x500020", "value": "Foo", "length": 3, "string_type": "utf8"},
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        res = await list_strings(sm, bridge, "sess1")

        assert isinstance(res, StringResults)
        assert res.total_count == 3
        assert len(res.strings) == 3
        assert res.offset == 0
        assert res.limit == 100
        assert isinstance(res.strings[0], StringInfo)
        assert res.strings[0].ea == "0x500000"
        assert res.strings[0].value == "Hello"
        assert res.strings[0].length == 5
        assert res.strings[0].string_type == "ascii"

    @pytest.mark.asyncio
    async def test_filter_pattern_applied(self):
        result = ScriptResult(
            success=True,
            data={
                "strings": [
                    {"ea": "0x500000", "value": "Hello World", "length": 11, "string_type": "ascii"},
                    {"ea": "0x500010", "value": "Goodbye", "length": 7, "string_type": "ascii"},
                    {"ea": "0x500020", "value": "Hello There", "length": 11, "string_type": "ascii"},
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        res = await list_strings(sm, bridge, "sess1", filter_pattern="Hello*")

        assert res.total_count == 2
        assert len(res.strings) == 2
        assert all(s.value.startswith("Hello") for s in res.strings)

    @pytest.mark.asyncio
    async def test_filter_pattern_passed_to_bridge(self):
        result = ScriptResult(
            success=True,
            data={"strings": []},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_strings(sm, bridge, "sess1", filter_pattern="test*")

        assert bridge.last_params["filter_pattern"] == "test*"

    @pytest.mark.asyncio
    async def test_pagination_offset_and_limit(self):
        strings_data = [
            {"ea": f"0x50000{i}", "value": f"str_{i}", "length": 5, "string_type": "ascii"}
            for i in range(10)
        ]
        result = ScriptResult(success=True, data={"strings": strings_data})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        res = await list_strings(sm, bridge, "sess1", offset=3, limit=4)

        assert res.total_count == 10
        assert res.offset == 3
        assert res.limit == 4
        assert len(res.strings) == 4
        assert res.strings[0].value == "str_3"
        assert res.strings[3].value == "str_6"

    @pytest.mark.asyncio
    async def test_pagination_beyond_end(self):
        strings_data = [
            {"ea": f"0x50000{i}", "value": f"str_{i}", "length": 5, "string_type": "ascii"}
            for i in range(3)
        ]
        result = ScriptResult(success=True, data={"strings": strings_data})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        res = await list_strings(sm, bridge, "sess1", offset=10, limit=5)

        assert res.total_count == 3
        assert len(res.strings) == 0

    @pytest.mark.asyncio
    async def test_empty_string_list(self):
        result = ScriptResult(success=True, data={"strings": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        res = await list_strings(sm, bridge, "sess1")

        assert res.total_count == 0
        assert res.strings == []

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(success=False, data={"error": {"message": "IDA error"}})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await list_strings(sm, bridge, "sess1")
        assert exc_info.value.code == ErrorCode.FUNCTION_NOT_FOUND
        assert exc_info.value.tool_name == "list_strings"

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data={"strings": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_strings(sm, bridge, "my_session_42")
        assert sm.last_session_id == "my_session_42"

    @pytest.mark.asyncio
    async def test_filter_none_not_in_params(self):
        result = ScriptResult(success=True, data={"strings": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_strings(sm, bridge, "sess1", filter_pattern=None)
        assert "filter_pattern" not in bridge.last_params


# ---------------------------------------------------------------------------
# get_string_xrefs
# ---------------------------------------------------------------------------


class TestGetStringXrefs:
    """Tests for get_string_xrefs tool handler."""

    @pytest.mark.asyncio
    async def test_returns_xrefs(self):
        result = ScriptResult(
            success=True,
            data={
                "xrefs": [
                    {
                        "source_ea": "0x401000",
                        "target_ea": "0x500000",
                        "xref_type": "data_read",
                        "source_function": "main",
                        "target_function": None,
                    },
                    {
                        "source_ea": "0x401050",
                        "target_ea": "0x500000",
                        "xref_type": "data_offset",
                        "source_function": "init",
                        "target_function": None,
                    },
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        xrefs = await get_string_xrefs(sm, bridge, "sess1", "0x500000")

        assert len(xrefs) == 2
        assert isinstance(xrefs[0], XrefInfo)
        assert xrefs[0].source_ea == "0x401000"
        assert xrefs[0].target_ea == "0x500000"
        assert xrefs[0].xref_type == "data_read"
        assert xrefs[0].source_function == "main"
        assert xrefs[1].xref_type == "data_offset"

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_string_xrefs(sm, bridge, "sess1", "not_an_address")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "get_string_xrefs"

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "String not found"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_string_xrefs(sm, bridge, "sess1", "0x500000")
        assert exc_info.value.code == ErrorCode.FUNCTION_NOT_FOUND
        assert exc_info.value.tool_name == "get_string_xrefs"

    @pytest.mark.asyncio
    async def test_empty_xrefs(self):
        result = ScriptResult(success=True, data={"xrefs": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        xrefs = await get_string_xrefs(sm, bridge, "sess1", "0x500000")
        assert xrefs == []

    @pytest.mark.asyncio
    async def test_ea_passed_as_int_to_bridge(self):
        result = ScriptResult(success=True, data={"xrefs": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_string_xrefs(sm, bridge, "sess1", "0x500000")
        assert bridge.last_operation == "get_string_xrefs"
        assert bridge.last_params == {"ea": 0x500000}

    @pytest.mark.asyncio
    async def test_decimal_ea_accepted(self):
        result = ScriptResult(success=True, data={"xrefs": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_string_xrefs(sm, bridge, "sess1", "5242880")
        assert bridge.last_params == {"ea": 5242880}

    @pytest.mark.asyncio
    async def test_optional_function_fields_none(self):
        result = ScriptResult(
            success=True,
            data={
                "xrefs": [
                    {
                        "source_ea": "0x401000",
                        "target_ea": "0x500000",
                        "xref_type": "data_read",
                    },
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        xrefs = await get_string_xrefs(sm, bridge, "sess1", "0x500000")
        assert xrefs[0].source_function is None
        assert xrefs[0].target_function is None

    @pytest.mark.asyncio
    async def test_script_failure_empty_data(self):
        result = ScriptResult(success=False, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_string_xrefs(sm, bridge, "sess1", "0x500000")
        assert exc_info.value.code == ErrorCode.FUNCTION_NOT_FOUND
