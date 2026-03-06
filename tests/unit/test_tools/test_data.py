"""Unit tests for data/names tool handlers.

Tests the tool handler functions in ``ida_headless_mcp.tools.data``
using a fake session manager that returns pre-configured ScriptResult data.
"""

from __future__ import annotations

import pytest

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.ida_bridge import ScriptResult
from ida_headless_mcp.tools.data import (
    get_data_type,
    list_names,
    rename_location,
    set_data_type,
)


# ---------------------------------------------------------------------------
# Helpers — lightweight fakes for tool tests
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
# list_names
# ---------------------------------------------------------------------------


class TestListNames:
    """Tests for list_names tool handler."""

    @pytest.mark.asyncio
    async def test_returns_all_names(self):
        result = ScriptResult(
            success=True,
            data={
                "names": [
                    {"ea": "0x401000", "name": "main", "type": "function"},
                    {"ea": "0x402000", "name": "g_counter", "type": "data"},
                    {"ea": "0x403000", "name": "loc_403000"},
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        names = await list_names(sm, bridge, "sess1")

        assert len(names) == 3
        assert names[0].ea == "0x401000"
        assert names[0].name == "main"
        assert names[0].type == "function"
        assert names[1].ea == "0x402000"
        assert names[1].name == "g_counter"
        assert names[1].type == "data"
        assert names[2].ea == "0x403000"
        assert names[2].name == "loc_403000"
        assert names[2].type is None
        assert bridge.last_operation == "list_names"
        assert bridge.last_params == {}

    @pytest.mark.asyncio
    async def test_empty_list(self):
        result = ScriptResult(success=True, data={"names": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        names = await list_names(sm, bridge, "sess1")
        assert names == []

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Session error"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await list_names(sm, bridge, "sess1")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "list_names"

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data={"names": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_names(sm, bridge, "session_xyz")
        assert sm.last_session_id == "session_xyz"

    @pytest.mark.asyncio
    async def test_defaults_when_data_missing(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        names = await list_names(sm, bridge, "sess1")
        assert names == []


# ---------------------------------------------------------------------------
# rename_location
# ---------------------------------------------------------------------------


class TestRenameLocation:
    """Tests for rename_location tool handler."""

    @pytest.mark.asyncio
    async def test_successful_rename(self):
        result = ScriptResult(
            success=True,
            data={"message": "Location at 0x401000 renamed to my_func"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await rename_location(sm, bridge, "sess1", "0x401000", "my_func")

        assert op.success is True
        assert "my_func" in op.message
        assert bridge.last_operation == "rename_location"
        assert bridge.last_params == {"ea": 0x401000, "new_name": "my_func"}

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_invalid_address(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await rename_location(sm, bridge, "sess1", "not_an_address", "foo")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "rename_location"

    @pytest.mark.asyncio
    async def test_empty_name_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await rename_location(sm, bridge, "sess1", "0x401000", "")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "rename_location"

    @pytest.mark.asyncio
    async def test_whitespace_name_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await rename_location(sm, bridge, "sess1", "0x401000", "   ")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER

    @pytest.mark.asyncio
    async def test_decimal_ea_accepted(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await rename_location(sm, bridge, "sess1", "4198400", "my_func")
        assert bridge.last_params["ea"] == 4198400

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Cannot rename location"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await rename_location(sm, bridge, "sess1", "0x401000", "foo")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert "Cannot rename location" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await rename_location(sm, bridge, "session_abc", "0x401000", "foo")
        assert sm.last_session_id == "session_abc"

    @pytest.mark.asyncio
    async def test_defaults_when_data_missing(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await rename_location(sm, bridge, "sess1", "0x401000", "foo")
        assert op.success is True
        assert op.message == ""

    @pytest.mark.asyncio
    async def test_script_failure_generic_message(self):
        result = ScriptResult(success=False, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await rename_location(sm, bridge, "sess1", "0x401000", "foo")
        assert "Script execution failed" in exc_info.value.message


# ---------------------------------------------------------------------------
# get_data_type
# ---------------------------------------------------------------------------


class TestGetDataType:
    """Tests for get_data_type tool handler."""

    @pytest.mark.asyncio
    async def test_successful_get(self):
        result = ScriptResult(
            success=True,
            data={"ea": "0x402000", "type_name": "dword", "size": 4},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        dt = await get_data_type(sm, bridge, "sess1", "0x402000")

        assert dt.ea == "0x402000"
        assert dt.type_name == "dword"
        assert dt.size == 4
        assert bridge.last_operation == "get_data_type"
        assert bridge.last_params == {"ea": 0x402000}

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_invalid_address(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_data_type(sm, bridge, "sess1", "bad_addr")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "get_data_type"

    @pytest.mark.asyncio
    async def test_decimal_ea_accepted(self):
        result = ScriptResult(
            success=True,
            data={"ea": "0x402000", "type_name": "byte", "size": 1},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        dt = await get_data_type(sm, bridge, "sess1", "4202496")
        assert bridge.last_params["ea"] == 4202496
        assert dt.type_name == "byte"

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Address unmapped"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_data_type(sm, bridge, "sess1", "0x402000")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert "Address unmapped" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(
            success=True,
            data={"ea": "0x402000", "type_name": "byte", "size": 1},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_data_type(sm, bridge, "session_abc", "0x402000")
        assert sm.last_session_id == "session_abc"

    @pytest.mark.asyncio
    async def test_defaults_when_data_missing(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        dt = await get_data_type(sm, bridge, "sess1", "0x402000")
        assert dt.ea == "0x402000"
        assert dt.type_name == ""
        assert dt.size == 0

    @pytest.mark.asyncio
    async def test_script_failure_generic_message(self):
        result = ScriptResult(success=False, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_data_type(sm, bridge, "sess1", "0x402000")
        assert "Script execution failed" in exc_info.value.message


# ---------------------------------------------------------------------------
# set_data_type
# ---------------------------------------------------------------------------


class TestSetDataType:
    """Tests for set_data_type tool handler."""

    @pytest.mark.asyncio
    async def test_successful_set(self):
        result = ScriptResult(
            success=True,
            data={"message": "Type at 0x402000 changed to dword"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await set_data_type(sm, bridge, "sess1", "0x402000", "dword")

        assert op.success is True
        assert "dword" in op.message
        assert bridge.last_operation == "set_data_type"
        assert bridge.last_params == {"ea": 0x402000, "type_str": "dword"}

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_invalid_address(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await set_data_type(sm, bridge, "sess1", "xyz", "dword")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "set_data_type"

    @pytest.mark.asyncio
    async def test_empty_type_str_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await set_data_type(sm, bridge, "sess1", "0x402000", "")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "set_data_type"

    @pytest.mark.asyncio
    async def test_whitespace_type_str_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await set_data_type(sm, bridge, "sess1", "0x402000", "   ")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER

    @pytest.mark.asyncio
    async def test_decimal_ea_accepted(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await set_data_type(sm, bridge, "sess1", "4202496", "word")
        assert bridge.last_params["ea"] == 4202496

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Cannot set type"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await set_data_type(sm, bridge, "sess1", "0x402000", "dword")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert "Cannot set type" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await set_data_type(sm, bridge, "session_abc", "0x402000", "dword")
        assert sm.last_session_id == "session_abc"

    @pytest.mark.asyncio
    async def test_defaults_when_data_missing(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await set_data_type(sm, bridge, "sess1", "0x402000", "dword")
        assert op.success is True
        assert op.message == ""

    @pytest.mark.asyncio
    async def test_script_failure_generic_message(self):
        result = ScriptResult(success=False, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await set_data_type(sm, bridge, "sess1", "0x402000", "dword")
        assert "Script execution failed" in exc_info.value.message
