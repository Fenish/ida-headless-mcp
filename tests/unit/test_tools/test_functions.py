"""Unit tests for function tool handlers.

Tests the tool handler functions in ``ida_headless_mcp.tools.functions``
using a mock session manager that returns pre-configured ScriptResult data.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock

import pytest

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.ida_bridge import ScriptResult
from ida_headless_mcp.models import FunctionDetails, FunctionInfo, OperationResult
from ida_headless_mcp.tools.functions import (
    create_function,
    delete_function,
    get_function_details,
    list_functions,
    rename_function,
)


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
# list_functions
# ---------------------------------------------------------------------------


class TestListFunctions:
    """Tests for list_functions tool handler."""

    @pytest.mark.asyncio
    async def test_returns_all_functions(self):
        result = ScriptResult(
            success=True,
            data={
                "functions": [
                    {"ea": "0x401000", "name": "main", "end_ea": "0x401100", "size": 256},
                    {"ea": "0x401100", "name": "helper", "end_ea": "0x401180", "size": 128},
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        funcs = await list_functions(sm, bridge, "sess1")

        assert len(funcs) == 2
        assert isinstance(funcs[0], FunctionInfo)
        assert funcs[0].ea == "0x401000"
        assert funcs[0].name == "main"
        assert funcs[0].size == 256
        assert funcs[1].name == "helper"

    @pytest.mark.asyncio
    async def test_filter_pattern_passed_to_bridge(self):
        result = ScriptResult(
            success=True,
            data={
                "functions": [
                    {"ea": "0x401000", "name": "main", "end_ea": "0x401100", "size": 256},
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        funcs = await list_functions(sm, bridge, "sess1", filter_pattern="main*")

        assert bridge.last_params == {"filter_pattern": "main*"}
        assert len(funcs) == 1
        assert funcs[0].name == "main"

    @pytest.mark.asyncio
    async def test_client_side_filter_excludes_non_matching(self):
        """Even if the bridge returns unfiltered results, client-side filter applies."""
        result = ScriptResult(
            success=True,
            data={
                "functions": [
                    {"ea": "0x401000", "name": "main", "end_ea": "0x401100", "size": 256},
                    {"ea": "0x401100", "name": "helper", "end_ea": "0x401180", "size": 128},
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        funcs = await list_functions(sm, bridge, "sess1", filter_pattern="main*")

        assert len(funcs) == 1
        assert funcs[0].name == "main"

    @pytest.mark.asyncio
    async def test_empty_function_list(self):
        result = ScriptResult(success=True, data={"functions": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        funcs = await list_functions(sm, bridge, "sess1")
        assert funcs == []

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(success=False, data={"error": {"message": "IDA error"}})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await list_functions(sm, bridge, "sess1")
        assert exc_info.value.code == ErrorCode.FUNCTION_NOT_FOUND
        assert exc_info.value.tool_name == "list_functions"


# ---------------------------------------------------------------------------
# get_function_details
# ---------------------------------------------------------------------------


class TestGetFunctionDetails:
    """Tests for get_function_details tool handler."""

    @pytest.mark.asyncio
    async def test_returns_full_details(self):
        result = ScriptResult(
            success=True,
            data={
                "ea": "0x401000",
                "name": "main",
                "end_ea": "0x401100",
                "size": 256,
                "num_blocks": 5,
                "calling_convention": "cdecl",
                "frame_size": 64,
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        details = await get_function_details(sm, bridge, "sess1", "0x401000")

        assert isinstance(details, FunctionDetails)
        assert details.ea == "0x401000"
        assert details.name == "main"
        assert details.size == 256
        assert details.num_blocks == 5
        assert details.calling_convention == "cdecl"
        assert details.frame_size == 64

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_function_details(sm, bridge, "sess1", "not_an_address")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "get_function_details"

    @pytest.mark.asyncio
    async def test_no_function_at_ea_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "No function at 0x999"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_function_details(sm, bridge, "sess1", "0x999")
        assert exc_info.value.code == ErrorCode.FUNCTION_NOT_FOUND

    @pytest.mark.asyncio
    async def test_ea_passed_as_int_to_bridge(self):
        result = ScriptResult(
            success=True,
            data={
                "ea": "0x401000",
                "name": "main",
                "end_ea": "0x401100",
                "size": 256,
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_function_details(sm, bridge, "sess1", "0x401000")
        assert bridge.last_params == {"ea": 0x401000}


# ---------------------------------------------------------------------------
# rename_function
# ---------------------------------------------------------------------------


class TestRenameFunction:
    """Tests for rename_function tool handler."""

    @pytest.mark.asyncio
    async def test_successful_rename(self):
        result = ScriptResult(
            success=True,
            data={"message": "Renamed to my_func"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await rename_function(sm, bridge, "sess1", "0x401000", "my_func")

        assert isinstance(op, OperationResult)
        assert op.success is True
        assert "my_func" in op.message

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await rename_function(sm, bridge, "sess1", "xyz", "new_name")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS

    @pytest.mark.asyncio
    async def test_params_passed_to_bridge(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await rename_function(sm, bridge, "sess1", "0x401000", "new_name")
        assert bridge.last_operation == "rename_function"
        assert bridge.last_params == {"ea": 0x401000, "new_name": "new_name"}


# ---------------------------------------------------------------------------
# create_function
# ---------------------------------------------------------------------------


class TestCreateFunction:
    """Tests for create_function tool handler."""

    @pytest.mark.asyncio
    async def test_successful_create(self):
        result = ScriptResult(
            success=True,
            data={"message": "Created function at 0x402000"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await create_function(sm, bridge, "sess1", "0x402000")

        assert isinstance(op, OperationResult)
        assert op.success is True
        assert "0x402000" in op.message

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await create_function(sm, bridge, "sess1", "bad")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS

    @pytest.mark.asyncio
    async def test_params_passed_to_bridge(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await create_function(sm, bridge, "sess1", "0x402000")
        assert bridge.last_operation == "create_function"
        assert bridge.last_params == {"ea": 0x402000}


# ---------------------------------------------------------------------------
# delete_function
# ---------------------------------------------------------------------------


class TestDeleteFunction:
    """Tests for delete_function tool handler."""

    @pytest.mark.asyncio
    async def test_successful_delete(self):
        result = ScriptResult(
            success=True,
            data={"message": "Function deleted"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await delete_function(sm, bridge, "sess1", "0x401000")

        assert isinstance(op, OperationResult)
        assert op.success is True
        assert "deleted" in op.message.lower()

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await delete_function(sm, bridge, "sess1", "nope")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS

    @pytest.mark.asyncio
    async def test_no_function_at_ea(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "No function at 0x999"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await delete_function(sm, bridge, "sess1", "0x999")
        assert exc_info.value.code == ErrorCode.FUNCTION_NOT_FOUND

    @pytest.mark.asyncio
    async def test_params_passed_to_bridge(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await delete_function(sm, bridge, "sess1", "0x401000")
        assert bridge.last_operation == "delete_function"
        assert bridge.last_params == {"ea": 0x401000}


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge case tests across function tool handlers."""

    @pytest.mark.asyncio
    async def test_decimal_ea_accepted(self):
        """EA can be provided as a decimal string."""
        result = ScriptResult(
            success=True,
            data={
                "ea": "0x100",
                "name": "func",
                "end_ea": "0x200",
                "size": 256,
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        details = await get_function_details(sm, bridge, "sess1", "256")
        assert bridge.last_params == {"ea": 256}

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        """The session_id is correctly forwarded to the session manager."""
        result = ScriptResult(success=True, data={"functions": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_functions(sm, bridge, "my_session_123")
        assert sm.last_session_id == "my_session_123"

    @pytest.mark.asyncio
    async def test_filter_pattern_none_not_in_params(self):
        """When filter_pattern is None, it should not appear in bridge params."""
        result = ScriptResult(success=True, data={"functions": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_functions(sm, bridge, "sess1", filter_pattern=None)
        assert "filter_pattern" not in bridge.last_params
