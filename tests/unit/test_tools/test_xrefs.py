"""Unit tests for cross-reference tool handlers.

Tests the tool handler functions in ``ida_headless_mcp.tools.xrefs``
using a mock session manager that returns pre-configured ScriptResult data.
"""

from __future__ import annotations

import pytest

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.ida_bridge import ScriptResult
from ida_headless_mcp.models import FunctionXrefs, XrefInfo
from ida_headless_mcp.tools.xrefs import (
    get_function_xrefs,
    get_xrefs_from,
    get_xrefs_to,
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
# get_xrefs_to
# ---------------------------------------------------------------------------


class TestGetXrefsTo:
    """Tests for get_xrefs_to tool handler."""

    @pytest.mark.asyncio
    async def test_returns_xrefs(self):
        result = ScriptResult(
            success=True,
            data={
                "xrefs": [
                    {
                        "source_ea": "0x401000",
                        "target_ea": "0x402000",
                        "xref_type": "code_call",
                        "source_function": "main",
                        "target_function": "helper",
                    },
                    {
                        "source_ea": "0x401050",
                        "target_ea": "0x402000",
                        "xref_type": "code_jump",
                        "source_function": "main",
                        "target_function": "helper",
                    },
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        xrefs = await get_xrefs_to(sm, bridge, "sess1", "0x402000")

        assert len(xrefs) == 2
        assert isinstance(xrefs[0], XrefInfo)
        assert xrefs[0].source_ea == "0x401000"
        assert xrefs[0].target_ea == "0x402000"
        assert xrefs[0].xref_type == "code_call"
        assert xrefs[0].source_function == "main"
        assert xrefs[1].xref_type == "code_jump"

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_xrefs_to(sm, bridge, "sess1", "not_an_address")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "get_xrefs_to"

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "IDA error"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_xrefs_to(sm, bridge, "sess1", "0x402000")
        assert exc_info.value.code == ErrorCode.FUNCTION_NOT_FOUND
        assert exc_info.value.tool_name == "get_xrefs_to"

    @pytest.mark.asyncio
    async def test_empty_xrefs(self):
        result = ScriptResult(success=True, data={"xrefs": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        xrefs = await get_xrefs_to(sm, bridge, "sess1", "0x402000")
        assert xrefs == []

    @pytest.mark.asyncio
    async def test_ea_passed_as_int_to_bridge(self):
        result = ScriptResult(success=True, data={"xrefs": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_xrefs_to(sm, bridge, "sess1", "0x402000")
        assert bridge.last_operation == "get_xrefs_to"
        assert bridge.last_params == {"ea": 0x402000}

    @pytest.mark.asyncio
    async def test_optional_function_fields_none(self):
        """source_function and target_function can be absent."""
        result = ScriptResult(
            success=True,
            data={
                "xrefs": [
                    {
                        "source_ea": "0x401000",
                        "target_ea": "0x402000",
                        "xref_type": "data_read",
                    },
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        xrefs = await get_xrefs_to(sm, bridge, "sess1", "0x402000")
        assert xrefs[0].source_function is None
        assert xrefs[0].target_function is None


# ---------------------------------------------------------------------------
# get_xrefs_from
# ---------------------------------------------------------------------------


class TestGetXrefsFrom:
    """Tests for get_xrefs_from tool handler."""

    @pytest.mark.asyncio
    async def test_returns_xrefs(self):
        result = ScriptResult(
            success=True,
            data={
                "xrefs": [
                    {
                        "source_ea": "0x401000",
                        "target_ea": "0x402000",
                        "xref_type": "code_call",
                        "source_function": "main",
                        "target_function": "helper",
                    },
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        xrefs = await get_xrefs_from(sm, bridge, "sess1", "0x401000")

        assert len(xrefs) == 1
        assert isinstance(xrefs[0], XrefInfo)
        assert xrefs[0].source_ea == "0x401000"
        assert xrefs[0].target_ea == "0x402000"
        assert xrefs[0].xref_type == "code_call"

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_xrefs_from(sm, bridge, "sess1", "bad_addr")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "get_xrefs_from"

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Script failed"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_xrefs_from(sm, bridge, "sess1", "0x401000")
        assert exc_info.value.code == ErrorCode.FUNCTION_NOT_FOUND

    @pytest.mark.asyncio
    async def test_empty_xrefs(self):
        result = ScriptResult(success=True, data={"xrefs": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        xrefs = await get_xrefs_from(sm, bridge, "sess1", "0x401000")
        assert xrefs == []

    @pytest.mark.asyncio
    async def test_ea_passed_as_int_to_bridge(self):
        result = ScriptResult(success=True, data={"xrefs": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_xrefs_from(sm, bridge, "sess1", "0x401000")
        assert bridge.last_operation == "get_xrefs_from"
        assert bridge.last_params == {"ea": 0x401000}

    @pytest.mark.asyncio
    async def test_data_xref_types(self):
        """Verify data xref types are parsed correctly."""
        result = ScriptResult(
            success=True,
            data={
                "xrefs": [
                    {
                        "source_ea": "0x401000",
                        "target_ea": "0x500000",
                        "xref_type": "data_write",
                        "source_function": "init",
                        "target_function": None,
                    },
                    {
                        "source_ea": "0x401010",
                        "target_ea": "0x500004",
                        "xref_type": "data_offset",
                    },
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        xrefs = await get_xrefs_from(sm, bridge, "sess1", "0x401000")
        assert xrefs[0].xref_type == "data_write"
        assert xrefs[1].xref_type == "data_offset"


# ---------------------------------------------------------------------------
# get_function_xrefs
# ---------------------------------------------------------------------------


class TestGetFunctionXrefs:
    """Tests for get_function_xrefs tool handler."""

    @pytest.mark.asyncio
    async def test_returns_callers_and_callees(self):
        result = ScriptResult(
            success=True,
            data={
                "callers": [
                    {
                        "source_ea": "0x401000",
                        "target_ea": "0x402000",
                        "xref_type": "code_call",
                        "source_function": "main",
                        "target_function": "helper",
                    },
                ],
                "callees": [
                    {
                        "source_ea": "0x402000",
                        "target_ea": "0x403000",
                        "xref_type": "code_call",
                        "source_function": "helper",
                        "target_function": "printf",
                    },
                ],
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        fxrefs = await get_function_xrefs(sm, bridge, "sess1", "helper")

        assert isinstance(fxrefs, FunctionXrefs)
        assert len(fxrefs.callers) == 1
        assert len(fxrefs.callees) == 1
        assert fxrefs.callers[0].source_function == "main"
        assert fxrefs.callees[0].target_function == "printf"

    @pytest.mark.asyncio
    async def test_function_name_passed_to_bridge(self):
        result = ScriptResult(
            success=True,
            data={"callers": [], "callees": []},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_function_xrefs(sm, bridge, "sess1", "my_func")
        assert bridge.last_operation == "get_function_xrefs"
        assert bridge.last_params == {"function_name": "my_func"}

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Function not found"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_function_xrefs(sm, bridge, "sess1", "nonexistent")
        assert exc_info.value.code == ErrorCode.FUNCTION_NOT_FOUND
        assert exc_info.value.tool_name == "get_function_xrefs"

    @pytest.mark.asyncio
    async def test_empty_callers_and_callees(self):
        result = ScriptResult(
            success=True,
            data={"callers": [], "callees": []},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        fxrefs = await get_function_xrefs(sm, bridge, "sess1", "isolated_func")
        assert fxrefs.callers == []
        assert fxrefs.callees == []

    @pytest.mark.asyncio
    async def test_no_ea_validation_for_function_name(self):
        """get_function_xrefs takes a name string, not an EA — no EA validation."""
        result = ScriptResult(
            success=True,
            data={"callers": [], "callees": []},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        # Should NOT raise McpToolError with INVALID_ADDRESS
        fxrefs = await get_function_xrefs(sm, bridge, "sess1", "not_a_hex_addr")
        assert isinstance(fxrefs, FunctionXrefs)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestXrefEdgeCases:
    """Edge case tests across xref tool handlers."""

    @pytest.mark.asyncio
    async def test_decimal_ea_accepted(self):
        """EA can be provided as a decimal string."""
        result = ScriptResult(success=True, data={"xrefs": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        xrefs = await get_xrefs_to(sm, bridge, "sess1", "4202496")
        assert bridge.last_params == {"ea": 4202496}

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        """The session_id is correctly forwarded to the session manager."""
        result = ScriptResult(success=True, data={"xrefs": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_xrefs_to(sm, bridge, "my_session_42", "0x401000")
        assert sm.last_session_id == "my_session_42"

    @pytest.mark.asyncio
    async def test_script_failure_no_error_key(self):
        """Script failure with data that lacks an 'error' key."""
        result = ScriptResult(success=False, data="unexpected failure")
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_xrefs_to(sm, bridge, "sess1", "0x401000")
        assert exc_info.value.code == ErrorCode.FUNCTION_NOT_FOUND
        assert "unexpected failure" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_script_failure_empty_data(self):
        """Script failure with None/empty data."""
        result = ScriptResult(success=False, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_xrefs_from(sm, bridge, "sess1", "0x401000")
        assert exc_info.value.code == ErrorCode.FUNCTION_NOT_FOUND
