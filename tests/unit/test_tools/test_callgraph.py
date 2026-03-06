"""Unit tests for call graph tool handlers.

Tests the tool handler functions in ``ida_headless_mcp.tools.callgraph``
using a fake session manager that returns pre-configured ScriptResult data.
"""

from __future__ import annotations

import pytest

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.ida_bridge import ScriptResult
from ida_headless_mcp.tools.callgraph import (
    get_call_graph,
    get_callees,
    get_callers,
    _parse_call_graph_node,
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
# _parse_call_graph_node
# ---------------------------------------------------------------------------


class TestParseCallGraphNode:
    """Tests for the recursive call graph node parser."""

    def test_leaf_node(self):
        data = {"ea": "0x401000", "name": "main", "children": []}
        node = _parse_call_graph_node(data)
        assert node.ea == "0x401000"
        assert node.name == "main"
        assert node.children == []

    def test_nested_children(self):
        data = {
            "ea": "0x401000",
            "name": "main",
            "children": [
                {"ea": "0x401100", "name": "helper", "children": []},
                {
                    "ea": "0x401200",
                    "name": "init",
                    "children": [
                        {"ea": "0x401300", "name": "deep", "children": []},
                    ],
                },
            ],
        }
        node = _parse_call_graph_node(data)
        assert node.ea == "0x401000"
        assert len(node.children) == 2
        assert node.children[0].ea == "0x401100"
        assert node.children[0].name == "helper"
        assert node.children[1].ea == "0x401200"
        assert len(node.children[1].children) == 1
        assert node.children[1].children[0].name == "deep"

    def test_missing_children_key(self):
        data = {"ea": "0x401000", "name": "main"}
        node = _parse_call_graph_node(data)
        assert node.children == []

    def test_defaults_for_missing_fields(self):
        data = {}
        node = _parse_call_graph_node(data)
        assert node.ea == ""
        assert node.name == ""
        assert node.children == []


# ---------------------------------------------------------------------------
# get_callers
# ---------------------------------------------------------------------------


class TestGetCallers:
    """Tests for get_callers tool handler."""

    @pytest.mark.asyncio
    async def test_returns_all_callers(self):
        result = ScriptResult(
            success=True,
            data={
                "callers": [
                    {"ea": "0x401000", "name": "main"},
                    {"ea": "0x401100", "name": "init"},
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        callers = await get_callers(sm, bridge, "sess1", "0x402000")

        assert len(callers) == 2
        assert callers[0].ea == "0x401000"
        assert callers[0].name == "main"
        assert callers[1].ea == "0x401100"
        assert callers[1].name == "init"
        assert bridge.last_operation == "get_callers"
        assert bridge.last_params == {"ea": 0x402000}

    @pytest.mark.asyncio
    async def test_empty_callers(self):
        result = ScriptResult(success=True, data={"callers": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        callers = await get_callers(sm, bridge, "sess1", "0x402000")
        assert callers == []

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_invalid_address(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_callers(sm, bridge, "sess1", "not_an_address")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "get_callers"

    @pytest.mark.asyncio
    async def test_decimal_ea_accepted(self):
        result = ScriptResult(success=True, data={"callers": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_callers(sm, bridge, "sess1", "4198400")
        assert bridge.last_params["ea"] == 4198400

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Function not found"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_callers(sm, bridge, "sess1", "0x402000")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert "Function not found" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data={"callers": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_callers(sm, bridge, "session_xyz", "0x402000")
        assert sm.last_session_id == "session_xyz"

    @pytest.mark.asyncio
    async def test_defaults_when_data_missing(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        callers = await get_callers(sm, bridge, "sess1", "0x402000")
        assert callers == []

    @pytest.mark.asyncio
    async def test_script_failure_generic_message(self):
        result = ScriptResult(success=False, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_callers(sm, bridge, "sess1", "0x402000")
        assert "Script execution failed" in exc_info.value.message


# ---------------------------------------------------------------------------
# get_callees
# ---------------------------------------------------------------------------


class TestGetCallees:
    """Tests for get_callees tool handler."""

    @pytest.mark.asyncio
    async def test_returns_all_callees(self):
        result = ScriptResult(
            success=True,
            data={
                "callees": [
                    {"ea": "0x403000", "name": "printf"},
                    {"ea": "0x403100", "name": "malloc"},
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        callees = await get_callees(sm, bridge, "sess1", "0x401000")

        assert len(callees) == 2
        assert callees[0].ea == "0x403000"
        assert callees[0].name == "printf"
        assert callees[1].ea == "0x403100"
        assert callees[1].name == "malloc"
        assert bridge.last_operation == "get_callees"
        assert bridge.last_params == {"ea": 0x401000}

    @pytest.mark.asyncio
    async def test_empty_callees(self):
        result = ScriptResult(success=True, data={"callees": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        callees = await get_callees(sm, bridge, "sess1", "0x401000")
        assert callees == []

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_invalid_address(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_callees(sm, bridge, "sess1", "bad_addr")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "get_callees"

    @pytest.mark.asyncio
    async def test_decimal_ea_accepted(self):
        result = ScriptResult(success=True, data={"callees": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_callees(sm, bridge, "sess1", "4198400")
        assert bridge.last_params["ea"] == 4198400

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Function not found"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_callees(sm, bridge, "sess1", "0x401000")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert "Function not found" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data={"callees": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_callees(sm, bridge, "session_abc", "0x401000")
        assert sm.last_session_id == "session_abc"

    @pytest.mark.asyncio
    async def test_defaults_when_data_missing(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        callees = await get_callees(sm, bridge, "sess1", "0x401000")
        assert callees == []

    @pytest.mark.asyncio
    async def test_script_failure_generic_message(self):
        result = ScriptResult(success=False, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_callees(sm, bridge, "sess1", "0x401000")
        assert "Script execution failed" in exc_info.value.message


# ---------------------------------------------------------------------------
# get_call_graph
# ---------------------------------------------------------------------------


class TestGetCallGraph:
    """Tests for get_call_graph tool handler."""

    @pytest.mark.asyncio
    async def test_returns_nested_graph(self):
        result = ScriptResult(
            success=True,
            data={
                "ea": "0x401000",
                "name": "main",
                "children": [
                    {"ea": "0x401100", "name": "helper", "children": []},
                    {
                        "ea": "0x401200",
                        "name": "init",
                        "children": [
                            {"ea": "0x401300", "name": "deep", "children": []},
                        ],
                    },
                ],
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        node = await get_call_graph(sm, bridge, "sess1", "0x401000", depth=3)

        assert node.ea == "0x401000"
        assert node.name == "main"
        assert len(node.children) == 2
        assert node.children[0].name == "helper"
        assert node.children[1].name == "init"
        assert len(node.children[1].children) == 1
        assert node.children[1].children[0].name == "deep"
        assert bridge.last_operation == "get_call_graph"
        assert bridge.last_params == {"ea": 0x401000, "depth": 3}

    @pytest.mark.asyncio
    async def test_leaf_graph(self):
        result = ScriptResult(
            success=True,
            data={"ea": "0x401000", "name": "leaf_func", "children": []},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        node = await get_call_graph(sm, bridge, "sess1", "0x401000")

        assert node.ea == "0x401000"
        assert node.name == "leaf_func"
        assert node.children == []

    @pytest.mark.asyncio
    async def test_default_depth_is_3(self):
        result = ScriptResult(
            success=True,
            data={"ea": "0x401000", "name": "main", "children": []},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_call_graph(sm, bridge, "sess1", "0x401000")
        assert bridge.last_params["depth"] == 3

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_invalid_address(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_call_graph(sm, bridge, "sess1", "not_valid")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "get_call_graph"

    @pytest.mark.asyncio
    async def test_zero_depth_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_call_graph(sm, bridge, "sess1", "0x401000", depth=0)
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "get_call_graph"

    @pytest.mark.asyncio
    async def test_negative_depth_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_call_graph(sm, bridge, "sess1", "0x401000", depth=-1)
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER

    @pytest.mark.asyncio
    async def test_decimal_ea_accepted(self):
        result = ScriptResult(
            success=True,
            data={"ea": "0x401000", "name": "main", "children": []},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_call_graph(sm, bridge, "sess1", "4198400", depth=2)
        assert bridge.last_params["ea"] == 4198400

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Function not found"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_call_graph(sm, bridge, "sess1", "0x401000")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert "Function not found" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(
            success=True,
            data={"ea": "0x401000", "name": "main", "children": []},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_call_graph(sm, bridge, "session_xyz", "0x401000")
        assert sm.last_session_id == "session_xyz"

    @pytest.mark.asyncio
    async def test_defaults_when_data_missing(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        node = await get_call_graph(sm, bridge, "sess1", "0x401000")
        assert node.ea == ""
        assert node.name == ""
        assert node.children == []

    @pytest.mark.asyncio
    async def test_script_failure_generic_message(self):
        result = ScriptResult(success=False, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_call_graph(sm, bridge, "sess1", "0x401000")
        assert "Script execution failed" in exc_info.value.message
