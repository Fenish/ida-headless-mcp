"""Unit tests for search tool handlers.

Tests the tool handler functions in ``ida_headless_mcp.tools.search``
using a fake session manager that returns pre-configured ScriptResult data.
"""

from __future__ import annotations

import pytest

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.ida_bridge import ScriptResult
from ida_headless_mcp.tools.search import (
    search_bytes,
    search_immediate,
    search_text,
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
# search_bytes
# ---------------------------------------------------------------------------


class TestSearchBytes:
    """Tests for search_bytes tool handler."""

    @pytest.mark.asyncio
    async def test_returns_matching_eas(self):
        result = ScriptResult(
            success=True,
            data={"results": ["0x401000", "0x401010", "0x401020"]},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        eas = await search_bytes(sm, bridge, "sess1", "AA BB CC")

        assert eas == ["0x401000", "0x401010", "0x401020"]
        assert bridge.last_operation == "search_bytes"
        assert bridge.last_params["pattern"] == "AA BB CC"

    @pytest.mark.asyncio
    async def test_wildcard_pattern_accepted(self):
        result = ScriptResult(success=True, data={"results": ["0x401000"]})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        eas = await search_bytes(sm, bridge, "sess1", "AA ?? CC")

        assert eas == ["0x401000"]

    @pytest.mark.asyncio
    async def test_empty_pattern_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={"results": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await search_bytes(sm, bridge, "sess1", "")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "search_bytes"

    @pytest.mark.asyncio
    async def test_bad_pattern_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={"results": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await search_bytes(sm, bridge, "sess1", "ZZ GG")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER

    @pytest.mark.asyncio
    async def test_start_ea_and_end_ea_passed_to_bridge(self):
        result = ScriptResult(success=True, data={"results": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await search_bytes(
            sm, bridge, "sess1", "AA BB",
            start_ea="0x401000", end_ea="0x402000",
        )

        assert bridge.last_params["start_ea"] == 0x401000
        assert bridge.last_params["end_ea"] == 0x402000

    @pytest.mark.asyncio
    async def test_optional_eas_not_in_params_when_none(self):
        result = ScriptResult(success=True, data={"results": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await search_bytes(sm, bridge, "sess1", "AA BB")

        assert "start_ea" not in bridge.last_params
        assert "end_ea" not in bridge.last_params

    @pytest.mark.asyncio
    async def test_invalid_start_ea_raises_error(self):
        result = ScriptResult(success=True, data={"results": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await search_bytes(sm, bridge, "sess1", "AA BB", start_ea="bad")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS

    @pytest.mark.asyncio
    async def test_invalid_end_ea_raises_error(self):
        result = ScriptResult(success=True, data={"results": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await search_bytes(sm, bridge, "sess1", "AA BB", end_ea="nope")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS

    @pytest.mark.asyncio
    async def test_max_results_limits_output(self):
        result = ScriptResult(
            success=True,
            data={"results": [f"0x{i:x}" for i in range(200)]},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        eas = await search_bytes(sm, bridge, "sess1", "AA BB", max_results=5)

        assert len(eas) == 5

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Search failed"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await search_bytes(sm, bridge, "sess1", "AA BB")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "search_bytes"

    @pytest.mark.asyncio
    async def test_empty_results(self):
        result = ScriptResult(success=True, data={"results": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        eas = await search_bytes(sm, bridge, "sess1", "FF EE DD")
        assert eas == []


# ---------------------------------------------------------------------------
# search_text
# ---------------------------------------------------------------------------


class TestSearchText:
    """Tests for search_text tool handler."""

    @pytest.mark.asyncio
    async def test_returns_matching_eas(self):
        result = ScriptResult(
            success=True,
            data={"results": ["0x402000", "0x402100"]},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        eas = await search_text(sm, bridge, "sess1", "Hello")

        assert eas == ["0x402000", "0x402100"]
        assert bridge.last_operation == "search_text"
        assert bridge.last_params["text"] == "Hello"

    @pytest.mark.asyncio
    async def test_empty_text_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={"results": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await search_text(sm, bridge, "sess1", "")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "search_text"

    @pytest.mark.asyncio
    async def test_start_ea_and_end_ea_passed_to_bridge(self):
        result = ScriptResult(success=True, data={"results": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await search_text(
            sm, bridge, "sess1", "test",
            start_ea="0x400000", end_ea="0x500000",
        )

        assert bridge.last_params["start_ea"] == 0x400000
        assert bridge.last_params["end_ea"] == 0x500000

    @pytest.mark.asyncio
    async def test_optional_eas_not_in_params_when_none(self):
        result = ScriptResult(success=True, data={"results": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await search_text(sm, bridge, "sess1", "test")

        assert "start_ea" not in bridge.last_params
        assert "end_ea" not in bridge.last_params

    @pytest.mark.asyncio
    async def test_invalid_start_ea_raises_error(self):
        result = ScriptResult(success=True, data={"results": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await search_text(sm, bridge, "sess1", "test", start_ea="xyz")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS

    @pytest.mark.asyncio
    async def test_max_results_limits_output(self):
        result = ScriptResult(
            success=True,
            data={"results": [f"0x{i:x}" for i in range(50)]},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        eas = await search_text(sm, bridge, "sess1", "test", max_results=10)

        assert len(eas) == 10

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Text search failed"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await search_text(sm, bridge, "sess1", "test")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "search_text"


# ---------------------------------------------------------------------------
# search_immediate
# ---------------------------------------------------------------------------


class TestSearchImmediate:
    """Tests for search_immediate tool handler."""

    @pytest.mark.asyncio
    async def test_returns_matching_eas(self):
        result = ScriptResult(
            success=True,
            data={"results": ["0x401050", "0x401080"]},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        eas = await search_immediate(sm, bridge, "sess1", 42)

        assert eas == ["0x401050", "0x401080"]
        assert bridge.last_operation == "search_immediate"
        assert bridge.last_params["value"] == 42

    @pytest.mark.asyncio
    async def test_start_ea_and_end_ea_passed_to_bridge(self):
        result = ScriptResult(success=True, data={"results": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await search_immediate(
            sm, bridge, "sess1", 0xFF,
            start_ea="0x401000", end_ea="0x402000",
        )

        assert bridge.last_params["start_ea"] == 0x401000
        assert bridge.last_params["end_ea"] == 0x402000

    @pytest.mark.asyncio
    async def test_optional_eas_not_in_params_when_none(self):
        result = ScriptResult(success=True, data={"results": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await search_immediate(sm, bridge, "sess1", 0)

        assert "start_ea" not in bridge.last_params
        assert "end_ea" not in bridge.last_params

    @pytest.mark.asyncio
    async def test_invalid_start_ea_raises_error(self):
        result = ScriptResult(success=True, data={"results": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await search_immediate(sm, bridge, "sess1", 42, start_ea="bad")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS

    @pytest.mark.asyncio
    async def test_invalid_end_ea_raises_error(self):
        result = ScriptResult(success=True, data={"results": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await search_immediate(sm, bridge, "sess1", 42, end_ea="nope")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS

    @pytest.mark.asyncio
    async def test_max_results_limits_output(self):
        result = ScriptResult(
            success=True,
            data={"results": [f"0x{i:x}" for i in range(200)]},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        eas = await search_immediate(sm, bridge, "sess1", 42, max_results=3)

        assert len(eas) == 3

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Immediate search failed"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await search_immediate(sm, bridge, "sess1", 42)
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "search_immediate"

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data={"results": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await search_immediate(sm, bridge, "my_session_123", 0)
        assert sm.last_session_id == "my_session_123"

    @pytest.mark.asyncio
    async def test_max_results_passed_to_bridge(self):
        result = ScriptResult(success=True, data={"results": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await search_immediate(sm, bridge, "sess1", 42, max_results=50)
        assert bridge.last_params["max_results"] == 50
