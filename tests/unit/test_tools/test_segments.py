"""Unit tests for segment tool handlers.

Tests the tool handler functions in ``ida_headless_mcp.tools.segments``
using a mock session manager that returns pre-configured ScriptResult data.
"""

from __future__ import annotations

import pytest

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.ida_bridge import ScriptResult
from ida_headless_mcp.models import SegmentInfo
from ida_headless_mcp.tools.segments import get_segment, get_segment_at, list_segments


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
# Sample segment data
# ---------------------------------------------------------------------------

SAMPLE_SEGMENTS = [
    {
        "name": ".text",
        "start_ea": "0x401000",
        "end_ea": "0x402000",
        "size": 4096,
        "permissions": "r-x",
        "seg_class": "CODE",
        "bitness": 64,
    },
    {
        "name": ".data",
        "start_ea": "0x500000",
        "end_ea": "0x501000",
        "size": 4096,
        "permissions": "rw-",
        "seg_class": "DATA",
        "bitness": 64,
    },
    {
        "name": ".rodata",
        "start_ea": "0x600000",
        "end_ea": "0x600800",
        "size": 2048,
        "permissions": "r--",
        "seg_class": "CONST",
        "bitness": 32,
    },
]


# ---------------------------------------------------------------------------
# list_segments
# ---------------------------------------------------------------------------


class TestListSegments:
    """Tests for list_segments tool handler."""

    @pytest.mark.asyncio
    async def test_returns_all_segments(self):
        result = ScriptResult(success=True, data={"segments": SAMPLE_SEGMENTS})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        segments = await list_segments(sm, bridge, "sess1")

        assert len(segments) == 3
        assert isinstance(segments[0], SegmentInfo)
        assert segments[0].name == ".text"
        assert segments[0].start_ea == "0x401000"
        assert segments[0].end_ea == "0x402000"
        assert segments[0].size == 4096
        assert segments[0].permissions == "r-x"
        assert segments[0].seg_class == "CODE"
        assert segments[0].bitness == 64

    @pytest.mark.asyncio
    async def test_second_segment_parsed(self):
        result = ScriptResult(success=True, data={"segments": SAMPLE_SEGMENTS})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        segments = await list_segments(sm, bridge, "sess1")

        assert segments[1].name == ".data"
        assert segments[1].permissions == "rw-"
        assert segments[1].seg_class == "DATA"

    @pytest.mark.asyncio
    async def test_empty_segment_list(self):
        result = ScriptResult(success=True, data={"segments": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        segments = await list_segments(sm, bridge, "sess1")
        assert segments == []

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(success=False, data={"error": {"message": "IDA error"}})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await list_segments(sm, bridge, "sess1")
        assert exc_info.value.code == ErrorCode.FUNCTION_NOT_FOUND
        assert exc_info.value.tool_name == "list_segments"

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data={"segments": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_segments(sm, bridge, "my_session_99")
        assert sm.last_session_id == "my_session_99"

    @pytest.mark.asyncio
    async def test_bridge_operation_and_params(self):
        result = ScriptResult(success=True, data={"segments": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_segments(sm, bridge, "sess1")
        assert bridge.last_operation == "list_segments"
        assert bridge.last_params == {}


# ---------------------------------------------------------------------------
# get_segment
# ---------------------------------------------------------------------------


class TestGetSegment:
    """Tests for get_segment tool handler."""

    @pytest.mark.asyncio
    async def test_get_by_name(self):
        result = ScriptResult(success=True, data=SAMPLE_SEGMENTS[0])
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        seg = await get_segment(sm, bridge, "sess1", ".text")

        assert isinstance(seg, SegmentInfo)
        assert seg.name == ".text"
        assert seg.start_ea == "0x401000"
        assert seg.permissions == "r-x"
        # Name should be passed as "name" param
        assert bridge.last_params == {"name": ".text"}

    @pytest.mark.asyncio
    async def test_get_by_ea(self):
        result = ScriptResult(success=True, data=SAMPLE_SEGMENTS[0])
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        seg = await get_segment(sm, bridge, "sess1", "0x401000")

        assert isinstance(seg, SegmentInfo)
        assert seg.name == ".text"
        # EA should be passed as "ea" param (parsed to int)
        assert bridge.last_params == {"ea": 0x401000}

    @pytest.mark.asyncio
    async def test_get_by_decimal_ea(self):
        result = ScriptResult(success=True, data=SAMPLE_SEGMENTS[1])
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        seg = await get_segment(sm, bridge, "sess1", "5242880")

        assert seg.name == ".data"
        assert bridge.last_params == {"ea": 5242880}

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Segment not found"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_segment(sm, bridge, "sess1", ".nonexistent")
        assert exc_info.value.code == ErrorCode.FUNCTION_NOT_FOUND
        assert exc_info.value.tool_name == "get_segment"

    @pytest.mark.asyncio
    async def test_bridge_operation(self):
        result = ScriptResult(success=True, data=SAMPLE_SEGMENTS[0])
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_segment(sm, bridge, "sess1", ".text")
        assert bridge.last_operation == "get_segment"


# ---------------------------------------------------------------------------
# get_segment_at
# ---------------------------------------------------------------------------


class TestGetSegmentAt:
    """Tests for get_segment_at tool handler."""

    @pytest.mark.asyncio
    async def test_returns_containing_segment(self):
        result = ScriptResult(success=True, data=SAMPLE_SEGMENTS[0])
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        seg = await get_segment_at(sm, bridge, "sess1", "0x401500")

        assert isinstance(seg, SegmentInfo)
        assert seg.name == ".text"
        assert seg.start_ea == "0x401000"
        assert seg.end_ea == "0x402000"

    @pytest.mark.asyncio
    async def test_ea_passed_as_int_to_bridge(self):
        result = ScriptResult(success=True, data=SAMPLE_SEGMENTS[0])
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_segment_at(sm, bridge, "sess1", "0x401500")
        assert bridge.last_operation == "get_segment_at"
        assert bridge.last_params == {"ea": 0x401500}

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_segment_at(sm, bridge, "sess1", "not_an_address")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "get_segment_at"

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "No segment at address"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_segment_at(sm, bridge, "sess1", "0x999999")
        assert exc_info.value.code == ErrorCode.FUNCTION_NOT_FOUND
        assert exc_info.value.tool_name == "get_segment_at"

    @pytest.mark.asyncio
    async def test_decimal_ea_accepted(self):
        result = ScriptResult(success=True, data=SAMPLE_SEGMENTS[1])
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_segment_at(sm, bridge, "sess1", "5242880")
        assert bridge.last_params == {"ea": 5242880}

    @pytest.mark.asyncio
    async def test_script_failure_empty_data(self):
        result = ScriptResult(success=False, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_segment_at(sm, bridge, "sess1", "0x401000")
        assert exc_info.value.code == ErrorCode.FUNCTION_NOT_FOUND

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data=SAMPLE_SEGMENTS[0])
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_segment_at(sm, bridge, "my_session_77", "0x401000")
        assert sm.last_session_id == "my_session_77"
