"""Unit tests for bookmark tool handlers.

Tests the tool handler functions in ``ida_headless_mcp.tools.bookmarks``
using a fake session manager that returns pre-configured ScriptResult data.
"""

from __future__ import annotations

import pytest

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.ida_bridge import ScriptResult
from ida_headless_mcp.tools.bookmarks import (
    add_bookmark,
    delete_bookmark,
    list_bookmarks,
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
# add_bookmark
# ---------------------------------------------------------------------------


class TestAddBookmark:
    """Tests for add_bookmark tool handler."""

    @pytest.mark.asyncio
    async def test_returns_operation_result(self):
        result = ScriptResult(
            success=True,
            data={"message": "Bookmark added at 0x401000"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await add_bookmark(sm, bridge, "sess1", "0x401000", "interesting func")

        assert op.success is True
        assert op.message == "Bookmark added at 0x401000"
        assert bridge.last_operation == "add_bookmark"
        assert bridge.last_params == {"ea": 0x401000, "description": "interesting func"}

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_invalid_address(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await add_bookmark(sm, bridge, "sess1", "not_an_address", "desc")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "add_bookmark"

    @pytest.mark.asyncio
    async def test_empty_description_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await add_bookmark(sm, bridge, "sess1", "0x401000", "")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "add_bookmark"

    @pytest.mark.asyncio
    async def test_whitespace_description_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await add_bookmark(sm, bridge, "sess1", "0x401000", "   ")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Failed to add bookmark"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await add_bookmark(sm, bridge, "sess1", "0x401000", "desc")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert "Failed to add bookmark" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(
            success=True,
            data={"message": "ok"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await add_bookmark(sm, bridge, "my_session_42", "0x401000", "desc")
        assert sm.last_session_id == "my_session_42"

    @pytest.mark.asyncio
    async def test_decimal_ea_accepted(self):
        result = ScriptResult(
            success=True,
            data={"message": "ok"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await add_bookmark(sm, bridge, "sess1", "4198400", "desc")
        assert bridge.last_params["ea"] == 4198400

    @pytest.mark.asyncio
    async def test_defaults_when_data_missing(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await add_bookmark(sm, bridge, "sess1", "0x401000", "desc")
        assert op.success is True
        assert op.message == ""

    @pytest.mark.asyncio
    async def test_script_failure_generic_message(self):
        result = ScriptResult(success=False, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await add_bookmark(sm, bridge, "sess1", "0x401000", "desc")
        assert "Script execution failed" in exc_info.value.message


# ---------------------------------------------------------------------------
# list_bookmarks
# ---------------------------------------------------------------------------


class TestListBookmarks:
    """Tests for list_bookmarks tool handler."""

    @pytest.mark.asyncio
    async def test_returns_bookmarks(self):
        result = ScriptResult(
            success=True,
            data={
                "bookmarks": [
                    {"ea": "0x401000", "description": "main entry"},
                    {"ea": "0x402000", "description": "crypto func"},
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        bookmarks = await list_bookmarks(sm, bridge, "sess1")

        assert len(bookmarks) == 2
        assert bookmarks[0].ea == "0x401000"
        assert bookmarks[0].description == "main entry"
        assert bookmarks[1].ea == "0x402000"
        assert bookmarks[1].description == "crypto func"
        assert bridge.last_operation == "list_bookmarks"
        assert bridge.last_params == {}

    @pytest.mark.asyncio
    async def test_empty_list(self):
        result = ScriptResult(success=True, data={"bookmarks": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        bookmarks = await list_bookmarks(sm, bridge, "sess1")
        assert bookmarks == []

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Session error"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await list_bookmarks(sm, bridge, "sess1")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "list_bookmarks"

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data={"bookmarks": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_bookmarks(sm, bridge, "session_xyz")
        assert sm.last_session_id == "session_xyz"

    @pytest.mark.asyncio
    async def test_defaults_when_data_missing(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        bookmarks = await list_bookmarks(sm, bridge, "sess1")
        assert bookmarks == []

    @pytest.mark.asyncio
    async def test_missing_description_defaults_to_empty(self):
        result = ScriptResult(
            success=True,
            data={"bookmarks": [{"ea": "0x401000"}]},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        bookmarks = await list_bookmarks(sm, bridge, "sess1")
        assert len(bookmarks) == 1
        assert bookmarks[0].description == ""


# ---------------------------------------------------------------------------
# delete_bookmark
# ---------------------------------------------------------------------------


class TestDeleteBookmark:
    """Tests for delete_bookmark tool handler."""

    @pytest.mark.asyncio
    async def test_returns_operation_result(self):
        result = ScriptResult(
            success=True,
            data={"message": "Bookmark deleted at 0x401000"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await delete_bookmark(sm, bridge, "sess1", "0x401000")

        assert op.success is True
        assert op.message == "Bookmark deleted at 0x401000"
        assert bridge.last_operation == "delete_bookmark"
        assert bridge.last_params == {"ea": 0x401000}

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_invalid_address(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await delete_bookmark(sm, bridge, "sess1", "xyz")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "delete_bookmark"

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Bookmark not found"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await delete_bookmark(sm, bridge, "sess1", "0x401000")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert "Bookmark not found" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(
            success=True,
            data={"message": "ok"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await delete_bookmark(sm, bridge, "session_abc", "0x401000")
        assert sm.last_session_id == "session_abc"

    @pytest.mark.asyncio
    async def test_decimal_ea_accepted(self):
        result = ScriptResult(
            success=True,
            data={"message": "ok"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await delete_bookmark(sm, bridge, "sess1", "4198400")
        assert bridge.last_params == {"ea": 4198400}

    @pytest.mark.asyncio
    async def test_defaults_when_data_missing(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await delete_bookmark(sm, bridge, "sess1", "0x401000")
        assert op.success is True
        assert op.message == ""

    @pytest.mark.asyncio
    async def test_script_failure_generic_message(self):
        result = ScriptResult(success=False, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await delete_bookmark(sm, bridge, "sess1", "0x401000")
        assert "Script execution failed" in exc_info.value.message
