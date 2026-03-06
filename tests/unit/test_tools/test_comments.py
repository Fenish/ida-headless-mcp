"""Unit tests for comment tool handlers.

Tests the tool handler functions in ``ida_headless_mcp.tools.comments``
using a mock session manager that returns pre-configured ScriptResult data.
"""

from __future__ import annotations

import pytest

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.ida_bridge import ScriptResult
from ida_headless_mcp.models import CommentInfo, OperationResult
from ida_headless_mcp.tools.comments import (
    get_comments,
    get_comments_range,
    set_comment,
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
# set_comment
# ---------------------------------------------------------------------------


class TestSetComment:
    """Tests for set_comment tool handler."""

    @pytest.mark.asyncio
    async def test_set_regular_comment(self):
        result = ScriptResult(
            success=True,
            data={"message": "Comment set"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await set_comment(sm, bridge, "sess1", "0x401000", "Entry point")

        assert isinstance(op, OperationResult)
        assert op.success is True
        assert op.message == "Comment set"

    @pytest.mark.asyncio
    async def test_set_repeatable_comment(self):
        result = ScriptResult(
            success=True,
            data={"message": "Comment set"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await set_comment(
            sm, bridge, "sess1", "0x401000", "Repeatable note", "repeatable"
        )

        assert op.success is True
        assert bridge.last_params == {
            "ea": 0x401000,
            "comment": "Repeatable note",
            "comment_type": "repeatable",
        }

    @pytest.mark.asyncio
    async def test_set_function_comment(self):
        result = ScriptResult(
            success=True,
            data={"message": "Comment set"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await set_comment(
            sm, bridge, "sess1", "0x401000", "Main entry", "function"
        )

        assert op.success is True
        assert bridge.last_params["comment_type"] == "function"

    @pytest.mark.asyncio
    async def test_default_comment_type_is_regular(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await set_comment(sm, bridge, "sess1", "0x401000", "test")

        assert bridge.last_params["comment_type"] == "regular"

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await set_comment(sm, bridge, "sess1", "not_valid", "text")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "set_comment"

    @pytest.mark.asyncio
    async def test_invalid_comment_type_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await set_comment(
                sm, bridge, "sess1", "0x401000", "text", "invalid_type"
            )
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert "invalid_type" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False, data={"error": {"message": "IDA error"}}
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await set_comment(sm, bridge, "sess1", "0x401000", "text")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "set_comment"

    @pytest.mark.asyncio
    async def test_params_passed_to_bridge(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await set_comment(sm, bridge, "sess1", "0x401000", "hello", "regular")

        assert bridge.last_operation == "set_comment"
        assert bridge.last_params == {
            "ea": 0x401000,
            "comment": "hello",
            "comment_type": "regular",
        }


# ---------------------------------------------------------------------------
# get_comments
# ---------------------------------------------------------------------------


class TestGetComments:
    """Tests for get_comments tool handler."""

    @pytest.mark.asyncio
    async def test_returns_all_comment_types(self):
        result = ScriptResult(
            success=True,
            data={
                "ea": "0x401000",
                "regular": "Entry point",
                "repeatable": "Main func",
                "function_comment": "Program entry",
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        ci = await get_comments(sm, bridge, "sess1", "0x401000")

        assert isinstance(ci, CommentInfo)
        assert ci.ea == "0x401000"
        assert ci.regular == "Entry point"
        assert ci.repeatable == "Main func"
        assert ci.function_comment == "Program entry"

    @pytest.mark.asyncio
    async def test_returns_none_for_missing_comments(self):
        result = ScriptResult(
            success=True,
            data={"ea": "0x401000"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        ci = await get_comments(sm, bridge, "sess1", "0x401000")

        assert ci.ea == "0x401000"
        assert ci.regular is None
        assert ci.repeatable is None
        assert ci.function_comment is None

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_comments(sm, bridge, "sess1", "bad_addr")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "get_comments"

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False, data={"error": {"message": "Script failed"}}
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_comments(sm, bridge, "sess1", "0x401000")
        assert exc_info.value.tool_name == "get_comments"

    @pytest.mark.asyncio
    async def test_ea_passed_as_int_to_bridge(self):
        result = ScriptResult(
            success=True,
            data={"ea": "0x401000"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_comments(sm, bridge, "sess1", "0x401000")
        assert bridge.last_params == {"ea": 0x401000}


# ---------------------------------------------------------------------------
# get_comments_range
# ---------------------------------------------------------------------------


class TestGetCommentsRange:
    """Tests for get_comments_range tool handler."""

    @pytest.mark.asyncio
    async def test_returns_comments_in_range(self):
        result = ScriptResult(
            success=True,
            data={
                "comments": [
                    {
                        "ea": "0x401000",
                        "regular": "Entry",
                        "repeatable": None,
                        "function_comment": "Main",
                    },
                    {
                        "ea": "0x401100",
                        "regular": None,
                        "repeatable": "Helper",
                        "function_comment": None,
                    },
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        comments = await get_comments_range(
            sm, bridge, "sess1", "0x401000", "0x402000"
        )

        assert len(comments) == 2
        assert isinstance(comments[0], CommentInfo)
        assert comments[0].ea == "0x401000"
        assert comments[0].regular == "Entry"
        assert comments[0].function_comment == "Main"
        assert comments[1].ea == "0x401100"
        assert comments[1].repeatable == "Helper"

    @pytest.mark.asyncio
    async def test_empty_range_returns_empty_list(self):
        result = ScriptResult(success=True, data={"comments": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        comments = await get_comments_range(
            sm, bridge, "sess1", "0x401000", "0x401001"
        )
        assert comments == []

    @pytest.mark.asyncio
    async def test_invalid_start_ea_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_comments_range(sm, bridge, "sess1", "bad", "0x402000")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "get_comments_range"

    @pytest.mark.asyncio
    async def test_invalid_end_ea_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_comments_range(sm, bridge, "sess1", "0x401000", "bad")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False, data={"error": {"message": "Range error"}}
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await get_comments_range(
                sm, bridge, "sess1", "0x401000", "0x402000"
            )
        assert exc_info.value.tool_name == "get_comments_range"

    @pytest.mark.asyncio
    async def test_params_passed_to_bridge(self):
        result = ScriptResult(success=True, data={"comments": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_comments_range(sm, bridge, "sess1", "0x401000", "0x402000")

        assert bridge.last_operation == "get_comments_range"
        assert bridge.last_params == {
            "start_ea": 0x401000,
            "end_ea": 0x402000,
        }

    @pytest.mark.asyncio
    async def test_decimal_eas_accepted(self):
        result = ScriptResult(success=True, data={"comments": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_comments_range(sm, bridge, "sess1", "100", "200")

        assert bridge.last_params == {"start_ea": 100, "end_ea": 200}


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge case tests across comment tool handlers."""

    @pytest.mark.asyncio
    async def test_decimal_ea_accepted_for_set_comment(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await set_comment(sm, bridge, "sess1", "256", "test")
        assert bridge.last_params["ea"] == 256

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data={"ea": "0x401000"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await get_comments(sm, bridge, "my_session_123", "0x401000")
        assert sm.last_session_id == "my_session_123"

    @pytest.mark.asyncio
    async def test_empty_comment_string_allowed(self):
        result = ScriptResult(success=True, data={"message": "Comment set"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await set_comment(sm, bridge, "sess1", "0x401000", "")
        assert op.success is True
        assert bridge.last_params["comment"] == ""
