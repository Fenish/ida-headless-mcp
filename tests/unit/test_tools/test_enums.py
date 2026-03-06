"""Unit tests for enum tool handlers.

Tests the tool handler functions in ``ida_headless_mcp.tools.enums``
using a fake session manager that returns pre-configured ScriptResult data.
"""

from __future__ import annotations

import pytest

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.ida_bridge import ScriptResult
from ida_headless_mcp.tools.enums import (
    add_enum_member,
    apply_enum,
    create_enum,
    list_enums,
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
# list_enums
# ---------------------------------------------------------------------------


class TestListEnums:
    """Tests for list_enums tool handler."""

    @pytest.mark.asyncio
    async def test_returns_all_enums(self):
        result = ScriptResult(
            success=True,
            data={
                "enums": [
                    {"name": "Color", "member_count": 3, "width": 4},
                    {"name": "Status", "member_count": 2, "width": 1},
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        enums = await list_enums(sm, bridge, "sess1")

        assert len(enums) == 2
        assert enums[0].name == "Color"
        assert enums[0].member_count == 3
        assert enums[0].width == 4
        assert enums[1].name == "Status"
        assert enums[1].member_count == 2
        assert enums[1].width == 1
        assert bridge.last_operation == "list_enums"
        assert bridge.last_params == {}

    @pytest.mark.asyncio
    async def test_empty_list(self):
        result = ScriptResult(success=True, data={"enums": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        enums = await list_enums(sm, bridge, "sess1")
        assert enums == []

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Session error"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await list_enums(sm, bridge, "sess1")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "list_enums"

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data={"enums": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_enums(sm, bridge, "session_xyz")
        assert sm.last_session_id == "session_xyz"

    @pytest.mark.asyncio
    async def test_defaults_when_data_missing(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        enums = await list_enums(sm, bridge, "sess1")
        assert enums == []


# ---------------------------------------------------------------------------
# create_enum
# ---------------------------------------------------------------------------


class TestCreateEnum:
    """Tests for create_enum tool handler."""

    @pytest.mark.asyncio
    async def test_successful_create(self):
        result = ScriptResult(
            success=True,
            data={"message": "Enum Color created with 3 members"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        members = [
            {"name": "RED", "value": 0},
            {"name": "GREEN", "value": 1},
            {"name": "BLUE", "value": 2},
        ]
        op = await create_enum(sm, bridge, "sess1", "Color", members)

        assert op.success is True
        assert "Color" in op.message
        assert bridge.last_operation == "create_enum"
        assert bridge.last_params == {"name": "Color", "members": members}

    @pytest.mark.asyncio
    async def test_empty_name_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await create_enum(sm, bridge, "sess1", "", [])
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "create_enum"

    @pytest.mark.asyncio
    async def test_whitespace_name_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await create_enum(sm, bridge, "sess1", "   ", [])
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Failed to create enum"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await create_enum(sm, bridge, "sess1", "MyEnum", [])
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert "Failed to create enum" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await create_enum(sm, bridge, "my_session_42", "E", [])
        assert sm.last_session_id == "my_session_42"

    @pytest.mark.asyncio
    async def test_defaults_when_data_missing(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await create_enum(sm, bridge, "sess1", "E", [])
        assert op.success is True
        assert op.message == ""

    @pytest.mark.asyncio
    async def test_script_failure_generic_message(self):
        result = ScriptResult(success=False, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await create_enum(sm, bridge, "sess1", "E", [])
        assert "Script execution failed" in exc_info.value.message


# ---------------------------------------------------------------------------
# add_enum_member
# ---------------------------------------------------------------------------


class TestAddEnumMember:
    """Tests for add_enum_member tool handler."""

    @pytest.mark.asyncio
    async def test_successful_add(self):
        result = ScriptResult(
            success=True,
            data={"message": "Member YELLOW added to Color"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await add_enum_member(sm, bridge, "sess1", "Color", "YELLOW", 3)

        assert op.success is True
        assert "YELLOW" in op.message
        assert bridge.last_operation == "add_enum_member"
        assert bridge.last_params == {
            "enum_name": "Color",
            "member_name": "YELLOW",
            "value": 3,
        }

    @pytest.mark.asyncio
    async def test_empty_enum_name_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await add_enum_member(sm, bridge, "sess1", "", "FOO", 0)
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "add_enum_member"

    @pytest.mark.asyncio
    async def test_whitespace_enum_name_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await add_enum_member(sm, bridge, "sess1", "  ", "FOO", 0)
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER

    @pytest.mark.asyncio
    async def test_empty_member_name_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await add_enum_member(sm, bridge, "sess1", "Color", "", 0)
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "add_enum_member"

    @pytest.mark.asyncio
    async def test_whitespace_member_name_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await add_enum_member(sm, bridge, "sess1", "Color", "   ", 0)
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Enum not found"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await add_enum_member(sm, bridge, "sess1", "Missing", "X", 0)
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert "Enum not found" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await add_enum_member(sm, bridge, "session_abc", "E", "M", 1)
        assert sm.last_session_id == "session_abc"

    @pytest.mark.asyncio
    async def test_defaults_when_data_missing(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await add_enum_member(sm, bridge, "sess1", "E", "M", 0)
        assert op.success is True
        assert op.message == ""

    @pytest.mark.asyncio
    async def test_script_failure_generic_message(self):
        result = ScriptResult(success=False, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await add_enum_member(sm, bridge, "sess1", "E", "M", 0)
        assert "Script execution failed" in exc_info.value.message


# ---------------------------------------------------------------------------
# apply_enum
# ---------------------------------------------------------------------------


class TestApplyEnum:
    """Tests for apply_enum tool handler."""

    @pytest.mark.asyncio
    async def test_successful_apply(self):
        result = ScriptResult(
            success=True,
            data={"message": "Enum Color applied at 0x401000 operand 1"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await apply_enum(sm, bridge, "sess1", "0x401000", 1, "Color")

        assert op.success is True
        assert "Color" in op.message
        assert bridge.last_operation == "apply_enum"
        assert bridge.last_params == {
            "ea": 0x401000,
            "operand": 1,
            "enum_name": "Color",
        }

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_invalid_address(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await apply_enum(sm, bridge, "sess1", "not_an_address", 0, "Color")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "apply_enum"

    @pytest.mark.asyncio
    async def test_empty_enum_name_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await apply_enum(sm, bridge, "sess1", "0x401000", 0, "")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "apply_enum"

    @pytest.mark.asyncio
    async def test_whitespace_enum_name_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await apply_enum(sm, bridge, "sess1", "0x401000", 0, "   ")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER

    @pytest.mark.asyncio
    async def test_decimal_ea_accepted(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await apply_enum(sm, bridge, "sess1", "4198400", 0, "Color")
        assert bridge.last_params["ea"] == 4198400

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Cannot apply enum"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await apply_enum(sm, bridge, "sess1", "0x401000", 0, "Color")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert "Cannot apply enum" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await apply_enum(sm, bridge, "session_abc", "0x401000", 0, "E")
        assert sm.last_session_id == "session_abc"

    @pytest.mark.asyncio
    async def test_defaults_when_data_missing(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await apply_enum(sm, bridge, "sess1", "0x401000", 0, "E")
        assert op.success is True
        assert op.message == ""

    @pytest.mark.asyncio
    async def test_script_failure_generic_message(self):
        result = ScriptResult(success=False, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await apply_enum(sm, bridge, "sess1", "0x401000", 0, "E")
        assert "Script execution failed" in exc_info.value.message
