"""Unit tests for type tool handlers.

Tests the tool handler functions in ``ida_headless_mcp.tools.types``
using a mock session manager that returns pre-configured ScriptResult data.
"""

from __future__ import annotations

import pytest

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.ida_bridge import ScriptResult
from ida_headless_mcp.models import OperationResult, TypeInfo
from ida_headless_mcp.tools.types import (
    add_struct_field,
    apply_type,
    create_struct,
    delete_type,
    list_types,
    parse_header,
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
# list_types
# ---------------------------------------------------------------------------


class TestListTypes:
    """Tests for list_types tool handler."""

    @pytest.mark.asyncio
    async def test_returns_all_types(self):
        result = ScriptResult(
            success=True,
            data={
                "types": [
                    {"name": "MyStruct", "size": 16, "definition": "struct MyStruct { int x; int y; }"},
                    {"name": "Point", "size": 8, "definition": "struct Point { int a; int b; }"},
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        types = await list_types(sm, bridge, "sess1")

        assert len(types) == 2
        assert isinstance(types[0], TypeInfo)
        assert types[0].name == "MyStruct"
        assert types[0].size == 16
        assert types[0].definition == "struct MyStruct { int x; int y; }"
        assert types[1].name == "Point"

    @pytest.mark.asyncio
    async def test_empty_type_list(self):
        result = ScriptResult(success=True, data={"types": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        types = await list_types(sm, bridge, "sess1")
        assert types == []

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "IDA error"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await list_types(sm, bridge, "sess1")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "list_types"

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data={"types": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_types(sm, bridge, "my_session")
        assert sm.last_session_id == "my_session"


# ---------------------------------------------------------------------------
# create_struct
# ---------------------------------------------------------------------------


class TestCreateStruct:
    """Tests for create_struct tool handler."""

    @pytest.mark.asyncio
    async def test_successful_create(self):
        result = ScriptResult(
            success=True,
            data={"message": "Struct MyStruct created"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        fields = [
            {"name": "x", "type_str": "int", "offset": 0},
            {"name": "y", "type_str": "int", "offset": 4},
        ]
        op = await create_struct(sm, bridge, "sess1", "MyStruct", fields)

        assert isinstance(op, OperationResult)
        assert op.success is True
        assert "MyStruct" in op.message

    @pytest.mark.asyncio
    async def test_params_passed_to_bridge(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        fields = [{"name": "a", "type_str": "char", "offset": 0}]
        await create_struct(sm, bridge, "sess1", "Foo", fields)

        assert bridge.last_operation == "create_struct"
        assert bridge.last_params == {"name": "Foo", "fields": fields}

    @pytest.mark.asyncio
    async def test_type_conflict_raises_error(self):
        result = ScriptResult(
            success=False,
            data={
                "error": {
                    "code": "TYPE_CONFLICT",
                    "message": "Type 'MyStruct' already exists",
                }
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await create_struct(sm, bridge, "sess1", "MyStruct", [])
        assert exc_info.value.code == ErrorCode.TYPE_CONFLICT
        assert exc_info.value.tool_name == "create_struct"

    @pytest.mark.asyncio
    async def test_generic_failure_uses_invalid_parameter(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Something went wrong"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await create_struct(sm, bridge, "sess1", "Bad", [])
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER


# ---------------------------------------------------------------------------
# add_struct_field
# ---------------------------------------------------------------------------


class TestAddStructField:
    """Tests for add_struct_field tool handler."""

    @pytest.mark.asyncio
    async def test_successful_add(self):
        result = ScriptResult(
            success=True,
            data={"message": "Field 'z' added to MyStruct"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        field = {"name": "z", "type_str": "int", "offset": 8}
        op = await add_struct_field(sm, bridge, "sess1", "MyStruct", field)

        assert isinstance(op, OperationResult)
        assert op.success is True

    @pytest.mark.asyncio
    async def test_params_passed_to_bridge(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        field = {"name": "w", "type_str": "short", "offset": 0}
        await add_struct_field(sm, bridge, "sess1", "Bar", field)

        assert bridge.last_operation == "add_struct_field"
        assert bridge.last_params == {"struct_name": "Bar", "field": field}

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Struct not found"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await add_struct_field(sm, bridge, "sess1", "Missing", {})
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER


# ---------------------------------------------------------------------------
# apply_type
# ---------------------------------------------------------------------------


class TestApplyType:
    """Tests for apply_type tool handler."""

    @pytest.mark.asyncio
    async def test_successful_apply(self):
        result = ScriptResult(
            success=True,
            data={"message": "Type applied at 0x401000"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await apply_type(sm, bridge, "sess1", "0x401000", "int *")

        assert isinstance(op, OperationResult)
        assert op.success is True

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await apply_type(sm, bridge, "sess1", "not_an_address", "int")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "apply_type"

    @pytest.mark.asyncio
    async def test_ea_passed_as_int_to_bridge(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await apply_type(sm, bridge, "sess1", "0x401000", "char *")
        assert bridge.last_params == {"ea": 0x401000, "type_str": "char *"}

    @pytest.mark.asyncio
    async def test_decimal_ea_accepted(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await apply_type(sm, bridge, "sess1", "256", "int")
        assert bridge.last_params == {"ea": 256, "type_str": "int"}

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Cannot apply type"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await apply_type(sm, bridge, "sess1", "0x401000", "bad_type")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER


# ---------------------------------------------------------------------------
# delete_type
# ---------------------------------------------------------------------------


class TestDeleteType:
    """Tests for delete_type tool handler."""

    @pytest.mark.asyncio
    async def test_successful_delete(self):
        result = ScriptResult(
            success=True,
            data={"message": "Type 'MyStruct' deleted"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await delete_type(sm, bridge, "sess1", "MyStruct")

        assert isinstance(op, OperationResult)
        assert op.success is True
        assert "deleted" in op.message.lower()

    @pytest.mark.asyncio
    async def test_params_passed_to_bridge(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await delete_type(sm, bridge, "sess1", "SomeType")
        assert bridge.last_operation == "delete_type"
        assert bridge.last_params == {"name": "SomeType"}

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Type not found"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await delete_type(sm, bridge, "sess1", "Missing")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER


# ---------------------------------------------------------------------------
# parse_header
# ---------------------------------------------------------------------------


class TestParseHeader:
    """Tests for parse_header tool handler."""

    @pytest.mark.asyncio
    async def test_successful_parse(self):
        result = ScriptResult(
            success=True,
            data={"message": "Header parsed successfully"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await parse_header(sm, bridge, "sess1", "struct Foo { int x; };")

        assert isinstance(op, OperationResult)
        assert op.success is True

    @pytest.mark.asyncio
    async def test_params_passed_to_bridge(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        header = "typedef int DWORD;"
        await parse_header(sm, bridge, "sess1", header)
        assert bridge.last_operation == "parse_header"
        assert bridge.last_params == {"header_text": header}

    @pytest.mark.asyncio
    async def test_type_conflict_raises_error(self):
        result = ScriptResult(
            success=False,
            data={
                "error": {
                    "code": "TYPE_CONFLICT",
                    "message": "Type 'Foo' already exists",
                }
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await parse_header(sm, bridge, "sess1", "struct Foo { int x; };")
        assert exc_info.value.code == ErrorCode.TYPE_CONFLICT

    @pytest.mark.asyncio
    async def test_generic_failure(self):
        result = ScriptResult(
            success=False,
            data=None,
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await parse_header(sm, bridge, "sess1", "invalid header")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert "Script execution failed" in exc_info.value.message
