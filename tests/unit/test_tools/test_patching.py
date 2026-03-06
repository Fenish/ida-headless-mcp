"""Unit tests for patching tool handlers.

Tests the tool handler functions in ``ida_headless_mcp.tools.patching``
using a mock session manager that returns pre-configured ScriptResult data.
"""

from __future__ import annotations

import pytest

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.ida_bridge import ScriptResult
from ida_headless_mcp.models import OperationResult, PatchInfo
from ida_headless_mcp.tools.patching import (
    assemble_and_patch,
    list_patches,
    patch_bytes,
    read_bytes,
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
# read_bytes
# ---------------------------------------------------------------------------


class TestReadBytes:
    """Tests for read_bytes tool handler."""

    @pytest.mark.asyncio
    async def test_returns_hex_string(self):
        result = ScriptResult(
            success=True,
            data={"hex_bytes": "90cc41"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        hex_str = await read_bytes(sm, bridge, "sess1", "0x401000", 3)

        assert hex_str == "90cc41"

    @pytest.mark.asyncio
    async def test_empty_read(self):
        result = ScriptResult(
            success=True,
            data={"hex_bytes": ""},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        hex_str = await read_bytes(sm, bridge, "sess1", "0x401000", 0)

        assert hex_str == ""

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await read_bytes(sm, bridge, "sess1", "not_an_address", 4)
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "read_bytes"

    @pytest.mark.asyncio
    async def test_unmapped_address_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Address 0x999 is unmapped"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await read_bytes(sm, bridge, "sess1", "0x999", 4)
        assert exc_info.value.code == ErrorCode.ADDRESS_UNMAPPED
        assert exc_info.value.tool_name == "read_bytes"

    @pytest.mark.asyncio
    async def test_params_passed_to_bridge(self):
        result = ScriptResult(success=True, data={"hex_bytes": "90"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await read_bytes(sm, bridge, "sess1", "0x401000", 1)
        assert bridge.last_operation == "read_bytes"
        assert bridge.last_params == {"ea": 0x401000, "length": 1}

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Read failed"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await read_bytes(sm, bridge, "sess1", "0x401000", 4)
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "read_bytes"


# ---------------------------------------------------------------------------
# patch_bytes
# ---------------------------------------------------------------------------


class TestPatchBytes:
    """Tests for patch_bytes tool handler."""

    @pytest.mark.asyncio
    async def test_successful_patch(self):
        result = ScriptResult(
            success=True,
            data={"message": "Patched 2 bytes at 0x401000"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await patch_bytes(sm, bridge, "sess1", "0x401000", "90cc")

        assert isinstance(op, OperationResult)
        assert op.success is True
        assert "Patched" in op.message

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await patch_bytes(sm, bridge, "sess1", "xyz", "90")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "patch_bytes"

    @pytest.mark.asyncio
    async def test_unmapped_address_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Address 0x999 is unmapped"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await patch_bytes(sm, bridge, "sess1", "0x999", "90")
        assert exc_info.value.code == ErrorCode.ADDRESS_UNMAPPED

    @pytest.mark.asyncio
    async def test_params_passed_to_bridge(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await patch_bytes(sm, bridge, "sess1", "0x401000", "cccc")
        assert bridge.last_operation == "patch_bytes"
        assert bridge.last_params == {"ea": 0x401000, "hex_values": "cccc"}

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Patch failed"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await patch_bytes(sm, bridge, "sess1", "0x401000", "90")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER


# ---------------------------------------------------------------------------
# assemble_and_patch
# ---------------------------------------------------------------------------


class TestAssembleAndPatch:
    """Tests for assemble_and_patch tool handler."""

    @pytest.mark.asyncio
    async def test_successful_assemble(self):
        result = ScriptResult(
            success=True,
            data={"message": "Assembled and patched 1 bytes"},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await assemble_and_patch(sm, bridge, "sess1", "0x401000", "nop")

        assert isinstance(op, OperationResult)
        assert op.success is True
        assert "Assembled" in op.message

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await assemble_and_patch(sm, bridge, "sess1", "bad", "nop")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "assemble_and_patch"

    @pytest.mark.asyncio
    async def test_unmapped_address_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Address 0x999 is unmapped"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await assemble_and_patch(sm, bridge, "sess1", "0x999", "nop")
        assert exc_info.value.code == ErrorCode.ADDRESS_UNMAPPED

    @pytest.mark.asyncio
    async def test_assembly_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Assembly failed: invalid instruction"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await assemble_and_patch(sm, bridge, "sess1", "0x401000", "invalid_asm")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER

    @pytest.mark.asyncio
    async def test_params_passed_to_bridge(self):
        result = ScriptResult(success=True, data={"message": "ok"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await assemble_and_patch(sm, bridge, "sess1", "0x401000", "nop")
        assert bridge.last_operation == "assemble_and_patch"
        assert bridge.last_params == {"ea": 0x401000, "assembly": "nop"}


# ---------------------------------------------------------------------------
# list_patches
# ---------------------------------------------------------------------------


class TestListPatches:
    """Tests for list_patches tool handler."""

    @pytest.mark.asyncio
    async def test_returns_patch_list(self):
        result = ScriptResult(
            success=True,
            data={
                "patches": [
                    {"ea": "0x401000", "original_byte": "90", "patched_byte": "cc"},
                    {"ea": "0x401001", "original_byte": "90", "patched_byte": "41"},
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        patches = await list_patches(sm, bridge, "sess1")

        assert len(patches) == 2
        assert isinstance(patches[0], PatchInfo)
        assert patches[0].ea == "0x401000"
        assert patches[0].original_byte == "90"
        assert patches[0].patched_byte == "cc"
        assert patches[1].ea == "0x401001"

    @pytest.mark.asyncio
    async def test_empty_patch_list(self):
        result = ScriptResult(success=True, data={"patches": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        patches = await list_patches(sm, bridge, "sess1")
        assert patches == []

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Failed to list patches"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await list_patches(sm, bridge, "sess1")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "list_patches"

    @pytest.mark.asyncio
    async def test_params_passed_to_bridge(self):
        result = ScriptResult(success=True, data={"patches": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_patches(sm, bridge, "sess1")
        assert bridge.last_operation == "list_patches"
        assert bridge.last_params == {}


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge case tests across patching tool handlers."""

    @pytest.mark.asyncio
    async def test_decimal_ea_accepted(self):
        """EA can be provided as a decimal string."""
        result = ScriptResult(success=True, data={"hex_bytes": "90"})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await read_bytes(sm, bridge, "sess1", "256", 1)
        assert bridge.last_params == {"ea": 256, "length": 1}

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        """The session_id is correctly forwarded to the session manager."""
        result = ScriptResult(success=True, data={"patches": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_patches(sm, bridge, "my_session_123")
        assert sm.last_session_id == "my_session_123"

    @pytest.mark.asyncio
    async def test_missing_data_returns_empty_hex(self):
        """When data is None or missing hex_bytes, read_bytes returns empty string."""
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        hex_str = await read_bytes(sm, bridge, "sess1", "0x401000", 4)
        assert hex_str == ""

    @pytest.mark.asyncio
    async def test_missing_data_returns_empty_message(self):
        """When data is missing message, patch_bytes returns empty message."""
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        op = await patch_bytes(sm, bridge, "sess1", "0x401000", "90")
        assert op.message == ""

    @pytest.mark.asyncio
    async def test_generic_script_failure_no_error_key(self):
        """Script failure without 'error' key in data uses fallback message."""
        result = ScriptResult(success=False, data="something went wrong")
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await read_bytes(sm, bridge, "sess1", "0x401000", 4)
        assert "something went wrong" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_script_failure_empty_data(self):
        """Script failure with empty data uses default message."""
        result = ScriptResult(success=False, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await read_bytes(sm, bridge, "sess1", "0x401000", 4)
        assert "Script execution failed" in exc_info.value.message
