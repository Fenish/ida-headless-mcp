"""Unit tests for decompilation tool handlers.

Tests the tool handler functions in ``ida_headless_mcp.tools.decompile``
using a mock session manager that returns pre-configured ScriptResult data.
"""

from __future__ import annotations

import pytest

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.ida_bridge import ScriptResult
from ida_headless_mcp.models import DecompileResult
from ida_headless_mcp.tools.decompile import decompile_function


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
# decompile_function — success cases
# ---------------------------------------------------------------------------


class TestDecompileFunction:
    """Tests for decompile_function tool handler."""

    @pytest.mark.asyncio
    async def test_successful_decompilation(self):
        result = ScriptResult(
            success=True,
            data={
                "ea": "0x401000",
                "name": "main",
                "pseudocode": "int main(int argc, char **argv) { return 0; }",
                "parameter_types": ["int", "char **"],
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        dr = await decompile_function(sm, bridge, "sess1", "0x401000")

        assert isinstance(dr, DecompileResult)
        assert dr.ea == "0x401000"
        assert dr.name == "main"
        assert "return 0" in dr.pseudocode
        assert dr.parameter_types == ["int", "char **"]

    @pytest.mark.asyncio
    async def test_ea_passed_as_int_to_bridge(self):
        result = ScriptResult(
            success=True,
            data={
                "ea": "0x401000",
                "name": "main",
                "pseudocode": "int main() {}",
                "parameter_types": [],
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await decompile_function(sm, bridge, "sess1", "0x401000")

        assert bridge.last_operation == "decompile_function"
        assert bridge.last_params["ea"] == 0x401000

    @pytest.mark.asyncio
    async def test_default_parameter_types_empty(self):
        """When parameter_types is missing from data, default to empty list."""
        result = ScriptResult(
            success=True,
            data={
                "ea": "0x401000",
                "name": "func",
                "pseudocode": "void func() {}",
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        dr = await decompile_function(sm, bridge, "sess1", "0x401000")
        assert dr.parameter_types == []

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(
            success=True,
            data={
                "ea": "0x401000",
                "name": "f",
                "pseudocode": "void f() {}",
                "parameter_types": [],
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await decompile_function(sm, bridge, "my_session_42", "0x401000")
        assert sm.last_session_id == "my_session_42"


# ---------------------------------------------------------------------------
# decompile_function — var_hints
# ---------------------------------------------------------------------------


class TestDecompileVarHints:
    """Tests for variable renaming hints in decompile_function."""

    @pytest.mark.asyncio
    async def test_var_hints_passed_to_bridge(self):
        result = ScriptResult(
            success=True,
            data={
                "ea": "0x401000",
                "name": "main",
                "pseudocode": "int main(int argc) {}",
                "parameter_types": ["int"],
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        hints = {"v1": "argc", "v2": "argv"}
        await decompile_function(sm, bridge, "sess1", "0x401000", var_hints=hints)

        assert bridge.last_params["var_hints"] == {"v1": "argc", "v2": "argv"}

    @pytest.mark.asyncio
    async def test_no_var_hints_omitted_from_params(self):
        result = ScriptResult(
            success=True,
            data={
                "ea": "0x401000",
                "name": "f",
                "pseudocode": "void f() {}",
                "parameter_types": [],
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await decompile_function(sm, bridge, "sess1", "0x401000", var_hints=None)
        assert "var_hints" not in bridge.last_params


# ---------------------------------------------------------------------------
# decompile_function — error cases
# ---------------------------------------------------------------------------


class TestDecompileErrors:
    """Tests for error handling in decompile_function."""

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await decompile_function(sm, bridge, "sess1", "not_an_address")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "decompile_function"

    @pytest.mark.asyncio
    async def test_decompiler_unavailable(self):
        result = ScriptResult(
            success=False,
            data={
                "error": {
                    "code": "DECOMPILER_UNAVAILABLE",
                    "message": "Hex-Rays decompiler is not available",
                }
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await decompile_function(sm, bridge, "sess1", "0x401000")
        assert exc_info.value.code == ErrorCode.DECOMPILER_UNAVAILABLE
        assert "not available" in exc_info.value.message
        assert exc_info.value.tool_name == "decompile_function"

    @pytest.mark.asyncio
    async def test_decompilation_failed(self):
        result = ScriptResult(
            success=False,
            data={
                "error": {
                    "message": "Function too complex to decompile",
                }
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await decompile_function(sm, bridge, "sess1", "0x401000")
        assert exc_info.value.code == ErrorCode.DECOMPILATION_FAILED
        assert "too complex" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_decompilation_failed_no_error_dict(self):
        """When data has no 'error' key, still raises DECOMPILATION_FAILED."""
        result = ScriptResult(
            success=False,
            data="something went wrong",
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await decompile_function(sm, bridge, "sess1", "0x401000")
        assert exc_info.value.code == ErrorCode.DECOMPILATION_FAILED

    @pytest.mark.asyncio
    async def test_decompilation_failed_empty_data(self):
        """When data is None/empty, still raises DECOMPILATION_FAILED."""
        result = ScriptResult(success=False, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await decompile_function(sm, bridge, "sess1", "0x401000")
        assert exc_info.value.code == ErrorCode.DECOMPILATION_FAILED

    @pytest.mark.asyncio
    async def test_decimal_ea_accepted(self):
        """EA can be provided as a decimal string."""
        result = ScriptResult(
            success=True,
            data={
                "ea": "0x100",
                "name": "func",
                "pseudocode": "void func() {}",
                "parameter_types": [],
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await decompile_function(sm, bridge, "sess1", "256")
        assert bridge.last_params["ea"] == 256
