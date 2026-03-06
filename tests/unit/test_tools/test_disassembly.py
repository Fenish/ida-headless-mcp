"""Unit tests for disassembly tool handlers.

Tests the tool handler functions in ``ida_headless_mcp.tools.disassembly``
using a mock session manager that returns pre-configured ScriptResult data.
"""

from __future__ import annotations

import pytest

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.ida_bridge import ScriptResult
from ida_headless_mcp.models import InstructionInfo
from ida_headless_mcp.tools.disassembly import (
    disassemble_at,
    disassemble_function,
    disassemble_range,
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
# disassemble_at
# ---------------------------------------------------------------------------


class TestDisassembleAt:
    """Tests for disassemble_at tool handler."""

    @pytest.mark.asyncio
    async def test_successful_disassembly(self):
        result = ScriptResult(
            success=True,
            data={
                "ea": "0x401000",
                "raw_bytes": "55",
                "mnemonic": "push",
                "operands": "ebp",
                "comment": "function prologue",
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        instr = await disassemble_at(sm, bridge, "sess1", "0x401000")

        assert isinstance(instr, InstructionInfo)
        assert instr.ea == "0x401000"
        assert instr.raw_bytes == "55"
        assert instr.mnemonic == "push"
        assert instr.operands == "ebp"
        assert instr.comment == "function prologue"

    @pytest.mark.asyncio
    async def test_no_comment_returns_none(self):
        result = ScriptResult(
            success=True,
            data={
                "ea": "0x401000",
                "raw_bytes": "55",
                "mnemonic": "push",
                "operands": "ebp",
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        instr = await disassemble_at(sm, bridge, "sess1", "0x401000")
        assert instr.comment is None

    @pytest.mark.asyncio
    async def test_invalid_ea_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await disassemble_at(sm, bridge, "sess1", "not_an_address")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "disassemble_at"

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "IDA error"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await disassemble_at(sm, bridge, "sess1", "0x401000")
        assert exc_info.value.code == ErrorCode.FUNCTION_NOT_FOUND
        assert exc_info.value.tool_name == "disassemble_at"

    @pytest.mark.asyncio
    async def test_ea_passed_as_int_to_bridge(self):
        result = ScriptResult(
            success=True,
            data={
                "ea": "0x401000",
                "raw_bytes": "55",
                "mnemonic": "push",
                "operands": "ebp",
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await disassemble_at(sm, bridge, "sess1", "0x401000")
        assert bridge.last_operation == "disassemble_at"
        assert bridge.last_params == {"ea": 0x401000}

    @pytest.mark.asyncio
    async def test_decimal_ea_accepted(self):
        result = ScriptResult(
            success=True,
            data={
                "ea": "0x100",
                "raw_bytes": "90",
                "mnemonic": "nop",
                "operands": "",
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await disassemble_at(sm, bridge, "sess1", "256")
        assert bridge.last_params == {"ea": 256}

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(
            success=True,
            data={
                "ea": "0x401000",
                "raw_bytes": "55",
                "mnemonic": "push",
                "operands": "ebp",
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await disassemble_at(sm, bridge, "my_session_42", "0x401000")
        assert sm.last_session_id == "my_session_42"


# ---------------------------------------------------------------------------
# disassemble_range
# ---------------------------------------------------------------------------


class TestDisassembleRange:
    """Tests for disassemble_range tool handler."""

    @pytest.mark.asyncio
    async def test_returns_multiple_instructions(self):
        result = ScriptResult(
            success=True,
            data={
                "instructions": [
                    {"ea": "0x401000", "raw_bytes": "55", "mnemonic": "push", "operands": "ebp", "comment": None},
                    {"ea": "0x401001", "raw_bytes": "89e5", "mnemonic": "mov", "operands": "ebp, esp", "comment": None},
                    {"ea": "0x401003", "raw_bytes": "c3", "mnemonic": "ret", "operands": "", "comment": "return"},
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        instrs = await disassemble_range(sm, bridge, "sess1", "0x401000", "0x401004")

        assert len(instrs) == 3
        assert all(isinstance(i, InstructionInfo) for i in instrs)
        assert instrs[0].mnemonic == "push"
        assert instrs[1].mnemonic == "mov"
        assert instrs[2].comment == "return"

    @pytest.mark.asyncio
    async def test_empty_range(self):
        result = ScriptResult(success=True, data={"instructions": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        instrs = await disassemble_range(sm, bridge, "sess1", "0x401000", "0x401000")
        assert instrs == []

    @pytest.mark.asyncio
    async def test_invalid_start_ea_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await disassemble_range(sm, bridge, "sess1", "bad", "0x401100")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS
        assert exc_info.value.tool_name == "disassemble_range"

    @pytest.mark.asyncio
    async def test_invalid_end_ea_raises_error(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await disassemble_range(sm, bridge, "sess1", "0x401000", "xyz")
        assert exc_info.value.code == ErrorCode.INVALID_ADDRESS

    @pytest.mark.asyncio
    async def test_eas_passed_as_ints_to_bridge(self):
        result = ScriptResult(success=True, data={"instructions": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await disassemble_range(sm, bridge, "sess1", "0x401000", "0x401100")
        assert bridge.last_operation == "disassemble_range"
        assert bridge.last_params == {"start_ea": 0x401000, "end_ea": 0x401100}

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Range error"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await disassemble_range(sm, bridge, "sess1", "0x401000", "0x401100")
        assert exc_info.value.code == ErrorCode.FUNCTION_NOT_FOUND


# ---------------------------------------------------------------------------
# disassemble_function
# ---------------------------------------------------------------------------


class TestDisassembleFunction:
    """Tests for disassemble_function tool handler."""

    @pytest.mark.asyncio
    async def test_with_ea_input(self):
        result = ScriptResult(
            success=True,
            data={
                "instructions": [
                    {"ea": "0x401000", "raw_bytes": "55", "mnemonic": "push", "operands": "ebp", "comment": None},
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        instrs = await disassemble_function(sm, bridge, "sess1", "0x401000")

        assert len(instrs) == 1
        assert instrs[0].mnemonic == "push"
        assert bridge.last_params == {"ea": 0x401000}

    @pytest.mark.asyncio
    async def test_with_function_name_input(self):
        result = ScriptResult(
            success=True,
            data={
                "instructions": [
                    {"ea": "0x401000", "raw_bytes": "55", "mnemonic": "push", "operands": "ebp", "comment": None},
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        instrs = await disassemble_function(sm, bridge, "sess1", "main")

        assert len(instrs) == 1
        assert bridge.last_params == {"function_name": "main"}

    @pytest.mark.asyncio
    async def test_function_not_found_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "No function at 0x999"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await disassemble_function(sm, bridge, "sess1", "0x999")
        assert exc_info.value.code == ErrorCode.FUNCTION_NOT_FOUND
        assert exc_info.value.tool_name == "disassemble_function"

    @pytest.mark.asyncio
    async def test_script_failure_no_error_dict(self):
        result = ScriptResult(success=False, data="something went wrong")
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await disassemble_function(sm, bridge, "sess1", "0x401000")
        assert exc_info.value.code == ErrorCode.FUNCTION_NOT_FOUND

    @pytest.mark.asyncio
    async def test_script_failure_empty_data(self):
        result = ScriptResult(success=False, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await disassemble_function(sm, bridge, "sess1", "main")
        assert exc_info.value.code == ErrorCode.FUNCTION_NOT_FOUND

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(
            success=True,
            data={"instructions": []},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await disassemble_function(sm, bridge, "session_99", "main")
        assert sm.last_session_id == "session_99"

    @pytest.mark.asyncio
    async def test_decimal_ea_treated_as_ea(self):
        """A decimal string like '256' should be parsed as EA, not name."""
        result = ScriptResult(
            success=True,
            data={"instructions": []},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await disassemble_function(sm, bridge, "sess1", "256")
        assert bridge.last_params == {"ea": 256}
