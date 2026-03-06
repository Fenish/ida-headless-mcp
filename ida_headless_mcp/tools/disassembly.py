"""Disassembly tool handlers.

Each handler validates inputs, builds an IDAPython script via the bridge,
executes it through the session manager, and parses the result into typed
model dataclasses.

Requirements: 6.1, 6.2, 6.3, 6.4
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import InstructionInfo, parse_ea

if TYPE_CHECKING:
    from ida_headless_mcp.ida_bridge import IdaBridge, ScriptResult


def _validate_ea(ea_str: str, tool_name: str) -> int:
    """Parse and validate an EA string, raising McpToolError on failure."""
    try:
        return parse_ea(ea_str)
    except ValueError:
        raise McpToolError(
            code=ErrorCode.INVALID_ADDRESS,
            message=f"Invalid address: {ea_str}",
            tool_name=tool_name,
        )


def _check_script_success(result: "ScriptResult", tool_name: str) -> None:
    """Raise McpToolError if the script execution failed."""
    if not result.success:
        error_data = result.data or {}
        if isinstance(error_data, dict) and "error" in error_data:
            err = error_data["error"]
            msg = err.get("message", "Unknown error")
        else:
            msg = str(error_data) if error_data else "Script execution failed"
        raise McpToolError(
            code=ErrorCode.FUNCTION_NOT_FOUND,
            message=msg,
            tool_name=tool_name,
        )


def _parse_instruction(raw: dict) -> InstructionInfo:
    """Parse a raw instruction dict into an InstructionInfo dataclass."""
    return InstructionInfo(
        ea=raw["ea"],
        raw_bytes=raw["raw_bytes"],
        mnemonic=raw["mnemonic"],
        operands=raw["operands"],
        comment=raw.get("comment"),
    )


async def disassemble_at(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
) -> InstructionInfo:
    """Disassemble a single instruction at the given EA.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address of the instruction (hex or decimal string).

    Returns:
        An :class:`InstructionInfo` instance.

    Raises:
        McpToolError: If the EA is invalid or script execution fails.
    """
    ea_int = _validate_ea(ea, "disassemble_at")

    script = bridge.build_script("disassemble_at", {"ea": ea_int})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "disassemble_at")

    data = result.data or {}
    return _parse_instruction(data)


async def disassemble_range(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    start_ea: str,
    end_ea: str,
) -> list[InstructionInfo]:
    """Disassemble all instructions in an address range.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        start_ea: Start of the address range (hex or decimal string).
        end_ea: End of the address range (hex or decimal string).

    Returns:
        A list of :class:`InstructionInfo` instances.

    Raises:
        McpToolError: If either EA is invalid or script execution fails.
    """
    start_int = _validate_ea(start_ea, "disassemble_range")
    end_int = _validate_ea(end_ea, "disassemble_range")

    script = bridge.build_script(
        "disassemble_range", {"start_ea": start_int, "end_ea": end_int}
    )
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "disassemble_range")

    data = result.data or {}
    raw_instructions = data.get("instructions", [])
    return [_parse_instruction(raw) for raw in raw_instructions]


async def disassemble_function(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    function_name_or_ea: str,
) -> list[InstructionInfo]:
    """Disassemble all instructions in a function.

    The *function_name_or_ea* argument is first parsed as an EA.  If that
    fails it is treated as a function name and resolved via a name-lookup
    script.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        function_name_or_ea: Either a hex/decimal EA or a function name.

    Returns:
        A list of :class:`InstructionInfo` instances.

    Raises:
        McpToolError: If the function cannot be found or script execution
            fails.
    """
    # Try to parse as EA first; if that fails, treat as function name.
    try:
        ea_int = parse_ea(function_name_or_ea)
        params: dict = {"ea": ea_int}
    except ValueError:
        params = {"function_name": function_name_or_ea}

    script = bridge.build_script("disassemble_function", params)
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "disassemble_function")

    data = result.data or {}
    raw_instructions = data.get("instructions", [])
    return [_parse_instruction(raw) for raw in raw_instructions]
