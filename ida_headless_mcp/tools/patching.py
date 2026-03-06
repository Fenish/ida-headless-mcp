"""Patching and byte manipulation tool handlers.

Each handler validates inputs, builds an IDAPython script via the bridge,
executes it through the session manager, and parses the result into typed
model dataclasses.

Requirements: 13.1, 13.2, 13.3, 13.4, 13.5
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import (
    OperationResult,
    PatchInfo,
    parse_ea,
)

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
    """Raise McpToolError if the script execution failed.

    Checks for ADDRESS_UNMAPPED error code when the error message indicates
    an unmapped address, otherwise falls back to INVALID_PARAMETER.
    """
    if not result.success:
        error_data = result.data or {}
        if isinstance(error_data, dict) and "error" in error_data:
            err = error_data["error"]
            msg = err.get("message", "Unknown error")
        else:
            msg = str(error_data) if error_data else "Script execution failed"

        # Detect unmapped address errors
        if "unmapped" in msg.lower():
            code = ErrorCode.ADDRESS_UNMAPPED
        else:
            code = ErrorCode.INVALID_PARAMETER

        raise McpToolError(
            code=code,
            message=msg,
            tool_name=tool_name,
        )


async def read_bytes(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
    length: int,
) -> str:
    """Read raw bytes at the given EA as a hex string.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address to read from (hex or decimal string).
        length: Number of bytes to read.

    Returns:
        A hex string of the raw bytes (e.g. ``"90cc41"``).

    Raises:
        McpToolError: If the EA is invalid, the address is unmapped, or
            the script fails.
    """
    ea_int = _validate_ea(ea, "read_bytes")

    script = bridge.build_script("read_bytes", {"ea": ea_int, "length": length})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "read_bytes")

    data = result.data or {}
    return data.get("hex_bytes", "")


async def patch_bytes(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
    hex_values: str,
) -> OperationResult:
    """Write bytes to the IDB at the given EA.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address to patch (hex or decimal string).
        hex_values: Hex string of bytes to write (e.g. ``"90cc"``).

    Returns:
        An :class:`OperationResult` indicating success or failure.

    Raises:
        McpToolError: If the EA is invalid, the address is unmapped, or
            the script fails.
    """
    ea_int = _validate_ea(ea, "patch_bytes")

    script = bridge.build_script(
        "patch_bytes", {"ea": ea_int, "hex_values": hex_values}
    )
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "patch_bytes")

    data = result.data or {}
    return OperationResult(
        success=result.success,
        message=data.get("message", ""),
    )


async def assemble_and_patch(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
    assembly: str,
) -> OperationResult:
    """Assemble an instruction and patch it at the given EA.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address to patch (hex or decimal string).
        assembly: Assembly instruction string (e.g. ``"nop"``).

    Returns:
        An :class:`OperationResult` indicating success or failure.

    Raises:
        McpToolError: If the EA is invalid, the address is unmapped,
            assembly fails, or the script fails.
    """
    ea_int = _validate_ea(ea, "assemble_and_patch")

    script = bridge.build_script(
        "assemble_and_patch", {"ea": ea_int, "assembly": assembly}
    )
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "assemble_and_patch")

    data = result.data or {}
    return OperationResult(
        success=result.success,
        message=data.get("message", ""),
    )


async def list_patches(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
) -> list[PatchInfo]:
    """List all patched addresses with original and patched byte values.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.

    Returns:
        A list of :class:`PatchInfo` instances.

    Raises:
        McpToolError: If the script fails.
    """
    script = bridge.build_script("list_patches", {})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "list_patches")

    data = result.data or {}
    raw_patches = data.get("patches", [])

    return [
        PatchInfo(
            ea=p["ea"],
            original_byte=p["original_byte"],
            patched_byte=p["patched_byte"],
        )
        for p in raw_patches
    ]
