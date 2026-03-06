"""Enum management tool handlers.

Each handler validates inputs, builds an IDAPython script via the bridge,
executes it through the session manager, and parses the result into typed
model dataclasses.

Requirements: 19.1, 19.2, 19.3, 19.4
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import (
    EnumInfo,
    OperationResult,
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
    """Raise McpToolError if the script execution failed."""
    if not result.success:
        error_data = result.data or {}
        if isinstance(error_data, dict) and "error" in error_data:
            err = error_data["error"]
            msg = err.get("message", "Unknown error")
        else:
            msg = str(error_data) if error_data else "Script execution failed"
        raise McpToolError(
            code=ErrorCode.INVALID_PARAMETER,
            message=msg,
            tool_name=tool_name,
        )


async def list_enums(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
) -> list[EnumInfo]:
    """List all defined enums in the current IDB.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.

    Returns:
        A list of :class:`EnumInfo` with name, member_count, and width.

    Raises:
        McpToolError: If the script fails.
    """
    script = bridge.build_script("list_enums", {})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "list_enums")

    data = result.data or {}
    raw_enums = data.get("enums", [])

    return [
        EnumInfo(
            name=e["name"],
            member_count=e["member_count"],
            width=e["width"],
        )
        for e in raw_enums
    ]


async def create_enum(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    name: str,
    members: list[dict],
) -> OperationResult:
    """Create a new enum with the given name and members.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        name: Name of the enum to create.
        members: List of dicts with ``name`` and ``value`` keys.

    Returns:
        An :class:`OperationResult` indicating success or failure.

    Raises:
        McpToolError: If name is empty or the script fails.
    """
    if not name or not name.strip():
        raise McpToolError(
            code=ErrorCode.INVALID_PARAMETER,
            message="Enum name must not be empty",
            tool_name="create_enum",
        )

    script = bridge.build_script(
        "create_enum", {"name": name, "members": members}
    )
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "create_enum")

    data = result.data or {}
    return OperationResult(
        success=result.success,
        message=data.get("message", ""),
    )


async def add_enum_member(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    enum_name: str,
    member_name: str,
    value: int,
) -> OperationResult:
    """Add a member to an existing enum.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        enum_name: Name of the enum to modify.
        member_name: Name of the new member.
        value: Integer value for the new member.

    Returns:
        An :class:`OperationResult` indicating success or failure.

    Raises:
        McpToolError: If enum_name or member_name is empty, or the script fails.
    """
    if not enum_name or not enum_name.strip():
        raise McpToolError(
            code=ErrorCode.INVALID_PARAMETER,
            message="Enum name must not be empty",
            tool_name="add_enum_member",
        )

    if not member_name or not member_name.strip():
        raise McpToolError(
            code=ErrorCode.INVALID_PARAMETER,
            message="Member name must not be empty",
            tool_name="add_enum_member",
        )

    script = bridge.build_script(
        "add_enum_member",
        {"enum_name": enum_name, "member_name": member_name, "value": value},
    )
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "add_enum_member")

    data = result.data or {}
    return OperationResult(
        success=result.success,
        message=data.get("message", ""),
    )


async def apply_enum(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
    operand: int,
    enum_name: str,
) -> OperationResult:
    """Apply an enum to an operand at the given EA.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address (hex or decimal string).
        operand: Operand index (0 or 1).
        enum_name: Name of the enum to apply.

    Returns:
        An :class:`OperationResult` indicating success or failure.

    Raises:
        McpToolError: If the EA is invalid, enum_name is empty, or the
            script fails.
    """
    ea_int = _validate_ea(ea, "apply_enum")

    if not enum_name or not enum_name.strip():
        raise McpToolError(
            code=ErrorCode.INVALID_PARAMETER,
            message="Enum name must not be empty",
            tool_name="apply_enum",
        )

    script = bridge.build_script(
        "apply_enum",
        {"ea": ea_int, "operand": operand, "enum_name": enum_name},
    )
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "apply_enum")

    data = result.data or {}
    return OperationResult(
        success=result.success,
        message=data.get("message", ""),
    )
