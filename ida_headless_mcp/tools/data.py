"""Data and names tool handlers.

Each handler validates inputs, builds an IDAPython script via the bridge,
executes it through the session manager, and parses the result into typed
model dataclasses.

Requirements: 20.1, 20.2, 20.3, 20.4
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import (
    DataTypeInfo,
    NameInfo,
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


async def list_names(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
) -> list[NameInfo]:
    """List all named locations in the current IDB.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.

    Returns:
        A list of :class:`NameInfo` with ea, name, and optional type.

    Raises:
        McpToolError: If the script fails.
    """
    script = bridge.build_script("list_names", {})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "list_names")

    data = result.data or {}
    raw_names = data.get("names", [])

    return [
        NameInfo(
            ea=n["ea"],
            name=n["name"],
            type=n.get("type"),
        )
        for n in raw_names
    ]


async def rename_location(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
    new_name: str,
) -> OperationResult:
    """Rename a location at the given EA.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address (hex or decimal string).
        new_name: The new name to assign.

    Returns:
        An :class:`OperationResult` indicating success or failure.

    Raises:
        McpToolError: If the EA is invalid, new_name is empty, or the
            script fails.
    """
    ea_int = _validate_ea(ea, "rename_location")

    if not new_name or not new_name.strip():
        raise McpToolError(
            code=ErrorCode.INVALID_PARAMETER,
            message="New name must not be empty",
            tool_name="rename_location",
        )

    script = bridge.build_script(
        "rename_location", {"ea": ea_int, "new_name": new_name}
    )
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "rename_location")

    data = result.data or {}
    return OperationResult(
        success=result.success,
        message=data.get("message", ""),
    )


async def get_data_type(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
) -> DataTypeInfo:
    """Get data type information at the given EA.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address (hex or decimal string).

    Returns:
        A :class:`DataTypeInfo` with ea, type_name, and size.

    Raises:
        McpToolError: If the EA is invalid or the script fails.
    """
    ea_int = _validate_ea(ea, "get_data_type")

    script = bridge.build_script("get_data_type", {"ea": ea_int})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "get_data_type")

    data = result.data or {}
    return DataTypeInfo(
        ea=data.get("ea", ea),
        type_name=data.get("type_name", ""),
        size=data.get("size", 0),
    )


async def set_data_type(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
    type_str: str,
) -> OperationResult:
    """Change the data type at the given EA.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address (hex or decimal string).
        type_str: The type string to apply (e.g. ``"dword"``, ``"byte"``).

    Returns:
        An :class:`OperationResult` indicating success or failure.

    Raises:
        McpToolError: If the EA is invalid, type_str is empty, or the
            script fails.
    """
    ea_int = _validate_ea(ea, "set_data_type")

    if not type_str or not type_str.strip():
        raise McpToolError(
            code=ErrorCode.INVALID_PARAMETER,
            message="Type string must not be empty",
            tool_name="set_data_type",
        )

    script = bridge.build_script(
        "set_data_type", {"ea": ea_int, "type_str": type_str}
    )
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "set_data_type")

    data = result.data or {}
    return OperationResult(
        success=result.success,
        message=data.get("message", ""),
    )
