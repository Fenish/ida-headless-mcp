"""Function listing and management tool handlers.

Each handler validates inputs, builds an IDAPython script via the bridge,
executes it through the session manager, and parses the result into typed
model dataclasses.

Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7
"""

from __future__ import annotations

import fnmatch
from typing import TYPE_CHECKING

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import (
    FunctionDetails,
    FunctionInfo,
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
            code=ErrorCode.FUNCTION_NOT_FOUND,
            message=msg,
            tool_name=tool_name,
        )


async def list_functions(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    filter_pattern: str | None = None,
) -> list[FunctionInfo]:
    """List all recognised functions, optionally filtered by name pattern.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        filter_pattern: Optional glob pattern to filter function names.

    Returns:
        A list of :class:`FunctionInfo` instances.

    Raises:
        McpToolError: On script execution failure.
    """
    params: dict = {}
    if filter_pattern is not None:
        params["filter_pattern"] = filter_pattern

    script = bridge.build_script("list_functions", params)
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "list_functions")

    data = result.data or {}
    raw_functions = data.get("functions", [])

    functions = [
        FunctionInfo(
            ea=f["ea"],
            name=f["name"],
            end_ea=f["end_ea"],
            size=f["size"],
        )
        for f in raw_functions
    ]

    # Apply client-side filter as well (in case the bridge didn't filter)
    if filter_pattern is not None:
        functions = [
            f for f in functions if fnmatch.fnmatch(f.name, filter_pattern)
        ]

    return functions


async def get_function_details(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
) -> FunctionDetails:
    """Get detailed information about a function at the given EA.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address of the function (hex or decimal string).

    Returns:
        A :class:`FunctionDetails` instance.

    Raises:
        McpToolError: If the EA is invalid or no function exists there.
    """
    ea_int = _validate_ea(ea, "get_function_details")

    script = bridge.build_script("get_function_details", {"ea": ea_int})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "get_function_details")

    data = result.data or {}
    return FunctionDetails(
        ea=data["ea"],
        name=data["name"],
        end_ea=data["end_ea"],
        size=data["size"],
        num_blocks=data.get("num_blocks", 0),
        calling_convention=data.get("calling_convention", ""),
        frame_size=data.get("frame_size", 0),
    )


async def rename_function(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
    new_name: str,
) -> OperationResult:
    """Rename a function at the given EA.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address of the function.
        new_name: The new name to assign.

    Returns:
        An :class:`OperationResult` indicating success or failure.

    Raises:
        McpToolError: If the EA is invalid or no function exists there.
    """
    ea_int = _validate_ea(ea, "rename_function")

    script = bridge.build_script(
        "rename_function", {"ea": ea_int, "new_name": new_name}
    )
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "rename_function")

    data = result.data or {}
    return OperationResult(
        success=result.success,
        message=data.get("message", ""),
    )


async def create_function(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
) -> OperationResult:
    """Create a new function at the given EA.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address where the function should start.

    Returns:
        An :class:`OperationResult` indicating success or failure.

    Raises:
        McpToolError: If the EA is invalid.
    """
    ea_int = _validate_ea(ea, "create_function")

    script = bridge.build_script("create_function", {"ea": ea_int})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "create_function")

    data = result.data or {}
    return OperationResult(
        success=result.success,
        message=data.get("message", ""),
    )


async def delete_function(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
) -> OperationResult:
    """Delete the function at the given EA.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address of the function to delete.

    Returns:
        An :class:`OperationResult` indicating success or failure.

    Raises:
        McpToolError: If the EA is invalid or no function exists there.
    """
    ea_int = _validate_ea(ea, "delete_function")

    script = bridge.build_script("delete_function", {"ea": ea_int})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "delete_function")

    data = result.data or {}
    return OperationResult(
        success=result.success,
        message=data.get("message", ""),
    )
