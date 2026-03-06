"""Bookmark tool handlers — manage marked positions in the IDB.

Each handler validates inputs, builds an IDAPython script via the bridge,
executes it through the session manager, and parses the result.

Requirements: 16.1, 16.2, 16.3
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import (
    BookmarkInfo,
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


async def add_bookmark(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
    description: str,
) -> OperationResult:
    """Add a marked position (bookmark) at the given EA.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address (hex or decimal string).
        description: Bookmark description text.

    Returns:
        An :class:`OperationResult` indicating success or failure.

    Raises:
        McpToolError: If the EA is invalid, description is empty, or the
            script fails.
    """
    ea_int = _validate_ea(ea, "add_bookmark")

    if not description or not description.strip():
        raise McpToolError(
            code=ErrorCode.INVALID_PARAMETER,
            message="Bookmark description must not be empty",
            tool_name="add_bookmark",
        )

    script = bridge.build_script(
        "add_bookmark",
        {"ea": ea_int, "description": description},
    )
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "add_bookmark")

    data = result.data or {}
    return OperationResult(
        success=result.success,
        message=data.get("message", ""),
    )


async def list_bookmarks(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
) -> list[BookmarkInfo]:
    """List all bookmarks (marked positions) in the current IDB.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.

    Returns:
        A list of :class:`BookmarkInfo` with EA and description.

    Raises:
        McpToolError: If the script fails.
    """
    script = bridge.build_script("list_bookmarks", {})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "list_bookmarks")

    data = result.data or {}
    raw_bookmarks = data.get("bookmarks", [])

    return [
        BookmarkInfo(
            ea=b["ea"],
            description=b.get("description", ""),
        )
        for b in raw_bookmarks
    ]


async def delete_bookmark(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
) -> OperationResult:
    """Delete a bookmark (marked position) at the given EA.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address (hex or decimal string).

    Returns:
        An :class:`OperationResult` indicating success or failure.

    Raises:
        McpToolError: If the EA is invalid or the script fails.
    """
    ea_int = _validate_ea(ea, "delete_bookmark")

    script = bridge.build_script(
        "delete_bookmark",
        {"ea": ea_int},
    )
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "delete_bookmark")

    data = result.data or {}
    return OperationResult(
        success=result.success,
        message=data.get("message", ""),
    )
