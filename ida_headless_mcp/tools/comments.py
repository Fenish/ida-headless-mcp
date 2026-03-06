"""Comment and annotation tool handlers.

Each handler validates inputs, builds an IDAPython script via the bridge,
executes it through the session manager, and parses the result into typed
model dataclasses.

Requirements: 12.1, 12.2, 12.3, 12.4, 12.5
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import (
    CommentInfo,
    OperationResult,
    parse_ea,
)

if TYPE_CHECKING:
    from ida_headless_mcp.ida_bridge import IdaBridge, ScriptResult

_VALID_COMMENT_TYPES = {"regular", "repeatable", "function"}


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


async def set_comment(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
    comment: str,
    comment_type: str = "regular",
) -> OperationResult:
    """Set a comment at the given EA.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address (hex or decimal string).
        comment: The comment text to set.
        comment_type: One of ``"regular"``, ``"repeatable"``, or ``"function"``.

    Returns:
        An :class:`OperationResult` indicating success or failure.

    Raises:
        McpToolError: If the EA is invalid, comment_type is unknown, or
            the script fails.
    """
    ea_int = _validate_ea(ea, "set_comment")

    if comment_type not in _VALID_COMMENT_TYPES:
        raise McpToolError(
            code=ErrorCode.INVALID_PARAMETER,
            message=f"Unknown comment type: {comment_type}. Must be one of {sorted(_VALID_COMMENT_TYPES)}",
            tool_name="set_comment",
        )

    script = bridge.build_script(
        "set_comment",
        {"ea": ea_int, "comment": comment, "comment_type": comment_type},
    )
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "set_comment")

    data = result.data or {}
    return OperationResult(
        success=result.success,
        message=data.get("message", ""),
    )


async def get_comments(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
) -> CommentInfo:
    """Get all comment types at the given EA.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address (hex or decimal string).

    Returns:
        A :class:`CommentInfo` with regular, repeatable, and function comment
        fields populated (or ``None`` where no comment exists).

    Raises:
        McpToolError: If the EA is invalid or the script fails.
    """
    ea_int = _validate_ea(ea, "get_comments")

    script = bridge.build_script("get_comments", {"ea": ea_int})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "get_comments")

    data = result.data or {}
    return CommentInfo(
        ea=data.get("ea", ea),
        regular=data.get("regular"),
        repeatable=data.get("repeatable"),
        function_comment=data.get("function_comment"),
    )


async def get_comments_range(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    start_ea: str,
    end_ea: str,
) -> list[CommentInfo]:
    """Get all comments within an address range.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        start_ea: Start of the address range (inclusive).
        end_ea: End of the address range (exclusive).

    Returns:
        A list of :class:`CommentInfo` for addresses with comments in the range.

    Raises:
        McpToolError: If either EA is invalid or the script fails.
    """
    start_int = _validate_ea(start_ea, "get_comments_range")
    end_int = _validate_ea(end_ea, "get_comments_range")

    script = bridge.build_script(
        "get_comments_range",
        {"start_ea": start_int, "end_ea": end_int},
    )
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "get_comments_range")

    data = result.data or {}
    raw_comments = data.get("comments", [])

    return [
        CommentInfo(
            ea=c["ea"],
            regular=c.get("regular"),
            repeatable=c.get("repeatable"),
            function_comment=c.get("function_comment"),
        )
        for c in raw_comments
    ]
