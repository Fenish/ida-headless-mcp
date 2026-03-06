"""Segment and section information tool handlers.

Each handler validates inputs, builds an IDAPython script via the bridge,
executes it through the session manager, and parses the result into typed
model dataclasses.

Requirements: 9.1, 9.2, 9.3
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import SegmentInfo, parse_ea

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


def _parse_segment(raw: dict) -> SegmentInfo:
    """Parse a raw segment dict into a SegmentInfo dataclass."""
    return SegmentInfo(
        name=raw["name"],
        start_ea=raw["start_ea"],
        end_ea=raw["end_ea"],
        size=raw["size"],
        permissions=raw["permissions"],
        seg_class=raw["seg_class"],
        bitness=raw["bitness"],
    )


async def list_segments(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
) -> list[SegmentInfo]:
    """List all segments in the binary with full attributes.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.

    Returns:
        A list of :class:`SegmentInfo` instances.

    Raises:
        McpToolError: On script execution failure.
    """
    script = bridge.build_script("list_segments", {})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "list_segments")

    data = result.data or {}
    raw_segments = data.get("segments", [])
    return [_parse_segment(s) for s in raw_segments]


async def get_segment(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    name_or_ea: str,
) -> SegmentInfo:
    """Get a segment by name or EA.

    Tries to parse *name_or_ea* as an effective address first.  If that
    fails, it is treated as a segment name.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        name_or_ea: Segment name or effective address string.

    Returns:
        A :class:`SegmentInfo` instance.

    Raises:
        McpToolError: On script execution failure.
    """
    params: dict = {}
    try:
        ea_int = parse_ea(name_or_ea)
        params["ea"] = ea_int
    except ValueError:
        params["name"] = name_or_ea

    script = bridge.build_script("get_segment", params)
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "get_segment")

    data = result.data or {}
    return _parse_segment(data)


async def get_segment_at(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
) -> SegmentInfo:
    """Get the segment containing the given EA.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address (hex or decimal string).

    Returns:
        A :class:`SegmentInfo` instance for the containing segment.

    Raises:
        McpToolError: If the EA is invalid or script execution fails.
    """
    ea_int = _validate_ea(ea, "get_segment_at")

    script = bridge.build_script("get_segment_at", {"ea": ea_int})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "get_segment_at")

    data = result.data or {}
    return _parse_segment(data)
