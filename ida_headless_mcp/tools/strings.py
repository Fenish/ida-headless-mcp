"""String extraction and search tool handlers.

Each handler validates inputs, builds an IDAPython script via the bridge,
executes it through the session manager, and parses the result into typed
model dataclasses.

Requirements: 8.1, 8.2, 8.3, 8.4
"""

from __future__ import annotations

import fnmatch
from typing import TYPE_CHECKING

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import StringInfo, StringResults, XrefInfo, parse_ea

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


async def list_strings(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    filter_pattern: str | None = None,
    offset: int = 0,
    limit: int = 100,
) -> StringResults:
    """List strings in the binary with optional filtering and pagination.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        filter_pattern: Optional glob pattern to filter string values.
        offset: Number of results to skip (for pagination).
        limit: Maximum number of results to return.

    Returns:
        A :class:`StringResults` instance with paginated string data.

    Raises:
        McpToolError: On script execution failure.
    """
    params: dict = {}
    if filter_pattern is not None:
        params["filter_pattern"] = filter_pattern
    params["offset"] = offset
    params["limit"] = limit

    script = bridge.build_script("list_strings", params)
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "list_strings")

    data = result.data or {}
    raw_strings = data.get("strings", [])

    all_strings = [
        StringInfo(
            ea=s["ea"],
            value=s["value"],
            length=s["length"],
            string_type=s["string_type"],
        )
        for s in raw_strings
    ]

    # Apply client-side filter (in case the bridge didn't filter)
    if filter_pattern is not None:
        all_strings = [
            s for s in all_strings if fnmatch.fnmatch(s.value, filter_pattern)
        ]

    total_count = len(all_strings)

    # Apply pagination
    paginated = all_strings[offset : offset + limit]

    return StringResults(
        strings=paginated,
        total_count=total_count,
        offset=offset,
        limit=limit,
    )


async def get_string_xrefs(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
) -> list[XrefInfo]:
    """Get all cross-references to a string at the given EA.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address of the string (hex or decimal string).

    Returns:
        A list of :class:`XrefInfo` instances.

    Raises:
        McpToolError: If the EA is invalid or script execution fails.
    """
    ea_int = _validate_ea(ea, "get_string_xrefs")

    script = bridge.build_script("get_string_xrefs", {"ea": ea_int})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "get_string_xrefs")

    data = result.data or {}
    raw_xrefs = data.get("xrefs", [])
    return [
        XrefInfo(
            source_ea=x["source_ea"],
            target_ea=x["target_ea"],
            xref_type=x["xref_type"],
            source_function=x.get("source_function"),
            target_function=x.get("target_function"),
        )
        for x in raw_xrefs
    ]
