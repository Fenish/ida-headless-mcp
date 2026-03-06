"""Cross-reference tool handlers.

Each handler validates inputs, builds an IDAPython script via the bridge,
executes it through the session manager, and parses the result into typed
model dataclasses.

Requirements: 7.1, 7.2, 7.3, 7.4
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import FunctionXrefs, XrefInfo, parse_ea

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


def _parse_xref(raw: dict) -> XrefInfo:
    """Parse a raw xref dict into an XrefInfo dataclass."""
    return XrefInfo(
        source_ea=raw["source_ea"],
        target_ea=raw["target_ea"],
        xref_type=raw["xref_type"],
        source_function=raw.get("source_function"),
        target_function=raw.get("target_function"),
    )


async def get_xrefs_to(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
) -> list[XrefInfo]:
    """Get all cross-references targeting the given EA.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address to query xrefs to (hex or decimal string).

    Returns:
        A list of :class:`XrefInfo` instances.

    Raises:
        McpToolError: If the EA is invalid or script execution fails.
    """
    ea_int = _validate_ea(ea, "get_xrefs_to")

    script = bridge.build_script("get_xrefs_to", {"ea": ea_int})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "get_xrefs_to")

    data = result.data or {}
    raw_xrefs = data.get("xrefs", [])
    return [_parse_xref(x) for x in raw_xrefs]


async def get_xrefs_from(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
) -> list[XrefInfo]:
    """Get all cross-references originating from the given EA.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address to query xrefs from (hex or decimal string).

    Returns:
        A list of :class:`XrefInfo` instances.

    Raises:
        McpToolError: If the EA is invalid or script execution fails.
    """
    ea_int = _validate_ea(ea, "get_xrefs_from")

    script = bridge.build_script("get_xrefs_from", {"ea": ea_int})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "get_xrefs_from")

    data = result.data or {}
    raw_xrefs = data.get("xrefs", [])
    return [_parse_xref(x) for x in raw_xrefs]


async def get_function_xrefs(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    function_name: str,
) -> FunctionXrefs:
    """Get callers and callees for a named function.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        function_name: Name of the function to query.

    Returns:
        A :class:`FunctionXrefs` instance with callers and callees.

    Raises:
        McpToolError: If script execution fails.
    """
    script = bridge.build_script(
        "get_function_xrefs", {"function_name": function_name}
    )
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "get_function_xrefs")

    data = result.data or {}
    raw_callers = data.get("callers", [])
    raw_callees = data.get("callees", [])
    return FunctionXrefs(
        callers=[_parse_xref(x) for x in raw_callers],
        callees=[_parse_xref(x) for x in raw_callees],
    )
