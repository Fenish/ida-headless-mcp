"""Call graph tool handlers.

Each handler validates inputs, builds an IDAPython script via the bridge,
executes it through the session manager, and parses the result into typed
model dataclasses.

Requirements: 21.1, 21.2, 21.3
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import (
    CallGraphNode,
    FunctionRef,
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


def _parse_call_graph_node(data: dict) -> CallGraphNode:
    """Recursively parse a nested dict into a :class:`CallGraphNode` tree.

    Args:
        data: A dict with ``ea``, ``name``, and optional ``children`` keys.

    Returns:
        A :class:`CallGraphNode` with recursively parsed children.
    """
    children = [
        _parse_call_graph_node(child) for child in data.get("children", [])
    ]
    return CallGraphNode(
        ea=data.get("ea", ""),
        name=data.get("name", ""),
        children=children,
    )


async def get_callers(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
) -> list[FunctionRef]:
    """Return all functions that call the function at *ea*.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address (hex or decimal string).

    Returns:
        A list of :class:`FunctionRef` representing callers.

    Raises:
        McpToolError: If the EA is invalid or the script fails.
    """
    ea_int = _validate_ea(ea, "get_callers")

    script = bridge.build_script("get_callers", {"ea": ea_int})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "get_callers")

    data = result.data or {}
    raw_callers = data.get("callers", [])

    return [
        FunctionRef(ea=c["ea"], name=c["name"])
        for c in raw_callers
    ]


async def get_callees(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
) -> list[FunctionRef]:
    """Return all functions called by the function at *ea*.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address (hex or decimal string).

    Returns:
        A list of :class:`FunctionRef` representing callees.

    Raises:
        McpToolError: If the EA is invalid or the script fails.
    """
    ea_int = _validate_ea(ea, "get_callees")

    script = bridge.build_script("get_callees", {"ea": ea_int})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "get_callees")

    data = result.data or {}
    raw_callees = data.get("callees", [])

    return [
        FunctionRef(ea=c["ea"], name=c["name"])
        for c in raw_callees
    ]


async def get_call_graph(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
    depth: int = 3,
) -> CallGraphNode:
    """Return a recursive call tree rooted at the function at *ea*.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address (hex or decimal string).
        depth: Maximum depth of the call tree (must be > 0).

    Returns:
        A :class:`CallGraphNode` tree up to *depth* levels deep.

    Raises:
        McpToolError: If the EA is invalid, depth <= 0, or the script fails.
    """
    ea_int = _validate_ea(ea, "get_call_graph")

    if depth <= 0:
        raise McpToolError(
            code=ErrorCode.INVALID_PARAMETER,
            message="Depth must be greater than 0",
            tool_name="get_call_graph",
        )

    script = bridge.build_script(
        "get_call_graph", {"ea": ea_int, "depth": depth}
    )
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "get_call_graph")

    data = result.data or {}
    return _parse_call_graph_node(data)
