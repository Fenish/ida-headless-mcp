"""Search tool handlers — byte pattern, text, and immediate value search.

Each handler validates inputs, builds an IDAPython script via the bridge,
executes it through the session manager, and parses the result into a list
of EA hex strings.

Requirements: 14.1, 14.2, 14.3, 14.4, 14.5
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import parse_ea

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


# Regex for validating byte patterns: hex byte pairs or ?? wildcards
_BYTE_PATTERN_RE = re.compile(r"^([0-9a-fA-F]{2}|\?\?)(\s+([0-9a-fA-F]{2}|\?\?))*$")


def _validate_byte_pattern(pattern: str, tool_name: str) -> None:
    """Validate a byte search pattern, raising INVALID_PARAMETER on bad input."""
    stripped = pattern.strip()
    if not stripped:
        raise McpToolError(
            code=ErrorCode.INVALID_PARAMETER,
            message="Byte pattern must not be empty",
            tool_name=tool_name,
        )
    if not _BYTE_PATTERN_RE.match(stripped):
        raise McpToolError(
            code=ErrorCode.INVALID_PARAMETER,
            message=f"Invalid byte pattern: {pattern!r}. Expected hex bytes (e.g. 'AA BB ?? CC').",
            tool_name=tool_name,
        )


async def search_bytes(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    pattern: str,
    start_ea: str | None = None,
    end_ea: str | None = None,
    max_results: int = 100,
) -> list[str]:
    """Search for a byte pattern with wildcard support.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        pattern: Hex byte pattern with ``??`` wildcards (e.g. ``"AA BB ?? CC"``).
        start_ea: Optional start address to constrain the search range.
        end_ea: Optional end address to constrain the search range.
        max_results: Maximum number of results to return.

    Returns:
        A list of EA hex strings where the pattern was found.

    Raises:
        McpToolError: If the pattern is invalid, an EA is invalid, or the
            script fails.
    """
    _validate_byte_pattern(pattern, "search_bytes")

    params: dict = {"pattern": pattern, "max_results": max_results}

    if start_ea is not None:
        params["start_ea"] = _validate_ea(start_ea, "search_bytes")
    if end_ea is not None:
        params["end_ea"] = _validate_ea(end_ea, "search_bytes")

    script = bridge.build_script("search_bytes", params)
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "search_bytes")

    data = result.data or {}
    results = data.get("results", [])
    return results[:max_results]


async def search_text(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    text: str,
    start_ea: str | None = None,
    end_ea: str | None = None,
    max_results: int = 100,
) -> list[str]:
    """Search for a text string in the binary.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        text: The text string to search for.
        start_ea: Optional start address to constrain the search range.
        end_ea: Optional end address to constrain the search range.
        max_results: Maximum number of results to return.

    Returns:
        A list of EA hex strings where the text was found.

    Raises:
        McpToolError: If the text is empty, an EA is invalid, or the
            script fails.
    """
    if not text:
        raise McpToolError(
            code=ErrorCode.INVALID_PARAMETER,
            message="Search text must not be empty",
            tool_name="search_text",
        )

    params: dict = {"text": text, "max_results": max_results}

    if start_ea is not None:
        params["start_ea"] = _validate_ea(start_ea, "search_text")
    if end_ea is not None:
        params["end_ea"] = _validate_ea(end_ea, "search_text")

    script = bridge.build_script("search_text", params)
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "search_text")

    data = result.data or {}
    results = data.get("results", [])
    return results[:max_results]


async def search_immediate(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    value: int,
    start_ea: str | None = None,
    end_ea: str | None = None,
    max_results: int = 100,
) -> list[str]:
    """Search for an immediate operand value in instructions.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        value: The immediate integer value to search for.
        start_ea: Optional start address to constrain the search range.
        end_ea: Optional end address to constrain the search range.
        max_results: Maximum number of results to return.

    Returns:
        A list of EA hex strings where the immediate value was found.

    Raises:
        McpToolError: If an EA is invalid or the script fails.
    """
    params: dict = {"value": value, "max_results": max_results}

    if start_ea is not None:
        params["start_ea"] = _validate_ea(start_ea, "search_immediate")
    if end_ea is not None:
        params["end_ea"] = _validate_ea(end_ea, "search_immediate")

    script = bridge.build_script("search_immediate", params)
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "search_immediate")

    data = result.data or {}
    results = data.get("results", [])
    return results[:max_results]
