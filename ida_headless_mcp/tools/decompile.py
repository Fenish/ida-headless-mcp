"""Decompilation tool handlers.

Each handler validates inputs, builds an IDAPython script via the bridge,
executes it through the session manager, and parses the result into typed
model dataclasses.

Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import DecompileResult, parse_ea

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
    """Raise McpToolError if the script execution failed.

    For decompilation, checks for DECOMPILER_UNAVAILABLE first, then falls
    back to DECOMPILATION_FAILED.
    """
    if not result.success:
        error_data = result.data or {}
        if isinstance(error_data, dict) and "error" in error_data:
            err = error_data["error"]
            code = err.get("code", "")
            msg = err.get("message", "Unknown error")
            if code == ErrorCode.DECOMPILER_UNAVAILABLE:
                raise McpToolError(
                    code=ErrorCode.DECOMPILER_UNAVAILABLE,
                    message=msg,
                    tool_name=tool_name,
                )
        else:
            msg = str(error_data) if error_data else "Decompilation failed"
        raise McpToolError(
            code=ErrorCode.DECOMPILATION_FAILED,
            message=msg,
            tool_name=tool_name,
        )


async def decompile_function(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
    var_hints: dict[str, str] | None = None,
) -> DecompileResult:
    """Decompile a function at the given EA into C-like pseudocode.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address of the function (hex or decimal string).
        var_hints: Optional mapping of original variable names to desired
            names.  When provided, the decompile script will rename
            variables in the output accordingly.

    Returns:
        A :class:`DecompileResult` instance with pseudocode and metadata.

    Raises:
        McpToolError: If the EA is invalid, the decompiler is unavailable,
            or decompilation fails.
    """
    ea_int = _validate_ea(ea, "decompile_function")

    params: dict = {"ea": ea_int}
    if var_hints is not None:
        params["var_hints"] = var_hints

    script = bridge.build_script("decompile_function", params)
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "decompile_function")

    data = result.data or {}
    return DecompileResult(
        ea=data["ea"],
        name=data["name"],
        pseudocode=data["pseudocode"],
        parameter_types=data.get("parameter_types", []),
    )
