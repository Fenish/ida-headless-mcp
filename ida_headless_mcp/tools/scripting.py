"""Scripting tool handlers — execute arbitrary IDAPython scripts.

Each handler validates inputs, builds an IDAPython script via the bridge,
executes it through the session manager, and parses the result.

Requirements: 17.1, 17.2, 17.3, 17.4, 17.5
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ida_headless_mcp.errors import ErrorCode, McpToolError

if TYPE_CHECKING:
    from ida_headless_mcp.ida_bridge import IdaBridge, ScriptResult


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


def _build_response(result: "ScriptResult") -> dict[str, Any]:
    """Build the standard scripting response dict from a ScriptResult.

    Returns:
        A dict with stdout, return_value, exception info, and success flag.
    """
    data = result.data or {}
    exception_info = None
    if isinstance(data, dict) and "exception" in data:
        exc = data["exception"]
        exception_info = {
            "type": exc.get("type", ""),
            "message": exc.get("message", ""),
            "traceback": exc.get("traceback", ""),
        }

    return {
        "stdout": result.stdout,
        "return_value": result.return_value,
        "exception": exception_info,
        "success": result.success,
    }


async def execute_script(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    script: str,
    timeout: int = 30,
) -> dict[str, Any]:
    """Execute an inline IDAPython script in the given session.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        script: IDAPython script source code to execute.
        timeout: Maximum execution time in seconds.

    Returns:
        A dict with ``stdout``, ``return_value``, ``exception``, and
        ``success`` keys.

    Raises:
        McpToolError: If the script is empty, timeout is invalid, or
            execution fails.
    """
    if not script or not script.strip():
        raise McpToolError(
            code=ErrorCode.INVALID_PARAMETER,
            message="Script must not be empty",
            tool_name="execute_script",
        )

    if timeout is not None and timeout <= 0:
        raise McpToolError(
            code=ErrorCode.INVALID_PARAMETER,
            message="Timeout must be greater than 0",
            tool_name="execute_script",
        )

    built = bridge.build_script(
        "execute_script",
        {"script": script, "timeout": timeout},
    )
    result = await session_manager.execute_script(session_id, built)

    return _build_response(result)


async def execute_script_file(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    script_path: str,
    timeout: int = 30,
) -> dict[str, Any]:
    """Execute an IDAPython script from a file path in the given session.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        script_path: Path to the IDAPython script file.
        timeout: Maximum execution time in seconds.

    Returns:
        A dict with ``stdout``, ``return_value``, ``exception``, and
        ``success`` keys.

    Raises:
        McpToolError: If the script_path is empty, timeout is invalid, or
            execution fails.
    """
    if not script_path or not script_path.strip():
        raise McpToolError(
            code=ErrorCode.INVALID_PARAMETER,
            message="Script path must not be empty",
            tool_name="execute_script_file",
        )

    if timeout is not None and timeout <= 0:
        raise McpToolError(
            code=ErrorCode.INVALID_PARAMETER,
            message="Timeout must be greater than 0",
            tool_name="execute_script_file",
        )

    built = bridge.build_script(
        "execute_script_file",
        {"script_path": script_path, "timeout": timeout},
    )
    result = await session_manager.execute_script(session_id, built)

    return _build_response(result)
