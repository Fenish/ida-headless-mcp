"""Signature tool handlers — FLIRT signature application and listing.

Each handler validates inputs, builds an IDAPython script via the bridge,
executes it through the session manager, and parses the result.

Requirements: 15.1, 15.2, 15.3, 15.4
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import SignatureResult

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


async def apply_signature(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    sig_file: str,
) -> SignatureResult:
    """Apply a FLIRT signature file to the current IDB.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        sig_file: Name of the .sig file to apply.

    Returns:
        A :class:`SignatureResult` with the file name and match count.

    Raises:
        McpToolError: If *sig_file* is empty or the script fails.
    """
    if not sig_file or not sig_file.strip():
        raise McpToolError(
            code=ErrorCode.INVALID_PARAMETER,
            message="Signature file name must not be empty",
            tool_name="apply_signature",
        )

    params = {"sig_file": sig_file}
    script = bridge.build_script("apply_signature", params)
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "apply_signature")

    data = result.data or {}
    return SignatureResult(
        sig_file=data.get("sig_file", sig_file),
        functions_matched=data.get("functions_matched", 0),
    )


async def list_applied_signatures(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
) -> list[str]:
    """List currently applied FLIRT signatures for a session.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.

    Returns:
        A list of applied signature file names.

    Raises:
        McpToolError: If the script fails.
    """
    script = bridge.build_script("list_applied_signatures", {})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "list_applied_signatures")

    data = result.data or {}
    return data.get("signatures", [])


async def list_available_signatures(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
) -> list[str]:
    """List available .sig files in the signatures directory.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.

    Returns:
        A list of available .sig file names.

    Raises:
        McpToolError: If the script fails.
    """
    script = bridge.build_script("list_available_signatures", {})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "list_available_signatures")

    data = result.data or {}
    return data.get("signatures", [])
