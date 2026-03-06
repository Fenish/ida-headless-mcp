"""Import and export table tool handlers.

Each handler validates inputs, builds an IDAPython script via the bridge,
executes it through the session manager, and parses the result into typed
model dataclasses.

Requirements: 10.1, 10.2, 10.3
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import ExportInfo, ImportInfo

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


async def list_imports(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    library: str | None = None,
) -> list[ImportInfo]:
    """List all imported functions, optionally filtered by library.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        library: Optional library name to filter imports by.

    Returns:
        A list of :class:`ImportInfo` instances.

    Raises:
        McpToolError: On script execution failure.
    """
    params: dict = {}
    if library is not None:
        params["library"] = library

    script = bridge.build_script("list_imports", params)
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "list_imports")

    data = result.data or {}
    raw_imports = data.get("imports", [])

    imports = [
        ImportInfo(
            library=imp["library"],
            name=imp["name"],
            ordinal=imp["ordinal"],
            ea=imp["ea"],
        )
        for imp in raw_imports
    ]

    # Apply client-side filtering as well (case-insensitive)
    if library is not None:
        imports = [
            imp for imp in imports
            if imp.library.lower() == library.lower()
        ]

    return imports


async def list_exports(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
) -> list[ExportInfo]:
    """List all exported symbols.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.

    Returns:
        A list of :class:`ExportInfo` instances.

    Raises:
        McpToolError: On script execution failure.
    """
    script = bridge.build_script("list_exports", {})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "list_exports")

    data = result.data or {}
    raw_exports = data.get("exports", [])

    return [
        ExportInfo(
            name=exp["name"],
            ordinal=exp["ordinal"],
            ea=exp["ea"],
        )
        for exp in raw_exports
    ]
