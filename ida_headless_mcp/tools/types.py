"""Type information and struct management tool handlers.

Each handler validates inputs, builds an IDAPython script via the bridge,
executes it through the session manager, and parses the result into typed
model dataclasses.

Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import (
    FieldDef,
    OperationResult,
    TypeInfo,
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
    """Raise McpToolError if the script execution failed.

    Checks for TYPE_CONFLICT error code in the error data; otherwise
    falls back to INVALID_PARAMETER.
    """
    if not result.success:
        error_data = result.data or {}
        code = ErrorCode.INVALID_PARAMETER
        if isinstance(error_data, dict) and "error" in error_data:
            err = error_data["error"]
            msg = err.get("message", "Unknown error")
            if err.get("code") == ErrorCode.TYPE_CONFLICT:
                code = ErrorCode.TYPE_CONFLICT
        else:
            msg = str(error_data) if error_data else "Script execution failed"
        raise McpToolError(
            code=code,
            message=msg,
            tool_name=tool_name,
        )


async def list_types(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
) -> list[TypeInfo]:
    """List all locally defined types.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.

    Returns:
        A list of :class:`TypeInfo` instances.

    Raises:
        McpToolError: On script execution failure.
    """
    script = bridge.build_script("list_types", {})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "list_types")

    data = result.data or {}
    raw_types = data.get("types", [])

    return [
        TypeInfo(
            name=t["name"],
            size=t["size"],
            definition=t["definition"],
        )
        for t in raw_types
    ]


async def create_struct(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    name: str,
    fields: list[dict],
) -> OperationResult:
    """Create a new struct type with the given name and fields.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        name: Name of the struct to create.
        fields: List of field dicts with ``name``, ``type_str``, ``offset`` keys.

    Returns:
        An :class:`OperationResult` indicating success or failure.

    Raises:
        McpToolError: On script failure or TYPE_CONFLICT.
    """
    script = bridge.build_script(
        "create_struct", {"name": name, "fields": fields}
    )
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "create_struct")

    data = result.data or {}
    return OperationResult(
        success=result.success,
        message=data.get("message", ""),
    )


async def add_struct_field(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    struct_name: str,
    field: dict,
) -> OperationResult:
    """Add a field to an existing struct.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        struct_name: Name of the struct to modify.
        field: Field dict with ``name``, ``type_str``, ``offset`` keys.

    Returns:
        An :class:`OperationResult` indicating success or failure.

    Raises:
        McpToolError: On script failure or TYPE_CONFLICT.
    """
    script = bridge.build_script(
        "add_struct_field", {"struct_name": struct_name, "field": field}
    )
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "add_struct_field")

    data = result.data or {}
    return OperationResult(
        success=result.success,
        message=data.get("message", ""),
    )


async def apply_type(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    ea: str,
    type_str: str,
) -> OperationResult:
    """Apply a type to a function or variable at the given EA.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        ea: Effective address (hex or decimal string).
        type_str: The type string to apply.

    Returns:
        An :class:`OperationResult` indicating success or failure.

    Raises:
        McpToolError: If the EA is invalid or the script fails.
    """
    ea_int = _validate_ea(ea, "apply_type")

    script = bridge.build_script(
        "apply_type", {"ea": ea_int, "type_str": type_str}
    )
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "apply_type")

    data = result.data or {}
    return OperationResult(
        success=result.success,
        message=data.get("message", ""),
    )


async def delete_type(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    name: str,
) -> OperationResult:
    """Delete a local type by name.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        name: Name of the type to delete.

    Returns:
        An :class:`OperationResult` indicating success or failure.

    Raises:
        McpToolError: On script failure.
    """
    script = bridge.build_script("delete_type", {"name": name})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "delete_type")

    data = result.data or {}
    return OperationResult(
        success=result.success,
        message=data.get("message", ""),
    )


async def parse_header(
    session_manager,
    bridge: "IdaBridge",
    session_id: str,
    header_text: str,
) -> OperationResult:
    """Parse a C header declaration and add resulting types to the IDB.

    Args:
        session_manager: The session manager to execute scripts against.
        bridge: The IDA bridge for script generation.
        session_id: Target session.
        header_text: The C header text to parse.

    Returns:
        An :class:`OperationResult` indicating success or failure.

    Raises:
        McpToolError: On script failure or TYPE_CONFLICT.
    """
    script = bridge.build_script("parse_header", {"header_text": header_text})
    result = await session_manager.execute_script(session_id, script)
    _check_script_success(result, "parse_header")

    data = result.data or {}
    return OperationResult(
        success=result.success,
        message=data.get("message", ""),
    )
