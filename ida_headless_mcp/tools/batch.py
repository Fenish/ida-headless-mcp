"""Batch analysis tool handlers.

Each handler validates inputs, delegates to the :class:`BatchManager`, and
returns the appropriate model.

Requirements: 18.1, 18.2, 18.3, 18.4
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import BatchJobInfo, BatchStatus

if TYPE_CHECKING:
    from ida_headless_mcp.batch_manager import BatchManager
    from ida_headless_mcp.ida_bridge import IdaBridge
    from ida_headless_mcp.session_manager import SessionManager


async def start_batch(
    session_manager: "SessionManager",
    bridge: "IdaBridge",
    batch_manager: "BatchManager",
    binary_paths: list[str],
) -> BatchJobInfo:
    """Start a batch analysis job for the given binary paths.

    Args:
        session_manager: The session manager (unused directly, kept for
            handler signature consistency).
        bridge: The IDA bridge (unused directly).
        batch_manager: The batch manager that orchestrates the job.
        binary_paths: List of binary file paths to analyse.

    Returns:
        A :class:`BatchJobInfo` with the new job's ID, total count, and state.

    Raises:
        McpToolError: If *binary_paths* is empty or not a list.
    """
    if not binary_paths:
        raise McpToolError(
            code=ErrorCode.INVALID_PARAMETER,
            message="binary_paths must not be empty",
            tool_name="start_batch",
        )

    return await batch_manager.start_batch(binary_paths)


async def get_batch_status(
    batch_manager: "BatchManager",
    job_id: str,
) -> BatchStatus:
    """Return the current status of a batch analysis job.

    Args:
        batch_manager: The batch manager tracking jobs.
        job_id: The batch job identifier.

    Returns:
        A :class:`BatchStatus` with progress counts and any errors.

    Raises:
        McpToolError: If *job_id* is empty or unknown.
    """
    if not job_id or not job_id.strip():
        raise McpToolError(
            code=ErrorCode.INVALID_PARAMETER,
            message="job_id must not be empty",
            tool_name="get_batch_status",
        )

    return batch_manager.get_status(job_id)
