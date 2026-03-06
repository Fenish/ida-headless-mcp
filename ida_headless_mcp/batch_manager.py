"""Batch analysis manager for processing multiple binaries concurrently.

Provides :class:`BatchManager` which queues binaries for analysis, respects
a configurable concurrency limit via an :class:`asyncio.Semaphore`, and
tracks per-job progress.

Requirements: 18.1, 18.2, 18.3, 18.4
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import BatchJobInfo, BatchStatus

if TYPE_CHECKING:
    from ida_headless_mcp.session_manager import SessionManager


# ---------------------------------------------------------------------------
# Batch job state & data
# ---------------------------------------------------------------------------


class BatchJobState(str, Enum):
    """Lifecycle states for a batch analysis job."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class BatchJob:
    """Internal representation of a batch analysis job."""

    job_id: str
    binary_paths: list[str]
    state: BatchJobState
    results: dict[str, str] = field(default_factory=dict)   # path -> session_id
    errors: dict[str, str] = field(default_factory=dict)     # path -> error msg
    completed: set[str] = field(default_factory=set)
    in_progress: set[str] = field(default_factory=set)
    pending: set[str] = field(default_factory=set)


# ---------------------------------------------------------------------------
# Batch Manager
# ---------------------------------------------------------------------------


class BatchManager:
    """Orchestrates batch analysis of multiple binaries.

    Args:
        session_manager: The session manager used to create analysis sessions.
        max_concurrent: Maximum number of binaries analysed simultaneously.
    """

    def __init__(
        self,
        session_manager: "SessionManager",
        max_concurrent: int = 3,
    ) -> None:
        self._session_manager = session_manager
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._jobs: dict[str, BatchJob] = {}

    # -- public API --------------------------------------------------------

    async def start_batch(self, binary_paths: list[str]) -> BatchJobInfo:
        """Queue *binary_paths* for analysis and return a job summary.

        Raises:
            McpToolError: If *binary_paths* is empty.
        """
        if not binary_paths:
            raise McpToolError(
                code=ErrorCode.INVALID_PARAMETER,
                message="binary_paths must not be empty",
                tool_name="start_batch",
            )

        job_id = uuid.uuid4().hex[:12]
        job = BatchJob(
            job_id=job_id,
            binary_paths=list(binary_paths),
            state=BatchJobState.IN_PROGRESS,
            pending=set(binary_paths),
        )
        self._jobs[job_id] = job

        # Fire-and-forget the background processing task
        asyncio.ensure_future(self._process_job(job))

        return BatchJobInfo(
            job_id=job_id,
            total=len(binary_paths),
            state=job.state.value,
        )

    def get_status(self, job_id: str) -> BatchStatus:
        """Return the current status of a batch job.

        Raises:
            McpToolError: If *job_id* is unknown.
        """
        job = self._jobs.get(job_id)
        if job is None:
            raise McpToolError(
                code=ErrorCode.BATCH_NOT_FOUND,
                message=f"No batch job found with ID '{job_id}'",
                tool_name="get_batch_status",
            )

        return BatchStatus(
            job_id=job.job_id,
            state=job.state.value,
            completed=len(job.completed),
            in_progress=len(job.in_progress),
            pending=len(job.pending),
            errors=dict(job.errors),
            session_ids=dict(job.results),
        )

    async def cancel_job(self, job_id: str) -> None:
        """Cancel a batch job, marking remaining pending items as failed.

        Raises:
            McpToolError: If *job_id* is unknown.
        """
        job = self._jobs.get(job_id)
        if job is None:
            raise McpToolError(
                code=ErrorCode.BATCH_NOT_FOUND,
                message=f"No batch job found with ID '{job_id}'",
                tool_name="cancel_job",
            )

        # Mark all pending binaries as cancelled
        for path in list(job.pending):
            job.pending.discard(path)
            job.errors[path] = "Cancelled"
            job.completed.add(path)

        job.state = BatchJobState.FAILED


    # -- internal ----------------------------------------------------------

    async def _process_job(self, job: BatchJob) -> None:
        """Process all binaries in *job* respecting the concurrency limit."""
        tasks = [
            self._analyse_binary(job, path) for path in job.binary_paths
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Determine final state
        if job.errors and len(job.errors) == len(job.binary_paths):
            job.state = BatchJobState.FAILED
        else:
            job.state = BatchJobState.COMPLETED

    async def _analyse_binary(self, job: BatchJob, binary_path: str) -> None:
        """Analyse a single binary within the semaphore limit."""
        async with self._semaphore:
            job.pending.discard(binary_path)
            job.in_progress.add(binary_path)
            try:
                session = await self._session_manager.create_session(binary_path)
                session_id = (
                    session.session_id
                    if hasattr(session, "session_id")
                    else str(session)
                )
                job.results[binary_path] = session_id
                job.completed.add(binary_path)
            except Exception as exc:
                job.errors[binary_path] = str(exc)
                job.completed.add(binary_path)
            finally:
                job.in_progress.discard(binary_path)
