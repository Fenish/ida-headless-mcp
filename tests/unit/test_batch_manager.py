"""Unit tests for the BatchManager.

Tests the batch job lifecycle, status tracking, concurrency limiting,
and error handling in ``ida_headless_mcp.batch_manager``.
"""

from __future__ import annotations

import asyncio

import pytest

from ida_headless_mcp.batch_manager import BatchJob, BatchJobState, BatchManager
from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import BatchJobInfo, BatchStatus


# ---------------------------------------------------------------------------
# Helpers — fake session manager
# ---------------------------------------------------------------------------


class _FakeSession:
    """Minimal session object returned by the fake session manager."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id


class FakeSessionManager:
    """Session manager that creates fake sessions without spawning IDA."""

    def __init__(self, *, fail_paths: set[str] | None = None, delay: float = 0) -> None:
        self._counter = 0
        self._fail_paths = fail_paths or set()
        self._delay = delay

    async def create_session(self, binary_path: str) -> _FakeSession:
        if self._delay:
            await asyncio.sleep(self._delay)
        if binary_path in self._fail_paths:
            raise RuntimeError(f"Failed to open {binary_path}")
        self._counter += 1
        return _FakeSession(session_id=f"sess_{self._counter}")


# ---------------------------------------------------------------------------
# BatchJobState enum
# ---------------------------------------------------------------------------


class TestBatchJobState:
    def test_values(self):
        assert BatchJobState.PENDING == "pending"
        assert BatchJobState.IN_PROGRESS == "in_progress"
        assert BatchJobState.COMPLETED == "completed"
        assert BatchJobState.FAILED == "failed"

    def test_is_str_enum(self):
        assert isinstance(BatchJobState.PENDING, str)


# ---------------------------------------------------------------------------
# BatchJob dataclass
# ---------------------------------------------------------------------------


class TestBatchJob:
    def test_defaults(self):
        job = BatchJob(
            job_id="j1",
            binary_paths=["/a", "/b"],
            state=BatchJobState.PENDING,
        )
        assert job.results == {}
        assert job.errors == {}
        assert job.completed == set()
        assert job.in_progress == set()
        assert job.pending == set()


# ---------------------------------------------------------------------------
# BatchManager.start_batch
# ---------------------------------------------------------------------------


class TestStartBatch:
    @pytest.mark.asyncio
    async def test_returns_batch_job_info(self):
        sm = FakeSessionManager()
        bm = BatchManager(sm, max_concurrent=2)

        info = await bm.start_batch(["/bin/a", "/bin/b"])

        assert isinstance(info, BatchJobInfo)
        assert info.total == 2
        assert info.state == "in_progress"
        assert info.job_id  # non-empty

    @pytest.mark.asyncio
    async def test_empty_paths_raises(self):
        sm = FakeSessionManager()
        bm = BatchManager(sm)

        with pytest.raises(McpToolError) as exc_info:
            await bm.start_batch([])
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER

    @pytest.mark.asyncio
    async def test_job_completes_successfully(self):
        sm = FakeSessionManager()
        bm = BatchManager(sm, max_concurrent=3)

        info = await bm.start_batch(["/bin/a", "/bin/b", "/bin/c"])
        # Give the background tasks time to finish
        await asyncio.sleep(0.1)

        status = bm.get_status(info.job_id)
        assert status.state == "completed"
        assert status.completed == 3
        assert status.pending == 0
        assert status.in_progress == 0
        assert len(status.session_ids) == 3
        assert status.errors == {}

    @pytest.mark.asyncio
    async def test_partial_failure(self):
        sm = FakeSessionManager(fail_paths={"/bin/bad"})
        bm = BatchManager(sm, max_concurrent=3)

        info = await bm.start_batch(["/bin/good", "/bin/bad"])
        await asyncio.sleep(0.1)

        status = bm.get_status(info.job_id)
        assert status.state == "completed"
        assert status.completed == 2
        assert "/bin/bad" in status.errors
        assert "/bin/good" in status.session_ids

    @pytest.mark.asyncio
    async def test_all_fail_sets_failed_state(self):
        sm = FakeSessionManager(fail_paths={"/a", "/b"})
        bm = BatchManager(sm, max_concurrent=2)

        info = await bm.start_batch(["/a", "/b"])
        await asyncio.sleep(0.1)

        status = bm.get_status(info.job_id)
        assert status.state == "failed"
        assert len(status.errors) == 2


# ---------------------------------------------------------------------------
# BatchManager.get_status
# ---------------------------------------------------------------------------


class TestGetStatus:
    @pytest.mark.asyncio
    async def test_unknown_job_raises(self):
        sm = FakeSessionManager()
        bm = BatchManager(sm)

        with pytest.raises(McpToolError) as exc_info:
            bm.get_status("nonexistent")
        assert exc_info.value.code == ErrorCode.BATCH_NOT_FOUND

    @pytest.mark.asyncio
    async def test_returns_batch_status(self):
        sm = FakeSessionManager()
        bm = BatchManager(sm, max_concurrent=3)

        info = await bm.start_batch(["/x"])
        await asyncio.sleep(0.1)

        status = bm.get_status(info.job_id)
        assert isinstance(status, BatchStatus)
        assert status.job_id == info.job_id


# ---------------------------------------------------------------------------
# Multiple independent jobs
# ---------------------------------------------------------------------------


class TestMultipleJobs:
    @pytest.mark.asyncio
    async def test_independent_tracking(self):
        sm = FakeSessionManager()
        bm = BatchManager(sm, max_concurrent=5)

        info1 = await bm.start_batch(["/a"])
        info2 = await bm.start_batch(["/b", "/c"])
        await asyncio.sleep(0.1)

        s1 = bm.get_status(info1.job_id)
        s2 = bm.get_status(info2.job_id)

        assert s1.completed == 1
        assert s2.completed == 2
        assert info1.job_id != info2.job_id
