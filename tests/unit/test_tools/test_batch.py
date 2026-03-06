"""Unit tests for batch tool handlers.

Tests the tool handler functions in ``ida_headless_mcp.tools.batch``
using fake batch manager / session manager / bridge objects.
"""

from __future__ import annotations

import pytest

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import BatchJobInfo, BatchStatus
from ida_headless_mcp.tools.batch import get_batch_status, start_batch


# ---------------------------------------------------------------------------
# Helpers — lightweight fakes
# ---------------------------------------------------------------------------


class FakeBridge:
    """Unused bridge stub kept for handler signature consistency."""
    pass


class FakeSessionManager:
    """Unused session manager stub kept for handler signature consistency."""
    pass


class FakeBatchManager:
    """Batch manager that returns pre-configured results."""

    def __init__(
        self,
        *,
        start_result: BatchJobInfo | None = None,
        status_result: BatchStatus | None = None,
        status_error: McpToolError | None = None,
    ) -> None:
        self._start_result = start_result
        self._status_result = status_result
        self._status_error = status_error
        self.last_binary_paths: list[str] | None = None
        self.last_job_id: str | None = None

    async def start_batch(self, binary_paths: list[str]) -> BatchJobInfo:
        self.last_binary_paths = binary_paths
        assert self._start_result is not None
        return self._start_result

    def get_status(self, job_id: str) -> BatchStatus:
        self.last_job_id = job_id
        if self._status_error:
            raise self._status_error
        assert self._status_result is not None
        return self._status_result


# ---------------------------------------------------------------------------
# start_batch tool handler
# ---------------------------------------------------------------------------


class TestStartBatch:
    @pytest.mark.asyncio
    async def test_success(self):
        info = BatchJobInfo(job_id="abc123", total=3, state="in_progress")
        bm = FakeBatchManager(start_result=info)

        result = await start_batch(
            FakeSessionManager(), FakeBridge(), bm, ["/a", "/b", "/c"]
        )

        assert result is info
        assert bm.last_binary_paths == ["/a", "/b", "/c"]

    @pytest.mark.asyncio
    async def test_empty_paths_raises(self):
        bm = FakeBatchManager()

        with pytest.raises(McpToolError) as exc_info:
            await start_batch(FakeSessionManager(), FakeBridge(), bm, [])
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "start_batch"

    @pytest.mark.asyncio
    async def test_binary_paths_forwarded(self):
        info = BatchJobInfo(job_id="x", total=2, state="in_progress")
        bm = FakeBatchManager(start_result=info)

        await start_batch(
            FakeSessionManager(), FakeBridge(), bm, ["/bin/ls", "/bin/cat"]
        )

        assert bm.last_binary_paths == ["/bin/ls", "/bin/cat"]

    @pytest.mark.asyncio
    async def test_returns_batch_job_info(self):
        info = BatchJobInfo(job_id="j42", total=1, state="in_progress")
        bm = FakeBatchManager(start_result=info)

        result = await start_batch(
            FakeSessionManager(), FakeBridge(), bm, ["/bin/ls"]
        )

        assert isinstance(result, BatchJobInfo)
        assert result.job_id == "j42"
        assert result.total == 1


# ---------------------------------------------------------------------------
# get_batch_status tool handler
# ---------------------------------------------------------------------------


class TestGetBatchStatus:
    @pytest.mark.asyncio
    async def test_success(self):
        status = BatchStatus(
            job_id="abc",
            state="completed",
            completed=3,
            in_progress=0,
            pending=0,
            errors={},
            session_ids={"/a": "s1", "/b": "s2", "/c": "s3"},
        )
        bm = FakeBatchManager(status_result=status)

        result = await get_batch_status(bm, "abc")

        assert result is status
        assert bm.last_job_id == "abc"

    @pytest.mark.asyncio
    async def test_empty_job_id_raises(self):
        bm = FakeBatchManager()

        with pytest.raises(McpToolError) as exc_info:
            await get_batch_status(bm, "")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "get_batch_status"

    @pytest.mark.asyncio
    async def test_whitespace_job_id_raises(self):
        bm = FakeBatchManager()

        with pytest.raises(McpToolError) as exc_info:
            await get_batch_status(bm, "   ")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER

    @pytest.mark.asyncio
    async def test_unknown_job_id_propagates_error(self):
        err = McpToolError(
            code=ErrorCode.BATCH_NOT_FOUND,
            message="No batch job found with ID 'nope'",
            tool_name="get_batch_status",
        )
        bm = FakeBatchManager(status_error=err)

        with pytest.raises(McpToolError) as exc_info:
            await get_batch_status(bm, "nope")
        assert exc_info.value.code == ErrorCode.BATCH_NOT_FOUND

    @pytest.mark.asyncio
    async def test_job_id_forwarded(self):
        status = BatchStatus(
            job_id="myid",
            state="in_progress",
            completed=1,
            in_progress=1,
            pending=0,
        )
        bm = FakeBatchManager(status_result=status)

        await get_batch_status(bm, "myid")
        assert bm.last_job_id == "myid"
