"""Property-based tests for batch processing.

Property 25 from the IDA Headless MCP design document.
"""

from __future__ import annotations

import asyncio

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ida_headless_mcp.batch_manager import BatchManager


# ---------------------------------------------------------------------------
# Helpers — fake session manager
# ---------------------------------------------------------------------------


class FakeSessionManager:
    """Session manager that creates fake sessions without spawning IDA."""

    def __init__(self, fail_paths: set[str] | None = None, delay: float = 0) -> None:
        self._counter = 0
        self._fail_paths = fail_paths or set()
        self._delay = delay

    async def create_session(self, binary_path: str):
        if self._delay:
            await asyncio.sleep(self._delay)
        if binary_path in self._fail_paths:
            raise RuntimeError(f"Failed to open {binary_path}")
        self._counter += 1
        return type("S", (), {"session_id": f"sess_{self._counter}"})()


# ===================================================================
# Property 25: Batch job progress invariant
# ===================================================================


class TestBatchJobProgressInvariant:
    """Property 25: Batch job progress invariant.

    *For any* batch job with N binary paths, ``completed + in_progress +
    pending`` must always equal N.  The number of concurrent IDA processes
    must never exceed the configured ``batch_max_concurrent`` limit.  When
    the job completes, the number of session_ids must equal the number of
    successfully analysed binaries.

    **Validates: Requirements 18.1, 18.2, 18.3, 18.4**
    """

    # ---------------------------------------------------------------
    # 25a: completed + in_progress + pending == total after completion
    # ---------------------------------------------------------------

    @settings(max_examples=50)
    @given(num_binaries=st.integers(min_value=1, max_value=8))
    @pytest.mark.asyncio
    async def test_counts_sum_to_total_after_completion(self, num_binaries: int) -> None:
        """**Validates: Requirements 18.1, 18.2**"""
        paths = [f"/bin/test_{i}" for i in range(num_binaries)]
        sm = FakeSessionManager()
        bm = BatchManager(sm, max_concurrent=3)

        info = await bm.start_batch(paths)
        await asyncio.sleep(0.1)

        status = bm.get_status(info.job_id)
        total = status.completed + status.in_progress + status.pending
        assert total == num_binaries

    # ---------------------------------------------------------------
    # 25b: After completion all are completed, none pending/in_progress
    # ---------------------------------------------------------------

    @settings(max_examples=50)
    @given(num_binaries=st.integers(min_value=1, max_value=8))
    @pytest.mark.asyncio
    async def test_all_completed_after_finish(self, num_binaries: int) -> None:
        """**Validates: Requirements 18.2, 18.4**"""
        paths = [f"/bin/test_{i}" for i in range(num_binaries)]
        sm = FakeSessionManager()
        bm = BatchManager(sm, max_concurrent=3)

        info = await bm.start_batch(paths)
        await asyncio.sleep(0.1)

        status = bm.get_status(info.job_id)
        assert status.completed == num_binaries
        assert status.pending == 0
        assert status.in_progress == 0

    # ---------------------------------------------------------------
    # 25c: Errors dict contains exactly the failing paths
    # ---------------------------------------------------------------

    @settings(max_examples=50)
    @given(
        num_binaries=st.integers(min_value=2, max_value=8),
        fail_ratio=st.floats(min_value=0.0, max_value=1.0),
    )
    @pytest.mark.asyncio
    async def test_errors_match_fail_paths(
        self, num_binaries: int, fail_ratio: float
    ) -> None:
        """**Validates: Requirements 18.2, 18.3**"""
        paths = [f"/bin/test_{i}" for i in range(num_binaries)]
        num_fail = int(num_binaries * fail_ratio)
        fail_paths = set(paths[:num_fail])

        sm = FakeSessionManager(fail_paths=fail_paths)
        bm = BatchManager(sm, max_concurrent=3)

        info = await bm.start_batch(paths)
        await asyncio.sleep(0.1)

        status = bm.get_status(info.job_id)
        assert set(status.errors.keys()) == fail_paths

    # ---------------------------------------------------------------
    # 25d: session_ids dict contains exactly the successful paths
    # ---------------------------------------------------------------

    @settings(max_examples=50)
    @given(
        num_binaries=st.integers(min_value=2, max_value=8),
        fail_ratio=st.floats(min_value=0.0, max_value=1.0),
    )
    @pytest.mark.asyncio
    async def test_session_ids_match_successful_paths(
        self, num_binaries: int, fail_ratio: float
    ) -> None:
        """**Validates: Requirements 18.4**"""
        paths = [f"/bin/test_{i}" for i in range(num_binaries)]
        num_fail = int(num_binaries * fail_ratio)
        fail_paths = set(paths[:num_fail])
        expected_success = set(paths) - fail_paths

        sm = FakeSessionManager(fail_paths=fail_paths)
        bm = BatchManager(sm, max_concurrent=3)

        info = await bm.start_batch(paths)
        await asyncio.sleep(0.1)

        status = bm.get_status(info.job_id)
        assert set(status.session_ids.keys()) == expected_success
