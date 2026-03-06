"""Property-based tests for string tools and pagination.

Properties 11–12 from the IDA Headless MCP design document.
"""

from __future__ import annotations

import fnmatch

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from ida_headless_mcp.ida_bridge import ScriptResult
from ida_headless_mcp.models import StringInfo, StringResults
from ida_headless_mcp.tools.strings import list_strings
from tests.strategies import (
    filter_patterns,
    string_info_lists,
    string_infos,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeBridge:
    """Minimal bridge that records build_script calls."""

    def build_script(self, operation: str, params: dict, result_path: str = "") -> str:
        return f"__script__:{operation}"


class _FakeSessionManager:
    """Session manager returning a pre-configured ScriptResult."""

    def __init__(self, result: ScriptResult) -> None:
        self._result = result

    async def execute_script(self, session_id: str, script: str) -> ScriptResult:
        return self._result


def _make_script_result(strings: list[StringInfo]) -> ScriptResult:
    """Build a ScriptResult containing the given string list as raw dicts."""
    raw = [
        {
            "ea": s.ea,
            "value": s.value,
            "length": s.length,
            "string_type": s.string_type,
        }
        for s in strings
    ]
    return ScriptResult(success=True, data={"strings": raw})


# ===================================================================
# Property 11: String filter correctness
# ===================================================================


class TestStringFilterCorrectness:
    """Property 11: String filter correctness.

    *For any* string list and filter pattern, every string in the filtered
    result must have a value matching the pattern, and no matching string
    should be excluded from the result.

    **Validates: Requirements 8.1, 8.2, 8.3**
    """

    @settings(max_examples=100)
    @given(strings=string_info_lists, pattern=filter_patterns)
    @pytest.mark.asyncio
    async def test_filter_includes_only_matching(
        self, strings: list[StringInfo], pattern: str
    ) -> None:
        # Feature: ida-headless-mcp, Property 11: String filter correctness
        result = _make_script_result(strings)
        sm = _FakeSessionManager(result)
        bridge = _FakeBridge()

        # Use a large limit to avoid pagination cutting results
        sr = await list_strings(
            sm, bridge, "sess1", filter_pattern=pattern, offset=0, limit=10000
        )

        # Every returned string must match the pattern
        for s in sr.strings:
            assert fnmatch.fnmatch(s.value, pattern), (
                f"String '{s.value}' does not match pattern '{pattern}'"
            )

    @settings(max_examples=100)
    @given(strings=string_info_lists, pattern=filter_patterns)
    @pytest.mark.asyncio
    async def test_filter_excludes_no_matching(
        self, strings: list[StringInfo], pattern: str
    ) -> None:
        # Feature: ida-headless-mcp, Property 11: String filter correctness
        result = _make_script_result(strings)
        sm = _FakeSessionManager(result)
        bridge = _FakeBridge()

        sr = await list_strings(
            sm, bridge, "sess1", filter_pattern=pattern, offset=0, limit=10000
        )
        returned_values = {s.value for s in sr.strings}

        # No matching string should be missing
        expected_values = {
            s.value for s in strings if fnmatch.fnmatch(s.value, pattern)
        }
        assert returned_values == expected_values

    @settings(max_examples=100)
    @given(strings=string_info_lists, pattern=filter_patterns)
    @pytest.mark.asyncio
    async def test_total_count_matches_filtered(
        self, strings: list[StringInfo], pattern: str
    ) -> None:
        # Feature: ida-headless-mcp, Property 11: String filter correctness
        result = _make_script_result(strings)
        sm = _FakeSessionManager(result)
        bridge = _FakeBridge()

        sr = await list_strings(
            sm, bridge, "sess1", filter_pattern=pattern, offset=0, limit=10000
        )

        expected_count = sum(
            1 for s in strings if fnmatch.fnmatch(s.value, pattern)
        )
        assert sr.total_count == expected_count


# ===================================================================
# Property 12: Pagination invariants
# ===================================================================


class TestPaginationInvariants:
    """Property 12: Pagination invariants.

    *For any* paginated result with offset O and limit L, the returned
    list must contain at most L entries. Requesting offset O and offset
    O+L should produce non-overlapping results that together cover the
    correct contiguous range.

    **Validates: Requirements 8.4**
    """

    @settings(max_examples=100)
    @given(
        strings=string_info_lists,
        offset=st.integers(min_value=0, max_value=50),
        limit=st.integers(min_value=1, max_value=50),
    )
    @pytest.mark.asyncio
    async def test_at_most_limit_entries(
        self, strings: list[StringInfo], offset: int, limit: int
    ) -> None:
        # Feature: ida-headless-mcp, Property 12: Pagination invariants
        result = _make_script_result(strings)
        sm = _FakeSessionManager(result)
        bridge = _FakeBridge()

        sr = await list_strings(
            sm, bridge, "sess1", filter_pattern=None, offset=offset, limit=limit
        )

        assert len(sr.strings) <= limit
        assert sr.limit == limit
        assert sr.offset == offset

    @settings(max_examples=100)
    @given(
        strings=string_info_lists,
        offset=st.integers(min_value=0, max_value=50),
        limit=st.integers(min_value=1, max_value=50),
    )
    @pytest.mark.asyncio
    async def test_total_count_equals_full_list(
        self, strings: list[StringInfo], offset: int, limit: int
    ) -> None:
        # Feature: ida-headless-mcp, Property 12: Pagination invariants
        result = _make_script_result(strings)
        sm = _FakeSessionManager(result)
        bridge = _FakeBridge()

        sr = await list_strings(
            sm, bridge, "sess1", filter_pattern=None, offset=offset, limit=limit
        )

        assert sr.total_count == len(strings)

    @settings(max_examples=100)
    @given(
        strings=st.lists(string_infos(), min_size=1, max_size=20),
        limit=st.integers(min_value=1, max_value=10),
    )
    @pytest.mark.asyncio
    async def test_consecutive_pages_non_overlapping(
        self, strings: list[StringInfo], limit: int
    ) -> None:
        # Feature: ida-headless-mcp, Property 12: Pagination invariants
        result = _make_script_result(strings)
        bridge = _FakeBridge()

        # Fetch page 1 (offset=0) and page 2 (offset=limit)
        sm1 = _FakeSessionManager(result)
        page1 = await list_strings(
            sm1, bridge, "sess1", filter_pattern=None, offset=0, limit=limit
        )

        sm2 = _FakeSessionManager(result)
        page2 = await list_strings(
            sm2, bridge, "sess1", filter_pattern=None, offset=limit, limit=limit
        )

        # Pages correspond to non-overlapping slices [0:limit] and [limit:2*limit]
        # so their combined length must not exceed the total
        assert len(page1.strings) + len(page2.strings) <= len(strings)

        # Verify positional correctness: page1 items match strings[0:limit],
        # page2 items match strings[limit:2*limit]
        for i, s in enumerate(page1.strings):
            assert s.value == strings[i].value
            assert s.ea == strings[i].ea
        for i, s in enumerate(page2.strings):
            assert s.value == strings[limit + i].value
            assert s.ea == strings[limit + i].ea

    @settings(max_examples=100)
    @given(
        strings=st.lists(string_infos(), min_size=1, max_size=20),
        limit=st.integers(min_value=1, max_value=10),
    )
    @pytest.mark.asyncio
    async def test_pages_cover_contiguous_range(
        self, strings: list[StringInfo], limit: int
    ) -> None:
        # Feature: ida-headless-mcp, Property 12: Pagination invariants
        result = _make_script_result(strings)
        bridge = _FakeBridge()

        # Collect all pages
        all_collected: list[StringInfo] = []
        offset = 0
        while True:
            sm = _FakeSessionManager(result)
            page = await list_strings(
                sm, bridge, "sess1", filter_pattern=None, offset=offset, limit=limit
            )
            all_collected.extend(page.strings)
            if len(page.strings) < limit:
                break
            offset += limit

        # All collected entries should equal the full list
        assert len(all_collected) == len(strings)
        # Values should match in order
        for orig, collected in zip(strings, all_collected):
            assert orig.value == collected.value
            assert orig.ea == collected.ea
