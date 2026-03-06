"""Property-based tests for segment containment invariant.

Property 13 from the IDA Headless MCP design document.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from ida_headless_mcp.models import SegmentInfo
from tests.conftest import MockIdaBridge
from tests.strategies import segment_infos, segment_info_lists


# ===================================================================
# Property 13: Segment containment invariant
# ===================================================================


class TestSegmentContainmentInvariant:
    """Property 13: Segment containment invariant.

    *For any* EA within a segment, querying the segment at that EA must
    return a segment where start_ea <= ea < end_ea. The segment must
    include name, start_ea, end_ea, size, permissions, class, and bitness
    fields. Querying by name or by EA for the same segment must return
    identical results.

    **Validates: Requirements 9.1, 9.2, 9.3**
    """

    # ---------------------------------------------------------------
    # 13a: Generated SegmentInfo has consistent size == end_ea - start_ea
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(seg=segment_infos())
    def test_segment_size_equals_end_minus_start(self, seg: SegmentInfo) -> None:
        # Feature: ida-headless-mcp, Property 13: Segment containment invariant
        start = int(seg.start_ea, 16)
        end = int(seg.end_ea, 16)
        assert seg.size == end - start, (
            f"size={seg.size} but end_ea - start_ea = {end - start}"
        )

    # ---------------------------------------------------------------
    # 13b: All required fields are present and well-typed
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(seg=segment_infos())
    def test_segment_has_all_required_fields(self, seg: SegmentInfo) -> None:
        # Feature: ida-headless-mcp, Property 13: Segment containment invariant
        assert isinstance(seg.name, str) and len(seg.name) > 0
        assert isinstance(seg.start_ea, str) and seg.start_ea.startswith("0x")
        assert isinstance(seg.end_ea, str) and seg.end_ea.startswith("0x")
        assert isinstance(seg.size, int) and seg.size > 0
        assert isinstance(seg.permissions, str) and len(seg.permissions) > 0
        assert isinstance(seg.seg_class, str) and len(seg.seg_class) > 0
        assert isinstance(seg.bitness, int) and seg.bitness in (16, 32, 64)

    # ---------------------------------------------------------------
    # 13c: get_segment_at returns correct segment for EAs within range
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(seg=segment_infos())
    def test_get_segment_at_returns_containing_segment(self, seg: SegmentInfo) -> None:
        # Feature: ida-headless-mcp, Property 13: Segment containment invariant
        start = int(seg.start_ea, 16)
        end = int(seg.end_ea, 16)
        assume(end - start >= 1)

        bridge = MockIdaBridge()
        bridge.add_segment(
            seg.name, start, seg.size,
            permissions=seg.permissions,
            seg_class=seg.seg_class,
            bitness=seg.bitness,
        )

        # Pick an EA within the segment (start_ea <= ea < end_ea)
        mid_ea = start + (end - start) // 2
        result = bridge.get_segment_at(mid_ea)

        assert result is not None
        result_start = int(result.start_ea, 16)
        result_end = int(result.end_ea, 16)
        assert result_start <= mid_ea < result_end

    # ---------------------------------------------------------------
    # 13d: get_segment_at for start_ea and end_ea-1 both return segment
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(seg=segment_infos())
    def test_segment_boundary_containment(self, seg: SegmentInfo) -> None:
        # Feature: ida-headless-mcp, Property 13: Segment containment invariant
        start = int(seg.start_ea, 16)
        end = int(seg.end_ea, 16)
        assume(end - start >= 2)

        bridge = MockIdaBridge()
        bridge.add_segment(
            seg.name, start, seg.size,
            permissions=seg.permissions,
            seg_class=seg.seg_class,
            bitness=seg.bitness,
        )

        # start_ea is inside the segment
        result_start = bridge.get_segment_at(start)
        assert result_start is not None
        assert result_start.name == seg.name

        # end_ea - 1 is the last valid address inside the segment
        result_last = bridge.get_segment_at(end - 1)
        assert result_last is not None
        assert result_last.name == seg.name

        # end_ea itself is outside the segment
        result_end = bridge.get_segment_at(end)
        # Should be None since no other segment covers this address
        assert result_end is None

    # ---------------------------------------------------------------
    # 13e: get_segment by name returns same result as get_segment_at by EA
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(seg=segment_infos())
    def test_get_segment_by_name_matches_get_segment_at(self, seg: SegmentInfo) -> None:
        # Feature: ida-headless-mcp, Property 13: Segment containment invariant
        start = int(seg.start_ea, 16)
        end = int(seg.end_ea, 16)
        assume(end - start >= 1)

        bridge = MockIdaBridge()
        bridge.add_segment(
            seg.name, start, seg.size,
            permissions=seg.permissions,
            seg_class=seg.seg_class,
            bitness=seg.bitness,
        )

        by_name = bridge.get_segment(seg.name)
        mid_ea = start + (end - start) // 2
        by_ea = bridge.get_segment_at(mid_ea)

        assert by_name is not None
        assert by_ea is not None
        assert by_name.name == by_ea.name
        assert by_name.start_ea == by_ea.start_ea
        assert by_name.end_ea == by_ea.end_ea
        assert by_name.size == by_ea.size
        assert by_name.permissions == by_ea.permissions
        assert by_name.seg_class == by_ea.seg_class
        assert by_name.bitness == by_ea.bitness

    # ---------------------------------------------------------------
    # 13f: list_segments returns all added segments
    # ---------------------------------------------------------------

    @settings(max_examples=50)
    @given(segments=segment_info_lists)
    def test_list_segments_returns_all_added(self, segments: list[SegmentInfo]) -> None:
        # Feature: ida-headless-mcp, Property 13: Segment containment invariant
        bridge = MockIdaBridge()

        # Deduplicate by name (bridge uses name as key)
        seen_names: set[str] = set()
        unique_segments: list[SegmentInfo] = []
        for seg in segments:
            if seg.name not in seen_names:
                seen_names.add(seg.name)
                unique_segments.append(seg)

        for seg in unique_segments:
            start = int(seg.start_ea, 16)
            bridge.add_segment(
                seg.name, start, seg.size,
                permissions=seg.permissions,
                seg_class=seg.seg_class,
                bitness=seg.bitness,
            )

        listed = bridge.list_segments()
        assert len(listed) == len(unique_segments)

        listed_names = {s.name for s in listed}
        for seg in unique_segments:
            assert seg.name in listed_names
