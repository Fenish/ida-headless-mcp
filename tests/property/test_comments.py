"""Property-based tests for comment round-trip behaviour.

Property 17 from the IDA Headless MCP design document.
"""

from __future__ import annotations

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from ida_headless_mcp.models import CommentInfo
from tests.conftest import MockIdaBridge
from tests.strategies import comment_strings, ea_strings


# ===================================================================
# Property 17: Comment round-trip
# ===================================================================


class TestCommentRoundTrip:
    """Property 17: Comment round-trip.

    *For any* EA and comment text, setting a regular comment and then
    getting comments at that EA should return the same text in the
    ``regular`` field. The same applies for repeatable comments and
    function comments in their respective fields. For range queries,
    all returned comments must have EAs within the requested range.

    **Validates: Requirements 12.1, 12.2, 12.3, 12.4, 12.5**
    """

    # ---------------------------------------------------------------
    # 17a: Regular comment set/get round-trip
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(ea_str=ea_strings, comment=comment_strings)
    def test_regular_comment_round_trip(self, ea_str: str, comment: str) -> None:
        """**Validates: Requirements 12.1**"""
        bridge = MockIdaBridge()
        ea = int(ea_str, 16)

        result = bridge.set_comment(ea, comment, "regular")
        assert result.success

        ci = bridge.get_comments(ea)
        assert ci.regular == comment

    # ---------------------------------------------------------------
    # 17b: Repeatable comment set/get round-trip
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(ea_str=ea_strings, comment=comment_strings)
    def test_repeatable_comment_round_trip(self, ea_str: str, comment: str) -> None:
        """**Validates: Requirements 12.2**"""
        bridge = MockIdaBridge()
        ea = int(ea_str, 16)

        result = bridge.set_comment(ea, comment, "repeatable")
        assert result.success

        ci = bridge.get_comments(ea)
        assert ci.repeatable == comment

    # ---------------------------------------------------------------
    # 17c: Function comment set/get round-trip
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(ea_str=ea_strings, comment=comment_strings)
    def test_function_comment_round_trip(self, ea_str: str, comment: str) -> None:
        """**Validates: Requirements 12.3**"""
        bridge = MockIdaBridge()
        ea = int(ea_str, 16)

        result = bridge.set_comment(ea, comment, "function")
        assert result.success

        ci = bridge.get_comments(ea)
        assert ci.function_comment == comment

    # ---------------------------------------------------------------
    # 17d: get_comments returns all comment types at an EA
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea_str=ea_strings,
        regular=comment_strings,
        repeatable=comment_strings,
        func_comment=comment_strings,
    )
    def test_get_comments_returns_all_types(
        self,
        ea_str: str,
        regular: str,
        repeatable: str,
        func_comment: str,
    ) -> None:
        """**Validates: Requirements 12.4**"""
        bridge = MockIdaBridge()
        ea = int(ea_str, 16)

        bridge.set_comment(ea, regular, "regular")
        bridge.set_comment(ea, repeatable, "repeatable")
        bridge.set_comment(ea, func_comment, "function")

        ci = bridge.get_comments(ea)
        assert ci.regular == regular
        assert ci.repeatable == repeatable
        assert ci.function_comment == func_comment
        assert ci.ea == ea_str

    # ---------------------------------------------------------------
    # 17e: Range query returns only comments within range
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        data=st.data(),
        num_comments=st.integers(min_value=1, max_value=10),
    )
    def test_range_query_returns_comments_within_range(
        self, data: st.DataObject, num_comments: int
    ) -> None:
        """**Validates: Requirements 12.5**"""
        bridge = MockIdaBridge()

        # Generate distinct EAs and comments
        eas = data.draw(
            st.lists(
                st.integers(min_value=0x1000, max_value=0xFFFF),
                min_size=num_comments,
                max_size=num_comments,
                unique=True,
            )
        )
        comments = data.draw(
            st.lists(comment_strings, min_size=num_comments, max_size=num_comments)
        )

        for ea, comment in zip(eas, comments):
            bridge.set_comment(ea, comment, "regular")

        # Pick a range that covers some of the EAs
        sorted_eas = sorted(eas)
        start_ea = sorted_eas[0]
        end_ea = sorted_eas[-1] + 1  # exclusive end

        result = bridge.get_comments_range(start_ea, end_ea)

        # All returned comments must have EAs within [start_ea, end_ea)
        for ci in result:
            ci_ea = int(ci.ea, 16)
            assert start_ea <= ci_ea < end_ea

    # ---------------------------------------------------------------
    # 17f: get_comments at EA with no comments returns None fields
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(ea_str=ea_strings)
    def test_get_comments_no_comments_returns_none(self, ea_str: str) -> None:
        """**Validates: Requirements 12.4**"""
        bridge = MockIdaBridge()
        ea = int(ea_str, 16)

        ci = bridge.get_comments(ea)
        assert ci.regular is None
        assert ci.repeatable is None
        assert ci.function_comment is None

    # ---------------------------------------------------------------
    # 17g: Setting one comment type does not affect others
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(ea_str=ea_strings, comment=comment_strings)
    def test_setting_regular_does_not_affect_repeatable(
        self, ea_str: str, comment: str
    ) -> None:
        """**Validates: Requirements 12.1, 12.2**"""
        bridge = MockIdaBridge()
        ea = int(ea_str, 16)

        bridge.set_comment(ea, comment, "regular")

        ci = bridge.get_comments(ea)
        assert ci.regular == comment
        assert ci.repeatable is None
        assert ci.function_comment is None

    # ---------------------------------------------------------------
    # 17h: Range query with multiple comment types
    # ---------------------------------------------------------------

    @settings(max_examples=50)
    @given(
        data=st.data(),
    )
    def test_range_query_preserves_comment_types(
        self, data: st.DataObject
    ) -> None:
        """**Validates: Requirements 12.5**"""
        bridge = MockIdaBridge()

        # Set up comments at a few known EAs with different types
        eas = data.draw(
            st.lists(
                st.integers(min_value=0x1000, max_value=0xFFFF),
                min_size=2,
                max_size=5,
                unique=True,
            )
        )

        for ea in eas:
            comment = data.draw(comment_strings)
            comment_type = data.draw(st.sampled_from(["regular", "repeatable", "function"]))
            bridge.set_comment(ea, comment, comment_type)

        sorted_eas = sorted(eas)
        start_ea = sorted_eas[0]
        end_ea = sorted_eas[-1] + 1

        result = bridge.get_comments_range(start_ea, end_ea)

        # Every returned CommentInfo should have at least one non-None comment field
        for ci in result:
            has_comment = (
                ci.regular is not None
                or ci.repeatable is not None
                or ci.function_comment is not None
            )
            assert has_comment
