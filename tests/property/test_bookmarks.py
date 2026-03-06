"""Property-based tests for bookmark lifecycle round-trip behaviour.

Property 23 from the IDA Headless MCP design document.
"""

from __future__ import annotations

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from ida_headless_mcp.models import BookmarkInfo
from tests.conftest import MockIdaBridge
from tests.strategies import ea_integers, comment_strings


# ===================================================================
# Property 23: Bookmark lifecycle round-trip
# ===================================================================


class TestBookmarkLifecycleRoundTrip:
    """Property 23: Bookmark lifecycle round-trip.

    *For any* EA and description, adding a bookmark and then listing
    bookmarks should include an entry with that EA and description.
    Deleting the bookmark and listing again should exclude it.

    **Validates: Requirements 16.1, 16.2, 16.3**
    """

    # ---------------------------------------------------------------
    # 23a: Add bookmark, list bookmarks, verify it appears
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
        description=comment_strings,
    )
    def test_add_bookmark_appears_in_list(self, ea: int, description: str) -> None:
        """**Validates: Requirements 16.1, 16.2**"""
        bridge = MockIdaBridge()

        result = bridge.add_bookmark(ea, description)
        assert result.success

        bookmarks = bridge.list_bookmarks()
        ea_str = f"0x{ea:x}"
        matching = [b for b in bookmarks if b.ea == ea_str]
        assert len(matching) == 1
        assert matching[0].description == description

    # ---------------------------------------------------------------
    # 23b: Add then delete bookmark, verify it's removed
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
        description=comment_strings,
    )
    def test_add_then_delete_removes_bookmark(self, ea: int, description: str) -> None:
        """**Validates: Requirements 16.1, 16.3**"""
        bridge = MockIdaBridge()

        bridge.add_bookmark(ea, description)
        delete_result = bridge.delete_bookmark(ea)
        assert delete_result.success

        bookmarks = bridge.list_bookmarks()
        ea_str = f"0x{ea:x}"
        matching = [b for b in bookmarks if b.ea == ea_str]
        assert len(matching) == 0

    # ---------------------------------------------------------------
    # 23c: Multiple bookmarks at different EAs all appear in list
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        data=st.data(),
        num_bookmarks=st.integers(min_value=2, max_value=8),
    )
    def test_multiple_bookmarks_all_appear(
        self, data: st.DataObject, num_bookmarks: int
    ) -> None:
        """**Validates: Requirements 16.1, 16.2**"""
        bridge = MockIdaBridge()

        eas = data.draw(
            st.lists(
                st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
                min_size=num_bookmarks,
                max_size=num_bookmarks,
                unique=True,
            )
        )
        descriptions = data.draw(
            st.lists(
                comment_strings,
                min_size=num_bookmarks,
                max_size=num_bookmarks,
            )
        )

        for ea, desc in zip(eas, descriptions):
            result = bridge.add_bookmark(ea, desc)
            assert result.success

        bookmarks = bridge.list_bookmarks()
        bookmark_eas = {b.ea for b in bookmarks}

        for ea in eas:
            assert f"0x{ea:x}" in bookmark_eas

        assert len(bookmarks) == num_bookmarks

    # ---------------------------------------------------------------
    # 23d: Deleting a non-existent bookmark returns failure
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
    )
    def test_delete_nonexistent_bookmark_fails(self, ea: int) -> None:
        """**Validates: Requirements 16.3**"""
        bridge = MockIdaBridge()

        result = bridge.delete_bookmark(ea)
        assert not result.success

    # ---------------------------------------------------------------
    # 23e: Adding bookmark at same EA overwrites description
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
        desc1=comment_strings,
        desc2=comment_strings,
    )
    def test_add_bookmark_same_ea_overwrites(
        self, ea: int, desc1: str, desc2: str
    ) -> None:
        """**Validates: Requirements 16.1, 16.2**"""
        bridge = MockIdaBridge()

        bridge.add_bookmark(ea, desc1)
        bridge.add_bookmark(ea, desc2)

        bookmarks = bridge.list_bookmarks()
        ea_str = f"0x{ea:x}"
        matching = [b for b in bookmarks if b.ea == ea_str]
        assert len(matching) == 1
        assert matching[0].description == desc2
