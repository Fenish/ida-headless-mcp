"""Property-based tests for enum lifecycle round-trip behaviour.

Property 26 from the IDA Headless MCP design document.
"""

from __future__ import annotations

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from ida_headless_mcp.models import EnumInfo, EnumMember
from tests.conftest import MockIdaBridge
from tests.strategies import enum_names, enum_member_names, enum_members


# ===================================================================
# Property 26: Enum lifecycle round-trip
# ===================================================================


class TestEnumLifecycleRoundTrip:
    """Property 26: Enum lifecycle round-trip.

    *For any* enum with a valid name and members, creating it and then
    listing enums should include it with correct name and member_count.
    Adding a member and then listing should show the updated member_count.

    **Validates: Requirements 19.1, 19.2, 19.3**
    """

    # ---------------------------------------------------------------
    # 26a: Create enum, list enums, verify it appears with correct
    #      name and member_count
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        name=enum_names,
        members=st.lists(enum_members(), min_size=0, max_size=8, unique_by=lambda m: m.name),
    )
    def test_create_enum_appears_in_list(
        self, name: str, members: list[EnumMember]
    ) -> None:
        """**Validates: Requirements 19.1, 19.2**"""
        bridge = MockIdaBridge()

        result = bridge.create_enum(name, members)
        assert result.success

        enums = bridge.list_enums()
        matching = [e for e in enums if e.name == name]
        assert len(matching) == 1
        assert matching[0].member_count == len(members)

    # ---------------------------------------------------------------
    # 26b: Create enum then add member, verify member_count increases
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        name=enum_names,
        initial_members=st.lists(enum_members(), min_size=0, max_size=5, unique_by=lambda m: m.name),
        new_member_name=enum_member_names,
        new_member_value=st.integers(min_value=0, max_value=0xFFFFFFFF),
    )
    def test_add_member_increases_count(
        self,
        name: str,
        initial_members: list[EnumMember],
        new_member_name: str,
        new_member_value: int,
    ) -> None:
        """**Validates: Requirements 19.2, 19.3**"""
        # Ensure the new member name doesn't collide with existing ones
        existing_names = {m.name for m in initial_members}
        assume(new_member_name not in existing_names)

        bridge = MockIdaBridge()

        bridge.create_enum(name, initial_members)
        original_count = len(initial_members)

        add_result = bridge.add_enum_member(name, new_member_name, new_member_value)
        assert add_result.success

        enums = bridge.list_enums()
        matching = [e for e in enums if e.name == name]
        assert len(matching) == 1
        assert matching[0].member_count == original_count + 1

    # ---------------------------------------------------------------
    # 26c: Creating duplicate enum returns failure
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        name=enum_names,
        members=st.lists(enum_members(), min_size=0, max_size=5, unique_by=lambda m: m.name),
    )
    def test_create_duplicate_enum_fails(
        self, name: str, members: list[EnumMember]
    ) -> None:
        """**Validates: Requirements 19.2**"""
        bridge = MockIdaBridge()

        first = bridge.create_enum(name, members)
        assert first.success

        second = bridge.create_enum(name, members)
        assert not second.success

    # ---------------------------------------------------------------
    # 26d: Adding member to non-existent enum returns failure
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        enum_name=enum_names,
        member_name=enum_member_names,
        member_value=st.integers(min_value=0, max_value=0xFFFFFFFF),
    )
    def test_add_member_nonexistent_enum_fails(
        self, enum_name: str, member_name: str, member_value: int
    ) -> None:
        """**Validates: Requirements 19.3**"""
        bridge = MockIdaBridge()

        result = bridge.add_enum_member(enum_name, member_name, member_value)
        assert not result.success

    # ---------------------------------------------------------------
    # 26e: Multiple enums tracked independently
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        data=st.data(),
        num_enums=st.integers(min_value=2, max_value=6),
    )
    def test_multiple_enums_tracked_independently(
        self, data: st.DataObject, num_enums: int
    ) -> None:
        """**Validates: Requirements 19.1, 19.2**"""
        bridge = MockIdaBridge()

        names = data.draw(
            st.lists(
                enum_names,
                min_size=num_enums,
                max_size=num_enums,
                unique=True,
            )
        )
        member_lists = [
            data.draw(
                st.lists(enum_members(), min_size=0, max_size=5, unique_by=lambda m: m.name)
            )
            for _ in range(num_enums)
        ]

        for name, members in zip(names, member_lists):
            result = bridge.create_enum(name, members)
            assert result.success

        enums = bridge.list_enums()
        assert len(enums) == num_enums

        enum_map = {e.name: e for e in enums}
        for name, members in zip(names, member_lists):
            assert name in enum_map
            assert enum_map[name].member_count == len(members)
