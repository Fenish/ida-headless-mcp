"""Property-based tests for type lifecycle and type application round-trips.

Properties 15 and 16 from the IDA Headless MCP design document.
"""

from __future__ import annotations

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from ida_headless_mcp.models import FieldDef, TypeInfo
from tests.conftest import MockIdaBridge
from tests.strategies import (
    ea_strings,
    field_defs,
    function_names,
    type_definitions,
    type_infos,
)


# ===================================================================
# Property 15: Type lifecycle round-trip
# ===================================================================


class TestTypeLifecycleRoundTrip:
    """Property 15: Type lifecycle round-trip.

    *For any* struct with a valid name and fields, creating it and then
    listing types should include it with correct name and size. Deleting
    it and listing again should exclude it. Adding a field to an existing
    struct and then inspecting it should show the new field at the correct
    offset.

    **Validates: Requirements 11.1, 11.2, 11.3, 11.5**
    """

    # ---------------------------------------------------------------
    # 15a: Create struct then list_types includes it
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(name=function_names, fields=st.lists(field_defs(), min_size=0, max_size=5))
    def test_create_struct_appears_in_list(
        self, name: str, fields: list[FieldDef]
    ) -> None:
        """**Validates: Requirements 11.1, 11.2**"""
        bridge = MockIdaBridge()

        result = bridge.create_struct(name, fields)
        assert result.success

        types = bridge.list_types()
        names = [t.name for t in types]
        assert name in names

    # ---------------------------------------------------------------
    # 15b: Created struct has correct name in TypeInfo
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(name=function_names, fields=st.lists(field_defs(), min_size=0, max_size=5))
    def test_created_struct_has_correct_name(
        self, name: str, fields: list[FieldDef]
    ) -> None:
        """**Validates: Requirements 11.1, 11.2**"""
        bridge = MockIdaBridge()
        bridge.create_struct(name, fields)

        types = bridge.list_types()
        matching = [t for t in types if t.name == name]
        assert len(matching) == 1
        assert matching[0].name == name

    # ---------------------------------------------------------------
    # 15c: Delete struct removes it from list_types
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(name=function_names, fields=st.lists(field_defs(), min_size=0, max_size=5))
    def test_delete_struct_removes_from_list(
        self, name: str, fields: list[FieldDef]
    ) -> None:
        """**Validates: Requirements 11.5**"""
        bridge = MockIdaBridge()

        bridge.create_struct(name, fields)
        types_before = bridge.list_types()
        assert any(t.name == name for t in types_before)

        delete_result = bridge.delete_type(name)
        assert delete_result.success

        types_after = bridge.list_types()
        assert not any(t.name == name for t in types_after)

    # ---------------------------------------------------------------
    # 15d: Add field to existing struct increases field count
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        name=function_names,
        initial_fields=st.lists(field_defs(), min_size=0, max_size=3),
        new_field=field_defs(),
    )
    def test_add_field_reflected_in_struct(
        self, name: str, initial_fields: list[FieldDef], new_field: FieldDef
    ) -> None:
        """**Validates: Requirements 11.3**"""
        bridge = MockIdaBridge()

        bridge.create_struct(name, initial_fields)

        add_result = bridge.add_struct_field(name, new_field)
        assert add_result.success

        # The internal fields list should now include the new field
        entry = bridge.types[name]
        field_names = [f.name for f in entry["fields"]]
        assert new_field.name in field_names

    # ---------------------------------------------------------------
    # 15e: Duplicate struct name fails
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(name=function_names, fields=st.lists(field_defs(), min_size=0, max_size=3))
    def test_duplicate_struct_name_fails(
        self, name: str, fields: list[FieldDef]
    ) -> None:
        """**Validates: Requirements 11.1, 11.2**"""
        bridge = MockIdaBridge()

        first = bridge.create_struct(name, fields)
        assert first.success

        second = bridge.create_struct(name, fields)
        assert not second.success

    # ---------------------------------------------------------------
    # 15f: Create/list/delete lifecycle with multiple structs
    # ---------------------------------------------------------------

    @settings(max_examples=50)
    @given(
        names=st.lists(
            function_names, min_size=1, max_size=5, unique=True
        ),
    )
    def test_multiple_struct_lifecycle(self, names: list[str]) -> None:
        """**Validates: Requirements 11.1, 11.2, 11.5**"""
        bridge = MockIdaBridge()

        # Create all structs
        for name in names:
            result = bridge.create_struct(name, [])
            assert result.success

        # All should appear in list
        listed = bridge.list_types()
        listed_names = {t.name for t in listed}
        for name in names:
            assert name in listed_names

        # Delete first struct
        del_result = bridge.delete_type(names[0])
        assert del_result.success

        # Remaining structs still present, deleted one gone
        listed_after = bridge.list_types()
        listed_names_after = {t.name for t in listed_after}
        assert names[0] not in listed_names_after
        for name in names[1:]:
            assert name in listed_names_after


# ===================================================================
# Property 16: Type application round-trip
# ===================================================================


class TestTypeApplicationRoundTrip:
    """Property 16: Type application round-trip.

    *For any* valid type string and EA, applying the type and then
    querying the data type at that EA should return the applied type.

    **Validates: Requirements 11.4**
    """

    # ---------------------------------------------------------------
    # 16a: apply_type then get_data_type returns applied type
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea_str=ea_strings,
        type_str=type_definitions,
    )
    def test_apply_then_query_returns_applied_type(
        self, ea_str: str, type_str: str
    ) -> None:
        """**Validates: Requirements 11.4**"""
        bridge = MockIdaBridge()
        ea = int(ea_str, 16)

        apply_result = bridge.apply_type(ea, type_str)
        assert apply_result.success

        dt = bridge.get_data_type(ea)
        assert dt.type_name == type_str

    # ---------------------------------------------------------------
    # 16b: apply_type overwrites previous type at same EA
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea_str=ea_strings,
        type_str_1=type_definitions,
        type_str_2=type_definitions,
    )
    def test_apply_type_overwrites_previous(
        self, ea_str: str, type_str_1: str, type_str_2: str
    ) -> None:
        """**Validates: Requirements 11.4**"""
        bridge = MockIdaBridge()
        ea = int(ea_str, 16)

        bridge.apply_type(ea, type_str_1)
        bridge.apply_type(ea, type_str_2)

        dt = bridge.get_data_type(ea)
        assert dt.type_name == type_str_2

    # ---------------------------------------------------------------
    # 16c: apply_type at different EAs are independent
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea_str_1=ea_strings,
        ea_str_2=ea_strings,
        type_str_1=type_definitions,
        type_str_2=type_definitions,
    )
    def test_apply_type_at_different_eas_independent(
        self, ea_str_1: str, ea_str_2: str, type_str_1: str, type_str_2: str
    ) -> None:
        """**Validates: Requirements 11.4**"""
        ea1 = int(ea_str_1, 16)
        ea2 = int(ea_str_2, 16)
        assume(ea1 != ea2)

        bridge = MockIdaBridge()

        bridge.apply_type(ea1, type_str_1)
        bridge.apply_type(ea2, type_str_2)

        dt1 = bridge.get_data_type(ea1)
        dt2 = bridge.get_data_type(ea2)
        assert dt1.type_name == type_str_1
        assert dt2.type_name == type_str_2

    # ---------------------------------------------------------------
    # 16d: get_data_type returns correct EA in result
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea_str=ea_strings,
        type_str=type_definitions,
    )
    def test_applied_type_result_has_correct_ea(
        self, ea_str: str, type_str: str
    ) -> None:
        """**Validates: Requirements 11.4**"""
        bridge = MockIdaBridge()
        ea = int(ea_str, 16)

        bridge.apply_type(ea, type_str)

        dt = bridge.get_data_type(ea)
        assert dt.ea == ea_str
