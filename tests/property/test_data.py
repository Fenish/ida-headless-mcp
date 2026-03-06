"""Property-based tests for data/names round-trip behaviour.

Property 27 from the IDA Headless MCP design document.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from tests.conftest import MockIdaBridge
from tests.strategies import function_names, type_definitions, ea_integers


# ===================================================================
# Property 27: Name and data type round-trip
# ===================================================================


class TestNameAndDataTypeRoundTrip:
    """Property 27: Name and data type round-trip.

    *For any* EA and valid name, renaming a location and then listing
    names should show the new name at that EA. For any valid type string,
    changing the data type at an EA and then querying should return the
    new type.

    **Validates: Requirements 20.1, 20.2, 20.3, 20.4**
    """

    # ---------------------------------------------------------------
    # 27a: Add function (registers name), rename it, verify list_names
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
        original_name=function_names,
        new_name=function_names,
    )
    def test_rename_appears_in_list_names(
        self, ea: int, original_name: str, new_name: str
    ) -> None:
        """**Validates: Requirements 20.1, 20.2**"""
        bridge = MockIdaBridge()

        bridge.add_function(ea, original_name, size=16)

        result = bridge.rename_location(ea, new_name)
        assert result.success

        names = bridge.list_names()
        ea_str = f"0x{ea:x}"
        matching = [n for n in names if n.ea == ea_str]
        assert len(matching) == 1
        assert matching[0].name == new_name

    # ---------------------------------------------------------------
    # 27b: Set data type at EA, get data type, verify type_name matches
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
        type_str=type_definitions,
    )
    def test_set_data_type_then_get(self, ea: int, type_str: str) -> None:
        """**Validates: Requirements 20.3, 20.4**"""
        bridge = MockIdaBridge()

        result = bridge.set_data_type(ea, type_str)
        assert result.success

        dt = bridge.get_data_type(ea)
        assert dt.type_name == type_str
        assert dt.ea == f"0x{ea:x}"
        assert dt.size > 0

    # ---------------------------------------------------------------
    # 27c: Rename then rename again, verify only latest name persists
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
        name1=function_names,
        name2=function_names,
    )
    def test_rename_twice_keeps_latest(
        self, ea: int, name1: str, name2: str
    ) -> None:
        """**Validates: Requirements 20.1, 20.2**"""
        bridge = MockIdaBridge()

        bridge.rename_location(ea, name1)
        bridge.rename_location(ea, name2)

        names = bridge.list_names()
        ea_str = f"0x{ea:x}"
        matching = [n for n in names if n.ea == ea_str]
        assert len(matching) == 1
        assert matching[0].name == name2

    # ---------------------------------------------------------------
    # 27d: Set data type then set different type, verify latest persists
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
        type1=type_definitions,
        type2=type_definitions,
    )
    def test_set_data_type_twice_keeps_latest(
        self, ea: int, type1: str, type2: str
    ) -> None:
        """**Validates: Requirements 20.3, 20.4**"""
        bridge = MockIdaBridge()

        bridge.set_data_type(ea, type1)
        bridge.set_data_type(ea, type2)

        dt = bridge.get_data_type(ea)
        assert dt.type_name == type2

    # ---------------------------------------------------------------
    # 27e: Default data type for unset EA is "byte" with size 1
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
    )
    def test_default_data_type_is_byte(self, ea: int) -> None:
        """**Validates: Requirements 20.3**"""
        bridge = MockIdaBridge()

        dt = bridge.get_data_type(ea)
        assert dt.type_name == "byte"
        assert dt.size == 1
        assert dt.ea == f"0x{ea:x}"
