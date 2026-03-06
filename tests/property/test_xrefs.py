"""Property-based tests for cross-reference structural validity.

Property 10 from the IDA Headless MCP design document.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from ida_headless_mcp.models import FunctionXrefs, XrefInfo
from tests.conftest import MockIdaBridge
from tests.strategies import (
    ea_strings,
    function_names,
    xref_infos,
    xref_info_lists,
    xref_types,
)

# Valid xref_type values per the design document
VALID_XREF_TYPES = frozenset(
    {"code_call", "code_jump", "data_read", "data_write", "data_offset"}
)


# ===================================================================
# Property 10: Cross-reference structural validity
# ===================================================================


class TestCrossReferenceStructuralValidity:
    """Property 10: Cross-reference structural validity.

    *For any* xref result (to or from), each entry must contain source_ea,
    target_ea, and xref_type. The xref_type must be one of: code_call,
    code_jump, data_read, data_write, data_offset. For function xrefs,
    the result must contain both callers and callees lists.

    **Validates: Requirements 7.1, 7.2, 7.3, 7.4**
    """

    # ---------------------------------------------------------------
    # 10a: Generated XrefInfo instances have all required fields
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(xref=xref_infos())
    def test_xref_info_has_all_required_fields(self, xref: XrefInfo) -> None:
        # Feature: ida-headless-mcp, Property 10: Cross-reference structural validity
        # source_ea must be a hex string
        assert isinstance(xref.source_ea, str)
        assert xref.source_ea.startswith("0x")
        int(xref.source_ea, 16)  # must parse as valid hex

        # target_ea must be a hex string
        assert isinstance(xref.target_ea, str)
        assert xref.target_ea.startswith("0x")
        int(xref.target_ea, 16)

        # xref_type must be a valid value
        assert isinstance(xref.xref_type, str)
        assert xref.xref_type in VALID_XREF_TYPES, (
            f"Invalid xref_type: {xref.xref_type!r}"
        )

        # Optional fields must be str or None
        assert xref.source_function is None or isinstance(xref.source_function, str)
        assert xref.target_function is None or isinstance(xref.target_function, str)

    # ---------------------------------------------------------------
    # 10b: xref_type is always one of the valid values
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(xref_type=xref_types)
    def test_xref_type_is_valid(self, xref_type: str) -> None:
        # Feature: ida-headless-mcp, Property 10: Cross-reference structural validity
        assert xref_type in VALID_XREF_TYPES

    # ---------------------------------------------------------------
    # 10c: Lists of XrefInfo all have valid structure
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(xrefs=xref_info_lists)
    def test_xref_list_all_entries_valid(self, xrefs: list[XrefInfo]) -> None:
        # Feature: ida-headless-mcp, Property 10: Cross-reference structural validity
        for xref in xrefs:
            assert isinstance(xref.source_ea, str) and xref.source_ea.startswith("0x")
            assert isinstance(xref.target_ea, str) and xref.target_ea.startswith("0x")
            assert xref.xref_type in VALID_XREF_TYPES

    # ---------------------------------------------------------------
    # 10d: MockIdaBridge xrefs-to returns structurally valid entries
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        source_ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
        target_ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
    )
    def test_bridge_xrefs_to_structural_validity(
        self, source_ea: int, target_ea: int
    ) -> None:
        # Feature: ida-headless-mcp, Property 10: Cross-reference structural validity
        assume(source_ea != target_ea)

        bridge = MockIdaBridge()
        bridge.add_function(source_ea, f"src_{source_ea:x}", 64)
        bridge.add_function(target_ea, f"tgt_{target_ea:x}", 64)
        bridge.add_xref(source_ea, target_ea)

        xrefs = bridge.get_xrefs_to(target_ea)

        assert len(xrefs) >= 1
        for xref in xrefs:
            assert isinstance(xref.source_ea, str) and xref.source_ea.startswith("0x")
            assert isinstance(xref.target_ea, str) and xref.target_ea.startswith("0x")
            assert xref.xref_type in VALID_XREF_TYPES
            assert xref.target_ea == f"0x{target_ea:x}"

    # ---------------------------------------------------------------
    # 10e: MockIdaBridge xrefs-from returns structurally valid entries
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        source_ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
        target_ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
    )
    def test_bridge_xrefs_from_structural_validity(
        self, source_ea: int, target_ea: int
    ) -> None:
        # Feature: ida-headless-mcp, Property 10: Cross-reference structural validity
        assume(source_ea != target_ea)

        bridge = MockIdaBridge()
        bridge.add_function(source_ea, f"src_{source_ea:x}", 64)
        bridge.add_function(target_ea, f"tgt_{target_ea:x}", 64)
        bridge.add_xref(source_ea, target_ea)

        xrefs = bridge.get_xrefs_from(source_ea)

        assert len(xrefs) >= 1
        for xref in xrefs:
            assert isinstance(xref.source_ea, str) and xref.source_ea.startswith("0x")
            assert isinstance(xref.target_ea, str) and xref.target_ea.startswith("0x")
            assert xref.xref_type in VALID_XREF_TYPES
            assert xref.source_ea == f"0x{source_ea:x}"

    # ---------------------------------------------------------------
    # 10f: Function xrefs contain both callers and callees lists
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        caller_ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
        func_ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
        callee_ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
    )
    def test_function_xrefs_has_callers_and_callees(
        self, caller_ea: int, func_ea: int, callee_ea: int
    ) -> None:
        # Feature: ida-headless-mcp, Property 10: Cross-reference structural validity
        assume(len({caller_ea, func_ea, callee_ea}) == 3)

        bridge = MockIdaBridge()
        bridge.add_function(caller_ea, f"caller_{caller_ea:x}", 64)
        bridge.add_function(func_ea, f"func_{func_ea:x}", 64)
        bridge.add_function(callee_ea, f"callee_{callee_ea:x}", 64)
        bridge.add_xref(caller_ea, func_ea)
        bridge.add_xref(func_ea, callee_ea)

        func_xrefs = bridge.get_function_xrefs(func_ea)

        # Must be a FunctionXrefs with both lists
        assert isinstance(func_xrefs, FunctionXrefs)
        assert isinstance(func_xrefs.callers, list)
        assert isinstance(func_xrefs.callees, list)

        # Callers should include the caller
        assert len(func_xrefs.callers) >= 1
        caller_sources = {x.source_ea for x in func_xrefs.callers}
        assert f"0x{caller_ea:x}" in caller_sources

        # Callees should include the callee
        assert len(func_xrefs.callees) >= 1
        callee_targets = {x.target_ea for x in func_xrefs.callees}
        assert f"0x{callee_ea:x}" in callee_targets

        # All entries must be structurally valid
        for xref in func_xrefs.callers + func_xrefs.callees:
            assert xref.xref_type in VALID_XREF_TYPES
