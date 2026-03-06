"""Property-based tests for decompilation result completeness.

Property 8 from the IDA Headless MCP design document.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ida_headless_mcp.models import DecompileResult
from tests.conftest import MockIdaBridge
from tests.strategies import ea_strings, function_names, type_definitions


# ---------------------------------------------------------------------------
# Hypothesis strategies for decompilation
# ---------------------------------------------------------------------------

# Generate random pseudocode strings (non-empty, C-like)
_pseudocode_bodies = st.from_regex(
    r"[a-zA-Z_][a-zA-Z0-9_ ]{0,49}", fullmatch=True
)

pseudocode_strings = st.builds(
    lambda ret, name, body: f"{ret} {name}() {{ {body}; }}",
    ret=st.sampled_from(["int", "void", "char*", "long"]),
    name=function_names,
    body=_pseudocode_bodies,
)

parameter_type_lists = st.lists(type_definitions, min_size=0, max_size=8)

# Variable hint pairs: old_name -> new_name
# Use fixed-width numeric suffixes to avoid prefix collisions in str.replace
_var_name = st.integers(min_value=0, max_value=999).map(lambda n: f"v{n:03d}")
_hint_name = st.from_regex(r"renamed_[a-z]{1,10}", fullmatch=True)
var_hint_maps = st.dictionaries(
    keys=_var_name,
    values=_hint_name,
    min_size=1,
    max_size=5,
)


# ===================================================================
# Property 8: Decompilation result completeness
# ===================================================================


class TestDecompilationResultCompleteness:
    """Property 8: Decompilation result completeness.

    *For any* successful decompilation result, the response must include
    a non-empty pseudocode string, the function's EA, name, and parameter
    types. When variable renaming hints are provided, the suggested names
    must appear in the returned pseudocode.

    **Validates: Requirements 5.1, 5.2, 5.5**
    """

    # ---------------------------------------------------------------
    # 8a: Generated DecompileResult instances have all required fields
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea=ea_strings,
        name=function_names,
        pseudocode=pseudocode_strings,
        param_types=parameter_type_lists,
    )
    def test_decompile_result_fields_present_and_nonempty(
        self,
        ea: str,
        name: str,
        pseudocode: str,
        param_types: list[str],
    ) -> None:
        # Feature: ida-headless-mcp, Property 8: Decompilation result completeness
        result = DecompileResult(
            ea=ea,
            name=name,
            pseudocode=pseudocode,
            parameter_types=param_types,
        )

        assert isinstance(result.ea, str) and len(result.ea) > 0
        assert isinstance(result.name, str) and len(result.name) > 0
        assert isinstance(result.pseudocode, str) and len(result.pseudocode) > 0
        assert isinstance(result.parameter_types, list)

    # ---------------------------------------------------------------
    # 8b: MockIdaBridge decompile returns complete results
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
        func_name=function_names,
        size=st.integers(min_value=16, max_value=0x1000),
    )
    def test_mock_bridge_decompile_completeness(
        self,
        ea: int,
        func_name: str,
        size: int,
    ) -> None:
        # Feature: ida-headless-mcp, Property 8: Decompilation result completeness
        bridge = MockIdaBridge()
        bridge.add_function(ea, func_name, size)

        result = bridge.decompile_function(ea)

        assert result is not None
        assert isinstance(result.ea, str) and len(result.ea) > 0
        assert result.ea == f"0x{ea:x}"
        assert isinstance(result.name, str) and len(result.name) > 0
        assert result.name == func_name
        assert isinstance(result.pseudocode, str) and len(result.pseudocode) > 0
        assert isinstance(result.parameter_types, list)
        assert len(result.parameter_types) > 0

    # ---------------------------------------------------------------
    # 8c: Variable hints appear in decompiled output
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
        func_name=function_names,
        var_hints=var_hint_maps,
    )
    def test_var_hints_appear_in_pseudocode(
        self,
        ea: int,
        func_name: str,
        var_hints: dict[str, str],
    ) -> None:
        # Feature: ida-headless-mcp, Property 8: Decompilation result completeness
        bridge = MockIdaBridge()
        bridge.add_function(ea, func_name, 64)

        # Build pseudocode that contains the old variable names so
        # the hint replacement has something to work with.
        # Each old var name gets a unique assignment statement.
        body_parts = [f"{old_name} = 0" for old_name in sorted(var_hints)]
        custom_pseudocode = (
            f"int func() {{ " + "; ".join(body_parts) + "; return 0; }"
        )
        bridge.decompile_results[ea] = custom_pseudocode

        result = bridge.decompile_function(ea, var_hints=var_hints)

        assert result is not None
        for new_name in var_hints.values():
            assert new_name in result.pseudocode, (
                f"Expected hint '{new_name}' in pseudocode but got: {result.pseudocode}"
            )
