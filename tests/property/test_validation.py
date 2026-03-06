"""Property-based tests for EA validation and error response structure.

Properties 29 and 30 from the IDA Headless MCP design document.
"""

from __future__ import annotations

import string

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.models import parse_ea


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# Strings that are valid numeric literals accepted by int(..., 0)
_hex_digits = st.text(
    alphabet=string.hexdigits, min_size=1, max_size=12
).map(lambda s: "0x" + s)

_decimal_digits = st.integers(min_value=0, max_value=2**64 - 1).map(str)

_octal_digits = st.integers(min_value=0, max_value=0o777777).map(lambda n: f"0o{oct(n)[2:]}")

_binary_digits = st.integers(min_value=0, max_value=0xFFFF).map(lambda n: f"0b{bin(n)[2:]}")

valid_ea_strings = st.one_of(_hex_digits, _decimal_digits, _octal_digits, _binary_digits)

# Strings that are definitely NOT valid numeric literals
non_numeric_strings = st.text(
    alphabet=string.ascii_letters + "!@#$%^&*()_+-=[]{}|;':\",./<>? ",
    min_size=1,
    max_size=50,
).filter(lambda s: not s.strip().lstrip("-").isdigit())

# Strategy for all ErrorCode enum members
error_codes = st.sampled_from(list(ErrorCode))

# Strategy for tool names (non-empty strings)
tool_names = st.text(
    alphabet=string.ascii_lowercase + "_",
    min_size=1,
    max_size=40,
).filter(lambda s: len(s.strip()) > 0 and s[0] != "_")

# Strategy for human-readable error messages
error_messages = st.text(min_size=1, max_size=200).filter(lambda s: len(s.strip()) > 0)


# ===================================================================
# Property 29: EA validation
# ===================================================================
# Feature: ida-headless-mcp, Property 29: EA validation


class TestEaValidationProperty:
    """Property 29: EA validation.

    *For any* non-numeric string or out-of-range integer, ``parse_ea``
    should raise a ``ValueError``. *For any* valid hex string (e.g.,
    "0x401000") or decimal string, ``parse_ea`` should return the correct
    integer value.

    **Validates: Requirements 22.1**
    """

    @settings(max_examples=100)
    @given(ea_str=valid_ea_strings)
    def test_valid_ea_returns_correct_int(self, ea_str: str) -> None:
        # Feature: ida-headless-mcp, Property 29: EA validation
        result = parse_ea(ea_str)
        expected = int(ea_str, 0)
        assert result == expected
        assert isinstance(result, int)

    @settings(max_examples=100)
    @given(s=non_numeric_strings)
    def test_non_numeric_string_raises_value_error(self, s: str) -> None:
        # Feature: ida-headless-mcp, Property 29: EA validation
        # Ensure the string truly cannot be parsed as an integer
        try:
            int(s, 0)
        except (ValueError, TypeError):
            pass  # Good — it's genuinely non-numeric
        else:
            assume(False)  # Skip if Hypothesis accidentally generated a valid number

        with pytest.raises(ValueError, match="Invalid address"):
            parse_ea(s)


# ===================================================================
# Property 30: Error response structure consistency
# ===================================================================
# Feature: ida-headless-mcp, Property 30: Error response structure consistency


class TestErrorStructureProperty:
    """Property 30: Error response structure consistency.

    *For any* error response from any tool, the response must contain an
    ``error_code`` (from the defined ErrorCode enum), a human-readable
    ``message``, and the ``tool_name`` that failed. For non-existent
    session IDs, the error code must be ``SESSION_NOT_FOUND``.

    **Validates: Requirements 22.2, 22.4**
    """

    @settings(max_examples=100)
    @given(code=error_codes, message=error_messages, tool_name=tool_names)
    def test_error_response_has_all_required_fields(
        self, code: ErrorCode, message: str, tool_name: str
    ) -> None:
        # Feature: ida-headless-mcp, Property 30: Error response structure consistency
        err = McpToolError(code=code, message=message, tool_name=tool_name)
        d = err.to_dict()

        # Top-level must have "error" key
        assert "error" in d

        inner = d["error"]

        # All three required fields must be present
        assert "code" in inner
        assert "message" in inner
        assert "tool_name" in inner

        # Values must match what was provided
        assert inner["code"] == code
        assert inner["message"] == message
        assert inner["tool_name"] == tool_name

        # code must be a valid ErrorCode value
        assert inner["code"] in {e.value for e in ErrorCode}

        # message must be a non-empty string
        assert isinstance(inner["message"], str)
        assert len(inner["message"]) > 0

        # tool_name must be a non-empty string
        assert isinstance(inner["tool_name"], str)
        assert len(inner["tool_name"]) > 0

    @settings(max_examples=100)
    @given(
        session_id=st.text(min_size=1, max_size=50).filter(lambda s: len(s.strip()) > 0),
        tool_name=tool_names,
    )
    def test_session_not_found_uses_correct_error_code(
        self, session_id: str, tool_name: str
    ) -> None:
        # Feature: ida-headless-mcp, Property 30: Error response structure consistency
        err = McpToolError(
            code=ErrorCode.SESSION_NOT_FOUND,
            message=f"No session found with ID '{session_id}'",
            tool_name=tool_name,
        )
        d = err.to_dict()

        assert d["error"]["code"] == ErrorCode.SESSION_NOT_FOUND
        assert d["error"]["code"] == "SESSION_NOT_FOUND"
        assert session_id in d["error"]["message"]
