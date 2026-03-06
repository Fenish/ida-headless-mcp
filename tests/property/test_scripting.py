"""Property-based tests for script execution output capture.

Property 24 from the IDA Headless MCP design document.
"""

from __future__ import annotations

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from tests.conftest import MockIdaBridge


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Printable strings that don't contain quotes or backslashes (to keep
# print("...") parsing simple inside MockIdaBridge).
_safe_print_text = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N", "P", "S", "Z"),
        blacklist_characters="\"'\\()\n\r",
    ),
    min_size=1,
    max_size=60,
)


# ===================================================================
# Property 24: Script execution output capture
# ===================================================================


class TestScriptExecutionOutputCapture:
    """Property 24: Script execution output capture.

    *For any* IDAPython script string that writes to stdout, executing it
    should return a result containing the stdout output.  If the script
    raises an exception, the result must contain the exception type,
    message, and traceback fields.

    **Validates: Requirements 17.1, 17.3**
    """

    # ---------------------------------------------------------------
    # 24a: Single print statement captures stdout
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(text=_safe_print_text)
    def test_single_print_captured_in_stdout(self, text: str) -> None:
        """**Validates: Requirements 17.1**"""
        bridge = MockIdaBridge()
        script = f'print("{text}")'
        result = bridge.execute_script(script)

        assert result.success is True
        assert text in result.stdout

    # ---------------------------------------------------------------
    # 24b: Raise statement produces failure with exception data
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(msg=_safe_print_text)
    def test_raise_produces_failure_with_exception_fields(self, msg: str) -> None:
        """**Validates: Requirements 17.3**"""
        bridge = MockIdaBridge()
        script = f'raise RuntimeError("{msg}")'
        result = bridge.execute_script(script)

        assert result.success is False
        assert result.data is not None
        exc = result.data["exception"]
        assert "type" in exc
        assert "message" in exc
        assert "traceback" in exc

    # ---------------------------------------------------------------
    # 24c: Script without print or raise returns success with empty stdout
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(var_name=st.from_regex(r"[a-z][a-z0-9_]{0,15}", fullmatch=True))
    def test_no_print_no_raise_returns_success_empty_stdout(self, var_name: str) -> None:
        """**Validates: Requirements 17.1**"""
        bridge = MockIdaBridge()
        script = f"{var_name} = 42"
        result = bridge.execute_script(script)

        assert result.success is True
        assert result.stdout == ""

    # ---------------------------------------------------------------
    # 24d: Multiple print statements produce multi-line stdout
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        texts=st.lists(_safe_print_text, min_size=2, max_size=6),
    )
    def test_multiple_prints_produce_multiline_stdout(self, texts: list[str]) -> None:
        """**Validates: Requirements 17.1**"""
        bridge = MockIdaBridge()
        lines = [f'print("{t}")' for t in texts]
        script = "\n".join(lines)
        result = bridge.execute_script(script)

        assert result.success is True
        stdout_lines = result.stdout.split("\n")
        assert len(stdout_lines) == len(texts)
        for expected, actual in zip(texts, stdout_lines):
            assert expected == actual
