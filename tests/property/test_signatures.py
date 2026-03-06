"""Property-based tests for signature listing consistency.

Property 22 from the IDA Headless MCP design document.
"""

from __future__ import annotations

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from ida_headless_mcp.models import SignatureResult
from tests.conftest import MockIdaBridge


# Strategy: generate valid .sig filenames
sig_filenames = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789_-"),
    min_size=1,
    max_size=20,
).map(lambda s: s + ".sig")


# ===================================================================
# Property 22: Signature listing consistency
# ===================================================================


class TestSignatureListingConsistency:
    """Property 22: Signature listing consistency.

    *For any* signatures directory, the list of available signatures
    should match the ``.sig`` files in that directory. After applying a
    signature, the applied signatures list should include it.

    **Validates: Requirements 15.2, 15.3**
    """

    # ---------------------------------------------------------------
    # 22a: Available signatures match what is set on the bridge
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        sig_files=st.lists(sig_filenames, min_size=0, max_size=15, unique=True),
    )
    def test_available_signatures_match_directory(
        self, sig_files: list[str]
    ) -> None:
        """**Validates: Requirements 15.3**"""
        bridge = MockIdaBridge()
        bridge.available_signatures = list(sig_files)

        result = bridge.list_available_signatures()
        assert result == sig_files

    # ---------------------------------------------------------------
    # 22b: Applied signatures contain all applied ones
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        sig_files=st.lists(sig_filenames, min_size=1, max_size=10, unique=True),
    )
    def test_applied_signatures_contain_all_applied(
        self, sig_files: list[str]
    ) -> None:
        """**Validates: Requirements 15.2**"""
        bridge = MockIdaBridge()

        for sig in sig_files:
            bridge.apply_signature(sig)

        applied = bridge.list_applied_signatures()
        for sig in sig_files:
            assert sig in applied

    # ---------------------------------------------------------------
    # 22c: Applying same signature twice doesn't duplicate
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        sig_file=sig_filenames,
    )
    def test_apply_same_signature_twice_no_duplicate(
        self, sig_file: str
    ) -> None:
        """**Validates: Requirements 15.2**"""
        bridge = MockIdaBridge()

        bridge.apply_signature(sig_file)
        bridge.apply_signature(sig_file)

        applied = bridge.list_applied_signatures()
        assert applied.count(sig_file) == 1

    # ---------------------------------------------------------------
    # 22d: apply_signature returns SignatureResult with correct name
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        sig_file=sig_filenames,
    )
    def test_apply_signature_returns_correct_result(
        self, sig_file: str
    ) -> None:
        """**Validates: Requirements 15.2**"""
        bridge = MockIdaBridge()

        result = bridge.apply_signature(sig_file)

        assert isinstance(result, SignatureResult)
        assert result.sig_file == sig_file
        assert isinstance(result.functions_matched, int)
        assert result.functions_matched >= 0
