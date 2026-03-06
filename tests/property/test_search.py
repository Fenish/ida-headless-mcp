"""Property-based tests for search tool behaviour.

Properties 19, 20, 21 from the IDA Headless MCP design document.
"""

from __future__ import annotations

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from tests.conftest import MockIdaBridge


# ===================================================================
# Property 19: Search result constraints
# ===================================================================


class TestSearchResultConstraints:
    """Property 19: Search result constraints.

    *For any* search (byte pattern, text, or immediate) with a
    max_results parameter M, the result list must contain at most M
    entries. When start_ea and end_ea are specified, all returned EAs
    must satisfy ``start_ea <= ea <= end_ea``.

    **Validates: Requirements 14.4, 14.5**
    """

    # ---------------------------------------------------------------
    # 19a: search_bytes returns at most M results
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        max_results=st.integers(min_value=1, max_value=20),
        num_bytes=st.integers(min_value=1, max_value=50),
        base_ea=st.integers(min_value=0x1000, max_value=0x8000),
    )
    def test_search_bytes_at_most_m_results(
        self, max_results: int, num_bytes: int, base_ea: int
    ) -> None:
        """**Validates: Requirements 14.4**"""
        bridge = MockIdaBridge()
        # Fill memory with a single repeated byte so every address matches
        for i in range(num_bytes):
            bridge.memory[base_ea + i] = 0xAA

        results = bridge.search_bytes("aa", max_results=max_results)
        assert len(results) <= max_results

    # ---------------------------------------------------------------
    # 19b: search_bytes EAs within specified range
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        base_ea=st.integers(min_value=0x1000, max_value=0x8000),
        span=st.integers(min_value=10, max_value=100),
        max_results=st.integers(min_value=1, max_value=50),
    )
    def test_search_bytes_eas_within_range(
        self, base_ea: int, span: int, max_results: int
    ) -> None:
        """**Validates: Requirements 14.5**"""
        bridge = MockIdaBridge()
        end_ea = base_ea + span
        # Populate memory across a wider range than the search window
        for i in range(span + 40):
            bridge.memory[base_ea - 20 + i] = 0xBB

        results = bridge.search_bytes(
            "bb", start_ea=base_ea, end_ea=end_ea, max_results=max_results
        )
        for ea_str in results:
            ea = int(ea_str, 16)
            assert base_ea <= ea <= end_ea

    # ---------------------------------------------------------------
    # 19c: search_text returns at most M results
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        max_results=st.integers(min_value=1, max_value=10),
        num_strings=st.integers(min_value=1, max_value=30),
    )
    def test_search_text_at_most_m_results(
        self, max_results: int, num_strings: int
    ) -> None:
        """**Validates: Requirements 14.4**"""
        bridge = MockIdaBridge()
        for i in range(num_strings):
            bridge.add_string(0x1000 + i * 0x100, "needle", "ascii")

        results = bridge.search_text("needle", max_results=max_results)
        assert len(results) <= max_results

    # ---------------------------------------------------------------
    # 19d: search_text EAs within specified range
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        base_ea=st.integers(min_value=0x1000, max_value=0x8000),
        span=st.integers(min_value=0x100, max_value=0x1000),
        max_results=st.integers(min_value=1, max_value=50),
    )
    def test_search_text_eas_within_range(
        self, base_ea: int, span: int, max_results: int
    ) -> None:
        """**Validates: Requirements 14.5**"""
        bridge = MockIdaBridge()
        end_ea = base_ea + span
        # Add strings both inside and outside the range
        bridge.add_string(base_ea - 0x100, "target", "ascii")
        bridge.add_string(base_ea + 0x10, "target", "ascii")
        bridge.add_string(base_ea + span - 0x10, "target", "ascii")
        bridge.add_string(end_ea + 0x100, "target", "ascii")

        results = bridge.search_text(
            "target", start_ea=base_ea, end_ea=end_ea, max_results=max_results
        )
        for ea_str in results:
            ea = int(ea_str, 16)
            assert base_ea <= ea <= end_ea

    # ---------------------------------------------------------------
    # 19e: search_immediate returns at most M results
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        max_results=st.integers(min_value=1, max_value=10),
        num_bytes=st.integers(min_value=1, max_value=50),
        base_ea=st.integers(min_value=0x1000, max_value=0x8000),
        value=st.integers(min_value=0, max_value=255),
    )
    def test_search_immediate_at_most_m_results(
        self, max_results: int, num_bytes: int, base_ea: int, value: int
    ) -> None:
        """**Validates: Requirements 14.4**"""
        bridge = MockIdaBridge()
        for i in range(num_bytes):
            bridge.memory[base_ea + i] = value

        results = bridge.search_immediate(value, max_results=max_results)
        assert len(results) <= max_results

    # ---------------------------------------------------------------
    # 19f: search_immediate EAs within specified range
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        base_ea=st.integers(min_value=0x1000, max_value=0x8000),
        span=st.integers(min_value=10, max_value=100),
        max_results=st.integers(min_value=1, max_value=50),
        value=st.integers(min_value=0, max_value=255),
    )
    def test_search_immediate_eas_within_range(
        self, base_ea: int, span: int, max_results: int, value: int
    ) -> None:
        """**Validates: Requirements 14.5**"""
        bridge = MockIdaBridge()
        end_ea = base_ea + span
        # Populate memory across a wider range
        for i in range(span + 40):
            bridge.memory[base_ea - 20 + i] = value

        results = bridge.search_immediate(
            value, start_ea=base_ea, end_ea=end_ea, max_results=max_results
        )
        for ea_str in results:
            ea = int(ea_str, 16)
            assert base_ea <= ea <= end_ea


# ===================================================================
# Property 20: Byte pattern search verification
# ===================================================================


class TestBytePatternSearchVerification:
    """Property 20: Byte pattern search verification.

    *For any* byte pattern search result, reading bytes at each returned
    EA should match the search pattern (with wildcards treated as
    matching any byte).

    **Validates: Requirements 14.1**
    """

    # ---------------------------------------------------------------
    # 20a: Known bytes placed in memory are found by search
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        base_ea=st.integers(min_value=0x1000, max_value=0x8000),
        byte_values=st.lists(
            st.integers(min_value=0, max_value=255),
            min_size=1,
            max_size=8,
        ),
    )
    def test_byte_search_finds_planted_pattern(
        self, base_ea: int, byte_values: list[int]
    ) -> None:
        """**Validates: Requirements 14.1**"""
        bridge = MockIdaBridge()
        # Plant the bytes at base_ea
        for i, b in enumerate(byte_values):
            bridge.memory[base_ea + i] = b

        pattern = " ".join(f"{b:02x}" for b in byte_values)
        results = bridge.search_bytes(pattern)

        # The planted EA must appear in results
        ea_str = f"0x{base_ea:x}"
        assert ea_str in results

    # ---------------------------------------------------------------
    # 20b: Reading bytes at result EAs matches the pattern
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        base_ea=st.integers(min_value=0x1000, max_value=0x8000),
        byte_values=st.lists(
            st.integers(min_value=0, max_value=255),
            min_size=1,
            max_size=8,
        ),
    )
    def test_read_bytes_at_result_eas_matches_pattern(
        self, base_ea: int, byte_values: list[int]
    ) -> None:
        """**Validates: Requirements 14.1**"""
        bridge = MockIdaBridge()
        # Plant the bytes
        for i, b in enumerate(byte_values):
            bridge.memory[base_ea + i] = b

        pattern = " ".join(f"{b:02x}" for b in byte_values)
        results = bridge.search_bytes(pattern)

        pattern_parts = pattern.strip().split()
        for ea_str in results:
            ea = int(ea_str, 16)
            read_hex = bridge.read_bytes(ea, len(pattern_parts))
            # Verify each byte matches (wildcards always match)
            for i, p in enumerate(pattern_parts):
                if p == "??":
                    continue
                actual_byte = read_hex[i * 2 : i * 2 + 2]
                assert actual_byte == p.lower()

    # ---------------------------------------------------------------
    # 20c: Wildcard pattern matches at planted EA
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        base_ea=st.integers(min_value=0x1000, max_value=0x8000),
        byte_values=st.lists(
            st.integers(min_value=0, max_value=255),
            min_size=2,
            max_size=8,
        ),
        wildcard_idx=st.data(),
    )
    def test_wildcard_pattern_matches(
        self, base_ea: int, byte_values: list[int], wildcard_idx: st.DataObject
    ) -> None:
        """**Validates: Requirements 14.1**"""
        bridge = MockIdaBridge()
        for i, b in enumerate(byte_values):
            bridge.memory[base_ea + i] = b

        # Replace one position with a wildcard
        idx = wildcard_idx.draw(st.integers(min_value=0, max_value=len(byte_values) - 1))
        parts = [f"{b:02x}" for b in byte_values]
        parts[idx] = "??"
        pattern = " ".join(parts)

        results = bridge.search_bytes(pattern)
        ea_str = f"0x{base_ea:x}"
        assert ea_str in results


# ===================================================================
# Property 21: Text search verification
# ===================================================================


class TestTextSearchVerification:
    """Property 21: Text search verification.

    *For any* text search result, reading bytes at each returned EA and
    decoding should contain the searched text.

    **Validates: Requirements 14.2**
    """

    # ---------------------------------------------------------------
    # 21a: Planted text string is found by search
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        base_ea=st.integers(min_value=0x1000, max_value=0x8000),
        text=st.text(
            alphabet=st.characters(
                whitelist_categories=("L", "N"),
                blacklist_characters="\x00",
            ),
            min_size=1,
            max_size=50,
        ),
    )
    def test_text_search_finds_planted_string(
        self, base_ea: int, text: str
    ) -> None:
        """**Validates: Requirements 14.2**"""
        bridge = MockIdaBridge()
        bridge.add_string(base_ea, text, "ascii")

        results = bridge.search_text(text)
        ea_str = f"0x{base_ea:x}"
        assert ea_str in results

    # ---------------------------------------------------------------
    # 21b: Result EAs contain the searched text in their string value
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        base_ea=st.integers(min_value=0x1000, max_value=0x8000),
        prefix=st.text(
            alphabet=st.characters(whitelist_categories=("L",)),
            min_size=0,
            max_size=10,
        ),
        needle=st.text(
            alphabet=st.characters(
                whitelist_categories=("L", "N"),
                blacklist_characters="\x00",
            ),
            min_size=1,
            max_size=20,
        ),
        suffix=st.text(
            alphabet=st.characters(whitelist_categories=("L",)),
            min_size=0,
            max_size=10,
        ),
    )
    def test_result_eas_contain_searched_text(
        self, base_ea: int, prefix: str, needle: str, suffix: str
    ) -> None:
        """**Validates: Requirements 14.2**"""
        bridge = MockIdaBridge()
        full_text = prefix + needle + suffix
        assume(len(full_text) > 0)
        bridge.add_string(base_ea, full_text, "ascii")

        results = bridge.search_text(needle)
        # Every result EA should have a string containing the needle
        for ea_str in results:
            ea = int(ea_str, 16)
            assert ea in bridge.strings
            assert needle in bridge.strings[ea].value

    # ---------------------------------------------------------------
    # 21c: Substring search finds containing strings
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        base_ea=st.integers(min_value=0x1000, max_value=0x8000),
        text=st.text(
            alphabet=st.characters(
                whitelist_categories=("L", "N"),
                blacklist_characters="\x00",
            ),
            min_size=3,
            max_size=30,
        ),
        data=st.data(),
    )
    def test_substring_search(
        self, base_ea: int, text: str, data: st.DataObject
    ) -> None:
        """**Validates: Requirements 14.2**"""
        bridge = MockIdaBridge()
        bridge.add_string(base_ea, text, "ascii")

        # Pick a random substring of the text
        start_idx = data.draw(st.integers(min_value=0, max_value=len(text) - 1))
        end_idx = data.draw(st.integers(min_value=start_idx + 1, max_value=len(text)))
        substring = text[start_idx:end_idx]
        assume(len(substring) > 0)

        results = bridge.search_text(substring)
        ea_str = f"0x{base_ea:x}"
        assert ea_str in results
