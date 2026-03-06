"""Property-based tests for patching round-trip behaviour.

Property 18 from the IDA Headless MCP design document.
"""

from __future__ import annotations

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from ida_headless_mcp.models import PatchInfo
from tests.conftest import MockIdaBridge
from tests.strategies import ea_strings


# ===================================================================
# Property 18: Patch round-trip
# ===================================================================


class TestPatchRoundTrip:
    """Property 18: Patch round-trip.

    *For any* valid EA within a segment and any byte sequence, patching
    those bytes and then reading the same EA and length should return
    the patched values. The patch list should include the patched
    address with correct original and patched byte values. The
    read_bytes result hex string length must equal ``2 * requested_length``.

    **Validates: Requirements 13.1, 13.2, 13.4**
    """

    # ---------------------------------------------------------------
    # 18a: Patch then read returns patched values
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea_int=st.integers(min_value=0x1000, max_value=0xFFFF),
        byte_values=st.lists(
            st.integers(min_value=0, max_value=255),
            min_size=1,
            max_size=16,
        ),
    )
    def test_patch_then_read_returns_patched_values(
        self, ea_int: int, byte_values: list[int]
    ) -> None:
        """**Validates: Requirements 13.1, 13.2**"""
        bridge = MockIdaBridge()

        hex_values = "".join(f"{b:02x}" for b in byte_values)
        result = bridge.patch_bytes(ea_int, hex_values)
        assert result.success

        read_hex = bridge.read_bytes(ea_int, len(byte_values))
        assert read_hex == hex_values

    # ---------------------------------------------------------------
    # 18b: read_bytes hex string length equals 2 * requested_length
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea_int=st.integers(min_value=0x1000, max_value=0xFFFF),
        length=st.integers(min_value=1, max_value=32),
    )
    def test_read_bytes_length_equals_twice_requested(
        self, ea_int: int, length: int
    ) -> None:
        """**Validates: Requirements 13.1**"""
        bridge = MockIdaBridge()

        read_hex = bridge.read_bytes(ea_int, length)
        assert len(read_hex) == 2 * length

    # ---------------------------------------------------------------
    # 18c: Patch list contains correct original and patched values
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea_int=st.integers(min_value=0x1000, max_value=0xFFFF),
        byte_values=st.lists(
            st.integers(min_value=0, max_value=255),
            min_size=1,
            max_size=8,
        ),
    )
    def test_patch_list_correctness(
        self, ea_int: int, byte_values: list[int]
    ) -> None:
        """**Validates: Requirements 13.4**"""
        bridge = MockIdaBridge()

        # Pre-populate memory with known original values
        original_values = []
        for i in range(len(byte_values)):
            orig = (i * 17 + 42) % 256  # deterministic original values
            bridge.memory[ea_int + i] = orig
            original_values.append(orig)

        hex_values = "".join(f"{b:02x}" for b in byte_values)
        bridge.patch_bytes(ea_int, hex_values)

        patches = bridge.list_patches()

        # Verify each patched byte appears in the patch list
        for i, patched_byte in enumerate(byte_values):
            addr = ea_int + i
            ea_str = f"0x{addr:x}"
            matching = [p for p in patches if p.ea == ea_str]
            assert len(matching) == 1, f"Expected exactly one patch at {ea_str}"
            patch = matching[0]
            assert patch.original_byte == f"{original_values[i]:02x}"
            assert patch.patched_byte == f"{patched_byte:02x}"

    # ---------------------------------------------------------------
    # 18d: Patching at one EA does not affect other EAs
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea1=st.integers(min_value=0x1000, max_value=0x7FFF),
        ea2=st.integers(min_value=0x8000, max_value=0xFFFF),
        byte1=st.integers(min_value=0, max_value=255),
        byte2=st.integers(min_value=0, max_value=255),
    )
    def test_patching_one_ea_does_not_affect_other(
        self, ea1: int, ea2: int, byte1: int, byte2: int
    ) -> None:
        """**Validates: Requirements 13.1, 13.2**"""
        bridge = MockIdaBridge()

        # Set initial values at both EAs
        bridge.memory[ea1] = 0xAA
        bridge.memory[ea2] = 0xBB

        # Patch only ea1
        bridge.patch_bytes(ea1, f"{byte1:02x}")

        # ea2 should still have its original value
        read_ea2 = bridge.read_bytes(ea2, 1)
        assert read_ea2 == "bb"

        # ea1 should have the patched value
        read_ea1 = bridge.read_bytes(ea1, 1)
        assert read_ea1 == f"{byte1:02x}"

    # ---------------------------------------------------------------
    # 18e: Multiple patches accumulate in patch list
    # ---------------------------------------------------------------

    @settings(max_examples=50)
    @given(
        data=st.data(),
        num_patches=st.integers(min_value=2, max_value=5),
    )
    def test_multiple_patches_accumulate(
        self, data: st.DataObject, num_patches: int
    ) -> None:
        """**Validates: Requirements 13.2, 13.4**"""
        bridge = MockIdaBridge()

        eas = data.draw(
            st.lists(
                st.integers(min_value=0x1000, max_value=0xFFFF),
                min_size=num_patches,
                max_size=num_patches,
                unique=True,
            )
        )
        byte_vals = data.draw(
            st.lists(
                st.integers(min_value=0, max_value=255),
                min_size=num_patches,
                max_size=num_patches,
            )
        )

        for ea, bv in zip(eas, byte_vals):
            bridge.patch_bytes(ea, f"{bv:02x}")

        patches = bridge.list_patches()
        patched_eas = {p.ea for p in patches}

        # All patched EAs should appear in the patch list
        for ea in eas:
            assert f"0x{ea:x}" in patched_eas

    # ---------------------------------------------------------------
    # 18f: Unpatched memory reads as zero
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea_int=st.integers(min_value=0x1000, max_value=0xFFFF),
        length=st.integers(min_value=1, max_value=16),
    )
    def test_unpatched_memory_reads_as_zero(
        self, ea_int: int, length: int
    ) -> None:
        """**Validates: Requirements 13.1**"""
        bridge = MockIdaBridge()

        read_hex = bridge.read_bytes(ea_int, length)
        assert read_hex == "00" * length
