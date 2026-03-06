"""Property-based tests for disassembly instruction completeness.

Property 9 from the IDA Headless MCP design document.
"""

from __future__ import annotations

import re

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from ida_headless_mcp.models import InstructionInfo
from tests.conftest import MockIdaBridge
from tests.strategies import address_ranges, ea_strings, instruction_infos


# ===================================================================
# Property 9: Disassembly instruction completeness
# ===================================================================


class TestDisassemblyInstructionCompleteness:
    """Property 9: Disassembly instruction completeness.

    *For any* instruction in a disassembly result, the entry must contain
    EA, raw_bytes, mnemonic, and operands fields. For range-based
    disassembly, all instruction EAs must fall within the requested range.

    **Validates: Requirements 6.1, 6.2, 6.3, 6.4**
    """

    # ---------------------------------------------------------------
    # 9a: Generated InstructionInfo instances have all required fields
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(instr=instruction_infos())
    def test_instruction_info_has_all_required_fields(
        self, instr: InstructionInfo
    ) -> None:
        # Feature: ida-headless-mcp, Property 9: Disassembly instruction completeness
        # EA must be a hex string
        assert isinstance(instr.ea, str)
        assert instr.ea.startswith("0x")
        # Verify it parses as a valid integer
        int(instr.ea, 16)

        # raw_bytes must be a non-empty string
        assert isinstance(instr.raw_bytes, str)
        assert len(instr.raw_bytes) > 0

        # mnemonic must be a non-empty string
        assert isinstance(instr.mnemonic, str)
        assert len(instr.mnemonic) > 0

        # operands must be a string (can be empty for instructions like nop/ret)
        assert isinstance(instr.operands, str)

        # comment is optional (str | None)
        assert instr.comment is None or isinstance(instr.comment, str)

    # ---------------------------------------------------------------
    # 9b: Range-based disassembly EAs fall within the requested range
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(addr_range=address_ranges)
    def test_range_disassembly_eas_within_range(
        self, addr_range: tuple[str, str]
    ) -> None:
        # Feature: ida-headless-mcp, Property 9: Disassembly instruction completeness
        start_ea_str, end_ea_str = addr_range
        start_ea = int(start_ea_str, 16)
        end_ea = int(end_ea_str, 16)

        # Limit range size to keep tests fast
        assume(end_ea - start_ea <= 256)

        bridge = MockIdaBridge()
        instructions = bridge.disassemble_range(start_ea, end_ea)

        for instr in instructions:
            instr_ea = int(instr.ea, 16)
            assert start_ea <= instr_ea < end_ea, (
                f"Instruction EA {instr.ea} outside range "
                f"[{start_ea_str}, {end_ea_str})"
            )

    # ---------------------------------------------------------------
    # 9c: MockIdaBridge disassembly returns complete results
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        ea=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
        byte_val=st.integers(min_value=0, max_value=255),
    )
    def test_single_disassembly_completeness(
        self, ea: int, byte_val: int
    ) -> None:
        # Feature: ida-headless-mcp, Property 9: Disassembly instruction completeness
        bridge = MockIdaBridge()
        bridge.memory[ea] = byte_val

        instr = bridge.disassemble_at(ea)

        # All required fields present
        assert isinstance(instr.ea, str) and instr.ea.startswith("0x")
        assert instr.ea == f"0x{ea:x}"
        assert isinstance(instr.raw_bytes, str) and len(instr.raw_bytes) > 0
        assert isinstance(instr.mnemonic, str) and len(instr.mnemonic) > 0
        assert isinstance(instr.operands, str)
        assert instr.comment is None or isinstance(instr.comment, str)

    # ---------------------------------------------------------------
    # 9d: Range disassembly with pre-populated memory has complete fields
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        base_ea=st.integers(min_value=0x1000, max_value=0xFFFFFF00),
        size=st.integers(min_value=1, max_value=32),
        byte_vals=st.lists(
            st.integers(min_value=0, max_value=255),
            min_size=1,
            max_size=32,
        ),
    )
    def test_range_disassembly_all_fields_complete(
        self, base_ea: int, size: int, byte_vals: list[int]
    ) -> None:
        # Feature: ida-headless-mcp, Property 9: Disassembly instruction completeness
        bridge = MockIdaBridge()

        # Populate memory for the range
        actual_size = min(size, len(byte_vals))
        for i in range(actual_size):
            bridge.memory[base_ea + i] = byte_vals[i]

        end_ea = base_ea + actual_size
        instructions = bridge.disassemble_range(base_ea, end_ea)

        assert len(instructions) == actual_size

        for instr in instructions:
            # Every instruction must have all required fields
            assert isinstance(instr.ea, str) and instr.ea.startswith("0x")
            assert isinstance(instr.raw_bytes, str) and len(instr.raw_bytes) > 0
            assert isinstance(instr.mnemonic, str) and len(instr.mnemonic) > 0
            assert isinstance(instr.operands, str)

            # EA must be within the range
            instr_ea = int(instr.ea, 16)
            assert base_ea <= instr_ea < end_ea
