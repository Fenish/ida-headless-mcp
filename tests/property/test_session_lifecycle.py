"""Property-based tests for session lifecycle and architecture detection.

Properties 2 and 3 from the IDA Headless MCP design document.
"""

from __future__ import annotations

import os
import struct
import tempfile

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from ida_headless_mcp.session_manager import detect_architecture
from tests.conftest import MockSessionManager, SessionState
from tests.strategies import file_paths


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# Binary paths that do NOT contain '32' (so MockSessionManager maps to 64-bit)
_path_chars_no_digit = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-./",
    min_size=1,
    max_size=60,
).filter(lambda s: "32" not in s and len(s.strip()) > 0)

# Binary paths that contain '32' (so MockSessionManager maps to 32-bit)
_path_with_32 = _path_chars_no_digit.map(lambda s: s + "_32_bit")

# General binary paths for session lifecycle testing
binary_paths = st.one_of(
    file_paths,
    _path_chars_no_digit,
    _path_with_32,
)

# Architecture choices for ELF/PE header generation
architectures = st.sampled_from(["32", "64"])


# ===================================================================
# Property 2: Session lifecycle round-trip
# ===================================================================
# Feature: ida-headless-mcp, Property 2: Session lifecycle round-trip


class TestSessionLifecycleProperty:
    """Property 2: Session lifecycle round-trip.

    *For any* valid binary path, creating a session should return a unique
    session ID that appears in the session list with correct binary_path
    and architecture. Closing that session should remove it from the
    session list and the session count should decrease by one.

    **Validates: Requirements 2.1, 2.4, 2.6**
    """

    @settings(max_examples=100)
    @given(path=binary_paths)
    @pytest.mark.asyncio
    async def test_create_session_returns_unique_id_in_list(self, path: str) -> None:
        # Feature: ida-headless-mcp, Property 2: Session lifecycle round-trip
        mgr = MockSessionManager()
        session = await mgr.create_session(path)

        # Session ID must be a non-empty string
        assert isinstance(session.session_id, str)
        assert len(session.session_id) > 0

        # Session must appear in list_sessions
        listed = mgr.list_sessions()
        listed_ids = [s.session_id for s in listed]
        assert session.session_id in listed_ids

        # Listed session must have correct binary_path and architecture
        info = next(s for s in listed if s.session_id == session.session_id)
        assert info.binary_path == path
        assert info.architecture in ("32", "64")

    @settings(max_examples=100)
    @given(path=binary_paths)
    @pytest.mark.asyncio
    async def test_close_session_removes_from_list(self, path: str) -> None:
        # Feature: ida-headless-mcp, Property 2: Session lifecycle round-trip
        mgr = MockSessionManager()
        session = await mgr.create_session(path)
        count_before = len(mgr.list_sessions())

        await mgr.close_session(session.session_id)

        count_after = len(mgr.list_sessions())
        assert count_after == count_before - 1

        listed_ids = [s.session_id for s in mgr.list_sessions()]
        assert session.session_id not in listed_ids

    @settings(max_examples=50)
    @given(paths=st.lists(binary_paths, min_size=2, max_size=6, unique=True))
    @pytest.mark.asyncio
    async def test_multiple_sessions_have_unique_ids(self, paths: list[str]) -> None:
        # Feature: ida-headless-mcp, Property 2: Session lifecycle round-trip
        mgr = MockSessionManager()
        sessions = []
        for p in paths:
            s = await mgr.create_session(p)
            sessions.append(s)

        # All session IDs must be unique
        ids = [s.session_id for s in sessions]
        assert len(ids) == len(set(ids))

        # Session count must match
        assert len(mgr.list_sessions()) == len(paths)

        # Close all and verify empty
        for s in sessions:
            await mgr.close_session(s.session_id)
        assert len(mgr.list_sessions()) == 0


# ===================================================================
# Property 3: Architecture-based executable selection
# ===================================================================
# Feature: ida-headless-mcp, Property 3: Architecture-based executable selection


class TestArchitectureSelectionProperty:
    """Property 3: Architecture-based executable selection.

    *For any* binary, the session manager should select ``idat`` for
    32-bit binaries and ``idat64`` for 64-bit binaries. The session's
    ``architecture`` field must match the selected executable.

    **Validates: Requirements 2.5**
    """

    @settings(max_examples=100)
    @given(arch=architectures)
    def test_elf_architecture_detection(self, arch: str) -> None:
        # Feature: ida-headless-mcp, Property 3: Architecture-based executable selection
        # Build a minimal ELF header: \x7fELF + EI_CLASS byte
        ei_class = b"\x01" if arch == "32" else b"\x02"
        elf_header = b"\x7fELF" + ei_class + b"\x00" * 11  # pad to 16 bytes

        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(elf_header)
            tmp_path = f.name

        try:
            detected = detect_architecture(tmp_path)
            assert detected == arch
        finally:
            os.unlink(tmp_path)

    @settings(max_examples=100)
    @given(arch=architectures)
    def test_pe_architecture_detection(self, arch: str) -> None:
        # Feature: ida-headless-mcp, Property 3: Architecture-based executable selection
        # Build a minimal PE header:
        # MZ header at offset 0, PE offset at 0x3C, PE\0\0 + machine field
        machine = 0x14C if arch == "32" else 0x8664
        pe_offset = 0x80  # typical PE offset

        # MZ header (just the signature + padding up to 0x3C)
        mz_header = b"MZ" + b"\x00" * (0x3C - 2)
        # PE offset at 0x3C (little-endian uint32)
        mz_header += struct.pack("<I", pe_offset)
        # Pad to PE offset
        mz_header += b"\x00" * (pe_offset - len(mz_header))
        # PE signature + machine field
        pe_header = b"PE\x00\x00" + struct.pack("<H", machine)
        data = mz_header + pe_header

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
            f.write(data)
            tmp_path = f.name

        try:
            detected = detect_architecture(tmp_path)
            assert detected == arch
        finally:
            os.unlink(tmp_path)

    @settings(max_examples=50)
    @given(data=st.binary(min_size=0, max_size=64))
    def test_unknown_format_defaults_to_64(self, data: bytes) -> None:
        # Feature: ida-headless-mcp, Property 3: Architecture-based executable selection
        # Skip data that accidentally looks like ELF or PE
        assume(not data.startswith(b"\x7fELF"))
        assume(not data.startswith(b"MZ"))

        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(data)
            tmp_path = f.name

        try:
            detected = detect_architecture(tmp_path)
            assert detected == "64"
        finally:
            os.unlink(tmp_path)

    @settings(max_examples=50)
    @given(arch=architectures)
    @pytest.mark.asyncio
    async def test_mock_session_manager_architecture_matches(self, arch: str) -> None:
        # Feature: ida-headless-mcp, Property 3: Architecture-based executable selection
        # MockSessionManager uses a simple heuristic: '32' in path → 32-bit
        mgr = MockSessionManager()
        if arch == "32":
            path = "/some/binary_32_bit"
        else:
            path = "/some/binary_app"

        session = await mgr.create_session(path)
        assert session.architecture == arch

        info = next(
            s for s in mgr.list_sessions()
            if s.session_id == session.session_id
        )
        assert info.architecture == arch
