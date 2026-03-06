"""Property-based tests for IDA path validation.

Property 1 from the IDA Headless MCP design document.
"""

from __future__ import annotations

import platform

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ida_headless_mcp.config import ServerConfig
from tests.strategies import file_paths


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# Random path segments that are very unlikely to exist on disk
_nonexistent_path_segments = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789_",
    min_size=4,
    max_size=20,
)

# Paths that should not exist on the filesystem
nonexistent_paths = st.tuples(
    _nonexistent_path_segments,
    _nonexistent_path_segments,
    _nonexistent_path_segments,
).map(lambda parts: f"/nonexistent_{parts[0]}/{parts[1]}/{parts[2]}")


# ===================================================================
# Property 1: IDA path validation
# ===================================================================
# Feature: ida-headless-mcp, Property 1: IDA path validation


class TestIdaPathValidationProperty:
    """Property 1: IDA path validation.

    *For any* server configuration, the server should accept the
    configuration if and only if the ``ida_path`` points to a directory
    containing a valid ``idat`` or ``idat64`` executable. Invalid paths
    must produce an error containing the offending path string.

    **Validates: Requirements 1.4, 1.5**
    """

    @settings(max_examples=50)
    @given(path=nonexistent_paths)
    def test_nonexistent_path_raises_with_descriptive_error(self, path: str) -> None:
        """Random non-existent paths must raise ValueError with the path in the message."""
        # Feature: ida-headless-mcp, Property 1: IDA path validation
        config = ServerConfig(ida_path=path)
        with pytest.raises(ValueError, match=path.replace("\\", "\\\\")):
            config.validate()

    @settings(max_examples=50)
    @given(path=nonexistent_paths)
    def test_nonexistent_path_error_is_descriptive(self, path: str) -> None:
        """The error message must mention the offending path."""
        # Feature: ida-headless-mcp, Property 1: IDA path validation
        config = ServerConfig(ida_path=path)
        try:
            config.validate()
            pytest.fail("Expected ValueError for non-existent path")
        except ValueError as exc:
            assert path in str(exc), (
                f"Error message should contain the path '{path}', got: {exc}"
            )

    @settings(max_examples=30, suppress_health_check=[HealthCheck.function_scoped_fixture])
    @given(data=st.data())
    def test_directory_without_executables_raises(self, tmp_path, data) -> None:
        """A real directory without idat/idat64 must raise ValueError."""
        # Feature: ida-headless-mcp, Property 1: IDA path validation
        # Create a unique subdirectory per hypothesis example
        import uuid

        test_dir = tmp_path / uuid.uuid4().hex
        test_dir.mkdir()

        # Add some random non-IDA files
        num_files = data.draw(st.integers(min_value=0, max_value=3))
        for i in range(num_files):
            fname = data.draw(
                st.from_regex(r"[a-z]{2,8}\.(txt|dat|bin)", fullmatch=True)
            )
            (test_dir / fname).write_text("dummy")

        config = ServerConfig(ida_path=str(test_dir))
        with pytest.raises(ValueError) as exc_info:
            config.validate()

        # Error must mention the path
        assert str(test_dir) in str(exc_info.value)

    @settings(max_examples=30, suppress_health_check=[HealthCheck.function_scoped_fixture])
    @given(
        exe_choice=st.sampled_from(["idat", "idat64", "both"]),
    )
    def test_directory_with_executables_passes(self, tmp_path, exe_choice: str) -> None:
        """A directory containing idat or idat64 executables must pass validation."""
        # Feature: ida-headless-mcp, Property 1: IDA path validation
        import uuid

        test_dir = tmp_path / uuid.uuid4().hex
        test_dir.mkdir()

        suffix = ".exe" if platform.system() == "Windows" else ""

        if exe_choice in ("idat", "both"):
            exe_path = test_dir / f"idat{suffix}"
            exe_path.write_text("fake")
        if exe_choice in ("idat64", "both"):
            exe_path = test_dir / f"idat64{suffix}"
            exe_path.write_text("fake")

        config = ServerConfig(ida_path=str(test_dir))
        # Should not raise
        config.validate()

    @settings(max_examples=20, suppress_health_check=[HealthCheck.function_scoped_fixture])
    @given(data=st.data())
    def test_file_path_instead_of_directory_raises(self, tmp_path, data) -> None:
        """A path pointing to a file (not a directory) must raise ValueError."""
        # Feature: ida-headless-mcp, Property 1: IDA path validation
        import uuid

        fname = data.draw(
            st.from_regex(r"[a-z]{3,10}\.(exe|bin|dat)", fullmatch=True)
        )
        file_path = tmp_path / f"{uuid.uuid4().hex}_{fname}"
        file_path.write_text("not a directory")

        config = ServerConfig(ida_path=str(file_path))
        with pytest.raises(ValueError) as exc_info:
            config.validate()

        assert str(file_path) in str(exc_info.value)
