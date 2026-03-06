"""Unit tests for the configuration module."""

from __future__ import annotations

import platform
from pathlib import Path

import pytest

from ida_headless_mcp.config import ServerConfig


class TestServerConfigDefaults:
    """Test default field values."""

    def test_defaults(self):
        cfg = ServerConfig(ida_path="/some/path")
        assert cfg.ida_binary_32 == "idat"
        assert cfg.ida_binary_64 == "idat64"
        assert cfg.max_concurrent_sessions == 5
        assert cfg.session_timeout == 3600
        assert cfg.script_timeout == 300
        assert cfg.batch_max_concurrent == 3
        assert cfg.signatures_dir is None
        assert cfg.transport == "stdio"
        assert cfg.sse_host == "127.0.0.1"
        assert cfg.sse_port == 8080


class TestServerConfigValidate:
    """Test the validate() method."""

    def test_nonexistent_path_raises(self, tmp_path: Path):
        cfg = ServerConfig(ida_path=str(tmp_path / "nonexistent"))
        with pytest.raises(ValueError, match="does not exist"):
            cfg.validate()

    def test_file_instead_of_dir_raises(self, tmp_path: Path):
        f = tmp_path / "somefile"
        f.write_text("")
        cfg = ServerConfig(ida_path=str(f))
        with pytest.raises(ValueError, match="not a directory"):
            cfg.validate()

    def test_dir_without_executables_raises(self, tmp_path: Path):
        cfg = ServerConfig(ida_path=str(tmp_path))
        with pytest.raises(ValueError, match="No valid IDA executables"):
            cfg.validate()

    def test_valid_with_idat64(self, tmp_path: Path):
        suffix = ".exe" if platform.system() == "Windows" else ""
        (tmp_path / f"idat64{suffix}").write_text("")
        cfg = ServerConfig(ida_path=str(tmp_path))
        cfg.validate()  # should not raise

    def test_valid_with_idat(self, tmp_path: Path):
        suffix = ".exe" if platform.system() == "Windows" else ""
        (tmp_path / f"idat{suffix}").write_text("")
        cfg = ServerConfig(ida_path=str(tmp_path))
        cfg.validate()  # should not raise

    def test_valid_with_both(self, tmp_path: Path):
        suffix = ".exe" if platform.system() == "Windows" else ""
        (tmp_path / f"idat{suffix}").write_text("")
        (tmp_path / f"idat64{suffix}").write_text("")
        cfg = ServerConfig(ida_path=str(tmp_path))
        cfg.validate()  # should not raise

    def test_error_message_contains_path(self, tmp_path: Path):
        bad = str(tmp_path / "nope")
        cfg = ServerConfig(ida_path=bad)
        with pytest.raises(ValueError, match=bad.replace("\\", "\\\\")):
            cfg.validate()

    def test_custom_binary_names(self, tmp_path: Path):
        suffix = ".exe" if platform.system() == "Windows" else ""
        (tmp_path / f"my_ida{suffix}").write_text("")
        cfg = ServerConfig(
            ida_path=str(tmp_path),
            ida_binary_32="my_ida",
            ida_binary_64="my_ida64",
        )
        cfg.validate()  # should not raise
