"""Unit tests for ida_headless_mcp.__main__ — CLI entry point.

Tests cover argument parsing, config construction, and error handling.
The server is mocked to avoid actually running it.
"""

from __future__ import annotations

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ida_headless_mcp.__main__ import build_parser, main


# ---------------------------------------------------------------------------
# Argument parsing tests
# ---------------------------------------------------------------------------


class TestBuildParser:
    """Tests for the argparse configuration."""

    def test_ida_path_from_arg(self):
        parser = build_parser()
        args = parser.parse_args(["--ida-path", "/opt/ida"])
        assert args.ida_path == "/opt/ida"

    def test_ida_path_from_env(self, monkeypatch):
        monkeypatch.setenv("IDA_PATH", "/env/ida")
        parser = build_parser()
        args = parser.parse_args([])
        assert args.ida_path == "/env/ida"

    def test_ida_path_arg_overrides_env(self, monkeypatch):
        monkeypatch.setenv("IDA_PATH", "/env/ida")
        parser = build_parser()
        args = parser.parse_args(["--ida-path", "/arg/ida"])
        assert args.ida_path == "/arg/ida"

    def test_transport_default(self):
        parser = build_parser()
        args = parser.parse_args(["--ida-path", "/ida"])
        assert args.transport == "stdio"

    def test_transport_sse(self):
        parser = build_parser()
        args = parser.parse_args(["--ida-path", "/ida", "--transport", "sse"])
        assert args.transport == "sse"

    def test_transport_invalid_choice(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--ida-path", "/ida", "--transport", "grpc"])

    def test_sse_host_default(self):
        parser = build_parser()
        args = parser.parse_args(["--ida-path", "/ida"])
        assert args.sse_host == "127.0.0.1"

    def test_sse_host_custom(self):
        parser = build_parser()
        args = parser.parse_args(["--ida-path", "/ida", "--sse-host", "0.0.0.0"])
        assert args.sse_host == "0.0.0.0"

    def test_sse_port_default(self):
        parser = build_parser()
        args = parser.parse_args(["--ida-path", "/ida"])
        assert args.sse_port == 8080

    def test_sse_port_custom(self):
        parser = build_parser()
        args = parser.parse_args(["--ida-path", "/ida", "--sse-port", "9090"])
        assert args.sse_port == 9090

    def test_max_sessions_default(self):
        parser = build_parser()
        args = parser.parse_args(["--ida-path", "/ida"])
        assert args.max_sessions == 5

    def test_max_sessions_custom(self):
        parser = build_parser()
        args = parser.parse_args(["--ida-path", "/ida", "--max-sessions", "10"])
        assert args.max_sessions == 10

    def test_signatures_dir_default(self):
        parser = build_parser()
        args = parser.parse_args(["--ida-path", "/ida"])
        assert args.signatures_dir is None

    def test_signatures_dir_custom(self):
        parser = build_parser()
        args = parser.parse_args(["--ida-path", "/ida", "--signatures-dir", "/sigs"])
        assert args.signatures_dir == "/sigs"


# ---------------------------------------------------------------------------
# main() tests
# ---------------------------------------------------------------------------


class TestMain:
    """Tests for the main() entry point."""

    def test_missing_ida_path_exits(self, monkeypatch):
        monkeypatch.delenv("IDA_PATH", raising=False)
        with pytest.raises(SystemExit) as exc_info:
            main([])
        assert exc_info.value.code == 2  # argparse error exit code

    @patch("ida_headless_mcp.__main__.IdaMcpServer")
    def test_builds_config_and_runs_server(self, mock_server_cls):
        mock_instance = MagicMock()
        mock_instance.run = AsyncMock()
        mock_server_cls.return_value = mock_instance

        main(["--ida-path", "/fake/ida", "--max-sessions", "3", "--transport", "stdio"])

        # Verify IdaMcpServer was constructed with a proper config
        mock_server_cls.assert_called_once()
        config = mock_server_cls.call_args[0][0]
        assert config.ida_path == "/fake/ida"
        assert config.max_concurrent_sessions == 3
        assert config.transport == "stdio"
        assert config.sse_host == "127.0.0.1"
        assert config.sse_port == 8080
        assert config.signatures_dir is None

    @patch("ida_headless_mcp.__main__.IdaMcpServer")
    def test_passes_sse_options_to_config(self, mock_server_cls):
        mock_instance = MagicMock()
        mock_instance.run = AsyncMock()
        mock_server_cls.return_value = mock_instance

        main([
            "--ida-path", "/fake/ida",
            "--transport", "sse",
            "--sse-host", "0.0.0.0",
            "--sse-port", "9999",
        ])

        config = mock_server_cls.call_args[0][0]
        assert config.transport == "sse"
        assert config.sse_host == "0.0.0.0"
        assert config.sse_port == 9999

    @patch("ida_headless_mcp.__main__.IdaMcpServer")
    def test_passes_signatures_dir_to_config(self, mock_server_cls):
        mock_instance = MagicMock()
        mock_instance.run = AsyncMock()
        mock_server_cls.return_value = mock_instance

        main(["--ida-path", "/fake/ida", "--signatures-dir", "/my/sigs"])

        config = mock_server_cls.call_args[0][0]
        assert config.signatures_dir == "/my/sigs"

    @patch("ida_headless_mcp.__main__.IdaMcpServer")
    def test_server_exception_causes_exit_1(self, mock_server_cls):
        mock_server_cls.side_effect = ValueError("bad config")

        with pytest.raises(SystemExit) as exc_info:
            main(["--ida-path", "/fake/ida"])
        assert exc_info.value.code == 1

    @patch("ida_headless_mcp.__main__.IdaMcpServer")
    def test_run_exception_causes_exit_1(self, mock_server_cls):
        mock_instance = MagicMock()
        mock_instance.run = AsyncMock(side_effect=RuntimeError("mcp not installed"))
        mock_server_cls.return_value = mock_instance

        with pytest.raises(SystemExit) as exc_info:
            main(["--ida-path", "/fake/ida"])
        assert exc_info.value.code == 1
