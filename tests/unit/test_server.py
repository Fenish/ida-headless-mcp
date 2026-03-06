"""Unit tests for ida_headless_mcp.server — IdaMcpServer class.

Tests cover:
- __init__ calls config.validate()
- Invalid config raises ValueError
- _register_tools() populates the tools dict with all expected tool names
- get_server_info() returns correct structure
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ida_headless_mcp.config import ServerConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_valid_config(**overrides) -> ServerConfig:
    """Return a ServerConfig with a dummy ida_path (validation is mocked)."""
    defaults = {
        "ida_path": "/fake/ida",
        "max_concurrent_sessions": 5,
        "batch_max_concurrent": 3,
    }
    defaults.update(overrides)
    return ServerConfig(**defaults)


# ---------------------------------------------------------------------------
# Expected tool names — all tools from all 15+ tool modules
# ---------------------------------------------------------------------------

EXPECTED_TOOLS = sorted([
    # sessions
    "create_session", "list_sessions", "close_session",
    # functions
    "list_functions", "get_function_details", "rename_function",
    "create_function", "delete_function",
    # decompile
    "decompile_function",
    # disassembly
    "disassemble_at", "disassemble_range", "disassemble_function",
    # xrefs
    "get_xrefs_to", "get_xrefs_from", "get_function_xrefs",
    # strings
    "list_strings", "get_string_xrefs",
    # segments
    "list_segments", "get_segment", "get_segment_at",
    # imports_exports
    "list_imports", "list_exports",
    # types
    "list_types", "create_struct", "add_struct_field",
    "apply_type", "delete_type", "parse_header",
    # comments
    "set_comment", "get_comments", "get_comments_range",
    # patching
    "read_bytes", "patch_bytes", "assemble_and_patch", "list_patches",
    # search
    "search_bytes", "search_text", "search_immediate",
    # signatures
    "apply_signature", "list_applied_signatures", "list_available_signatures",
    # bookmarks
    "add_bookmark", "list_bookmarks", "delete_bookmark",
    # scripting
    "execute_script", "execute_script_file",
    # batch
    "start_batch", "get_batch_status",
    # enums
    "list_enums", "create_enum", "add_enum_member", "apply_enum",
    # data
    "list_names", "rename_location", "get_data_type", "set_data_type",
    # callgraph
    "get_callers", "get_callees", "get_call_graph",
])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestIdaMcpServerInit:
    """Tests for IdaMcpServer.__init__."""

    @patch("ida_headless_mcp.server.SessionManager")
    @patch("ida_headless_mcp.server.IdaBridge")
    @patch("ida_headless_mcp.server.BatchManager")
    def test_init_calls_config_validate(self, mock_bm, mock_bridge, mock_sm):
        """__init__ must call config.validate() before proceeding."""
        config = _make_valid_config()
        config.validate = MagicMock()

        from ida_headless_mcp.server import IdaMcpServer

        server = IdaMcpServer(config)

        config.validate.assert_called_once()

    @patch("ida_headless_mcp.server.SessionManager")
    @patch("ida_headless_mcp.server.IdaBridge")
    @patch("ida_headless_mcp.server.BatchManager")
    def test_init_creates_session_manager(self, mock_bm, mock_bridge, mock_sm):
        """__init__ must create a SessionManager with the config."""
        config = _make_valid_config()
        config.validate = MagicMock()

        from ida_headless_mcp.server import IdaMcpServer

        server = IdaMcpServer(config)

        mock_sm.assert_called_once_with(config)

    @patch("ida_headless_mcp.server.SessionManager")
    @patch("ida_headless_mcp.server.IdaBridge")
    @patch("ida_headless_mcp.server.BatchManager")
    def test_init_creates_batch_manager(self, mock_bm, mock_bridge, mock_sm):
        """__init__ must create a BatchManager with session_manager and concurrency."""
        config = _make_valid_config(batch_max_concurrent=7)
        config.validate = MagicMock()

        from ida_headless_mcp.server import IdaMcpServer

        server = IdaMcpServer(config)

        mock_bm.assert_called_once_with(mock_sm.return_value, 7)

    def test_init_invalid_config_raises_value_error(self):
        """If config.validate() raises ValueError, __init__ must propagate it."""
        config = _make_valid_config(ida_path="/nonexistent/path")
        # Don't mock validate — let the real one run against a bad path

        from ida_headless_mcp.server import IdaMcpServer

        with pytest.raises(ValueError, match="IDA path does not exist"):
            IdaMcpServer(config)


class TestRegisterTools:
    """Tests for IdaMcpServer._register_tools()."""

    @patch("ida_headless_mcp.server.SessionManager")
    @patch("ida_headless_mcp.server.IdaBridge")
    @patch("ida_headless_mcp.server.BatchManager")
    def test_all_expected_tools_registered(self, mock_bm, mock_bridge, mock_sm):
        """_register_tools() must populate _tools with all expected tool names."""
        config = _make_valid_config()
        config.validate = MagicMock()

        from ida_headless_mcp.server import IdaMcpServer

        server = IdaMcpServer(config)

        registered = sorted(server._tools.keys())
        assert registered == EXPECTED_TOOLS

    @patch("ida_headless_mcp.server.SessionManager")
    @patch("ida_headless_mcp.server.IdaBridge")
    @patch("ida_headless_mcp.server.BatchManager")
    def test_each_tool_has_handler_and_description(self, mock_bm, mock_bridge, mock_sm):
        """Each registered tool must have a callable handler and a non-empty description."""
        config = _make_valid_config()
        config.validate = MagicMock()

        from ida_headless_mcp.server import IdaMcpServer

        server = IdaMcpServer(config)

        for name, info in server._tools.items():
            assert callable(info["handler"]), f"{name} handler is not callable"
            assert isinstance(info["description"], str) and info["description"], (
                f"{name} has empty or missing description"
            )
            assert isinstance(info["module"], str) and info["module"], (
                f"{name} has empty or missing module"
            )

    @patch("ida_headless_mcp.server.SessionManager")
    @patch("ida_headless_mcp.server.IdaBridge")
    @patch("ida_headless_mcp.server.BatchManager")
    def test_tool_count(self, mock_bm, mock_bridge, mock_sm):
        """Verify the total number of registered tools matches expectations."""
        config = _make_valid_config()
        config.validate = MagicMock()

        from ida_headless_mcp.server import IdaMcpServer

        server = IdaMcpServer(config)

        assert len(server._tools) == len(EXPECTED_TOOLS)


class TestGetServerInfo:
    """Tests for IdaMcpServer.get_server_info()."""

    @patch("ida_headless_mcp.server.SessionManager")
    @patch("ida_headless_mcp.server.IdaBridge")
    @patch("ida_headless_mcp.server.BatchManager")
    def test_server_info_structure(self, mock_bm, mock_bridge, mock_sm):
        """get_server_info() must return version, supported_ida_version, tools, session_count."""
        config = _make_valid_config()
        config.validate = MagicMock()

        # Make list_sessions return an empty list
        mock_sm.return_value.list_sessions.return_value = []

        from ida_headless_mcp.server import IdaMcpServer

        server = IdaMcpServer(config)
        info = server.get_server_info()

        assert "version" in info
        assert "supported_ida_version" in info
        assert "available_tools" in info
        assert "session_count" in info

    @patch("ida_headless_mcp.server.SessionManager")
    @patch("ida_headless_mcp.server.IdaBridge")
    @patch("ida_headless_mcp.server.BatchManager")
    def test_server_info_version(self, mock_bm, mock_bridge, mock_sm):
        """get_server_info() version must be a non-empty string."""
        config = _make_valid_config()
        config.validate = MagicMock()
        mock_sm.return_value.list_sessions.return_value = []

        from ida_headless_mcp.server import IdaMcpServer

        server = IdaMcpServer(config)
        info = server.get_server_info()

        assert isinstance(info["version"], str)
        assert len(info["version"]) > 0

    @patch("ida_headless_mcp.server.SessionManager")
    @patch("ida_headless_mcp.server.IdaBridge")
    @patch("ida_headless_mcp.server.BatchManager")
    def test_server_info_tools_match_registry(self, mock_bm, mock_bridge, mock_sm):
        """available_tools in server info must match the registered tool names."""
        config = _make_valid_config()
        config.validate = MagicMock()
        mock_sm.return_value.list_sessions.return_value = []

        from ida_headless_mcp.server import IdaMcpServer

        server = IdaMcpServer(config)
        info = server.get_server_info()

        assert info["available_tools"] == EXPECTED_TOOLS

    @patch("ida_headless_mcp.server.SessionManager")
    @patch("ida_headless_mcp.server.IdaBridge")
    @patch("ida_headless_mcp.server.BatchManager")
    def test_server_info_session_count(self, mock_bm, mock_bridge, mock_sm):
        """session_count must reflect the number of active sessions."""
        config = _make_valid_config()
        config.validate = MagicMock()

        # Simulate 3 active sessions
        mock_sm.return_value.list_sessions.return_value = [
            MagicMock(), MagicMock(), MagicMock()
        ]

        from ida_headless_mcp.server import IdaMcpServer

        server = IdaMcpServer(config)
        info = server.get_server_info()

        assert info["session_count"] == 3

    @patch("ida_headless_mcp.server.SessionManager")
    @patch("ida_headless_mcp.server.IdaBridge")
    @patch("ida_headless_mcp.server.BatchManager")
    def test_server_info_supported_ida_version(self, mock_bm, mock_bridge, mock_sm):
        """supported_ida_version must be a non-empty string."""
        config = _make_valid_config()
        config.validate = MagicMock()
        mock_sm.return_value.list_sessions.return_value = []

        from ida_headless_mcp.server import IdaMcpServer

        server = IdaMcpServer(config)
        info = server.get_server_info()

        assert isinstance(info["supported_ida_version"], str)
        assert len(info["supported_ida_version"]) > 0


# ---------------------------------------------------------------------------
# Shutdown tests
# ---------------------------------------------------------------------------


class TestGracefulShutdown:
    """Tests for IdaMcpServer.shutdown()."""

    @patch("ida_headless_mcp.server.SessionManager")
    @patch("ida_headless_mcp.server.IdaBridge")
    @patch("ida_headless_mcp.server.BatchManager")
    def test_shutdown_sets_shutting_down_flag(self, mock_bm, mock_bridge, mock_sm):
        """shutdown() must set _shutting_down to True."""
        import asyncio

        config = _make_valid_config()
        config.validate = MagicMock()
        mock_sm.return_value.close_all_sessions = AsyncMock()
        mock_sm.return_value._sessions = {}
        mock_bm.return_value._jobs = {}

        from ida_headless_mcp.server import IdaMcpServer

        server = IdaMcpServer(config)
        assert server._shutting_down is False

        asyncio.run(server.shutdown())
        assert server._shutting_down is True

    @patch("ida_headless_mcp.server.SessionManager")
    @patch("ida_headless_mcp.server.IdaBridge")
    @patch("ida_headless_mcp.server.BatchManager")
    def test_shutdown_cancels_batch_jobs(self, mock_bm, mock_bridge, mock_sm):
        """shutdown() must cancel all in-progress batch jobs."""
        import asyncio
        from ida_headless_mcp.batch_manager import BatchJobState

        config = _make_valid_config()
        config.validate = MagicMock()
        mock_sm.return_value.close_all_sessions = AsyncMock()
        mock_sm.return_value._sessions = {}

        # Create a mock batch job that is in progress
        job = MagicMock()
        job.state = BatchJobState.IN_PROGRESS
        mock_bm_instance = mock_bm.return_value
        mock_bm_instance._jobs = {"job1": job}
        mock_bm_instance.cancel_job = AsyncMock()

        from ida_headless_mcp.server import IdaMcpServer

        server = IdaMcpServer(config)

        asyncio.run(server.shutdown())
        mock_bm_instance.cancel_job.assert_called_once_with("job1")

    @patch("ida_headless_mcp.server.SessionManager")
    @patch("ida_headless_mcp.server.IdaBridge")
    @patch("ida_headless_mcp.server.BatchManager")
    def test_shutdown_closes_all_sessions(self, mock_bm, mock_bridge, mock_sm):
        """shutdown() must call close_all_sessions on the session manager."""
        import asyncio

        config = _make_valid_config()
        config.validate = MagicMock()
        mock_sm_instance = mock_sm.return_value
        mock_sm_instance.close_all_sessions = AsyncMock()
        mock_sm_instance._sessions = {}
        mock_bm.return_value._jobs = {}

        from ida_headless_mcp.server import IdaMcpServer

        server = IdaMcpServer(config)

        asyncio.run(server.shutdown())
        mock_sm_instance.close_all_sessions.assert_called_once()

    @patch("ida_headless_mcp.server.SessionManager")
    @patch("ida_headless_mcp.server.IdaBridge")
    @patch("ida_headless_mcp.server.BatchManager")
    def test_shutdown_idempotent(self, mock_bm, mock_bridge, mock_sm):
        """Calling shutdown() twice must not re-run the shutdown logic."""
        import asyncio

        config = _make_valid_config()
        config.validate = MagicMock()
        mock_sm_instance = mock_sm.return_value
        mock_sm_instance.close_all_sessions = AsyncMock()
        mock_sm_instance._sessions = {}
        mock_bm.return_value._jobs = {}

        from ida_headless_mcp.server import IdaMcpServer

        server = IdaMcpServer(config)

        asyncio.run(server.shutdown())
        asyncio.run(server.shutdown())

        # close_all_sessions should only be called once
        mock_sm_instance.close_all_sessions.assert_called_once()

    @patch("ida_headless_mcp.server.SessionManager")
    @patch("ida_headless_mcp.server.IdaBridge")
    @patch("ida_headless_mcp.server.BatchManager")
    def test_shutdown_skips_completed_batch_jobs(self, mock_bm, mock_bridge, mock_sm):
        """shutdown() must not cancel already-completed batch jobs."""
        import asyncio
        from ida_headless_mcp.batch_manager import BatchJobState

        config = _make_valid_config()
        config.validate = MagicMock()
        mock_sm.return_value.close_all_sessions = AsyncMock()
        mock_sm.return_value._sessions = {}

        # Create a completed batch job
        job = MagicMock()
        job.state = BatchJobState.COMPLETED
        mock_bm_instance = mock_bm.return_value
        mock_bm_instance._jobs = {"job1": job}
        mock_bm_instance.cancel_job = AsyncMock()

        from ida_headless_mcp.server import IdaMcpServer

        server = IdaMcpServer(config)

        asyncio.run(server.shutdown())
        mock_bm_instance.cancel_job.assert_not_called()

    @patch("ida_headless_mcp.server.SessionManager")
    @patch("ida_headless_mcp.server.IdaBridge")
    @patch("ida_headless_mcp.server.BatchManager")
    def test_shutdown_force_kills_on_timeout(self, mock_bm, mock_bridge, mock_sm):
        """If close_all_sessions times out, shutdown must force-kill processes."""
        import asyncio

        config = _make_valid_config()
        config.validate = MagicMock()

        # Make close_all_sessions hang forever
        async def hang_forever():
            await asyncio.sleep(999)

        mock_sm_instance = mock_sm.return_value
        mock_sm_instance.close_all_sessions = MagicMock(side_effect=hang_forever)

        # Create a mock session with a running process
        mock_process = MagicMock()
        mock_process.returncode = None
        mock_process.kill = MagicMock()
        mock_process.wait = AsyncMock()

        mock_session = MagicMock()
        mock_session.process = mock_process
        mock_session.command_dir = MagicMock()

        mock_sm_instance._sessions = {"s1": mock_session}
        mock_sm_instance._cleanup_command_dir = MagicMock()
        mock_bm.return_value._jobs = {}

        from ida_headless_mcp.server import IdaMcpServer

        server = IdaMcpServer(config)
        # Use a very short timeout for testing
        server._GRACEFUL_TIMEOUT = 0.1

        asyncio.run(server.shutdown())

        mock_process.kill.assert_called_once()
        mock_sm_instance._cleanup_command_dir.assert_called_once_with(mock_session)

    @patch("ida_headless_mcp.server.SessionManager")
    @patch("ida_headless_mcp.server.IdaBridge")
    @patch("ida_headless_mcp.server.BatchManager")
    def test_shutdown_handles_cancel_job_error(self, mock_bm, mock_bridge, mock_sm):
        """shutdown() must not crash if cancel_job raises an exception."""
        import asyncio
        from ida_headless_mcp.batch_manager import BatchJobState

        config = _make_valid_config()
        config.validate = MagicMock()
        mock_sm.return_value.close_all_sessions = AsyncMock()
        mock_sm.return_value._sessions = {}

        job = MagicMock()
        job.state = BatchJobState.IN_PROGRESS
        mock_bm_instance = mock_bm.return_value
        mock_bm_instance._jobs = {"job1": job}
        mock_bm_instance.cancel_job = AsyncMock(side_effect=RuntimeError("cancel failed"))

        from ida_headless_mcp.server import IdaMcpServer

        server = IdaMcpServer(config)

        # Should not raise
        asyncio.run(server.shutdown())
        assert server._shutting_down is True
