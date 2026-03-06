"""Unit tests for ida_headless_mcp.session_manager."""

from __future__ import annotations

import asyncio
import json
import os
import struct
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ida_headless_mcp.config import ServerConfig
from ida_headless_mcp.ida_bridge import ScriptResult
from ida_headless_mcp.session_manager import (
    Session,
    SessionManager,
    SessionState,
    _find_existing_idb,
    detect_architecture,
)


# ---------------------------------------------------------------------------
# SessionState enum tests
# ---------------------------------------------------------------------------


class TestSessionState:
    """Tests for the SessionState enum."""

    def test_all_states_defined(self):
        states = {s.value for s in SessionState}
        assert states == {"starting", "analyzing", "ready", "busy", "error", "closed"}

    def test_state_values(self):
        assert SessionState.STARTING.value == "starting"
        assert SessionState.ANALYZING.value == "analyzing"
        assert SessionState.READY.value == "ready"
        assert SessionState.BUSY.value == "busy"
        assert SessionState.ERROR.value == "error"
        assert SessionState.CLOSED.value == "closed"


# ---------------------------------------------------------------------------
# Session class tests
# ---------------------------------------------------------------------------


class TestSession:
    """Tests for the Session dataclass."""

    def test_session_creation(self):
        session = Session(
            session_id="abc123",
            binary_path="/tmp/test.bin",
            idb_path="/tmp/test.bin.i64",
            architecture="64",
            process=None,
            command_dir=Path("/tmp/cmd_abc123"),
        )
        assert session.session_id == "abc123"
        assert session.binary_path == "/tmp/test.bin"
        assert session.idb_path == "/tmp/test.bin.i64"
        assert session.architecture == "64"
        assert session.state == SessionState.STARTING
        assert session.process is None
        assert session.created_at > 0

    def test_to_session_info(self):
        session = Session(
            session_id="abc123",
            binary_path="/tmp/test.bin",
            idb_path="/tmp/test.bin.i64",
            architecture="64",
            process=None,
            command_dir=Path("/tmp/cmd_abc123"),
        )
        session.state = SessionState.READY
        info = session.to_session_info()
        assert info.session_id == "abc123"
        assert info.binary_path == "/tmp/test.bin"
        assert info.architecture == "64"
        assert info.state == "ready"
        assert info.created_at == session.created_at

    def test_session_32bit(self):
        session = Session(
            session_id="def456",
            binary_path="/tmp/test32.bin",
            idb_path="/tmp/test32.bin.idb",
            architecture="32",
            process=None,
            command_dir=Path("/tmp/cmd_def456"),
        )
        assert session.architecture == "32"


# ---------------------------------------------------------------------------
# Architecture detection tests
# ---------------------------------------------------------------------------


class TestDetectArchitecture:
    """Tests for detect_architecture()."""

    def test_elf_64bit(self, tmp_path):
        binary = tmp_path / "test64.elf"
        # ELF magic + EI_CLASS=2 (64-bit)
        binary.write_bytes(b"\x7fELF\x02")
        assert detect_architecture(str(binary)) == "64"

    def test_elf_32bit(self, tmp_path):
        binary = tmp_path / "test32.elf"
        # ELF magic + EI_CLASS=1 (32-bit)
        binary.write_bytes(b"\x7fELF\x01")
        assert detect_architecture(str(binary)) == "32"

    def test_pe_32bit(self, tmp_path):
        binary = tmp_path / "test32.exe"
        # Build a minimal PE header: MZ + PE offset at 0x3C + PE sig + machine=0x14c
        data = bytearray(256)
        data[0:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)  # PE offset at 0x80
        data[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<H", data, 0x84, 0x14C)  # i386
        binary.write_bytes(bytes(data))
        assert detect_architecture(str(binary)) == "32"

    def test_pe_64bit(self, tmp_path):
        binary = tmp_path / "test64.exe"
        data = bytearray(256)
        data[0:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<H", data, 0x84, 0x8664)  # AMD64
        binary.write_bytes(bytes(data))
        assert detect_architecture(str(binary)) == "64"

    def test_unknown_format_defaults_to_64(self, tmp_path):
        binary = tmp_path / "unknown.bin"
        binary.write_bytes(b"\x00\x01\x02\x03\x04\x05")
        assert detect_architecture(str(binary)) == "64"

    def test_nonexistent_file_defaults_to_64(self):
        assert detect_architecture("/nonexistent/path/binary") == "64"

    def test_empty_file_defaults_to_64(self, tmp_path):
        binary = tmp_path / "empty.bin"
        binary.write_bytes(b"")
        assert detect_architecture(str(binary)) == "64"


# ---------------------------------------------------------------------------
# IDB reuse detection tests
# ---------------------------------------------------------------------------


class TestFindExistingIdb:
    """Tests for _find_existing_idb()."""

    def test_finds_i64(self, tmp_path):
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00")
        idb = tmp_path / "test.bin.i64"
        idb.write_bytes(b"\x00")
        assert _find_existing_idb(str(binary)) == str(idb)

    def test_finds_idb(self, tmp_path):
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00")
        idb = tmp_path / "test.bin.idb"
        idb.write_bytes(b"\x00")
        assert _find_existing_idb(str(binary)) == str(idb)

    def test_prefers_i64_over_idb(self, tmp_path):
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00")
        (tmp_path / "test.bin.i64").write_bytes(b"\x00")
        (tmp_path / "test.bin.idb").write_bytes(b"\x00")
        result = _find_existing_idb(str(binary))
        assert result is not None
        assert result.endswith(".i64")

    def test_returns_none_when_no_idb(self, tmp_path):
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00")
        assert _find_existing_idb(str(binary)) is None


# ---------------------------------------------------------------------------
# SessionManager tests
# ---------------------------------------------------------------------------


class TestSessionManager:
    """Tests for SessionManager (using mocked subprocess)."""

    @pytest.fixture
    def config(self, tmp_path):
        ida_dir = tmp_path / "ida"
        ida_dir.mkdir()
        (ida_dir / "idat64").write_bytes(b"")
        (ida_dir / "idat").write_bytes(b"")
        return ServerConfig(ida_path=str(ida_dir))

    @pytest.fixture
    def manager(self, config):
        return SessionManager(config)

    def test_init(self, manager, config):
        assert manager.config is config
        assert manager._sessions == {}
        assert manager.bridge is not None

    def test_get_session_not_found(self, manager):
        with pytest.raises(KeyError, match="Session not found"):
            manager.get_session("nonexistent")

    def test_list_sessions_empty(self, manager):
        assert manager.list_sessions() == []

    @pytest.mark.asyncio
    async def test_create_session_binary_not_found(self, manager):
        with pytest.raises(FileNotFoundError, match="Binary not found"):
            await manager.create_session("/nonexistent/binary")

    @pytest.mark.asyncio
    async def test_create_session_spawns_process(self, config, tmp_path):
        """Test that create_session spawns a process and waits for ready."""
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x7fELF\x02")  # 64-bit ELF

        manager = SessionManager(config)

        # Mock the subprocess creation and ready-waiting
        mock_process = MagicMock()
        mock_process.returncode = None
        mock_process.terminate = MagicMock()
        mock_process.kill = MagicMock()
        mock_process.wait = AsyncMock()
        mock_process.stderr = None

        with patch("ida_headless_mcp.session_manager.asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = mock_process

            # Patch _wait_for_ready to avoid actual polling
            with patch.object(manager, "_wait_for_ready", new_callable=AsyncMock):
                session = await manager.create_session(str(binary))

                assert session.architecture == "64"
                assert session.state == SessionState.READY
                assert session.binary_path == str(binary)
                assert session.session_id in [s.session_id for s in manager.list_sessions()]

    @pytest.mark.asyncio
    async def test_create_session_32bit(self, config, tmp_path):
        """Test that 32-bit binaries get the correct architecture."""
        binary = tmp_path / "test32.bin"
        binary.write_bytes(b"\x7fELF\x01")  # 32-bit ELF

        manager = SessionManager(config)
        mock_process = MagicMock()
        mock_process.returncode = None
        mock_process.stderr = None

        with patch("ida_headless_mcp.session_manager.asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = mock_process
            with patch.object(manager, "_wait_for_ready", new_callable=AsyncMock):
                session = await manager.create_session(str(binary))
                assert session.architecture == "32"

    @pytest.mark.asyncio
    async def test_create_session_reuse_idb(self, config, tmp_path):
        """Test IDB reuse when an existing .i64 file is present."""
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x7fELF\x02")
        existing_idb = tmp_path / "test.bin.i64"
        existing_idb.write_bytes(b"\x00")

        manager = SessionManager(config)
        mock_process = MagicMock()
        mock_process.returncode = None
        mock_process.stderr = None

        with patch("ida_headless_mcp.session_manager.asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = mock_process
            with patch.object(manager, "_wait_for_ready", new_callable=AsyncMock):
                session = await manager.create_session(str(binary), reuse_idb=True)
                assert session.idb_path == str(existing_idb)

    @pytest.mark.asyncio
    async def test_create_session_no_reuse(self, config, tmp_path):
        """Test that reuse_idb=False ignores existing IDB."""
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x7fELF\x02")
        existing_idb = tmp_path / "test.bin.i64"
        existing_idb.write_bytes(b"\x00")

        manager = SessionManager(config)
        mock_process = MagicMock()
        mock_process.returncode = None
        mock_process.stderr = None

        with patch("ida_headless_mcp.session_manager.asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = mock_process
            with patch.object(manager, "_wait_for_ready", new_callable=AsyncMock):
                session = await manager.create_session(str(binary), reuse_idb=False)
                # Should use the default path, not the existing one
                assert session.idb_path == str(binary) + ".i64"

    @pytest.mark.asyncio
    async def test_close_session(self, config, tmp_path):
        """Test closing a session terminates the process and cleans up."""
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x7fELF\x02")

        manager = SessionManager(config)
        mock_process = MagicMock()
        mock_process.returncode = None
        mock_process.terminate = MagicMock()
        mock_process.kill = MagicMock()
        mock_process.wait = AsyncMock()
        mock_process.stderr = None

        with patch("ida_headless_mcp.session_manager.asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = mock_process
            with patch.object(manager, "_wait_for_ready", new_callable=AsyncMock):
                session = await manager.create_session(str(binary))
                sid = session.session_id

                # Patch _dispatch_script for the save command
                with patch.object(manager, "_dispatch_script", new_callable=AsyncMock):
                    # Simulate process already exited for terminate
                    mock_process.returncode = 0
                    await manager.close_session(sid)

                assert session.state == SessionState.CLOSED
                assert sid not in [s.session_id for s in manager.list_sessions()]

    @pytest.mark.asyncio
    async def test_close_session_not_found(self, manager):
        with pytest.raises(KeyError, match="Session not found"):
            await manager.close_session("nonexistent")

    @pytest.mark.asyncio
    async def test_close_all_sessions(self, config, tmp_path):
        """Test closing all sessions."""
        manager = SessionManager(config)
        mock_process = MagicMock()
        mock_process.returncode = None
        mock_process.terminate = MagicMock()
        mock_process.kill = MagicMock()
        mock_process.wait = AsyncMock()
        mock_process.stderr = None

        binaries = []
        for i in range(3):
            b = tmp_path / f"test{i}.bin"
            b.write_bytes(b"\x7fELF\x02")
            binaries.append(b)

        with patch("ida_headless_mcp.session_manager.asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = mock_process
            with patch.object(manager, "_wait_for_ready", new_callable=AsyncMock):
                for b in binaries:
                    await manager.create_session(str(b))

                assert len(manager.list_sessions()) == 3

                mock_process.returncode = 0
                await manager.close_all_sessions()
                assert len(manager.list_sessions()) == 0

    @pytest.mark.asyncio
    async def test_execute_script(self, config, tmp_path):
        """Test script execution via the file-based protocol."""
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x7fELF\x02")

        manager = SessionManager(config)
        mock_process = MagicMock()
        mock_process.returncode = None
        mock_process.stderr = None

        with patch("ida_headless_mcp.session_manager.asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = mock_process
            with patch.object(manager, "_wait_for_ready", new_callable=AsyncMock):
                session = await manager.create_session(str(binary))

        # Now test execute_script by mocking _dispatch_script
        expected_result = ScriptResult(success=True, data={"test": "value"})
        with patch.object(manager, "_dispatch_script", new_callable=AsyncMock, return_value=expected_result):
            result = await manager.execute_script(session.session_id, "print('hello')")
            assert result.success is True
            assert result.data == {"test": "value"}
            assert session.state == SessionState.READY

    @pytest.mark.asyncio
    async def test_execute_script_not_ready(self, config, tmp_path):
        """Test that execute_script rejects sessions not in READY state."""
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x7fELF\x02")

        manager = SessionManager(config)
        mock_process = MagicMock()
        mock_process.returncode = None
        mock_process.stderr = None

        with patch("ida_headless_mcp.session_manager.asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = mock_process
            with patch.object(manager, "_wait_for_ready", new_callable=AsyncMock):
                session = await manager.create_session(str(binary))

        session.state = SessionState.ERROR
        with pytest.raises(RuntimeError, match="expected READY"):
            await manager.execute_script(session.session_id, "print('hello')")

    @pytest.mark.asyncio
    async def test_execute_script_session_not_found(self, manager):
        with pytest.raises(KeyError, match="Session not found"):
            await manager.execute_script("nonexistent", "print('hello')")

    @pytest.mark.asyncio
    async def test_dispatch_script_file_protocol(self, config, tmp_path):
        """Test the actual file-based dispatch protocol."""
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x7fELF\x02")

        manager = SessionManager(config)

        # Create a session manually with a real command_dir
        cmd_dir = tmp_path / "cmd"
        cmd_dir.mkdir()

        session = Session(
            session_id="test123",
            binary_path=str(binary),
            idb_path=str(binary) + ".i64",
            architecture="64",
            process=MagicMock(returncode=None),
            command_dir=cmd_dir,
        )
        session.state = SessionState.READY

        # Simulate the IDA process writing result.json and ready sentinel
        # after a short delay
        async def simulate_ida():
            await asyncio.sleep(0.2)
            result_data = {"success": True, "data": {"answer": 42}}
            (cmd_dir / "result.json").write_text(json.dumps(result_data))
            (cmd_dir / "ready").write_text("")

        task = asyncio.create_task(simulate_ida())

        result = await manager._dispatch_script(session, "print('test')", timeout=5)
        await task

        assert result.success is True
        assert result.data == {"answer": 42}

    @pytest.mark.asyncio
    async def test_dispatch_script_timeout(self, config, tmp_path):
        """Test that dispatch times out when no result appears."""
        cmd_dir = tmp_path / "cmd"
        cmd_dir.mkdir()

        mock_process = MagicMock(returncode=None)
        mock_process.terminate = MagicMock()
        mock_process.kill = MagicMock()
        mock_process.wait = AsyncMock()
        mock_process.stderr = None

        session = Session(
            session_id="test_timeout",
            binary_path="/fake/binary",
            idb_path="/fake/binary.i64",
            architecture="64",
            process=mock_process,
            command_dir=cmd_dir,
        )

        manager = SessionManager(config)

        with pytest.raises(TimeoutError, match="timed out"):
            await manager._dispatch_script(session, "print('slow')", timeout=0.3)

    def test_list_sessions_returns_info(self, config):
        """Test that list_sessions returns SessionInfo objects."""
        manager = SessionManager(config)

        # Manually add a session
        session = Session(
            session_id="manual1",
            binary_path="/tmp/test.bin",
            idb_path="/tmp/test.bin.i64",
            architecture="64",
            process=None,
            command_dir=Path("/tmp/cmd"),
        )
        session.state = SessionState.READY
        manager._sessions["manual1"] = session

        sessions = manager.list_sessions()
        assert len(sessions) == 1
        assert sessions[0].session_id == "manual1"
        assert sessions[0].state == "ready"
        assert sessions[0].architecture == "64"


# ---------------------------------------------------------------------------
# Crash detection and timeout handling tests (Task 4.2)
# ---------------------------------------------------------------------------


class TestCrashDetection:
    """Tests for IDA process crash detection and error state handling."""

    @pytest.fixture
    def config(self, tmp_path):
        ida_dir = tmp_path / "ida"
        ida_dir.mkdir()
        (ida_dir / "idat64").write_bytes(b"")
        (ida_dir / "idat").write_bytes(b"")
        return ServerConfig(ida_path=str(ida_dir))

    def _make_session(self, tmp_path, returncode=None, stderr_data=b""):
        """Create a Session with a mock process."""
        cmd_dir = tmp_path / "cmd"
        cmd_dir.mkdir(exist_ok=True)

        mock_process = MagicMock()
        mock_process.returncode = returncode
        mock_process.terminate = MagicMock()
        mock_process.kill = MagicMock()
        mock_process.wait = AsyncMock()

        # Set up stderr as an async-readable stream
        mock_stderr = AsyncMock()
        mock_stderr.read = AsyncMock(return_value=stderr_data)
        mock_process.stderr = mock_stderr

        session = Session(
            session_id="crash_test",
            binary_path="/fake/binary",
            idb_path="/fake/binary.i64",
            architecture="64",
            process=mock_process,
            command_dir=cmd_dir,
        )
        session.state = SessionState.READY
        return session

    def test_session_has_error_fields(self, tmp_path):
        """Session should have error_message, exit_code, and _monitor_task attributes."""
        session = self._make_session(tmp_path)
        assert session.error_message is None
        assert session.exit_code is None
        assert session._monitor_task is None

    @pytest.mark.asyncio
    async def test_dispatch_script_crash_sets_error_state(self, config, tmp_path):
        """When IDA process crashes during script dispatch, session state should be ERROR."""
        session = self._make_session(tmp_path, returncode=-11, stderr_data=b"Segmentation fault")
        manager = SessionManager(config)

        with pytest.raises(RuntimeError, match="exited unexpectedly"):
            await manager._dispatch_script(session, "print('test')", timeout=1)

        assert session.state == SessionState.ERROR
        assert session.exit_code == -11
        assert "Segmentation fault" in session.error_message

    @pytest.mark.asyncio
    async def test_dispatch_script_crash_cleans_up_temp_files(self, config, tmp_path):
        """Crash during dispatch should clean up the command directory."""
        session = self._make_session(tmp_path, returncode=1, stderr_data=b"error")
        manager = SessionManager(config)

        with pytest.raises(RuntimeError):
            await manager._dispatch_script(session, "print('test')", timeout=1)

        # command_dir should be cleaned up
        assert not session.command_dir.exists()

    @pytest.mark.asyncio
    async def test_dispatch_script_timeout_sets_error_state(self, config, tmp_path):
        """When script times out, session state should be ERROR."""
        session = self._make_session(tmp_path)
        manager = SessionManager(config)

        with pytest.raises(TimeoutError, match="timed out"):
            await manager._dispatch_script(session, "print('slow')", timeout=0.3)

        assert session.state == SessionState.ERROR
        assert "timed out" in session.error_message

    @pytest.mark.asyncio
    async def test_dispatch_script_timeout_terminates_process(self, config, tmp_path):
        """When script times out, the IDA process should be terminated."""
        session = self._make_session(tmp_path)
        manager = SessionManager(config)

        # Make wait_for return immediately to simulate process exiting after kill
        session.process.wait = AsyncMock(return_value=0)

        with pytest.raises(TimeoutError):
            await manager._dispatch_script(session, "print('slow')", timeout=0.3)

        session.process.terminate.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_script_timeout_cleans_up_temp_files(self, config, tmp_path):
        """Timeout during dispatch should clean up the command directory."""
        session = self._make_session(tmp_path)
        session.process.wait = AsyncMock(return_value=0)
        manager = SessionManager(config)

        with pytest.raises(TimeoutError):
            await manager._dispatch_script(session, "print('slow')", timeout=0.3)

        assert not session.command_dir.exists()

    @pytest.mark.asyncio
    async def test_wait_for_ready_crash_sets_error_state(self, config, tmp_path):
        """When IDA crashes during initial analysis, session should be ERROR."""
        session = self._make_session(
            tmp_path, returncode=-6, stderr_data=b"Aborted"
        )
        session.state = SessionState.ANALYZING
        manager = SessionManager(config)

        with pytest.raises(RuntimeError, match="exited during analysis"):
            await manager._wait_for_ready(session)

        assert session.state == SessionState.ERROR
        assert session.exit_code == -6
        assert "Aborted" in session.error_message

    @pytest.mark.asyncio
    async def test_wait_for_ready_crash_cleans_up(self, config, tmp_path):
        """Crash during wait_for_ready should clean up temp files."""
        session = self._make_session(
            tmp_path, returncode=1, stderr_data=b"error"
        )
        session.state = SessionState.ANALYZING
        manager = SessionManager(config)

        with pytest.raises(RuntimeError):
            await manager._wait_for_ready(session)

        assert not session.command_dir.exists()

    @pytest.mark.asyncio
    async def test_wait_for_ready_timeout_sets_error_state(self, config, tmp_path):
        """When IDA doesn't become ready within timeout, session should be ERROR."""
        session = self._make_session(tmp_path)
        session.state = SessionState.ANALYZING
        session.process.wait = AsyncMock(return_value=0)

        # Use a very short timeout
        config.session_timeout = 0.3
        manager = SessionManager(config)

        with pytest.raises(TimeoutError, match="did not become ready"):
            await manager._wait_for_ready(session)

        assert session.state == SessionState.ERROR
        assert "did not become ready" in session.error_message

    @pytest.mark.asyncio
    async def test_wait_for_ready_timeout_terminates_process(self, config, tmp_path):
        """Timeout during wait_for_ready should terminate the process."""
        session = self._make_session(tmp_path)
        session.state = SessionState.ANALYZING
        session.process.wait = AsyncMock(return_value=0)

        config.session_timeout = 0.3
        manager = SessionManager(config)

        with pytest.raises(TimeoutError):
            await manager._wait_for_ready(session)

        session.process.terminate.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_script_sets_error_on_crash(self, config, tmp_path):
        """execute_script should set ERROR state when dispatch raises."""
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x7fELF\x02")

        manager = SessionManager(config)
        mock_process = MagicMock()
        mock_process.returncode = None
        mock_process.stderr = None

        with patch(
            "ida_headless_mcp.session_manager.asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
        ) as mock_exec:
            mock_exec.return_value = mock_process
            with patch.object(manager, "_wait_for_ready", new_callable=AsyncMock):
                with patch.object(manager, "_start_monitor"):
                    session = await manager.create_session(str(binary))

        # Simulate crash during script execution
        with patch.object(
            manager,
            "_dispatch_script",
            new_callable=AsyncMock,
            side_effect=RuntimeError("IDA process exited unexpectedly"),
        ):
            with pytest.raises(RuntimeError):
                await manager.execute_script(session.session_id, "print('test')")

        assert session.state == SessionState.ERROR


class TestBackgroundMonitor:
    """Tests for the background process crash monitoring task."""

    @pytest.fixture
    def config(self, tmp_path):
        ida_dir = tmp_path / "ida"
        ida_dir.mkdir()
        (ida_dir / "idat64").write_bytes(b"")
        return ServerConfig(ida_path=str(ida_dir))

    @pytest.mark.asyncio
    async def test_monitor_detects_crash(self, config, tmp_path):
        """Background monitor should detect process crash and set ERROR state."""
        cmd_dir = tmp_path / "cmd"
        cmd_dir.mkdir()

        mock_process = MagicMock()
        mock_process.returncode = None
        mock_stderr = AsyncMock()
        mock_stderr.read = AsyncMock(return_value=b"SIGSEGV")
        mock_process.stderr = mock_stderr

        session = Session(
            session_id="monitor_test",
            binary_path="/fake/binary",
            idb_path="/fake/binary.i64",
            architecture="64",
            process=mock_process,
            command_dir=cmd_dir,
        )
        session.state = SessionState.READY

        manager = SessionManager(config)

        # Start the monitor
        manager._start_monitor(session)

        # Simulate process crash after a short delay
        await asyncio.sleep(0.1)
        mock_process.returncode = -11

        # Wait for the monitor to detect the crash
        await asyncio.sleep(1.0)

        assert session.state == SessionState.ERROR
        assert session.exit_code == -11
        assert "SIGSEGV" in session.error_message
        assert not cmd_dir.exists()  # temp files cleaned up

    @pytest.mark.asyncio
    async def test_monitor_stops_on_closed_session(self, config, tmp_path):
        """Monitor should stop when session is closed."""
        cmd_dir = tmp_path / "cmd"
        cmd_dir.mkdir()

        mock_process = MagicMock()
        mock_process.returncode = None
        mock_process.stderr = None

        session = Session(
            session_id="monitor_close_test",
            binary_path="/fake/binary",
            idb_path="/fake/binary.i64",
            architecture="64",
            process=mock_process,
            command_dir=cmd_dir,
        )
        session.state = SessionState.READY

        manager = SessionManager(config)
        manager._start_monitor(session)

        # Close the session
        session.state = SessionState.CLOSED

        # Wait for monitor to notice and exit
        await asyncio.sleep(1.0)

        assert session._monitor_task.done()

    @pytest.mark.asyncio
    async def test_monitor_cancellation(self, config, tmp_path):
        """Monitor task should handle cancellation gracefully."""
        cmd_dir = tmp_path / "cmd"
        cmd_dir.mkdir()

        mock_process = MagicMock()
        mock_process.returncode = None
        mock_process.stderr = None

        session = Session(
            session_id="cancel_test",
            binary_path="/fake/binary",
            idb_path="/fake/binary.i64",
            architecture="64",
            process=mock_process,
            command_dir=cmd_dir,
        )
        session.state = SessionState.READY

        manager = SessionManager(config)
        manager._start_monitor(session)

        # Cancel the monitor
        manager._stop_monitor(session)
        await asyncio.sleep(0.2)

        assert session._monitor_task.done()

    @pytest.mark.asyncio
    async def test_stop_monitor_no_task(self, config, tmp_path):
        """_stop_monitor should be safe to call when no monitor is running."""
        session = Session(
            session_id="no_monitor",
            binary_path="/fake/binary",
            idb_path="/fake/binary.i64",
            architecture="64",
            process=None,
            command_dir=tmp_path,
        )
        # Should not raise
        SessionManager._stop_monitor(session)

    @pytest.mark.asyncio
    async def test_monitor_does_not_act_on_already_errored_session(self, config, tmp_path):
        """Monitor should not overwrite error info if session is already in ERROR state."""
        cmd_dir = tmp_path / "cmd"
        cmd_dir.mkdir()

        mock_process = MagicMock()
        mock_process.returncode = -11
        mock_stderr = AsyncMock()
        mock_stderr.read = AsyncMock(return_value=b"crash info")
        mock_process.stderr = mock_stderr

        session = Session(
            session_id="already_error",
            binary_path="/fake/binary",
            idb_path="/fake/binary.i64",
            architecture="64",
            process=mock_process,
            command_dir=cmd_dir,
        )
        session.state = SessionState.ERROR
        session.error_message = "Previous error"

        manager = SessionManager(config)
        manager._start_monitor(session)

        await asyncio.sleep(0.5)

        # Should not overwrite the existing error
        assert session.error_message == "Previous error"


class TestReadStderr:
    """Tests for the _read_stderr helper."""

    @pytest.fixture
    def config(self, tmp_path):
        ida_dir = tmp_path / "ida"
        ida_dir.mkdir()
        (ida_dir / "idat64").write_bytes(b"")
        return ServerConfig(ida_path=str(ida_dir))

    @pytest.mark.asyncio
    async def test_read_stderr_with_data(self, config, tmp_path):
        """Should read and decode stderr bytes."""
        session = Session(
            session_id="stderr_test",
            binary_path="/fake/binary",
            idb_path="/fake/binary.i64",
            architecture="64",
            process=MagicMock(),
            command_dir=tmp_path,
        )
        mock_stderr = AsyncMock()
        mock_stderr.read = AsyncMock(return_value=b"error output here")
        session.process.stderr = mock_stderr

        manager = SessionManager(config)
        result = await manager._read_stderr(session)
        assert result == "error output here"

    @pytest.mark.asyncio
    async def test_read_stderr_no_process(self, config, tmp_path):
        """Should return empty string when process is None."""
        session = Session(
            session_id="no_proc",
            binary_path="/fake/binary",
            idb_path="/fake/binary.i64",
            architecture="64",
            process=None,
            command_dir=tmp_path,
        )
        manager = SessionManager(config)
        result = await manager._read_stderr(session)
        assert result == ""

    @pytest.mark.asyncio
    async def test_read_stderr_no_stderr_stream(self, config, tmp_path):
        """Should return empty string when stderr stream is None."""
        session = Session(
            session_id="no_stderr",
            binary_path="/fake/binary",
            idb_path="/fake/binary.i64",
            architecture="64",
            process=MagicMock(stderr=None),
            command_dir=tmp_path,
        )
        manager = SessionManager(config)
        result = await manager._read_stderr(session)
        assert result == ""

    @pytest.mark.asyncio
    async def test_read_stderr_exception_returns_empty(self, config, tmp_path):
        """Should return empty string if reading stderr raises."""
        session = Session(
            session_id="stderr_err",
            binary_path="/fake/binary",
            idb_path="/fake/binary.i64",
            architecture="64",
            process=MagicMock(),
            command_dir=tmp_path,
        )
        mock_stderr = AsyncMock()
        mock_stderr.read = AsyncMock(side_effect=OSError("broken pipe"))
        session.process.stderr = mock_stderr

        manager = SessionManager(config)
        result = await manager._read_stderr(session)
        assert result == ""
