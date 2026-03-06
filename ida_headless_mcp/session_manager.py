"""Session Manager — lifecycle management for IDA headless analysis sessions.

This module manages the lifecycle of IDA Pro headless processes.  Each
analysis session runs in its own ``idat`` / ``idat64`` process, communicating
with the MCP server via a file-based protocol (write ``script.py``, read
``result.json``, watch for ``ready`` sentinel).

Key responsibilities:

* Spawn and track IDA processes (one per session).
* Detect binary architecture (32/64-bit) from ELF/PE magic bytes.
* Enforce a configurable concurrency limit via :class:`asyncio.Semaphore`.
* Provide ``execute_script`` for dispatching IDAPython scripts and collecting
  results.
* Support IDB reuse (skip re-analysis when an ``.idb`` / ``.i64`` already
  exists).
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import shutil
import struct
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from ida_headless_mcp.config import ServerConfig
from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.ida_bridge import IdaBridge, ScriptResult
from ida_headless_mcp.models import SessionInfo

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_POLL_INTERVAL = 0.1  # seconds between file-system polls
_PROCESS_WAIT_TIMEOUT = 10  # seconds to wait for graceful process exit


# ---------------------------------------------------------------------------
# SessionState
# ---------------------------------------------------------------------------


class SessionState(Enum):
    """Lifecycle states for an IDA analysis session."""

    STARTING = "starting"
    ANALYZING = "analyzing"
    READY = "ready"
    BUSY = "busy"
    ERROR = "error"
    CLOSED = "closed"


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


class Session:
    """Represents a single IDA analysis session backed by an OS process.

    Attributes:
        session_id: Unique identifier for this session.
        binary_path: Absolute path to the binary being analysed.
        idb_path: Path to the IDA database file (``.idb`` or ``.i64``).
        architecture: ``"32"`` or ``"64"`` depending on the binary.
        state: Current lifecycle state.
        process: The underlying :class:`asyncio.subprocess.Process`, or
            ``None`` if the session has been closed.
        created_at: Unix timestamp of session creation.
        command_dir: Temporary directory used for script/result exchange.
        error_message: Captured error details when the session enters ERROR state.
        exit_code: Process exit code if the IDA process has terminated.
    """

    def __init__(
        self,
        session_id: str,
        binary_path: str,
        idb_path: str,
        architecture: Literal["32", "64"],
        process: asyncio.subprocess.Process | None,
        command_dir: Path,
    ) -> None:
        self.session_id = session_id
        self.binary_path = binary_path
        self.idb_path = idb_path
        self.architecture: Literal["32", "64"] = architecture
        self.state = SessionState.STARTING
        self.process = process
        self.created_at = time.time()
        self.command_dir = command_dir
        self.error_message: str | None = None
        self.exit_code: int | None = None
        self._monitor_task: asyncio.Task | None = None

    def to_session_info(self) -> SessionInfo:
        """Return a lightweight :class:`SessionInfo` snapshot."""
        return SessionInfo(
            session_id=self.session_id,
            binary_path=self.binary_path,
            architecture=self.architecture,
            state=self.state.value,
            created_at=self.created_at,
        )


# ---------------------------------------------------------------------------
# Architecture detection
# ---------------------------------------------------------------------------


def detect_architecture(binary_path: str) -> Literal["32", "64"]:
    """Detect whether a binary is 32-bit or 64-bit from its file header.

    Supports ELF and PE (MZ/PE) formats.  Falls back to ``"64"`` for
    unrecognised formats.

    Args:
        binary_path: Path to the binary file.

    Returns:
        ``"32"`` or ``"64"``.
    """
    try:
        with open(binary_path, "rb") as f:
            magic = f.read(4)

            # ELF: byte 4 (EI_CLASS) — 1 = 32-bit, 2 = 64-bit
            if magic[:4] == b"\x7fELF":
                ei_class = f.read(1)
                if ei_class == b"\x01":
                    return "32"
                return "64"

            # PE: MZ header → PE offset at 0x3C → PE signature + machine
            if magic[:2] == b"MZ":
                f.seek(0x3C)
                pe_offset_bytes = f.read(4)
                if len(pe_offset_bytes) < 4:
                    return "64"
                pe_offset = struct.unpack("<I", pe_offset_bytes)[0]
                f.seek(pe_offset)
                pe_sig = f.read(4)
                if pe_sig != b"PE\x00\x00":
                    return "64"
                machine = struct.unpack("<H", f.read(2))[0]
                # 0x14c = i386, 0x8664 = AMD64, 0xAA64 = ARM64
                if machine == 0x14C:
                    return "32"
                return "64"

    except (OSError, struct.error):
        pass

    # Default to 64-bit for unknown formats
    return "64"


def _find_existing_idb(binary_path: str) -> str | None:
    """Check for an existing IDB file next to the binary.

    Looks for ``<binary>.i64`` first, then ``<binary>.idb``.

    Returns:
        The path to the existing IDB, or ``None``.
    """
    for ext in (".i64", ".idb"):
        candidate = binary_path + ext
        if os.path.isfile(candidate):
            return candidate
    return None


# ---------------------------------------------------------------------------
# SessionManager
# ---------------------------------------------------------------------------


class SessionManager:
    """Manages the lifecycle of IDA headless analysis sessions.

    The manager enforces a configurable concurrency limit via an
    :class:`asyncio.Semaphore` and provides methods to create, query,
    execute scripts against, and close sessions.

    Args:
        config: Server configuration (IDA paths, limits, timeouts).
        bridge: Optional :class:`IdaBridge` instance.  A default one is
            created if not supplied.
    """

    def __init__(self, config: ServerConfig, bridge: IdaBridge | None = None) -> None:
        self.config = config
        self.bridge = bridge or IdaBridge()
        self._sessions: dict[str, Session] = {}
        self._semaphore = asyncio.Semaphore(config.max_concurrent_sessions)
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Session creation
    # ------------------------------------------------------------------

    async def create_session(
        self,
        binary_path: str,
        reuse_idb: bool = True,
    ) -> Session:
        """Create a new analysis session for *binary_path*.

        1. Detect architecture (32/64-bit).
        2. Select the appropriate ``idat`` / ``idat64`` executable.
        3. Check for an existing IDB if *reuse_idb* is ``True``.
        4. Create a temporary command directory.
        5. Spawn the IDA process with the command-loop script.
        6. Wait for the initial ``ready`` sentinel (analysis complete).

        Args:
            binary_path: Path to the binary to analyse.
            reuse_idb: If ``True``, reuse an existing ``.idb`` / ``.i64``
                file when available.

        Returns:
            The newly created :class:`Session`.

        Raises:
            FileNotFoundError: If *binary_path* does not exist.
            RuntimeError: If the IDA process fails to start.
        """
        binary_path = os.path.abspath(binary_path)
        if not os.path.isfile(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        architecture = detect_architecture(binary_path)
        session_id = uuid.uuid4().hex[:12]

        # Determine IDB path
        existing_idb = _find_existing_idb(binary_path) if reuse_idb else None
        if existing_idb:
            idb_path = existing_idb
        else:
            ext = ".i64" if architecture == "64" else ".idb"
            idb_path = binary_path + ext

        # Create temp command directory for script/result exchange
        command_dir = Path(tempfile.mkdtemp(prefix=f"ida_mcp_{session_id}_"))

        # Select IDA executable — prefer 64-bit variant, fall back to unified binary
        suffix = ".exe" if platform.system() == "Windows" else ""
        if architecture == "64":
            preferred = self.config.ida_binary_64  # e.g. idat64
            fallback = self.config.ida_binary_32   # e.g. idat (IDA 9.0 unified)
        else:
            preferred = self.config.ida_binary_32
            fallback = None

        ida_executable = os.path.join(self.config.ida_path, f"{preferred}{suffix}")
        if not os.path.isfile(ida_executable) and fallback:
            ida_executable = os.path.join(self.config.ida_path, f"{fallback}{suffix}")

        # Resolve the command loop script path
        command_loop_script = str(
            Path(__file__).parent / "scripts" / "command_loop.py"
        )

        # Build the IDA command line
        # -A = autonomous mode (no dialogs)
        # -S"script" = run script on startup
        cmd = [
            ida_executable,
            "-A",
            f'-S"{command_loop_script}"',
            binary_path,
        ]

        # Acquire semaphore slot (limits concurrency)
        await self._semaphore.acquire()

        try:
            env = os.environ.copy()
            env["IDA_MCP_COMMAND_DIR"] = str(command_dir)

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            session = Session(
                session_id=session_id,
                binary_path=binary_path,
                idb_path=idb_path,
                architecture=architecture,
                process=process,
                command_dir=command_dir,
            )
            session.state = SessionState.ANALYZING

            async with self._lock:
                self._sessions[session_id] = session

            # Wait for the initial ready sentinel (IDA finished auto-analysis
            # and the command loop is running).
            await self._wait_for_ready(session)
            session.state = SessionState.READY

            # Start background crash monitor
            self._start_monitor(session)

            logger.info(
                "Session %s created for %s (%s-bit)",
                session_id,
                binary_path,
                architecture,
            )
            return session

        except Exception:
            # Release semaphore on failure and clean up
            self._semaphore.release()
            shutil.rmtree(command_dir, ignore_errors=True)
            raise

    # ------------------------------------------------------------------
    # Session closing
    # ------------------------------------------------------------------

    async def close_session(self, session_id: str, save: bool = True) -> None:
        """Close a session, optionally saving the IDB first.

        Args:
            session_id: The session to close.
            save: If ``True``, send a save command before quitting.

        Raises:
            KeyError: If *session_id* is not found.
        """
        async with self._lock:
            if session_id not in self._sessions:
                raise KeyError(f"Session not found: {session_id}")
            session = self._sessions.pop(session_id)

        try:
            # Stop the background crash monitor
            self._stop_monitor(session)

            if save and session.state in (SessionState.READY, SessionState.BUSY):
                # Send a save-and-quit script
                save_script = (
                    'import idc\n'
                    'idc.save_database(idc.get_idb_path(), 0)\n'
                )
                try:
                    await self._dispatch_script(session, save_script, timeout=30)
                except Exception:
                    logger.warning(
                        "Failed to save IDB for session %s", session_id
                    )

            await self._terminate_process(session)
        finally:
            session.state = SessionState.CLOSED
            self._cleanup_command_dir(session)
            self._semaphore.release()

        logger.info("Session %s closed", session_id)

    async def close_all_sessions(self) -> None:
        """Close all active sessions."""
        session_ids = list(self._sessions.keys())
        for sid in session_ids:
            try:
                await self.close_session(sid, save=False)
            except Exception:
                logger.exception("Error closing session %s", sid)

    # ------------------------------------------------------------------
    # Script execution
    # ------------------------------------------------------------------

    async def execute_script(self, session_id: str, script: str) -> ScriptResult:
        """Execute an IDAPython script in the given session.

        Writes ``script.py`` to the session's command directory, waits for
        ``result.json`` and the ``ready`` sentinel, then parses and returns
        the result.

        Args:
            session_id: Target session.
            script: IDAPython script source code.

        Returns:
            The parsed :class:`ScriptResult`.

        Raises:
            KeyError: If *session_id* is not found.
            RuntimeError: If the session is not in a usable state.
        """
        session = self.get_session(session_id)

        if session.state not in (SessionState.READY,):
            raise RuntimeError(
                f"Session {session_id} is in state {session.state.value}, "
                f"expected READY"
            )

        session.state = SessionState.BUSY
        try:
            result = await self._dispatch_script(
                session, script, timeout=self.config.script_timeout
            )
            return result
        except Exception as exc:
            session.state = SessionState.ERROR
            raise
        finally:
            if session.state == SessionState.BUSY:
                session.state = SessionState.READY

    # ------------------------------------------------------------------
    # Session queries
    # ------------------------------------------------------------------

    def get_session(self, session_id: str) -> Session:
        """Return the :class:`Session` for *session_id*.

        Raises:
            KeyError: If the session does not exist.
        """
        if session_id not in self._sessions:
            raise KeyError(f"Session not found: {session_id}")
        return self._sessions[session_id]

    def list_sessions(self) -> list[SessionInfo]:
        """Return a :class:`SessionInfo` snapshot for every active session."""
        return [s.to_session_info() for s in self._sessions.values()]


    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _dispatch_script(
        self,
        session: Session,
        script: str,
        timeout: int | None = None,
    ) -> ScriptResult:
        """Write a script to the command dir and wait for the result.

        1. Remove any stale ``ready`` sentinel and ``result.json``.
        2. Write ``script.py``.
        3. Poll for ``result.json`` + ``ready`` sentinel.
        4. Parse and return the result.
        """
        timeout = timeout or self.config.script_timeout
        cmd_dir = session.command_dir

        script_path = cmd_dir / "script.py"
        result_path = cmd_dir / "result.json"
        ready_path = cmd_dir / "ready"

        # Clean up stale files from previous execution
        for p in (ready_path, result_path):
            if p.exists():
                p.unlink()

        # Write the script
        script_path.write_text(script, encoding="utf-8")

        # Wait for result.json and ready sentinel
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            # Check if the process has died
            if session.process and session.process.returncode is not None:
                stderr_text = await self._read_stderr(session)
                session.exit_code = session.process.returncode
                session.error_message = (
                    f"IDA process exited unexpectedly with code "
                    f"{session.process.returncode}: {stderr_text}"
                )
                session.state = SessionState.ERROR
                self._cleanup_command_dir(session)
                raise RuntimeError(session.error_message)

            if result_path.exists() and ready_path.exists():
                result = self.bridge.parse_result(result_path)
                # Clean up
                for p in (script_path, result_path, ready_path):
                    if p.exists():
                        p.unlink()
                return result

            await asyncio.sleep(_POLL_INTERVAL)

        # Timeout: force-kill the process and clean up
        stderr_text = await self._read_stderr(session)
        session.error_message = (
            f"Script execution timed out after {timeout}s in session "
            f"{session.session_id}"
        )
        session.state = SessionState.ERROR
        await self._terminate_process(session)
        self._cleanup_command_dir(session)
        raise TimeoutError(session.error_message)

    async def _wait_for_ready(self, session: Session) -> None:
        """Wait for the initial ``ready`` sentinel after IDA starts.

        This blocks until the command loop inside IDA signals that
        auto-analysis is complete and it's ready for commands.
        """
        ready_path = session.command_dir / "ready"
        deadline = time.monotonic() + self.config.session_timeout

        while time.monotonic() < deadline:
            if session.process and session.process.returncode is not None:
                stderr_text = await self._read_stderr(session)
                session.exit_code = session.process.returncode
                session.error_message = (
                    f"IDA process exited during analysis with code "
                    f"{session.process.returncode}: {stderr_text}"
                )
                session.state = SessionState.ERROR
                self._cleanup_command_dir(session)
                raise RuntimeError(session.error_message)

            if ready_path.exists():
                ready_path.unlink()
                return

            await asyncio.sleep(_POLL_INTERVAL)

        # Timeout waiting for analysis to complete
        session.error_message = (
            f"IDA process did not become ready within "
            f"{self.config.session_timeout}s"
        )
        session.state = SessionState.ERROR
        await self._terminate_process(session)
        self._cleanup_command_dir(session)
        raise TimeoutError(session.error_message)

    async def _terminate_process(self, session: Session) -> None:
        """Terminate the IDA process gracefully, then force-kill if needed."""
        if session.process is None:
            return

        if session.process.returncode is not None:
            return  # Already exited

        try:
            session.process.terminate()
            try:
                await asyncio.wait_for(
                    session.process.wait(), timeout=_PROCESS_WAIT_TIMEOUT
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "Force-killing IDA process for session %s",
                    session.session_id,
                )
                session.process.kill()
                await session.process.wait()
        except ProcessLookupError:
            pass  # Process already gone

    @staticmethod
    def _cleanup_command_dir(session: Session) -> None:
        """Remove the session's temporary command directory."""
        if session.command_dir and session.command_dir.exists():
            shutil.rmtree(session.command_dir, ignore_errors=True)

    @staticmethod
    async def _read_stderr(session: Session) -> str:
        """Read and return stderr from the session's process.

        Returns an empty string if stderr is unavailable.
        """
        if session.process and session.process.stderr:
            try:
                stderr_bytes = await session.process.stderr.read()
                return stderr_bytes.decode(errors="replace")
            except Exception:
                return ""
        return ""

    async def _monitor_process(self, session: Session) -> None:
        """Background task that monitors the IDA process for unexpected crashes.

        Runs continuously while the session is active.  When the process
        exits unexpectedly (i.e. the session is not in CLOSED or ERROR
        state), this task captures stderr, sets the session to ERROR, and
        cleans up temp files.
        """
        try:
            while True:
                # Stop monitoring if the session is already closed or errored
                if session.state in (SessionState.CLOSED, SessionState.ERROR):
                    return

                # Check if the process has exited
                if session.process and session.process.returncode is not None:
                    # Process died — only act if we're not already handling it
                    if session.state not in (
                        SessionState.CLOSED,
                        SessionState.ERROR,
                    ):
                        stderr_text = await self._read_stderr(session)
                        session.exit_code = session.process.returncode
                        session.error_message = (
                            f"IDA process crashed with exit code "
                            f"{session.process.returncode}: {stderr_text}"
                        )
                        session.state = SessionState.ERROR
                        self._cleanup_command_dir(session)
                        logger.error(
                            "Session %s: IDA process crashed (exit code %d)",
                            session.session_id,
                            session.process.returncode,
                        )
                    return

                await asyncio.sleep(_POLL_INTERVAL * 5)
        except asyncio.CancelledError:
            return

    def _start_monitor(self, session: Session) -> None:
        """Start the background crash-monitoring task for a session."""
        session._monitor_task = asyncio.create_task(
            self._monitor_process(session),
            name=f"monitor-{session.session_id}",
        )

    @staticmethod
    def _stop_monitor(session: Session) -> None:
        """Cancel the background crash-monitoring task for a session."""
        if session._monitor_task and not session._monitor_task.done():
            session._monitor_task.cancel()
