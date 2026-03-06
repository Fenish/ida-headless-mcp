"""IDAPython command loop — file-watching loop that runs inside an IDA process.

This script is executed by IDA Pro in headless mode.  It polls a *command
directory* (specified via the ``IDA_MCP_COMMAND_DIR`` environment variable)
for incoming ``script.py`` files, executes them via :func:`exec`, and writes
results back as ``result.json``.  A ``ready`` sentinel file is created after
each execution to signal the MCP server that the IDA process is ready for
the next command.

Protocol
--------
1. The MCP server writes an IDAPython script to ``<command_dir>/script.py``.
2. This loop detects the file, reads its contents, and removes it.
3. The script is executed via ``exec()`` in a shared namespace that persists
   across commands (so scripts can build on previous state).
4. If the executed script writes ``result.json`` itself, that result is kept.
   If the script raises an exception *without* writing a result, this loop
   writes an error ``result.json`` on its behalf.
5. A ``ready`` sentinel file is created to signal completion.
6. The loop then waits for the next ``script.py``.

Environment Variables
---------------------
``IDA_MCP_COMMAND_DIR``
    Absolute path to the directory used for script/result exchange.
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_POLL_INTERVAL = 0.1  # seconds between polls when idle

# ---------------------------------------------------------------------------
# Resolve command directory from environment
# ---------------------------------------------------------------------------


def _get_command_dir() -> str:
    """Return the command directory path from the environment.

    Raises
    ------
    RuntimeError
        If ``IDA_MCP_COMMAND_DIR`` is not set or points to a non-existent
        directory.
    """
    command_dir = os.environ.get("IDA_MCP_COMMAND_DIR")
    if not command_dir:
        raise RuntimeError(
            "IDA_MCP_COMMAND_DIR environment variable is not set. "
            "The command loop requires this variable to locate the "
            "script/result exchange directory."
        )
    if not os.path.isdir(command_dir):
        raise RuntimeError(
            f"IDA_MCP_COMMAND_DIR points to a non-existent directory: "
            f"{command_dir}"
        )
    return command_dir


# ---------------------------------------------------------------------------
# Core loop helpers
# ---------------------------------------------------------------------------


def _write_result(command_dir: str, result: dict) -> None:
    """Write *result* as JSON to ``<command_dir>/result.json``."""
    result_path = os.path.join(command_dir, "result.json")
    with open(result_path, "w") as fh:
        json.dump(result, fh)


def _create_ready_sentinel(command_dir: str) -> None:
    """Create the ``ready`` sentinel file in *command_dir*."""
    ready_path = os.path.join(command_dir, "ready")
    with open(ready_path, "w") as fh:
        fh.write("")


def _execute_script(script_code: str, command_dir: str) -> None:
    """Execute *script_code* and handle result/error writing.

    The script is executed via :func:`exec` in a namespace that includes
    ``__name__`` set to ``"__main__"`` so that ``if __name__ == ...`` guards
    work as expected.

    If the script itself writes ``result.json``, that file is preserved.
    If the script raises an exception without writing a result, an error
    result is written automatically.
    """
    result_path = os.path.join(command_dir, "result.json")

    # Build a namespace for the executed script.  We intentionally keep a
    # persistent namespace so that scripts can share state across invocations
    # (e.g. helper functions defined in one script can be used by the next).
    exec_globals: dict = {"__name__": "__main__", "__file__": "<mcp_script>"}

    try:
        exec(script_code, exec_globals)  # noqa: S102 — intentional exec
    except Exception as exc:
        # Only write an error result if the script didn't already produce one.
        if not os.path.exists(result_path):
            error_result = {
                "success": False,
                "error": {
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "traceback": traceback.format_exc(),
                },
            }
            _write_result(command_dir, error_result)


def _poll_once(command_dir: str) -> bool:
    """Check for ``script.py`` and execute it if present.

    Returns ``True`` if a script was found and executed, ``False`` otherwise.
    """
    script_path = os.path.join(command_dir, "script.py")
    if not os.path.exists(script_path):
        return False

    # Read and remove the script file atomically (as much as the OS allows).
    with open(script_path, "r") as fh:
        script_code = fh.read()
    os.remove(script_path)

    # Execute the script (handles its own error writing).
    _execute_script(script_code, command_dir)

    # Signal that we're ready for the next command.
    _create_ready_sentinel(command_dir)
    return True


def run_loop(command_dir: str | None = None) -> None:  # pragma: no cover
    """Run the command loop indefinitely.

    Parameters
    ----------
    command_dir:
        Override for the command directory.  When ``None`` (the default),
        the directory is read from ``IDA_MCP_COMMAND_DIR``.
    """
    if command_dir is None:
        command_dir = _get_command_dir()

    while True:
        if not _poll_once(command_dir):
            time.sleep(_POLL_INTERVAL)


# ---------------------------------------------------------------------------
# Entry point — executed when IDA runs this script via ``-S`` flag
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    run_loop()
