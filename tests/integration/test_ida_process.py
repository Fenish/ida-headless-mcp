"""Integration test stubs for real IDA process management.

These tests require a working IDA Pro installation and are gated behind
the ``--run-integration`` pytest flag.  Run with::

    pytest tests/integration/ --run-integration
"""

from __future__ import annotations

import pytest


@pytest.mark.integration
def test_create_session_with_real_ida() -> None:
    """Verify that a session can be created with a real IDA Pro binary."""
    pass


@pytest.mark.integration
def test_execute_script_in_real_ida() -> None:
    """Verify that an IDAPython script executes inside a real IDA session."""
    pass


@pytest.mark.integration
def test_session_cleanup_on_close() -> None:
    """Verify that closing a session terminates the IDA process and cleans up temp files."""
    pass


@pytest.mark.integration
def test_crash_detection() -> None:
    """Verify that the server detects and reports IDA process crashes."""
    pass
