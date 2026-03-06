"""End-to-end integration test stubs for MCP client-server round-trips.

These tests require a working IDA Pro installation and are gated behind
the ``--run-integration`` pytest flag.  Run with::

    pytest tests/integration/ --run-integration
"""

from __future__ import annotations

import pytest


@pytest.mark.integration
def test_mcp_server_startup() -> None:
    """Verify that the MCP server starts and accepts connections."""
    pass


@pytest.mark.integration
def test_list_functions_via_mcp() -> None:
    """Verify listing functions through a full MCP client-server round-trip."""
    pass


@pytest.mark.integration
def test_decompile_via_mcp() -> None:
    """Verify decompilation through a full MCP client-server round-trip."""
    pass


@pytest.mark.integration
def test_batch_analysis_via_mcp() -> None:
    """Verify batch analysis through a full MCP client-server round-trip."""
    pass
