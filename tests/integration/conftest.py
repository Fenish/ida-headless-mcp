"""Integration test configuration.

Adds ``--run-integration`` CLI flag to pytest. Integration tests are
skipped by default unless this flag is provided.
"""

from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run integration tests (requires a real IDA Pro installation)",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "integration: mark test as integration test (requires --run-integration)",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if config.getoption("--run-integration"):
        return
    skip_integration = pytest.mark.skip(
        reason="Integration tests require --run-integration flag"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)
