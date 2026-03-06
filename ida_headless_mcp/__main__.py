"""CLI entry point for the IDA Headless MCP Server.

Run via ``python -m ida_headless_mcp``.

Requirements: 1.1
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

from ida_headless_mcp.config import ServerConfig
from ida_headless_mcp.server import IdaMcpServer


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="ida-headless-mcp",
        description="IDA Headless MCP Server — expose IDA Pro as MCP tools.",
    )
    parser.add_argument(
        "--ida-path",
        default=os.environ.get("IDA_PATH"),
        help=(
            "Path to the directory containing idat/idat64 executables. "
            "Falls back to the IDA_PATH environment variable."
        ),
    )
    parser.add_argument(
        "--transport",
        default="stdio",
        choices=["stdio", "sse"],
        help="Transport protocol (default: stdio).",
    )
    parser.add_argument(
        "--sse-host",
        default="127.0.0.1",
        help="Host address for SSE transport (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--sse-port",
        type=int,
        default=8080,
        help="Port number for SSE transport (default: 8080).",
    )
    parser.add_argument(
        "--max-sessions",
        type=int,
        default=5,
        help="Maximum concurrent IDA sessions (default: 5).",
    )
    parser.add_argument(
        "--signatures-dir",
        default=None,
        help="Path to FLIRT signatures directory.",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    """Parse arguments, build config, and run the server."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.ida_path:
        parser.error(
            "--ida-path is required (or set the IDA_PATH environment variable)"
        )

    config = ServerConfig(
        ida_path=args.ida_path,
        max_concurrent_sessions=args.max_sessions,
        signatures_dir=args.signatures_dir,
        transport=args.transport,
        sse_host=args.sse_host,
        sse_port=args.sse_port,
    )

    try:
        server = IdaMcpServer(config)
        asyncio.run(server.run())
    except Exception as exc:
        logging.error("Fatal: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
