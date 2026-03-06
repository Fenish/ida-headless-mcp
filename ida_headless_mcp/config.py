"""Configuration module for IDA Headless MCP Server."""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ServerConfig:
    """Server configuration for the IDA Headless MCP Server.

    Attributes:
        ida_path: Path to the directory containing idat/idat64 executables.
        ida_binary_32: Name of the 32-bit IDA executable.
        ida_binary_64: Name of the 64-bit IDA executable.
        max_concurrent_sessions: Maximum number of concurrent IDA sessions.
        session_timeout: Session inactivity timeout in seconds.
        script_timeout: Per-script execution timeout in seconds.
        batch_max_concurrent: Maximum concurrent IDA processes for batch jobs.
        signatures_dir: Optional path to FLIRT signatures directory.
        transport: Transport protocol ("stdio" or "sse").
        sse_host: Host address for SSE transport.
        sse_port: Port number for SSE transport.
    """

    ida_path: str
    ida_binary_32: str = "idat"
    ida_binary_64: str = "idat64"
    max_concurrent_sessions: int = 5
    session_timeout: int = 3600
    script_timeout: int = 300
    batch_max_concurrent: int = 3
    signatures_dir: str | None = None
    transport: str = "stdio"
    sse_host: str = "127.0.0.1"
    sse_port: int = 8080

    def validate(self) -> None:
        """Validate the configuration.

        Checks that ``ida_path`` points to a directory containing valid
        idat/idat64 executables. On Windows the ``.exe`` suffix is appended
        automatically.

        Raises:
            ValueError: If the IDA path is invalid or executables are missing.
        """
        ida_dir = Path(self.ida_path)

        if not ida_dir.exists():
            raise ValueError(
                f"IDA path does not exist: {self.ida_path}"
            )

        if not ida_dir.is_dir():
            raise ValueError(
                f"IDA path is not a directory: {self.ida_path}"
            )

        suffix = ".exe" if platform.system() == "Windows" else ""
        bin32 = ida_dir / f"{self.ida_binary_32}{suffix}"
        bin64 = ida_dir / f"{self.ida_binary_64}{suffix}"

        if not bin32.is_file() and not bin64.is_file():
            raise ValueError(
                f"No valid IDA executables found in {self.ida_path}. "
                f"Expected '{self.ida_binary_32}{suffix}' or "
                f"'{self.ida_binary_64}{suffix}'."
            )
