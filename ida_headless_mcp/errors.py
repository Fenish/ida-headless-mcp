"""Error types for IDA Headless MCP Server."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ErrorCode(str, Enum):
    """Standardised error codes returned by MCP tool handlers.

    Each member doubles as a plain string so it serialises naturally to JSON.
    """

    INVALID_ADDRESS = "INVALID_ADDRESS"
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
    NO_ACTIVE_SESSION = "NO_ACTIVE_SESSION"
    IDA_NOT_FOUND = "IDA_NOT_FOUND"
    DECOMPILER_UNAVAILABLE = "DECOMPILER_UNAVAILABLE"
    DECOMPILATION_FAILED = "DECOMPILATION_FAILED"
    FUNCTION_NOT_FOUND = "FUNCTION_NOT_FOUND"
    TYPE_CONFLICT = "TYPE_CONFLICT"
    ADDRESS_UNMAPPED = "ADDRESS_UNMAPPED"
    SCRIPT_TIMEOUT = "SCRIPT_TIMEOUT"
    IDA_CRASH = "IDA_CRASH"
    IDA_TIMEOUT = "IDA_TIMEOUT"
    BATCH_NOT_FOUND = "BATCH_NOT_FOUND"
    INVALID_PARAMETER = "INVALID_PARAMETER"


@dataclass
class McpToolError(Exception):
    """Structured error returned by any MCP tool invocation.

    Inherits from :class:`Exception` so it can be raised and caught in
    standard Python exception handling.

    Attributes:
        code: An :class:`ErrorCode` value (or its string equivalent).
        message: A human-readable description of the failure.
        tool_name: The MCP tool that produced the error.
    """

    code: str
    message: str
    tool_name: str

    def to_dict(self) -> dict:
        """Serialise the error to the canonical JSON structure.

        Returns a dict matching the error response format::

            {
                "error": {
                    "code": "...",
                    "message": "...",
                    "tool_name": "..."
                }
            }
        """
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "tool_name": self.tool_name,
            }
        }
