"""Unit tests for signature tool handlers.

Tests the tool handler functions in ``ida_headless_mcp.tools.signatures``
using a fake session manager that returns pre-configured ScriptResult data.
"""

from __future__ import annotations

import pytest

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.ida_bridge import ScriptResult
from ida_headless_mcp.tools.signatures import (
    apply_signature,
    list_applied_signatures,
    list_available_signatures,
)


# ---------------------------------------------------------------------------
# Helpers — lightweight fakes for tool tests
# ---------------------------------------------------------------------------


class FakeBridge:
    """A bridge that records build_script calls and returns a fixed script."""

    def __init__(self) -> None:
        self.last_operation: str | None = None
        self.last_params: dict | None = None

    def build_script(self, operation: str, params: dict, result_path: str = "") -> str:
        self.last_operation = operation
        self.last_params = params
        return f"__script__:{operation}"


class FakeSessionManager:
    """A session manager that returns pre-configured ScriptResult values."""

    def __init__(self, result: ScriptResult) -> None:
        self._result = result
        self.last_session_id: str | None = None
        self.last_script: str | None = None

    async def execute_script(self, session_id: str, script: str) -> ScriptResult:
        self.last_session_id = session_id
        self.last_script = script
        return self._result


# ---------------------------------------------------------------------------
# apply_signature
# ---------------------------------------------------------------------------


class TestApplySignature:
    """Tests for apply_signature tool handler."""

    @pytest.mark.asyncio
    async def test_returns_signature_result(self):
        result = ScriptResult(
            success=True,
            data={"sig_file": "libc.sig", "functions_matched": 42},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        sig_result = await apply_signature(sm, bridge, "sess1", "libc.sig")

        assert sig_result.sig_file == "libc.sig"
        assert sig_result.functions_matched == 42
        assert bridge.last_operation == "apply_signature"
        assert bridge.last_params == {"sig_file": "libc.sig"}

    @pytest.mark.asyncio
    async def test_empty_sig_file_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await apply_signature(sm, bridge, "sess1", "")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "apply_signature"

    @pytest.mark.asyncio
    async def test_whitespace_sig_file_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await apply_signature(sm, bridge, "sess1", "   ")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Signature file not found"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await apply_signature(sm, bridge, "sess1", "missing.sig")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "apply_signature"
        assert "Signature file not found" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(
            success=True,
            data={"sig_file": "test.sig", "functions_matched": 0},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await apply_signature(sm, bridge, "my_session_42", "test.sig")
        assert sm.last_session_id == "my_session_42"

    @pytest.mark.asyncio
    async def test_zero_matches(self):
        result = ScriptResult(
            success=True,
            data={"sig_file": "empty.sig", "functions_matched": 0},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        sig_result = await apply_signature(sm, bridge, "sess1", "empty.sig")
        assert sig_result.functions_matched == 0

    @pytest.mark.asyncio
    async def test_defaults_when_data_missing_fields(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        sig_result = await apply_signature(sm, bridge, "sess1", "fallback.sig")
        assert sig_result.sig_file == "fallback.sig"
        assert sig_result.functions_matched == 0

    @pytest.mark.asyncio
    async def test_script_failure_generic_message(self):
        result = ScriptResult(success=False, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await apply_signature(sm, bridge, "sess1", "test.sig")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert "Script execution failed" in exc_info.value.message


# ---------------------------------------------------------------------------
# list_applied_signatures
# ---------------------------------------------------------------------------


class TestListAppliedSignatures:
    """Tests for list_applied_signatures tool handler."""

    @pytest.mark.asyncio
    async def test_returns_applied_signatures(self):
        result = ScriptResult(
            success=True,
            data={"signatures": ["libc.sig", "libm.sig"]},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        sigs = await list_applied_signatures(sm, bridge, "sess1")

        assert sigs == ["libc.sig", "libm.sig"]
        assert bridge.last_operation == "list_applied_signatures"
        assert bridge.last_params == {}

    @pytest.mark.asyncio
    async def test_empty_list(self):
        result = ScriptResult(success=True, data={"signatures": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        sigs = await list_applied_signatures(sm, bridge, "sess1")
        assert sigs == []

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Session error"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await list_applied_signatures(sm, bridge, "sess1")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "list_applied_signatures"

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data={"signatures": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_applied_signatures(sm, bridge, "session_xyz")
        assert sm.last_session_id == "session_xyz"

    @pytest.mark.asyncio
    async def test_defaults_when_data_missing(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        sigs = await list_applied_signatures(sm, bridge, "sess1")
        assert sigs == []


# ---------------------------------------------------------------------------
# list_available_signatures
# ---------------------------------------------------------------------------


class TestListAvailableSignatures:
    """Tests for list_available_signatures tool handler."""

    @pytest.mark.asyncio
    async def test_returns_available_signatures(self):
        result = ScriptResult(
            success=True,
            data={"signatures": ["libc.sig", "libm.sig", "libpthread.sig"]},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        sigs = await list_available_signatures(sm, bridge, "sess1")

        assert sigs == ["libc.sig", "libm.sig", "libpthread.sig"]
        assert bridge.last_operation == "list_available_signatures"
        assert bridge.last_params == {}

    @pytest.mark.asyncio
    async def test_empty_directory(self):
        result = ScriptResult(success=True, data={"signatures": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        sigs = await list_available_signatures(sm, bridge, "sess1")
        assert sigs == []

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(
            success=False,
            data={"error": {"message": "Directory not found"}},
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await list_available_signatures(sm, bridge, "sess1")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "list_available_signatures"

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data={"signatures": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_available_signatures(sm, bridge, "session_abc", )
        assert sm.last_session_id == "session_abc"

    @pytest.mark.asyncio
    async def test_defaults_when_data_missing(self):
        result = ScriptResult(success=True, data={})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        sigs = await list_available_signatures(sm, bridge, "sess1")
        assert sigs == []
