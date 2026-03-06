"""Unit tests for scripting tool handlers.

Tests the tool handler functions in ``ida_headless_mcp.tools.scripting``
using a fake session manager that returns pre-configured ScriptResult data.
"""

from __future__ import annotations

import pytest

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.ida_bridge import ScriptResult
from ida_headless_mcp.tools.scripting import (
    execute_script,
    execute_script_file,
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
# execute_script
# ---------------------------------------------------------------------------


class TestExecuteScript:
    """Tests for execute_script tool handler."""

    @pytest.mark.asyncio
    async def test_success_with_stdout(self):
        result = ScriptResult(
            success=True,
            data=None,
            stdout="Hello from script\n",
            return_value=42,
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        resp = await execute_script(sm, bridge, "sess1", "print('Hello from script')")

        assert resp["success"] is True
        assert resp["stdout"] == "Hello from script\n"
        assert resp["return_value"] == 42
        assert resp["exception"] is None
        assert bridge.last_operation == "execute_script"
        assert bridge.last_params["script"] == "print('Hello from script')"
        assert bridge.last_params["timeout"] == 30

    @pytest.mark.asyncio
    async def test_success_no_return_value(self):
        result = ScriptResult(success=True, data=None, stdout="", return_value=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        resp = await execute_script(sm, bridge, "sess1", "x = 1")

        assert resp["success"] is True
        assert resp["stdout"] == ""
        assert resp["return_value"] is None
        assert resp["exception"] is None

    @pytest.mark.asyncio
    async def test_exception_captured(self):
        result = ScriptResult(
            success=False,
            data={
                "exception": {
                    "type": "ValueError",
                    "message": "bad value",
                    "traceback": "Traceback ...\nValueError: bad value",
                }
            },
            stdout="partial output\n",
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        resp = await execute_script(sm, bridge, "sess1", "raise ValueError('bad value')")

        assert resp["success"] is False
        assert resp["stdout"] == "partial output\n"
        assert resp["exception"] is not None
        assert resp["exception"]["type"] == "ValueError"
        assert resp["exception"]["message"] == "bad value"
        assert "Traceback" in resp["exception"]["traceback"]

    @pytest.mark.asyncio
    async def test_empty_script_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await execute_script(sm, bridge, "sess1", "")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "execute_script"

    @pytest.mark.asyncio
    async def test_whitespace_script_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await execute_script(sm, bridge, "sess1", "   \n  ")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER

    @pytest.mark.asyncio
    async def test_zero_timeout_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await execute_script(sm, bridge, "sess1", "x = 1", timeout=0)
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "execute_script"

    @pytest.mark.asyncio
    async def test_negative_timeout_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await execute_script(sm, bridge, "sess1", "x = 1", timeout=-5)
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER

    @pytest.mark.asyncio
    async def test_custom_timeout_forwarded(self):
        result = ScriptResult(success=True, data=None, stdout="")
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await execute_script(sm, bridge, "sess1", "x = 1", timeout=60)

        assert bridge.last_params["timeout"] == 60

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data=None, stdout="")
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await execute_script(sm, bridge, "my_session_42", "x = 1")
        assert sm.last_session_id == "my_session_42"

    @pytest.mark.asyncio
    async def test_default_timeout_is_30(self):
        result = ScriptResult(success=True, data=None, stdout="")
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await execute_script(sm, bridge, "sess1", "x = 1")
        assert bridge.last_params["timeout"] == 30

    @pytest.mark.asyncio
    async def test_exception_with_missing_fields_defaults(self):
        result = ScriptResult(
            success=False,
            data={"exception": {"type": "RuntimeError"}},
            stdout="",
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        resp = await execute_script(sm, bridge, "sess1", "raise RuntimeError()")

        assert resp["exception"]["type"] == "RuntimeError"
        assert resp["exception"]["message"] == ""
        assert resp["exception"]["traceback"] == ""


# ---------------------------------------------------------------------------
# execute_script_file
# ---------------------------------------------------------------------------


class TestExecuteScriptFile:
    """Tests for execute_script_file tool handler."""

    @pytest.mark.asyncio
    async def test_success_with_stdout(self):
        result = ScriptResult(
            success=True,
            data=None,
            stdout="File script output\n",
            return_value="done",
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        resp = await execute_script_file(
            sm, bridge, "sess1", "/path/to/script.py"
        )

        assert resp["success"] is True
        assert resp["stdout"] == "File script output\n"
        assert resp["return_value"] == "done"
        assert resp["exception"] is None
        assert bridge.last_operation == "execute_script_file"
        assert bridge.last_params["script_path"] == "/path/to/script.py"
        assert bridge.last_params["timeout"] == 30

    @pytest.mark.asyncio
    async def test_exception_captured(self):
        result = ScriptResult(
            success=False,
            data={
                "exception": {
                    "type": "FileNotFoundError",
                    "message": "No such file",
                    "traceback": "Traceback ...\nFileNotFoundError: No such file",
                }
            },
            stdout="",
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        resp = await execute_script_file(
            sm, bridge, "sess1", "/missing/script.py"
        )

        assert resp["success"] is False
        assert resp["exception"]["type"] == "FileNotFoundError"
        assert resp["exception"]["message"] == "No such file"

    @pytest.mark.asyncio
    async def test_empty_path_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await execute_script_file(sm, bridge, "sess1", "")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "execute_script_file"

    @pytest.mark.asyncio
    async def test_whitespace_path_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await execute_script_file(sm, bridge, "sess1", "   ")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER

    @pytest.mark.asyncio
    async def test_zero_timeout_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await execute_script_file(
                sm, bridge, "sess1", "/path/to/script.py", timeout=0
            )
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "execute_script_file"

    @pytest.mark.asyncio
    async def test_negative_timeout_raises_invalid_parameter(self):
        result = ScriptResult(success=True, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await execute_script_file(
                sm, bridge, "sess1", "/path/to/script.py", timeout=-10
            )
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER

    @pytest.mark.asyncio
    async def test_custom_timeout_forwarded(self):
        result = ScriptResult(success=True, data=None, stdout="")
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await execute_script_file(
            sm, bridge, "sess1", "/path/to/script.py", timeout=120
        )
        assert bridge.last_params["timeout"] == 120

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data=None, stdout="")
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await execute_script_file(
            sm, bridge, "session_xyz", "/path/to/script.py"
        )
        assert sm.last_session_id == "session_xyz"

    @pytest.mark.asyncio
    async def test_default_timeout_is_30(self):
        result = ScriptResult(success=True, data=None, stdout="")
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await execute_script_file(sm, bridge, "sess1", "/path/to/script.py")
        assert bridge.last_params["timeout"] == 30

    @pytest.mark.asyncio
    async def test_exception_with_missing_fields_defaults(self):
        result = ScriptResult(
            success=False,
            data={"exception": {"type": "OSError"}},
            stdout="",
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        resp = await execute_script_file(
            sm, bridge, "sess1", "/path/to/script.py"
        )

        assert resp["exception"]["type"] == "OSError"
        assert resp["exception"]["message"] == ""
        assert resp["exception"]["traceback"] == ""
