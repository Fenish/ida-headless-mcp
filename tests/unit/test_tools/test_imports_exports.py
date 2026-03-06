"""Unit tests for import/export tool handlers.

Tests the tool handler functions in ``ida_headless_mcp.tools.imports_exports``
using a mock session manager that returns pre-configured ScriptResult data.
"""

from __future__ import annotations

import pytest

from ida_headless_mcp.errors import ErrorCode, McpToolError
from ida_headless_mcp.ida_bridge import ScriptResult
from ida_headless_mcp.models import ExportInfo, ImportInfo
from ida_headless_mcp.tools.imports_exports import list_exports, list_imports


# ---------------------------------------------------------------------------
# Helpers — lightweight mock session manager and bridge for tool tests
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
# list_imports
# ---------------------------------------------------------------------------


class TestListImports:
    """Tests for list_imports tool handler."""

    @pytest.mark.asyncio
    async def test_returns_all_imports(self):
        result = ScriptResult(
            success=True,
            data={
                "imports": [
                    {"library": "libc.so", "name": "printf", "ordinal": 0, "ea": "0x600000"},
                    {"library": "libc.so", "name": "malloc", "ordinal": 1, "ea": "0x600008"},
                    {"library": "libm.so", "name": "sin", "ordinal": 0, "ea": "0x600010"},
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        imports = await list_imports(sm, bridge, "sess1")

        assert len(imports) == 3
        assert isinstance(imports[0], ImportInfo)
        assert imports[0].library == "libc.so"
        assert imports[0].name == "printf"
        assert imports[0].ordinal == 0
        assert imports[0].ea == "0x600000"

    @pytest.mark.asyncio
    async def test_filter_by_library(self):
        result = ScriptResult(
            success=True,
            data={
                "imports": [
                    {"library": "libc.so", "name": "printf", "ordinal": 0, "ea": "0x600000"},
                    {"library": "libc.so", "name": "malloc", "ordinal": 1, "ea": "0x600008"},
                    {"library": "libm.so", "name": "sin", "ordinal": 0, "ea": "0x600010"},
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        imports = await list_imports(sm, bridge, "sess1", library="libc.so")

        assert len(imports) == 2
        assert all(imp.library == "libc.so" for imp in imports)

    @pytest.mark.asyncio
    async def test_filter_case_insensitive(self):
        result = ScriptResult(
            success=True,
            data={
                "imports": [
                    {"library": "KERNEL32.dll", "name": "CreateFileA", "ordinal": 0, "ea": "0x600000"},
                    {"library": "kernel32.dll", "name": "ReadFile", "ordinal": 1, "ea": "0x600008"},
                    {"library": "ntdll.dll", "name": "NtClose", "ordinal": 0, "ea": "0x600010"},
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        imports = await list_imports(sm, bridge, "sess1", library="kernel32.dll")

        assert len(imports) == 2
        assert imports[0].name == "CreateFileA"
        assert imports[1].name == "ReadFile"

    @pytest.mark.asyncio
    async def test_library_param_passed_to_bridge(self):
        result = ScriptResult(success=True, data={"imports": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_imports(sm, bridge, "sess1", library="libc.so")

        assert bridge.last_params == {"library": "libc.so"}

    @pytest.mark.asyncio
    async def test_no_library_param_when_none(self):
        result = ScriptResult(success=True, data={"imports": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_imports(sm, bridge, "sess1", library=None)

        assert "library" not in bridge.last_params

    @pytest.mark.asyncio
    async def test_empty_imports(self):
        result = ScriptResult(success=True, data={"imports": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        imports = await list_imports(sm, bridge, "sess1")
        assert imports == []

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(success=False, data={"error": {"message": "IDA error"}})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await list_imports(sm, bridge, "sess1")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "list_imports"

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data={"imports": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_imports(sm, bridge, "my_session_123")
        assert sm.last_session_id == "my_session_123"

    @pytest.mark.asyncio
    async def test_bridge_operation(self):
        result = ScriptResult(success=True, data={"imports": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_imports(sm, bridge, "sess1")
        assert bridge.last_operation == "list_imports"


# ---------------------------------------------------------------------------
# list_exports
# ---------------------------------------------------------------------------


class TestListExports:
    """Tests for list_exports tool handler."""

    @pytest.mark.asyncio
    async def test_returns_all_exports(self):
        result = ScriptResult(
            success=True,
            data={
                "exports": [
                    {"name": "main", "ordinal": 0, "ea": "0x401000"},
                    {"name": "init", "ordinal": 1, "ea": "0x401300"},
                ]
            },
        )
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        exports = await list_exports(sm, bridge, "sess1")

        assert len(exports) == 2
        assert isinstance(exports[0], ExportInfo)
        assert exports[0].name == "main"
        assert exports[0].ordinal == 0
        assert exports[0].ea == "0x401000"
        assert exports[1].name == "init"

    @pytest.mark.asyncio
    async def test_empty_exports(self):
        result = ScriptResult(success=True, data={"exports": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        exports = await list_exports(sm, bridge, "sess1")
        assert exports == []

    @pytest.mark.asyncio
    async def test_script_failure_raises_error(self):
        result = ScriptResult(success=False, data={"error": {"message": "IDA error"}})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await list_exports(sm, bridge, "sess1")
        assert exc_info.value.code == ErrorCode.INVALID_PARAMETER
        assert exc_info.value.tool_name == "list_exports"

    @pytest.mark.asyncio
    async def test_session_id_forwarded(self):
        result = ScriptResult(success=True, data={"exports": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_exports(sm, bridge, "my_session_456")
        assert sm.last_session_id == "my_session_456"

    @pytest.mark.asyncio
    async def test_bridge_operation_and_params(self):
        result = ScriptResult(success=True, data={"exports": []})
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        await list_exports(sm, bridge, "sess1")
        assert bridge.last_operation == "list_exports"
        assert bridge.last_params == {}

    @pytest.mark.asyncio
    async def test_script_failure_empty_data(self):
        result = ScriptResult(success=False, data=None)
        sm = FakeSessionManager(result)
        bridge = FakeBridge()

        with pytest.raises(McpToolError) as exc_info:
            await list_exports(sm, bridge, "sess1")
        assert exc_info.value.tool_name == "list_exports"
