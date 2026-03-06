"""Unit tests for ida_headless_mcp.ida_bridge.

Tests:
1. Script generation for each operation produces syntactically valid Python (ast.parse)
2. Generated scripts include the standard template (try/except, JSON result writing, idc.qexit(0))
3. parse_result() with success and error JSON files
4. Unknown operations raise ValueError

Validates: Requirements 17.1, 17.5
"""

from __future__ import annotations

import ast
import json
import textwrap
from pathlib import Path

import pytest

from ida_headless_mcp.ida_bridge import IdaBridge, ScriptResult, _OPERATION_BUILDERS


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def bridge() -> IdaBridge:
    return IdaBridge()


# Minimal valid params for every operation so build_script can generate code.
OPERATION_PARAMS: dict[str, dict] = {
    "list_functions": {},
    "get_function_details": {"ea": "0x401000"},
    "rename_function": {"ea": "0x401000", "new_name": "my_func"},
    "create_function": {"ea": "0x401000"},
    "delete_function": {"ea": "0x401000"},
    "decompile": {"ea": "0x401000"},
    "disassemble_at": {"ea": "0x401000"},
    "disassemble_range": {"start_ea": "0x401000", "end_ea": "0x402000"},
    "disassemble_function": {"ea": "0x401000"},
    "get_xrefs_to": {"ea": "0x401000"},
    "get_xrefs_from": {"ea": "0x401000"},
    "get_function_xrefs": {"ea": "0x401000"},
    "list_strings": {},
    "list_segments": {},
    "get_segment": {"name_or_ea": ".text"},
    "get_segment_at": {"ea": "0x401000"},
    "list_imports": {},
    "list_exports": {},
    "list_types": {},
    "create_struct": {"name": "my_struct", "fields": [{"name": "x", "type_str": "int", "offset": 0}]},
    "add_struct_field": {"struct_name": "my_struct", "field": {"name": "y", "type_str": "int", "offset": 4}},
    "apply_type": {"ea": "0x401000", "type_str": "int"},
    "delete_type": {"name": "my_struct"},
    "parse_header": {"header_text": "typedef int DWORD;"},
    "set_comment": {"ea": "0x401000", "comment": "entry point"},
    "get_comments": {"ea": "0x401000"},
    "get_comments_range": {"start_ea": "0x401000", "end_ea": "0x402000"},
    "read_bytes": {"ea": "0x401000", "length": 16},
    "patch_bytes": {"ea": "0x401000", "hex_values": "9090"},
    "assemble_and_patch": {"ea": "0x401000", "assembly": "nop"},
    "list_patches": {},
    "search_bytes": {"pattern": "90 90 ??"},
    "search_text": {"text": "hello"},
    "search_immediate": {"value": 42},
    "apply_signature": {"sig_file": "libc.sig"},
    "list_applied_signatures": {},
    "list_available_signatures": {},
    "add_bookmark": {"ea": "0x401000", "description": "interesting"},
    "list_bookmarks": {},
    "delete_bookmark": {"ea": "0x401000"},
    "execute_script": {"script": "print('hello')"},
    "execute_script_file": {"script_path": "/tmp/test.py"},
    "list_enums": {},
    "create_enum": {"name": "Color", "members": [{"name": "RED", "value": 0}]},
    "add_enum_member": {"enum_name": "Color", "member_name": "BLUE", "value": 2},
    "apply_enum": {"ea": "0x401000", "operand": 0, "enum_name": "Color"},
    "list_names": {},
    "rename_location": {"ea": "0x401000", "new_name": "main"},
    "get_data_type": {"ea": "0x401000"},
    "set_data_type": {"ea": "0x401000", "type_str": "dword"},
    "get_callers": {"ea": "0x401000"},
    "get_callees": {"ea": "0x401000"},
    "get_call_graph": {"ea": "0x401000", "depth": 2},
}


# ---------------------------------------------------------------------------
# 1. Script generation produces syntactically valid Python for every operation
# ---------------------------------------------------------------------------

class TestScriptSyntaxValidity:
    """Every generated script must be parseable by ast.parse()."""

    @pytest.mark.parametrize("operation", sorted(_OPERATION_BUILDERS.keys()))
    def test_generated_script_is_valid_python(self, bridge: IdaBridge, operation: str):
        params = OPERATION_PARAMS[operation]
        script = bridge.build_script(operation, params, result_path="/tmp/result.json")
        # ast.parse raises SyntaxError if the script is not valid Python
        ast.parse(script)


# ---------------------------------------------------------------------------
# 2. Script template structure (try/except, JSON writing, idc.qexit)
# ---------------------------------------------------------------------------

class TestScriptTemplateStructure:
    """Generated scripts must include the standard template elements."""

    @pytest.mark.parametrize("operation", sorted(_OPERATION_BUILDERS.keys()))
    def test_script_contains_try_except(self, bridge: IdaBridge, operation: str):
        params = OPERATION_PARAMS[operation]
        script = bridge.build_script(operation, params, result_path="/tmp/result.json")
        assert "try:" in script
        assert "except Exception as e:" in script

    @pytest.mark.parametrize("operation", sorted(_OPERATION_BUILDERS.keys()))
    def test_script_writes_json_result(self, bridge: IdaBridge, operation: str):
        params = OPERATION_PARAMS[operation]
        script = bridge.build_script(operation, params, result_path="/tmp/result.json")
        assert "json.dump(result, f)" in script

    @pytest.mark.parametrize("operation", sorted(_OPERATION_BUILDERS.keys()))
    def test_script_calls_qexit(self, bridge: IdaBridge, operation: str):
        params = OPERATION_PARAMS[operation]
        script = bridge.build_script(operation, params, result_path="/tmp/result.json")
        assert "idc.qexit(0)" in script

    @pytest.mark.parametrize("operation", sorted(_OPERATION_BUILDERS.keys()))
    def test_script_imports_required_modules(self, bridge: IdaBridge, operation: str):
        """Validates: Requirement 17.5 — script environment has idaapi, idautils, idc, ida_funcs."""
        params = OPERATION_PARAMS[operation]
        script = bridge.build_script(operation, params, result_path="/tmp/result.json")
        assert "import idaapi" in script
        assert "import idautils" in script
        assert "import idc" in script
        assert "import ida_funcs" in script

    @pytest.mark.parametrize("operation", sorted(_OPERATION_BUILDERS.keys()))
    def test_script_sets_result_path(self, bridge: IdaBridge, operation: str):
        params = OPERATION_PARAMS[operation]
        result_path = "/tmp/my_result.json"
        script = bridge.build_script(operation, params, result_path=result_path)
        assert f"RESULT_PATH = {result_path!r}" in script

    def test_script_uses_default_result_path(self, bridge: IdaBridge):
        script = bridge.build_script("list_functions", {})
        assert "RESULT_PATH = 'result.json'" in script

    @pytest.mark.parametrize("operation", sorted(_OPERATION_BUILDERS.keys()))
    def test_script_captures_traceback_on_error(self, bridge: IdaBridge, operation: str):
        params = OPERATION_PARAMS[operation]
        script = bridge.build_script(operation, params, result_path="/tmp/result.json")
        assert "traceback.format_exc()" in script

    @pytest.mark.parametrize("operation", sorted(_OPERATION_BUILDERS.keys()))
    def test_script_defines_main_function(self, bridge: IdaBridge, operation: str):
        params = OPERATION_PARAMS[operation]
        script = bridge.build_script(operation, params, result_path="/tmp/result.json")
        assert "def main():" in script
        assert "\nmain()\n" in script


# ---------------------------------------------------------------------------
# 3. parse_result() with success and error JSON files
# ---------------------------------------------------------------------------

class TestParseResult:
    """Test parse_result reads JSON result files correctly."""

    def test_parse_success_result(self, bridge: IdaBridge, tmp_path: Path):
        result_file = tmp_path / "result.json"
        result_file.write_text(json.dumps({
            "success": True,
            "data": {"functions": [{"ea": "0x401000", "name": "main"}]},
            "stdout": "analysis complete",
            "stderr": "",
            "return_value": 42,
        }))
        result = bridge.parse_result(result_file)
        assert isinstance(result, ScriptResult)
        assert result.success is True
        assert result.data == {"functions": [{"ea": "0x401000", "name": "main"}]}
        assert result.stdout == "analysis complete"
        assert result.stderr == ""
        assert result.return_value == 42

    def test_parse_error_result(self, bridge: IdaBridge, tmp_path: Path):
        result_file = tmp_path / "result.json"
        result_file.write_text(json.dumps({
            "success": False,
            "error": {
                "type": "ValueError",
                "message": "No function at 0x401000",
                "traceback": "Traceback ...",
            },
        }))
        result = bridge.parse_result(result_file)
        assert result.success is False
        assert result.data is None
        assert result.stdout == ""
        assert result.stderr == ""

    def test_parse_minimal_success(self, bridge: IdaBridge, tmp_path: Path):
        """A result file with only 'success' should still parse."""
        result_file = tmp_path / "result.json"
        result_file.write_text(json.dumps({"success": True}))
        result = bridge.parse_result(result_file)
        assert result.success is True
        assert result.data is None
        assert result.stdout == ""
        assert result.return_value is None

    def test_parse_result_missing_file_raises(self, bridge: IdaBridge, tmp_path: Path):
        missing = tmp_path / "nonexistent.json"
        with pytest.raises(FileNotFoundError):
            bridge.parse_result(missing)

    def test_parse_result_invalid_json_raises(self, bridge: IdaBridge, tmp_path: Path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not valid json {{{")
        with pytest.raises(json.JSONDecodeError):
            bridge.parse_result(bad_file)

    def test_parse_result_defaults_success_to_false(self, bridge: IdaBridge, tmp_path: Path):
        """If 'success' key is missing, it should default to False."""
        result_file = tmp_path / "result.json"
        result_file.write_text(json.dumps({"data": {"some": "value"}}))
        result = bridge.parse_result(result_file)
        assert result.success is False
        assert result.data == {"some": "value"}

    def test_parse_result_with_all_fields(self, bridge: IdaBridge, tmp_path: Path):
        result_file = tmp_path / "result.json"
        result_file.write_text(json.dumps({
            "success": True,
            "data": [1, 2, 3],
            "stdout": "line1\nline2",
            "stderr": "warning",
            "return_value": {"key": "val"},
        }))
        result = bridge.parse_result(result_file)
        assert result.success is True
        assert result.data == [1, 2, 3]
        assert result.stdout == "line1\nline2"
        assert result.stderr == "warning"
        assert result.return_value == {"key": "val"}


# ---------------------------------------------------------------------------
# 4. Unknown operations raise ValueError
# ---------------------------------------------------------------------------

class TestUnknownOperation:
    """build_script must raise ValueError for unrecognised operations."""

    def test_unknown_operation_raises(self, bridge: IdaBridge):
        with pytest.raises(ValueError, match="Unknown operation: bogus_op"):
            bridge.build_script("bogus_op", {})

    def test_empty_operation_raises(self, bridge: IdaBridge):
        with pytest.raises(ValueError, match="Unknown operation: "):
            bridge.build_script("", {})


# ---------------------------------------------------------------------------
# 5. Coverage check — OPERATION_PARAMS covers all registered operations
# ---------------------------------------------------------------------------

class TestOperationCoverage:
    """Ensure our test params dict covers every registered operation."""

    def test_all_operations_have_params(self):
        missing = set(_OPERATION_BUILDERS.keys()) - set(OPERATION_PARAMS.keys())
        assert not missing, f"Missing test params for operations: {missing}"
