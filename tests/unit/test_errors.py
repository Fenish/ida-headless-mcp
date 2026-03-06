"""Unit tests for ida_headless_mcp.errors."""

from ida_headless_mcp.errors import ErrorCode, McpToolError


class TestErrorCode:
    """Tests for the ErrorCode enum."""

    def test_has_14_members(self):
        assert len(ErrorCode) == 14

    def test_is_str_enum(self):
        """Each member should be usable as a plain string."""
        for member in ErrorCode:
            assert isinstance(member, str)
            assert member == member.value

    def test_all_expected_codes_present(self):
        expected = {
            "INVALID_ADDRESS",
            "SESSION_NOT_FOUND",
            "NO_ACTIVE_SESSION",
            "IDA_NOT_FOUND",
            "DECOMPILER_UNAVAILABLE",
            "DECOMPILATION_FAILED",
            "FUNCTION_NOT_FOUND",
            "TYPE_CONFLICT",
            "ADDRESS_UNMAPPED",
            "SCRIPT_TIMEOUT",
            "IDA_CRASH",
            "IDA_TIMEOUT",
            "BATCH_NOT_FOUND",
            "INVALID_PARAMETER",
        }
        actual = {member.value for member in ErrorCode}
        assert actual == expected


class TestMcpToolError:
    """Tests for the McpToolError dataclass."""

    def test_fields(self):
        err = McpToolError(
            code=ErrorCode.SESSION_NOT_FOUND,
            message="No session found with ID 'abc123'",
            tool_name="decompile_function",
        )
        assert err.code == "SESSION_NOT_FOUND"
        assert err.message == "No session found with ID 'abc123'"
        assert err.tool_name == "decompile_function"

    def test_to_dict_structure(self):
        err = McpToolError(
            code=ErrorCode.SESSION_NOT_FOUND,
            message="No session found with ID 'abc123'",
            tool_name="decompile_function",
        )
        result = err.to_dict()
        assert "error" in result
        inner = result["error"]
        assert set(inner.keys()) == {"code", "message", "tool_name"}
        assert inner["code"] == "SESSION_NOT_FOUND"
        assert inner["message"] == "No session found with ID 'abc123'"
        assert inner["tool_name"] == "decompile_function"

    def test_to_dict_with_string_code(self):
        """code can be a raw string, not just an ErrorCode member."""
        err = McpToolError(
            code="CUSTOM_ERROR",
            message="something went wrong",
            tool_name="my_tool",
        )
        assert err.to_dict()["error"]["code"] == "CUSTOM_ERROR"
