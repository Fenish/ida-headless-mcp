"""Unit tests for the IDAPython command loop script."""

from __future__ import annotations

import json
import os
import textwrap
import time

import pytest

from ida_headless_mcp.scripts.command_loop import (
    _create_ready_sentinel,
    _execute_script,
    _get_command_dir,
    _poll_once,
    _write_result,
)


# ---------------------------------------------------------------------------
# _get_command_dir
# ---------------------------------------------------------------------------


class TestGetCommandDir:
    """Tests for environment variable resolution."""

    def test_missing_env_var_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("IDA_MCP_COMMAND_DIR", raising=False)
        with pytest.raises(RuntimeError, match="not set"):
            _get_command_dir()

    def test_nonexistent_dir_raises(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        bad_path = str(tmp_path / "does_not_exist")
        monkeypatch.setenv("IDA_MCP_COMMAND_DIR", bad_path)
        with pytest.raises(RuntimeError, match="non-existent"):
            _get_command_dir()

    def test_valid_dir_returns_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        monkeypatch.setenv("IDA_MCP_COMMAND_DIR", str(tmp_path))
        assert _get_command_dir() == str(tmp_path)


# ---------------------------------------------------------------------------
# _write_result
# ---------------------------------------------------------------------------


class TestWriteResult:
    def test_writes_json(self, tmp_path) -> None:
        result = {"success": True, "data": {"count": 42}}
        _write_result(str(tmp_path), result)
        with open(tmp_path / "result.json") as fh:
            assert json.load(fh) == result

    def test_overwrites_existing(self, tmp_path) -> None:
        _write_result(str(tmp_path), {"old": True})
        _write_result(str(tmp_path), {"new": True})
        with open(tmp_path / "result.json") as fh:
            assert json.load(fh) == {"new": True}


# ---------------------------------------------------------------------------
# _create_ready_sentinel
# ---------------------------------------------------------------------------


class TestCreateReadySentinel:
    def test_creates_ready_file(self, tmp_path) -> None:
        _create_ready_sentinel(str(tmp_path))
        assert (tmp_path / "ready").exists()

    def test_ready_file_is_empty(self, tmp_path) -> None:
        _create_ready_sentinel(str(tmp_path))
        assert (tmp_path / "ready").read_text() == ""


# ---------------------------------------------------------------------------
# _execute_script
# ---------------------------------------------------------------------------


class TestExecuteScript:
    def test_successful_script_that_writes_result(self, tmp_path) -> None:
        """Script writes its own result.json — loop should not overwrite."""
        script = textwrap.dedent(f"""\
            import json
            result = {{"success": True, "data": {{"answer": 42}}}}
            with open(r"{tmp_path / 'result.json'}", "w") as f:
                json.dump(result, f)
        """)
        _execute_script(script, str(tmp_path))
        with open(tmp_path / "result.json") as fh:
            data = json.load(fh)
        assert data["success"] is True
        assert data["data"]["answer"] == 42

    def test_exception_writes_error_result(self, tmp_path) -> None:
        """Script raises — loop should write an error result."""
        script = "raise ValueError('test error')"
        _execute_script(script, str(tmp_path))
        with open(tmp_path / "result.json") as fh:
            data = json.load(fh)
        assert data["success"] is False
        assert data["error"]["type"] == "ValueError"
        assert data["error"]["message"] == "test error"
        assert "traceback" in data["error"]

    def test_exception_does_not_overwrite_existing_result(self, tmp_path) -> None:
        """If script wrote result.json before raising, keep the script's result."""
        script = textwrap.dedent(f"""\
            import json
            with open(r"{tmp_path / 'result.json'}", "w") as f:
                json.dump({{"success": True, "data": "partial"}}, f)
            raise RuntimeError("late failure")
        """)
        _execute_script(script, str(tmp_path))
        with open(tmp_path / "result.json") as fh:
            data = json.load(fh)
        # The script's own result should be preserved.
        assert data["success"] is True
        assert data["data"] == "partial"

    def test_syntax_error_writes_error_result(self, tmp_path) -> None:
        script = "def bad syntax here"
        _execute_script(script, str(tmp_path))
        with open(tmp_path / "result.json") as fh:
            data = json.load(fh)
        assert data["success"] is False
        assert data["error"]["type"] == "SyntaxError"

    def test_script_has_main_namespace(self, tmp_path) -> None:
        """Script should see __name__ == '__main__'."""
        script = textwrap.dedent(f"""\
            import json
            with open(r"{tmp_path / 'result.json'}", "w") as f:
                json.dump({{"success": True, "data": {{"name": __name__}}}}, f)
        """)
        _execute_script(script, str(tmp_path))
        with open(tmp_path / "result.json") as fh:
            data = json.load(fh)
        assert data["data"]["name"] == "__main__"


# ---------------------------------------------------------------------------
# _poll_once
# ---------------------------------------------------------------------------


class TestPollOnce:
    def test_no_script_returns_false(self, tmp_path) -> None:
        assert _poll_once(str(tmp_path)) is False

    def test_script_found_returns_true(self, tmp_path) -> None:
        (tmp_path / "script.py").write_text("x = 1")
        assert _poll_once(str(tmp_path)) is True

    def test_script_removed_after_execution(self, tmp_path) -> None:
        (tmp_path / "script.py").write_text("x = 1")
        _poll_once(str(tmp_path))
        assert not (tmp_path / "script.py").exists()

    def test_ready_sentinel_created(self, tmp_path) -> None:
        (tmp_path / "script.py").write_text("x = 1")
        _poll_once(str(tmp_path))
        assert (tmp_path / "ready").exists()

    def test_ready_sentinel_created_even_on_error(self, tmp_path) -> None:
        (tmp_path / "script.py").write_text("raise Exception('boom')")
        _poll_once(str(tmp_path))
        assert (tmp_path / "ready").exists()
        with open(tmp_path / "result.json") as fh:
            data = json.load(fh)
        assert data["success"] is False

    def test_successful_script_writes_result_and_ready(self, tmp_path) -> None:
        script = textwrap.dedent(f"""\
            import json
            with open(r"{tmp_path / 'result.json'}", "w") as f:
                json.dump({{"success": True, "data": "hello"}}, f)
        """)
        (tmp_path / "script.py").write_text(script)
        _poll_once(str(tmp_path))
        assert (tmp_path / "ready").exists()
        assert not (tmp_path / "script.py").exists()
        with open(tmp_path / "result.json") as fh:
            data = json.load(fh)
        assert data["success"] is True
