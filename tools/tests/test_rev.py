"""Tests for ctf_rev.py, radare2 output parsing, JSON handling, and tool output."""

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ctf_rev


def _unwrap(tool):
    """Get underlying function from FastMCP tool wrapper (2.x .fn vs 3.x plain)."""
    return getattr(tool, "fn", tool)


# Access underlying functions from FastMCP tool wrappers
rev_functions = _unwrap(ctf_rev.rev_functions)
rev_decompile = _unwrap(ctf_rev.rev_decompile)
rev_strings_xrefs = _unwrap(ctf_rev.rev_strings_xrefs)


# -- _parse_r2_json tests ----------------------------------------------------


class TestParseR2Json:
    def test_valid_array(self):
        result = ctf_rev._parse_r2_json('[{"name": "main", "offset": 4096}]')
        assert result == [{"name": "main", "offset": 4096}]

    def test_valid_object(self):
        result = ctf_rev._parse_r2_json('{"key": "value"}')
        assert result == {"key": "value"}

    def test_with_warning_prefix(self):
        raw = 'WARNING: some r2 warning\n[{"name": "main"}]'
        result = ctf_rev._parse_r2_json(raw)
        assert result == [{"name": "main"}]

    def test_with_multiple_warning_lines(self):
        raw = "WARN: blah\nSome info\n\n[1, 2, 3]"
        result = ctf_rev._parse_r2_json(raw)
        assert result == [1, 2, 3]

    def test_empty_string(self):
        assert ctf_rev._parse_r2_json("") is None

    def test_whitespace_only(self):
        assert ctf_rev._parse_r2_json("   \n  ") is None

    def test_no_json(self):
        assert ctf_rev._parse_r2_json("just some text output") is None

    def test_invalid_json(self):
        assert ctf_rev._parse_r2_json("[{broken json") is None

    def test_object_before_array(self):
        result = ctf_rev._parse_r2_json('warn\n{"a": 1}')
        assert result == {"a": 1}

    def test_nested_json(self):
        raw = '[{"funcs": [{"name": "a"}, {"name": "b"}]}]'
        result = ctf_rev._parse_r2_json(raw)
        assert len(result) == 1
        assert len(result[0]["funcs"]) == 2


# -- _r2_cmd tests ----------------------------------------------------------─


class TestR2Cmd:
    def test_returns_dict_with_stdout_stderr_returncode(self):
        # Even if r2 is not installed, run_tool returns a structured dict
        result = ctf_rev._r2_cmd("/dev/null", ["?V"])
        assert "stdout" in result
        assert "stderr" in result
        assert "returncode" in result


# -- rev_functions tool tests ------------------------------------------------─


class TestR2Functions:
    def test_nonexistent_file(self):
        result = json.loads(rev_functions("/nonexistent/binary/xyz"))
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_returns_valid_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            raw = rev_functions(path)
            parsed = json.loads(raw)
            assert "path" in parsed or "error" in parsed
        finally:
            os.unlink(path)

    def test_symlink_resolves(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"data")
            real_path = f.name
        link_path = real_path + ".link"
        try:
            os.symlink(real_path, link_path)
            result = json.loads(rev_functions(link_path))
            if "path" in result:
                assert result["path"] == os.path.realpath(link_path)
        finally:
            os.unlink(real_path)
            if os.path.exists(link_path):
                os.unlink(link_path)


# -- rev_decompile tool tests ------------------------------------------------


class TestR2Decompile:
    def test_nonexistent_file(self):
        result = json.loads(rev_decompile("/nonexistent/binary/xyz"))
        assert "error" in result

    def test_returns_valid_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            raw = rev_decompile(path)
            parsed = json.loads(raw)
            assert isinstance(parsed, dict)
        finally:
            os.unlink(path)

    def test_custom_function(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(rev_decompile(path, function="vuln"))
            # Will likely fail to decompile a fake ELF, but should have proper structure
            assert "function" in result or "error" in result
        finally:
            os.unlink(path)

    def test_hex_address_function(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(rev_decompile(path, function="0x401000"))
            assert isinstance(result, dict)
        finally:
            os.unlink(path)

    def test_decompiler_param(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            for dec in ["auto", "r2ghidra", "r2dec"]:
                raw = rev_decompile(path, decompiler=dec)
                parsed = json.loads(raw)
                assert isinstance(parsed, dict)
        finally:
            os.unlink(path)


# -- rev_strings_xrefs tool tests --------------------------------------------


class TestR2StringsXrefs:
    def test_nonexistent_file(self):
        result = json.loads(rev_strings_xrefs("/nonexistent/binary/xyz"))
        assert "error" in result

    def test_returns_valid_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            raw = rev_strings_xrefs(path)
            parsed = json.loads(raw)
            assert isinstance(parsed, dict)
        finally:
            os.unlink(path)

    def test_filter_param(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(rev_strings_xrefs(path, filter="flag|password"))
            # r2 may not be available in CI, accept either valid result or error
            if "error" not in result:
                assert result["filter"] == "flag|password"
        finally:
            os.unlink(path)


# -- Integration: all tools return valid JSON --------------------------------


class TestJsonOutput:
    """Every tool must return valid JSON regardless of input."""

    def test_r2_functions_always_json(self):
        raw = rev_functions("/dev/null")
        json.loads(raw)

    def test_r2_decompile_always_json(self):
        raw = rev_decompile("/dev/null")
        json.loads(raw)

    def test_r2_strings_xrefs_always_json(self):
        raw = rev_strings_xrefs("/dev/null")
        json.loads(raw)


# -- TestRevMocked, mock-based r2 output parsing tests ----------------------


class TestRevMocked:
    def test_functions_with_callrefs(self):
        """Mock r2 function list with call references."""
        from unittest.mock import patch

        r2_output = json.dumps(
            [
                {
                    "name": "main",
                    "offset": 0x401000,
                    "size": 100,
                    "nbbs": 5,
                    "callrefs": [{"addr": 0x401100, "type": "CALL"}],
                },
                {"name": "helper", "offset": 0x401100, "size": 50, "nbbs": 2},
            ]
        )
        mock_result = {"stdout": r2_output, "stderr": "", "returncode": 0}

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            with patch("ctf_rev.run_tool", return_value=mock_result):
                result = json.loads(rev_functions(path))
                assert result["function_count"] == 2
                assert result["functions"][0]["name"] == "main"
                assert len(result["functions"][0]["calls"]) == 1
                assert result["functions"][0]["calls"][0]["address"] == "0x401100"
        finally:
            os.unlink(path)

    def test_decompile_success(self):
        """Mock r2 successful decompilation."""
        from unittest.mock import patch

        decompiled_code = (
            "void main(void) {\n  char buf[64];\n  gets(buf);\n  return;\n}"
        )
        call_count = [0]

        def mock_run(cmd, timeout=None, input_data=None, cwd=None):
            call_count[0] += 1
            if "pdg" in cmd[-2]:  # decompile command
                return {"stdout": decompiled_code, "stderr": "", "returncode": 0}
            if "?v" in cmd[-2]:  # address query
                return {"stdout": "0x401000", "stderr": "", "returncode": 0}
            return {"stdout": "", "stderr": "", "returncode": 0}

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            with patch("ctf_rev.run_tool", side_effect=mock_run):
                result = json.loads(rev_decompile(path))
                assert result["decompiler"] == "r2ghidra"
                assert "gets(buf)" in result["code"]
        finally:
            os.unlink(path)

    def test_strings_xrefs_parsing(self):
        """Mock r2 strings with cross-references."""
        from unittest.mock import patch

        call_count = [0]

        def mock_run(cmd, timeout=None, input_data=None, cwd=None):
            call_count[0] += 1
            cmd_str = cmd[-2] if len(cmd) > 2 else ""
            if "izj" in cmd_str:
                return {
                    "stdout": json.dumps(
                        [
                            {
                                "string": "Enter password:",
                                "vaddr": 0x402000,
                                "section": ".rodata",
                                "type": "ascii",
                                "size": 15,
                            },
                            {
                                "string": "flag{test}",
                                "vaddr": 0x402020,
                                "section": ".rodata",
                                "type": "ascii",
                                "size": 10,
                            },
                        ]
                    ),
                    "stderr": "",
                    "returncode": 0,
                }
            if "axtj" in cmd_str:
                return {
                    "stdout": json.dumps(
                        [
                            {
                                "from": 0x401050,
                                "addr": 0x402000,
                                "type": "DATA",
                                "fcn_name": "main",
                                "opcode": "lea rdi, [0x402000]",
                            }
                        ]
                    ),
                    "stderr": "",
                    "returncode": 0,
                }
            return {"stdout": "", "stderr": "", "returncode": 0}

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            with patch("ctf_rev.run_tool", side_effect=mock_run):
                result = json.loads(rev_strings_xrefs(path))
                assert result["count"] == 2
                assert result["strings"][0]["string"] == "Enter password:"
        finally:
            os.unlink(path)
