"""Tests for template interpolation."""

import os

from devai.interpolate import interpolate, interpolate_context


class TestInterpolate:
    def test_var_template(self):
        result = interpolate("Hello ${var:name}", {"name": "DevAI"})
        assert result == "Hello DevAI"

    def test_env_template(self, monkeypatch):
        monkeypatch.setenv("DEVAI_TEST_VAR", "from-env")
        result = interpolate("Value: ${env:DEVAI_TEST_VAR}")
        assert result == "Value: from-env"

    def test_file_template(self, tmp_path):
        sample = tmp_path / "sample.txt"
        sample.write_text("file contents", encoding="utf-8")
        result = interpolate("${file:sample.txt}", base_path=tmp_path)
        assert result == "file contents"

    def test_legacy_context_key(self):
        result = interpolate("$code", {"code": "def foo(): pass"})
        assert result == "def foo(): pass"

    def test_interpolate_context(self):
        context = {"code": "${var:source}", "source": "x = 1"}
        resolved = interpolate_context(context)
        assert resolved["code"] == "x = 1"
        assert resolved["source"] == "x = 1"

    def test_missing_env_returns_empty(self):
        assert interpolate("${env:DEVAI_MISSING_VAR_XYZ}") == ""
