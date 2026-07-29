"""Tests for template interpolation."""

from pathlib import Path

from devai.interpolate import interpolate, interpolate_dict


class TestInterpolate:
    def test_var(self):
        result = interpolate("Hello ${name}", {"name": "world"})
        assert result == "Hello world"

    def test_var_prefix(self):
        result = interpolate("Hello ${var:name}", {"name": "dev"})
        assert result == "Hello dev"

    def test_env(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR", "from-env")
        result = interpolate("Value: ${env:TEST_VAR}")
        assert result == "Value: from-env"

    def test_file(self, tmp_path: Path):
        file_path = tmp_path / "data.txt"
        file_path.write_text("file-content")
        result = interpolate("Data: ${file:data.txt}", base_path=tmp_path)
        assert result == "Data: file-content"

    def test_interpolate_dict(self):
        result = interpolate_dict({"greet": "Hi ${name}"}, {"name": "there"})
        assert result["greet"] == "Hi there"
