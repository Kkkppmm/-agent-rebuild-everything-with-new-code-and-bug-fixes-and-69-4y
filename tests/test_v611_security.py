"""Tests for v6.11.0 security analyzers."""

from pathlib import Path

from devai import DynamicImportAnalyzer, SecurityScanner


class TestDynamicImportAnalyzer:
    def test_clean_literal_import(self, tmp_path: Path):
        (tmp_path / "safe.py").write_text(
            "import importlib\n\n"
            "def load_plugin():\n"
            "    return importlib.import_module('myapp.plugins.default')\n",
            encoding="utf-8",
        )
        findings = DynamicImportAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_dunder_import(self, tmp_path: Path):
        (tmp_path / "loader.py").write_text(
            "def load(name):\n"
            "    return __import__(name)\n",
            encoding="utf-8",
        )
        findings = DynamicImportAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "dunder_import" for f in findings)

    def test_detects_importlib_import_module(self, tmp_path: Path):
        (tmp_path / "plugin.py").write_text(
            "import importlib\n\n"
            "def load_plugin(name: str):\n"
            "    return importlib.import_module(name)\n",
            encoding="utf-8",
        )
        findings = DynamicImportAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "importlib_import_module" for f in findings)

    def test_detects_spec_from_file_location(self, tmp_path: Path):
        (tmp_path / "ext.py").write_text(
            "import importlib.util\n\n"
            "def load_from(path, name):\n"
            "    spec = importlib.util.spec_from_file_location(name, path)\n"
            "    return spec\n",
            encoding="utf-8",
        )
        findings = DynamicImportAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "spec_from_file_location" for f in findings)

    def test_allows_literal_spec_from_file_location(self, tmp_path: Path):
        (tmp_path / "fixed.py").write_text(
            "import importlib.util\n\n"
            "def load():\n"
            "    return importlib.util.spec_from_file_location('m', '/app/m.py')\n",
            encoding="utf-8",
        )
        findings = DynamicImportAnalyzer(str(tmp_path)).analyze()
        assert not any(f.pattern == "spec_from_file_location" for f in findings)


class TestDynamicImportSecurityScanner:
    def test_integrated_in_security_scanner(self, tmp_path: Path):
        (tmp_path / "bad.py").write_text(
            "def load(name):\n    return __import__(name)\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("dynamic_import",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "dynamic_import" for cat in report.categories)
