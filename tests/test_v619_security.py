"""Tests for v6.19.0 security analyzers."""

from pathlib import Path

from devai import SecurityScanner, TemplateAutoescapeAnalyzer


class TestTemplateAutoescapeAnalyzer:
    def test_clean_environment_with_autoescape(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from jinja2 import Environment\n"
            "Environment(autoescape=True)\n",
            encoding="utf-8",
        )
        findings = TemplateAutoescapeAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_clean_environment_with_select_autoescape(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from jinja2 import Environment, select_autoescape\n"
            "Environment(autoescape=select_autoescape(['html', 'xml']))\n",
            encoding="utf-8",
        )
        findings = TemplateAutoescapeAnalyzer(str(tmp_path)).analyze()
        assert not findings

    def test_detects_missing_autoescape(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from jinja2 import Environment\n"
            "Environment()\n",
            encoding="utf-8",
        )
        findings = TemplateAutoescapeAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "missing_template_autoescape" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_disabled_autoescape(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "import jinja2\n"
            "jinja2.Environment(autoescape=False)\n",
            encoding="utf-8",
        )
        findings = TemplateAutoescapeAnalyzer(str(tmp_path)).analyze()
        assert any(f.pattern == "disabled_template_autoescape" for f in findings)

    def test_detects_imported_environment_without_autoescape(self, tmp_path: Path):
        (tmp_path / "views.py").write_text(
            "from jinja2 import Environment\n"
            "env = Environment(loader=None)\n",
            encoding="utf-8",
        )
        findings = TemplateAutoescapeAnalyzer(str(tmp_path)).analyze()
        assert len(findings) == 1


class TestTemplateAutoescapeScanner:
    def test_integrated_in_security_scanner(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from jinja2 import Environment\n"
            "Environment()\n",
            encoding="utf-8",
        )
        report = SecurityScanner(str(tmp_path), checks=("template_autoescape",)).scan()
        assert report.total_findings >= 1
        assert any(cat.name == "template_autoescape" for cat in report.categories)
