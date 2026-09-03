"""Tests for SphinxAnalyzer."""

from pathlib import Path

from devai.sphinx_analyzer import SphinxAnalyzer, SphinxFinding


INSECURE_CONF = """\
import sys
import os
import subprocess

project = "Demo Docs"
release = "1.0.0"
api_key = "sk-live-secret-token-12345"

sys.path.insert(0, "../outside")
sys.path.append("/tmp/untrusted")

extensions = [
    "sphinx.ext.autodoc",
    "sphinxcontrib.programoutput",
    "sphinx.ext.viewcode",
]

nitpicky = False

html_baseurl = "http://insecure.example.com/docs/"
intersphinx_mapping = {
    "python": ("http://evil.example.com/python", None),
}

html_js_files = [
    "https://cdn.example.com/jquery.min.js",
]

autodoc_mock_imports = ["*"]
autodoc_default_options = {"members": True}

linkcheck_ignore = ["http://*", "https://*"]

eval("print('bad')")
subprocess.call(["echo", "bad"])
"""

HARDENED_CONF = """\
import os

project = "Demo Docs"
copyright = "2026, Demo"
author = "Demo"
release = "1.0.0"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
]

templates_path = ["_templates"]
exclude_patterns = ["_build"]

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]

nitpicky = True

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

html_js_files = []
"""


class TestSphinxAnalyzer:
    def test_detects_insecure_conf_py(self, tmp_path: Path):
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "conf.py").write_text(INSECURE_CONF, encoding="utf-8")
        analyzer = SphinxAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "unsafe_sys_path" in kinds
        assert "nitpicky_false" in kinds
        assert "insecure_http" in kinds
        assert "external_script" in kinds
        assert "mock_imports_wildcard" in kinds
        assert "eval_exec" in kinds
        assert "shell_execution" in kinds
        assert "interactive_extension" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_conf_scores_well(self, tmp_path: Path):
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "conf.py").write_text(HARDENED_CONF, encoding="utf-8")
        analyzer = SphinxAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_doc_conf_also_scanned(self, tmp_path: Path):
        doc = tmp_path / "doc"
        doc.mkdir()
        (doc / "conf.py").write_text("project = 'x'\nextensions = []\nnitpicky = False\n", encoding="utf-8")
        analyzer = SphinxAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(analyzer.config_files()) == 1
        assert any(f.kind == "nitpicky_false" for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = SphinxAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_ignores_non_sphinx_conf(self, tmp_path: Path):
        (tmp_path / "conf.py").write_text("DEBUG = True\nDATABASE_URL = 'sqlite:///db'\n", encoding="utf-8")
        analyzer = SphinxAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.stats.config_files == 0

    def test_generate_hardened_template(self):
        template = SphinxAnalyzer(".").generate_hardened_template()
        assert "nitpicky = True" in template
        assert "https://docs.python.org/3" in template

    def test_finding_format(self):
        finding = SphinxFinding(
            kind="nitpicky_false",
            severity="medium",
            message="test message",
            path="docs/conf.py",
            lineno=2,
        )
        assert "medium" in finding.format()
        assert "docs/conf.py:2" in finding.format()

    def test_to_context(self, tmp_path: Path):
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "conf.py").write_text("project = 'x'\nextensions = []\nnitpicky = False\n", encoding="utf-8")
        analyzer = SphinxAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Sphinx analysis:" in context
        assert "nitpicky" in context

    def test_summary(self, tmp_path: Path):
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "conf.py").write_text("project = 'x'\nextensions = []\nnitpicky = False\n", encoding="utf-8")
        analyzer = SphinxAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "Sphinx configs:" in summary
        assert "1 file(s)" in summary

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "conf.py").write_text(
            "project = 'x'\nextensions = []\nnitpicky = False\nsys.path.insert(0, '../outside')\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        sphinx = next(c for c in report.categories if c.name == "sphinx")
        assert sphinx.score < 100.0
        assert sphinx.details.get("findings", 0) > 0
