"""Tests for SphinxAnalyzer."""

from pathlib import Path

from devai.sphinx_analyzer import SphinxAnalyzer


GOOD_CONF = """\
project = "My Project"
copyright = "2026, Org"
author = "Org"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

html_theme = "sphinx_rtd_theme"
"""


class TestSphinxAnalyzer:
    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = SphinxAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0
        assert "no conf.py" in analyzer.summary().lower()

    def test_clean_conf(self, tmp_path: Path):
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "conf.py").write_text(GOOD_CONF, encoding="utf-8")
        analyzer = SphinxAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not findings
        stats = analyzer.stats
        assert stats.config_files == 1
        assert stats.extensions >= 2
        assert analyzer.health_score() == 100.0

    def test_detects_dangerous_exec(self, tmp_path: Path):
        docs = tmp_path / "docs"
        docs.mkdir()
        conf = GOOD_CONF + "\nos.system('rm -rf /')\n"
        (docs / "conf.py").write_text(conf, encoding="utf-8")
        findings = SphinxAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "dangerous_exec" for f in findings)

    def test_detects_secret_in_config(self, tmp_path: Path):
        docs = tmp_path / "docs"
        docs.mkdir()
        conf = GOOD_CONF + "\napi_key = 'sk-live-secret12345'\n"
        (docs / "conf.py").write_text(conf, encoding="utf-8")
        findings = SphinxAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "secret_in_config" for f in findings)

    def test_detects_missing_intersphinx(self, tmp_path: Path):
        docs = tmp_path / "docs"
        docs.mkdir()
        conf = (
            "project = 'Docs'\n"
            "extensions = ['sphinx.ext.autodoc']\n"
        )
        (docs / "conf.py").write_text(conf, encoding="utf-8")
        findings = SphinxAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "missing_intersphinx" for f in findings)

    def test_detects_http_base_url(self, tmp_path: Path):
        docs = tmp_path / "docs"
        docs.mkdir()
        conf = GOOD_CONF + "\nhtml_baseurl = 'http://example.com/docs/'\n"
        (docs / "conf.py").write_text(conf, encoding="utf-8")
        findings = SphinxAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "http_base_url" for f in findings)

    def test_ignores_non_docs_conf(self, tmp_path: Path):
        (tmp_path / "conf.py").write_text("project = 'Not Sphinx'\n", encoding="utf-8")
        findings = SphinxAnalyzer(str(tmp_path)).analyze()
        assert findings == []

    def test_generate_template(self, tmp_path: Path):
        template = SphinxAnalyzer(str(tmp_path)).generate_hardened_template()
        assert "intersphinx_mapping" in template
        assert "os.environ" in template

    def test_to_context(self, tmp_path: Path):
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "conf.py").write_text(GOOD_CONF, encoding="utf-8")
        context = SphinxAnalyzer(str(tmp_path)).to_context()
        assert "Sphinx configuration analysis" in context
        assert "health score" in context
