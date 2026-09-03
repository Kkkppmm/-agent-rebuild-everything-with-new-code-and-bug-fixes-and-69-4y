"""Tests for MkDocsAnalyzer."""

from pathlib import Path

from devai.mkdocs_analyzer import MkDocsAnalyzer


GOOD_CONFIG = """\
site_name: My Docs
site_url: https://example.com/docs/
repo_url: https://github.com/org/repo

nav:
  - Home: index.md

plugins:
  - search

dev_addr: 127.0.0.1:8000
"""


class TestMkDocsAnalyzer:
    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = MkDocsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0
        assert "no config" in analyzer.summary().lower()

    def test_clean_config(self, tmp_path: Path):
        (tmp_path / "mkdocs.yml").write_text(GOOD_CONFIG, encoding="utf-8")
        analyzer = MkDocsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not findings
        stats = analyzer.stats
        assert stats.config_files == 1
        assert stats.plugins >= 1
        assert analyzer.health_score() == 100.0

    def test_detects_http_site_url(self, tmp_path: Path):
        config = "site_url: http://example.com/docs/\nnav:\n  - Home: index.md\n"
        (tmp_path / "mkdocs.yml").write_text(config, encoding="utf-8")
        findings = MkDocsAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "http_site_url" for f in findings)

    def test_detects_public_dev_addr(self, tmp_path: Path):
        config = "site_name: Docs\ndev_addr: 0.0.0.0:8000\n"
        (tmp_path / "mkdocs.yml").write_text(config, encoding="utf-8")
        findings = MkDocsAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "public_dev_addr" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_secret_in_config(self, tmp_path: Path):
        config = "site_name: Docs\napi_key: 'sk-live-secret12345'\n"
        (tmp_path / "mkdocs.yml").write_text(config, encoding="utf-8")
        findings = MkDocsAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "secret_in_config" for f in findings)

    def test_detects_missing_nav(self, tmp_path: Path):
        config = "site_name: Docs\nsite_url: https://example.com/\n"
        (tmp_path / "mkdocs.yml").write_text(config, encoding="utf-8")
        findings = MkDocsAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "missing_nav" for f in findings)

    def test_generate_template(self, tmp_path: Path):
        template = MkDocsAnalyzer(str(tmp_path)).generate_hardened_template()
        assert "site_url: https://" in template
        assert "dev_addr: 127.0.0.1" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "mkdocs.yml").write_text(GOOD_CONFIG, encoding="utf-8")
        context = MkDocsAnalyzer(str(tmp_path)).to_context()
        assert "MkDocs configuration analysis" in context
        assert "health score" in context
