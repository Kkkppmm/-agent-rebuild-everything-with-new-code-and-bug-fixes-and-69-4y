"""Tests for MkDocsAnalyzer."""

from pathlib import Path

from devai.mkdocs_analyzer import MkDocsAnalyzer, MkDocsFinding


INSECURE_MKDOCS = """
site_name: My Docs
site_url: http://docs.example.com
repo_url: http://github.com/org/repo
docs_dir: ../secrets
strict: false
use_directory_urls: false
dev_addr: 0.0.0.0
plugins:
  - minify
extra_javascript: https://cdn.example.com/script.js
ENV API_SECRET=supersecret
"""

HARDENED_MKDOCS = """
site_name: My Docs
site_url: https://docs.example.com/
repo_url: https://github.com/org/repo
edit_uri: edit/main/docs/
docs_dir: docs
strict: true
use_directory_urls: true

theme:
  name: material

plugins:
  - search
  - minify

nav:
  - Home: index.md
  - Guide: guide.md
"""


class TestMkDocsAnalyzer:
    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = MkDocsAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "mkdocs.yml").write_text(INSECURE_MKDOCS, encoding="utf-8")
        analyzer = MkDocsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "path_traversal" in kinds
        assert "strict_disabled" in kinds
        assert "dev_addr_exposed" in kinds
        assert "hardcoded_secret" in kinds
        assert "missing_nav" in kinds
        assert "search_plugin_missing" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "mkdocs.yml").write_text(HARDENED_MKDOCS, encoding="utf-8")
        analyzer = MkDocsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.config_files == 1
        assert analyzer.infos[0].has_nav is True

    def test_finds_mkdocs_yaml(self, tmp_path: Path):
        (tmp_path / "mkdocs.yaml").write_text(
            "site_name: Docs\nsite_url: https://docs.example.com\nnav:\n  - Home: index.md\n",
            encoding="utf-8",
        )
        analyzer = MkDocsAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 1

    def test_summary_context_and_template(self, tmp_path: Path):
        (tmp_path / "mkdocs.yml").write_text(HARDENED_MKDOCS, encoding="utf-8")
        analyzer = MkDocsAnalyzer(str(tmp_path))
        assert "MkDocs configs:" in analyzer.summary()
        assert "MkDocs analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "strict: true" in template
        assert "plugins:" in template

    def test_finding_format(self):
        finding = MkDocsFinding(
            kind="insecure_http",
            severity="medium",
            message="insecure HTTP URL",
            path="mkdocs.yml",
            lineno=2,
        )
        assert "mkdocs.yml:2" in finding.format()
        assert "medium" in finding.format()
