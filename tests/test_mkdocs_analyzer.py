"""Tests for MkDocsAnalyzer."""

from pathlib import Path

from devai.mkdocs_analyzer import MkDocsAnalyzer, MkDocsFinding


INSECURE_MKDOCS = """\
site_name: Insecure Docs
repo_url: https://user:secret-token@github.com/example/repo.git
edit_uri: ../admin/

extra_javascript:
  - http://cdn.example.com/tracker.js
extra_css:
  - http://cdn.example.com/theme.css

hooks:
  - hooks/custom.py

plugins:
  - search
  - git-revision-date-localized:
      enable_creation_date: true
  - git+https://github.com/example/unpinned-plugin.git

markdown_extensions:
  - pymdownx.snippets:
      base_path: /etc
      check_paths: true

google_analytics:
  - UA-123456-1
  - auto

api_key: api_key=hardcoded_secret_value_12345
strict: false
"""

HARDENED_MKDOCS = """\
site_name: Secure Docs
repo_url: https://github.com/org/repo
edit_uri: edit/main/docs/

theme:
  name: material

plugins:
  - search
  - minify

strict: true
"""


class TestMkDocsAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = MkDocsAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "mkdocs.yml").write_text(INSECURE_MKDOCS, encoding="utf-8")
        analyzer = MkDocsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "credentials_in_url" in kinds
        assert "insecure_http" in kinds
        assert "custom_hooks" in kinds
        assert "snippets_path_traversal" in kinds
        assert "remote_plugin" in kinds
        assert "strict_disabled" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "mkdocs.yml").write_text(HARDENED_MKDOCS, encoding="utf-8")
        analyzer = MkDocsAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].site_name == "Secure Docs"

    def test_finding_format(self):
        finding = MkDocsFinding(
            kind="custom_hooks",
            severity="medium",
            message="Custom hooks execute arbitrary Python during build",
            path="mkdocs.yml",
            lineno=10,
            line="hooks:",
        )
        assert "mkdocs.yml:10" in finding.format()

    def test_generate_template(self):
        analyzer = MkDocsAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "site_name:" in template
        assert "strict: true" in template

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / "mkdocs.yml").write_text(INSECURE_MKDOCS, encoding="utf-8")
        analyzer = MkDocsAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "MkDocs analysis:" in context
        assert "Hardcoded secret" in context or "Credentials embedded" in context

    def test_summary_without_configs(self, tmp_path: Path):
        analyzer = MkDocsAnalyzer(str(tmp_path))
        assert "none found" in analyzer.summary()
