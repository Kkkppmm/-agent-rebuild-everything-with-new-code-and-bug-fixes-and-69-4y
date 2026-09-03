"""Tests for MkDocsAnalyzer."""

from pathlib import Path

from devai.mkdocs_analyzer import MkDocsAnalyzer, MkDocsFinding


INSECURE_MKDOCS = """\
site_name: Demo Docs
site_url: http://insecure.example.com/docs/
repo_url: https://user:secretpass@github.com/org/repo
edit_uri: http://evil.example.com/edit/

strict: false
dev_addr: 0.0.0.0:8000

plugins:
  - search
  - macros
  - git-revision-date-localized

markdown_extensions:
  - pymdownx.snippets:
      base_path: /tmp/untrusted
      check_paths: true

extra_javascript:
  - https://cdn.example.com/jquery.min.js

extra_css:
  - https://cdn.example.com/theme.css

watch:
  - ../outside

validation:
  nav: ignore
"""

HARDENED_MKDOCS = """\
site_name: Demo Docs
site_url: https://example.com/docs/
repo_url: https://github.com/org/repo
edit_uri: edit/main/docs/

strict: true
dev_addr: 127.0.0.1:8000

theme:
  name: material

plugins:
  - search

markdown_extensions:
  - admonition
  - pymdownx.highlight

nav:
  - Home: index.md
"""


class TestMkDocsAnalyzer:
    def test_detects_insecure_mkdocs_yml(self, tmp_path: Path):
        (tmp_path / "mkdocs.yml").write_text(INSECURE_MKDOCS, encoding="utf-8")
        analyzer = MkDocsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "strict_false" in kinds
        assert "credential_in_url" in kinds
        assert "dev_addr_exposed" in kinds
        assert "macros_plugin" in kinds
        assert "snippets_unsafe_path" in kinds
        assert "external_script" in kinds
        assert "watch_parent_path" in kinds
        assert "insecure_http" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_mkdocs_scores_well(self, tmp_path: Path):
        (tmp_path / "mkdocs.yml").write_text(HARDENED_MKDOCS, encoding="utf-8")
        analyzer = MkDocsAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_mkdocs_yaml_also_scanned(self, tmp_path: Path):
        (tmp_path / "mkdocs.yaml").write_text("strict: false\n", encoding="utf-8")
        analyzer = MkDocsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(analyzer.config_files()) == 1
        assert any(f.kind == "strict_false" for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = MkDocsAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_generate_hardened_template(self):
        template = MkDocsAnalyzer(".").generate_hardened_template()
        assert "strict: true" in template
        assert "127.0.0.1:8000" in template

    def test_finding_format(self):
        finding = MkDocsFinding(
            kind="strict_false",
            severity="medium",
            message="test message",
            path="mkdocs.yml",
            lineno=2,
        )
        assert "medium" in finding.format()
        assert "mkdocs.yml:2" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "mkdocs.yml").write_text("strict: false\n", encoding="utf-8")
        analyzer = MkDocsAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "MkDocs analysis:" in context
        assert "strict" in context

    def test_summary(self, tmp_path: Path):
        (tmp_path / "mkdocs.yml").write_text("strict: false\n", encoding="utf-8")
        analyzer = MkDocsAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "MkDocs configs:" in summary
        assert "1 file(s)" in summary

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "mkdocs.yml").write_text(
            "strict: false\ndev_addr: 0.0.0.0:8000\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        mkdocs = next(c for c in report.categories if c.name == "mkdocs")
        assert mkdocs.score < 100.0
        assert mkdocs.details.get("findings", 0) > 0
