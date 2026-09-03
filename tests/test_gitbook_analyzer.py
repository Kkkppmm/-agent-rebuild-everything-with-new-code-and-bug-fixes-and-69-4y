"""Tests for GitBookAnalyzer."""

from pathlib import Path

from devai.gitbook_analyzer import GitBookAnalyzer, GitBookFinding


INSECURE_GITBOOK_YAML = """\
root: ../outside

structure:
  readme: README.md
  summary: SUMMARY.md

plugins:
  - search
  - github
  - include-code

integrations:
  github:
    url: https://user:secretpass@github.com/org/repo

variables:
  api_key: hardcoded-secret-value

config:
  gitbook:
    version: 2.6.7
  include-code:
    check: false
    folder: ../src

redirects:
  old/page: javascript:alert(1)
"""

HARDENED_GITBOOK_YAML = """\
root: ./docs/

structure:
  readme: README.md
  summary: SUMMARY.md

plugins:
  - search
  - github

integrations:
  github:
    url: https://github.com/org/repo

variables: {}

config:
  gitbook:
    version: 3.2.3
"""

INSECURE_BOOK_JSON = """\
{
  "title": "My Book",
  "gitbook": "2.6.7",
  "plugins": ["github", "include-code"],
  "pluginsConfig": {
    "github": {
      "url": "http://insecure.example.com/repo"
    },
    "include-code": {
      "check": false,
      "folder": "../"
    }
  },
  "variables": {
    "api_token": "secret-token-value"
  }
}
"""


class TestGitBookAnalyzer:
    def test_detects_insecure_gitbook_yaml(self, tmp_path: Path):
        (tmp_path / ".gitbook.yaml").write_text(INSECURE_GITBOOK_YAML, encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "root_outside_project" in kinds
        assert "credential_in_url" in kinds
        assert "include_code_plugin" in kinds
        assert "variables_secret" in kinds
        assert "old_gitbook_version" in kinds
        assert "unsafe_redirect" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_gitbook_scores_well(self, tmp_path: Path):
        (tmp_path / ".gitbook.yaml").write_text(HARDENED_GITBOOK_YAML, encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_book_json_also_scanned(self, tmp_path: Path):
        (tmp_path / "book.json").write_text(INSECURE_BOOK_JSON, encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(analyzer.config_files()) == 1
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "old_gitbook_version" in kinds

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = GitBookAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_generate_hardened_template(self):
        template = GitBookAnalyzer(".").generate_hardened_template()
        assert "root: ./docs/" in template
        assert "variables: {}" in template

    def test_finding_format(self):
        finding = GitBookFinding(
            kind="root_outside_project",
            severity="high",
            message="test message",
            path=".gitbook.yaml",
            lineno=1,
        )
        assert "high" in finding.format()
        assert ".gitbook.yaml:1" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".gitbook.yaml").write_text("root: ../outside\n", encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "GitBook analysis:" in context
        assert "root points outside" in context

    def test_summary(self, tmp_path: Path):
        (tmp_path / ".gitbook.yaml").write_text("root: ../outside\n", encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "GitBook configs:" in summary
        assert "1 file(s)" in summary

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / ".gitbook.yaml").write_text(
            "root: ../outside\nvariables:\n  api_key: leaked\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        gitbook = next(c for c in report.categories if c.name == "gitbook")
        assert gitbook.score < 100.0
        assert gitbook.details.get("findings", 0) > 0
