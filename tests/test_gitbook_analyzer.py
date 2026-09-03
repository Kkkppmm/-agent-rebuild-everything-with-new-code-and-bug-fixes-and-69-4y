"""Tests for GitBookAnalyzer."""

from pathlib import Path

from devai.gitbook_analyzer import GitBookAnalyzer, GitBookFinding


INSECURE_GITBOOK = """\
root: ../outside

structure:
  readme: README.md
  summary: SUMMARY.md

redirects:
  old-page: http://evil.example.com/phish

variables:
  api_key: super-secret-token-12345

plugins:
  - gitbook-plugin-ga
  - https://evil.example.com/plugin.js

git:
  github: https://user:secretpass@github.com/org/repo
"""

HARDENED_GITBOOK = """\
root: ./

structure:
  readme: README.md
  summary: SUMMARY.md

redirects: {}

variables: {}

plugins: []
"""

INSECURE_BOOK_JSON = """\
{
  "title": "My Book",
  "plugins": ["ga"],
  "pluginsConfig": {
    "ga": {
      "token": "UA-123456-1"
    }
  },
  "links": {
    "sidebar": {
      "Home": "http://insecure.example.com"
    }
  },
  "api_key": "hardcoded-secret-value"
}
"""


class TestGitBookAnalyzer:
    def test_detects_insecure_gitbook_yaml(self, tmp_path: Path):
        (tmp_path / ".gitbook.yaml").write_text(INSECURE_GITBOOK, encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "root_parent_path" in kinds
        assert "open_redirect" in kinds
        assert "variable_secret" in kinds
        assert "git_sync_credentials" in kinds
        assert "remote_plugin" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_gitbook_scores_well(self, tmp_path: Path):
        (tmp_path / ".gitbook.yaml").write_text(HARDENED_GITBOOK, encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_book_json_also_scanned(self, tmp_path: Path):
        (tmp_path / "book.json").write_text(INSECURE_BOOK_JSON, encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(analyzer.config_files()) == 1
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = GitBookAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_generate_hardened_template(self):
        template = GitBookAnalyzer(".").generate_hardened_template()
        assert "root: ./" in template
        assert "variables: {}" in template

    def test_finding_format(self):
        finding = GitBookFinding(
            kind="open_redirect",
            severity="medium",
            message="test message",
            path=".gitbook.yaml",
            lineno=5,
        )
        assert "medium" in finding.format()
        assert ".gitbook.yaml:5" in finding.format()

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
            "root: ../outside\nvariables:\n  api_key: secret123\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        gitbook = next(c for c in report.categories if c.name == "gitbook")
        assert gitbook.score < 100.0
        assert gitbook.details.get("findings", 0) > 0
