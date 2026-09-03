"""Tests for GitBookAnalyzer."""

from pathlib import Path

from devai.gitbook_analyzer import GitBookAnalyzer, GitBookFinding


INSECURE_GITBOOK = """\
root: ./

structure:
  readme: ../outside/README.md
  summary: SUMMARY.md

variables:
  api_key: super-secret-token-12345

plugins:
  - git+https://github.com/evil/plugin.git
  - http://cdn.example.com/plugin.js

redirects:
  old: http://insecure.example.com/new
"""

HARDENED_GITBOOK = """\
root: ./

structure:
  readme: README.md
  summary: SUMMARY.md

variables: {}

plugins: []
"""

INSECURE_BOOK_JSON = """\
{
  "title": "Demo",
  "plugins": ["git+https://github.com/evil/plugin.git"],
  "pluginsConfig": {
    "api_key": "secret-token-abc"
  },
  "links": {
    "sidebar": "http://insecure.example.com"
  }
}
"""


class TestGitBookAnalyzer:
    def test_detects_insecure_gitbook_yaml(self, tmp_path: Path):
        (tmp_path / ".gitbook.yaml").write_text(INSECURE_GITBOOK, encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "parent_path" in kinds
        assert "git_plugin" in kinds
        assert "insecure_http" in kinds
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
        assert any(f.kind == "hardcoded_secret" for f in findings)
        assert any(f.kind == "git_plugin" for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = GitBookAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_generate_hardened_template(self):
        template = GitBookAnalyzer(".").generate_hardened_template()
        assert "variables: {}" in template
        assert "SUMMARY.md" in template

    def test_finding_format(self):
        finding = GitBookFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path=".gitbook.yaml",
            lineno=2,
        )
        assert "high" in finding.format()
        assert ".gitbook.yaml:2" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".gitbook.yaml").write_text("variables:\n  token: abc123\n", encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "GitBook analysis:" in context
        assert "health score:" in context

    def test_summary(self, tmp_path: Path):
        (tmp_path / ".gitbook.yaml").write_text("variables:\n  token: abc123\n", encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "GitBook configs:" in summary
        assert "1 file(s)" in summary

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / ".gitbook.yaml").write_text(
            "variables:\n  api_key: leaked-secret\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        gitbook = next(c for c in report.categories if c.name == "gitbook")
        assert gitbook.score < 100.0
        assert gitbook.details.get("findings", 0) > 0

    def test_facade_gitbook_method(self):
        from devai.facade import DevAI

        dev = DevAI.mock()
        analyzer = dev.gitbook(".")
        assert isinstance(analyzer, GitBookAnalyzer)
