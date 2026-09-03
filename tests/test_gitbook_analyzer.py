"""Tests for GitBookAnalyzer."""

from pathlib import Path

from devai.gitbook_analyzer import GitBookAnalyzer, GitBookFinding


INSECURE_GITBOOK = """\
root: ../outside

structure:
  readme: README.md
  summary: SUMMARY.md

variables:
  api_key: sk-live-secret-token-12345
  token: bearer-abc123

redirects:
  old-page: https://evil.example.com/phish

plugins:
  - https://cdn.example.com/plugin.js

pdf:
  download: true
"""

INSECURE_BOOK_JSON = """\
{
  "gitbook": "3.2.3",
  "root": "../outside",
  "plugins": ["livereload"],
  "variables": {
    "api_key": "sk-live-secret-token-12345"
  }
}
"""

HARDENED_GITBOOK = """\
root: ./

structure:
  readme: README.md
  summary: SUMMARY.md

variables: {}

redirects: {}

plugins: []
"""


class TestGitBookAnalyzer:
    def test_detects_insecure_gitbook_yaml(self, tmp_path: Path):
        (tmp_path / ".gitbook.yaml").write_text(INSECURE_GITBOOK, encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "root_parent_path" in kinds
        assert "external_redirect" in kinds
        assert "external_asset" in kinds
        assert "pdf_download_enabled" in kinds
        assert analyzer.health_score() < 50.0

    def test_detects_insecure_book_json(self, tmp_path: Path):
        (tmp_path / "book.json").write_text(INSECURE_BOOK_JSON, encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "root_parent_path" in kinds

    def test_hardened_gitbook_scores_well(self, tmp_path: Path):
        (tmp_path / ".gitbook.yaml").write_text(HARDENED_GITBOOK, encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = GitBookAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = GitBookFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path=".gitbook.yaml",
            lineno=5,
            line="api_key: secret",
        )
        assert "[high]" in finding.format()
        assert ".gitbook.yaml:5" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = GitBookAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "root: ./" in template
        assert "SUMMARY.md" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".gitbook.yaml").write_text(INSECURE_GITBOOK, encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "GitBook analysis:" in context
        assert "health score:" in context

    def test_stats_property(self, tmp_path: Path):
        (tmp_path / ".gitbook.yaml").write_text(INSECURE_GITBOOK, encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        stats = analyzer.stats
        assert stats.config_files == 1
        assert stats.findings > 0
        assert stats.high_severity > 0
