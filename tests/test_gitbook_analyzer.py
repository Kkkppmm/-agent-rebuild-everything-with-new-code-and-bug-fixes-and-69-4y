"""Tests for GitBookAnalyzer."""

from pathlib import Path

from devai.gitbook_analyzer import GitBookAnalyzer, GitBookFinding


INSECURE_GITBOOK_YAML = """\
root: ./

structure:
  readme: README.md
  summary: SUMMARY.md

variables:
  apiKey: sk-hardcoded-secret
  token: ghp_abcdefghijklmnopqrstuvwxyz1234567890

plugins:
  - github
  - theme-default

pluginsConfig:
  github:
    url: http://insecure.example.com/repo
    token: ghp_abcdefghijklmnopqrstuvwxyz1234567890
  custom:
    script: https://cdn.example.com/plugin.js

redirects:
  old-page: https://evil.example.com/phish

additional-js:
  - https://cdn.example.com/tracker.js

eval("console.log('bad')");
"""

HARDENED_GITBOOK_YAML = """\
root: ./

structure:
  readme: README.md
  summary: SUMMARY.md

variables:
  version: "1.0.0"

plugins:
  - theme-default
  - search
  - highlight

pluginsConfig:
  github:
    url: https://github.com/org/repo

pdf:
  fontSize: 12
"""

INSECURE_BOOK_JSON = """\
{
  "title": "My Book",
  "plugins": ["github", "highlight"],
  "pluginsConfig": {
    "github": {
      "url": "http://insecure.example.com/repo",
      "token": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    }
  },
  "variables": {
    "apiKey": "sk-hardcoded-secret"
  }
}
"""


class TestGitBookAnalyzer:
    def test_detects_insecure_gitbook_yaml(self, tmp_path: Path):
        (tmp_path / ".gitbook.yaml").write_text(INSECURE_GITBOOK_YAML, encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "git_token" in kinds
        assert "insecure_http" in kinds
        assert "remote_plugin" in kinds or "remote_script" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_gitbook_scores_well(self, tmp_path: Path):
        (tmp_path / ".gitbook.yaml").write_text(HARDENED_GITBOOK_YAML, encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_book_json(self, tmp_path: Path):
        (tmp_path / "book.json").write_text(INSECURE_BOOK_JSON, encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "git_token" in kinds
        assert "insecure_http" in kinds

    def test_detects_gitbook_yml_extension(self, tmp_path: Path):
        (tmp_path / ".gitbook.yml").write_text(HARDENED_GITBOOK_YAML, encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        assert len(analyzer.config_files()) == 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / ".gitbook.yaml").write_text(INSECURE_GITBOOK_YAML, encoding="utf-8")
        analyzer = GitBookAnalyzer(str(tmp_path))
        assert "GitBook configs:" in analyzer.summary()
        assert "GitBook analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = GitBookAnalyzer(".").generate_hardened_template()
        assert "structure:" in template
        assert "plugins:" in template
        assert "theme-default" in template

    def test_finding_format(self):
        finding = GitBookFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path=".gitbook.yaml",
            lineno=5,
        )
        assert ".gitbook.yaml:5" in finding.format()

    def test_no_config_returns_full_score(self, tmp_path: Path):
        analyzer = GitBookAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "GitBook configs: none found"
