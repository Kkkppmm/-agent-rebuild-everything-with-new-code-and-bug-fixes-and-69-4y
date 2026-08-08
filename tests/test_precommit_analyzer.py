"""Tests for PrecommitAnalyzer."""

from pathlib import Path

from devai.precommit_analyzer import PrecommitAnalyzer, PrecommitFinding


INSECURE_PRECOMMIT = """
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: master
    hooks:
      - id: trailing-whitespace
  - repo: http://example.com/hooks
    rev: v4.5.0
    hooks:
      - id: custom-hook
"""

HARDENED_PRECOMMIT = """
default_stages: [commit]
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
"""


class TestPrecommitAnalyzer:
    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = PrecommitAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".pre-commit-config.yaml").write_text(INSECURE_PRECOMMIT, encoding="utf-8")
        analyzer = PrecommitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "floating_rev" in kinds
        assert "insecure_repo_url" in kinds
        assert analyzer.health_score() < 80.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / ".pre-commit-config.yaml").write_text(HARDENED_PRECOMMIT, encoding="utf-8")
        analyzer = PrecommitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.hooks >= 2

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / ".pre-commit-config.yaml").write_text(HARDENED_PRECOMMIT, encoding="utf-8")
        analyzer = PrecommitAnalyzer(str(tmp_path))
        assert "Pre-commit:" in analyzer.summary()
        assert "Pre-commit config analysis" in analyzer.to_context()

    def test_finding_format(self):
        finding = PrecommitFinding(
            kind="floating_rev",
            severity="high",
            message="not pinned",
            path=".pre-commit-config.yaml",
            lineno=3,
        )
        assert ".pre-commit-config.yaml:3" in finding.format()
