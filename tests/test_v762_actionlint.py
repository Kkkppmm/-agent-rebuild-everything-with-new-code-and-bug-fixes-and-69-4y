"""Tests for v7.62.0 ActionlintAnalyzer integration."""

from pathlib import Path

from devai import ActionlintAnalyzer, DevAI
from devai.project_health import ProjectHealth

HARDENED_CONFIG = """\
self-hosted-runner:
  labels:
    - self-hosted
    - linux
    - x64

config-variables: []

paths: {}
"""


class TestV762ActionlintIntegration:
    def test_facade_actionlint(self, tmp_path: Path):
        github = tmp_path / ".github"
        github.mkdir()
        (github / "actionlint.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().actionlint(tmp_path)
        assert isinstance(analyzer, ActionlintAnalyzer)
        assert analyzer.stats.config_files == 1

    def test_project_health_includes_actionlint_category(self, tmp_path: Path):
        github = tmp_path / ".github"
        github.mkdir()
        (github / "actionlint.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "actionlint" in names

    def test_public_exports(self):
        from devai import ActionlintFinding, ActionlintInfo, ActionlintStats

        assert ActionlintAnalyzer is not None
        assert ActionlintFinding is not None
        assert ActionlintInfo is not None
        assert ActionlintStats is not None
