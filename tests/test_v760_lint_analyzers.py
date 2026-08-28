"""Tests for v7.60.0 actionlint, tflint, and hadolint integration."""

from pathlib import Path

from devai import (
    ActionlintAnalyzer,
    DevAI,
    HadolintAnalyzer,
    TflintAnalyzer,
)
from devai.project_health import ProjectHealth

ACTIONLINT_CONFIG = """\
self-hosted-runner-allowed: false
config-schema: true
ignore: []
path-ignores: []
"""

TFLINT_CONFIG = """\
config {
  call_module_type = "local"
  force            = true
}

plugin "aws" {
  enabled = true
  version = "0.32.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}
"""

HADOLINT_CONFIG = """\
failure-threshold: warning
ignored: []
trustedRegistries:
  - docker.io
"""


class TestV760Integration:
    def test_facade_actionlint(self, tmp_path: Path):
        (tmp_path / ".actionlint.yaml").write_text(ACTIONLINT_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().actionlint(tmp_path)
        assert isinstance(analyzer, ActionlintAnalyzer)
        assert analyzer.stats.config_files == 1

    def test_facade_tflint(self, tmp_path: Path):
        (tmp_path / ".tflint.hcl").write_text(TFLINT_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().tflint(tmp_path)
        assert isinstance(analyzer, TflintAnalyzer)
        assert analyzer.stats.config_files == 1

    def test_facade_hadolint(self, tmp_path: Path):
        (tmp_path / ".hadolint.yaml").write_text(HADOLINT_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().hadolint(tmp_path)
        assert isinstance(analyzer, HadolintAnalyzer)
        assert analyzer.stats.config_files == 1

    def test_project_health_includes_new_categories(self, tmp_path: Path):
        (tmp_path / ".actionlint.yaml").write_text(ACTIONLINT_CONFIG, encoding="utf-8")
        (tmp_path / ".tflint.hcl").write_text(TFLINT_CONFIG, encoding="utf-8")
        (tmp_path / ".hadolint.yaml").write_text(HADOLINT_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "actionlint" in names
        assert "tflint" in names
        assert "hadolint" in names

    def test_public_exports(self):
        from devai import (
            ActionlintFinding,
            ActionlintInfo,
            ActionlintStats,
            HadolintFinding,
            HadolintInfo,
            HadolintStats,
            TflintFinding,
            TflintInfo,
            TflintStats,
        )

        assert ActionlintAnalyzer is not None
        assert TflintAnalyzer is not None
        assert HadolintAnalyzer is not None
        assert ActionlintFinding is not None
        assert TflintFinding is not None
        assert HadolintFinding is not None
        assert ActionlintInfo is not None
        assert TflintInfo is not None
        assert HadolintInfo is not None
        assert ActionlintStats is not None
        assert TflintStats is not None
        assert HadolintStats is not None
