"""Tests for v7.61.0 TflintAnalyzer integration."""

from pathlib import Path

from devai import DevAI, TflintAnalyzer
from devai.project_health import ProjectHealth

HARDENED_CONFIG = """\
config {
  call_module_type = "module"
}

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}
"""


class TestV761TflintIntegration:
    def test_facade_tflint(self, tmp_path: Path):
        (tmp_path / ".tflint.hcl").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().tflint(tmp_path)
        assert isinstance(analyzer, TflintAnalyzer)
        assert analyzer.stats.config_files == 1

    def test_project_health_includes_tflint_category(self, tmp_path: Path):
        (tmp_path / ".tflint.hcl").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "tflint" in names

    def test_public_exports(self):
        from devai import TflintFinding, TflintInfo, TflintStats

        assert TflintAnalyzer is not None
        assert TflintFinding is not None
        assert TflintInfo is not None
        assert TflintStats is not None
