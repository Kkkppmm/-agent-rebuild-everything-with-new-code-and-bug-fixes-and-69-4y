"""Tests for v7.59.0 YamllintAnalyzer integration."""

from pathlib import Path

from devai import DevAI, YamllintAnalyzer
from devai.project_health import ProjectHealth

HARDENED_CONFIG = """\
extends: default

rules:
  line-length:
    max: 120
  truthy:
    allowed-values: ['true', 'false']
  key-duplicates: enable
  octal-values: enable
"""


class TestV759YamllintIntegration:
    def test_facade_yamllint(self, tmp_path: Path):
        (tmp_path / ".yamllint").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().yamllint(tmp_path)
        assert isinstance(analyzer, YamllintAnalyzer)
        assert analyzer.stats.config_files == 1

    def test_project_health_includes_yamllint_category(self, tmp_path: Path):
        (tmp_path / ".yamllint").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "yamllint" in names

    def test_public_exports(self):
        from devai import YamllintFinding, YamllintInfo, YamllintStats

        assert YamllintAnalyzer is not None
        assert YamllintFinding is not None
        assert YamllintInfo is not None
        assert YamllintStats is not None
