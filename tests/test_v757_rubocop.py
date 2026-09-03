"""Tests for v7.57.0 RuboCopAnalyzer integration."""

from pathlib import Path

from devai import DevAI, RuboCopAnalyzer
from devai.project_health import ProjectHealth


HARDENED_CONFIG = """\
AllCops:
  NewCops: enable
  TargetRubyVersion: 3.3
  Exclude:
    - 'vendor/**/*'

Security/Eval:
  Enabled: true
"""


class TestV757RuboCopIntegration:
    def test_facade_rubocop(self, tmp_path: Path):
        (tmp_path / ".rubocop.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().rubocop(tmp_path)
        assert isinstance(analyzer, RuboCopAnalyzer)
        assert analyzer.stats.config_files == 1

    def test_project_health_includes_rubocop_category(self, tmp_path: Path):
        (tmp_path / ".rubocop.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "rubocop" in names

    def test_public_export(self):
        from devai import RuboCopFinding, RuboCopInfo, RuboCopStats

        assert RuboCopAnalyzer is not None
        assert RuboCopFinding is not None
        assert RuboCopInfo is not None
        assert RuboCopStats is not None
