"""Tests for v7.60.0 HadolintAnalyzer integration."""

from pathlib import Path

from devai import DevAI, HadolintAnalyzer
from devai.project_health import ProjectHealth

HARDENED_CONFIG = """\
failure-threshold: warning
no-fail: false
strict-labels: true
allow-deprecated-parent-images: false
"""


class TestV760HadolintIntegration:
    def test_facade_hadolint(self, tmp_path: Path):
        (tmp_path / ".hadolint.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().hadolint(tmp_path)
        assert isinstance(analyzer, HadolintAnalyzer)
        assert analyzer.stats.config_files == 1

    def test_project_health_includes_hadolint_category(self, tmp_path: Path):
        (tmp_path / ".hadolint.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "hadolint" in names

    def test_public_exports(self):
        from devai import HadolintFinding, HadolintInfo, HadolintStats

        assert HadolintAnalyzer is not None
        assert HadolintFinding is not None
        assert HadolintInfo is not None
        assert HadolintStats is not None
