"""Tests for v7.53.0 ShellcheckAnalyzer integration."""

from pathlib import Path

from devai import DevAI, ShellcheckAnalyzer
from devai.project_health import ProjectHealth

HARDENED_CONFIG = """\
shell=bash
external-sources=false
source-path=SCRIPTDIR
disable=
"""


class TestV758ShellcheckIntegration:
    def test_facade_shellcheck(self, tmp_path: Path):
        (tmp_path / ".shellcheckrc").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().shellcheck(tmp_path)
        assert isinstance(analyzer, ShellcheckAnalyzer)
        assert analyzer.stats.config_files == 1

    def test_project_health_includes_shellcheck_category(self, tmp_path: Path):
        (tmp_path / ".shellcheckrc").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "shellcheck" in names

    def test_public_exports(self):
        from devai import ShellcheckFinding, ShellcheckInfo, ShellcheckStats

        assert ShellcheckAnalyzer is not None
        assert ShellcheckFinding is not None
        assert ShellcheckInfo is not None
        assert ShellcheckStats is not None
