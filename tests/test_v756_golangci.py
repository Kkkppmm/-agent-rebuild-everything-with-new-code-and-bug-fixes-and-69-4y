"""Tests for v7.56.0 GolangciLintAnalyzer integration."""

from pathlib import Path

from devai import DevAI, GolangciLintAnalyzer
from devai.project_health import ProjectHealth


HARDENED_CONFIG = """\
run:
  timeout: 5m
  tests: true

linters:
  enable:
    - errcheck
    - govet
    - staticcheck
    - gosec
"""


class TestV756GolangciIntegration:
    def test_facade_golangci(self, tmp_path: Path):
        (tmp_path / ".golangci.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().golangci(tmp_path)
        assert isinstance(analyzer, GolangciLintAnalyzer)
        assert analyzer.stats.config_files == 1

    def test_project_health_includes_golangci_category(self, tmp_path: Path):
        (tmp_path / ".golangci.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "golangci" in names

    def test_public_export(self):
        from devai import GolangciFinding, GolangciInfo, GolangciStats

        assert GolangciLintAnalyzer is not None
        assert GolangciFinding is not None
        assert GolangciInfo is not None
        assert GolangciStats is not None
