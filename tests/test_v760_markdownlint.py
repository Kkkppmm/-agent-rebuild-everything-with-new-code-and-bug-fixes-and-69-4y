"""Tests for v7.60.0 MarkdownlintAnalyzer integration."""

from pathlib import Path

from devai import DevAI, MarkdownlintAnalyzer
from devai.project_health import ProjectHealth

HARDENED_CONFIG = """\
{
  "default": true,
  "MD013": {
    "line_length": 120,
    "code_blocks": false,
    "tables": false
  },
  "MD033": {
    "allowed_elements": []
  }
}
"""


class TestV760MarkdownlintIntegration:
    def test_facade_markdownlint(self, tmp_path: Path):
        (tmp_path / ".markdownlint.json").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().markdownlint(tmp_path)
        assert isinstance(analyzer, MarkdownlintAnalyzer)
        assert analyzer.stats.config_files == 1

    def test_project_health_includes_markdownlint_category(self, tmp_path: Path):
        (tmp_path / ".markdownlint.json").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "markdownlint" in names

    def test_public_exports(self):
        from devai import MarkdownlintFinding, MarkdownlintInfo, MarkdownlintStats

        assert MarkdownlintAnalyzer is not None
        assert MarkdownlintFinding is not None
        assert MarkdownlintInfo is not None
        assert MarkdownlintStats is not None
