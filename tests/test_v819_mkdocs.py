"""Tests for v8.19.0 MkDocsAnalyzer integration."""

from pathlib import Path

from devai import DevAI, MkDocsAnalyzer
from devai.project_health import ProjectHealth

HARDENED_CONFIG = """\
site_name: My Docs
site_url: https://example.com/docs/
repo_url: https://github.com/org/repo
strict: true

theme:
  name: material

plugins:
  - search
  - privacy
  - validation

dev_addr: 127.0.0.1:8000
"""


class TestV819MkDocsIntegration:
    def test_facade_mkdocs(self, tmp_path: Path):
        (tmp_path / "mkdocs.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().mkdocs(tmp_path)
        assert isinstance(analyzer, MkDocsAnalyzer)
        assert analyzer.stats.config_files == 1

    def test_project_health_includes_mkdocs_category(self, tmp_path: Path):
        (tmp_path / "mkdocs.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "mkdocs" in names

    def test_public_exports(self):
        from devai import MkDocsFinding, MkDocsInfo, MkDocsStats

        assert MkDocsAnalyzer is not None
        assert MkDocsFinding is not None
        assert MkDocsInfo is not None
        assert MkDocsStats is not None
