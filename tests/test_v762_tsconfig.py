"""Tests for v7.62.0 TsconfigAnalyzer integration."""

from pathlib import Path

from devai import DevAI, TsconfigAnalyzer
from devai.project_health import ProjectHealth

HARDENED_TSCONFIG = """\
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "noEmitOnError": true,
    "sourceMap": false
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules"]
}
"""


class TestV762TsconfigIntegration:
    def test_facade_tsconfig(self, tmp_path: Path):
        (tmp_path / "tsconfig.json").write_text(HARDENED_TSCONFIG, encoding="utf-8")
        analyzer = DevAI.mock().tsconfig(tmp_path)
        assert isinstance(analyzer, TsconfigAnalyzer)
        assert analyzer.stats.config_files == 1

    def test_project_health_includes_tsconfig_category(self, tmp_path: Path):
        (tmp_path / "tsconfig.json").write_text(HARDENED_TSCONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "tsconfig" in names

    def test_public_exports(self):
        from devai import TsconfigFinding, TsconfigInfo, TsconfigStats

        assert TsconfigAnalyzer is not None
        assert TsconfigFinding is not None
        assert TsconfigInfo is not None
        assert TsconfigStats is not None
