"""Tests for TsconfigAnalyzer."""

from pathlib import Path

from devai.tsconfig_analyzer import TsconfigAnalyzer, TsconfigFinding


INSECURE_TSCONFIG = """\
{
  "compilerOptions": {
    "strict": false,
    "noImplicitAny": false,
    "strictNullChecks": false,
    "skipLibCheck": true,
    "allowJs": true,
    "checkJs": false,
    "noUnusedLocals": false,
    "api_key": "hardcoded_secret_value_12345"
  },
  "extends": "http://evil.example/tsconfig.json"
}
"""

HARDENED_TSCONFIG = """\
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "skipLibCheck": false,
    "allowJs": false,
    "noUnusedLocals": true
  },
  "include": ["src"]
}
"""


class TestTsconfigAnalyzer:
    def test_detects_insecure_config(self, tmp_path: Path):
        (tmp_path / "tsconfig.json").write_text(INSECURE_TSCONFIG, encoding="utf-8")
        analyzer = TsconfigAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "strict_false" in kinds
        assert "no_implicit_any_false" in kinds
        assert "strict_null_checks_false" in kinds
        assert "skip_lib_check" in kinds
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "tsconfig.json").write_text(HARDENED_TSCONFIG, encoding="utf-8")
        analyzer = TsconfigAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].strict is True

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = TsconfigAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = TsconfigFinding(
            kind="strict_false",
            severity="high",
            message="test message",
            path="tsconfig.json",
            lineno=3,
            line='"strict": false',
        )
        assert "tsconfig.json:3" in finding.format()
        assert "test message" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = TsconfigAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert '"strict": true' in template
        assert '"noImplicitAny": true' in template

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "tsconfig.json").write_text(
            '{"compilerOptions": {"strict": false}}\n',
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        tsconfig = next(c for c in report.categories if c.name == "tsconfig")
        assert tsconfig.score < 100.0
        assert tsconfig.details.get("findings", 0) > 0
