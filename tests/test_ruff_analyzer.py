"""Tests for RuffAnalyzer."""

from pathlib import Path

from devai.ruff_analyzer import RuffAnalyzer, RuffFinding


INSECURE_RUFF_TOML = """\
target-version = "py310"
unsafe-fixes = true
preview = true
exclude = ["src", "lib"]
fixable = ["ALL"]
builtins = ["eval", "exec"]
allowed-confusables = ["а"]

[lint]
select = []
ignore = ["ALL", "S105", "S106"]
per-file-ignores = {"settings.py" = ["S105", "S107"]}
api_key = "api_key=hardcoded_secret_value_12345"
"""

HARDENED_RUFF_PYPROJECT = """\
[project]
name = "demo"

[tool.ruff]
target-version = "py310"
line-length = 88
unsafe-fixes = false

[tool.ruff.lint]
select = ["E", "F", "W", "I", "B", "S", "UP"]
ignore = []

[tool.ruff.lint.per-file-ignores]
"tests/**" = ["S101"]
"""

INSECURE_PYPROJECT = """\
[tool.ruff]
unsafe-fixes = true
ignore = ["S501", "S105"]

[tool.pytest.ini_options]
addopts = "-q"
"""


class TestRuffAnalyzer:
    def test_detects_insecure_ruff_toml(self, tmp_path: Path):
        (tmp_path / "ruff.toml").write_text(INSECURE_RUFF_TOML, encoding="utf-8")
        analyzer = RuffAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "unsafe_fixes" in kinds
        assert "ignore_all" in kinds
        assert "empty_select" in kinds
        assert "disabled_security_rules" in kinds
        assert "per_file_security_ignore" in kinds
        assert "exclude_source" in kinds
        assert "fixable_all" in kinds
        assert "builtins_shadow" in kinds
        assert "allowed_confusables" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_scores_well(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_RUFF_PYPROJECT, encoding="utf-8")
        analyzer = RuffAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert "S" in analyzer.infos[0].select_rules

    def test_pyproject_ignores_non_ruff_sections(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = RuffAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "unsafe_fixes" in kinds
        assert "disabled_security_rules" in kinds
        assert all(f.lineno <= 4 for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = RuffAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = RuffFinding(
            kind="unsafe_fixes",
            severity="medium",
            message="test message",
            path="ruff.toml",
            lineno=3,
            line="unsafe-fixes = true",
        )
        assert "ruff.toml:3" in finding.format()
        assert "test message" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = RuffAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "[tool.ruff]" in template
        assert '"S"' in template
        assert "unsafe-fixes = false" in template

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / "ruff.toml").write_text("unsafe-fixes = true\n", encoding="utf-8")
        analyzer = RuffAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Ruff analysis:" in context
        assert "unsafe_fixes" in context or "unsafe-fixes" in context
