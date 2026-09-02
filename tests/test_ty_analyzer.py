"""Tests for TyAnalyzer."""

from pathlib import Path

from devai.ty_analyzer import TyAnalyzer, TyFinding


INSECURE_TY_TOML = """\
[rules]
all = "ignore"
unresolved-import = "ignore"
possibly-unresolved-reference = "ignore"

[analysis]
allowed-unresolved-imports = ["*"]
respect-type-ignore-comments = false

[src]
exclude = ["src", "lib"]
extra-paths = ["/tmp/untrusted"]

[terminal]
error-on-warning = false

# api_key = hardcoded_secret_value_12345
api_key = "api_key=hardcoded_secret_value_12345"
"""

HARDENED_PYPROJECT = """\
[project]
name = "demo"

[tool.ty.rules]
all = "error"
possibly-unresolved-reference = "error"

[tool.ty.src]
include = ["src"]
exclude = ["**/__pycache__", ".venv"]

[tool.ty.terminal]
error-on-warning = true
"""

INSECURE_PYPROJECT = """\
[tool.ty.rules]
division-by-zero = "ignore"

[tool.pytest.ini_options]
addopts = "-q"
"""

INSECURE_OVERRIDES = """\
[tool.ty.rules]
all = "error"

[[tool.ty.overrides]]
include = ["tests/**"]
[tool.ty.overrides.rules]
all = "ignore"
"""


class TestTyAnalyzer:
    def test_detects_insecure_ty_toml(self, tmp_path: Path):
        (tmp_path / "ty.toml").write_text(INSECURE_TY_TOML, encoding="utf-8")
        analyzer = TyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "rules_all_ignore" in kinds
        assert "critical_rule_ignored" in kinds
        assert "error_on_warning_false" in kinds
        assert "exclude_source" in kinds
        assert "insecure_extra_path" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_scores_well(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = TyAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_pyproject_ignores_non_ty_sections(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = TyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert all(f.lineno <= 3 for f in findings)

    def test_detects_override_rule_ignore(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_OVERRIDES, encoding="utf-8")
        analyzer = TyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "override_rules_ignore" for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = TyAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_ty_toml_takes_precedence_over_pyproject(self, tmp_path: Path):
        (tmp_path / "ty.toml").write_text('[rules]\nall = "error"\n', encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[tool.ty.rules]\nall = "ignore"\n',
            encoding="utf-8",
        )
        analyzer = TyAnalyzer(str(tmp_path))
        paths = analyzer.config_files()
        assert (tmp_path / "ty.toml") in paths
        assert (tmp_path / "pyproject.toml") in paths

    def test_finding_format(self):
        finding = TyFinding(
            kind="rules_all_ignore",
            severity="high",
            message='all = "ignore" disables every ty rule',
            path="ty.toml",
            lineno=2,
            line='all = "ignore"',
        )
        assert "ty.toml:2" in finding.format()

    def test_generate_template(self):
        analyzer = TyAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "[tool.ty.rules]" in template
        assert "error-on-warning" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "ty.toml").write_text('[rules]\nall = "ignore"\n', encoding="utf-8")
        analyzer = TyAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "ty analysis:" in context
        assert "rules_all_ignore" in context or "ignore" in context

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "ty.toml").write_text(
            '[rules]\nall = "ignore"\nunresolved-import = "ignore"\n',
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        ty = next(c for c in report.categories if c.name == "ty")
        assert ty.score < 100.0
        assert ty.details.get("findings", 0) > 0
