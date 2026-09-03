"""Tests for TyAnalyzer."""

from pathlib import Path

from devai.ty_analyzer import TyAnalyzer, TyFinding


INSECURE_TY_TOML = """\
[rules]
all = "ignore"
possibly-missing-import = "ignore"
possibly-unresolved-reference = "ignore"
division-by-zero = "ignore"

[analysis]
replace-imports-with-any = true
respect-type-ignore-comments = false
allowed-unresolved-imports = ["**"]
strict-equality-semantics = false
strict-generic-narrowing = false

[src]
exclude = ["src", "lib"]
respect-ignore-files = false

[environment]
extra-paths = ["/tmp/untrusted"]

[terminal]
error-on-warning = false

# api_key = "api_key=hardcoded_secret_value_12345"
"""

HARDENED_PYPROJECT = """\
[project]
name = "demo"

[tool.ty.rules]
all = "error"
possibly-missing-import = "error"

[tool.ty.src]
include = ["src"]
exclude = ["**/__pycache__", ".venv"]
"""

INSECURE_PYPROJECT = """\
[tool.ty.rules]
all = "warn"
possibly-missing-import = "ignore"
exclude = ["src"]

[tool.pytest.ini_options]
addopts = "-q"
"""


class TestTyAnalyzer:
    def test_detects_insecure_ty_toml(self, tmp_path: Path):
        (tmp_path / "ty.toml").write_text(INSECURE_TY_TOML, encoding="utf-8")
        analyzer = TyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "rules_all_ignore" in kinds
        assert "critical_rule_ignored" in kinds
        assert "replace_imports_with_any" in kinds
        assert "broad_allowed_imports" in kinds
        assert "exclude_source" in kinds
        assert "insecure_extra_path" in kinds
        assert "error_on_warning_false" in kinds
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
        assert all(f.lineno <= 4 for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = TyAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_ty_toml_takes_precedence_over_pyproject(self, tmp_path: Path):
        (tmp_path / "ty.toml").write_text("[rules]\nall = \"ignore\"\n", encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[tool.ty.rules]\nall = "error"\n',
            encoding="utf-8",
        )
        analyzer = TyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(analyzer.config_files()) == 2
        assert any(f.kind == "rules_all_ignore" for f in findings)

    def test_generate_hardened_template(self):
        template = TyAnalyzer(".").generate_hardened_template()
        assert "[tool.ty.rules]" in template
        assert 'all = "error"' in template

    def test_finding_format(self):
        finding = TyFinding(
            kind="rules_all_ignore",
            severity="high",
            message="test message",
            path="ty.toml",
            lineno=2,
        )
        assert "high" in finding.format()
        assert "ty.toml:2" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "ty.toml").write_text("[rules]\nall = \"ignore\"\n", encoding="utf-8")
        analyzer = TyAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "ty analysis:" in context
        assert "rules.all" in context

    def test_summary(self, tmp_path: Path):
        (tmp_path / "ty.toml").write_text("[rules]\nall = \"ignore\"\n", encoding="utf-8")
        analyzer = TyAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "ty configs:" in summary
        assert "1 file(s)" in summary

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "ty.toml").write_text(
            '[rules]\nall = "ignore"\npossibly-missing-import = "ignore"\n',
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        ty = next(c for c in report.categories if c.name == "ty")
        assert ty.score < 100.0
        assert ty.details.get("findings", 0) > 0
