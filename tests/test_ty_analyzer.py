"""Tests for TyAnalyzer."""

from pathlib import Path

from devai.ty_analyzer import TyAnalyzer, TyFinding


INSECURE_TY_TOML = """\
[rules]
all = "ignore"
unresolved-import = "ignore"
possibly-missing-import = "ignore"
invalid-assignment = "ignore"

[terminal]
error-on-warning = false

[analysis]
respect-type-ignore-comments = false
allowed-unresolved-imports = ["**"]
replace-imports-with-any = ["legacy.**"]

[src]
exclude = ["src", "lib"]

[environment]
root = "/tmp/untrusted"
API_KEY = "api_key=hardcoded_secret_value_12345"
"""

HARDENED_PYPROJECT = """\
[project]
name = "demo"

[tool.ty.environment]
python-version = "3.12"

[tool.ty.rules]
possibly-unresolved-reference = "warn"
possibly-missing-import = "error"
unresolved-import = "error"

[tool.ty.terminal]
error-on-warning = true
"""

INSECURE_PYPROJECT = """\
[tool.ty.rules]
unresolved-import = "ignore"
invalid-assignment = "ignore"

[tool.ty.src]
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
        assert "hardcoded_secret" in kinds
        assert "rules_all_ignore" in kinds
        assert "ignored_import_rules" in kinds
        assert "ignored_assignment_rules" in kinds
        assert "error_on_warning_false" in kinds
        assert "respect_type_ignore_false" in kinds
        assert "replace_imports_with_any" in kinds
        assert "allowed_unresolved_broad" in kinds
        assert "exclude_source" in kinds
        assert "insecure_extra_path" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_scores_well(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = TyAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].path == "pyproject.toml"

    def test_pyproject_ignores_non_ty_sections(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = TyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert all(f.lineno <= 6 for f in findings)

    def test_ty_toml_takes_precedence_over_pyproject(self, tmp_path: Path):
        (tmp_path / "ty.toml").write_text("[rules]\nall = \"ignore\"\n", encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[tool.ty.rules]\nall = "ignore"\n',
            encoding="utf-8",
        )
        analyzer = TyAnalyzer(str(tmp_path))
        assert len(analyzer.config_files()) == 1
        assert analyzer.config_files()[0].name == "ty.toml"

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = TyAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = TyFinding(
            kind="rules_all_ignore",
            severity="high",
            message='rules.all="ignore" disables all type checks',
            path="ty.toml",
            lineno=2,
            line='all = "ignore"',
        )
        assert "ty.toml:2" in finding.format()

    def test_generate_template(self):
        analyzer = TyAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "[tool.ty.rules]" in template
        assert "error-on-warning = true" in template

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
