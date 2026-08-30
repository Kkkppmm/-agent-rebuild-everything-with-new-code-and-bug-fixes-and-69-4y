"""Tests for MypyAnalyzer."""

from pathlib import Path

from devai.mypy_analyzer import MypyAnalyzer, MypyFinding


INSECURE_MYPY_INI = """\
[mypy]
python_version = 3.10
strict = false
ignore_missing_imports = true
follow_imports = skip
disallow_untyped_defs = false
check_untyped_defs = false
warn_return_any = false
allow_untyped_globals = true
allow_redefinition = true
warn_unused_ignores = false
exclude = src, lib
mypy_path = /tmp/untrusted
api_key = api_key=hardcoded_secret_value_12345
disable_error_code = ["import-untyped", "no-untyped-def"]

[mypy-settings.*]
ignore_missing_imports = true
"""

HARDENED_PYPROJECT = """\
[project]
name = "demo"

[tool.mypy]
python_version = "3.10"
strict = true
warn_return_any = true
warn_unused_ignores = true
disallow_untyped_defs = true
check_untyped_defs = true

[[tool.mypy.overrides]]
module = "tests.*"
disallow_untyped_defs = false
"""

INSECURE_SETUP_CFG = """\
[metadata]
name = demo

[mypy]
ignore_missing_imports = true
follow_imports = skip
"""

INSECURE_PYPROJECT = """\
[tool.mypy]
strict = false
ignore_missing_imports = true

[tool.pytest.ini_options]
addopts = "-q"
"""


class TestMypyAnalyzer:
    def test_detects_insecure_mypy_ini(self, tmp_path: Path):
        (tmp_path / "mypy.ini").write_text(INSECURE_MYPY_INI, encoding="utf-8")
        analyzer = MypyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "ignore_missing_imports" in kinds
        assert "follow_imports_skip" in kinds
        assert "strict_disabled" in kinds
        assert "disallow_untyped_defs_false" in kinds
        assert "check_untyped_defs_false" in kinds
        assert "allow_untyped_globals" in kinds
        assert "exclude_source" in kinds
        assert "insecure_mypy_path" in kinds
        assert "disabled_error_codes" in kinds
        assert "per_module_sensitive_override" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_scores_well(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = MypyAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].strict is True

    def test_setup_cfg_mypy_section(self, tmp_path: Path):
        (tmp_path / "setup.cfg").write_text(INSECURE_SETUP_CFG, encoding="utf-8")
        analyzer = MypyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "ignore_missing_imports" in kinds
        assert "follow_imports_skip" in kinds
        assert all("setup.cfg" in f.path for f in findings)

    def test_pyproject_ignores_non_mypy_sections(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = MypyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "strict_disabled" in kinds
        assert "ignore_missing_imports" in kinds
        assert all(f.lineno <= 4 for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = MypyAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = MypyFinding(
            kind="ignore_missing_imports",
            severity="medium",
            message="test message",
            path="mypy.ini",
            lineno=3,
            line="ignore_missing_imports = true",
        )
        assert "mypy.ini:3" in finding.format()
        assert "test message" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = MypyAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "[tool.mypy]" in template
        assert "strict = true" in template
        assert "disallow_untyped_defs = true" in template

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / "mypy.ini").write_text("ignore_missing_imports = true\n", encoding="utf-8")
        analyzer = MypyAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Mypy analysis:" in context
        assert "ignore_missing_imports" in context
