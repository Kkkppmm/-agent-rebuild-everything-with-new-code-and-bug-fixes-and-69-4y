"""Tests for TyAnalyzer."""

from pathlib import Path

from devai.ty_analyzer import TyAnalyzer, TyFinding


INSECURE_PYPROJECT = """\
[project]
name = "demo"
version = "0.1.0"

[tool.ty]
python-version = "*"
search-path = ["/tmp/untrusted"]

[tool.ty.rules]
index-out-of-bounds = "ignore"
possibly-unbound = "warn"
* = "ignore"
password = "hardcoded-ty-password"
"""

INSECURE_TY_TOML = """\
[rules]
unresolved-import = "ignore"

[src]
exclude = ["src", "lib"]
extraPaths = ["/etc/passwd"]
"""

HARDENED_PYPROJECT = """\
[project]
name = "demo"
version = "0.1.0"

[tool.ty]
python-version = "3.12"

[tool.ty.src]
include = ["src"]
exclude = ["**/__pycache__", ".venv"]
"""


class TestTyAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = TyAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0

    def test_detects_ty_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = TyAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 1

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        (tmp_path / "ty.toml").write_text(INSECURE_TY_TOML, encoding="utf-8")
        analyzer = TyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "rule_ignored" in kinds
        assert "wildcard_rule_ignore" in kinds
        assert "exclude_source" in kinds
        assert "insecure_extra_path" in kinds
        assert "loose_python_version" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = TyAnalyzer(str(tmp_path))
        assert analyzer.health_score() >= 95.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = TyAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert isinstance(finding, TyFinding)
        assert "[" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = TyAnalyzer(str(tmp_path))
        assert "Ty configs: 1" in analyzer.summary()
        context = analyzer.to_context()
        assert "Ty analysis:" in context
        assert "ignored rules:" in context

    def test_generate_hardened_template(self, tmp_path: Path):
        analyzer = TyAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "[tool.ty]" in template
        assert "python-version" in template
