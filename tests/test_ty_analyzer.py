"""Tests for TyAnalyzer."""

from pathlib import Path

from devai.ty_analyzer import TyAnalyzer, TyFinding


INSECURE_PYPROJECT = """\
[project]
name = "example"
version = "0.1.0"

[tool.ty.rules]
all = "ignore"
unresolved-import = "ignore"
possibly-missing-import = "ignore"

[tool.ty.src]
exclude = ["src", "lib"]

[tool.ty.terminal]
error-on-warning = false
respect-type-ignore-comments = false
api_key = "hardcoded-secret-token-12345"
remote = "http://evil.com/index"
"""

HARDENED_PYPROJECT = """\
[project]
name = "example"
version = "0.1.0"

[tool.ty.environment]
python-version = "3.12"

[tool.ty.src]
include = ["src"]
exclude = ["**/tests"]

[tool.ty.rules]
all = "error"
possibly-missing-import = "error"
unresolved-import = "warn"

[tool.ty.terminal]
error-on-warning = true
"""

INSECURE_TY_TOML = """\
[rules]
all = "warn"
possibly-unresolved-reference = "ignore"
division-by-zero = "ignore"
"""


class TestTyAnalyzer:
    def test_detects_insecure_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = TyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "all_rules_ignored" in kinds
        assert "critical_rule_ignored" in kinds
        assert "exclude_source" in kinds
        assert "error_on_warning_disabled" in kinds
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_clean(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = TyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_detects_ty_toml(self, tmp_path: Path):
        (tmp_path / "ty.toml").write_text(INSECURE_TY_TOML, encoding="utf-8")
        analyzer = TyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.path == "ty.toml" for f in findings)
        assert any(f.kind == "all_rules_warn" for f in findings)

    def test_no_config_returns_clean(self, tmp_path: Path):
        analyzer = TyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.summary() == "ty configs: none found"

    def test_finding_format(self):
        finding = TyFinding(
            kind="all_rules_ignored",
            severity="high",
            message="test message",
            path="pyproject.toml",
            lineno=5,
        )
        assert "[high]" in finding.format()
        assert "pyproject.toml:5" in finding.format()

    def test_generate_template(self):
        template = TyAnalyzer(".").generate_hardened_template()
        assert "[tool.ty.rules]" in template
        assert 'all = "error"' in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = TyAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "ty configuration analysis" in context
        assert "health score" in context
