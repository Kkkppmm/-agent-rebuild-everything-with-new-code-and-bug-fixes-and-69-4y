"""Tests for CibuildwheelAnalyzer."""

from pathlib import Path

from devai.cibuildwheel_analyzer import CibuildwheelAnalyzer, CibuildwheelFinding


INSECURE_PYPROJECT = """\
[build-system]
requires = ["cibuildwheel"]
build-backend = "setuptools.build_meta"

[project]
name = "insecure-wheel"
version = "1.0.0"

[tool.cibuildwheel]
build = "cp3*"
test-command = "pytest {project}/tests"
before-build = "curl -s https://install.example.com/setup.sh | bash"
environment-pass = ["PYPI_SECRET_TOKEN", "AWS_SECRET_ACCESS_KEY"]

[tool.cibuildwheel.linux]
dependency-versions = ["numpy>=1.0"]
pip-args = "--extra-index-url http://insecure-pypi.example.com/simple"
CIBW_PYPI_TOKEN = "pypi-AgEIcHlwaS5vcmcvY2k-EXAMPLETOKENEXAMPLETOKENEX"

[tool.cibuildwheel.macos]
before-all = "pip install git+https://user:secret-token@github.com/example/pkg.git@main"
"""

INSECURE_CIBUILDWHEEL_TOML = """\
[tool.cibuildwheel]
test-command = "pytest"
TWINE_PASSWORD = "super-secret-password"
PIP_TRUSTED_HOST = "pypi.example.com"

[tool.cibuildwheel.linux]
before-build = "pip install requests=*"
index-url = "http://pypi.example.com/simple"
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["cibuildwheel"]
build-backend = "setuptools.build_meta"

[project]
name = "secure-wheel"
version = "1.0.0"

[tool.cibuildwheel]
build = "cp3*"
test-command = "pytest {project}/tests"

[tool.cibuildwheel.linux]
dependency-versions = ["numpy==1.26.0"]
"""


class TestCibuildwheelAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_ignores_non_cibuildwheel_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "plain"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "dynamic_version" in kinds
        assert "curl_pipe_shell" in kinds
        assert "pypi_token" in kinds
        assert "sensitive_env_pass" in kinds
        assert analyzer.health_score() < 100.0

    def test_detects_cibuildwheel_toml_issues(self, tmp_path: Path):
        (tmp_path / "cibuildwheel.toml").write_text(INSECURE_CIBUILDWHEEL_TOML, encoding="utf-8")
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "dynamic_version" in kinds
        assert "insecure_http" in kinds
        assert "trusted_host" in kinds
        assert "hardcoded_secret" in kinds

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high_medium = [f for f in findings if f.severity in ("high", "medium")]
        assert high_medium == []

    def test_finding_format(self):
        finding = CibuildwheelFinding(
            kind="pypi_token",
            severity="high",
            message="test message",
            path="pyproject.toml",
            lineno=10,
        )
        assert "[high]" in finding.format()
        assert "pyproject.toml:10" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        assert "finding(s)" in analyzer.summary()
        context = analyzer.to_context()
        assert "cibuildwheel analysis:" in context
        assert "health score:" in context

    def test_generate_hardened_config(self):
        analyzer = CibuildwheelAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "cibuildwheel" in config
        assert "CIBW_PYPI_TOKEN" in config
