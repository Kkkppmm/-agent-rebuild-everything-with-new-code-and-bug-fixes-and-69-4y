"""Tests for CibuildwheelAnalyzer."""

from pathlib import Path

from devai.cibuildwheel_analyzer import CibuildwheelAnalyzer, CibuildwheelFinding


INSECURE_PYPROJECT = """\
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "insecure-pkg"
version = "1.0.0"

[tool.cibuildwheel]
dependency-versions = "*"
before-all = "curl -s https://install.example.com/setup.sh | bash"
test-command = "pip install pytest && pytest {project}/tests"
environment-pass = ["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"]
manylinux-image = "docker.io/untrusted/manylinux:latest"

[tool.cibuildwheel.linux]
before-build = "pip install numpy"
repair-wheel-command = "pip install http://insecure-pypi.example.com/wheel.whl"
"""

INSECURE_CIBUILDWHEEL_TOML = """\
[tool.cibuildwheel]
before-test = "wget -qO- https://bootstrap.example.com/script.sh | sh"
test-command = "pip install requests"
TWINE_PASSWORD = "super-secret-password"
pypi-token = "pypi-AgEIcHlwaS5vcmcvY2k-EXAMPLETOKENEXAMPLETOKENEX"
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "secure-pkg"
version = "1.0.0"

[tool.cibuildwheel]
dependency-versions = ["pip==24.0", "setuptools==69.0.0", "wheel==0.42.0"]
manylinux-image = "quay.io/pypa/manylinux2014_x86_64"
musllinux-image = "quay.io/pypa/musllinux_x86_64"
test-command = "pip install pytest==7.4.0 && pytest {project}/tests"
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
        assert "curl_pipe_shell" in kinds
        assert "unpinned_dependency_versions" in kinds
        assert "unpinned_pip_install" in kinds
        assert "insecure_http" in kinds
        assert "sensitive_env_pass" in kinds
        assert "untrusted_image" in kinds
        assert analyzer.health_score() < 100.0

    def test_detects_cibuildwheel_toml_issues(self, tmp_path: Path):
        (tmp_path / "cibuildwheel.toml").write_text(INSECURE_CIBUILDWHEEL_TOML, encoding="utf-8")
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "curl_pipe_shell" in kinds
        assert "unpinned_pip_install" in kinds
        assert "hardcoded_secret" in kinds
        assert "pypi_token" in kinds

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high_medium = [f for f in findings if f.severity in ("high", "medium")]
        assert high_medium == []

    def test_finding_format(self):
        finding = CibuildwheelFinding(
            kind="curl_pipe_shell",
            severity="high",
            message="test message",
            path="pyproject.toml",
            lineno=3,
        )
        assert "pyproject.toml:3" in finding.format()

    def test_parses_hooks_and_platforms(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert len(analyzer.infos) == 1
        info = analyzer.infos[0]
        assert info.file_kind == "pyproject"
        assert "before-all" in info.build_hooks
        assert "linux" in info.platforms

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = CibuildwheelAnalyzer(str(tmp_path))
        assert "cibuildwheel configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "cibuildwheel analysis:" in ctx
        assert "health score:" in ctx

    def test_generate_hardened_config(self):
        analyzer = CibuildwheelAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "cibuildwheel.toml" in config
        assert "dependency-versions" in config
        assert "quay.io/pypa" in config

    def test_facade_cibuildwheel_method(self):
        from devai.facade import DevAI

        dev = DevAI.mock()
        analyzer = dev.cibuildwheel(".")
        assert isinstance(analyzer, CibuildwheelAnalyzer)
