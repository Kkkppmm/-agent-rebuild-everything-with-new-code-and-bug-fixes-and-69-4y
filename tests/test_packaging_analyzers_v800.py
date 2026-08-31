"""Tests for Python packaging analyzers added in v8.0.0."""

from pathlib import Path

import pytest

from devai.conda_analyzer import CondaAnalyzer
from devai.flit_analyzer import FlitAnalyzer
from devai.hatch_analyzer import HatchAnalyzer
from devai.pdm_analyzer import PdmAnalyzer
from devai.pipfile_analyzer import PipfileAnalyzer
from devai.piptools_analyzer import PipToolsAnalyzer
from devai.rye_analyzer import RyeAnalyzer
from devai.setuptools_analyzer import SetuptoolsAnalyzer

INSECURE_PYPROJECT = """\
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.envs.default]
dependencies = ["requests>=2.0"]

[tool.hatch.envs.default.scripts]
setup = "curl -s https://install.example.com/script.sh | bash"

[[tool.hatch.envs.default.index]]
url = "http://insecure-pypi.example.com/simple/"
password = "hardcoded-pypi-password"
"""

INSECURE_SETUP_PY = """\
from setuptools import setup
setup(
    name="example",
    install_requires=["flask", "requests>=2.0"],
    dependency_links=["http://insecure.example.com/packages/"],
    password="hardcoded-setuptools-password",
)
"""

INSECURE_PIPFILE = """\
[[source]]
url = "http://insecure-pypi.example.com/simple"
verify_ssl = false

[packages]
requests = ">=2.0"
flask = "*"
"""

INSECURE_CONDA = """\
name: myenv
channels:
  - http://insecure-channel.example.com
dependencies:
  - python>=3.10
  - requests
"""

INSECURE_REQUIREMENTS_IN = """\
--index-url http://insecure-pypi.example.com/simple/
requests>=2.0
flask
git+https://user:secret-token@github.com/example/bad-lib.git@main
"""

HARDENED_PYPROJECT = """\
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "example"
version = "1.0.0"
dependencies = ["requests==2.31.0"]
"""


@pytest.mark.parametrize(
    "analyzer_cls,config_name,config_content",
    [
        (SetuptoolsAnalyzer, "setup.py", INSECURE_SETUP_PY),
        (HatchAnalyzer, "pyproject.toml", INSECURE_PYPROJECT),
        (FlitAnalyzer, "pyproject.toml", INSECURE_PYPROJECT.replace("hatch", "flit")),
        (PdmAnalyzer, "pyproject.toml", INSECURE_PYPROJECT.replace("hatch", "pdm")),
        (PipfileAnalyzer, "Pipfile", INSECURE_PIPFILE),
        (CondaAnalyzer, "environment.yml", INSECURE_CONDA),
        (RyeAnalyzer, "pyproject.toml", INSECURE_PYPROJECT.replace("hatch", "rye")),
        (PipToolsAnalyzer, "requirements.in", INSECURE_REQUIREMENTS_IN),
    ],
)
def test_detects_insecure_patterns(
    tmp_path: Path,
    analyzer_cls: type,
    config_name: str,
    config_content: str,
) -> None:
    (tmp_path / config_name).write_text(config_content, encoding="utf-8")
    analyzer = analyzer_cls(str(tmp_path))
    findings = analyzer.analyze()
    kinds = {f.kind for f in findings}
    assert "insecure_http" in kinds or "hardcoded_secret" in kinds or "dynamic_version" in kinds
    assert analyzer.health_score() < 90.0


@pytest.mark.parametrize(
    "analyzer_cls",
    [
        SetuptoolsAnalyzer,
        HatchAnalyzer,
        FlitAnalyzer,
        PdmAnalyzer,
        PipfileAnalyzer,
        CondaAnalyzer,
        RyeAnalyzer,
        PipToolsAnalyzer,
    ],
)
def test_no_configs_returns_perfect_score(tmp_path: Path, analyzer_cls: type) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    analyzer = analyzer_cls(str(tmp_path))
    assert analyzer.stats.configs == 0
    assert analyzer.health_score() == 100.0


@pytest.mark.parametrize(
    "analyzer_cls",
    [
        SetuptoolsAnalyzer,
        HatchAnalyzer,
        FlitAnalyzer,
        PdmAnalyzer,
        PipfileAnalyzer,
        CondaAnalyzer,
        RyeAnalyzer,
        PipToolsAnalyzer,
    ],
)
def test_summary_and_context(tmp_path: Path, analyzer_cls: type) -> None:
    (tmp_path / "setup.py").write_text(INSECURE_SETUP_PY, encoding="utf-8")
    analyzer = analyzer_cls(str(tmp_path))
    assert "config" in analyzer.summary().lower()
    assert "health score" in analyzer.to_context().lower()


def test_hatch_hardened_config_scores_well(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
    analyzer = HatchAnalyzer(str(tmp_path))
    assert analyzer.health_score() >= 95.0


def test_pdm_missing_lockfile(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pdm]\nversion = { source = "file" }\n',
        encoding="utf-8",
    )
    analyzer = PdmAnalyzer(str(tmp_path))
    kinds = {f.kind for f in analyzer.analyze()}
    assert "missing_lockfile" in kinds


def test_pipfile_missing_lockfile(tmp_path: Path) -> None:
    (tmp_path / "Pipfile").write_text("[packages]\nrequests = \"*\"\n", encoding="utf-8")
    analyzer = PipfileAnalyzer(str(tmp_path))
    kinds = {f.kind for f in analyzer.analyze()}
    assert "missing_lockfile" in kinds


def test_piptools_detects_requirements_in_suffix(tmp_path: Path) -> None:
    (tmp_path / "requirements-dev.in").write_text(INSECURE_REQUIREMENTS_IN, encoding="utf-8")
    analyzer = PipToolsAnalyzer(str(tmp_path))
    assert analyzer.stats.configs >= 1
