"""Tests for Python packaging analyzers (setuptools, hatch, flit, pdm, pipfile, conda, rye, piptools)."""

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

INSECURE_HATCH = """\
[tool.hatch.envs.default]
dependencies = ["requests"]

[tool.hatch.publish.index]
url = "http://insecure-pypi.example.com/simple/"
token = "pypi-AgEIcHlwaS5vcmcCJDFlY2Jk..."
"""

HARDENED_HATCH = """\
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/demo"]

[project]
name = "demo"
version = "1.0.0"
dependencies = ["requests==2.31.0"]
"""

INSECURE_PDM = """\
[tool.pdm]
[[tool.pdm.source]]
url = "http://mirror.example.com/simple/"
verify_ssl = false

[project]
dependencies = ["bad-lib @ git+https://user:secret@github.com/example/bad-lib.git@main"]
"""

INSECURE_PIPFILE = """\
[[source]]
url = "http://insecure.example.com/simple"
verify_ssl = false

[packages]
requests = "*"
bad = {git = "https://user:token@github.com/example/bad.git", ref = "main"}

[scripts]
install = "curl -s https://install.example.com/script.sh | bash"
"""

INSECURE_CONDA = """\
name: demo
channels:
  - http://insecure-channel.example.com
dependencies:
  - python>=3.10
  - requests
"""

INSECURE_PIPTOOLS = """\
--extra-index-url http://insecure.example.com/simple
requests>=0
git+https://user:secret@github.com/example/pkg.git@main
"""

INSECURE_SETUPTOOLS = """\
[options]
install_requires =
    requests>=0
    bad @ git+https://user:token@github.com/example/bad.git@main

[upload]
password = hardcoded-pypi-password
"""

INSECURE_FLIT = """\
[tool.flit.metadata]
requires = ["requests>=0"]

[tool.flit.sdist]
include = [".aws/credentials"]
"""

INSECURE_RYE = """\
[tool.rye]
managed = true

[tool.rye.sources]
private = { url = "http://insecure.example.com/simple/" }

[project]
dependencies = ["requests = { version = \"*\" }"]
"""


@pytest.mark.parametrize(
    "analyzer_cls,config_name,config_text,ignore_text",
    [
        (HatchAnalyzer, "pyproject.toml", INSECURE_HATCH, '[project]\nname = "x"\n'),
        (PdmAnalyzer, "pyproject.toml", INSECURE_PDM, '[project]\nname = "x"\n'),
        (FlitAnalyzer, "pyproject.toml", INSECURE_FLIT, '[project]\nname = "x"\n'),
        (RyeAnalyzer, "pyproject.toml", INSECURE_RYE, '[project]\nname = "x"\n'),
    ],
)
def test_ignores_non_matching_pyproject(
    tmp_path: Path,
    analyzer_cls: type,
    config_name: str,
    config_text: str,
    ignore_text: str,
) -> None:
    (tmp_path / config_name).write_text(ignore_text, encoding="utf-8")
    analyzer = analyzer_cls(str(tmp_path))
    assert analyzer.stats.configs == 0


@pytest.mark.parametrize(
    "analyzer_cls,write_files,detect_kinds",
    [
        (
            HatchAnalyzer,
            lambda p: p.joinpath("pyproject.toml").write_text(INSECURE_HATCH, encoding="utf-8"),
            {"insecure_http", "pypi_token"},
        ),
        (
            PdmAnalyzer,
            lambda p: p.joinpath("pyproject.toml").write_text(INSECURE_PDM, encoding="utf-8"),
            {"insecure_http", "scm_credentials", "unpinned_git_dep"},
        ),
        (
            PipfileAnalyzer,
            lambda p: p.joinpath("Pipfile").write_text(INSECURE_PIPFILE, encoding="utf-8"),
            {"insecure_http", "scm_credentials", "curl_pipe_shell"},
        ),
        (
            CondaAnalyzer,
            lambda p: p.joinpath("environment.yml").write_text(INSECURE_CONDA, encoding="utf-8"),
            {"insecure_http", "dynamic_version"},
        ),
        (
            PipToolsAnalyzer,
            lambda p: p.joinpath("requirements.in").write_text(INSECURE_PIPTOOLS, encoding="utf-8"),
            {"insecure_http", "scm_credentials", "unpinned_git_dep"},
        ),
        (
            SetuptoolsAnalyzer,
            lambda p: p.joinpath("setup.cfg").write_text(INSECURE_SETUPTOOLS, encoding="utf-8"),
            {"hardcoded_secret", "scm_credentials", "dynamic_version"},
        ),
        (
            FlitAnalyzer,
            lambda p: p.joinpath("pyproject.toml").write_text(INSECURE_FLIT, encoding="utf-8"),
            {"dynamic_version", "sensitive_path"},
        ),
        (
            RyeAnalyzer,
            lambda p: p.joinpath("pyproject.toml").write_text(INSECURE_RYE, encoding="utf-8"),
            {"insecure_http", "dynamic_version"},
        ),
    ],
)
def test_detects_insecure_patterns(
    tmp_path: Path,
    analyzer_cls: type,
    write_files,
    detect_kinds: set[str],
) -> None:
    write_files(tmp_path)
    analyzer = analyzer_cls(str(tmp_path))
    kinds = {f.kind for f in analyzer.analyze()}
    assert detect_kinds.issubset(kinds)
    if analyzer.stats.high_severity > 0:
        assert analyzer.health_score() < 90.0


def test_hatch_hardened_scores_well(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(HARDENED_HATCH, encoding="utf-8")
    analyzer = HatchAnalyzer(str(tmp_path))
    assert analyzer.health_score() >= 95.0


def test_pdm_missing_lockfile(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pdm]\n[project]\nname = "demo"\n',
        encoding="utf-8",
    )
    analyzer = PdmAnalyzer(str(tmp_path))
    kinds = {f.kind for f in analyzer.analyze()}
    assert "missing_lockfile" in kinds


def test_pipfile_missing_lockfile(tmp_path: Path) -> None:
    (tmp_path / "Pipfile").write_text('[[source]]\nurl = "https://pypi.org/simple"\n', encoding="utf-8")
    analyzer = PipfileAnalyzer(str(tmp_path))
    kinds = {f.kind for f in analyzer.analyze()}
    assert "missing_lockfile" in kinds


def test_generate_hardened_config(tmp_path: Path) -> None:
    for cls in (
        HatchAnalyzer,
        PdmAnalyzer,
        PipfileAnalyzer,
        CondaAnalyzer,
        PipToolsAnalyzer,
        SetuptoolsAnalyzer,
        FlitAnalyzer,
        RyeAnalyzer,
    ):
        config = cls(str(tmp_path)).generate_hardened_config()
        assert len(config) > 20


def test_summary_and_context(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(INSECURE_HATCH, encoding="utf-8")
    analyzer = HatchAnalyzer(str(tmp_path))
    assert "Hatch configs:" in analyzer.summary()
    context = analyzer.to_context()
    assert "Hatch analysis:" in context
    assert "health score:" in context
