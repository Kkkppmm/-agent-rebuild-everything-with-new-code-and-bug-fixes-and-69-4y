"""Tests for TaskfileAnalyzer."""

from pathlib import Path

from devai.taskfile_analyzer import TaskfileAnalyzer, TaskfileFinding


INSECURE_TASKFILE = """\
version: '3'

dotenv: ['.env']

env:
  API_KEY: hardcoded-secret-token-12345
  DATABASE_PASSWORD: supersecret
  NODE_ENV: development

tasks:
  setup:
    desc: Install dependencies
    cmds:
      - curl https://example.com/install.sh | bash
      - sudo apt-get install -y build-essential

  deploy:
    desc: Deploy to production
    cmds:
      - rm -rf /
      - chmod 777 /var/www
      - git push origin main --force
      - wget http://insecure.example.com/deploy.sh | sh

  clone:
    cmds:
      - git clone https://user:password@github.com/org/repo.git
"""

HARDENED_TASKFILE = """\
version: '3'

dotenv: ['.env.example']

env:
  NODE_ENV: development

tasks:
  setup:
    desc: Install dependencies
    cmds:
      - npm ci

  test:
    desc: Run tests
    cmds:
      - npm test
"""


class TestTaskfileAnalyzer:
    def test_detects_insecure_taskfile(self, tmp_path: Path):
        (tmp_path / "Taskfile.yml").write_text(INSECURE_TASKFILE, encoding="utf-8")
        analyzer = TaskfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "sudo_usage" in kinds
        assert "destructive_rm" in kinds
        assert "chmod_777" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "dotenv_load" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_passes(self, tmp_path: Path):
        (tmp_path / "Taskfile.yml").write_text(HARDENED_TASKFILE, encoding="utf-8")
        analyzer = TaskfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_full_score(self, tmp_path: Path):
        analyzer = TaskfileAnalyzer(str(tmp_path))
        assert analyzer.stats.taskfiles == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = TaskfileFinding(
            kind="test",
            severity="high",
            message="test message",
            path="Taskfile.yml",
            lineno=1,
        )
        assert "[high] Taskfile.yml:1" in finding.format()

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / "Taskfile.yml").write_text(INSECURE_TASKFILE, encoding="utf-8")
        analyzer = TaskfileAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Taskfile analysis:" in context
        assert "piping curl/wget to shell" in context or "hardcoded secret" in context

    def test_generate_hardened_config(self):
        analyzer = TaskfileAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "version:" in config
        assert ".env.example" in config
