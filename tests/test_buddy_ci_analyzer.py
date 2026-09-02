"""Tests for BuddyCIAnalyzer."""

from pathlib import Path

from devai.buddy_ci_analyzer import BuddyCIAnalyzer, BuddyCIFinding


INSECURE_CONFIG = """
- pipeline: "Insecure Pipeline"
  on: "PUSH"
  refs:
    - "refs/heads/main"
  actions:
    - action: "Deploy"
      type: "BUILD"
      docker_image_name: "library/ubuntu"
      docker_image_tag: "latest"
      docker_privileged_mode: true
      docker_network_mode: "host"
      docker_volumes:
        - "/var/run/docker.sock:/var/run/docker.sock"
        - "/etc/passwd:/etc/passwd"
      execute_commands:
        - "curl -sSL http://install.example.com/setup.sh | bash"
        - "echo Deploying $BUDDY_EXECUTION_PULL_REQUEST_TITLE"
      set_env:
        API_TOKEN: "sk-live-hardcoded-secret"
        password: "supersecret123"

    - action: "security-audit"
      type: "BUILD"
      docker_image_name: "library/python"
      docker_image_tag: "main"
      execute_commands:
        - "bandit -r ."
"""

HARDENED_CONFIG = """
- pipeline: "Hardened Pipeline"
  on: "PUSH"
  refs:
    - "refs/heads/main"
  fail_on_prepare_env_warning: true
  actions:
    - action: "Test"
      type: "BUILD"
      docker_image_name: "library/python"
      docker_image_tag: "3.12-slim"
      execute_commands:
        - "pip install -e '.[dev]'"
        - "python -m pytest"

    - action: "Security Scan"
      type: "BUILD"
      docker_image_name: "library/python"
      docker_image_tag: "3.12-slim"
      execute_commands:
        - "pip install devai"
        - "devai security-scan ."
"""


def _write_buddy_config(tmp_path: Path, content: str) -> Path:
    buddy_dir = tmp_path / ".buddy"
    buddy_dir.mkdir()
    path = buddy_dir / "pipeline.yml"
    path.write_text(content, encoding="utf-8")
    return path


class TestBuddyCIAnalyzer:
    def test_no_pipelines_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = BuddyCIAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        _write_buddy_config(tmp_path, INSECURE_CONFIG)
        analyzer = BuddyCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "privileged_container" in kinds
        assert "host_network" in kinds
        assert "docker_socket_mount" in kinds
        assert "sensitive_volume" in kinds
        assert "script_injection" in kinds
        assert "latest_tag" in kinds
        assert "floating_image_tag" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_few_findings(self, tmp_path: Path):
        _write_buddy_config(tmp_path, HARDENED_CONFIG)
        analyzer = BuddyCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        _write_buddy_config(tmp_path, HARDENED_CONFIG)
        analyzer = BuddyCIAnalyzer(str(tmp_path))
        assert "Buddy CI:" in analyzer.summary()
        assert "health score" in analyzer.to_context()

    def test_generate_hardened_template(self):
        analyzer = BuddyCIAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "pipeline:" in template
        assert "Security Scan" in template

    def test_finding_format(self):
        finding = BuddyCIFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test",
            path="pipeline.yml",
            lineno=1,
        )
        assert "[high]" in finding.format()
