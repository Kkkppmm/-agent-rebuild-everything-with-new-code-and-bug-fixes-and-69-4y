"""Tests for CirrusCIAnalyzer."""

from pathlib import Path

from devai.cirrus_ci_analyzer import CirrusCIAnalyzer, CirrusCIFinding


INSECURE_CONFIG = """
task:
  ubuntu_instance:
    image: ubuntu:latest
    privileged: true
    network: host
  env:
    API_TOKEN: "sk-live-hardcoded-secret"
    password: "supersecret123"
  script: |
    curl -sSL http://install.example.com/setup.sh | bash
    echo Deploying $CIRRUS_CHANGE_TITLE on $CIRRUS_BRANCH
  container:
    dockerfile: Dockerfile
    docker_arguments:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc/passwd:/etc/passwd

gke_task:
  gke_container:
    cluster_name: my-cluster
    use_insecure_kubelet_readonly_port: true
    use_static_credentials: true
  env:
    SECRET_KEY: "hardcoded-value"
  script: wget http://repo.example.com/pkg.sh | bash

fetch_task:
  skip_tls_verify: true
  script: curl http://api.example.com/data
"""

HARDENED_CONFIG = """
task:
  ubuntu_instance:
    image: ubuntu:24.04

  env:
    PYTHON_VERSION: "3.12"

  test_script: |
    pip install -e '.[dev]'
    python -m pytest

security_scan_task:
  ubuntu_instance:
    image: ubuntu:24.04

  test_script: |
    pip install devai
    devai security-scan .
"""


def _write_cirrus_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / ".cirrus.yml"
    path.write_text(content, encoding="utf-8")
    return path


class TestCirrusCIAnalyzer:
    def test_no_pipelines_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = CirrusCIAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        _write_cirrus_config(tmp_path, INSECURE_CONFIG)
        analyzer = CirrusCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "plaintext_env_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "privileged_container" in kinds
        assert "host_network" in kinds
        assert "docker_socket_mount" in kinds
        assert "sensitive_volume" in kinds
        assert "script_injection" in kinds
        assert "latest_tag" in kinds
        assert "insecure_skip_verify" in kinds
        assert "insecure_kubelet" in kinds
        assert "static_credentials" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_few_findings(self, tmp_path: Path):
        _write_cirrus_config(tmp_path, HARDENED_CONFIG)
        analyzer = CirrusCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        _write_cirrus_config(tmp_path, HARDENED_CONFIG)
        analyzer = CirrusCIAnalyzer(str(tmp_path))
        assert "Cirrus CI:" in analyzer.summary()
        assert "health score" in analyzer.to_context()

    def test_generate_hardened_template(self):
        analyzer = CirrusCIAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "ubuntu_instance:" in template
        assert "security_scan_task" in template

    def test_finding_format(self):
        finding = CirrusCIFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test",
            path=".cirrus.yml",
            lineno=1,
        )
        assert "[high]" in finding.format()
