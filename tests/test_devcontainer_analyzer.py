"""Tests for DevContainerAnalyzer."""

from pathlib import Path

from devai.devcontainer_analyzer import DevContainerAnalyzer, DevContainerFinding


INSECURE_CONFIG = """{
  "name": "Insecure Dev",
  "image": "mcr.microsoft.com/devcontainers/python:latest",
  "remoteUser": "root",
  "privileged": true,
  "runArgs": ["--privileged"],
  "capAdd": ["SYS_ADMIN"],
  "securityOpt": ["seccomp:unconfined"],
  "containerEnv": {
    "API_KEY": "sk-live-hardcoded-secret",
    "password": "supersecret123"
  },
  "mounts": [
    "source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind",
    "source=/,target=/host-root,type=bind"
  ],
  "postCreateCommand": "curl -sSL http://install.example.com/setup.sh | bash"
}"""

HARDENED_CONFIG = """{
  "name": "Secure Dev",
  "image": "mcr.microsoft.com/devcontainers/python:3.12",
  "remoteUser": "vscode",
  "features": {
    "ghcr.io/devcontainers/features/git:1": {}
  },
  "postCreateCommand": "pip install -e '.[dev]'",
  "forwardPorts": [8000]
}"""


def _write_devcontainer(tmp_path: Path, content: str) -> Path:
    dev_dir = tmp_path / ".devcontainer"
    dev_dir.mkdir()
    path = dev_dir / "devcontainer.json"
    path.write_text(content, encoding="utf-8")
    return path


class TestDevContainerAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = DevContainerAnalyzer(str(tmp_path))
        assert analyzer.stats.containers == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        _write_devcontainer(tmp_path, INSECURE_CONFIG)
        analyzer = DevContainerAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "privileged" in kinds
        assert "root_user" in kinds
        assert "docker_socket_mount" in kinds
        assert "sensitive_host_mount" in kinds
        assert "curl_pipe_shell" in kinds
        assert "dangerous_capability" in kinds
        assert "unconfined_security" in kinds
        assert "latest_image_tag" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_few_findings(self, tmp_path: Path):
        _write_devcontainer(tmp_path, HARDENED_CONFIG)
        analyzer = DevContainerAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_compose_file_scanned(self, tmp_path: Path):
        dev_dir = tmp_path / ".devcontainer"
        dev_dir.mkdir()
        (dev_dir / "devcontainer.json").write_text(HARDENED_CONFIG, encoding="utf-8")
        (dev_dir / "docker-compose.yml").write_text(
            "services:\n  app:\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
            encoding="utf-8",
        )
        analyzer = DevContainerAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "privileged" in kinds
        assert "docker_socket_mount" in kinds

    def test_summary_and_context(self, tmp_path: Path):
        _write_devcontainer(tmp_path, HARDENED_CONFIG)
        analyzer = DevContainerAnalyzer(str(tmp_path))
        assert "Dev containers: 1 config(s)" in analyzer.summary()
        context = analyzer.to_context()
        assert "Dev container analysis:" in context
        assert "health score:" in context

    def test_generate_hardened_template(self, tmp_path: Path):
        analyzer = DevContainerAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "remoteUser" in template
        assert "vscode" in template

    def test_finding_format(self):
        finding = DevContainerFinding(
            kind="privileged",
            severity="high",
            message="test message",
            path=".devcontainer/devcontainer.json",
            lineno=5,
        )
        assert "high" in finding.format()
        assert "test message" in finding.format()
