"""Tests for DevContainerAnalyzer."""

from pathlib import Path

from devai.devcontainer_analyzer import DevContainerAnalyzer, DevContainerFinding


INSECURE_CONFIG = """{
  "name": "Insecure",
  "image": "mcr.microsoft.com/devcontainers/python:latest",
  "privileged": true,
  "runArgs": ["--privileged"],
  "containerEnv": {
    "API_TOKEN": "sk-live-hardcoded-secret-key-12345",
    "password": "supersecret123"
  },
  "mounts": [
    "source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind"
  ],
  "postCreateCommand": "curl -sSL http://install.example.com/setup.sh | bash",
  "forwardPorts": [22, 8080]
}"""

HARDENED_CONFIG = """{
  "name": "Python Dev Container",
  "image": "mcr.microsoft.com/devcontainers/python:1-3.12",
  "remoteUser": "vscode",
  "workspaceFolder": "/workspaces/${localWorkspaceFolderBasename}",
  "postCreateCommand": "pip install -e .[dev]",
  "forwardPorts": [8000]
}"""


def _write_devcontainer(tmp_path: Path, content: str, name: str = "devcontainer.json") -> Path:
    if "/" in name:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
    else:
        dev_dir = tmp_path / ".devcontainer"
        dev_dir.mkdir(exist_ok=True)
        path = dev_dir / name
    path.write_text(content, encoding="utf-8")
    return path


class TestDevContainerAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = DevContainerAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        _write_devcontainer(tmp_path, INSECURE_CONFIG)
        analyzer = DevContainerAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "privileged" in kinds
        assert "docker_socket_mount" in kinds
        assert "curl_pipe_shell" in kinds
        assert "unpinned_image" in kinds
        assert "no_remote_user" in kinds
        assert analyzer.stats.high_severity >= 4

    def test_hardened_config_has_fewer_findings(self, tmp_path: Path):
        _write_devcontainer(tmp_path, HARDENED_CONFIG)
        analyzer = DevContainerAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() == 100.0

    def test_finding_format(self):
        finding = DevContainerFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path=".devcontainer/devcontainer.json",
            lineno=5,
            line="password: secret",
        )
        assert "[high]" in finding.format()
        assert "devcontainer.json:5" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = DevContainerAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "DevContainerAnalyzer" in template
        assert "remoteUser" in template

    def test_to_context(self, tmp_path: Path):
        _write_devcontainer(tmp_path, HARDENED_CONFIG)
        analyzer = DevContainerAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Dev container analysis:" in context
        assert "health score:" in context

    def test_root_devcontainer_json(self, tmp_path: Path):
        path = tmp_path / "devcontainer.json"
        path.write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = DevContainerAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
