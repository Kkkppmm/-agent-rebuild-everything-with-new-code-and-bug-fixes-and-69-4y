"""Tests for DevContainerAnalyzer."""

from pathlib import Path

from devai.devcontainer_analyzer import DevContainerAnalyzer, DevContainerFinding


INSECURE_CONFIG = """
{
  "name": "Insecure Dev Container",
  "image": "mcr.microsoft.com/devcontainers/python:latest",
  "remoteUser": "root",
  "containerEnv": {
    "API_TOKEN": "sk-live-hardcoded-secret",
    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"
  },
  "runArgs": [
    "--privileged",
    "--network=host",
    "-v", "/var/run/docker.sock:/var/run/docker.sock",
    "--cap-add=SYS_ADMIN"
  ],
  "mounts": [
    "source=/,target=/host,type=bind"
  ],
  "forwardPorts": [0],
  "postCreateCommand": "curl -sSL http://install.example.com/setup.sh | bash",
  "initializeCommand": "echo ${localWorkspaceFolder}"
}
"""

HARDENED_CONFIG = """
{
  "name": "Hardened Dev Container",
  "image": "mcr.microsoft.com/devcontainers/python:1-3.12-bookworm",
  "remoteUser": "vscode",
  "containerEnv": {
    "PYTHONUNBUFFERED": "1"
  },
  "remoteEnv": {
    "API_ENDPOINT": "${localEnv:API_ENDPOINT}"
  },
  "forwardPorts": [8000],
  "postCreateCommand": "pip install -r requirements.txt",
  "runArgs": [
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges"
  ]
}
"""


def _write_devcontainer(tmp_path: Path, content: str) -> Path:
    dev_dir = tmp_path / ".devcontainer"
    dev_dir.mkdir(parents=True)
    path = dev_dir / "devcontainer.json"
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
        assert "plaintext_aws_key" in kinds
        assert "curl_pipe_shell" in kinds
        assert "privileged_container" in kinds
        assert "docker_socket_mount" in kinds
        assert "host_mount" in kinds
        assert "host_network" in kinds
        assert "dangerous_capability" in kinds
        assert "latest_image_tag" in kinds
        assert "root_user" in kinds
        assert "forward_all_ports" in kinds
        assert "lifecycle_injection" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_few_findings(self, tmp_path: Path):
        _write_devcontainer(tmp_path, HARDENED_CONFIG)
        analyzer = DevContainerAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) == 0
        assert analyzer.health_score() == 100.0

    def test_finding_format(self, tmp_path: Path):
        _write_devcontainer(tmp_path, INSECURE_CONFIG)
        analyzer = DevContainerAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert all(isinstance(f, DevContainerFinding) for f in findings)
        assert all(f.path == ".devcontainer/devcontainer.json" for f in findings)
        assert all(
            "[high]" in f.format() or "[medium]" in f.format() or "[low]" in f.format()
            for f in findings
        )

    def test_summary_and_context(self, tmp_path: Path):
        _write_devcontainer(tmp_path, HARDENED_CONFIG)
        analyzer = DevContainerAnalyzer(str(tmp_path))
        assert "Dev containers: 1 config(s)" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Dev container config analysis:" in ctx
        assert "health score: 100.0/100" in ctx

    def test_generate_hardened_template(self, tmp_path: Path):
        analyzer = DevContainerAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "remoteUser" in template
        assert "cap-drop=ALL" in template

    def test_root_devcontainer_json(self, tmp_path: Path):
        (tmp_path / ".devcontainer.json").write_text(
            '{"name": "root config", "image": "python:3.12", "remoteUser": "vscode"}',
            encoding="utf-8",
        )
        analyzer = DevContainerAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
