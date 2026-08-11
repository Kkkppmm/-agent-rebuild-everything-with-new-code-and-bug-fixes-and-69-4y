"""Tests for DevContainerAnalyzer."""

from pathlib import Path

from devai.devcontainer_analyzer import DevContainerAnalyzer, DevContainerFinding


INSECURE_DEVCONTAINER = """\
{
  "name": "Insecure",
  "image": "mcr.microsoft.com/devcontainers/python:latest",
  "runArgs": ["--privileged", "--network=host", "--cap-add=SYS_ADMIN"],
  "mounts": [
    "source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind"
  ],
  "remoteEnv": {
    "API_SECRET": "supersecret12345"
  },
  "postCreateCommand": "curl -fsSL https://example.com/install.sh | bash"
}
"""

HARDENED_DEVCONTAINER = """\
{
  "name": "Hardened",
  "image": "mcr.microsoft.com/devcontainers/python:1-3.12-bookworm",
  "remoteUser": "vscode",
  "postCreateCommand": "pip install -e '.[dev]'",
  "features": {
    "ghcr.io/devcontainers/features/common-utils:2": {}
  }
}
"""


class TestDevContainerAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = DevContainerAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        devcontainer_dir = tmp_path / ".devcontainer"
        devcontainer_dir.mkdir()
        (devcontainer_dir / "devcontainer.json").write_text(
            INSECURE_DEVCONTAINER, encoding="utf-8"
        )
        analyzer = DevContainerAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "privileged_mode" in kinds
        assert "host_network" in kinds
        assert "dangerous_capability" in kinds
        assert "docker_socket_mount" in kinds
        assert "secret_in_env" in kinds
        assert "curl_pipe_shell" in kinds
        assert "latest_tag" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / ".devcontainer.json").write_text(HARDENED_DEVCONTAINER, encoding="utf-8")
        analyzer = DevContainerAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.config_files == 1
        assert analyzer.infos[0].remote_user == "vscode"

    def test_finds_root_level_config(self, tmp_path: Path):
        (tmp_path / "devcontainer.json").write_text(HARDENED_DEVCONTAINER, encoding="utf-8")
        analyzer = DevContainerAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 1

    def test_summary_context_and_template(self, tmp_path: Path):
        (tmp_path / ".devcontainer.json").write_text(HARDENED_DEVCONTAINER, encoding="utf-8")
        analyzer = DevContainerAnalyzer(str(tmp_path))
        assert "Dev containers:" in analyzer.summary()
        assert "Dev container analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "remoteUser" in template
        assert "vscode" in template

    def test_invalid_json_reported(self, tmp_path: Path):
        (tmp_path / ".devcontainer.json").write_text("{not json", encoding="utf-8")
        analyzer = DevContainerAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "invalid_json" for f in findings)

    def test_finding_format(self):
        finding = DevContainerFinding(
            kind="privileged_mode",
            severity="high",
            message="privileged",
            path=".devcontainer/devcontainer.json",
            lineno=4,
        )
        assert "devcontainer.json:4" in finding.format()
        assert "high" in finding.format()
