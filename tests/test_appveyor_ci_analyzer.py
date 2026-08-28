"""Tests for AppVeyorCIAnalyzer."""

from pathlib import Path

from devai.appveyor_ci_analyzer import AppVeyorCIAnalyzer, AppVeyorCIFinding


INSECURE_CONFIG = """
version: latest
image: Visual Studio 2022
enable_rdp: true
publish_wan_artifacts: true

environment:
  API_TOKEN: "sk-live-hardcoded-secret"
  password: "supersecret123"

install:
  - curl -sSL http://install.example.com/setup.sh | bash
  - echo Building %APPVEYOR_PULL_REQUEST_TITLE%

deploy:
  api_key: "cleartext-deploy-key-12345"
  provider: GitHub
"""

HARDENED_CONFIG = """
version: 1.0.{build}
image: Visual Studio 2022

environment:
  matrix:
    - PYTHON: "C:\\Python312"
      PYTHON_VERSION: "3.12"

install:
  - "%PYTHON%\\python.exe -m pip install -e .[dev]"

build_script:
  - "%PYTHON%\\python.exe -m pytest"

test_script:
  - "%PYTHON%\\python.exe -m devai security-scan ."
"""


def _write_appveyor_config(tmp_path: Path, content: str, name: str = "appveyor.yml") -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


class TestAppVeyorCIAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = AppVeyorCIAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        _write_appveyor_config(tmp_path, INSECURE_CONFIG)
        analyzer = AppVeyorCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "api_key_deploy" in kinds
        assert "rdp_enabled" in kinds
        assert "script_injection" in kinds
        assert "unpinned_version" in kinds
        assert analyzer.stats.high_severity >= 4

    def test_hardened_config_has_fewer_findings(self, tmp_path: Path):
        _write_appveyor_config(tmp_path, HARDENED_CONFIG)
        analyzer = AppVeyorCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() == 100.0

    def test_finding_format(self):
        finding = AppVeyorCIFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="appveyor.yml",
            lineno=5,
            line="password: secret",
        )
        assert "[high]" in finding.format()
        assert "appveyor.yml:5" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = AppVeyorCIAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "AppVeyorCIAnalyzer" in template
        assert "deploy: off" in template

    def test_to_context(self, tmp_path: Path):
        _write_appveyor_config(tmp_path, HARDENED_CONFIG)
        analyzer = AppVeyorCIAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "AppVeyor CI analysis:" in context
        assert "health score:" in context

    def test_dot_appveyor_filename(self, tmp_path: Path):
        _write_appveyor_config(tmp_path, HARDENED_CONFIG, name=".appveyor.yml")
        analyzer = AppVeyorCIAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
