"""Tests for AzurePipelinesAnalyzer."""

from pathlib import Path

from devai.azure_pipelines_analyzer import AzurePipelinesAnalyzer, AzurePipelinesFinding


INSECURE_CONFIG = """
trigger:
  branches:
    include:
      - main

pr:
  branches:
    include:
      - '*'

pool:
  vmImage: ubuntu-latest

variables:
  API_TOKEN: "sk-live-hardcoded-secret"
  system.debug: true

stages:
  - stage: Build
    jobs:
      - job: Build
        steps:
          - checkout: self
          - task: Docker@latest
          - script: curl -sSL http://install.example.com/setup.sh | bash
          - script: echo Building $(Build.SourceBranch)
          - task: UsePythonVersion@0
            inputs:
              versionSpec: '3.12'

  - stage: Security
    jobs:
      - job: Scan
        displayName: Security scan
        steps:
          - script: devai security-scan .
            condition: failed()
"""

HARDENED_CONFIG = """
trigger:
  branches:
    include:
      - main

pr:
  branches:
    include:
      - main

pool:
  vmImage: ubuntu-latest

variables:
  pythonVersion: '3.12'

stages:
  - stage: Test
    jobs:
      - job: Test
        steps:
          - task: UsePythonVersion@0
            inputs:
              versionSpec: $(pythonVersion)
          - script: python -m pytest
            displayName: Run tests
"""


def _write_azure_pipeline(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "azure-pipelines.yml"
    path.write_text(content, encoding="utf-8")
    return path


class TestAzurePipelinesAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        _write_azure_pipeline(tmp_path, INSECURE_CONFIG)
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "unpinned_task" in kinds
        assert "system_debug" in kinds
        assert "pr_checkout" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_few_findings(self, tmp_path: Path):
        _write_azure_pipeline(tmp_path, HARDENED_CONFIG)
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        _write_azure_pipeline(tmp_path, HARDENED_CONFIG)
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        assert "Azure Pipelines:" in analyzer.summary()
        assert "health score" in analyzer.to_context()

    def test_generate_hardened_template(self):
        analyzer = AzurePipelinesAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "trigger:" in template
        assert "Security" in template

    def test_finding_format(self):
        finding = AzurePipelinesFinding(
            kind="test",
            severity="high",
            message="test message",
            path="azure-pipelines.yml",
            lineno=1,
        )
        assert "[high]" in finding.format()
