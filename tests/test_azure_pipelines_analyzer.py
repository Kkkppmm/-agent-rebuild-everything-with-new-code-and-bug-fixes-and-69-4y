"""Tests for AzurePipelinesAnalyzer."""

from pathlib import Path

from devai.azure_pipelines_analyzer import AzurePipelinesAnalyzer, AzurePipelinesFinding


INSECURE_PIPELINE = """
trigger:
  - main

pool:
  vmImage: ubuntu-latest

steps:
  - task: SomeTask@main
    inputs:
      foo: bar

  - script: curl -fsSL https://example.com/install.sh | bash
    env:
      API_SECRET: hardcoded-secret-value

  - bash: echo $(Build.SourceBranch)
    env:
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)

  - pwsh: |
      powershell -ExecutionPolicy Bypass -File deploy.ps1
    continueOnError: true
"""

HARDENED_PIPELINE = """
trigger:
  - main

pr:
  - main

pool:
  vmImage: ubuntu-latest

variables:
  pythonVersion: '3.12'

steps:
  - checkout: self
    persistCredentials: false
    clean: true

  - task: UsePythonVersion@0
    inputs:
      versionSpec: '$(pythonVersion)'

  - script: python -m pytest
    displayName: Run tests
"""


class TestAzurePipelinesAnalyzer:
    def test_no_pipelines_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "azure-pipelines.yml").write_text(INSECURE_PIPELINE, encoding="utf-8")
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "unpinned_task" in kinds
        assert "curl_pipe_shell" in kinds
        assert "secret_in_env" in kinds
        assert "system_access_token" in kinds
        assert "execution_policy_bypass" in kinds
        assert "continue_on_error" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pipeline_scores_well(self, tmp_path: Path):
        (tmp_path / "azure-pipelines.yml").write_text(HARDENED_PIPELINE, encoding="utf-8")
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.pipelines == 1
        assert analyzer.infos[0].tasks >= 1

    def test_finds_pipelines_in_subdirectory(self, tmp_path: Path):
        pipeline_dir = tmp_path / ".azure-pipelines"
        pipeline_dir.mkdir()
        (pipeline_dir / "ci.yml").write_text(HARDENED_PIPELINE, encoding="utf-8")
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 1

    def test_summary_context_and_template(self, tmp_path: Path):
        (tmp_path / "azure-pipelines.yml").write_text(HARDENED_PIPELINE, encoding="utf-8")
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        assert "Azure Pipelines:" in analyzer.summary()
        assert "Azure Pipelines analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "trigger:" in template
        assert "UsePythonVersion@0" in template

    def test_finding_format(self):
        finding = AzurePipelinesFinding(
            kind="unpinned_task",
            severity="high",
            message="unsafe",
            path="azure-pipelines.yml",
            lineno=2,
        )
        assert "azure-pipelines.yml:2" in finding.format()
