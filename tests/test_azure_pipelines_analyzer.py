"""Tests for AzurePipelinesAnalyzer."""

from pathlib import Path

from devai.azure_pipelines_analyzer import AzureFinding, AzurePipelinesAnalyzer

INSECURE_AZURE = """
trigger:
  branches:
    include:
      - '*'

variables:
  API_SECRET: 'supersecret'

stages:
  - stage: Test
    jobs:
      - job: Test
        steps:
          - checkout: self
            persistCredentials: true
          - script: |
              curl -fsSL https://example.com/install.sh | bash
              sudo apt-get update
              echo $(Build.SourceVersionMessage)
          - bash: eval $DEPLOY_SCRIPT

  - stage: Deploy
    jobs:
      - deployment: Deploy
        environment: production
        strategy:
          runOnce:
            deploy:
              steps:
                - script: echo deploy
        container:
          image: alpine:latest
          options: --privileged
"""

HARDENED_AZURE = """
trigger:
  branches:
    include:
      - main

pr:
  branches:
    include:
      - main

pool:
  vmImage: ubuntu-22.04

stages:
  - stage: Test
    jobs:
      - job: Test
        steps:
          - checkout: self
          - script: |
              pip install -e ".[dev]"
              python -m pytest
            displayName: Run tests
"""


class TestAzurePipelinesAnalyzer:
    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "no config" in analyzer.summary().lower()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "azure-pipelines.yml").write_text(INSECURE_AZURE, encoding="utf-8")
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "secret_in_variables" in kinds
        assert "curl_pipe_shell" in kinds
        assert "sudo_usage" in kinds
        assert "dangerous_script" in kinds
        assert "privileged_container" in kinds
        assert "persist_credentials" in kinds
        assert "untrusted_pipeline_var" in kinds
        assert "deploy_without_branch_guard" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "azure-pipelines.yml").write_text(HARDENED_AZURE, encoding="utf-8")
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.config_files == 1
        assert analyzer.infos[0].job_count >= 1

    def test_finding_format(self):
        finding = AzureFinding(
            kind="test",
            severity="high",
            message="test message",
            path="azure-pipelines.yml",
            lineno=1,
            line="test line",
        )
        assert "[high]" in finding.format()
        assert "azure-pipelines.yml:1" in finding.format()

    def test_generate_template(self, tmp_path: Path):
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "stages:" in template
        assert "python -m pytest" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "azure-pipelines.yml").write_text(INSECURE_AZURE, encoding="utf-8")
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Azure Pipelines configuration analysis" in context
        assert "health score" in context

    def test_finds_config_in_azure_directory(self, tmp_path: Path):
        azure_dir = tmp_path / ".azure-pipelines"
        azure_dir.mkdir()
        (azure_dir / "ci.yml").write_text(HARDENED_AZURE, encoding="utf-8")
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 1
