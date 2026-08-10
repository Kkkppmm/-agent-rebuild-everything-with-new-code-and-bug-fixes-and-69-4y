"""Tests for AzurePipelinesAnalyzer."""

from pathlib import Path

from devai.azure_pipelines_analyzer import AzurePipelinesAnalyzer, AzurePipelinesFinding

INSECURE_PIPELINE = """
trigger:
  branches:
    include:
      - main

pool:
  vmImage: ubuntu-latest

variables:
  - name: API_SECRET
    value: supersecret123
  - name: TOKEN
    value: abc123

stages:
  - stage: Build
    jobs:
      - job: BuildJob
        container:
          image: python
          options: --privileged --user root
        steps:
          - script: curl -fsSL https://example.com/install.sh | bash
          - script: sudo pip install -r requirements.txt
            continueOnError: true
          - script: export NODE_TLS_REJECT_UNAUTHORIZED=0 && npm install
          - script: echo $(Build.SourceBranchName) > /tmp/out
"""

HARDENED_PIPELINE = """
trigger:
  branches:
    include:
      - main

pool:
  vmImage: ubuntu-22.04

variables:
  - group: shared-secrets

stages:
  - stage: Test
    jobs:
      - job: UnitTests
        container: python:3.12-slim
        steps:
          - checkout: self
            fetchDepth: 1
          - script: python -m pytest
"""


class TestAzurePipelinesAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "azure-pipelines.yml").write_text(INSECURE_PIPELINE, encoding="utf-8")
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "plaintext_secret_var" in kinds
        assert "curl_pipe_shell" in kinds
        assert "sudo_usage" in kinds
        assert "privileged_container" in kinds
        assert "tls_verification_disabled" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "azure-pipelines.yml").write_text(HARDENED_PIPELINE, encoding="utf-8")
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.configs == 1
        assert analyzer.infos[0].uses_container is True

    def test_finds_azure_pipelines_suffix(self, tmp_path: Path):
        (tmp_path / "ci.azure-pipelines.yml").write_text(HARDENED_PIPELINE, encoding="utf-8")
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1

    def test_generate_template(self, tmp_path: Path):
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "Key Vault" in template or "shared-secrets" in template
        assert "ubuntu-22.04" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "azure-pipelines.yml").write_text(HARDENED_PIPELINE, encoding="utf-8")
        analyzer = AzurePipelinesAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Azure Pipelines analysis" in context

    def test_finding_format(self):
        finding = AzurePipelinesFinding(
            kind="test",
            severity="high",
            message="test message",
            path="azure-pipelines.yml",
            lineno=1,
            stage="Build",
        )
        assert "high" in finding.format()
        assert "Build" in finding.format()
