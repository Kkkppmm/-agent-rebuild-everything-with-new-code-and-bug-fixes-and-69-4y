"""Tests for v6.74.0 infrastructure analyzers."""

from pathlib import Path

from devai import AWSCodePipelineAnalyzer, DevAI
from devai.project_health import ProjectHealth


HARDENED_PIPELINE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  AppPipeline:
    Type: AWS::CodePipeline::Pipeline
    Properties:
      ArtifactStore:
        Type: S3
        Location: artifacts
        EncryptionKey:
          Type: KMS
          Id: alias/aws/s3
      Stages:
        - Name: Source
          Actions: []
        - Name: Deploy
          Actions:
            - Name: Approval
              ActionTypeId:
                Provider: Manual
"""


class TestV674InfrastructureAnalyzers:
    def test_facade_aws_codepipeline(self, tmp_path: Path):
        (tmp_path / "pipeline.yaml").write_text(HARDENED_PIPELINE, encoding="utf-8")
        analyzer = DevAI.mock().aws_codepipeline(tmp_path)
        assert isinstance(analyzer, AWSCodePipelineAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_project_health_includes_aws_codepipeline_category(self, tmp_path: Path):
        (tmp_path / "pipeline.yaml").write_text(HARDENED_PIPELINE, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "aws_codepipeline" in names
