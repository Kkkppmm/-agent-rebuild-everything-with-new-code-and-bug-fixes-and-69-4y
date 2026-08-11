"""Tests for v6.70.0+ infrastructure analyzers."""

from pathlib import Path

from devai import AWSCodeBuildAnalyzer, AWSCodePipelineAnalyzer, DevAI
from devai.project_health import ProjectHealth


HARDENED_BUILDSPEC = """
version: 0.2

env:
  parameter-store:
    API_ENDPOINT: /prod/api-endpoint

phases:
  install:
    runtime-versions:
      python: 3.12
    commands:
      - pip install -r requirements.txt

  build:
    commands:
      - python -m build

artifacts:
  files:
    - dist/**/*
  encryption: true
"""

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


class TestV670InfrastructureAnalyzers:
    def test_facade_aws_codebuild(self, tmp_path: Path):
        (tmp_path / "buildspec.yml").write_text(HARDENED_BUILDSPEC, encoding="utf-8")
        analyzer = DevAI.mock().aws_codebuild(tmp_path)
        assert isinstance(analyzer, AWSCodeBuildAnalyzer)
        assert analyzer.stats.buildspecs == 1

    def test_project_health_includes_aws_codebuild_category(self, tmp_path: Path):
        (tmp_path / "buildspec.yml").write_text(HARDENED_BUILDSPEC, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "aws_codebuild" in names

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
