"""Tests for v6.74.0 infrastructure analyzers."""

from pathlib import Path

from devai import AWSCodePipelineAnalyzer, DevAI
from devai.project_health import ProjectHealth


HARDENED_PIPELINE = """
{
  "pipeline": {
    "name": "HardenedPipeline",
    "roleArn": "arn:aws:iam::123456789012:role/CodePipelineServiceRole",
    "artifactStore": {
      "type": "S3",
      "location": "my-pipeline-artifacts",
      "encryptionKey": {
        "id": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
        "type": "KMS"
      }
    },
    "stages": [
      {
        "name": "Source",
        "actions": [
          {
            "name": "Source",
            "configuration": {
              "RepositoryName": "MyRepo",
              "PollForSourceChanges": "false"
            }
          }
        ]
      }
    ]
  }
}
"""


class TestV674InfrastructureAnalyzers:
    def test_facade_aws_codepipeline(self, tmp_path: Path):
        aws_dir = tmp_path / ".aws" / "codepipeline"
        aws_dir.mkdir(parents=True)
        (aws_dir / "pipeline.json").write_text(HARDENED_PIPELINE, encoding="utf-8")
        analyzer = DevAI.mock().aws_codepipeline(tmp_path)
        assert isinstance(analyzer, AWSCodePipelineAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_project_health_includes_aws_codepipeline_category(self, tmp_path: Path):
        (tmp_path / "pipeline.json").write_text(HARDENED_PIPELINE, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "aws_codepipeline" in names
