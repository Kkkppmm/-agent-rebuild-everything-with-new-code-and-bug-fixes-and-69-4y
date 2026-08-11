"""Tests for v6.74.0 infrastructure analyzers."""

from pathlib import Path

from devai import AWSCodePipelineAnalyzer, DevAI
from devai.project_health import ProjectHealth


HARDENED_CONFIG = """
{
  "pipeline": {
    "name": "SecurePipeline",
    "artifactStore": {
      "type": "S3",
      "location": "artifacts",
      "encryptionKey": {
        "id": "arn:aws:kms:us-east-1:123456789012:key/abcd",
        "type": "KMS"
      }
    },
    "stages": [
      {
        "name": "Source",
        "actions": [
          {
            "name": "SourceAction",
            "actionTypeId": {
              "category": "Source",
              "owner": "AWS",
              "provider": "CodeCommit",
              "version": "1"
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
        (tmp_path / "pipeline.json").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = DevAI.mock().aws_codepipeline(tmp_path)
        assert isinstance(analyzer, AWSCodePipelineAnalyzer)
        assert analyzer.stats.pipelines == 1

    def test_project_health_includes_aws_codepipeline_category(self, tmp_path: Path):
        (tmp_path / "pipeline.json").write_text(HARDENED_CONFIG, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {cat.name for cat in report.categories}
        assert "aws_codepipeline" in names
