"""Tests for AWSCodePipelineAnalyzer."""

from pathlib import Path

from devai.aws_codepipeline_analyzer import AWSCodePipelineAnalyzer, AWSCodePipelineFinding


INSECURE_CONFIG = """
{
  "pipeline": {
    "name": "InsecurePipeline",
    "roleArn": "arn:aws:iam::*:role/AdministratorAccess",
    "artifactStore": {
      "type": "S3",
      "location": "my-bucket.s3.amazonaws.com"
    },
    "stages": [
      {
        "name": "Source",
        "actions": [
          {
            "name": "Source",
            "actionTypeId": {
              "category": "Source",
              "owner": "ThirdParty",
              "provider": "GitHub",
              "version": "1"
            },
            "configuration": {
              "OAuthToken": "ghp_hardcoded_github_token_secret",
              "Owner": "myorg",
              "Repo": "myrepo",
              "Branch": "main",
              "PollForSourceChanges": "true"
            }
          }
        ]
      },
      {
        "name": "Deploy",
        "actions": [
          {
            "name": "Deploy",
            "configuration": {
              "ClusterName": "prod",
              "ServiceName": "api",
              "FileName": "imagedefinitions.json",
              "Image": "myapp:latest"
            },
            "configuration": {
              "UserParameters": "#{variables.DEPLOY_TAG}"
            }
          }
        ]
      }
    ]
  }
}
"""

HARDENED_CONFIG = """
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
            "actionTypeId": {
              "category": "Source",
              "owner": "AWS",
              "provider": "CodeCommit",
              "version": "1"
            },
            "configuration": {
              "RepositoryName": "MyRepo",
              "BranchName": "main",
              "PollForSourceChanges": "false"
            }
          }
        ]
      }
    ]
  }
}
"""


def _write_pipeline(tmp_path: Path, content: str, name: str = "pipeline.json") -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


class TestAWSCodePipelineAnalyzer:
    def test_no_pipelines_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = AWSCodePipelineAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        _write_pipeline(tmp_path, INSECURE_CONFIG)
        analyzer = AWSCodePipelineAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_oauth_token" in kinds
        assert "overprivileged_role" in kinds
        assert "missing_encryption_key" in kinds
        assert "poll_for_source" in kinds
        assert "latest_image_tag" in kinds
        assert "variable_injection" in kinds

    def test_hardened_config_minimal_findings(self, tmp_path: Path):
        _write_pipeline(tmp_path, HARDENED_CONFIG)
        analyzer = AWSCodePipelineAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0

    def test_detects_cloudformation_pipeline(self, tmp_path: Path):
        cfn = tmp_path / "infra.yaml"
        cfn.write_text(
            """
Resources:
  MyPipeline:
    Type: AWS::CodePipeline::Pipeline
    Properties:
      RoleArn: arn:aws:iam::123456789012:role/CodePipelineRole
      ArtifactStore:
        Type: S3
        Location: artifacts-bucket
""",
            encoding="utf-8",
        )
        analyzer = AWSCodePipelineAnalyzer(str(tmp_path))
        assert len(analyzer.files()) == 1
        findings = analyzer.analyze()
        assert any(f.kind == "missing_encryption_key" for f in findings)

    def test_finding_format(self):
        finding = AWSCodePipelineFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="pipeline.json",
            lineno=10,
        )
        assert "[high]" in finding.format()
        assert "pipeline.json:10" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = AWSCodePipelineAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "encryptionKey" in template
        assert "PollForSourceChanges" in template

    def test_to_context(self, tmp_path: Path):
        _write_pipeline(tmp_path, HARDENED_CONFIG)
        analyzer = AWSCodePipelineAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "AWS CodePipeline analysis" in context
        assert "health score" in context

    def test_summary(self, tmp_path: Path):
        _write_pipeline(tmp_path, INSECURE_CONFIG)
        analyzer = AWSCodePipelineAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "AWS CodePipeline" in summary
        assert "finding" in summary
