"""Tests for AWSCodePipelineAnalyzer."""

from pathlib import Path

from devai.aws_codepipeline_analyzer import AWSCodePipelineAnalyzer, AWSCodePipelineFinding


INSECURE_CONFIG = """
{
  "pipeline": {
    "name": "InsecurePipeline",
    "roleArn": "arn:aws:iam::123456789012:role/CodePipelineRole",
    "artifactStore": {
      "type": "S3",
      "location": "my-public-artifacts"
    },
    "stages": [
      {
        "name": "Source",
        "actions": [
          {
            "name": "GitHubSource",
            "actionTypeId": {
              "category": "Source",
              "owner": "ThirdParty",
              "provider": "GitHub",
              "version": "1"
            },
            "configuration": {
              "Owner": "myorg",
              "Repo": "myrepo",
              "BranchName": "*",
              "OAuthToken": "ghp_hardcoded_secret_token_12345",
              "PollForSourceChanges": "true"
            }
          }
        ]
      },
      {
        "name": "Build",
        "actions": [
          {
            "name": "BuildAction",
            "actionTypeId": {
              "category": "Build",
              "owner": "AWS",
              "provider": "CodeBuild",
              "version": "1"
            },
            "configuration": {
              "ProjectName": "my-build",
              "EnvironmentVariables": "#{variables.untrusted_input}"
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
    "name": "SecurePipeline",
    "roleArn": "arn:aws:iam::123456789012:role/CodePipelineServiceRole",
    "artifactStore": {
      "type": "S3",
      "location": "my-secure-artifacts",
      "encryptionKey": {
        "id": "arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
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
            },
            "configuration": {
              "RepositoryName": "my-repo",
              "BranchName": "main",
              "PollForSourceChanges": "false"
            }
          }
        ]
      },
      {
        "name": "Security",
        "actions": [
          {
            "name": "SecurityScan",
            "actionTypeId": {
              "category": "Build",
              "owner": "AWS",
              "provider": "CodeBuild",
              "version": "1"
            },
            "configuration": {
              "ProjectName": "security-scan"
            }
          }
        ]
      },
      {
        "name": "Approval",
        "actions": [
          {
            "name": "ManualApproval",
            "actionTypeId": {
              "category": "Approval",
              "owner": "AWS",
              "provider": "Manual",
              "version": "1"
            }
          }
        ]
      }
    ]
  }
}
"""


def _write_pipeline_config(tmp_path: Path, content: str, name: str = "pipeline.json") -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


class TestAWSCodePipelineAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = AWSCodePipelineAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        _write_pipeline_config(tmp_path, INSECURE_CONFIG)
        analyzer = AWSCodePipelineAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "config_secret" in kinds
        assert "unencrypted_artifacts" in kinds
        assert "wildcard_branch" in kinds
        assert "variable_injection" in kinds
        assert "poll_source_changes" in kinds
        assert analyzer.stats.high_severity >= 2

    def test_hardened_config_has_fewer_findings(self, tmp_path: Path):
        _write_pipeline_config(tmp_path, HARDENED_CONFIG)
        analyzer = AWSCodePipelineAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() == 100.0

    def test_finding_format(self):
        finding = AWSCodePipelineFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="pipeline.json",
            lineno=5,
            line='"OAuthToken": "secret"',
        )
        assert "[high]" in finding.format()
        assert "pipeline.json:5" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = AWSCodePipelineAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "encryptionKey" in template
        assert "PollForSourceChanges" in template
        assert "Security" in template

    def test_to_context(self, tmp_path: Path):
        _write_pipeline_config(tmp_path, HARDENED_CONFIG)
        analyzer = AWSCodePipelineAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "AWS CodePipeline analysis:" in context
        assert "health score:" in context

    def test_suffix_pipeline_filename(self, tmp_path: Path):
        _write_pipeline_config(tmp_path, HARDENED_CONFIG, name="deploy-pipeline.json")
        analyzer = AWSCodePipelineAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 1
