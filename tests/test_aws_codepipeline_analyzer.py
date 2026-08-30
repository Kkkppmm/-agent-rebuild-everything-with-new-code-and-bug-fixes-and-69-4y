"""Tests for AWSCodePipelineAnalyzer."""

from pathlib import Path

from devai.aws_codepipeline_analyzer import AWSCodePipelineAnalyzer, AWSCodePipelineFinding


INSECURE_CONFIG = """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  PipelineArtifactBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: public-read

  ApplicationPipeline:
    Type: AWS::CodePipeline::Pipeline
    Properties:
      Name: insecure-pipeline
      RoleArn: arn:aws:iam::123456789012:role/CrossAccountRole
      ArtifactStore:
        Type: S3
        Location: !Ref PipelineArtifactBucket
        EncryptionKey:
          Id: none
          Type: KMS
      Stages:
        - StageName: Source
          Actions:
            - Name: Source
              Configuration:
                RepositoryName: my-repo
        - StageName: Build
          Actions:
            - Name: Build
              Configuration:
                ProjectName: my-build
                UserParameters: "deploy $CODEPIPELINE_EXECUTION_ID on $CODEBUILD_BUILD_ID"
        - StageName: Production
          Actions:
            - Name: Deploy
              Configuration:
                commands: curl -sSL http://install.example.com/setup.sh | bash
      EnvironmentVariables:
        - Name: API_TOKEN
          Value: "sk-live-hardcoded-secret"
        - Name: AWS_ACCESS_KEY_ID
          Value: "AKIAIOSFODNN7EXAMPLE"
        - Name: password
          Value: "supersecret123"
      EncryptionDisabled: true
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: "*"
            Resource: "*"
"""

HARDENED_CONFIG = """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  PipelineArtifactBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: aws:kms
      VersioningConfiguration:
        Status: Enabled

  ApplicationPipeline:
    Type: AWS::CodePipeline::Pipeline
    Properties:
      Name: secure-pipeline
      ArtifactStore:
        Type: S3
        Location: !Ref PipelineArtifactBucket
        EncryptionKey:
          Id: !GetAtt PipelineKmsKey.Arn
          Type: KMS
      Stages:
        - StageName: Source
          Actions:
            - Name: Source
              ActionTypeId:
                Category: Source
                Provider: CodeCommit
        - StageName: Build
          Actions:
            - Name: Build
              ActionTypeId:
                Category: Build
                Provider: CodeBuild
        - StageName: SecurityScan
          Actions:
            - Name: SecurityScan
              ActionTypeId:
                Category: Build
                Provider: CodeBuild
        - StageName: Approval
          Actions:
            - Name: ManualApproval
              ActionTypeId:
                Category: Approval
                Provider: Manual
        - StageName: Staging
          Actions:
            - Name: Deploy
              ActionTypeId:
                Category: Deploy
                Provider: CloudFormation
"""


def _write_pipeline_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "codepipeline.yml"
    path.write_text(content, encoding="utf-8")
    return path


class TestAWSCodePipelineAnalyzer:
    def test_no_pipelines_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = AWSCodePipelineAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        _write_pipeline_config(tmp_path, INSECURE_CONFIG)
        analyzer = AWSCodePipelineAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "plaintext_aws_key" in kinds
        assert "encryption_disabled" in kinds
        assert "missing_encryption_key" in kinds
        assert "public_s3_acl" in kinds
        assert "wildcard_iam_action" in kinds
        assert "wildcard_iam_resource" in kinds
        assert "curl_pipe_shell" in kinds
        assert "script_injection" in kinds
        assert "missing_approval" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_few_findings(self, tmp_path: Path):
        _write_pipeline_config(tmp_path, HARDENED_CONFIG)
        analyzer = AWSCodePipelineAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        _write_pipeline_config(tmp_path, HARDENED_CONFIG)
        analyzer = AWSCodePipelineAnalyzer(str(tmp_path))
        assert "AWS CodePipeline:" in analyzer.summary()
        assert "health score" in analyzer.to_context()

    def test_generate_hardened_template(self):
        analyzer = AWSCodePipelineAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "AWS::CodePipeline::Pipeline" in template
        assert "SecurityScan" in template
        assert "Approval" in template

    def test_finding_format(self):
        finding = AWSCodePipelineFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test",
            path="codepipeline.yml",
            lineno=1,
        )
        assert "[high]" in finding.format()
