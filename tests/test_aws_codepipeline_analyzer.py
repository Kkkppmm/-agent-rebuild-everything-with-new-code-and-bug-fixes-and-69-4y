"""Tests for AWSCodePipelineAnalyzer."""

from pathlib import Path

from devai.aws_codepipeline_analyzer import AWSCodePipelineAnalyzer, AWSCodePipelineFinding


INSECURE_CONFIG = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  AppPipeline:
    Type: AWS::CodePipeline::Pipeline
    Properties:
      Name: app-pipeline
      RoleArn: arn:aws:iam::123456789012:role/CodePipelineAdminRole
      ArtifactStore:
        Type: S3
        Location: my-artifacts-bucket
      Stages:
        - Name: Source
          Actions:
            - Name: SourceAction
              ActionTypeId:
                Category: Source
                Owner: ThirdParty
                Provider: GitHub
                Version: '*'
              Configuration:
                Owner: my-org
                Repo: my-repo
                BranchName: '*'
                OAuthToken: "ghp_hardcoded_github_token"
                AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE"
              OutputArtifacts:
                - Name: SourceOutput
        - Name: Build
          Actions:
            - Name: BuildAction
              ActionTypeId:
                Category: Build
                Owner: AWS
                Provider: CodeBuild
                Version: '1'
              Configuration:
                ProjectName: my-build
                UserParameters: "deploy #{CodePipeline_PipelineName} from http://insecure.example.com"
              InputArtifacts:
                - Name: SourceOutput
        - Name: Deploy
          Actions:
            - Name: DeployAction
              ActionTypeId:
                Category: Deploy
                Owner: AWS
                Provider: CodeDeploy
                Version: '1'
              Configuration:
                ApplicationName: my-app
                DeploymentGroupName: production
              InputArtifacts:
                - Name: SourceOutput
"""

HARDENED_CONFIG = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  AppPipeline:
    Type: AWS::CodePipeline::Pipeline
    Properties:
      Name: app-pipeline
      RoleArn: arn:aws:iam::123456789012:role/CodePipelineRole
      ArtifactStore:
        Type: S3
        Location: my-artifacts-bucket
        EncryptionKey:
          Type: KMS
          Id: alias/aws/s3
      Stages:
        - Name: Source
          Actions:
            - Name: SourceAction
              ActionTypeId:
                Category: Source
                Owner: AWS
                Provider: CodeCommit
                Version: '1'
              Configuration:
                RepositoryName: my-repo
                BranchName: main
              OutputArtifacts:
                - Name: SourceOutput
        - Name: Build
          Actions:
            - Name: BuildAction
              ActionTypeId:
                Category: Build
                Owner: AWS
                Provider: CodeBuild
                Version: '1'
              Configuration:
                ProjectName: my-build
              InputArtifacts:
                - Name: SourceOutput
        - Name: Deploy
          Actions:
            - Name: Approval
              ActionTypeId:
                Category: Approval
                Owner: AWS
                Provider: Manual
                Version: '1'
              Configuration:
                CustomData: Approve production deployment
            - Name: DeployAction
              ActionTypeId:
                Category: Deploy
                Owner: AWS
                Provider: CodeDeploy
                Version: '1'
              Configuration:
                ApplicationName: my-app
                DeploymentGroupName: production
              InputArtifacts:
                - Name: SourceOutput
              RunOrder: 2
"""


def _write_pipeline(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "pipeline.yaml"
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
        assert "hardcoded_secret" in kinds
        assert "plaintext_aws_key" in kinds
        assert "unencrypted_artifacts" in kinds
        assert "wildcard_branch" in kinds
        assert "unpinned_action_version" in kinds
        assert "script_injection" in kinds
        assert "insecure_http" in kinds
        assert "missing_manual_approval" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_few_findings(self, tmp_path: Path):
        _write_pipeline(tmp_path, HARDENED_CONFIG)
        analyzer = AWSCodePipelineAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) == 0
        assert analyzer.health_score() == 100.0

    def test_finding_format(self, tmp_path: Path):
        _write_pipeline(tmp_path, INSECURE_CONFIG)
        analyzer = AWSCodePipelineAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert all(isinstance(f, AWSCodePipelineFinding) for f in findings)
        assert all(f.path == "pipeline.yaml" for f in findings)
        assert all(
            "[high]" in f.format() or "[medium]" in f.format() or "[low]" in f.format()
            for f in findings
        )

    def test_summary_and_context(self, tmp_path: Path):
        _write_pipeline(tmp_path, HARDENED_CONFIG)
        analyzer = AWSCodePipelineAnalyzer(str(tmp_path))
        assert "AWS CodePipeline: 1 file(s)" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "AWS CodePipeline config analysis:" in ctx
        assert "health score: 100.0/100" in ctx

    def test_generate_hardened_template(self, tmp_path: Path):
        analyzer = AWSCodePipelineAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "AWS::CodePipeline::Pipeline" in template
        assert "EncryptionKey:" in template
        assert "Provider: Manual" in template

    def test_codepipeline_dir_detection(self, tmp_path: Path):
        aws_dir = tmp_path / ".aws" / "codepipeline"
        aws_dir.mkdir(parents=True)
        (aws_dir / "deploy.yml").write_text(
            "stages:\n  - name: Source\n    actions: []\n",
            encoding="utf-8",
        )
        analyzer = AWSCodePipelineAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 1
