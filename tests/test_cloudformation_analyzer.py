"""Tests for CloudFormationAnalyzer."""

from pathlib import Path

from devai.cloudformation_analyzer import CloudFormationAnalyzer, CloudFormationFinding


INSECURE_CFN = """\
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DbPassword:
    Type: String
    Default: hardcodedpassword123
Resources:
  WebSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
  Database:
    Type: AWS::RDS::DBInstance
    Properties:
      MasterUserPassword: supersecret123
      PubliclyAccessible: true
      SkipFinalSnapshot: true
      StorageEncrypted: false
  AdminPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: "*"
            Resource: "*"
"""

HARDENED_CFN = """\
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  BucketName:
    Type: String
Resources:
  AppBucket:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain
    Properties:
      BucketName: !Ref BucketName
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
"""


class TestCloudFormationAnalyzer:
    def test_no_templates_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = CloudFormationAnalyzer(str(tmp_path))
        assert analyzer.stats.templates == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "stack.yaml").write_text(INSECURE_CFN, encoding="utf-8")
        analyzer = CloudFormationAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "open_security_group" in kinds
        assert "public_s3_acl" in kinds
        assert "hardcoded_secret" in kinds
        assert "public_database" in kinds
        assert "skip_final_snapshot" in kinds
        assert "wildcard_iam" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_template_scores_well(self, tmp_path: Path):
        (tmp_path / "bucket.yaml").write_text(HARDENED_CFN, encoding="utf-8")
        analyzer = CloudFormationAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.templates == 1

    def test_summary_context_and_template(self, tmp_path: Path):
        (tmp_path / "bucket.yaml").write_text(HARDENED_CFN, encoding="utf-8")
        analyzer = CloudFormationAnalyzer(str(tmp_path))
        assert "CloudFormation" in analyzer.summary()
        assert "CloudFormation analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "BlockPublicAcls" in template

    def test_finding_format(self):
        finding = CloudFormationFinding(
            kind="open_security_group",
            severity="high",
            message="open SG",
            path="stack.yaml",
            lineno=12,
        )
        assert "stack.yaml:12" in finding.format()
