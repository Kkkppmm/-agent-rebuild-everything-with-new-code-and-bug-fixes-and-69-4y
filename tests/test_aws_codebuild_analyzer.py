"""Tests for AWSCodeBuildAnalyzer."""

from pathlib import Path

from devai.aws_codebuild_analyzer import AWSCodeBuildAnalyzer, AWSCodeBuildFinding


INSECURE_CONFIG = """
version: 0.2

env:
  variables:
    API_TOKEN: "sk-live-hardcoded-secret"
    AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE"

phases:
  install:
    runtime-versions:
      python: latest
    commands:
      - curl -sSL http://install.example.com/setup.sh | bash
      - docker run --privileged --network host -v /var/run/docker.sock:/var/run/docker.sock myapp:latest

  pre_build:
    commands:
      - echo Building branch $CODEBUILD_WEBHOOK_HEAD_REF

  build:
    commands:
      - docker build -t myapp:latest .

  post_build:
    commands:
      - aws s3 cp dist/ s3://bucket/ --acl public-read

artifacts:
  files:
    - '**/*'
  encryption: false
"""

HARDENED_CONFIG = """
version: 0.2

env:
  variables:
    PYTHON_VERSION: "3.12"
  parameter-store:
    API_ENDPOINT: /prod/api-endpoint
  secrets-manager:
    DB_PASSWORD: arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db

phases:
  install:
    runtime-versions:
      python: 3.12
    commands:
      - pip install -r requirements.txt

  pre_build:
    commands:
      - python -m pytest

  build:
    commands:
      - python -m build

artifacts:
  files:
    - dist/**/*
  encryption: true
"""


def _write_buildspec(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "buildspec.yml"
    path.write_text(content, encoding="utf-8")
    return path


class TestAWSCodeBuildAnalyzer:
    def test_no_buildspecs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = AWSCodeBuildAnalyzer(str(tmp_path))
        assert analyzer.stats.buildspecs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        _write_buildspec(tmp_path, INSECURE_CONFIG)
        analyzer = AWSCodeBuildAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "plaintext_aws_key" in kinds
        assert "curl_pipe_shell" in kinds
        assert "privileged_container" in kinds
        assert "docker_socket_mount" in kinds
        assert "script_injection" in kinds
        assert "unencrypted_artifacts" in kinds
        assert "public_s3_acl" in kinds
        assert "latest_image_tag" in kinds
        assert "unpinned_runtime" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_few_findings(self, tmp_path: Path):
        _write_buildspec(tmp_path, HARDENED_CONFIG)
        analyzer = AWSCodeBuildAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) == 0
        assert analyzer.health_score() == 100.0

    def test_finding_format(self, tmp_path: Path):
        _write_buildspec(tmp_path, INSECURE_CONFIG)
        analyzer = AWSCodeBuildAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert all(isinstance(f, AWSCodeBuildFinding) for f in findings)
        assert all(f.path == "buildspec.yml" for f in findings)
        assert all(
            "[high]" in f.format() or "[medium]" in f.format() or "[low]" in f.format()
            for f in findings
        )

    def test_summary_and_context(self, tmp_path: Path):
        _write_buildspec(tmp_path, HARDENED_CONFIG)
        analyzer = AWSCodeBuildAnalyzer(str(tmp_path))
        assert "AWS CodeBuild: 1 file(s)" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "AWS CodeBuild buildspec analysis:" in ctx
        assert "health score: 100.0/100" in ctx

    def test_generate_hardened_template(self, tmp_path: Path):
        analyzer = AWSCodeBuildAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "version: 0.2" in template
        assert "secrets-manager:" in template
        assert "encryption: true" in template

    def test_codebuild_dir_detection(self, tmp_path: Path):
        aws_dir = tmp_path / ".aws" / "codebuild"
        aws_dir.mkdir(parents=True)
        (aws_dir / "pipeline.yml").write_text(
            "version: 0.2\nphases:\n  build:\n    commands:\n      - echo ok\n",
            encoding="utf-8",
        )
        analyzer = AWSCodeBuildAnalyzer(str(tmp_path))
        assert analyzer.stats.buildspecs == 1
