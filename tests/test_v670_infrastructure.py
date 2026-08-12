"""Tests for v6.70.0 infrastructure analyzers."""

from pathlib import Path

from devai import AWSCodeBuildAnalyzer, DevAI
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
