"""Tests for CloudBuildAnalyzer."""

from pathlib import Path

from devai.cloud_build_analyzer import CloudBuildAnalyzer, CloudBuildFinding


INSECURE_CONFIG = """
steps:
  - id: setup
    name: golang:latest
    entrypoint: bash
    args:
      - -c
      - |
        curl -sSL http://install.example.com/setup.sh | bash
        echo "Building branch $BRANCH_NAME"
        docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock --user root ubuntu:latest
    env:
      - name: API_KEY
        value: "sk-abcdefghijklmnopqrstuvwxyz1234567890"

  - id: security-scan
    name: gcr.io/cloud-builders/gcloud
    entrypoint: bash
    args:
      - -c
      - devai security-scan .
    allowFailure: true

substitutions:
  _DEPLOY_TOKEN: "ghp_abcdefghijklmnopqrstuvwxyz1234567890"

serviceAccount: projects/$PROJECT_ID/serviceAccounts/$PROJECT_NUMBER@cloudbuild.gserviceaccount.com

images:
  - gcr.io/$PROJECT_ID/app:latest
"""

HARDENED_CONFIG = """
steps:
  - id: test
    name: python:3.12-slim
    entrypoint: bash
    args:
      - -c
      - |
        pip install -e ".[dev]"
        python -m pytest
    secretEnv:
      - PYPI_TOKEN

  - id: security-scan
    name: gcr.io/cloud-builders/gcloud
    entrypoint: bash
    args:
      - -c
      - devai security-scan .
    waitFor:
      - test

availableSecrets:
  secretManager:
    - versionName: projects/$PROJECT_ID/secrets/pypi-token/versions/latest
      env: PYPI_TOKEN

options:
  logging: CLOUD_LOGGING_ONLY

serviceAccount: projects/$PROJECT_ID/serviceAccounts/cloud-build@$PROJECT_ID.iam.gserviceaccount.com

images:
  - gcr.io/$PROJECT_ID/app:$SHORT_SHA
"""


class TestCloudBuildAnalyzer:
    def test_no_cloud_build_files(self, tmp_path: Path):
        (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
        analyzer = CloudBuildAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_finds_cloud_build_config(self, tmp_path: Path):
        (tmp_path / "cloudbuild.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = CloudBuildAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 1

    def test_insecure_vs_hardened(self, tmp_path: Path):
        (tmp_path / "cloudbuild.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")

        insecure = CloudBuildAnalyzer(str(tmp_path))
        insecure_score = insecure.health_score()
        insecure_findings = insecure.analyze()

        (tmp_path / "cloudbuild.yaml").write_text(HARDENED_CONFIG, encoding="utf-8")
        hardened = CloudBuildAnalyzer(str(tmp_path))
        hardened_score = hardened.health_score()

        assert len(insecure_findings) > 0
        assert insecure_score < hardened_score

    def test_finding_types(self, tmp_path: Path):
        (tmp_path / "cloudbuild.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")
        findings = CloudBuildAnalyzer(str(tmp_path)).analyze()
        kinds = {f.kind for f in findings}
        assert all(isinstance(f, CloudBuildFinding) for f in findings)
        assert "hardcoded_secret" in kinds or "hardcoded_env" in kinds or "plain_secret_value" in kinds
        assert "curl_pipe_shell" in kinds
        assert "privileged_container" in kinds

    def test_generate_template(self, tmp_path: Path):
        analyzer = CloudBuildAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "CloudBuildAnalyzer" in template
        assert "secretEnv" in template
        assert "availableSecrets" in template

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "cloudbuild.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = CloudBuildAnalyzer(str(tmp_path))
        assert "Cloud Build:" in analyzer.summary()
        assert "health score" in analyzer.to_context()

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "cloudbuild.yaml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = CloudBuildAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert finding.format().startswith("[")
