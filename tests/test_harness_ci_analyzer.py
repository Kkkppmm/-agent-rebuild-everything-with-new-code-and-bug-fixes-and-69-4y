"""Tests for HarnessCIAnalyzer."""

from pathlib import Path

from devai.harness_ci_analyzer import HarnessCIAnalyzer, HarnessCIFinding


INSECURE_CONFIG = """
pipeline:
  name: insecure-pipeline
  identifier: insecure_pipeline
  variables:
    - name: API_TOKEN
      value: sk-live-hardcoded-secret
  stages:
    - stage:
        name: build
        identifier: build
        spec:
          disableAutoAbort: true
          execution:
            steps:
              - step:
                  name: Run
                  identifier: run
                  type: Run
                  spec:
                    shell: Bash
                    privileged: true
                    runAsUser: 0
                    image: alpine:latest
                    command: |
                      curl -sSL http://install.example.com/setup.sh | bash
                      echo Building $HARNESS_TRIGGER_BRANCH
                      docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock myapp:latest
                    envVariables:
                      AWS_KEY:
                        value: AKIAIOSFODNN7EXAMPLE
                      PASSWORD:
                        value: super-secret-password
"""

HARDENED_CONFIG = """
pipeline:
  name: secure-pipeline
  identifier: secure_pipeline
  stages:
    - stage:
        name: build
        identifier: build
        spec:
          execution:
            steps:
              - step:
                  name: Run
                  identifier: run
                  type: Run
                  spec:
                    shell: Bash
                    connectorRef: account.docker
                    image: alpine:3.19
                    command: echo "build"
                    envVariables:
                      DB_PASSWORD:
                        name: db_password
                        type: Secret
                        value: org.db_password
"""


def _write_pipeline(tmp_path: Path, content: str) -> Path:
    harness_dir = tmp_path / ".harness"
    harness_dir.mkdir(parents=True)
    path = harness_dir / "pipeline.yaml"
    path.write_text(content, encoding="utf-8")
    return path


class TestHarnessCIAnalyzer:
    def test_no_pipelines_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = HarnessCIAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        _write_pipeline(tmp_path, INSECURE_CONFIG)
        analyzer = HarnessCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "plaintext_pipeline_variable" in kinds
        assert "plaintext_aws_key" in kinds
        assert "curl_pipe_shell" in kinds
        assert "privileged_container" in kinds
        assert "docker_socket_mount" in kinds
        assert "script_injection" in kinds
        assert "latest_image_tag" in kinds
        assert "run_as_root" in kinds
        assert "insecure_pipeline_setting" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_few_findings(self, tmp_path: Path):
        _write_pipeline(tmp_path, HARDENED_CONFIG)
        analyzer = HarnessCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) == 0
        assert analyzer.health_score() == 100.0

    def test_finding_format(self, tmp_path: Path):
        _write_pipeline(tmp_path, INSECURE_CONFIG)
        analyzer = HarnessCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert all(isinstance(f, HarnessCIFinding) for f in findings)
        assert all(f.path == ".harness/pipeline.yaml" for f in findings)
        assert all(
            "[high]" in f.format() or "[medium]" in f.format() or "[low]" in f.format()
            for f in findings
        )

    def test_summary_and_context(self, tmp_path: Path):
        _write_pipeline(tmp_path, HARDENED_CONFIG)
        analyzer = HarnessCIAnalyzer(str(tmp_path))
        assert "Harness CI: 1 pipeline(s)" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Harness CI pipeline analysis:" in ctx
        assert "health score: 100.0/100" in ctx

    def test_generate_hardened_template(self, tmp_path: Path):
        analyzer = HarnessCIAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "pipeline:" in template
        assert "type: Secret" in template
        assert "connectorRef: account.docker" in template

    def test_harness_suffix_detection(self, tmp_path: Path):
        path = tmp_path / "deploy.harness.yaml"
        path.write_text(
            "pipeline:\n  name: deploy\n  identifier: deploy\n",
            encoding="utf-8",
        )
        analyzer = HarnessCIAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 1
