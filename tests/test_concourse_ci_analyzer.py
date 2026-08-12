"""Tests for ConcourseCIAnalyzer."""

from pathlib import Path

from devai.concourse_ci_analyzer import ConcourseCIAnalyzer, ConcourseCIFinding


INSECURE_CONFIG = """
resource_types: []

resources:
  - name: repo
    type: git
    source:
      uri: https://github.com/example/app.git
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEAhardcoded

jobs:
  - name: build
    plan:
      - get: repo
      - task: build-app
        privileged: true
        config:
          platform: linux
          image_resource:
            type: registry-image
            source:
              repository: golang
              tag: latest
          run:
            path: sh
            args:
              - -exc
              - |
                curl -sSL http://install.example.com/setup.sh | bash
                echo Deploying ((.:git.ref)) from PR ((.:pull-request))
          params:
            GITHUB_TOKEN: "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
          caches:
            - /root/.ssh

  - name: security-audit
    publicly_exposed_plan: true
    plan:
      - get: repo
      - task: bandit
        config:
          platform: linux
          image_resource:
            type: docker-image
            source:
              repository: python
          run:
            path: bandit
            args: ["-r", "."]
"""

HARDENED_CONFIG = """
resources:
  - name: repo
    type: git
    source:
      uri: ((git-uri))
      branch: main
      private_key: ((git-private-key))

jobs:
  - name: unit-tests
    plan:
      - get: repo
        trigger: true
      - task: test
        config:
          platform: linux
          image_resource:
            type: registry-image
            source:
              repository: python
              tag: "3.12-slim"
          inputs:
            - name: repo
          run:
            path: sh
            args:
              - -exc
              - |
                cd repo
                pip install -e ".[dev]"
                python -m pytest

  - name: security-scan
    plan:
      - get: repo
        passed: [unit-tests]
      - task: scan
        config:
          platform: linux
          image_resource:
            type: registry-image
            source:
              repository: python
              tag: "3.12-slim"
          inputs:
            - name: repo
          run:
            path: sh
            args:
              - -exc
              - |
                cd repo
                pip install devai
                devai security-scan .
"""


def _write_concourse_config(tmp_path: Path, content: str) -> Path:
    ci_dir = tmp_path / "ci"
    ci_dir.mkdir()
    path = ci_dir / "pipeline.yml"
    path.write_text(content, encoding="utf-8")
    return path


class TestConcourseCIAnalyzer:
    def test_no_pipelines_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = ConcourseCIAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.pipelines == 0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        _write_concourse_config(tmp_path, INSECURE_CONFIG)
        analyzer = ConcourseCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "curl_pipe_shell" in kinds
        assert "privileged_task" in kinds
        assert "hardcoded_param" in kinds
        assert "sensitive_cache" in kinds
        assert "publicly_exposed_plan" in kinds
        assert analyzer.health_score() < 100.0

    def test_hardened_config_has_fewer_findings(self, tmp_path: Path):
        _write_concourse_config(tmp_path, INSECURE_CONFIG)
        insecure = ConcourseCIAnalyzer(str(tmp_path))
        insecure.analyze()

        hardened_path = tmp_path / "ci" / "pipeline.yml"
        hardened_path.write_text(HARDENED_CONFIG, encoding="utf-8")
        hardened = ConcourseCIAnalyzer(str(tmp_path))
        hardened.analyze()
        assert hardened.stats.findings < insecure.stats.findings

    def test_findings_include_path_and_line(self, tmp_path: Path):
        _write_concourse_config(tmp_path, INSECURE_CONFIG)
        findings = ConcourseCIAnalyzer(str(tmp_path)).analyze()
        assert findings
        assert all(isinstance(f, ConcourseCIFinding) for f in findings)
        assert all(f.path == "ci/pipeline.yml" for f in findings)
        assert all(f.lineno > 0 for f in findings)

    def test_hardened_template_generated(self, tmp_path: Path):
        analyzer = ConcourseCIAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "ConcourseCIAnalyzer" in template
        assert "((git-uri))" in template
        assert "security-scan" in template

    def test_concourse_dir_detection(self, tmp_path: Path):
        concourse_dir = tmp_path / "concourse"
        concourse_dir.mkdir()
        (concourse_dir / "deploy.pipeline.yml").write_text(
            "jobs:\n  - name: deploy\n    plan: []\n",
            encoding="utf-8",
        )
        analyzer = ConcourseCIAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 1

    def test_summary_and_context(self, tmp_path: Path):
        _write_concourse_config(tmp_path, HARDENED_CONFIG)
        analyzer = ConcourseCIAnalyzer(str(tmp_path))
        assert "Concourse CI:" in analyzer.summary()
        context = analyzer.to_context()
        assert "Concourse CI pipeline analysis:" in context
        assert "health score:" in context
