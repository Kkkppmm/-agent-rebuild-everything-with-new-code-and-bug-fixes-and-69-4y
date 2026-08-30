"""Tests for SemaphoreCIAnalyzer."""

from pathlib import Path

from devai.semaphore_ci_analyzer import SemaphoreCIAnalyzer, SemaphoreCIFinding


INSECURE_CONFIG = """
version: v1.0
name: CI
agent:
  machine:
    type: e1-standard-2
    os_image: ubuntu

blocks:
  - name: build
    task:
      env_vars:
        - name: API_KEY
          value: "sk-live-hardcoded-secret"
        - name: TOKEN
          value: "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
      jobs:
        - name: build-app
          commands:
            - checkout
            - curl -sSL http://install.example.com/setup.sh | bash
            - echo Deploying branch ${SEMAPHORE_GIT_BRANCH} from PR ${SEMAPHORE_GIT_PR_NUMBER}
          docker:
            privileged: true
            network_mode: host
            volumes:
              - /var/run/docker.sock:/var/run/docker.sock
              - /root/.ssh:/root/.ssh
            image: golang:latest
            user: root

  - name: security-audit
    task:
      jobs:
        - name: bandit
          commands:
            - bandit -r .
          skip: true

promotions:
  - name: Production deploy
    pipeline_file: deploy.yml
    auto_promote:
      when: "branch = '*'"
"""

HARDENED_CONFIG = """
version: v1.0
name: CI
agent:
  machine:
    type: e1-standard-2
    os_image: ubuntu2004

blocks:
  - name: Tests
    task:
      jobs:
        - name: Run tests
          commands:
            - checkout
            - pip install -e ".[dev]"
            - python -m pytest

  - name: Security scan
    task:
      jobs:
        - name: Static analysis
          commands:
            - checkout
            - pip install devai
            - devai security-scan .

promotions:
  - name: Production deploy
    pipeline_file: deploy.yml
    auto_promote:
      when: "branch = 'main'"
"""


def _write_semaphore_config(tmp_path: Path, content: str) -> Path:
    sem_dir = tmp_path / ".semaphore"
    sem_dir.mkdir()
    path = sem_dir / "semaphore.yml"
    path.write_text(content, encoding="utf-8")
    return path


class TestSemaphoreCIAnalyzer:
    def test_no_pipelines_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = SemaphoreCIAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 0
        assert analyzer.health_score() == 100.0

    def test_insecure_config_has_high_findings(self, tmp_path: Path):
        _write_semaphore_config(tmp_path, INSECURE_CONFIG)
        analyzer = SemaphoreCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds or "hardcoded_env_value" in kinds
        assert "curl_pipe_shell" in kinds
        assert "privileged_container" in kinds
        assert "docker_socket_mount" in kinds
        assert "broad_auto_promote" in kinds
        assert analyzer.stats.high_severity >= 4
        assert analyzer.health_score() < 50.0

    def test_hardened_config_has_few_findings(self, tmp_path: Path):
        _write_semaphore_config(tmp_path, HARDENED_CONFIG)
        analyzer = SemaphoreCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_finding_format(self, tmp_path: Path):
        _write_semaphore_config(tmp_path, INSECURE_CONFIG)
        analyzer = SemaphoreCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert all(isinstance(f, SemaphoreCIFinding) for f in findings)
        assert all(f.path == ".semaphore/semaphore.yml" for f in findings)

    def test_summary_and_context(self, tmp_path: Path):
        _write_semaphore_config(tmp_path, HARDENED_CONFIG)
        analyzer = SemaphoreCIAnalyzer(str(tmp_path))
        assert "Semaphore CI: 1 file(s)" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Semaphore CI pipeline analysis:" in ctx

    def test_generate_template(self, tmp_path: Path):
        analyzer = SemaphoreCIAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "version:" in template
        assert "Security scan" in template

    def test_semaphore_dir_detection(self, tmp_path: Path):
        ci_dir = tmp_path / "ci"
        ci_dir.mkdir()
        (ci_dir / "pipeline.yaml").write_text(
            "version: v1.0\nblocks:\n  - name: test\n    task:\n      jobs: []\n",
            encoding="utf-8",
        )
        analyzer = SemaphoreCIAnalyzer(str(tmp_path))
        assert analyzer.stats.pipelines == 1
