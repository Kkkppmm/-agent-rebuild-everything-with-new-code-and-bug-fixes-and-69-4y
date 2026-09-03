"""Tests for TelepresenceAnalyzer."""

from pathlib import Path

from devai.telepresence_analyzer import TelepresenceAnalyzer, TelepresenceFinding


INSECURE_TELEPRESENCE = """\
---
workloads:
  - name: api
    namespace: production
    intercept:
      port: 8080
      default: true
      envFile: .env
      env:
        api_key: sk-live-hardcoded-secret
        db-password: super-secret-password

client:
  docker:
    enabled: true
    mount: /var/run/docker.sock

trafficManager:
  managerNamespace: production
  agent:
    securityContext:
      runAsUser: 0
      runAsNonRoot: false
      privileged: true
      hostNetwork: true
    volumes:
      - name: docker-sock
        hostPath:
          path: /var/run/docker.sock

managerRbac:
  create: true
  namespaced: false
  clusterRole: cluster-admin

hooks:
  postConnect:
    - sh
    - -c
    - curl -s https://install.example.com/script.sh | bash

kubeconfig: eyJhcGlWZXJzaW9uIjoidjEiLCJjbHVzdGVycyI6W119
image: traffic-manager:latest
insecureSkipTLSVerify: true
allowPrivileged: true
"""

HARDENED_TELEPRESENCE = """\
---
workloads:
  - name: api
    namespace: app-dev
    intercept:
      port: 8080
      default: false
      env:
        LOG_LEVEL: debug
      envFile: ./config/dev.env.example

client:
  docker:
    enabled: false

trafficManager:
  managerNamespace: telepresence-dev
  agent:
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      privileged: false

managerRbac:
  create: true
  namespaced: true
"""


class TestTelepresenceAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = TelepresenceAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "telepresence.yaml").write_text(INSECURE_TELEPRESENCE, encoding="utf-8")
        analyzer = TelepresenceAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "sensitive_env_file" in kinds
        assert "docker_socket_mount" in kinds
        assert "production_namespace" in kinds
        assert analyzer.stats.configs == 1
        assert analyzer.stats.high_severity > 0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "telepresence.yaml").write_text(HARDENED_TELEPRESENCE, encoding="utf-8")
        analyzer = TelepresenceAnalyzer(str(tmp_path))
        assert analyzer.health_score() >= 90.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "telepresence.yaml").write_text(INSECURE_TELEPRESENCE, encoding="utf-8")
        analyzer = TelepresenceAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert isinstance(finding, TelepresenceFinding)
        assert "[high]" in finding.format() or "[medium]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "telepresence.yaml").write_text(INSECURE_TELEPRESENCE, encoding="utf-8")
        analyzer = TelepresenceAnalyzer(str(tmp_path))
        assert "Telepresence configs: 1" in analyzer.summary()
        context = analyzer.to_context()
        assert "Telepresence analysis:" in context
        assert "health score:" in context

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = TelepresenceAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert "workloads:" in config
        assert "runAsNonRoot: true" in config

    def test_detects_telepresence_yml_filename(self, tmp_path: Path):
        (tmp_path / "telepresence.yml").write_text(
            "workloads:\n  - name: api\n    namespace: prod\n    intercept:\n      port: 8080\n",
            encoding="utf-8",
        )
        analyzer = TelepresenceAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
