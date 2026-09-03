"""Tests for GardenAnalyzer."""

from pathlib import Path

from devai.garden_analyzer import GardenAnalyzer, GardenFinding


INSECURE_GARDEN = """\
apiVersion: garden.io/v2
kind: Project
name: app

environments:
  - name: production
    defaultNamespace: production
    variables:
      api_key: sk-live-hardcoded-secret
      db-password: super-secret-password

providers:
  - name: kubernetes
    environments: [production]
    context: production-cluster
    buildMode: local-docker
    kubeconfig: eyJhcGlWZXJzaW9uIjoidjEiLCJjbHVzdGVycyI6W119
    namespace: production

---
kind: Deploy
name: api
type: container
spec:
  image: nginx:latest
  hostNetwork: true
  privileged: true
  securityContext:
    runAsUser: 0
    runAsNonRoot: false
  volumes:
    - name: docker-sock
      hostPath:
        path: /var/run/docker.sock
  sync:
    paths:
      - sourcePath: .env
        targetPath: /app/.env
      - sourcePath: .git
        targetPath: /app/.git
  ingresses:
    - path: /
      port: http
  extraFlags:
    - --force

---
kind: Run
name: bootstrap
spec:
  command:
    - sh
    - -c
    - curl -s https://install.example.com/script.sh | bash
"""

HARDENED_GARDEN = """\
apiVersion: garden.io/v2
kind: Project
name: app

environments:
  - name: dev
    defaultNamespace: app-dev
    variables:
      IMAGE_TAG: ${local.env.IMAGE_TAG || "dev"}

providers:
  - name: kubernetes
    environments: [dev]
    buildMode: cluster-build
    namespace: ${environment.namespace}

---
kind: Build
name: api
type: container
source:
  path: ./api

---
kind: Deploy
name: api
type: container
spec:
  image: ${actions.build.api.outputs.deploymentImageId}
  sync:
    paths:
      - sourcePath: ./api/src
        targetPath: /app/src
        exclude:
          - .git
          - .env
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
"""


class TestGardenAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = GardenAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "project.garden.yml").write_text(INSECURE_GARDEN, encoding="utf-8")
        analyzer = GardenAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "latest_image_tag" in kinds
        assert "sync_sensitive_path" in kinds
        assert "docker_socket_mount" in kinds
        assert analyzer.stats.configs == 1
        assert analyzer.stats.high_severity > 0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "project.garden.yml").write_text(HARDENED_GARDEN, encoding="utf-8")
        analyzer = GardenAnalyzer(str(tmp_path))
        assert analyzer.health_score() >= 90.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "project.garden.yml").write_text(INSECURE_GARDEN, encoding="utf-8")
        analyzer = GardenAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert isinstance(finding, GardenFinding)
        assert "[high]" in finding.format() or "[medium]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "project.garden.yml").write_text(INSECURE_GARDEN, encoding="utf-8")
        analyzer = GardenAnalyzer(str(tmp_path))
        assert "Garden configs: 1" in analyzer.summary()
        context = analyzer.to_context()
        assert "Garden analysis:" in context
        assert "health score:" in context

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = GardenAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert "apiVersion: garden.io/v2" in config
        assert "runAsNonRoot: true" in config

    def test_detects_garden_yml_filename(self, tmp_path: Path):
        (tmp_path / "garden.yml").write_text(
            "apiVersion: garden.io/v2\nkind: Project\nname: x\nvariables:\n  token: abc123\n",
            encoding="utf-8",
        )
        analyzer = GardenAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
        assert any(f.kind == "hardcoded_secret" for f in analyzer.analyze())
