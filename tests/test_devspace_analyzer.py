"""Tests for DevSpaceAnalyzer."""

from pathlib import Path

from devai.devspace_analyzer import DevSpaceAnalyzer, DevSpaceFinding


INSECURE_DEVSPACE = """\
version: v2beta1
name: app

vars:
  api_key: sk-live-hardcoded-secret

images:
  app:
    image: nginx:latest
    dockerfile: Dockerfile
    build:
      docker:
        options:
          - --add-host
          - docker:172.17.0.1
        args:
          - SECRET=hardcoded-build-secret

deployments:
  app:
    namespace: production
    replacePods: true
    kubectl:
      manifests:
        - git::https://github.com/org/manifests.git//k8s
    helm:
      chart:
        name: http://chart-repo.internal/charts/app
      values:
        securityContext:
          runAsUser: 0
          runAsNonRoot: false
        hostNetwork: true
        privileged: true
    updateImageTags: true

dev:
  ssh:
    enabled: true
  ports:
    - port: "8080"
      localPort: "0"
  sync:
    - path: .env
      excludePaths: []
    - path: .git
  terminal:
    enabled: true

secrets:
  db-password:
    value: super-secret-password

pipelines:
  deploy:
    run: |-
      curl -s https://install.example.com/script.sh | bash
      devspace deploy --wait=false --force
"""

HARDENED_DEVSPACE = """\
version: v2beta1
name: app

vars:
  IMAGE: ghcr.io/org/app

images:
  app:
    image: ${IMAGE}
    dockerfile: Dockerfile
    tags:
      - ${DEVSPACE_RANDOM}

deployments:
  app:
    helm:
      chart:
        name: ./chart
      valuesFiles:
        - values.yaml
    updateImageTags: true

dev:
  ports:
    - port: "8080"
  sync:
    - path: ./src
      excludePaths:
        - .git
        - .env
        - node_modules
  terminal:
    enabled: true

pipelines:
  deploy:
    run: |-
      devspace deploy --wait
"""


class TestDevSpaceAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = DevSpaceAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "devspace.yaml").write_text(INSECURE_DEVSPACE, encoding="utf-8")
        analyzer = DevSpaceAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds or "plaintext_secret_value" in kinds
        assert "latest_image_tag" in kinds
        assert "ssh_into_pod" in kinds
        assert "force_deploy" in kinds
        assert "sync_sensitive_path" in kinds
        assert analyzer.stats.configs == 1
        assert analyzer.stats.high_severity > 0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "devspace.yaml").write_text(HARDENED_DEVSPACE, encoding="utf-8")
        analyzer = DevSpaceAnalyzer(str(tmp_path))
        assert analyzer.health_score() >= 90.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "devspace.yaml").write_text(INSECURE_DEVSPACE, encoding="utf-8")
        analyzer = DevSpaceAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert isinstance(finding, DevSpaceFinding)
        assert "[high]" in finding.format() or "[medium]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "devspace.yaml").write_text(INSECURE_DEVSPACE, encoding="utf-8")
        analyzer = DevSpaceAnalyzer(str(tmp_path))
        assert "DevSpace configs: 1" in analyzer.summary()
        context = analyzer.to_context()
        assert "DevSpace analysis:" in context
        assert "health score:" in context

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = DevSpaceAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert "version: v2beta1" in config
        assert "excludePaths:" in config
