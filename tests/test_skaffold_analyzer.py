"""Tests for SkaffoldAnalyzer."""

from pathlib import Path

from devai.skaffold_analyzer import SkaffoldAnalyzer, SkaffoldFinding


INSECURE_SKAFFOLD = """\
apiVersion: skaffold/v4beta11
kind: Config
metadata:
  name: app

build:
  insecureRegistries:
    - registry.internal:5000
  artifacts:
    - image: nginx:latest
      docker:
        dockerfile: Dockerfile
        buildArgs:
          - api_key: sk-live-hardcoded-secret
  local:
    useDockerCLI: true
    mounts:
      - src: /var/run/docker.sock
        dest: /var/run/docker.sock

manifests:
  rawYaml:
    - git::https://github.com/org/manifests.git//k8s

deploy:
  kubeContext: production
  statusCheck: false
  kubectl:
    flags:
      apply:
        - --force
        - --grace-period=0
  useClusterAdmin: true

portForward:
  - resourceType: service
    resourceName: app
    port: 8080
    localPort: 0

profiles:
  - name: dev
    patches:
      - op: replace
        path: /deploy/kubectl/flags/apply
        value:
          - --force
"""

HARDENED_SKAFFOLD = """\
apiVersion: skaffold/v4beta11
kind: Config
metadata:
  name: app

build:
  artifacts:
    - image: ghcr.io/org/app
      docker:
        dockerfile: Dockerfile
  tagPolicy:
    gitCommit:
      variant: AbbrevCommitSha
  local:
    push: false
    useBuildkit: true

manifests:
  rawYaml:
    - k8s/*.yaml

deploy:
  kubectl:
    flags:
      apply:
        - --server-side
  statusCheck: true

portForward:
  - resourceType: service
    resourceName: app
    namespace: app
    port: 8080
    localPort: 8080
"""


class TestSkaffoldAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = SkaffoldAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "skaffold.yaml").write_text(INSECURE_SKAFFOLD, encoding="utf-8")
        analyzer = SkaffoldAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds or "insecure_registry" in kinds
        assert "latest_image_tag" in kinds
        assert "docker_socket_mount" in kinds
        assert "kubectl_force_apply" in kinds
        assert "status_check_disabled" in kinds
        assert "cluster_admin" in kinds
        assert analyzer.stats.configs == 1
        assert analyzer.stats.high_severity > 0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "skaffold.yaml").write_text(HARDENED_SKAFFOLD, encoding="utf-8")
        analyzer = SkaffoldAnalyzer(str(tmp_path))
        assert analyzer.health_score() >= 90.0
        assert analyzer.stats.findings == 0

    def test_finding_format(self):
        finding = SkaffoldFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="skaffold.yaml",
            lineno=10,
            line="api_key: secret",
        )
        assert "skaffold.yaml:10" in finding.format()

    def test_generate_hardened_config(self):
        analyzer = SkaffoldAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "apiVersion: skaffold/" in config
        assert "statusCheck: true" in config

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "skaffold.yaml").write_text(HARDENED_SKAFFOLD, encoding="utf-8")
        analyzer = SkaffoldAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Skaffold analysis:" in context
        assert "health score" in context
