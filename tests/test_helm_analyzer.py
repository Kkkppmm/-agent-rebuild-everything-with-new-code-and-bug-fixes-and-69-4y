"""Tests for HelmAnalyzer."""

from pathlib import Path

from devai.helm_analyzer import HelmAnalyzer, HelmFinding


INSECURE_VALUES = """
image:
  repository: myapp
  tag: latest

database:
  password: "supersecret123"
  apiKey: "sk-live-abc123"
"""

INSECURE_TEMPLATE = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}
spec:
  template:
    spec:
      hostNetwork: true
      hostPID: true
      containers:
        - name: app
          image: nginx:latest
          securityContext:
            privileged: true
            runAsUser: 0
            allowPrivilegeEscalation: true
"""

HARDENED_TEMPLATE = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: nginx:1.25.3
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
"""


def _make_chart(tmp_path: Path, name: str = "mychart") -> Path:
    chart = tmp_path / "charts" / name
    chart.mkdir(parents=True)
    (chart / "Chart.yaml").write_text(f"name: {name}\nversion: 0.1.0\n", encoding="utf-8")
    (chart / "values.yaml").write_text("replicaCount: 1\n", encoding="utf-8")
    templates = chart / "templates"
    templates.mkdir()
    return chart


class TestHelmAnalyzer:
    def test_no_charts_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = HelmAnalyzer(str(tmp_path))
        assert analyzer.stats.charts == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_values(self, tmp_path: Path):
        chart = _make_chart(tmp_path)
        (chart / "values.yaml").write_text(INSECURE_VALUES, encoding="utf-8")
        analyzer = HelmAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert analyzer.stats.charts == 1

    def test_detects_insecure_template(self, tmp_path: Path):
        chart = _make_chart(tmp_path)
        (chart / "templates" / "deployment.yaml").write_text(
            INSECURE_TEMPLATE, encoding="utf-8"
        )
        analyzer = HelmAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "privileged_container" in kinds
        assert "host_network" in kinds
        assert "host_pid" in kinds
        assert "run_as_root" in kinds
        assert "latest_image_tag" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_template_scores_well(self, tmp_path: Path):
        chart = _make_chart(tmp_path)
        (chart / "templates" / "deployment.yaml").write_text(
            HARDENED_TEMPLATE, encoding="utf-8"
        )
        analyzer = HelmAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.charts == 1

    def test_summary_context_and_template(self, tmp_path: Path):
        chart = _make_chart(tmp_path)
        (chart / "templates" / "deployment.yaml").write_text(
            HARDENED_TEMPLATE, encoding="utf-8"
        )
        analyzer = HelmAnalyzer(str(tmp_path))
        assert "Helm" in analyzer.summary()
        assert "Helm analysis" in analyzer.to_context()
        snippet = analyzer.generate_hardened_values_snippet()
        assert "runAsNonRoot" in snippet

    def test_finding_format(self):
        finding = HelmFinding(
            kind="privileged_container",
            severity="high",
            message="test",
            path="chart/templates/deploy.yaml",
            lineno=10,
        )
        assert "high" in finding.format()
        assert "deploy.yaml" in finding.format()
