"""HelmAnalyzer — audit Helm charts for security and deployment best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CHART_YAML = "Chart.yaml"
VALUES_YAML = "values.yaml"
TEMPLATE_DIR = "templates"

PRIVILEGED_PATTERN = re.compile(r"privileged:\s*true\b", re.IGNORECASE)
LATEST_TAG_PATTERN = re.compile(r"tag:\s*latest\b", re.IGNORECASE)
IMAGE_LATEST_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
SECRET_VALUE_PATTERN = re.compile(
    r"(password|secret|apiKey|api_key|token|credential)\s*:\s*(?:[\"'][^\"'$]+[\"']|[^\s{]+)",
    re.IGNORECASE,
)
RUN_AS_ROOT_PATTERN = re.compile(r"runAsUser:\s*0\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"hostNetwork:\s*true\b", re.IGNORECASE)
ALLOW_PRIV_ESC_PATTERN = re.compile(
    r"allowPrivilegeEscalation:\s*true\b",
    re.IGNORECASE,
)
HOST_PATH_PATTERN = re.compile(r"hostPath:", re.IGNORECASE)


@dataclass
class HelmFinding:
    """A security or best-practice issue in a Helm chart."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class HelmChartInfo:
    """Parsed metadata about a Helm chart."""

    path: str
    name: str = ""
    version: str = ""
    templates: int = 0
    has_values: bool = False


@dataclass
class HelmStats:
    """Aggregate Helm chart analysis statistics."""

    charts: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _find_charts(root: Path) -> list[Path]:
    """Find directories containing Chart.yaml."""
    charts: list[Path] = []
    for chart_yaml in sorted(root.rglob(CHART_YAML)):
        charts.append(chart_yaml.parent)
    return charts


class HelmAnalyzer:
    """Audit Helm charts for security risks and deployment best practices.

    Scans for privileged pods, :latest tags, hardcoded secrets in values,
    root containers, host networking, and hostPath volumes.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[HelmFinding] | None = None
        self._stats: HelmStats | None = None
        self._infos: list[HelmChartInfo] | None = None

    def charts(self) -> list[Path]:
        """Return Helm chart directories found in the project."""
        return _find_charts(self.root)

    def _chart_files(self, chart_dir: Path) -> list[Path]:
        files: list[Path] = []
        templates = chart_dir / TEMPLATE_DIR
        if templates.is_dir():
            files.extend(sorted(templates.rglob("*.yaml")))
            files.extend(sorted(templates.rglob("*.yml")))
            files.extend(sorted(templates.rglob("*.tpl")))
        values = chart_dir / VALUES_YAML
        if values.is_file():
            files.append(values)
        return files

    def _analyze_chart(self, chart_dir: Path) -> tuple[list[HelmFinding], HelmChartInfo]:
        findings: list[HelmFinding] = []
        rel_chart = str(chart_dir.relative_to(self.root))
        info = HelmChartInfo(path=rel_chart)

        chart_yaml = chart_dir / CHART_YAML
        if chart_yaml.is_file():
            try:
                for line in chart_yaml.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.startswith("name:"):
                        info.name = line.split(":", 1)[1].strip()
                    elif line.startswith("version:"):
                        info.version = line.split(":", 1)[1].strip()
            except OSError:
                pass

        values_yaml = chart_dir / VALUES_YAML
        info.has_values = values_yaml.is_file()

        for path in self._chart_files(chart_dir):
            rel = str(path.relative_to(self.root))
            if path.name == VALUES_YAML:
                info.templates += 0
            else:
                info.templates += 1

            try:
                raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue

            for lineno, raw in enumerate(raw_lines, start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue

                if PRIVILEGED_PATTERN.search(line):
                    findings.append(
                        HelmFinding(
                            kind="privileged",
                            severity="high",
                            message="privileged: true grants full host access",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

                if LATEST_TAG_PATTERN.search(line) or IMAGE_LATEST_PATTERN.search(line):
                    findings.append(
                        HelmFinding(
                            kind="latest_tag",
                            severity="medium",
                            message="image uses :latest tag — pin a specific version",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

                if SECRET_VALUE_PATTERN.search(line) and "{{" not in line:
                    findings.append(
                        HelmFinding(
                            kind="hardcoded_secret",
                            severity="high",
                            message="hardcoded secret in chart — use Kubernetes Secrets or external secrets",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

                if RUN_AS_ROOT_PATTERN.search(line):
                    findings.append(
                        HelmFinding(
                            kind="run_as_root",
                            severity="high",
                            message="runAsUser: 0 runs container as root",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

                if HOST_NETWORK_PATTERN.search(line):
                    findings.append(
                        HelmFinding(
                            kind="host_network",
                            severity="high",
                            message="hostNetwork: true shares the host network namespace",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

                if ALLOW_PRIV_ESC_PATTERN.search(line):
                    findings.append(
                        HelmFinding(
                            kind="privilege_escalation",
                            severity="medium",
                            message="allowPrivilegeEscalation: true enables privilege escalation",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

                if HOST_PATH_PATTERN.search(line):
                    findings.append(
                        HelmFinding(
                            kind="host_path",
                            severity="high",
                            message="hostPath volume exposes host filesystem",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

        return findings, info

    def analyze(self) -> list[HelmFinding]:
        """Scan Helm charts and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[HelmFinding] = []
        infos: list[HelmChartInfo] = []
        chart_dirs = self.charts()

        for chart_dir in chart_dirs:
            chart_findings, info = self._analyze_chart(chart_dir)
            findings.extend(chart_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = HelmStats(
            charts=len(chart_dirs),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> HelmStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[HelmChartInfo]:
        """Return parsed Helm chart metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no charts)."""
        self.analyze()
        stats = self.stats
        if stats.charts == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened Helm values.yaml template."""
        return """\
# Generated by DevAI HelmAnalyzer
replicaCount: 2

image:
  repository: myregistry/app
  tag: "1.0.0"
  pullPolicy: IfNotPresent

securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000

containerSecurityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL

resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.charts == 0:
            return "Helm charts: none found"
        return (
            f"Helm charts: {stats.charts} chart(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Helm chart analysis:",
            f"  charts: {stats.charts}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            name = info.name or info.path
            lines.append(f"  - {name} v{info.version}: {info.templates} template(s)")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
