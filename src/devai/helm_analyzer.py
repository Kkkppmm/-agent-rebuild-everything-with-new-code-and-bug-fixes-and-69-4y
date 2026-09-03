"""HelmAnalyzer — audit Helm charts for privileged pods, latest tags, and hardcoded secrets."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

HELM_DIRS = ("charts", "helm", "deploy", "k8s")
CHART_MARKER = "Chart.yaml"
VALUES_NAMES = ("values.yaml", "values.yml")
TEMPLATE_SUFFIXES = (".yaml", ".yml", ".tpl")

PRIVILEGED_PATTERN = re.compile(r"privileged\s*:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"hostNetwork\s*:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"hostPID\s*:\s*true\b", re.IGNORECASE)
HOST_IPC_PATTERN = re.compile(r"hostIPC\s*:\s*true\b", re.IGNORECASE)
RUN_AS_ROOT_PATTERN = re.compile(r"runAsUser\s*:\s*0\b")
ALLOW_ESCALATION_PATTERN = re.compile(
    r"allowPrivilegeEscalation\s*:\s*true\b",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"image\s*:\s*[\"']?[^\"'\s:]+:latest[\"']?\s*$|"
    r"image\s*:\s*[\"']?latest[\"']?\s*$",
    re.IGNORECASE,
)
HARDCODED_PASSWORD_PATTERN = re.compile(
    r"(?:password|passwd|secretKey|apiKey|token)\s*:\s*[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
MISSING_RESOURCE_LIMITS_PATTERN = re.compile(
    r"kind\s*:\s*(Deployment|StatefulSet|DaemonSet)",
    re.IGNORECASE,
)
RESOURCES_PATTERN = re.compile(r"\bresources\s*:", re.IGNORECASE)
RUN_AS_NON_ROOT_PATTERN = re.compile(r"runAsNonRoot\s*:\s*true\b", re.IGNORECASE)
READ_ONLY_ROOT_PATTERN = re.compile(
    r"readOnlyRootFilesystem\s*:\s*true\b",
    re.IGNORECASE,
)


@dataclass
class HelmFinding:
    """A security issue in a Helm chart file."""

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
    chart_name: str = ""
    templates: int = 0
    values_files: int = 0
    lines: int = 0


@dataclass
class HelmStats:
    """Aggregate Helm analysis statistics."""

    charts: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _find_chart_roots(root: Path) -> list[Path]:
    """Return directories containing Chart.yaml."""
    charts: list[Path] = []
    for path in sorted(root.rglob("Chart.yaml")):
        if path.is_file():
            charts.append(path.parent)
    for path in sorted(root.rglob("chart.yaml")):
        if path.is_file() and path.parent not in charts:
            charts.append(path.parent)
    return charts


def _is_helm_file(path: Path, chart_roots: list[Path]) -> bool:
    lower = path.name.lower()
    if lower in VALUES_NAMES:
        return True
    if lower.endswith(TEMPLATE_SUFFIXES):
        for chart_root in chart_roots:
            try:
                path.relative_to(chart_root)
                if "templates" in path.parts:
                    return True
            except ValueError:
                continue
    parts = {p.lower() for p in path.parts}
    if parts & set(HELM_DIRS) and lower.endswith((".yaml", ".yml")):
        return True
    return False


class HelmAnalyzer:
    """Audit Helm charts for privileged containers, latest image tags, and hardcoded secrets.

    Scans Chart.yaml, values.yaml, and template manifests for host namespaces,
    runAsUser 0, missing resource limits, and plaintext credentials in values.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[HelmFinding] | None = None
        self._stats: HelmStats | None = None
        self._infos: list[HelmChartInfo] | None = None

    def charts(self) -> list[Path]:
        """Return Helm chart root directories found in the project."""
        return _find_chart_roots(self.root)

    def files(self) -> list[Path]:
        """Return Helm-related files (values, templates) in discovered charts."""
        chart_roots = self.charts()
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            if _is_helm_file(path, chart_roots):
                found.append(path)
        for chart_root in chart_roots:
            chart_yaml = chart_root / "Chart.yaml"
            if chart_yaml.is_file() and chart_yaml not in found:
                found.append(chart_yaml)
        return sorted(set(found))

    def _chart_for_path(self, path: Path, chart_roots: list[Path]) -> str:
        for chart_root in chart_roots:
            try:
                path.relative_to(chart_root)
                return str(chart_root.relative_to(self.root))
            except ValueError:
                continue
        return ""

    def _analyze_file(
        self,
        path: Path,
        chart_roots: list[Path],
    ) -> tuple[list[HelmFinding], HelmChartInfo | None]:
        findings: list[HelmFinding] = []
        rel = str(path.relative_to(self.root))
        chart_path = self._chart_for_path(path, chart_roots)
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, None

        info = HelmChartInfo(path=chart_path or rel, lines=len(raw_lines))
        is_values = path.name.lower() in VALUES_NAMES
        is_template = "templates" in path.parts
        has_resources = False
        has_run_as_non_root = False
        has_read_only_root = False
        workload_kind = False

        if path.name.lower() == "chart.yaml":
            for line in raw_lines:
                if line.strip().startswith("name:"):
                    info.chart_name = line.split(":", 1)[1].strip().strip("\"'")
                    break
            return findings, info

        if is_values:
            info.values_files = 1

        if is_template:
            info.templates = 1

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    HelmFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged: true grants full host access to the container",
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

            if HOST_PID_PATTERN.search(line):
                findings.append(
                    HelmFinding(
                        kind="host_pid",
                        severity="high",
                        message="hostPID: true shares the host process namespace",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HOST_IPC_PATTERN.search(line):
                findings.append(
                    HelmFinding(
                        kind="host_ipc",
                        severity="medium",
                        message="hostIPC: true shares the host IPC namespace",
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
                        message="runAsUser: 0 runs the container as root",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ALLOW_ESCALATION_PATTERN.search(line):
                findings.append(
                    HelmFinding(
                        kind="privilege_escalation",
                        severity="medium",
                        message="allowPrivilegeEscalation: true permits privilege escalation",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    HelmFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific digest or version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if is_values and HARDCODED_PASSWORD_PATTERN.search(line):
                findings.append(
                    HelmFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential in values — use Kubernetes secrets or external secret manager",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if MISSING_RESOURCE_LIMITS_PATTERN.search(line):
                workload_kind = True

            if RESOURCES_PATTERN.search(line):
                has_resources = True

            if RUN_AS_NON_ROOT_PATTERN.search(line):
                has_run_as_non_root = True

            if READ_ONLY_ROOT_PATTERN.search(line):
                has_read_only_root = True

        if is_template and workload_kind and not has_resources:
            findings.append(
                HelmFinding(
                    kind="missing_resource_limits",
                    severity="low",
                    message="workload without resources limits — set requests and limits",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if is_template and workload_kind and not has_run_as_non_root:
            findings.append(
                HelmFinding(
                    kind="missing_run_as_non_root",
                    severity="medium",
                    message="workload without runAsNonRoot: true in securityContext",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if is_template and workload_kind and not has_read_only_root:
            findings.append(
                HelmFinding(
                    kind="missing_read_only_root",
                    severity="low",
                    message="workload without readOnlyRootFilesystem: true",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[HelmFinding]:
        """Scan Helm charts and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[HelmFinding] = []
        chart_roots = self.charts()
        infos_by_chart: dict[str, HelmChartInfo] = {}
        paths = self.files()

        for path in paths:
            file_findings, info = self._analyze_file(path, chart_roots)
            findings.extend(file_findings)
            if info and info.path:
                if info.path not in infos_by_chart:
                    infos_by_chart[info.path] = HelmChartInfo(
                        path=info.path,
                        chart_name=info.chart_name,
                    )
                chart_info = infos_by_chart[info.path]
                chart_info.templates += info.templates
                chart_info.values_files += info.values_files
                chart_info.lines += info.lines
                if info.chart_name:
                    chart_info.chart_name = info.chart_name

        self._findings = findings
        self._infos = list(infos_by_chart.values())
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = HelmStats(
            charts=len(chart_roots),
            files=len(paths),
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

    def generate_hardened_values_snippet(self) -> str:
        """Scaffold a hardened securityContext and resources block for values.yaml."""
        return """\
# Generated by DevAI HelmAnalyzer — add under your workload values
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL

resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi

image:
  tag: "1.0.0"  # pin version — avoid :latest
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.charts == 0:
            return "Helm charts: none found"
        return (
            f"Helm charts: {stats.charts} chart(s), {stats.files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Helm analysis:",
            f"  charts: {stats.charts}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            name = info.chart_name or info.path
            lines.append(
                f"  - {name}: {info.templates} template(s), "
                f"{info.values_files} values file(s)"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
