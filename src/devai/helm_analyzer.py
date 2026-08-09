"""HelmAnalyzer — audit Helm charts for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

LATEST_TAG_PATTERN = re.compile(
    r"(image:\s*[^\s]+:latest\b|tag:\s*['\"]?latest['\"]?\s*$)",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(r"privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"hostNetwork:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"hostPID:\s*true\b", re.IGNORECASE)
SECRET_INLINE_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential)\s*:\s*['\"][^'\"]{4,}['\"]",
    re.IGNORECASE,
)
RUN_AS_ROOT_PATTERN = re.compile(r"runAsUser:\s*0\b", re.IGNORECASE)
NO_RESOURCES_PATTERN = re.compile(r"resources:\s*\{\s*\}", re.IGNORECASE)
ALLOW_PRIVILEGE_ESCALATION_PATTERN = re.compile(
    r"allowPrivilegeEscalation:\s*true\b",
    re.IGNORECASE,
)
CAP_SYS_ADMIN_PATTERN = re.compile(r"SYS_ADMIN", re.IGNORECASE)


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
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class HelmInfo:
    """Parsed metadata about a Helm chart file."""

    path: str
    chart_name: str = ""
    templates: int = 0
    lines: int = 0


@dataclass
class HelmStats:
    """Aggregate Helm chart analysis statistics."""

    charts: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_helm_template(path: Path) -> bool:
    parts = path.parts
    if "templates" in parts and path.suffix in (".yaml", ".yml", ".tpl"):
        return True
    if path.name == "values.yaml" or path.name == "values.yml":
        return True
    return False


class HelmAnalyzer:
    """Audit Helm charts for privileged pods, latest tags, and hardcoded secrets."""

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[HelmFinding] | None = None
        self._stats: HelmStats | None = None
        self._infos: list[HelmInfo] | None = None

    def chart_files(self) -> list[Path]:
        """Return Helm chart template and values file paths."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_helm_template(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[HelmFinding], HelmInfo]:
        findings: list[HelmFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, HelmInfo(path=rel)

        info = HelmInfo(path=rel, lines=len(raw_lines))
        if "Chart.yaml" in path.name:
            for line in raw_lines:
                if line.strip().startswith("name:"):
                    info.chart_name = line.split(":", 1)[1].strip()
                    break

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("apiVersion:"):
                info.templates += 1

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    HelmFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="Container image uses :latest tag",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    HelmFinding(
                        kind="privileged_pod",
                        severity="high",
                        message="Pod runs in privileged mode",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if HOST_NETWORK_PATTERN.search(line):
                findings.append(
                    HelmFinding(
                        kind="host_network",
                        severity="high",
                        message="Pod uses host networking",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if HOST_PID_PATTERN.search(line):
                findings.append(
                    HelmFinding(
                        kind="host_pid",
                        severity="high",
                        message="Pod uses host PID namespace",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if SECRET_INLINE_PATTERN.search(line):
                findings.append(
                    HelmFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="Hardcoded secret in chart template or values",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if RUN_AS_ROOT_PATTERN.search(line):
                findings.append(
                    HelmFinding(
                        kind="run_as_root",
                        severity="high",
                        message="Container runs as root (runAsUser: 0)",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if ALLOW_PRIVILEGE_ESCALATION_PATTERN.search(line):
                findings.append(
                    HelmFinding(
                        kind="privilege_escalation",
                        severity="medium",
                        message="allowPrivilegeEscalation is true",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if CAP_SYS_ADMIN_PATTERN.search(line):
                findings.append(
                    HelmFinding(
                        kind="dangerous_capability",
                        severity="high",
                        message="SYS_ADMIN capability granted",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if NO_RESOURCES_PATTERN.search(line):
                findings.append(
                    HelmFinding(
                        kind="no_resource_limits",
                        severity="low",
                        message="Empty resources block — no CPU/memory limits set",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

        return findings, info

    def analyze(self) -> list[HelmFinding]:
        if self._findings is not None:
            return self._findings

        findings: list[HelmFinding] = []
        infos: list[HelmInfo] = []
        paths = self.chart_files()
        chart_dirs = {p.parent.parent for p in paths if "templates" in p.parts}

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        self._findings = findings
        self._infos = infos
        self._stats = HelmStats(
            charts=len(chart_dirs) if chart_dirs else len({p.parent for p in paths}),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> HelmStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[HelmInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        stats = self.stats
        if stats.charts == 0 or stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.charts == 0:
            return "Helm: none found"
        return (
            f"Helm: {stats.charts} chart(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Helm chart analysis:",
            f"  charts: {stats.charts}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
