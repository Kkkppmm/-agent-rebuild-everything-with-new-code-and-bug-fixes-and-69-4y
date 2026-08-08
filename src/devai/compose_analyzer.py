"""ComposeAnalyzer — audit Docker Compose files for container security."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

COMPOSE_NAMES = (
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
)

SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(r":latest\b", re.IGNORECASE)
SENSITIVE_VOLUME_PATTERN = re.compile(
    r"(/var/run/docker\.sock|/etc/passwd|/etc/shadow|/proc|/sys)",
    re.IGNORECASE,
)


@dataclass
class ComposeFinding:
    """A security or best-practice issue in a Compose file."""

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
class ComposeServiceInfo:
    """Parsed metadata about a Compose service."""

    name: str
    image: str | None = None
    privileged: bool = False
    host_network: bool = False


@dataclass
class ComposeStats:
    """Aggregate Compose analysis statistics."""

    compose_files: int
    services: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_compose_file(path: Path) -> bool:
    return path.name.lower() in COMPOSE_NAMES


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


class ComposeAnalyzer:
    """Audit Docker Compose files for security risks and best practices.

    Scans for privileged containers, host networking, secrets in environment
    variables, :latest image tags, and sensitive volume mounts.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ComposeFinding] | None = None
        self._stats: ComposeStats | None = None
        self._services: list[ComposeServiceInfo] | None = None

    def compose_files(self) -> list[Path]:
        """Return Compose file paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_compose_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[ComposeFinding], list[ComposeServiceInfo]]:
        findings: list[ComposeFinding] = []
        services: list[ComposeServiceInfo] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, services

        current_service: ComposeServiceInfo | None = None
        indent_service = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = _strip_comment(raw)
            if not line:
                continue

            stripped = line.lstrip()
            if stripped.endswith(":") and not stripped.startswith("-") and line == stripped:
                name = stripped[:-1].strip()
                if name and name not in ("services", "volumes", "networks", "version", "name"):
                    current_service = ComposeServiceInfo(name=name)
                    services.append(current_service)
                    indent_service = True
                continue

            if current_service is None:
                continue

            lower = stripped.lower()

            if lower.startswith("image:"):
                image = stripped.split(":", 1)[1].strip().strip("'\"")
                current_service.image = image
                if LATEST_TAG_PATTERN.search(image):
                    findings.append(
                        ComposeFinding(
                            kind="latest_tag",
                            severity="medium",
                            message=f"service '{current_service.name}' uses :latest image tag",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if re.search(r"privileged:\s*true\b", lower):
                current_service.privileged = True
                findings.append(
                    ComposeFinding(
                        kind="privileged",
                        severity="high",
                        message=f"service '{current_service.name}' runs privileged",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if re.search(r"network_mode:\s*host\b", lower):
                current_service.host_network = True
                findings.append(
                    ComposeFinding(
                        kind="host_network",
                        severity="high",
                        message=f"service '{current_service.name}' uses host network mode",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if lower.startswith("- ") and SENSITIVE_VOLUME_PATTERN.search(stripped):
                findings.append(
                    ComposeFinding(
                        kind="sensitive_volume",
                        severity="high",
                        message="volume mount exposes sensitive host path",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if "environment:" in lower or lower.startswith("- ") and "=" in stripped:
                if SECRET_ENV_PATTERN.search(stripped) and "=" in stripped:
                    findings.append(
                        ComposeFinding(
                            kind="secret_in_env",
                            severity="high",
                            message="potential secret in environment variable",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if lower.startswith("ports:") or (lower.startswith("- ") and re.search(r"\d+:\d+", stripped)):
                if re.search(r"0\.0\.0\.0:\d+", stripped):
                    findings.append(
                        ComposeFinding(
                            kind="bind_all_interfaces",
                            severity="medium",
                            message="port bound to 0.0.0.0 — consider restricting to localhost",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if not indent_service and line and not line[0].isspace():
                current_service = None

        return findings, services

    def analyze(self) -> list[ComposeFinding]:
        """Scan Compose files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[ComposeFinding] = []
        all_services: list[ComposeServiceInfo] = []
        paths = self.compose_files()

        for path in paths:
            file_findings, services = self._analyze_file(path)
            findings.extend(file_findings)
            all_services.extend(services)

        self._findings = findings
        self._services = all_services
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = ComposeStats(
            compose_files=len(paths),
            services=len(all_services),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> ComposeStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def services(self) -> list[ComposeServiceInfo]:
        """Return parsed service metadata."""
        if self._services is None:
            self.analyze()
        return self._services  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no Compose files)."""
        self.analyze()
        stats = self.stats
        if stats.compose_files == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.compose_files == 0:
            return "Compose files: none found"
        return (
            f"Compose files: {stats.compose_files} file(s), "
            f"{stats.services} service(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Docker Compose analysis:",
            f"  compose files: {stats.compose_files}",
            f"  services: {stats.services}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
