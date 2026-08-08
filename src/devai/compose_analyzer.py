"""ComposeAnalyzer — audit Docker Compose files for container security issues."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
COMPOSE_SUFFIXES = (".compose.yml", ".compose.yaml")

LATEST_TAG_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(r"privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"network_mode:\s*[\"']?host[\"']?\b", re.IGNORECASE)
CAP_ALL_PATTERN = re.compile(r"cap_add:\s*(\n\s*-\s*)?ALL\b", re.IGNORECASE)
DOCKER_SOCK_PATTERN = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential)\s*[:=]\s*['\"]?[^\s'\"${}]+",
    re.IGNORECASE,
)
ROOT_USER_PATTERN = re.compile(r"user:\s*[\"']?(root|0)[\"']?\s*$", re.IGNORECASE)


@dataclass
class ComposeFinding:
    """A security or best-practice issue in a Docker Compose file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    service: str = ""
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        svc = f" ({self.service})" if self.service else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{svc} — {self.message}"


@dataclass
class ComposeServiceInfo:
    """Parsed metadata about a compose service."""

    name: str
    image: str = ""
    privileged: bool = False
    host_network: bool = False


@dataclass
class ComposeStats:
    """Aggregate Docker Compose analysis statistics."""

    compose_files: int
    services: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_compose_file(path: Path) -> bool:
    name = path.name.lower()
    if name in COMPOSE_NAMES:
        return True
    return any(name.endswith(suffix) for suffix in COMPOSE_SUFFIXES)


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].rstrip()
    return line.rstrip()


class ComposeAnalyzer:
    """Audit Docker Compose files for container security risks.

    Detects privileged mode, host networking, docker.sock mounts, :latest tags,
    secrets in environment, and excessive Linux capabilities.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ComposeFinding] | None = None
        self._stats: ComposeStats | None = None
        self._services: list[ComposeServiceInfo] | None = None

    def compose_files(self) -> list[Path]:
        """Return Docker Compose file paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            if _is_compose_file(path):
                found.append(path)
        return found

    def _current_service(self, line: str, current: str) -> str:
        match = re.match(r"^\s{2}([\w-]+):\s*$", line)
        if match and match.group(1) not in ("services", "volumes", "networks", "secrets", "configs"):
            return match.group(1)
        return current

    def _analyze_file(self, path: Path) -> tuple[list[ComposeFinding], list[ComposeServiceInfo]]:
        findings: list[ComposeFinding] = []
        services: list[ComposeServiceInfo] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, services

        current_service = ""
        service_map: dict[str, ComposeServiceInfo] = {}
        in_cap_add = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = _strip_comment(raw)
            if not line.strip():
                continue

            current_service = self._current_service(line, current_service)
            if current_service and current_service not in service_map:
                info = ComposeServiceInfo(name=current_service)
                service_map[current_service] = info
                services.append(info)

            info = service_map.get(current_service)
            stripped = line.strip()

            if re.match(r"^\s*cap_add:\s*$", line, re.IGNORECASE):
                in_cap_add = True
            elif in_cap_add and re.match(r"^\s*-\s*ALL\s*$", stripped, re.IGNORECASE):
                findings.append(
                    ComposeFinding(
                        kind="cap_add_all",
                        severity="high",
                        message="cap_add: ALL grants excessive Linux capabilities",
                        path=rel,
                        lineno=lineno,
                        service=current_service,
                        line=raw.strip(),
                    )
                )
                in_cap_add = False
            elif stripped and not stripped.startswith("-") and not line.startswith(" " * 4):
                in_cap_add = False

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    ComposeFinding(
                        kind="latest_tag",
                        severity="medium",
                        message="service image uses :latest — pin a specific version",
                        path=rel,
                        lineno=lineno,
                        service=current_service,
                        line=raw.strip(),
                    )
                )
                if info and "image:" in line:
                    info.image = line.split("image:", 1)[1].strip()

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    ComposeFinding(
                        kind="privileged",
                        severity="high",
                        message="privileged: true grants full host access to the container",
                        path=rel,
                        lineno=lineno,
                        service=current_service,
                        line=raw.strip(),
                    )
                )
                if info:
                    info.privileged = True

            if HOST_NETWORK_PATTERN.search(line):
                findings.append(
                    ComposeFinding(
                        kind="host_network",
                        severity="high",
                        message="host network mode bypasses container network isolation",
                        path=rel,
                        lineno=lineno,
                        service=current_service,
                        line=raw.strip(),
                    )
                )
                if info:
                    info.host_network = True

            if DOCKER_SOCK_PATTERN.search(line):
                findings.append(
                    ComposeFinding(
                        kind="docker_sock_mount",
                        severity="high",
                        message="mounting /var/run/docker.sock enables host container escape",
                        path=rel,
                        lineno=lineno,
                        service=current_service,
                        line=raw.strip(),
                    )
                )

            if SECRET_ENV_PATTERN.search(line):
                if "${" not in line:
                    findings.append(
                        ComposeFinding(
                            kind="secret_in_env",
                            severity="high",
                            message="potential secret in environment — use Docker secrets",
                            path=rel,
                            lineno=lineno,
                            service=current_service,
                            line=raw.strip(),
                        )
                    )

            if ROOT_USER_PATTERN.search(line):
                findings.append(
                    ComposeFinding(
                        kind="runs_as_root",
                        severity="medium",
                        message="service runs as root — use a non-root user",
                        path=rel,
                        lineno=lineno,
                        service=current_service,
                        line=raw.strip(),
                    )
                )

        return findings, services

    def analyze(self) -> list[ComposeFinding]:
        """Scan compose files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[ComposeFinding] = []
        services: list[ComposeServiceInfo] = []
        paths = self.compose_files()

        for path in paths:
            file_findings, file_services = self._analyze_file(path)
            findings.extend(file_findings)
            services.extend(file_services)

        self._findings = findings
        self._services = services
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = ComposeStats(
            compose_files=len(paths),
            services=len(services),
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
        """Return a 0-100 health score (100 = no issues or no compose files)."""
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

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened Docker Compose template."""
        return """\
# Generated by DevAI ComposeAnalyzer
services:
  app:
    image: python:3.12-slim
    user: "1000:1000"
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    environment:
      - DATABASE_URL=${DATABASE_URL}
    ports:
      - "8000:8000"
    healthcheck:
      test: ["CMD", "python", "-c", "print('ok')"]
      interval: 30s
      timeout: 3s
"""

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
            "Compose analysis:",
            f"  compose files: {stats.compose_files}",
            f"  services: {stats.services}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for svc in self.services[:15]:
            flags = []
            if svc.privileged:
                flags.append("privileged")
            if svc.host_network:
                flags.append("host-network")
            flag_text = f" [{', '.join(flags)}]" if flags else ""
            lines.append(f"  - {svc.name}{flag_text}")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
