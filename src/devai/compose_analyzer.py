"""ComposeAnalyzer — audit Docker Compose files for security and best practices."""

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

LATEST_TAG_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
DOCKER_SOCK_PATTERN = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)
HOST_ROOT_MOUNT_PATTERN = re.compile(
    r"['\"]?(?:/|/etc|/proc|/sys)['\"]?\s*:\s*['\"]?(?:/|/etc|/proc|/sys)",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(r"^\s*privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(
    r"^\s*network_mode:\s*['\"]?host['\"]?\s*$",
    re.IGNORECASE,
)
PID_HOST_PATTERN = re.compile(
    r"^\s*pid:\s*['\"]?host['\"]?\s*$",
    re.IGNORECASE,
)
CAP_ADD_ALL_PATTERN = re.compile(r"^\s*-\s*ALL\b", re.IGNORECASE)
SECURE_OPT_UNCONFINED_PATTERN = re.compile(
    r"seccomp:unconfined|apparmor:unconfined",
    re.IGNORECASE,
)
REDIS_NO_AUTH_PORT_PATTERN = re.compile(
    r"^\s*-\s*['\"]?(6379|11211|27017)['\"]?(:\d+)?['\"]?\s*$",
    re.IGNORECASE,
)
RESOURCE_LIMIT_PATTERN = re.compile(
    r"(mem_limit|cpus|deploy:\s*$|resources:\s*$|limits:\s*$|memory:\s*|cpus?:\s*)",
    re.IGNORECASE,
)
USER_PATTERN = re.compile(r"^\s*user:\s+", re.IGNORECASE)


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
class ComposeInfo:
    """Parsed metadata about a Compose file."""

    path: str
    services: list[str] = field(default_factory=list)
    has_networks: bool = False
    has_volumes: bool = False
    lines: int = 0


@dataclass
class ComposeStats:
    """Aggregate Compose analysis statistics."""

    compose_files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_compose_file(path: Path) -> bool:
    name = path.name.lower()
    if name in COMPOSE_NAMES:
        return True
    if name.endswith(".compose.yml") or name.endswith(".compose.yaml"):
        return True
    return False


class ComposeAnalyzer:
    """Audit Docker Compose files for security risks and container best practices.

    Scans for privileged mode, host networking, :latest image tags, secrets in
    environment blocks, dangerous volume mounts, missing resource limits, and
    other common misconfigurations.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ComposeFinding] | None = None
        self._stats: ComposeStats | None = None
        self._infos: list[ComposeInfo] | None = None

    def compose_files(self) -> list[Path]:
        """Return Docker Compose file paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_compose_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[ComposeFinding], ComposeInfo]:
        findings: list[ComposeFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, ComposeInfo(path=rel)

        info = ComposeInfo(path=rel, lines=len(raw_lines))
        current_service = ""
        in_services = False
        service_indent = 0
        service_has_user = False
        service_has_resources = False
        in_environment = False
        env_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            indent = len(raw) - len(raw.lstrip())

            if indent == 0 and (line == "services:" or line.startswith("services:")):
                in_services = True
                current_service = ""
                continue

            if indent == 0 and (line == "networks:" or line.startswith("networks:")):
                info.has_networks = True
                in_services = False
                current_service = ""
                continue

            if indent == 0 and (line == "volumes:" or line.startswith("volumes:")):
                info.has_volumes = True
                in_services = False
                current_service = ""
                continue

            if in_services:
                if line.endswith(":") and not line.startswith("-") and indent <= 2:
                    key = line[:-1].strip()
                    if key and key[0].isalpha() and key not in ("version", "name"):
                        if current_service and not service_has_user:
                            findings.append(
                                ComposeFinding(
                                    kind="no_user",
                                    severity="medium",
                                    message=(
                                        "service has no user: directive — "
                                        "container may run as root"
                                    ),
                                    path=rel,
                                    lineno=lineno,
                                    service=current_service,
                                )
                            )
                        if current_service and not service_has_resources:
                            findings.append(
                                ComposeFinding(
                                    kind="no_resource_limits",
                                    severity="low",
                                    message=(
                                        "no memory/cpu limits — "
                                        "set deploy.resources or mem_limit"
                                    ),
                                    path=rel,
                                    lineno=lineno,
                                    service=current_service,
                                )
                            )
                        current_service = key
                        info.services.append(key)
                        service_indent = indent
                        service_has_user = False
                        service_has_resources = False
                        in_environment = False
                        continue

                if current_service and indent > service_indent:
                    if PRIVILEGED_PATTERN.match(line):
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

                    if HOST_NETWORK_PATTERN.match(line):
                        findings.append(
                            ComposeFinding(
                                kind="host_network",
                                severity="high",
                                message="network_mode: host bypasses container network isolation",
                                path=rel,
                                lineno=lineno,
                                service=current_service,
                                line=raw.strip(),
                            )
                        )

                    if PID_HOST_PATTERN.match(line):
                        findings.append(
                            ComposeFinding(
                                kind="pid_host",
                                severity="high",
                                message="pid: host shares host PID namespace",
                                path=rel,
                                lineno=lineno,
                                service=current_service,
                                line=raw.strip(),
                            )
                        )

                    if LATEST_TAG_PATTERN.search(line):
                        findings.append(
                            ComposeFinding(
                                kind="latest_tag",
                                severity="medium",
                                message="image uses :latest tag — pin to a specific version",
                                path=rel,
                                lineno=lineno,
                                service=current_service,
                                line=raw.strip(),
                            )
                        )

                    if DOCKER_SOCK_PATTERN.search(line):
                        findings.append(
                            ComposeFinding(
                                kind="docker_sock_mount",
                                severity="high",
                                message=(
                                    "mounting /var/run/docker.sock grants host Docker API access"
                                ),
                                path=rel,
                                lineno=lineno,
                                service=current_service,
                                line=raw.strip(),
                            )
                        )

                    if HOST_ROOT_MOUNT_PATTERN.search(line):
                        findings.append(
                            ComposeFinding(
                                kind="host_root_mount",
                                severity="high",
                                message="mounting host root or sensitive paths is dangerous",
                                path=rel,
                                lineno=lineno,
                                service=current_service,
                                line=raw.strip(),
                            )
                        )

                    if CAP_ADD_ALL_PATTERN.match(line):
                        findings.append(
                            ComposeFinding(
                                kind="cap_add_all",
                                severity="high",
                                message="cap_add: ALL grants every Linux capability",
                                path=rel,
                                lineno=lineno,
                                service=current_service,
                                line=raw.strip(),
                            )
                        )

                    if SECURE_OPT_UNCONFINED_PATTERN.search(line):
                        findings.append(
                            ComposeFinding(
                                kind="unconfined_security_opt",
                                severity="medium",
                                message="unconfined seccomp/apparmor weakens container isolation",
                                path=rel,
                                lineno=lineno,
                                service=current_service,
                                line=raw.strip(),
                            )
                        )

                    if REDIS_NO_AUTH_PORT_PATTERN.match(line):
                        findings.append(
                            ComposeFinding(
                                kind="exposed_data_service",
                                severity="medium",
                                message=(
                                    "data service port published without auth hints — "
                                    "restrict access and require authentication"
                                ),
                                path=rel,
                                lineno=lineno,
                                service=current_service,
                                line=raw.strip(),
                            )
                        )

                    if line == "environment:" or line.startswith("environment:"):
                        in_environment = True
                        env_indent = indent
                        continue

                    if in_environment:
                        child_indent = len(raw) - len(raw.lstrip())
                        if child_indent <= env_indent and line.endswith(":"):
                            in_environment = False
                        elif SECRET_ENV_PATTERN.search(line):
                            findings.append(
                                ComposeFinding(
                                    kind="secret_in_environment",
                                    severity="high",
                                    message=(
                                        "potential secret in environment — "
                                        "use secrets or env_file with restricted permissions"
                                    ),
                                    path=rel,
                                    lineno=lineno,
                                    service=current_service,
                                    line=raw.strip(),
                                )
                            )

                    if USER_PATTERN.match(line):
                        service_has_user = True

                    if RESOURCE_LIMIT_PATTERN.search(line):
                        service_has_resources = True

        if current_service and not service_has_user:
            findings.append(
                ComposeFinding(
                    kind="no_user",
                    severity="medium",
                    message="service has no user: directive — container may run as root",
                    path=rel,
                    lineno=info.lines,
                    service=current_service,
                )
            )
        if current_service and not service_has_resources:
            findings.append(
                ComposeFinding(
                    kind="no_resource_limits",
                    severity="low",
                    message="no memory/cpu limits — set deploy.resources or mem_limit",
                    path=rel,
                    lineno=info.lines,
                    service=current_service,
                )
            )

        return findings, info

    def analyze(self) -> list[ComposeFinding]:
        """Scan Compose files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[ComposeFinding] = []
        infos: list[ComposeInfo] = []
        paths = self.compose_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = ComposeStats(
            compose_files=len(paths),
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
    def infos(self) -> list[ComposeInfo]:
        """Return parsed Compose file metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

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

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened Docker Compose template."""
        return """\
# Generated by DevAI ComposeAnalyzer
services:
  app:
    image: python:3.12-slim
    user: "1000:1000"
    read_only: true
    tmpfs:
      - /tmp
    ports:
      - "127.0.0.1:8000:8000"
    environment:
      APP_ENV: production
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 512M
        reservations:
          cpus: "0.25"
          memory: 128M
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"]
      interval: 30s
      timeout: 3s
      retries: 3
    networks:
      - backend

networks:
  backend:
    driver: bridge
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.compose_files == 0:
            return "Compose files: none found"
        lines = [
            (
                f"Compose files: {stats.compose_files} file(s), "
                f"{stats.findings} finding(s) "
                f"({stats.high_severity} high, {stats.medium_severity} medium, "
                f"{stats.low_severity} low)"
            ),
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self) -> str:
        """Export findings as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "# Docker Compose Audit",
            "",
            self.summary(),
            "",
        ]
        if self.infos:
            lines.append("## Files")
            for info in self.infos:
                svc = ", ".join(info.services) if info.services else "none"
                lines.append(f"- {info.path}: {len(info.services)} service(s) [{svc}]")
            lines.append("")
        findings = self._findings or []
        if findings:
            lines.append("## Findings")
            for finding in findings[:50]:
                lines.append(f"- {finding.format()}")
            if len(findings) > 50:
                lines.append(f"- ... and {len(findings) - 50} more")
        return "\n".join(lines)
