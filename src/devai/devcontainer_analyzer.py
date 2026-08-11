"""DevContainerAnalyzer — audit dev container configs for security and best practices."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

DEVCONTAINER_NAMES = ("devcontainer.json",)
DEVCONTAINER_DIRS = (".devcontainer", "devcontainer")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_ENV_VALUE_PATTERN = re.compile(
    r"[\"'](?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE[_-]?KEY)[\"']\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']+[\"']",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DOCKER_SOCKET_PATTERN = re.compile(
    r"/var/run/docker\.sock",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"(?:\"privileged\"\s*:\s*true|--privileged\b|privileged:\s*true)",
    re.IGNORECASE,
)
ROOT_USER_PATTERN = re.compile(
    r"(?:\"(?:remoteUser|containerUser)\"\s*:\s*\"root\"|\"user\"\s*:\s*\"root\")",
    re.IGNORECASE,
)
DANGEROUS_CAP_PATTERN = re.compile(
    r"(?:SYS_ADMIN|NET_ADMIN|SYS_PTRACE|DAC_READ_SEARCH|ALL)",
)
UNCONFINED_SECURITY_PATTERN = re.compile(
    r"(?:seccomp:unconfined|apparmor:unconfined|label:disable)",
    re.IGNORECASE,
)
SENSITIVE_HOST_MOUNT_PATTERN = re.compile(
    r"(?:source|src)\s*=\s*(?:/|/etc|/root|/var/run|/proc|/sys)(?:[,/]|\"|$)",
    re.IGNORECASE,
)
LATEST_IMAGE_PATTERN = re.compile(
    r"(?:\"image\"\s*:\s*\"[^\"]+:latest\"|FROM\s+[^\s]+:latest\b)",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)


@dataclass
class DevContainerFinding:
    """A security or best-practice issue in a dev container config."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int = 0
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}" if self.lineno else self.path
        return f"[{self.severity}] {loc} — {self.message}"


@dataclass
class DevContainerInfo:
    """Parsed metadata about a dev container config."""

    path: str
    image: str = ""
    remote_user: str = ""
    features: list[str] = field(default_factory=list)
    forward_ports: list[int] = field(default_factory=list)
    lines: int = 0


@dataclass
class DevContainerStats:
    """Aggregate dev container analysis statistics."""

    containers: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_devcontainer_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in DEVCONTAINER_NAMES:
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(DEVCONTAINER_DIRS) and lower.endswith(".json"):
        return True
    return False


def _line_number_for_match(raw_lines: list[str], pattern: re.Pattern[str], text: str) -> int:
    for lineno, raw in enumerate(raw_lines, start=1):
        if pattern.search(raw) or pattern.search(text):
            return lineno
    return 1


class DevContainerAnalyzer:
    """Audit dev container configs for privileged mode, root user, and unsafe mounts.

    Scans ``.devcontainer/devcontainer.json`` and related files for Docker socket mounts,
    hardcoded secrets in ``containerEnv``/``remoteEnv``, curl-pipe-to-shell in lifecycle
    commands, dangerous capabilities, and host filesystem bind mounts.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[DevContainerFinding] | None = None
        self._stats: DevContainerStats | None = None
        self._infos: list[DevContainerInfo] | None = None

    def files(self) -> list[Path]:
        """Return dev container config paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_devcontainer_file(path):
                found.append(path)
        return found

    def _add_finding(
        self,
        findings: list[DevContainerFinding],
        *,
        kind: str,
        severity: str,
        message: str,
        rel: str,
        raw_lines: list[str],
        pattern: re.Pattern[str] | None = None,
        text: str = "",
        lineno: int = 0,
        line: str = "",
    ) -> None:
        if lineno == 0 and pattern is not None:
            lineno = _line_number_for_match(raw_lines, pattern, text)
        findings.append(
            DevContainerFinding(
                kind=kind,
                severity=severity,
                message=message,
                path=rel,
                lineno=lineno,
                line=line,
            )
        )

    def _analyze_json_content(
        self,
        path: Path,
        raw: str,
        raw_lines: list[str],
    ) -> tuple[list[DevContainerFinding], DevContainerInfo]:
        findings: list[DevContainerFinding] = []
        rel = str(path.relative_to(self.root))
        info = DevContainerInfo(path=rel, lines=len(raw_lines))

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            self._add_finding(
                findings,
                kind="invalid_json",
                severity="medium",
                message="devcontainer.json is not valid JSON",
                rel=rel,
                raw_lines=raw_lines,
                lineno=1,
            )
            return findings, info

        if not isinstance(data, dict):
            return findings, info

        if isinstance(data.get("image"), str):
            info.image = data["image"]
            if data["image"].endswith(":latest"):
                self._add_finding(
                    findings,
                    kind="latest_image_tag",
                    severity="medium",
                    message="image uses :latest tag — pin to a specific digest or version",
                    rel=rel,
                    raw_lines=raw_lines,
                    text=data["image"],
                )

        for user_key in ("remoteUser", "containerUser"):
            user = data.get(user_key)
            if isinstance(user, str) and user.lower() == "root":
                info.remote_user = user
                self._add_finding(
                    findings,
                    kind="root_user",
                    severity="medium",
                    message=f"{user_key} is root — use a non-root user for development containers",
                    rel=rel,
                    raw_lines=raw_lines,
                    pattern=ROOT_USER_PATTERN,
                    text=user_key,
                )

        if data.get("privileged") is True:
            self._add_finding(
                findings,
                kind="privileged",
                severity="high",
                message="privileged: true grants full host capabilities to the container",
                rel=rel,
                raw_lines=raw_lines,
                pattern=PRIVILEGED_PATTERN,
            )

        run_args = data.get("runArgs", [])
        if isinstance(run_args, list):
            for arg in run_args:
                if isinstance(arg, str) and "--privileged" in arg:
                    self._add_finding(
                        findings,
                        kind="privileged",
                        severity="high",
                        message="--privileged in runArgs grants full host capabilities",
                        rel=rel,
                        raw_lines=raw_lines,
                        pattern=PRIVILEGED_PATTERN,
                        text=arg,
                    )

        cap_add = data.get("capAdd", [])
        if isinstance(cap_add, list):
            for cap in cap_add:
                if isinstance(cap, str) and DANGEROUS_CAP_PATTERN.search(cap):
                    self._add_finding(
                        findings,
                        kind="dangerous_capability",
                        severity="high",
                        message=f"capAdd includes dangerous capability {cap!r}",
                        rel=rel,
                        raw_lines=raw_lines,
                        text=cap,
                    )

        security_opt = data.get("securityOpt", [])
        if isinstance(security_opt, list):
            for opt in security_opt:
                if isinstance(opt, str) and UNCONFINED_SECURITY_PATTERN.search(opt):
                    self._add_finding(
                        findings,
                        kind="unconfined_security",
                        severity="high",
                        message=f"securityOpt disables sandboxing: {opt!r}",
                        rel=rel,
                        raw_lines=raw_lines,
                        text=opt,
                    )

        for env_key in ("containerEnv", "remoteEnv"):
            env = data.get(env_key)
            if isinstance(env, dict):
                for key, value in env.items():
                    if not isinstance(value, str):
                        continue
                    secret_key = re.search(
                        r"(password|secret|api[_-]?key|token|credential|private[_-]?key)",
                        str(key),
                        re.IGNORECASE,
                    )
                    if secret_key and value and not value.startswith("${"):
                        self._add_finding(
                            findings,
                            kind="hardcoded_secret",
                            severity="high",
                            message=(
                                f"potential secret hardcoded in {env_key}.{key} — "
                                "use dev container secrets or local env files"
                            ),
                            rel=rel,
                            raw_lines=raw_lines,
                            text=str(key),
                        )

        for cmd_key in ("postCreateCommand", "postStartCommand", "postAttachCommand", "updateContentCommand"):
            cmd = data.get(cmd_key)
            commands: list[str] = []
            if isinstance(cmd, str):
                commands = [cmd]
            elif isinstance(cmd, list):
                commands = [c for c in cmd if isinstance(c, str)]
            for command in commands:
                if CURL_PIPE_SHELL_PATTERN.search(command):
                    self._add_finding(
                        findings,
                        kind="curl_pipe_shell",
                        severity="high",
                        message=f"piping curl/wget to shell in {cmd_key} is unsafe",
                        rel=rel,
                        raw_lines=raw_lines,
                        pattern=CURL_PIPE_SHELL_PATTERN,
                        text=command,
                    )
                if INSECURE_HTTP_PATTERN.search(command):
                    self._add_finding(
                        findings,
                        kind="insecure_http",
                        severity="low",
                        message=f"insecure HTTP URL in {cmd_key} — prefer HTTPS",
                        rel=rel,
                        raw_lines=raw_lines,
                        pattern=INSECURE_HTTP_PATTERN,
                        text=command,
                    )

        mounts = data.get("mounts", [])
        if isinstance(mounts, list):
            for mount in mounts:
                mount_str = mount if isinstance(mount, str) else json.dumps(mount)
                if DOCKER_SOCKET_PATTERN.search(mount_str):
                    self._add_finding(
                        findings,
                        kind="docker_socket_mount",
                        severity="high",
                        message="Docker socket mount grants host-level container access",
                        rel=rel,
                        raw_lines=raw_lines,
                        pattern=DOCKER_SOCKET_PATTERN,
                        text=mount_str,
                    )
                if SENSITIVE_HOST_MOUNT_PATTERN.search(mount_str):
                    self._add_finding(
                        findings,
                        kind="sensitive_host_mount",
                        severity="high",
                        message="bind mount exposes sensitive host path into the dev container",
                        rel=rel,
                        raw_lines=raw_lines,
                        pattern=SENSITIVE_HOST_MOUNT_PATTERN,
                        text=mount_str,
                    )

        mount = data.get("mount")
        if isinstance(mount, str):
            if DOCKER_SOCKET_PATTERN.search(mount):
                self._add_finding(
                    findings,
                    kind="docker_socket_mount",
                    severity="high",
                    message="Docker socket mount grants host-level container access",
                    rel=rel,
                    raw_lines=raw_lines,
                    pattern=DOCKER_SOCKET_PATTERN,
                    text=mount,
                )

        features = data.get("features", {})
        if isinstance(features, dict):
            info.features = list(features.keys())

        forward_ports = data.get("forwardPorts", [])
        if isinstance(forward_ports, list):
            for port in forward_ports:
                if isinstance(port, int):
                    info.forward_ports.append(port)
                elif isinstance(port, str) and port.isdigit():
                    info.forward_ports.append(int(port))

        for raw_line in raw_lines:
            if HARDCODED_SECRET_PATTERN.search(raw_line):
                self._add_finding(
                    findings,
                    kind="hardcoded_secret",
                    severity="high",
                    message="potential secret hardcoded in devcontainer config",
                    rel=rel,
                    raw_lines=raw_lines,
                    pattern=HARDCODED_SECRET_PATTERN,
                    line=raw_line.strip(),
                )
            if HARDCODED_ENV_VALUE_PATTERN.search(raw_line):
                self._add_finding(
                    findings,
                    kind="hardcoded_secret",
                    severity="high",
                    message="potential secret hardcoded in environment variable",
                    rel=rel,
                    raw_lines=raw_lines,
                    pattern=HARDCODED_ENV_VALUE_PATTERN,
                    line=raw_line.strip(),
                )

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[DevContainerFinding], DevContainerInfo]:
        rel = str(path.relative_to(self.root))
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = raw.splitlines()
        except OSError:
            return [], DevContainerInfo(path=rel)

        if path.name.lower() == "docker-compose.yml" or path.name.lower().endswith("docker-compose.json"):
            return self._analyze_compose_file(path, raw, raw_lines)

        return self._analyze_json_content(path, raw, raw_lines)

    def _analyze_compose_file(
        self,
        path: Path,
        raw: str,
        raw_lines: list[str],
    ) -> tuple[list[DevContainerFinding], DevContainerInfo]:
        findings: list[DevContainerFinding] = []
        rel = str(path.relative_to(self.root))
        info = DevContainerInfo(path=rel, lines=len(raw_lines))

        if PRIVILEGED_PATTERN.search(raw):
            self._add_finding(
                findings,
                kind="privileged",
                severity="high",
                message="privileged mode enabled in dev container compose file",
                rel=rel,
                raw_lines=raw_lines,
                pattern=PRIVILEGED_PATTERN,
            )

        if DOCKER_SOCKET_PATTERN.search(raw):
            self._add_finding(
                findings,
                kind="docker_socket_mount",
                severity="high",
                message="Docker socket mount in compose file grants host-level access",
                rel=rel,
                raw_lines=raw_lines,
                pattern=DOCKER_SOCKET_PATTERN,
            )

        for lineno, line in enumerate(raw_lines, start=1):
            if CURL_PIPE_SHELL_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="curl_pipe_shell",
                    severity="high",
                    message="piping curl/wget to shell in compose command is unsafe",
                    rel=rel,
                    raw_lines=raw_lines,
                    lineno=lineno,
                    line=line.strip(),
                )

        return findings, info

    def analyze(self) -> list[DevContainerFinding]:
        """Scan dev container configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[DevContainerFinding] = []
        infos: list[DevContainerInfo] = []
        paths = self.files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        compose_dir = self.root / ".devcontainer"
        if compose_dir.is_dir():
            for compose_name in ("docker-compose.yml", "docker-compose.yaml"):
                compose_path = compose_dir / compose_name
                if compose_path.is_file() and compose_path not in paths:
                    file_findings, info = self._analyze_compose_file(
                        compose_path,
                        compose_path.read_text(encoding="utf-8", errors="replace"),
                        compose_path.read_text(encoding="utf-8", errors="replace").splitlines(),
                    )
                    findings.extend(file_findings)
                    infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        container_count = len(infos) if infos else len(paths)
        self._stats = DevContainerStats(
            containers=container_count,
            files=container_count,
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> DevContainerStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[DevContainerInfo]:
        """Return parsed dev container metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no configs)."""
        self.analyze()
        stats = self.stats
        if stats.containers == 0:
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
        """Scaffold a hardened dev container template."""
        return """\
// Generated by DevAI DevContainerAnalyzer
{
  "name": "DevAI Python",
  "image": "mcr.microsoft.com/devcontainers/python:3.12",
  "remoteUser": "vscode",
  "features": {
    "ghcr.io/devcontainers/features/git:1": {}
  },
  "customizations": {
    "vscode": {
      "extensions": ["ms-python.python", "charliermarsh.ruff"]
    }
  },
  "postCreateCommand": "pip install -e '.[dev]'",
  "forwardPorts": [8000],
  "portsAttributes": {
    "8000": {
      "label": "app",
      "onAutoForward": "notify"
    }
  }
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.containers == 0:
            return "Dev containers: none found"
        return (
            f"Dev containers: {stats.containers} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Dev container analysis:",
            f"  containers: {stats.containers}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            image = info.image or "unspecified"
            user = info.remote_user or "default"
            lines.append(f"  - {info.path}: image={image}, user={user}")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
