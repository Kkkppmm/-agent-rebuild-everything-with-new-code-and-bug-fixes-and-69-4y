"""DevContainerAnalyzer — audit dev container configs for security and best practices."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

DEVCONTAINER_NAMES = ("devcontainer.json",)
DEVCONTAINER_DIRS = (".devcontainer",)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_ENV_VALUE_PATTERN = re.compile(
    r"^\s*\"(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE[_-]?KEY|AWS_[A-Z0-9_]+)\"\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']+[\"']",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:\"image\"\s*:\s*\"[^\"]+:latest\"|\"tag\"\s*:\s*\"latest\")",
    re.IGNORECASE,
)
DOCKER_SOCKET_MOUNT_PATTERN = re.compile(
    r"/var/run/docker\.sock",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"(?:--privileged|\"privileged\"\s*:\s*true|privileged\s*:\s*true)",
    re.IGNORECASE,
)
ROOT_USER_PATTERN = re.compile(
    r"(?:\"(?:remoteUser|containerUser)\"\s*:\s*\"root\"|\"user\"\s*:\s*\"root\")",
    re.IGNORECASE,
)
HOST_NETWORK_PATTERN = re.compile(
    r"(?:--network[=\s]+host|\"networkMode\"\s*:\s*\"host\")",
    re.IGNORECASE,
)
HOST_MOUNT_PATTERN = re.compile(
    r"(?:\"source\"\s*:\s*\"(?:/|/etc|/proc|/sys)\"|"
    r"-v\s+/(?:etc|proc|sys|):|/var/run/docker\.sock)",
    re.IGNORECASE,
)
DANGEROUS_CAP_PATTERN = re.compile(
    r"(?:--cap-add[= ](?:SYS_ADMIN|NET_ADMIN|NET_RAW|SYS_PTRACE|DAC_READ_SEARCH|ALL)\b|"
    r"\"capAdd\"\s*:\s*\[[^\]]*(?:SYS_ADMIN|NET_ADMIN|NET_RAW|ALL))",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
UNCONFINED_SECURITY_OPT_PATTERN = re.compile(
    r"(?:seccomp:unconfined|apparmor:unconfined|label:disable)",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(
    r"[\"']?AKIA[0-9A-Z]{16}[\"']?",
    re.IGNORECASE,
)
FORWARD_ALL_PORTS_PATTERN = re.compile(
    r"\"forwardPorts\"\s*:\s*\[\s*0\s*\]",
    re.IGNORECASE,
)
FEATURE_CURL_INSTALL_PATTERN = re.compile(
    r"\"features\"\s*:\s*\{[^}]*(?:curl|wget)[^}]*\|",
    re.IGNORECASE | re.DOTALL,
)
LIFECYCLE_COMMAND_KEYS = (
    "postCreateCommand",
    "postStartCommand",
    "postAttachCommand",
    "initializeCommand",
    "onCreateCommand",
    "updateContentCommand",
    "waitFor",
)


@dataclass
class DevContainerFinding:
    """A security or best-practice issue in a dev container config."""

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
class DevContainerInfo:
    """Parsed metadata about a dev container config file."""

    path: str
    image: str | None = None
    remote_user: str | None = None
    features: list[str] = field(default_factory=list)
    forward_ports: list[int] = field(default_factory=list)
    lines: int = 0


@dataclass
class DevContainerStats:
    """Aggregate dev container analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _strip_json_comments(text: str) -> str:
    """Remove // and /* */ comments for JSONC devcontainer files."""
    result: list[str] = []
    i = 0
    in_string = False
    escape = False
    while i < len(text):
        ch = text[i]
        if escape:
            result.append(ch)
            escape = False
            i += 1
            continue
        if ch == "\\" and in_string:
            result.append(ch)
            escape = True
            i += 1
            continue
        if ch == '"':
            in_string = not in_string
            result.append(ch)
            i += 1
            continue
        if not in_string and ch == "/" and i + 1 < len(text) and text[i + 1] == "/":
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        if not in_string and ch == "/" and i + 1 < len(text) and text[i + 1] == "*":
            i += 2
            while i + 1 < len(text) and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        result.append(ch)
        i += 1
    return "".join(result)


def _is_devcontainer_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in DEVCONTAINER_NAMES:
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(DEVCONTAINER_DIRS) and lower.endswith(".json"):
        return True
    if lower == ".devcontainer.json":
        return True
    return False


class DevContainerAnalyzer:
    """Audit dev container configs for hardcoded secrets, privileged mode, and unsafe mounts.

    Scans `.devcontainer/devcontainer.json` for root user, docker.sock mounts, :latest tags,
    curl-pipe-to-shell in lifecycle commands, and plaintext credentials in containerEnv.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[DevContainerFinding] | None = None
        self._stats: DevContainerStats | None = None
        self._infos: list[DevContainerInfo] | None = None

    def files(self) -> list[Path]:
        """Return dev container config files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_devcontainer_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[DevContainerFinding], DevContainerInfo]:
        findings: list[DevContainerFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = raw_text.splitlines()
        except OSError:
            return findings, DevContainerInfo(path=rel)

        info = DevContainerInfo(path=rel, lines=len(raw_lines))
        in_container_env = False
        in_remote_env = False
        in_run_args = False
        in_mounts = False
        in_lifecycle_command = False
        lifecycle_key = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line:
                continue

            if re.match(r"^\s*\"image\"\s*:", line, re.IGNORECASE):
                image_match = re.search(r"\"image\"\s*:\s*\"([^\"]+)\"", line, re.IGNORECASE)
                if image_match:
                    info.image = image_match.group(1)

            if re.match(r"^\s*\"remoteUser\"\s*:", line, re.IGNORECASE):
                user_match = re.search(r"\"remoteUser\"\s*:\s*\"([^\"]+)\"", line, re.IGNORECASE)
                if user_match:
                    info.remote_user = user_match.group(1)

            if re.match(r"^\s*\"containerEnv\"\s*:", line, re.IGNORECASE):
                in_container_env = True
                in_remote_env = False
                in_run_args = False
                in_mounts = False
                in_lifecycle_command = False
                continue

            if re.match(r"^\s*\"remoteEnv\"\s*:", line, re.IGNORECASE):
                in_remote_env = True
                in_container_env = False
                in_run_args = False
                in_mounts = False
                in_lifecycle_command = False
                continue

            if re.match(r"^\s*\"runArgs\"\s*:", line, re.IGNORECASE):
                in_run_args = True
                in_container_env = False
                in_remote_env = False
                in_mounts = False
                in_lifecycle_command = False
                continue

            if re.match(r"^\s*\"mounts\"\s*:", line, re.IGNORECASE):
                in_mounts = True
                in_container_env = False
                in_remote_env = False
                in_run_args = False
                in_lifecycle_command = False
                continue

            lifecycle_match = re.match(
                r"^\s*\"(" + "|".join(LIFECYCLE_COMMAND_KEYS) + r")\"\s*:",
                line,
                re.IGNORECASE,
            )
            if lifecycle_match:
                in_lifecycle_command = True
                lifecycle_key = lifecycle_match.group(1)
                in_container_env = False
                in_remote_env = False
                in_run_args = False
                in_mounts = False
                if CURL_PIPE_SHELL_PATTERN.search(line):
                    findings.append(
                        DevContainerFinding(
                            kind="curl_pipe_shell",
                            severity="high",
                            message="curl/wget piped to shell — verify script source and pin checksums",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                if re.search(r"\$\{[^}]+\}", line):
                    findings.append(
                        DevContainerFinding(
                            kind="lifecycle_injection",
                            severity="medium",
                            message=f"{lifecycle_key} interpolates variables — validate untrusted inputs",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                continue

            if re.match(r"^\s*\}\s*,?\s*$", line) or re.match(r"^\s*\]\s*,?\s*$", line):
                in_container_env = False
                in_remote_env = False
                in_run_args = False
                in_mounts = False
                in_lifecycle_command = False

            feature_match = re.search(r"\"([^\"]+/(?:features/)?[^\"]+)\"\s*:", line)
            if feature_match and "features" in raw_lines[max(0, lineno - 5) : lineno]:
                info.features.append(feature_match.group(1))

            port_match = re.search(r"\"forwardPorts\"\s*:\s*\[([^\]]*)\]", line, re.IGNORECASE)
            if port_match:
                for port_str in re.findall(r"\d+", port_match.group(1)):
                    info.forward_ports.append(int(port_str))

            if (in_container_env or in_remote_env) and HARDCODED_ENV_VALUE_PATTERN.match(line):
                if not re.search(r"(?:true|false|null|\$\{)", line, re.IGNORECASE):
                    findings.append(
                        DevContainerFinding(
                            kind="hardcoded_secret",
                            severity="high",
                            message="hardcoded value in container environment — use devcontainer secrets or host env references",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    DevContainerFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential — use devcontainer secrets or ${localEnv:VAR} references",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    DevContainerFinding(
                        kind="plaintext_aws_key",
                        severity="high",
                        message="plaintext AWS access key — use secrets or environment references",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    DevContainerFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — verify script source and pin checksums",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    DevContainerFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific digest or version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if (in_run_args or in_mounts) and DOCKER_SOCKET_MOUNT_PATTERN.search(line):
                findings.append(
                    DevContainerFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="Docker socket mount grants host-level container access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if (in_run_args or line) and PRIVILEGED_PATTERN.search(line):
                findings.append(
                    DevContainerFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged container mode grants full host access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ROOT_USER_PATTERN.search(line):
                findings.append(
                    DevContainerFinding(
                        kind="root_user",
                        severity="medium",
                        message="container runs as root — set remoteUser/containerUser to a non-root user",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if (in_run_args or in_mounts) and HOST_MOUNT_PATTERN.search(line):
                findings.append(
                    DevContainerFinding(
                        kind="host_mount",
                        severity="high",
                        message="sensitive host path mounted into container — restrict mount scope",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if (in_run_args or line) and HOST_NETWORK_PATTERN.search(line):
                findings.append(
                    DevContainerFinding(
                        kind="host_network",
                        severity="high",
                        message="host network mode bypasses container network isolation",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if (in_run_args or line) and DANGEROUS_CAP_PATTERN.search(line):
                findings.append(
                    DevContainerFinding(
                        kind="dangerous_capability",
                        severity="high",
                        message="dangerous Linux capability granted — drop unnecessary caps",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if (in_run_args or line) and UNCONFINED_SECURITY_OPT_PATTERN.search(line):
                findings.append(
                    DevContainerFinding(
                        kind="unconfined_security",
                        severity="medium",
                        message="unconfined seccomp/apparmor weakens container isolation",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    DevContainerFinding(
                        kind="insecure_http",
                        severity="low",
                        message="insecure HTTP URL in devcontainer config — prefer HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if FORWARD_ALL_PORTS_PATTERN.search(line):
                findings.append(
                    DevContainerFinding(
                        kind="forward_all_ports",
                        severity="medium",
                        message="forwardPorts includes 0 (all ports) — expose only required ports",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_lifecycle_command and re.search(r"\$\{[^}]+\}", line):
                findings.append(
                    DevContainerFinding(
                        kind="lifecycle_injection",
                        severity="medium",
                        message=f"{lifecycle_key} interpolates variables — validate untrusted inputs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        content = "\n".join(raw_lines)
        if FEATURE_CURL_INSTALL_PATTERN.search(content):
            findings.append(
                DevContainerFinding(
                    kind="feature_curl_install",
                    severity="medium",
                    message="feature definition pipes remote script to shell — verify feature source",
                    path=rel,
                    lineno=1,
                    line="features",
                )
            )

        try:
            parsed = json.loads(_strip_json_comments(raw_text))
            if isinstance(parsed, dict):
                if parsed.get("runArgs") and any(
                    isinstance(arg, str) and arg.startswith("--privileged")
                    for arg in parsed.get("runArgs", [])
                ):
                    pass  # already caught by line scan
                if not parsed.get("remoteUser") and not parsed.get("containerUser"):
                    if parsed.get("image") and "mcr.microsoft.com/devcontainers" not in str(
                        parsed.get("image", "")
                    ):
                        findings.append(
                            DevContainerFinding(
                                kind="missing_non_root_user",
                                severity="low",
                                message="no remoteUser/containerUser set — configure a non-root development user",
                                path=rel,
                                lineno=1,
                                line="remoteUser",
                            )
                        )
        except json.JSONDecodeError:
            findings.append(
                DevContainerFinding(
                    kind="invalid_json",
                    severity="medium",
                    message="devcontainer.json is not valid JSON/JSONC — fix syntax errors",
                    path=rel,
                    lineno=1,
                    line="",
                )
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

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = DevContainerStats(
            configs=len(paths),
            files=len(paths),
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
        if stats.configs == 0:
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
        """Scaffold a hardened dev container config template."""
        return """\
// Generated by DevAI DevContainerAnalyzer
{
  "name": "DevAI Hardened Dev Container",
  "image": "mcr.microsoft.com/devcontainers/python:1-3.12-bookworm",
  "remoteUser": "vscode",
  "containerEnv": {
    "PYTHONUNBUFFERED": "1"
  },
  "remoteEnv": {
    "API_ENDPOINT": "${localEnv:API_ENDPOINT}"
  },
  "forwardPorts": [8000],
  "portsAttributes": {
    "8000": {
      "label": "Application",
      "onAutoForward": "notify"
    }
  },
  "postCreateCommand": "pip install -r requirements.txt",
  "customizations": {
    "vscode": {
      "extensions": [
        "ms-python.python",
        "ms-python.vscode-pylance"
      ]
    }
  },
  "features": {},
  "mounts": [],
  "runArgs": [
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges"
  ]
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Dev containers: none found"
        return (
            f"Dev containers: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Dev container config analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            image = info.image or "unspecified"
            user = info.remote_user or "default"
            lines.append(f"  - {info.path}: image={image}, remoteUser={user}")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
