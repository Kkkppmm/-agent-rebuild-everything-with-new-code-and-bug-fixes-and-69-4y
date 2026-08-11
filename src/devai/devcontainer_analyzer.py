"""DevContainerAnalyzer — audit dev container configs for security and best practices."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEVCONTAINER_FILENAMES = ("devcontainer.json", ".devcontainer.json")
DEVCONTAINER_DIRS = (".devcontainer")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)",
    re.IGNORECASE,
)
SECRET_VALUE_PATTERN = re.compile(
    r"^(?:sk-[a-zA-Z0-9_-]{10,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|"
    r"xox[baprs]-[a-zA-Z0-9-]{10,})$"
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget|Invoke-WebRequest)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(r":latest\b", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(r"--privileged\b", re.IGNORECASE)
SENSITIVE_MOUNT_PATTERN = re.compile(
    r"(?:/var/run/docker\.sock|/etc/shadow|/etc/passwd|/root\b|/proc\b|/sys\b)",
    re.IGNORECASE,
)
DOCKER_SOCK_MOUNT_PATTERN = re.compile(r"docker\.sock", re.IGNORECASE)

COMMAND_KEYS = (
    "postCreateCommand",
    "postStartCommand",
    "postAttachCommand",
    "onCreateCommand",
    "updateContentCommand",
    "initializeCommand",
    "waitFor",
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
    workspace_folder: str = ""
    features: list[str] = field(default_factory=list)
    forward_ports: list[int] = field(default_factory=list)
    has_compose: bool = False
    privileged: bool = False


@dataclass
class DevContainerStats:
    """Aggregate dev container analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_devcontainer_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in DEVCONTAINER_FILENAMES:
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(DEVCONTAINER_DIRS) and lower.endswith(".json"):
        return True
    return False


def _collect_strings(value: Any, key_path: str = "") -> list[tuple[str, str]]:
    """Flatten JSON values into (key_path, string_value) pairs."""
    results: list[tuple[str, str]] = []
    if isinstance(value, str):
        results.append((key_path, value))
    elif isinstance(value, dict):
        for k, v in value.items():
            child_path = f"{key_path}.{k}" if key_path else k
            results.extend(_collect_strings(v, child_path))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            child_path = f"{key_path}[{i}]"
            results.extend(_collect_strings(item, child_path))
    return results


class DevContainerAnalyzer:
    """Audit dev container configs for hardcoded secrets, privileged mode, and unsafe mounts.

    Scans devcontainer.json for plaintext secrets in containerEnv, --privileged runArgs,
    Docker socket mounts, curl-pipe-to-shell in lifecycle commands, unpinned images,
    and missing remoteUser.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[DevContainerFinding] | None = None
        self._stats: DevContainerStats | None = None
        self._infos: list[DevContainerInfo] | None = None

    def files(self) -> list[Path]:
        """Return dev container config paths found in the project."""
        paths: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_devcontainer_file(path):
                paths.append(path)
        return paths

    def _analyze_file(self, path: Path) -> tuple[list[DevContainerFinding], DevContainerInfo]:
        findings: list[DevContainerFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            findings.append(
                DevContainerFinding(
                    kind="invalid_json",
                    severity="medium",
                    message=f"Invalid dev container JSON: {exc}",
                    path=rel,
                )
            )
            return findings, DevContainerInfo(path=rel)

        if not isinstance(data, dict):
            findings.append(
                DevContainerFinding(
                    kind="invalid_schema",
                    severity="medium",
                    message="devcontainer.json root must be an object",
                    path=rel,
                )
            )
            return findings, DevContainerInfo(path=rel)

        info = DevContainerInfo(
            path=rel,
            image=str(data.get("image", "")),
            remote_user=str(data.get("remoteUser", "")),
            workspace_folder=str(data.get("workspaceFolder", "")),
            has_compose=bool(data.get("dockerComposeFile")),
        )

        if isinstance(data.get("features"), dict):
            info.features = list(data["features"].keys())

        forward_ports = data.get("forwardPorts", [])
        if isinstance(forward_ports, list):
            info.forward_ports = [int(p) for p in forward_ports if isinstance(p, int)]

        privileged_flag = data.get("privileged")
        if privileged_flag is True:
            info.privileged = True
            findings.append(
                DevContainerFinding(
                    kind="privileged",
                    severity="high",
                    message="privileged: true grants full host capabilities — avoid in dev containers",
                    path=rel,
                    line="privileged: true",
                )
            )

        run_args = data.get("runArgs", [])
        if isinstance(run_args, list):
            for arg in run_args:
                if isinstance(arg, str) and PRIVILEGED_PATTERN.search(arg):
                    info.privileged = True
                    findings.append(
                        DevContainerFinding(
                            kind="privileged",
                            severity="high",
                            message="--privileged in runArgs grants full host capabilities",
                            path=rel,
                            line=arg,
                        )
                    )

        mounts = data.get("mounts", [])
        if isinstance(mounts, list):
            for mount in mounts:
                mount_str = mount if isinstance(mount, str) else json.dumps(mount)
                if DOCKER_SOCK_MOUNT_PATTERN.search(mount_str):
                    findings.append(
                        DevContainerFinding(
                            kind="docker_socket_mount",
                            severity="high",
                            message="Docker socket mount allows container escape to host",
                            path=rel,
                            line=mount_str[:120],
                        )
                    )
                elif SENSITIVE_MOUNT_PATTERN.search(mount_str):
                    findings.append(
                        DevContainerFinding(
                            kind="sensitive_mount",
                            severity="high",
                            message="Sensitive host path mounted into dev container",
                            path=rel,
                            line=mount_str[:120],
                        )
                    )

        env_keys = ("containerEnv", "remoteEnv", "containerEnvFile")
        for env_key in env_keys:
            env_data = data.get(env_key)
            if env_key == "containerEnvFile" and isinstance(env_data, str):
                continue
            if isinstance(env_data, dict):
                for var_name, var_value in env_data.items():
                    if not isinstance(var_value, str):
                        continue
                    if HARDCODED_SECRET_PATTERN.search(var_name) and var_value.strip():
                        if var_value.strip() not in ("", "${localEnv:VAR}", "${localEnv:VAR_NAME}"):
                            findings.append(
                                DevContainerFinding(
                                    kind="hardcoded_secret",
                                    severity="high",
                                    message=f"Hardcoded secret in {env_key}.{var_name} — use localEnv or secrets",
                                    path=rel,
                                    line=f"{var_name}: {var_value[:40]}",
                                )
                            )
                    elif SECRET_VALUE_PATTERN.match(var_value.strip()):
                        findings.append(
                            DevContainerFinding(
                                kind="hardcoded_secret",
                                severity="high",
                                message=f"Likely API key/token in {env_key}.{var_name}",
                                path=rel,
                                line=f"{var_name}: {var_value[:40]}",
                            )
                        )

        for cmd_key in COMMAND_KEYS:
            cmd_value = data.get(cmd_key)
            if isinstance(cmd_value, str):
                if CURL_PIPE_SHELL_PATTERN.search(cmd_value):
                    findings.append(
                        DevContainerFinding(
                            kind="curl_pipe_shell",
                            severity="high",
                            message=f"curl/wget pipe-to-shell in {cmd_key}",
                            path=rel,
                            line=cmd_value[:120],
                        )
                    )
                if INSECURE_HTTP_PATTERN.search(cmd_value):
                    findings.append(
                        DevContainerFinding(
                            kind="insecure_http",
                            severity="medium",
                            message=f"Insecure HTTP URL in {cmd_key}",
                            path=rel,
                            line=cmd_value[:120],
                        )
                    )
            elif isinstance(cmd_value, list):
                for item in cmd_value:
                    if isinstance(item, str):
                        if CURL_PIPE_SHELL_PATTERN.search(item):
                            findings.append(
                                DevContainerFinding(
                                    kind="curl_pipe_shell",
                                    severity="high",
                                    message=f"curl/wget pipe-to-shell in {cmd_key}",
                                    path=rel,
                                    line=item[:120],
                                )
                            )

        image = info.image
        if image and LATEST_TAG_PATTERN.search(image):
            findings.append(
                DevContainerFinding(
                    kind="unpinned_image",
                    severity="medium",
                    message=f"Unpinned image tag ':latest' in image — pin to a specific version",
                    path=rel,
                    line=image,
                )
            )

        if not info.remote_user and not info.has_compose and image:
            findings.append(
                DevContainerFinding(
                    kind="no_remote_user",
                    severity="medium",
                    message="Missing remoteUser — container may run as root",
                    path=rel,
                )
            )

        if info.forward_ports and 22 in info.forward_ports:
            findings.append(
                DevContainerFinding(
                    kind="ssh_port_forward",
                    severity="low",
                    message="Port 22 forwarded — SSH in dev container may be unnecessary",
                    path=rel,
                )
            )

        for key_path, text in _collect_strings(data):
            if CURL_PIPE_SHELL_PATTERN.search(text) and not any(
                f.kind == "curl_pipe_shell" and f.line == text[:120] for f in findings
            ):
                if any(cmd in key_path for cmd in COMMAND_KEYS):
                    continue
                findings.append(
                    DevContainerFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message=f"curl/wget pipe-to-shell in {key_path}",
                        path=rel,
                        line=text[:120],
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
        """Return parsed config metadata."""
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
        """Scaffold a hardened dev container template."""
        return """\
{
  // Generated by DevAI DevContainerAnalyzer
  "name": "Python Dev Container",
  "image": "mcr.microsoft.com/devcontainers/python:1-3.12",
  "remoteUser": "vscode",
  "workspaceFolder": "/workspaces/${localWorkspaceFolderBasename}",
  "features": {
    "ghcr.io/devcontainers/features/git:1": {}
  },
  "postCreateCommand": "pip install -e .[dev]",
  "customizations": {
    "vscode": {
      "extensions": [
        "ms-python.python",
        "charliermarsh.ruff"
      ]
    }
  },
  "forwardPorts": [8000],
  "portsAttributes": {
    "8000": {
      "label": "Application",
      "onAutoForward": "notify"
    }
  }
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
            "Dev container analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: image={info.image or 'compose'}, "
                f"remoteUser={info.remote_user or 'unset'}, "
                f"privileged={info.privileged}, ports={info.forward_ports}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
