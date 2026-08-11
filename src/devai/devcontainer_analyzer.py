"""DevContainerAnalyzer — audit dev container configs for security and best practices."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = ("devcontainer.json", ".devcontainer.json")
CONFIG_DIR = ".devcontainer"

LATEST_TAG_PATTERN = re.compile(r":latest\b", re.IGNORECASE)
SECRET_VALUE_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]\s*['\"][^'\"]{4,}",
    re.IGNORECASE,
)
SECRET_KEY_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
DOCKER_SOCK_PATTERN = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)
HOST_MOUNT_PATTERN = re.compile(
    r"source=(?:/|/etc|/proc|/sys|/var/run)[,/]",
    re.IGNORECASE,
)
COMMAND_FIELDS = (
    "initializeCommand",
    "onCreateCommand",
    "updateContentCommand",
    "postCreateCommand",
    "postStartCommand",
    "postAttachCommand",
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
    has_features: bool = False
    run_args: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class DevContainerStats:
    """Aggregate dev container analysis statistics."""

    config_files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_devcontainer_config(path: Path) -> bool:
    name = path.name.lower()
    if name in CONFIG_NAMES:
        return True
    if path.parent.name == CONFIG_DIR and name.endswith(".json"):
        return name.startswith("devcontainer")
    return False


def _line_for_substring(lines: list[str], needle: str) -> int:
    lower = needle.lower()
    for idx, line in enumerate(lines, start=1):
        if lower in line.lower():
            return idx
    return 1


class DevContainerAnalyzer:
    """Audit dev container configs for security risks and best practices.

    Scans ``devcontainer.json`` files for privileged mode, docker.sock mounts,
    hardcoded secrets, curl-pipe-to-shell lifecycle commands, and root execution.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[DevContainerFinding] | None = None
        self._stats: DevContainerStats | None = None
        self._infos: list[DevContainerInfo] | None = None

    def configs(self) -> list[Path]:
        """Return dev container config paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            if _is_devcontainer_config(path):
                found.append(path)
        return found

    def _add(
        self,
        findings: list[DevContainerFinding],
        *,
        kind: str,
        severity: str,
        message: str,
        rel: str,
        lineno: int,
        line: str = "",
    ) -> None:
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

    def _check_run_args(
        self,
        findings: list[DevContainerFinding],
        run_args: list[str],
        rel: str,
        raw_lines: list[str],
    ) -> None:
        for arg in run_args:
            lower = arg.lower()
            lineno = _line_for_substring(raw_lines, arg)
            if "--privileged" in lower:
                self._add(
                    findings,
                    kind="privileged_mode",
                    severity="high",
                    message="runArgs includes --privileged — avoid privileged dev containers",
                    rel=rel,
                    lineno=lineno,
                    line=arg,
                )
            if "--network=host" in lower or lower == "--net=host":
                self._add(
                    findings,
                    kind="host_network",
                    severity="high",
                    message="runArgs uses host networking — isolates poorly from the host",
                    rel=rel,
                    lineno=lineno,
                    line=arg,
                )
            if "--cap-add=all" in lower.replace(" ", "") or "cap-add=sys_admin" in lower:
                self._add(
                    findings,
                    kind="dangerous_capability",
                    severity="high",
                    message="runArgs adds dangerous Linux capabilities",
                    rel=rel,
                    lineno=lineno,
                    line=arg,
                )
            if "seccomp=unconfined" in lower or "apparmor=unconfined" in lower:
                self._add(
                    findings,
                    kind="security_opt_unconfined",
                    severity="high",
                    message="runArgs disables container security profiles",
                    rel=rel,
                    lineno=lineno,
                    line=arg,
                )

    def _check_mounts(
        self,
        findings: list[DevContainerFinding],
        mounts: list[str],
        rel: str,
        raw_lines: list[str],
    ) -> None:
        for mount in mounts:
            lineno = _line_for_substring(raw_lines, mount)
            if DOCKER_SOCK_PATTERN.search(mount):
                self._add(
                    findings,
                    kind="docker_socket_mount",
                    severity="high",
                    message="Mounts docker.sock — grants host Docker access from the dev container",
                    rel=rel,
                    lineno=lineno,
                    line=mount,
                )
            if HOST_MOUNT_PATTERN.search(mount):
                self._add(
                    findings,
                    kind="host_path_mount",
                    severity="medium",
                    message="Mounts sensitive host paths into the dev container",
                    rel=rel,
                    lineno=lineno,
                    line=mount,
                )

    def _check_env_block(
        self,
        findings: list[DevContainerFinding],
        env: dict[str, str],
        rel: str,
        raw_lines: list[str],
        block_name: str,
    ) -> None:
        for key, value in env.items():
            if not isinstance(value, str):
                continue
            if SECRET_KEY_PATTERN.search(key) and value.strip() and value.lower() not in {
                "",
                "changeme",
                "placeholder",
                "your-api-key",
            }:
                lineno = _line_for_substring(raw_lines, key)
                self._add(
                    findings,
                    kind="secret_in_env",
                    severity="high",
                    message=f"{block_name} contains a hardcoded secret for '{key}'",
                    rel=rel,
                    lineno=lineno,
                    line=f"{key}: {value[:40]}",
                )

    def _check_command_value(
        self,
        findings: list[DevContainerFinding],
        field_name: str,
        value: object,
        rel: str,
        raw_lines: list[str],
    ) -> None:
        commands: list[str] = []
        if isinstance(value, str):
            commands.append(value)
        elif isinstance(value, list):
            commands.extend(str(item) for item in value)
        elif isinstance(value, dict):
            commands.extend(str(item) for item in value.values())

        for command in commands:
            if CURL_PIPE_SHELL_PATTERN.search(command):
                lineno = _line_for_substring(raw_lines, field_name)
                self._add(
                    findings,
                    kind="curl_pipe_shell",
                    severity="high",
                    message=f"{field_name} runs curl/wget piped to a shell",
                    rel=rel,
                    lineno=lineno,
                    line=command[:120],
                )

    def _analyze_file(self, path: Path) -> tuple[list[DevContainerFinding], DevContainerInfo]:
        findings: list[DevContainerFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, DevContainerInfo(path=rel)

        raw_lines = text.splitlines()
        info = DevContainerInfo(path=rel, lines=len(raw_lines))

        for lineno, line in enumerate(raw_lines, start=1):
            if SECRET_VALUE_PATTERN.search(line):
                self._add(
                    findings,
                    kind="secret_in_config",
                    severity="high",
                    message="Hardcoded secret detected in dev container config",
                    rel=rel,
                    lineno=lineno,
                    line=line.strip()[:120],
                )
            if DOCKER_SOCK_PATTERN.search(line) and "mounts" not in line.lower():
                self._add(
                    findings,
                    kind="docker_socket_reference",
                    severity="medium",
                    message="References docker.sock — verify mount is intentional and scoped",
                    rel=rel,
                    lineno=lineno,
                    line=line.strip()[:120],
                )

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            self._add(
                findings,
                kind="invalid_json",
                severity="medium",
                message="devcontainer.json is not valid JSON",
                rel=rel,
                lineno=1,
            )
            return findings, info

        if not isinstance(data, dict):
            return findings, info

        image = data.get("image")
        if isinstance(image, str):
            info.image = image
            if LATEST_TAG_PATTERN.search(image):
                self._add(
                    findings,
                    kind="latest_tag",
                    severity="medium",
                    message="Image uses :latest — pin to a specific tag or digest",
                    rel=rel,
                    lineno=_line_for_substring(raw_lines, "image"),
                    line=image,
                )

        remote_user = data.get("remoteUser") or data.get("containerUser")
        if isinstance(remote_user, str):
            info.remote_user = remote_user
            if remote_user.lower() == "root":
                self._add(
                    findings,
                    kind="runs_as_root",
                    severity="medium",
                    message="remoteUser is root — prefer a non-root dev user",
                    rel=rel,
                    lineno=_line_for_substring(raw_lines, "remoteUser"),
                    line=remote_user,
                )
        else:
            self._add(
                findings,
                kind="runs_as_root",
                severity="medium",
                message="remoteUser/containerUser not set — container may run as root",
                rel=rel,
                lineno=1,
            )

        run_args = data.get("runArgs")
        if isinstance(run_args, list):
            info.run_args = [str(arg) for arg in run_args]
            self._check_run_args(findings, info.run_args, rel, raw_lines)

        mounts = data.get("mounts")
        if isinstance(mounts, list):
            self._check_mounts(findings, [str(m) for m in mounts], rel, raw_lines)

        for env_name in ("remoteEnv", "containerEnv"):
            env = data.get(env_name)
            if isinstance(env, dict):
                self._check_env_block(
                    findings,
                    {str(k): str(v) for k, v in env.items()},
                    rel,
                    raw_lines,
                    env_name,
                )

        features = data.get("features")
        if isinstance(features, dict) and features:
            info.has_features = True
            for feature_id in features:
                if isinstance(feature_id, str) and LATEST_TAG_PATTERN.search(feature_id):
                    self._add(
                        findings,
                        kind="unpinned_feature",
                        severity="medium",
                        message=f"Feature '{feature_id}' uses :latest — pin feature versions",
                        rel=rel,
                        lineno=_line_for_substring(raw_lines, feature_id),
                        line=feature_id,
                    )

        for field_name in COMMAND_FIELDS:
            if field_name in data:
                self._check_command_value(findings, field_name, data[field_name], rel, raw_lines)

        if data.get("overrideCommand") is True:
            self._add(
                findings,
                kind="override_command",
                severity="low",
                message="overrideCommand is true — verify startup command is intentional",
                rel=rel,
                lineno=_line_for_substring(raw_lines, "overrideCommand"),
            )

        return findings, info

    def analyze(self) -> list[DevContainerFinding]:
        """Scan dev container configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[DevContainerFinding] = []
        infos: list[DevContainerInfo] = []
        paths = self.configs()

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
            config_files=len(paths),
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
        if stats.config_files == 0:
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
        """Scaffold a hardened devcontainer.json template."""
        return """\
{
  "name": "DevAI Hardened Dev Container",
  "image": "mcr.microsoft.com/devcontainers/python:1-3.12-bookworm",
  "remoteUser": "vscode",
  "containerEnv": {
    "PIP_DISABLE_PIP_VERSION_CHECK": "1"
  },
  "postCreateCommand": "pip install -e '.[dev]'",
  "customizations": {
    "vscode": {
      "extensions": [
        "ms-python.python",
        "charliermarsh.ruff"
      ]
    }
  },
  "features": {
    "ghcr.io/devcontainers/features/common-utils:2": {
      "installZsh": false,
      "upgradePackages": true,
      "username": "vscode"
    }
  }
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Dev containers: none found"
        return (
            f"Dev containers: {stats.config_files} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Dev container analysis:",
            f"  config_files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            user = info.remote_user or "unset"
            image = info.image or "build/dockerCompose"
            lines.append(f"  - {info.path}: image={image}, remoteUser={user}")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
