"""TaskfileAnalyzer — audit Go Task YAML files for security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

TASKFILE_NAMES = (
    "Taskfile.yml",
    "Taskfile.yaml",
    "taskfile.yml",
    "taskfile.yaml",
)
TASKFILE_DIR = ".task"

CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
RM_RF_ROOT_PATTERN = re.compile(r"rm\s+-rf\s+(/|\$\(HOME\)|~|\*)", re.IGNORECASE)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
CHMOD_777_PATTERN = re.compile(r"chmod\s+777\b", re.IGNORECASE)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[:=]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
ENV_SECRET_PATTERN = re.compile(
    r"^[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL|AUTH)[A-Z0-9_]*\s*:\s*"
    r"[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
SCM_CREDENTIALS_PATTERN = re.compile(
    r"(?:git@|git\+https?://|https?://)[^:@\s]+:[^@\s]+@|"
    r"https?://[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:eval\s*\(|\bsh\s+-c\b)",
    re.IGNORECASE,
)
FORCE_PUSH_PATTERN = re.compile(r"git\s+push\s+.*--force", re.IGNORECASE)
DOTENV_LOAD_PATTERN = re.compile(r"dotenv\s*:\s*\[", re.IGNORECASE)
SENSITIVE_DOTENV_PATTERN = re.compile(
    r"dotenv\s*:\s*\[.*\.env[\"']?\s*\]",
    re.IGNORECASE,
)
TASK_NAME_PATTERN = re.compile(r"^\s{2,}([a-zA-Z0-9_-]+):\s*$")


@dataclass
class TaskfileFinding:
    """A security or best-practice issue in a Go Task YAML file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class TaskfileInfo:
    """Parsed metadata about a Taskfile."""

    path: str
    tasks: list[str] = field(default_factory=list)
    has_dotenv: bool = False
    lines: int = 0


@dataclass
class TaskfileStats:
    """Aggregate Taskfile analysis statistics."""

    taskfiles: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_taskfile(path: Path) -> bool:
    name = path.name
    if name in TASKFILE_NAMES:
        return True
    if TASKFILE_DIR in path.parts and name.endswith((".yml", ".yaml")):
        return True
    return False


def _strip_comment(line: str) -> str:
    stripped = line.strip()
    if stripped.startswith("#"):
        return ""
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


class TaskfileAnalyzer:
    """Audit Go Task YAML files for security risks and best practices.

    Scans Taskfile.yml/yaml and .task/*.yml for curl-pipe-to-shell, hardcoded
    secrets in env blocks, sudo usage, destructive rm -rf, chmod 777, insecure
    HTTP URLs, SCM credentials in URLs, dotenv loading of .env files, and
    dangerous shell patterns.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TaskfileFinding] | None = None
        self._stats: TaskfileStats | None = None
        self._infos: list[TaskfileInfo] | None = None

    def taskfiles(self) -> list[Path]:
        """Return Taskfile paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_taskfile(path):
                found.append(path)
        return found

    def _add_finding(
        self,
        findings: list[TaskfileFinding],
        kind: str,
        severity: str,
        message: str,
        rel: str,
        lineno: int,
        raw: str,
    ) -> None:
        findings.append(
            TaskfileFinding(
                kind=kind,
                severity=severity,
                message=message,
                path=rel,
                lineno=lineno,
                line=raw.strip(),
            )
        )

    def _analyze_file(self, path: Path) -> tuple[list[TaskfileFinding], TaskfileInfo]:
        findings: list[TaskfileFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, TaskfileInfo(path=rel)

        info = TaskfileInfo(path=rel, lines=len(raw_lines))
        in_env_block = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = _strip_comment(raw)
            if not line:
                continue

            if re.match(r"^\s*env\s*:", line, re.IGNORECASE):
                in_env_block = True
            elif re.match(r"^\s{2,}[a-zA-Z0-9_-]+\s*:", line) and not line.strip().startswith("-"):
                in_env_block = False

            task_match = TASK_NAME_PATTERN.match(raw)
            if task_match and not raw.strip().startswith("#"):
                info.tasks.append(task_match.group(1))

            if DOTENV_LOAD_PATTERN.search(line):
                info.has_dotenv = True
                if ".env" in line and ".env.example" not in line:
                    self._add_finding(
                        findings,
                        "dotenv_load",
                        "medium",
                        "dotenv loads .env files — ensure secrets are gitignored and not committed",
                        rel,
                        lineno,
                        raw,
                    )

            if HARDCODED_SECRET_PATTERN.search(line) or (
                in_env_block and ENV_SECRET_PATTERN.search(line)
            ):
                self._add_finding(
                    findings,
                    "hardcoded_secret",
                    "high",
                    "hardcoded secret in Taskfile — use env vars or secret stores",
                    rel,
                    lineno,
                    raw,
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                self._add_finding(
                    findings,
                    "aws_access_key",
                    "high",
                    "AWS access key in Taskfile — use credential helpers or secret stores",
                    rel,
                    lineno,
                    raw,
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                self._add_finding(
                    findings,
                    "curl_pipe_shell",
                    "high",
                    "piping curl/wget to shell is unsafe — vendor scripts with checksum verification",
                    rel,
                    lineno,
                    raw,
                )

            if RM_RF_ROOT_PATTERN.search(line):
                self._add_finding(
                    findings,
                    "destructive_rm",
                    "high",
                    "rm -rf on root or home directory is dangerous",
                    rel,
                    lineno,
                    raw,
                )

            if SUDO_PATTERN.search(line):
                self._add_finding(
                    findings,
                    "sudo_usage",
                    "medium",
                    "sudo in task commands can escalate privileges unexpectedly",
                    rel,
                    lineno,
                    raw,
                )

            if CHMOD_777_PATTERN.search(line):
                self._add_finding(
                    findings,
                    "chmod_777",
                    "high",
                    "chmod 777 grants world-writable permissions",
                    rel,
                    lineno,
                    raw,
                )

            if INSECURE_HTTP_PATTERN.search(line):
                self._add_finding(
                    findings,
                    "insecure_http",
                    "medium",
                    "insecure HTTP URL — use HTTPS for downloads and remote sources",
                    rel,
                    lineno,
                    raw,
                )

            if SCM_CREDENTIALS_PATTERN.search(line):
                self._add_finding(
                    findings,
                    "scm_credentials",
                    "high",
                    "credentials embedded in SCM URL — use SSH keys or credential helpers",
                    rel,
                    lineno,
                    raw,
                )

            if DANGEROUS_SHELL_PATTERN.search(line):
                self._add_finding(
                    findings,
                    "dangerous_shell",
                    "medium",
                    "dangerous shell pattern (eval or sh -c) — prefer explicit commands",
                    rel,
                    lineno,
                    raw,
                )

            if FORCE_PUSH_PATTERN.search(line):
                self._add_finding(
                    findings,
                    "git_force_push",
                    "medium",
                    "git push --force can overwrite remote history",
                    rel,
                    lineno,
                    raw,
                )

        return findings, info

    def analyze(self) -> list[TaskfileFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TaskfileFinding] = []
        infos: list[TaskfileInfo] = []
        paths = self.taskfiles()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = TaskfileStats(
            taskfiles=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> TaskfileStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[TaskfileInfo]:
        """Return parsed Taskfile metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no taskfiles)."""
        self.analyze()
        stats = self.stats
        if stats.taskfiles == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_config(self) -> str:
        """Scaffold a hardened Taskfile.yml snippet with secure defaults."""
        return """\
# Taskfile.yml — hardened defaults for Go Task projects
version: '3'

dotenv: ['.env.example']  # Never load committed .env with secrets

env:
  NODE_ENV: development
  # API_KEY: {{.API_KEY}}  # Inject via CI or local env

tasks:
  setup:
    desc: Install dependencies
    cmds:
      - npm ci
    # Avoid: curl https://example.com/install.sh | sh

  test:
    desc: Run tests
    cmds:
      - npm test
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.taskfiles == 0:
            return "Taskfiles: none found"
        return (
            f"Taskfiles: {stats.taskfiles} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Taskfile analysis:",
            f"  taskfiles: {stats.taskfiles}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            tasks = ", ".join(info.tasks[:8]) if info.tasks else "none"
            lines.append(
                f"  - {info.path}: {len(info.tasks)} task(s), dotenv={info.has_dotenv}"
            )
            lines.append(f"    tasks: {tasks}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
