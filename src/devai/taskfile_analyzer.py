"""TaskfileAnalyzer — audit Task (taskfile.dev) configs for security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

TASKFILE_NAMES = ("Taskfile.yml", "Taskfile.yaml")
TASKFILE_PREFIX = "Taskfile."
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
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
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.env(?!\.example)|\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config|"
    r"credentials\.json|service[-_]?account\.json)",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|"
    r"\bsh\s+-c\b|\bsudo\b)",
    re.IGNORECASE,
)
TASK_NAME_PATTERN = re.compile(r"^\s{2}([a-zA-Z0-9:_-]+):\s*$")
CMD_LINE_PATTERN = re.compile(r"^\s*-\s+", re.IGNORECASE)


@dataclass
class TaskfileFinding:
    """A security or best-practice issue in a Taskfile."""

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
    """Parsed metadata from a Taskfile."""

    path: str
    lines: int = 0
    tasks: list[str] = field(default_factory=list)
    includes: list[str] = field(default_factory=list)


@dataclass
class TaskfileStats:
    """Aggregate statistics from Taskfile analysis."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_taskfile(path: Path) -> bool:
    name = path.name
    if name in TASKFILE_NAMES:
        return True
    if name.startswith(TASKFILE_PREFIX) and name.endswith((".yml", ".yaml")):
        return True
    return False


def _is_comment_line(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


class TaskfileAnalyzer:
    """Audit Taskfile configs for security issues.

    Scans Taskfile.yml/yaml for hardcoded secrets, insecure HTTP URLs,
    credentials in git URLs, sensitive file references, curl piped to shell,
    and dangerous shell commands in task definitions.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TaskfileFinding] | None = None
        self._stats: TaskfileStats | None = None
        self._infos: list[TaskfileInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Taskfile paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_taskfile(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[TaskfileFinding],
        info: TaskfileInfo,
        in_cmds: bool,
    ) -> bool:
        if _is_comment_line(line):
            return in_cmds

        stripped = line.strip()

        task_match = TASK_NAME_PATTERN.match(line)
        if task_match:
            info.tasks.append(task_match.group(1))
            return False

        if stripped.startswith("includes:") or stripped.startswith("- task:"):
            include_match = re.search(r"task:\s*([^\s#]+)", stripped)
            if include_match:
                info.includes.append(include_match.group(1))

        if stripped == "cmds:" or stripped.startswith("cmd:"):
            return True

        if CMD_LINE_PATTERN.match(stripped) or in_cmds:
            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    TaskfileFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Taskfile — use env vars or CI secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    TaskfileFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in Taskfile — use credential helpers or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    TaskfileFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL — use HTTPS for downloads and remote scripts",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SCM_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    TaskfileFinding(
                        kind="scm_credentials",
                        severity="high",
                        message="credentials embedded in URL — use SSH keys or token env vars",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SENSITIVE_PATH_PATTERN.search(line):
                findings.append(
                    TaskfileFinding(
                        kind="sensitive_path",
                        severity="medium",
                        message="sensitive file path in task — avoid exposing secrets in task commands",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    TaskfileFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — vendor scripts with checksum verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DANGEROUS_SHELL_PATTERN.search(line):
                findings.append(
                    TaskfileFinding(
                        kind="dangerous_shell",
                        severity="high",
                        message="dangerous shell command in task — review for privilege escalation",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if stripped and not stripped.startswith("-") and not stripped.endswith(":"):
                return False

        if stripped and not stripped.startswith("-") and stripped.endswith(":"):
            return False

        return in_cmds

    def _analyze_file(self, path: Path) -> tuple[list[TaskfileFinding], TaskfileInfo]:
        findings: list[TaskfileFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, TaskfileInfo(path=rel)

        raw_lines = text.splitlines()
        info = TaskfileInfo(path=rel, lines=len(raw_lines))
        in_cmds = False

        for lineno, line in enumerate(raw_lines, start=1):
            in_cmds = self._scan_line(line, lineno, rel, findings, info, in_cmds)

        return findings, info

    def analyze(self) -> list[TaskfileFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TaskfileFinding] = []
        infos: list[TaskfileInfo] = []
        paths = self.configs()

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
            configs=len(paths),
            files=len(paths),
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

    def generate_hardened_config(self) -> str:
        """Scaffold a hardened Taskfile snippet with secure defaults."""
        return """\
# Taskfile.yml — hardened defaults for go-task projects
version: '3'

vars:
  # Use env vars for secrets — never hardcode credentials
  # API_KEY: '{{.API_KEY}}'

tasks:
  setup:
    desc: Install dependencies
    cmds:
      - echo "Run project setup here"
    # Avoid curl | sh — vendor scripts with checksum verification

  test:
    desc: Run tests
    cmds:
      - pytest
    env:
      NODE_ENV: test
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Taskfile configs: none found"
        return (
            f"Taskfile configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Taskfile analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            tasks = ", ".join(info.tasks[:8]) if info.tasks else "none"
            lines.append(
                f"  - {info.path}: {len(info.tasks)} task(s), tasks={tasks}"
            )
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
