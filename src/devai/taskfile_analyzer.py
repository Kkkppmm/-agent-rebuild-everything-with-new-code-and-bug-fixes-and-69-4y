"""TaskfileAnalyzer — audit Task (taskfile.dev) configs for security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

TASKFILE_NAMES = (
    "Taskfile.yml",
    "Taskfile.yaml",
    "taskfile.yml",
    "taskfile.yaml",
    ".taskfile.yml",
    ".taskfile.yaml",
)
TASKFILE_SUFFIXES = (".task.yml", ".task.yaml")

CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
RM_RF_ROOT_PATTERN = re.compile(r"rm\s+-rf\s+(/|\$\(HOME\)|~|\*)", re.IGNORECASE)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
CHMOD_777_PATTERN = re.compile(r"chmod\s+777\b", re.IGNORECASE)
SECRET_VAR_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
FORCE_PUSH_PATTERN = re.compile(r"git\s+push\s+.*--force", re.IGNORECASE)
EVAL_PATTERN = re.compile(r"\beval\s+", re.IGNORECASE)
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
TLS_VERIFY_OFF_PATTERN = re.compile(
    r"(?:GIT_SSL_NO_VERIFY|NODE_TLS_REJECT_UNAUTHORIZED)\s*=\s*(?:1|true|yes)|"
    r"(?:curl|wget)\s+[^\n]*--insecure\b|"
    r"(?:curl|wget)\s+[^\n]*-k\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|"
    r"\bsh\s+-c\b|\bsudo\b)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.env(?!\.example|\.local)|\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config|"
    r"credentials\.json|service[-_]?account\.json)",
    re.IGNORECASE,
)
REMOTE_INCLUDE_PATTERN = re.compile(
    r"^\s*(?:taskfile|dir)\s*:\s*['\"]?(https?://|git@)",
    re.IGNORECASE,
)
DOTENV_PATTERN = re.compile(r"^\s*dotenv\s*:", re.IGNORECASE)
METHOD_NONE_PATTERN = re.compile(r"^\s*method\s*:\s*['\"]?none['\"]?\s*$", re.IGNORECASE)
TASK_ENTRY_PATTERN = re.compile(r"^\s{2}([a-zA-Z0-9#@:_-]+)\s*:\s*$")
ENV_BLOCK_PATTERN = re.compile(r"^\s*(?:env|vars)\s*:", re.IGNORECASE)
INCLUDE_BLOCK_PATTERN = re.compile(r"^\s*includes?\s*:", re.IGNORECASE)


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
    """Parsed metadata about a Taskfile."""

    path: str
    tasks: list[str] = field(default_factory=list)
    includes: list[str] = field(default_factory=list)
    dotenv_files: list[str] = field(default_factory=list)
    env_keys: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class TaskfileStats:
    """Aggregate Taskfile analysis statistics."""

    taskfiles: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_taskfile(path: Path) -> bool:
    name = path.name
    if name in TASKFILE_NAMES:
        return True
    lower = name.lower()
    return lower.endswith(".task.yml") or lower.endswith(".task.yaml")


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


class TaskfileAnalyzer:
    """Audit Task (taskfile.dev) configs for security risks and best practices.

    Scans Taskfile.yml, taskfile.yaml, and *.task.yml for curl-pipe-to-shell,
    destructive rm -rf, sudo usage, secrets in env/vars blocks, chmod 777,
    git force-push, eval usage, remote includes, dotenv loading, and
    checksum bypass via method: none.
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

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[TaskfileFinding],
        info: TaskfileInfo,
        in_tasks: bool,
    ) -> bool:
        stripped = _strip_comment(line)
        if not stripped:
            return in_tasks

        if stripped == "tasks:":
            return True

        if in_tasks:
            task_match = TASK_ENTRY_PATTERN.match(line.rstrip())
            if task_match:
                task_name = task_match.group(1).strip()
                if task_name not in info.tasks:
                    info.tasks.append(task_name)

        if INCLUDE_BLOCK_PATTERN.match(stripped):
            include_ref = stripped.split(":", 1)[-1].strip().strip("\"'")
            if include_ref and include_ref not in info.includes:
                info.includes.append(include_ref)

        if REMOTE_INCLUDE_PATTERN.match(stripped):
            include_url = stripped.split(":", 1)[-1].strip().strip("\"'")
            if include_url and include_url not in info.includes:
                info.includes.append(include_url)
            findings.append(
                TaskfileFinding(
                    kind="remote_include",
                    severity="medium",
                    message="remote Taskfile include — pin checksums and verify sources",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DOTENV_PATTERN.match(stripped):
            dotenv_ref = stripped.split(":", 1)[-1].strip().strip("[]\"'")
            if dotenv_ref and dotenv_ref not in info.dotenv_files:
                info.dotenv_files.append(dotenv_ref)
            findings.append(
                TaskfileFinding(
                    kind="dotenv_loading",
                    severity="low",
                    message="dotenv loading in task — ensure env files are not committed with secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ENV_BLOCK_PATTERN.match(stripped):
            key = stripped.split(":", 1)[0].strip()
            if key and key not in info.env_keys:
                info.env_keys.append(key)

        if METHOD_NONE_PATTERN.match(stripped):
            findings.append(
                TaskfileFinding(
                    kind="checksum_bypass",
                    severity="high",
                    message="method: none disables remote Taskfile checksum verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SECRET_VAR_PATTERN.search(stripped):
            findings.append(
                TaskfileFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Taskfile — use env vars or a secret manager",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(stripped):
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

        if CURL_PIPE_SHELL_PATTERN.search(stripped):
            findings.append(
                TaskfileFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="piping curl/wget to shell is unsafe",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if RM_RF_ROOT_PATTERN.search(stripped):
            findings.append(
                TaskfileFinding(
                    kind="destructive_rm",
                    severity="high",
                    message="destructive rm -rf on root or home directory",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SUDO_PATTERN.search(stripped):
            findings.append(
                TaskfileFinding(
                    kind="sudo_usage",
                    severity="medium",
                    message="sudo in task command — avoid privilege escalation in scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CHMOD_777_PATTERN.search(stripped):
            findings.append(
                TaskfileFinding(
                    kind="chmod_777",
                    severity="high",
                    message="chmod 777 grants world-writable permissions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FORCE_PUSH_PATTERN.search(stripped):
            findings.append(
                TaskfileFinding(
                    kind="force_push",
                    severity="medium",
                    message="git push --force can overwrite remote history",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EVAL_PATTERN.search(stripped):
            findings.append(
                TaskfileFinding(
                    kind="eval_usage",
                    severity="medium",
                    message="eval in task command can execute arbitrary code",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(stripped):
            findings.append(
                TaskfileFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL — use HTTPS for downloads and includes",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(stripped):
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

        if TLS_VERIFY_OFF_PATTERN.search(stripped):
            findings.append(
                TaskfileFinding(
                    kind="tls_verify_disabled",
                    severity="high",
                    message="TLS verification disabled — keep certificate validation enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(stripped):
            findings.append(
                TaskfileFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell command in task — review script logic",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(stripped):
            findings.append(
                TaskfileFinding(
                    kind="sensitive_path",
                    severity="high",
                    message="sensitive path reference — avoid exposing credential files in tasks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        return in_tasks

    def _analyze_file(self, path: Path) -> tuple[list[TaskfileFinding], TaskfileInfo]:
        findings: list[TaskfileFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, TaskfileInfo(path=rel)

        info = TaskfileInfo(path=rel, lines=len(raw_lines))
        in_tasks = False

        for lineno, raw in enumerate(raw_lines, start=1):
            in_tasks = self._scan_line(raw, lineno, rel, findings, info, in_tasks)

        return findings, info

    def analyze(self) -> list[TaskfileFinding]:
        """Scan Taskfiles and return findings."""
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
        """Return a 0-100 health score (100 = no issues or no Taskfiles)."""
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

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened Taskfile template."""
        return """\
# Generated by DevAI TaskfileAnalyzer
version: '3'

# Use env vars for secrets — never hardcode tokens in tasks
# env:
#   API_TOKEN: '{{.API_TOKEN}}'

tasks:
  default:
    desc: List available tasks
    cmds:
      - task --list

  install:
    desc: Install project dependencies
    cmds:
      - pip install -e ".[dev]"

  test:
    desc: Run the test suite
    cmds:
      - python -m pytest

  lint:
    desc: Run linters
    cmds:
      - ruff check src tests

# Avoid curl | sh — vendor scripts with checksum verification
# Avoid sudo, chmod 777, and git push --force in task commands
# Pin remote includes with checksums — never use method: none in production
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
                f"  - {info.path}: {len(info.tasks)} task(s), "
                f"{len(info.env_keys)} env block(s)"
            )
            lines.append(f"    tasks: {tasks}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
