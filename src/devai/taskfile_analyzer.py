"""TaskfileAnalyzer — audit Taskfile.yml for security and task-runner safety."""

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
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
ENV_SECRET_PATTERN = re.compile(
    r"^[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL|AUTH)[A-Z0-9_]*\s*[=:]\s*"
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
    r"(?:rm\s+-rf\s+(/|\$\(HOME\)|~|\*)|chmod\s+777|eval\s*\(|"
    r"\bsh\s+-c\b|\bsudo\b)",
    re.IGNORECASE,
)
TLS_VERIFY_OFF_PATTERN = re.compile(
    r"(?:GIT_SSL_NO_VERIFY|NODE_TLS_REJECT_UNAUTHORIZED)\s*[=:]\s*(?:1|true|yes)|"
    r"(?:curl|wget)\s+[^\n]*--insecure\b|"
    r"(?:curl|wget)\s+[^\n]*-k\b",
    re.IGNORECASE,
)
PRIVILEGED_DOCKER_PATTERN = re.compile(
    r"(?:privileged\s*:\s*true|--privileged\b|docker\.sock|/var/run/docker\.sock)",
    re.IGNORECASE,
)
TASK_INJECTION_PATTERN = re.compile(
    r"\{\{\s*\.\s*(?:TASK|CLI|ROOT|DIR|USER_WORKING_DIR)\b",
    re.IGNORECASE,
)
VARS_SECTION_PATTERN = re.compile(r"^\s*vars:\s*$", re.IGNORECASE)
ENV_SECTION_PATTERN = re.compile(r"^\s*env:\s*$", re.IGNORECASE)
CMDS_SECTION_PATTERN = re.compile(r"^\s*cmds:\s*$", re.IGNORECASE)
SOURCES_SECTION_PATTERN = re.compile(r"^\s*sources:\s*$", re.IGNORECASE)
DOTENV_SECTION_PATTERN = re.compile(r"^\s*dotenv:\s*$", re.IGNORECASE)


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
    vars: list[str] = field(default_factory=list)
    global_env: list[str] = field(default_factory=list)


@dataclass
class TaskfileStats:
    """Aggregate Taskfile analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_taskfile(path: Path) -> bool:
    return path.name in TASKFILE_NAMES


def _is_comment_line(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def _strip_yaml_comment(line: str) -> str:
    if "#" in line:
        in_quote = False
        quote_char = ""
        for i, ch in enumerate(line):
            if ch in ("'", '"') and (i == 0 or line[i - 1] != "\\"):
                if not in_quote:
                    in_quote = True
                    quote_char = ch
                elif ch == quote_char:
                    in_quote = False
            elif ch == "#" and not in_quote:
                return line[:i].rstrip()
    return line.rstrip()


class TaskfileAnalyzer:
    """Audit Go Task Taskfiles for security issues.

    Scans Taskfile.yml and Taskfile.yaml for hardcoded secrets in vars/env,
    sensitive paths in sources/dotenv, curl piped to shell, privileged Docker,
    disabled TLS verification, SCM credentials in URLs, and dangerous shell
    commands in task cmds.
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
        in_vars: bool,
        in_env: bool,
        in_cmds: bool,
        in_sources: bool,
        in_dotenv: bool,
    ) -> None:
        if _is_comment_line(line):
            return

        stripped = _strip_yaml_comment(line).strip()
        if not stripped:
            return

        if VARS_SECTION_PATTERN.match(stripped):
            return
        if ENV_SECTION_PATTERN.match(stripped):
            return
        if CMDS_SECTION_PATTERN.match(stripped):
            return
        if SOURCES_SECTION_PATTERN.match(stripped):
            return
        if DOTENV_SECTION_PATTERN.match(stripped):
            return

        var_match = re.match(r"^([A-Za-z0-9_.-]+)\s*:\s*(.+)$", stripped)
        if var_match and (in_vars or in_env):
            name = var_match.group(1)
            value = var_match.group(2).strip()
            if in_vars:
                info.vars.append(name)
            if in_env:
                info.global_env.append(name)
            if HARDCODED_SECRET_PATTERN.search(stripped) or ENV_SECRET_PATTERN.search(stripped):
                findings.append(
                    TaskfileFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in vars/env — use environment or secret store",
                        path=rel,
                        lineno=lineno,
                        line=line.strip(),
                    )
                )
            elif value and not value.startswith("{{") and re.match(r'^["\'][^"\']+["\']$', value):
                if re.search(
                    r"(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL)",
                    name,
                    re.IGNORECASE,
                ):
                    findings.append(
                        TaskfileFinding(
                            kind="sensitive_env_var",
                            severity="medium",
                            message=f"sensitive variable {name} has a literal value — prefer secret injection",
                            path=rel,
                            lineno=lineno,
                            line=line.strip(),
                        )
                    )

        if in_sources or in_dotenv:
            literals = re.findall(r'["\']([^"\']+)["\']', stripped)
            if stripped.startswith("- "):
                literals.append(stripped[2:].strip().strip('"').strip("'"))
            for literal in literals:
                if SENSITIVE_PATH_PATTERN.search(literal):
                    findings.append(
                        TaskfileFinding(
                            kind="sensitive_path",
                            severity="high",
                            message=f"sensitive path in sources/dotenv: {literal}",
                            path=rel,
                            lineno=lineno,
                            line=line.strip(),
                        )
                    )

        if CURL_PIPE_SHELL_PATTERN.search(stripped):
            findings.append(
                TaskfileFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="piping curl/wget to shell in task command is unsafe",
                    path=rel,
                    lineno=lineno,
                    line=line.strip(),
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(stripped):
            kind = "destructive_command"
            if "sudo" in stripped.lower():
                kind = "sudo_usage"
            findings.append(
                TaskfileFinding(
                    kind=kind,
                    severity="high" if kind != "sudo_usage" else "medium",
                    message="dangerous shell command in task — review for privilege escalation or data loss",
                    path=rel,
                    lineno=lineno,
                    line=line.strip(),
                )
            )

        if INSECURE_HTTP_PATTERN.search(stripped):
            findings.append(
                TaskfileFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL — use HTTPS for downloads and remote resources",
                    path=rel,
                    lineno=lineno,
                    line=line.strip(),
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(stripped):
            findings.append(
                TaskfileFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in SCM URL — use SSH keys or token env vars",
                    path=rel,
                    lineno=lineno,
                    line=line.strip(),
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(stripped):
            findings.append(
                TaskfileFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="possible AWS access key in Taskfile",
                    path=rel,
                    lineno=lineno,
                    line=line.strip(),
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
                    line=line.strip(),
                )
            )

        if PRIVILEGED_DOCKER_PATTERN.search(stripped):
            findings.append(
                TaskfileFinding(
                    kind="privileged_docker",
                    severity="high",
                    message="privileged Docker or docker.sock mount — avoid container privilege escalation",
                    path=rel,
                    lineno=lineno,
                    line=line.strip(),
                )
            )

        if in_cmds and TASK_INJECTION_PATTERN.search(stripped):
            findings.append(
                TaskfileFinding(
                    kind="task_injection",
                    severity="low",
                    message="task template variable in command — ensure inputs are sanitized",
                    path=rel,
                    lineno=lineno,
                    line=line.strip(),
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
        in_tasks = False
        in_vars = False
        in_env = False
        in_cmds = False
        in_sources = False
        in_dotenv = False
        tasks_indent = -1
        section_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            stripped = _strip_yaml_comment(line)
            indent = len(line) - len(line.lstrip())
            content = stripped.strip()

            if content == "tasks:":
                in_tasks = True
                in_vars = False
                in_env = False
                in_cmds = False
                in_sources = False
                in_dotenv = False
                tasks_indent = indent
                continue

            if VARS_SECTION_PATTERN.match(content) and indent <= 2:
                in_vars = True
                in_env = False
                in_cmds = False
                in_sources = False
                in_dotenv = False
                in_tasks = False
                section_indent = indent
                continue

            if ENV_SECTION_PATTERN.match(content) and indent <= 2:
                in_env = True
                in_vars = False
                in_cmds = False
                in_sources = False
                in_dotenv = False
                in_tasks = False
                section_indent = indent
                continue

            if in_tasks and tasks_indent >= 0 and indent == tasks_indent + 2:
                task_match = re.match(r"^([a-zA-Z0-9#@:_-]+):\s*$", content)
                if task_match:
                    info.tasks.append(task_match.group(1))
                    in_cmds = False
                    in_sources = False
                    in_dotenv = False
                    section_indent = indent

            if CMDS_SECTION_PATTERN.match(content):
                in_cmds = True
                in_vars = False
                in_env = False
                in_sources = False
                in_dotenv = False
                section_indent = indent
                continue

            if SOURCES_SECTION_PATTERN.match(content):
                in_sources = True
                in_cmds = False
                in_dotenv = False
                section_indent = indent
                continue

            if DOTENV_SECTION_PATTERN.match(content):
                in_dotenv = True
                in_sources = False
                in_cmds = False
                section_indent = indent
                continue

            if indent <= section_indent and content and not content.startswith("-"):
                if content not in ("tasks:", "vars:", "env:"):
                    in_vars = False
                    in_env = False
                    in_cmds = False
                    in_sources = False
                    in_dotenv = False

            self._scan_line(
                line,
                lineno,
                rel,
                findings,
                info,
                in_vars=in_vars,
                in_env=in_env,
                in_cmds=in_cmds,
                in_sources=in_sources,
                in_dotenv=in_dotenv,
            )

        return findings, info

    def analyze(self) -> list[TaskfileFinding]:
        """Scan Taskfiles and return findings."""
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
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[TaskfileInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
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
        return """\
# Generated by DevAI TaskfileAnalyzer
version: '3'

vars:
  NODE_ENV: development

env:
  CI: "false"

tasks:
  default:
    desc: List available tasks
    cmds:
      - task --list

  install:
    desc: Install dependencies
    cmds:
      - pip install -e ".[dev]"

  test:
    desc: Run tests
    cmds:
      - python -m pytest
    sources:
      - src/**
      - tests/**
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Taskfiles: none found"
        return (
            f"Taskfiles: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
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
            lines.append(f"  - {info.path}: {len(info.tasks)} task(s), tasks={tasks}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
