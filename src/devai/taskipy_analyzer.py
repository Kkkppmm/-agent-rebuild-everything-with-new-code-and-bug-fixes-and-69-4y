"""TaskipyAnalyzer — audit pyproject.toml [tool.taskipy] for Taskipy task-runner security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = ("taskipy.toml",)
PYPROJECT_NAME = "pyproject.toml"

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
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|exec\s*\(|os\.system\s*\(|"
    r"subprocess\.(?:call|run|Popen)\([^)]*shell\s*=\s*True)",
    re.IGNORECASE,
)
INSECURE_PIP_INDEX_PATTERN = re.compile(
    r"(?:--index-url|--extra-index-url|--trusted-host)\s*[\"']?http://|"
    r"(?:--index-url|--extra-index-url)\s*[\"']http://",
    re.IGNORECASE,
)
GIT_HTTP_DEPS_PATTERN = re.compile(
    r"(?:git\+http://|http://[^\s\"']+#egg=)",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
SHELL_TRUE_PATTERN = re.compile(r"shell\s*=\s*True\b", re.IGNORECASE)
USE_VARS_TRUE_PATTERN = re.compile(r"use_vars\s*=\s*true\b", re.IGNORECASE)
CWD_OUTSIDE_PATTERN = re.compile(
    r"(?:cwd|chdir)\s*=\s*[\"'](?:\.\./|/etc/|/tmp/|\.ssh/)",
    re.IGNORECASE,
)
TASKIPY_SECTION_PATTERN = re.compile(r"^\[tool\.taskipy(?:\.tasks)?\]", re.IGNORECASE)
TASK_DEF_PATTERN = re.compile(
    r"^\s*([a-zA-Z_][\w-]*)\s*=\s*[\"']",
    re.IGNORECASE,
)
ENV_FORWARD_PATTERN = re.compile(
    r"(?:os\.environ\[|dict\(os\.environ\)|=\s*os\.environ\b(?!\s*\.get))",
    re.IGNORECASE,
)
INTERPOLATION_ALL_ENV_PATTERN = re.compile(
    r"\{[A-Z_][A-Z0-9_]*\}",
)


@dataclass
class TaskipyFinding:
    """A security or best-practice issue in a Taskipy configuration."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class TaskipyInfo:
    """Parsed metadata about a Taskipy configuration file."""

    path: str
    lines: int = 0
    tasks: list[str] = field(default_factory=list)
    use_vars: bool = False


@dataclass
class TaskipyStats:
    """Aggregate Taskipy analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


class TaskipyAnalyzer:
    """Audit pyproject.toml [tool.taskipy] for Taskipy task-runner security risks.

    Scans pyproject.toml and taskipy.toml for hardcoded secrets, use_vars=true,
    sudo usage, shell=True, os.environ forwarding, insecure pip indexes, HTTP git
    deps, cwd outside the project, and dangerous shell commands.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TaskipyFinding] | None = None
        self._stats: TaskipyStats | None = None
        self._infos: list[TaskipyInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Taskipy configuration paths found in the project."""
        found: list[Path] = []
        pyproject = self.root / PYPROJECT_NAME
        if pyproject.is_file() and self._has_taskipy_section(pyproject):
            found.append(pyproject)
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        return found

    def _has_taskipy_section(self, path: Path) -> bool:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        return "[tool.taskipy" in text.lower()

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[TaskipyFinding],
        info: TaskipyInfo,
        in_taskipy_section: bool,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        if in_taskipy_section and USE_VARS_TRUE_PATTERN.search(line):
            info.use_vars = True
            findings.append(
                TaskipyFinding(
                    kind="use_vars_all",
                    severity="medium",
                    message="use_vars=true forwards all env vars to tasks — prefer explicit interpolation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if not in_taskipy_section:
            return

        if HARDCODED_SECRET_PATTERN.search(line):
            if not re.search(r"os\.environ|getenv|environ\.get|\{[A-Z_]+\}", line, re.IGNORECASE):
                findings.append(
                    TaskipyFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Taskipy config — use env vars or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                TaskipyFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Taskipy config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                TaskipyFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in Taskipy config — use HTTPS for indexes and deps",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                TaskipyFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in URL — use SSH keys or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line) or DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                TaskipyFinding(
                    kind="dangerous_command",
                    severity="high",
                    message="dangerous shell command in Taskipy config — avoid eval/exec and remote scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_HTTP_DEPS_PATTERN.search(line):
            findings.append(
                TaskipyFinding(
                    kind="insecure_git_deps",
                    severity="high",
                    message="HTTP git dependency in Taskipy config — use HTTPS or pinned wheels",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CWD_OUTSIDE_PATTERN.search(line):
            findings.append(
                TaskipyFinding(
                    kind="cwd_outside",
                    severity="high",
                    message="cwd points outside project — review for path traversal risks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SUDO_PATTERN.search(line) and ("=" in line or '"' in line or "'" in line):
            findings.append(
                TaskipyFinding(
                    kind="sudo_usage",
                    severity="medium",
                    message="task runs with sudo — prefer least-privilege and avoid root in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SHELL_TRUE_PATTERN.search(line):
            findings.append(
                TaskipyFinding(
                    kind="shell_true",
                    severity="medium",
                    message="shell=True enables shell injection — pass argument lists instead",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ENV_FORWARD_PATTERN.search(line):
            findings.append(
                TaskipyFinding(
                    kind="env_forward_all",
                    severity="medium",
                    message="reading os.environ in tasks — prefer explicit env keys",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_PIP_INDEX_PATTERN.search(line):
            findings.append(
                TaskipyFinding(
                    kind="insecure_pip_index",
                    severity="medium",
                    message="insecure pip index URL — use HTTPS package indexes in tasks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[TaskipyFinding], TaskipyInfo]:
        findings: list[TaskipyFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, TaskipyInfo(path=rel)

        info = TaskipyInfo(path=rel, lines=len(raw_lines))
        in_taskipy_section = path.name == "taskipy.toml"

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            stripped = line.strip()
            if TASKIPY_SECTION_PATTERN.match(stripped):
                in_taskipy_section = True
            elif stripped.startswith("[") and not TASKIPY_SECTION_PATTERN.match(stripped):
                in_taskipy_section = False

            if in_taskipy_section:
                task_match = TASK_DEF_PATTERN.match(stripped)
                if task_match:
                    task_name = task_match.group(1)
                    if task_name.lower() not in ("use_vars", "cwd", "chdir"):
                        if task_name not in info.tasks:
                            info.tasks.append(task_name)

            self._scan_line(line, lineno, rel, findings, info, in_taskipy_section)

        return findings, info

    def analyze(self) -> list[TaskipyFinding]:
        """Scan Taskipy config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TaskipyFinding] = []
        infos: list[TaskipyInfo] = []
        paths = self.config_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = TaskipyStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> TaskipyStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[TaskipyInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
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
        """Scaffold a hardened pyproject.toml [tool.taskipy] template."""
        return """\
# Generated by DevAI TaskipyAnalyzer
# Add this section to pyproject.toml

[tool.taskipy]
use_vars = false

[tool.taskipy.tasks]
lint = "ruff check ."
test = "pytest tests"
typecheck = "mypy src"
# Use env interpolation instead of hardcoded secrets:
# deploy = "deploy-cli --token {DEPLOY_TOKEN}"
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Taskipy configs: none found"
        return (
            f"Taskipy configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Taskipy analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            tasks = ", ".join(info.tasks) if info.tasks else "none detected"
            use_vars = "yes" if info.use_vars else "no"
            lines.append(f"  - {info.path}: tasks={tasks}, use_vars={use_vars}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
