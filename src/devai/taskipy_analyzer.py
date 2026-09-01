"""TaskipyAnalyzer — audit tasks.py for Invoke task-runner security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = ("tasks.py", "taskfile.py")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*=\s*"
    r"[\"'][^\"']{4,}[\"']",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|exec\s*\(|\bos\.system\s*\(|"
    r"subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True)",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
SHELL_TRUE_PATTERN = re.compile(
    r"(?:run|ctx\.run)\s*\([^)]*shell\s*=\s*True",
    re.IGNORECASE,
)
TASKIPY_MARKER_PATTERN = re.compile(
    r"(?:from\s+taskipy\s+import|import\s+taskipy|@task|Namespace\s*\()",
    re.IGNORECASE,
)
INVOKE_MARKER_PATTERN = re.compile(
    r"(?:from\s+invoke\s+import|import\s+invoke|@task)",
    re.IGNORECASE,
)
WILDCARD_RUN_PATTERN = re.compile(
    r"(?:run|ctx\.run)\s*\(\s*[\"'][^\"']*\*[^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_ENV_PATTERN = re.compile(
    r"os\.environ\s*\[\s*[\"'](?:PASSWORD|SECRET|TOKEN|API_KEY|CREDENTIAL)",
    re.IGNORECASE,
)
UNSAFE_PRELOAD_PATTERN = re.compile(
    r"(?:preload|autouse)\s*=\s*True",
    re.IGNORECASE,
)


@dataclass
class TaskipyFinding:
    """A security or best-practice issue in a tasks.py file."""

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
    """Parsed metadata about a tasks.py file."""

    path: str
    lines: int = 0
    tasks: list[str] = field(default_factory=list)
    uses_taskipy: bool = False
    uses_invoke: bool = False


@dataclass
class TaskipyStats:
    """Aggregate taskipy analysis statistics."""

    config_files: int = 0
    findings: int = 0
    tasks: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES


class TaskipyAnalyzer:
    """Audit tasks.py for Invoke/taskipy task-runner security risks.

    Scans tasks.py for hardcoded secrets, shell=True usage, sudo commands,
    curl|sh patterns, dangerous subprocess calls, wildcard run arguments,
    and insecure HTTP URLs in task definitions.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TaskipyFinding] | None = None
        self._stats: TaskipyStats | None = None
        self._infos: list[TaskipyInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return tasks.py paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("tasks.py")):
            if path.is_file() and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[TaskipyFinding],
        info: TaskipyInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        if TASKIPY_MARKER_PATTERN.search(line):
            info.uses_taskipy = True
        if INVOKE_MARKER_PATTERN.search(line):
            info.uses_invoke = True

        task_match = re.match(
            r"^\s*def\s+(\w+)\s*\([^)]*(?:ctx|context)",
            line,
        )
        if task_match:
            task_name = task_match.group(1)
            if task_name not in info.tasks:
                info.tasks.append(task_name)

        task_decorator = re.search(r"@task(?:\([^)]*\))?\s*$", stripped)
        if task_decorator:
            next_task = re.match(r"^\s*def\s+(\w+)", stripped)
            if next_task and next_task.group(1) not in info.tasks:
                info.tasks.append(next_task.group(1))

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                TaskipyFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in tasks.py — use env vars or CI secrets",
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
                    message="AWS access key in tasks.py — rotate and use env vars",
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
                    message="insecure HTTP URL in tasks.py — use HTTPS",
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
                    message="dangerous shell command in task — avoid eval/exec and remote scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SUDO_PATTERN.search(line):
            findings.append(
                TaskipyFinding(
                    kind="sudo_usage",
                    severity="high",
                    message="task uses sudo — avoid elevated privileges in automation scripts",
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
                    message="task uses shell=True — prefer explicit argument lists to prevent injection",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if WILDCARD_RUN_PATTERN.search(line):
            findings.append(
                TaskipyFinding(
                    kind="wildcard_run",
                    severity="medium",
                    message="task run uses shell wildcards — review for command injection",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if HARDCODED_ENV_PATTERN.search(line):
            findings.append(
                TaskipyFinding(
                    kind="hardcoded_env_secret",
                    severity="high",
                    message="hardcoded secret assigned to os.environ — use secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNSAFE_PRELOAD_PATTERN.search(line):
            findings.append(
                TaskipyFinding(
                    kind="unsafe_preload",
                    severity="low",
                    message="preload/autouse task runs on every invocation — review side effects",
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
        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[TaskipyFinding]:
        """Scan tasks.py files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TaskipyFinding] = []
        infos: list[TaskipyInfo] = []
        paths = self.config_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        total_tasks = sum(len(i.tasks) for i in infos)
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        self._findings = findings
        self._infos = infos
        self._stats = TaskipyStats(
            config_files=len(paths),
            findings=len(findings),
            tasks=total_tasks,
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
        if stats.config_files == 0 or stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_template(self) -> str:
        return """\
# Generated by DevAI TaskipyAnalyzer
from invoke import task


@task
def lint(ctx):
    \"\"\"Run linters without shell=True.\"\"\"
    ctx.run("ruff check .", echo=True)


@task
def test(ctx):
    \"\"\"Run tests.\"\"\"
    ctx.run("pytest", echo=True)
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Taskipy: no tasks.py files found"
        return (
            f"Taskipy: {stats.config_files} file(s), {stats.tasks} task(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Taskipy/Invoke tasks analysis:",
            f"  config files: {stats.config_files}",
            f"  tasks: {stats.tasks}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            runner = []
            if info.uses_taskipy:
                runner.append("taskipy")
            if info.uses_invoke:
                runner.append("invoke")
            runner_str = ", ".join(runner) or "unknown"
            lines.append(f"  - {info.path}: {len(info.tasks)} task(s), runners=[{runner_str}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
