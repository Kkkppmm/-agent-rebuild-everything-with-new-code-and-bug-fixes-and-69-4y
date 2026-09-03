"""InvokeAnalyzer — audit tasks.py for Invoke task-runner security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = ("tasks.py",)
TASKS_PACKAGE_NAMES = ("tasks/__init__.py",)

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
RUN_AS_ROOT_PATTERN = re.compile(
    r"(?:run\s*\(\s*[\"']sudo|run\s*\(\s*[\"']su\s)",
    re.IGNORECASE,
)
WARN_ONLY_PATTERN = re.compile(
    r"warn_only\s*=\s*True\b",
    re.IGNORECASE,
)
PROMPT_PATTERN = re.compile(
    r"prompt\s*=\s*False\b",
    re.IGNORECASE,
)
PTY_PATTERN = re.compile(
    r"pty\s*=\s*True\b",
    re.IGNORECASE,
)
ENV_FORWARD_PATTERN = re.compile(
    r"(?:config\.run\.env|run\.env)\s*=\s*(?:os\.environ|dict\(os\.environ\))",
    re.IGNORECASE,
)
CHDIR_OUTSIDE_PATTERN = re.compile(
    r"(?:cd\s*\(\s*[\"'](?:\.\./|/etc/|/tmp/|\.ssh/)|"
    r"chdir\s*\(\s*[\"'](?:\.\./|/etc/|/tmp/|\.ssh/))",
    re.IGNORECASE,
)
TASK_DECORATOR_PATTERN = re.compile(r"^\s*@task\b")
TASK_DEF_PATTERN = re.compile(r"^\s*def\s+(\w+)\s*\(\s*(?:c|context)\b")


@dataclass
class InvokeFinding:
    """A security or best-practice issue in an Invoke tasks file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class InvokeInfo:
    """Parsed metadata about an Invoke tasks file."""

    path: str
    lines: int = 0
    tasks: list[str] = field(default_factory=list)


@dataclass
class InvokeStats:
    """Aggregate Invoke analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


class InvokeAnalyzer:
    """Audit tasks.py for Invoke task-runner security risks.

    Scans tasks.py and tasks/__init__.py for hardcoded secrets, sudo usage,
    warn_only=True, prompt=False, pty=True, os.environ forwarding, insecure
    pip indexes, HTTP git deps, chdir outside the project, and dangerous shell
    commands.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[InvokeFinding] | None = None
        self._stats: InvokeStats | None = None
        self._infos: list[InvokeInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Invoke tasks file paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES + TASKS_PACKAGE_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[InvokeFinding],
        info: InvokeInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        task_match = TASK_DEF_PATTERN.match(stripped)
        if task_match:
            task_name = task_match.group(1)
            if task_name not in info.tasks:
                info.tasks.append(task_name)

        if HARDCODED_SECRET_PATTERN.search(line):
            if not re.search(r"os\.environ|getenv|environ\.get", line, re.IGNORECASE):
                findings.append(
                    InvokeFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in tasks.py — use env vars or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                InvokeFinding(
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
                InvokeFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in tasks.py — use HTTPS for indexes and deps",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                InvokeFinding(
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
                InvokeFinding(
                    kind="dangerous_command",
                    severity="high",
                    message="dangerous shell command in tasks.py — avoid eval/exec and remote scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_HTTP_DEPS_PATTERN.search(line):
            findings.append(
                InvokeFinding(
                    kind="insecure_git_deps",
                    severity="high",
                    message="HTTP git dependency in tasks.py — use HTTPS or pinned wheels",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CHDIR_OUTSIDE_PATTERN.search(line):
            findings.append(
                InvokeFinding(
                    kind="chdir_outside",
                    severity="high",
                    message="cd/chdir points outside project — review for path traversal risks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if RUN_AS_ROOT_PATTERN.search(line) or (
            SUDO_PATTERN.search(line) and "run(" in line
        ):
            findings.append(
                InvokeFinding(
                    kind="sudo_usage",
                    severity="medium",
                    message="task runs with sudo — prefer least-privilege and avoid root in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if WARN_ONLY_PATTERN.search(line):
            findings.append(
                InvokeFinding(
                    kind="warn_only",
                    severity="medium",
                    message="warn_only=True masks command failures — prefer explicit error handling",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PROMPT_PATTERN.search(line):
            findings.append(
                InvokeFinding(
                    kind="prompt_disabled",
                    severity="medium",
                    message="prompt=False disables confirmation for destructive commands",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ENV_FORWARD_PATTERN.search(line):
            findings.append(
                InvokeFinding(
                    kind="env_forward_all",
                    severity="medium",
                    message="forwarding full os.environ into tasks — prefer explicit env keys",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_PIP_INDEX_PATTERN.search(line):
            findings.append(
                InvokeFinding(
                    kind="insecure_pip_index",
                    severity="medium",
                    message="insecure pip index URL — use HTTPS package indexes in tasks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PTY_PATTERN.search(line):
            findings.append(
                InvokeFinding(
                    kind="pty_enabled",
                    severity="low",
                    message="pty=True allocates a pseudo-terminal — review for interactive credential prompts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[InvokeFinding], InvokeInfo]:
        findings: list[InvokeFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, InvokeInfo(path=rel)

        info = InvokeInfo(path=rel, lines=len(raw_lines))

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[InvokeFinding]:
        """Scan Invoke tasks files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[InvokeFinding] = []
        infos: list[InvokeInfo] = []
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
        self._stats = InvokeStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> InvokeStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[InvokeInfo]:
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
        """Scaffold a hardened tasks.py template."""
        return """\
# Generated by DevAI InvokeAnalyzer
from __future__ import annotations

import os

from invoke import Collection, task


@task
def test(c):
    \"\"\"Run the test suite in an isolated environment.\"\"\"
    c.run("pytest tests", pty=False, warn_only=False)


@task
def lint(c):
    \"\"\"Run linters.\"\"\"
    c.run("ruff check .", pty=False, warn_only=False)


@task
def deploy(c):
    \"\"\"Deploy using credentials from the environment only.\"\"\"
    token = os.environ.get("DEPLOY_TOKEN")
    if not token:
        raise RuntimeError("DEPLOY_TOKEN is required")
    c.run("deploy-cli --token $DEPLOY_TOKEN", pty=False, warn_only=False)


ns = Collection(test, lint, deploy)
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Invoke configs: none found"
        return (
            f"Invoke configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Invoke analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            tasks = ", ".join(info.tasks) if info.tasks else "none detected"
            lines.append(f"  - {info.path}: tasks={tasks}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
