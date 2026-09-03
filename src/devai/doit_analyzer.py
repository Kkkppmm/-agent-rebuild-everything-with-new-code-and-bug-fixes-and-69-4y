"""DoitAnalyzer — audit dodo.py for Doit task-runner security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = ("dodo.py", "doit.cfg")
DOIT_PACKAGE_NAMES = ("doit_tasks/__init__.py",)

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
DOIT_TOOLS_SUDO_PATTERN = re.compile(r"(?:doit\.tools\.sudo|\bsudo)\s*\(", re.IGNORECASE)
SHELL_TRUE_PATTERN = re.compile(r"shell\s*=\s*True\b", re.IGNORECASE)
IGNORE_TASK_PATTERN = re.compile(
    r"['\"]ignore['\"]\s*:\s*True\b",
    re.IGNORECASE,
)
CHDIR_OUTSIDE_PATTERN = re.compile(
    r"(?:Chdir\s*\(\s*[\"'](?:\.\./|/etc/|/tmp/|\.ssh/)|"
    r"[\"']?chdir[\"']?\s*[:=]\s*[\"'](?:\.\./|/etc/|/tmp/|\.ssh/))",
    re.IGNORECASE,
)
TASK_DEF_PATTERN = re.compile(r"^\s*def\s+task_(\w+)\s*\(")
ENV_FORWARD_PATTERN = re.compile(
    r"(?:os\.environ\[|dict\(os\.environ\)|=\s*os\.environ\b(?!\s*\.get))",
    re.IGNORECASE,
)
GETPASS_HARDCODED_PATTERN = re.compile(
    r"getpass\.getpass\s*\(\s*[\"'][^\"']+[\"']\s*\)",
    re.IGNORECASE,
)
DOIT_CFG_VERBOSITY_ZERO_PATTERN = re.compile(
    r"^\s*verbosity\s*=\s*0\b",
    re.IGNORECASE,
)


@dataclass
class DoitFinding:
    """A security or best-practice issue in a Doit tasks file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class DoitInfo:
    """Parsed metadata about a Doit tasks file."""

    path: str
    lines: int = 0
    tasks: list[str] = field(default_factory=list)


@dataclass
class DoitStats:
    """Aggregate Doit analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


class DoitAnalyzer:
    """Audit dodo.py for Doit task-runner security risks.

    Scans dodo.py, doit.cfg, and doit_tasks/__init__.py for hardcoded secrets,
    sudo usage, ignore=True task options, shell=True, os.environ forwarding,
    insecure pip indexes, HTTP git deps, chdir outside the project, and
    dangerous shell commands.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[DoitFinding] | None = None
        self._stats: DoitStats | None = None
        self._infos: list[DoitInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Doit config file paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES + DOIT_PACKAGE_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[DoitFinding],
        info: DoitInfo,
        is_cfg: bool,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        if not is_cfg:
            task_match = TASK_DEF_PATTERN.match(stripped)
            if task_match:
                task_name = task_match.group(1)
                if task_name not in info.tasks:
                    info.tasks.append(task_name)

        if HARDCODED_SECRET_PATTERN.search(line):
            if not re.search(r"os\.environ|getenv|environ\.get", line, re.IGNORECASE):
                findings.append(
                    DoitFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Doit config — use env vars or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                DoitFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Doit config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                DoitFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in Doit config — use HTTPS for indexes and deps",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                DoitFinding(
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
                DoitFinding(
                    kind="dangerous_command",
                    severity="high",
                    message="dangerous shell command in Doit config — avoid eval/exec and remote scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_HTTP_DEPS_PATTERN.search(line):
            findings.append(
                DoitFinding(
                    kind="insecure_git_deps",
                    severity="high",
                    message="HTTP git dependency in Doit config — use HTTPS or pinned wheels",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CHDIR_OUTSIDE_PATTERN.search(line):
            findings.append(
                DoitFinding(
                    kind="chdir_outside",
                    severity="high",
                    message="chdir points outside project — review for path traversal risks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DOIT_TOOLS_SUDO_PATTERN.search(line) or (
            SUDO_PATTERN.search(line) and ("actions" in line or "run(" in line or '"' in line)
        ):
            findings.append(
                DoitFinding(
                    kind="sudo_usage",
                    severity="medium",
                    message="task runs with sudo — prefer least-privilege and avoid root in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_TASK_PATTERN.search(line):
            findings.append(
                DoitFinding(
                    kind="ignore_task_failure",
                    severity="medium",
                    message="ignore=True masks task failures — prefer explicit error handling",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SHELL_TRUE_PATTERN.search(line):
            findings.append(
                DoitFinding(
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
                DoitFinding(
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
                DoitFinding(
                    kind="insecure_pip_index",
                    severity="medium",
                    message="insecure pip index URL — use HTTPS package indexes in tasks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GETPASS_HARDCODED_PATTERN.search(line):
            findings.append(
                DoitFinding(
                    kind="hardcoded_getpass_prompt",
                    severity="low",
                    message="getpass with static prompt — review for credential handling in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if is_cfg and DOIT_CFG_VERBOSITY_ZERO_PATTERN.search(line):
            findings.append(
                DoitFinding(
                    kind="verbosity_zero",
                    severity="low",
                    message="verbosity=0 in doit.cfg hides task output — review for silent failures",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[DoitFinding], DoitInfo]:
        findings: list[DoitFinding] = []
        rel = str(path.relative_to(self.root))
        is_cfg = path.name == "doit.cfg"
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, DoitInfo(path=rel)

        info = DoitInfo(path=rel, lines=len(raw_lines))

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            self._scan_line(line, lineno, rel, findings, info, is_cfg)

        return findings, info

    def analyze(self) -> list[DoitFinding]:
        """Scan Doit config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[DoitFinding] = []
        infos: list[DoitInfo] = []
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
        self._stats = DoitStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> DoitStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[DoitInfo]:
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
        """Scaffold a hardened dodo.py template."""
        return """\
# Generated by DevAI DoitAnalyzer
from __future__ import annotations

import os

from doit.tools import run


def task_test():
    \"\"\"Run the test suite.\"\"\"
    return {
        "actions": [run("pytest tests", shell=False)],
        "verbosity": 2,
    }


def task_lint():
    \"\"\"Run linters.\"\"\"
    return {
        "actions": [run("ruff check .", shell=False)],
        "verbosity": 2,
    }


def task_deploy():
    \"\"\"Deploy using credentials from the environment only.\"\"\"
    token = os.environ.get("DEPLOY_TOKEN")
    if not token:
        raise RuntimeError("DEPLOY_TOKEN is required")
    return {
        "actions": [run("deploy-cli --token $DEPLOY_TOKEN", shell=False)],
        "verbosity": 2,
    }
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Doit configs: none found"
        return (
            f"Doit configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Doit analysis:",
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
