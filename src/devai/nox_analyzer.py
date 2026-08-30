"""NoxAnalyzer — audit noxfile.py for security and CI reliability risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = ("noxfile.py", "noxfile_config.py")

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
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|exec\s*\(|os\.system\s*\(|subprocess\.(?:call|run|Popen)\([^)]*shell\s*=\s*True)",
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
REUSE_VENV_PATTERN = re.compile(
    r"(?:reuse_existing_virtualenvs|reuse_venv)\s*=\s*True\b",
    re.IGNORECASE,
)
VENV_BACKEND_NONE_PATTERN = re.compile(
    r"venv_backend\s*=\s*[\"']none[\"']",
    re.IGNORECASE,
)
ENV_UPDATE_OS_ENVIRON_PATTERN = re.compile(
    r"(?:session\.env\.update|os\.environ\.copy)\s*\(\s*(?:os\.environ)?\s*\)",
    re.IGNORECASE,
)
CHDIR_OUTSIDE_PATTERN = re.compile(
    r"(?:session\.chdir|chdir)\s*\(\s*[\"'](?:\.\./|/etc/|/tmp/|\.ssh/)",
    re.IGNORECASE,
)
SECURITY_SESSION_SKIP_PATTERN = re.compile(
    r"(?:session\.notify|notify)\s*\(\s*[\"'][^\"']*(?:security|auth|permission|secret|credential)",
    re.IGNORECASE,
)
DOWNLOAD_PYTHON_PATTERN = re.compile(
    r"download_python\s*=\s*True\b",
    re.IGNORECASE,
)
SESSION_DECORATOR_PATTERN = re.compile(r"^\s*@nox\.session\b")
SESSION_DEF_PATTERN = re.compile(r"^\s*def\s+(\w+)\s*\(\s*session\b")


@dataclass
class NoxFinding:
    """A security or best-practice issue in a nox configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class NoxInfo:
    """Parsed metadata about a nox configuration file."""

    path: str
    lines: int = 0
    sessions: list[str] = field(default_factory=list)


@dataclass
class NoxStats:
    """Aggregate nox analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


class NoxAnalyzer:
    """Audit noxfile.py for security and CI reliability risks.

    Scans noxfile.py for hardcoded secrets, reuse_venv=True, venv_backend='none',
    os.environ forwarding, insecure pip indexes, HTTP git deps, chdir outside the
    project, and dangerous shell commands.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[NoxFinding] | None = None
        self._stats: NoxStats | None = None
        self._infos: list[NoxInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return nox configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[NoxFinding],
        info: NoxInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        session_match = SESSION_DEF_PATTERN.match(stripped)
        if session_match:
            session_name = session_match.group(1)
            if session_name not in info.sessions:
                info.sessions.append(session_name)

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                NoxFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in noxfile — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                NoxFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in noxfile — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                NoxFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in noxfile — use HTTPS for indexes and deps",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                NoxFinding(
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
                NoxFinding(
                    kind="dangerous_command",
                    severity="high",
                    message="dangerous shell command in noxfile — avoid eval/exec and remote scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_HTTP_DEPS_PATTERN.search(line):
            findings.append(
                NoxFinding(
                    kind="insecure_git_deps",
                    severity="high",
                    message="HTTP git dependency in noxfile — use HTTPS or pinned wheels",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CHDIR_OUTSIDE_PATTERN.search(line):
            findings.append(
                NoxFinding(
                    kind="chdir_outside",
                    severity="high",
                    message="session.chdir points outside project — review for path traversal risks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REUSE_VENV_PATTERN.search(line):
            findings.append(
                NoxFinding(
                    kind="reuse_venv",
                    severity="medium",
                    message="reuse_venv=True may leak packages between sessions — prefer isolated envs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if VENV_BACKEND_NONE_PATTERN.search(line):
            findings.append(
                NoxFinding(
                    kind="venv_backend_none",
                    severity="medium",
                    message="venv_backend='none' disables virtualenv isolation — review for supply-chain risks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ENV_UPDATE_OS_ENVIRON_PATTERN.search(line):
            findings.append(
                NoxFinding(
                    kind="env_forward_all",
                    severity="medium",
                    message="forwarding full os.environ into session — prefer explicit session.env keys",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_PIP_INDEX_PATTERN.search(line):
            findings.append(
                NoxFinding(
                    kind="insecure_pip_index",
                    severity="medium",
                    message="insecure pip index URL — use HTTPS package indexes in nox sessions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SECURITY_SESSION_SKIP_PATTERN.search(line):
            findings.append(
                NoxFinding(
                    kind="security_session_skip",
                    severity="medium",
                    message="session.notify may skip security-related sessions — review exclusions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DOWNLOAD_PYTHON_PATTERN.search(line):
            findings.append(
                NoxFinding(
                    kind="download_python",
                    severity="low",
                    message="download_python=True fetches interpreters at runtime — pin versions and verify sources",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[NoxFinding], NoxInfo]:
        findings: list[NoxFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, NoxInfo(path=rel)

        info = NoxInfo(path=rel, lines=len(raw_lines))

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[NoxFinding]:
        """Scan nox configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[NoxFinding] = []
        infos: list[NoxInfo] = []
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
        self._stats = NoxStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> NoxStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[NoxInfo]:
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
        """Scaffold a hardened noxfile.py template."""
        return """\
# Generated by DevAI NoxAnalyzer
from __future__ import annotations

import nox

nox.options.reuse_existing_virtualenvs = False
nox.options.stop_on_first_error = True


@nox.session(python=["3.10", "3.11", "3.12"])
def tests(session: nox.Session) -> None:
    session.install("-r", "requirements-test.txt")
    session.env["PYTHONWARNINGS"] = "error"
    session.run("pytest", "tests", *session.posargs)


@nox.session(python="3.12")
def lint(session: nox.Session) -> None:
    session.install("ruff")
    session.run("ruff", "check", ".")
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Nox configs: none found"
        return (
            f"Nox configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Nox analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            sessions = ", ".join(info.sessions) if info.sessions else "none detected"
            lines.append(f"  - {info.path}: sessions={sessions}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
