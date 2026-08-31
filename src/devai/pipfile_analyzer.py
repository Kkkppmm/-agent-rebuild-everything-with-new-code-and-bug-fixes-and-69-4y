"""PipfileAnalyzer — audit Pipenv Pipfile and Pipfile.lock for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PIPFILE_NAMES = ("Pipfile",)
PIPFILE_LOCK_NAMES = ("Pipfile.lock",)
PIPFILE_MARKER_PATTERN = re.compile(
    r"(?:^\[packages\]|^\[dev-packages\]|^\[requires\]|^\[\[source\]\]|"
    r"^\[scripts\]|pipenv)",
    re.IGNORECASE | re.MULTILINE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|pypi[_-]?token|http-basic)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
PYPI_TOKEN_PATTERN = re.compile(r"[\"']?pypi-[A-Za-z0-9_-]{20,}[\"']?", re.IGNORECASE)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
SCM_CREDENTIALS_PATTERN = re.compile(
    r"(?:git\+https?://|https?://)[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
DYNAMIC_VERSION_PATTERN = re.compile(
    r"=\s*[\"']\*[\"']|"
    r"=\s*[\"'](?:latest|LATEST)[\"']|"
    r"(?:>=|<=|>|<)\s*[\"']?\d",
    re.IGNORECASE,
)
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:ref|branch|tag)\s*=\s*[\"'](?:main|master|HEAD|develop)[\"']|"
    r"@(?:main|master|HEAD|develop)\b",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:verify_ssl[\"']?\s*[=:]\s*false|cert[\"']?\s*[=:]\s*false|disable[_-]?ssl|"
    r"ssl[_-]?verify[\"']?\s*[=:]\s*false|trusted-host\s*=)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
SOURCE_URL_PATTERN = re.compile(
    r"url\s*=\s*[\"']?(\S+)[\"']?",
    re.IGNORECASE,
)
SCRIPTS_SECTION_PATTERN = re.compile(r"^\s*\[scripts\]", re.IGNORECASE)


@dataclass
class PipfileFinding:
    """A security or best-practice issue in a Pipenv configuration file."""

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
class PipfileInfo:
    """Parsed metadata about a Pipenv configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    dependencies: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)


@dataclass
class PipfileStats:
    """Aggregate Pipenv analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_pipfile(path: Path) -> bool:
    """Return True if the path looks like a Pipenv configuration file."""
    name = path.name
    if name in PIPFILE_LOCK_NAMES:
        return True
    if name in PIPFILE_NAMES:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            if PIPFILE_MARKER_PATTERN.search(head):
                return True
        except OSError:
            pass
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "Pipfile":
        return "pipfile"
    if name == "Pipfile.lock":
        return "lock"
    return "unknown"


class PipfileAnalyzer:
    """Audit Pipenv Pipfile and Pipfile.lock for security issues.

    Scans Pipfile and Pipfile.lock for hardcoded PyPI tokens, insecure HTTP
    source URLs, credentials in git/source URLs, unpinned git dependencies,
    loose version constraints, disabled SSL verification, missing Pipfile.lock,
    and curl-pipe-to-shell patterns in scripts.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PipfileFinding] | None = None
        self._stats: PipfileStats | None = None
        self._infos: list[PipfileInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Pipenv configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_pipfile(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[PipfileFinding], PipfileInfo]:
        findings: list[PipfileFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, PipfileInfo(path=rel)

        raw_lines = text.splitlines()
        info = PipfileInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_packages = False

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if stripped.startswith("[") and stripped.endswith("]"):
                section = stripped.lower()
                in_packages = section in ("[packages]", "[dev-packages]")

            source_match = SOURCE_URL_PATTERN.search(stripped)
            if source_match:
                info.sources.append(source_match.group(1))

            if in_packages:
                dep_match = re.match(r"^([a-zA-Z0-9_.-]+)\s*=", stripped)
                if dep_match:
                    info.dependencies.append(dep_match.group(1))

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    PipfileFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Pipenv config — use PIPENV_PYPI_MIRROR or CI secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PYPI_TOKEN_PATTERN.search(line):
                findings.append(
                    PipfileFinding(
                        kind="pypi_token",
                        severity="high",
                        message="PyPI token in Pipenv config — use environment variables or CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    PipfileFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in Pipenv config — use credential helpers or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    PipfileFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL — use HTTPS for PyPI indexes and direct URL deps",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SCM_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    PipfileFinding(
                        kind="scm_credentials",
                        severity="high",
                        message="credentials embedded in VCS URL — use token env vars or SSH keys",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DYNAMIC_VERSION_PATTERN.search(stripped) and in_packages:
                findings.append(
                    PipfileFinding(
                        kind="dynamic_version",
                        severity="medium",
                        message="loose version constraint — pin dependencies and commit Pipfile.lock",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if GIT_DEP_UNPINNED_PATTERN.search(line):
                findings.append(
                    PipfileFinding(
                        kind="unpinned_git_dep",
                        severity="medium",
                        message="git dependency pinned to moving branch — pin to tag or commit SHA",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_SSL_PATTERN.search(line):
                findings.append(
                    PipfileFinding(
                        kind="insecure_ssl",
                        severity="high",
                        message="SSL/TLS verification disabled — keep verify_ssl enabled for remote indexes",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    PipfileFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — vendor scripts with checksum verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SENSITIVE_PATH_PATTERN.search(line):
                findings.append(
                    PipfileFinding(
                        kind="sensitive_path",
                        severity="high",
                        message="sensitive host path reference — avoid bundling credentials in builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if path.name == "Pipfile":
            lock_path = path.parent / "Pipfile.lock"
            if not lock_path.exists():
                findings.append(
                    PipfileFinding(
                        kind="missing_lockfile",
                        severity="low",
                        message="Pipfile.lock missing — commit lockfile for reproducible installs",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[PipfileFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PipfileFinding] = []
        infos: list[PipfileInfo] = []
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
        self._stats = PipfileStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> PipfileStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[PipfileInfo]:
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
        """Scaffold a hardened Pipfile snippet with secure defaults."""
        return """\
# Pipfile — hardened defaults for Pipenv projects
[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
# Pin versions explicitly, e.g. requests = "==2.31.0"
# Use git deps with ref = "<commit-sha>" not branch = "main"

[dev-packages]
# pytest = "==8.0.0"

[requires]
python_version = "3.10"

# Store credentials via environment variables or pipenv config:
#   export PIPENV_PYPI_MIRROR=https://pypi.org/simple
# Never commit tokens in Pipfile or Pipfile.lock
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Pipenv configs: none found"
        return (
            f"Pipenv configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Pipenv analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            deps = ", ".join(info.dependencies[:8]) if info.dependencies else "none"
            sources = ", ".join(info.sources[:8]) if info.sources else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.dependencies)} dependency(ies), {len(info.sources)} source(s)"
            )
            lines.append(f"    dependencies: {deps}")
            lines.append(f"    sources: {sources}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
