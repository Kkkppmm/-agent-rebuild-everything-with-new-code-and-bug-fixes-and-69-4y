"""PoetryAnalyzer — audit Poetry pyproject.toml and poetry.toml for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

POETRY_PYPROJECT_NAMES = ("pyproject.toml",)
POETRY_CONFIG_NAMES = ("poetry.toml",)
POETRY_LOCK_NAMES = ("poetry.lock",)
POETRY_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.poetry\]|^\[tool\.poetry\.|^\[tool\.poetry\.source|"
    r"^\[tool\.poetry\.group\.|poetry-core|poetry\s*=\s*\{)",
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
    r"=\s*[\"'](?:\*|latest|LATEST)[\"']|"
    r"=\s*\{[^}]*version\s*=\s*[\"'](?:\*|latest|LATEST)[\"']|"
    r"(?:>=|<=|>|<)\s*[\"']?\d",
    re.IGNORECASE,
)
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:git|rev|branch|tag)\s*=\s*[\"'](?:main|master|HEAD|develop)[\"']",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:cert\s*=\s*false|disable[_-]?ssl|ssl[_-]?verify\s*=\s*false|"
    r"insecureSkipTlsVerify|trustAllCertificates)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
PRIORITY_INSECURE_SOURCE_PATTERN = re.compile(
    r"priority\s*=\s*[\"']?(?:primary|explicit)[\"']?",
    re.IGNORECASE,
)
SCRIPTS_SHELL_PATTERN = re.compile(
    r"^\s*\[tool\.poetry\.scripts\]|^\s*\[project\.scripts\]",
    re.IGNORECASE,
)


@dataclass
class PoetryFinding:
    """A security or best-practice issue in a Poetry configuration file."""

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
class PoetryInfo:
    """Parsed metadata about a Poetry configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    dependencies: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)


@dataclass
class PoetryStats:
    """Aggregate Poetry analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_poetry_file(path: Path) -> bool:
    """Return True if the path looks like a Poetry configuration file."""
    name = path.name
    if name in POETRY_CONFIG_NAMES:
        return True
    if name in POETRY_PYPROJECT_NAMES:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            if POETRY_MARKER_PATTERN.search(head):
                return True
        except OSError:
            pass
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "pyproject.toml":
        return "pyproject"
    if name == "poetry.toml":
        return "poetry_config"
    if name == "poetry.lock":
        return "lock"
    return "unknown"


class PoetryAnalyzer:
    """Audit Poetry configuration for security issues.

    Scans pyproject.toml (with [tool.poetry]), poetry.toml, and related files
    for hardcoded PyPI tokens, insecure HTTP repository URLs, credentials in
    git/source URLs, unpinned git dependencies, dynamic version constraints,
    curl-pipe-to-shell in scripts, and disabled SSL verification.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PoetryFinding] | None = None
        self._stats: PoetryStats | None = None
        self._infos: list[PoetryInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Poetry configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_poetry_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[PoetryFinding], PoetryInfo]:
        findings: list[PoetryFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, PoetryInfo(path=rel)

        raw_lines = text.splitlines()
        info = PoetryInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_scripts_section = False

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if SCRIPTS_SHELL_PATTERN.search(stripped):
                in_scripts_section = True
            elif stripped.startswith("[") and not SCRIPTS_SHELL_PATTERN.search(stripped):
                in_scripts_section = False

            dep_match = re.search(
                r"^([a-zA-Z0-9_.-]+)\s*=\s*(?:\{|[\"'])",
                stripped,
            )
            if dep_match and not stripped.startswith("["):
                dep_name = dep_match.group(1)
                if dep_name not in ("name", "version", "description", "authors", "license"):
                    info.dependencies.append(dep_name)

            source_match = re.search(r"^\[\[tool\.poetry\.source\]\]|^\[tool\.poetry\.source\.", stripped)
            if source_match:
                name_match = re.search(r"name\s*=\s*[\"']([^\"']+)[\"']", stripped)
                if name_match:
                    info.sources.append(name_match.group(1))

            url_match = re.search(r"url\s*=\s*[\"']([^\"']+)[\"']", stripped)
            if url_match and "source" in stripped.lower():
                info.sources.append(url_match.group(1))

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    PoetryFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Poetry config — use poetry config http-basic or CI secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PYPI_TOKEN_PATTERN.search(line):
                findings.append(
                    PoetryFinding(
                        kind="pypi_token",
                        severity="high",
                        message="PyPI token in Poetry config — use POETRY_HTTP_BASIC_* env vars or keyring",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    PoetryFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in Poetry config — use credential helpers or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    PoetryFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL — use HTTPS for PyPI mirrors and custom sources",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SCM_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    PoetryFinding(
                        kind="scm_credentials",
                        severity="high",
                        message="credentials embedded in repository URL — use token env vars or SSH keys",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if (
                DYNAMIC_VERSION_PATTERN.search(stripped)
                and not re.match(r"python\s*=", stripped, re.IGNORECASE)
                and (
                    re.search(r"(?:dependencies|dev-dependencies|group)", stripped, re.IGNORECASE)
                    or ("=" in stripped and not stripped.startswith("["))
                )
            ):
                findings.append(
                    PoetryFinding(
                        kind="dynamic_version",
                        severity="medium",
                        message="loose version constraint — pin dependencies and commit poetry.lock",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if GIT_DEP_UNPINNED_PATTERN.search(line):
                findings.append(
                    PoetryFinding(
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
                    PoetryFinding(
                        kind="insecure_ssl",
                        severity="high",
                        message="SSL/TLS verification disabled — keep certificate validation enabled",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    PoetryFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in Poetry config — vendor scripts with checksum verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if in_scripts_section and CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    PoetryFinding(
                        kind="unsafe_script",
                        severity="high",
                        message="Poetry script runs curl-pipe-to-shell — avoid remote script execution",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SENSITIVE_PATH_PATTERN.search(line):
                findings.append(
                    PoetryFinding(
                        kind="sensitive_path",
                        severity="high",
                        message="sensitive host path reference — avoid bundling credentials in builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if (
                "url" in stripped.lower()
                and INSECURE_HTTP_PATTERN.search(line)
                and PRIORITY_INSECURE_SOURCE_PATTERN.search(text)
            ):
                findings.append(
                    PoetryFinding(
                        kind="insecure_primary_source",
                        severity="medium",
                        message="custom source over HTTP with primary priority — use HTTPS mirrors",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        lock_path = path.parent / "poetry.lock"
        if path.name == "pyproject.toml" and not lock_path.exists():
            findings.append(
                PoetryFinding(
                    kind="missing_lockfile",
                    severity="low",
                    message="poetry.lock missing — commit lockfile for reproducible installs",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[PoetryFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PoetryFinding] = []
        infos: list[PoetryInfo] = []
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
        self._stats = PoetryStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> PoetryStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[PoetryInfo]:
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
        """Scaffold a hardened poetry.toml snippet with secure defaults."""
        return """\
# poetry.toml — hardened defaults for Poetry projects
[virtualenvs]
in-project = true
create = true

[repositories]
# Use HTTPS PyPI mirrors only; store credentials via:
#   poetry config http-basic.<name> <username> <token>
# Never commit tokens in pyproject.toml or poetry.toml

[http-basic]
# Configure via `poetry config` or CI secret stores — do not commit here
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Poetry configs: none found"
        return (
            f"Poetry configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Poetry analysis:",
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
