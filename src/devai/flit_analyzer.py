"""FlitAnalyzer — audit Flit pyproject.toml and flit.ini for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

FLIT_STANDALONE_NAMES = ("flit.ini",)

FLIT_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.flit\]|^\[tool\.flit\.|flit_core)",
    re.IGNORECASE | re.MULTILINE,
)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|pypi[_-]?token|http-basic)\s*[=:]\s*"
    r"[\"']?[^\"\'\s${}][^\"\'<]*[\"']?",
    re.IGNORECASE,
)
PYPI_TOKEN_PATTERN = re.compile(r"[\"']?pypi-[A-Za-z0-9_-]{20,}[\"']?", re.IGNORECASE)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"\'<>]+",
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
    r"(?:git|rev|branch|tag)\s*=\s*[\"'](?:main|master|HEAD|develop)[\"']|"
    r"@(?:main|master|HEAD|develop)\b",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:cert\s*=\s*false|disable[_-]?ssl|ssl[_-]?verify\s*=\s*false|"
    r"verify[_-]?ssl\s*=\s*false|trusted-host\s*=|cert\s*=\s*/dev/null|allow-insecure-host)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
INDEX_URL_PATTERN = re.compile(
    r"(?:index-url|extra-index-url|url)\s*=\s*[\"']?(\S+)[\"']?",
    re.IGNORECASE,
)



@dataclass
class FlitFinding:
    """A security or best-practice issue in a Flit configuration file."""

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
class FlitInfo:
    """Parsed metadata about a Flit configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    dependencies: list[str] = field(default_factory=list)
    index_urls: list[str] = field(default_factory=list)


@dataclass
class FlitStats:
    """Aggregate Flit analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_flit_file(path: Path) -> bool:
    """Return True if the path looks like a Flit configuration file."""
    name = path.name
    if name in FLIT_STANDALONE_NAMES:
        return True
    if name == "pyproject.toml":
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            if FLIT_MARKER_PATTERN.search(head):
                return True
        except OSError:
            pass
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "flit.ini":
        return "flit_ini"
    if name == "pyproject.toml":
        return "pyproject"
    return "unknown"


class FlitAnalyzer:
    """Audit Flit configuration for security issues.

    Scans configuration files for hardcoded PyPI tokens, insecure HTTP index URLs,
    credentials in git/source URLs, unpinned git dependencies, loose version constraints,
    trusted-host bypasses, and disabled SSL verification.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[FlitFinding] | None = None
        self._stats: FlitStats | None = None
        self._infos: list[FlitInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Flit configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_flit_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[FlitFinding], FlitInfo]:
        findings: list[FlitFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, FlitInfo(path=rel)

        raw_lines = text.splitlines()
        info = FlitInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            index_match = INDEX_URL_PATTERN.search(stripped)
            if index_match:
                info.index_urls.append(index_match.group(1))

            dep_match = re.search(
                r"^([a-zA-Z0-9_.-]+)\s*=\s*(?:\{|[\"'])",
                stripped,
            )
            if dep_match and not stripped.startswith("["):
                dep_name = dep_match.group(1)
                if dep_name not in ("name", "version", "description", "authors", "license"):
                    info.dependencies.append(dep_name)

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    FlitFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Flit config — use CI secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PYPI_TOKEN_PATTERN.search(line):
                findings.append(
                    FlitFinding(
                        kind="pypi_token",
                        severity="high",
                        message="PyPI token in Flit config — use environment variables or keyring",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    FlitFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in Flit config — use credential helpers or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    FlitFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL — use HTTPS for package indexes and custom sources",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SCM_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    FlitFinding(
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
                    re.search(r"(?:requires|dependencies)", stripped, re.IGNORECASE)
                    or ("=" in stripped and not stripped.startswith("["))
                )
            ):
                findings.append(
                    FlitFinding(
                        kind="dynamic_version",
                        severity="medium",
                        message="loose version constraint — pin dependencies and commit lockfiles",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if GIT_DEP_UNPINNED_PATTERN.search(line):
                findings.append(
                    FlitFinding(
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
                    FlitFinding(
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
                    FlitFinding(
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
                    FlitFinding(
                        kind="sensitive_path",
                        severity="high",
                        message="sensitive host path reference — avoid bundling credentials in builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        return findings, info

    def analyze(self) -> list[FlitFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[FlitFinding] = []
        infos: list[FlitInfo] = []
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
        self._stats = FlitStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> FlitStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[FlitInfo]:
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
        """Scaffold a hardened config snippet with secure defaults."""
        return """# flit.ini — hardened Flit defaults (legacy)
[metadata]
# Prefer pyproject.toml [tool.flit.metadata] for new projects

[sdist]
# Exclude secrets and local config from source distributions
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Flit configs: none found"
        return (
            f"Flit configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Flit analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            deps = ", ".join(info.dependencies[:8]) if info.dependencies else "none"
            indexes = ", ".join(info.index_urls[:8]) if info.index_urls else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.dependencies)} dependency(ies), {len(info.index_urls)} index URL(s)"
            )
            lines.append(f"    dependencies: {deps}")
            lines.append(f"    index URLs: {indexes}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
