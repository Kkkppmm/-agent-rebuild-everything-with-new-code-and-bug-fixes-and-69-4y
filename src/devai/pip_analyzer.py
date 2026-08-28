"""PipAnalyzer — audit pip requirements files and pip.conf for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PIP_REQUIREMENTS_NAMES = (
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "requirements-prod.txt",
    "dev-requirements.txt",
    "test-requirements.txt",
    "prod-requirements.txt",
    "constraints.txt",
    "constraints-dev.txt",
)
PIP_CONFIG_NAMES = ("pip.conf", "pip.ini")
REQUIREMENTS_SUFFIX_PATTERN = re.compile(r"^requirements(?:[-_.][\w.-]+)?\.txt$", re.IGNORECASE)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|pypi[_-]?token)\s*[=:]\s*"
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
    r"(?:==\s*[\"']?\*[\"']?|[=<>!~]+\s*[\"']?\*[\"']?|"
    r"[=<>!~]+\s*[\"']?latest[\"']?|"
    r"(?<![=<>!~])>=\s*[\"']?\d|(?<![=<>!~])<=\s*[\"']?\d|"
    r"(?<![=<>!~])>\s*[\"']?\d|(?<![=<>!~])<\s*[\"']?\d)",
    re.IGNORECASE,
)
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:@main\b|@master\b|@HEAD\b|@develop\b|#egg=[^&]+@main\b|branch=main\b|branch=master\b)",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
TRUSTED_HOST_PATTERN = re.compile(
    r"(?:--trusted-host|trusted-host)\s*=\s*([^\s#]+)",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:cert\s*=\s*false|disable[_-]?ssl|ssl[_-]?verify\s*=\s*false|"
    r"trusted-host\s*=|cert\s*=\s*/dev/null)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
INDEX_URL_PATTERN = re.compile(
    r"(?:--index-url|--extra-index-url|index-url|extra-index-url)\s*[= ]?\s*(\S+)",
    re.IGNORECASE,
)
UNPINNED_REQUIREMENT_PATTERN = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9._-]*(?:\[[^\]]+\])?\s*$",
)


@dataclass
class PipFinding:
    """A security or best-practice issue in a pip configuration file."""

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
class PipInfo:
    """Parsed metadata about a pip configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    dependencies: list[str] = field(default_factory=list)
    index_urls: list[str] = field(default_factory=list)


@dataclass
class PipStats:
    """Aggregate pip analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_pip_file(path: Path) -> bool:
    """Return True if the path looks like a pip requirements or config file."""
    name = path.name.lower()
    if name in PIP_CONFIG_NAMES:
        return True
    if name in PIP_REQUIREMENTS_NAMES:
        return True
    if REQUIREMENTS_SUFFIX_PATTERN.match(path.name):
        return True
    return False


def _file_kind(path: Path) -> str:
    name = path.name.lower()
    if name.startswith("constraints"):
        return "constraints"
    if "requirements" in name:
        return "requirements"
    if name in PIP_CONFIG_NAMES:
        return "pip_config"
    return "unknown"


class PipAnalyzer:
    """Audit pip requirements and pip.conf for security issues.

    Scans requirements.txt, constraints.txt, and pip.conf/pip.ini for hardcoded
    PyPI tokens, insecure HTTP index URLs, credentials in git/source URLs,
    unpinned git dependencies, loose version constraints, trusted-host bypasses,
    and curl-pipe-to-shell patterns.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PipFinding] | None = None
        self._stats: PipStats | None = None
        self._infos: list[PipInfo] | None = None

    def configs(self) -> list[Path]:
        """Return pip configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_pip_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[PipFinding], PipInfo]:
        findings: list[PipFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, PipInfo(path=rel)

        raw_lines = text.splitlines()
        info = PipInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            index_match = INDEX_URL_PATTERN.search(stripped)
            if index_match:
                info.index_urls.append(index_match.group(1))

            dep_match = re.match(
                r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)(?:\[[^\]]+\])?(?:\s*[=<>!~]+|\s*$)",
                stripped,
            )
            if dep_match and not stripped.startswith("-"):
                dep_name = dep_match.group(1)
                if dep_name.lower() not in ("index-url", "extra-index-url", "trusted-host"):
                    info.dependencies.append(dep_name)

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    PipFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in pip config — use PIP_INDEX_URL env vars or CI secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PYPI_TOKEN_PATTERN.search(line):
                findings.append(
                    PipFinding(
                        kind="pypi_token",
                        severity="high",
                        message="PyPI token in pip config — use PIP_EXTRA_INDEX_URL or CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    PipFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in pip config — use credential helpers or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    PipFinding(
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
                    PipFinding(
                        kind="scm_credentials",
                        severity="high",
                        message="credentials embedded in VCS URL — use token env vars or SSH keys",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if (
                DYNAMIC_VERSION_PATTERN.search(stripped)
                and not stripped.startswith("-")
                and not stripped.lower().startswith("python")
            ):
                findings.append(
                    PipFinding(
                        kind="dynamic_version",
                        severity="medium",
                        message="loose version constraint — pin with == and maintain constraints.txt",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNPINNED_REQUIREMENT_PATTERN.match(stripped) and info.file_kind == "requirements":
                findings.append(
                    PipFinding(
                        kind="unpinned_dependency",
                        severity="low",
                        message="unpinned dependency — pin versions for reproducible installs",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if GIT_DEP_UNPINNED_PATTERN.search(line):
                findings.append(
                    PipFinding(
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
                    PipFinding(
                        kind="insecure_ssl",
                        severity="high",
                        message="SSL/TLS verification disabled or trusted-host bypass — keep certificate validation enabled",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            trusted_match = TRUSTED_HOST_PATTERN.search(stripped)
            if trusted_match:
                host = trusted_match.group(1)
                if host not in ("localhost", "127.0.0.1"):
                    findings.append(
                        PipFinding(
                            kind="trusted_host",
                            severity="medium",
                            message="trusted-host bypass — avoid disabling TLS verification for remote hosts",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    PipFinding(
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
                    PipFinding(
                        kind="sensitive_path",
                        severity="high",
                        message="sensitive host path reference — avoid bundling credentials in builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if stripped.startswith("-e ") and SENSITIVE_PATH_PATTERN.search(stripped):
                findings.append(
                    PipFinding(
                        kind="editable_sensitive_path",
                        severity="medium",
                        message="editable install from sensitive path — avoid local credential directories",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if info.file_kind == "requirements" and not any(
            p.name.startswith("constraints") for p in path.parent.glob("constraints*.txt")
        ):
            findings.append(
                PipFinding(
                    kind="missing_constraints",
                    severity="low",
                    message="constraints.txt missing — add constraints file for reproducible pip installs",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[PipFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PipFinding] = []
        infos: list[PipInfo] = []
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
        self._stats = PipStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> PipStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[PipInfo]:
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
        """Scaffold a hardened pip.conf snippet with secure defaults."""
        return """\
# pip.conf — hardened defaults for pip projects
[global]
# Use HTTPS PyPI only; store credentials via environment variables:
#   export PIP_INDEX_URL=https://pypi.org/simple
#   export PIP_EXTRA_INDEX_URL=https://user:token@private.pypi.example/simple
# Never commit tokens in requirements.txt or pip.conf

# Pin dependencies in requirements.txt with ==
# Maintain constraints.txt for reproducible CI installs
# Avoid --trusted-host except for local development on localhost
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Pip configs: none found"
        return (
            f"Pip configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Pip analysis:",
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
