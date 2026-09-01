"""CibuildwheelAnalyzer — audit cibuildwheel pyproject.toml for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CIBUILDWHEEL_PYPROJECT_NAMES = ("pyproject.toml",)
CIBUILDWHEEL_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.cibuildwheel\]|^\[tool\.cibuildwheel\.|"
    r"cibuildwheel\s*=\s*\{)",
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
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:cert\s*=\s*false|disable[_-]?ssl|ssl[_-]?verify\s*=\s*false|"
    r"trusted-host\s*=|allow-insecure-host|CURL_CA_BUNDLE\s*=\s*[\"']?[\"']?)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
SHELL_INJECTION_PATTERN = re.compile(
    r"(?:test-command|before-all|before-build|repair-wheel-command|"
    r"environment-pass|environment)\s*=\s*[\"'][^\"']*(?:;|\$\(|`|\|\s*sh\b)",
    re.IGNORECASE,
)
UNPINNED_IMAGE_PATTERN = re.compile(
    r"(?:manylinux-x86_64-image|manylinux-i686-image|musllinux-.*-image)\s*=\s*"
    r"[\"'][^\"']*:latest[\"']",
    re.IGNORECASE,
)
CIBW_ENV_SECRET_PATTERN = re.compile(
    r"(?:CIBW_ENVIRONMENT|CIBW_BEFORE_ALL|CIBW_BEFORE_BUILD|CIBW_TEST_COMMAND)\s*=\s*"
    r"[\"'][^\"']*(?:password|secret|token|key)[^\"']*[\"']",
    re.IGNORECASE,
)
SKIP_REPAIR_PATTERN = re.compile(
    r"(?:repair-wheel-command|CIBW_REPAIR_WHEEL_COMMAND)\s*=\s*[\"']?[\"']?",
    re.IGNORECASE,
)


@dataclass
class CibuildwheelFinding:
    """A security or best-practice issue in a cibuildwheel configuration file."""

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
class CibuildwheelInfo:
    """Parsed metadata about a cibuildwheel configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    platforms: list[str] = field(default_factory=list)
    env_vars: list[str] = field(default_factory=list)


@dataclass
class CibuildwheelStats:
    """Aggregate cibuildwheel analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_cibuildwheel_file(path: Path) -> bool:
    """Return True if the path looks like a cibuildwheel configuration file."""
    if path.name not in CIBUILDWHEEL_PYPROJECT_NAMES:
        return False
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:8192]
        return bool(CIBUILDWHEEL_MARKER_PATTERN.search(head))
    except OSError:
        return False


def _file_kind(path: Path) -> str:
    return "pyproject" if path.name == "pyproject.toml" else "unknown"


class CibuildwheelAnalyzer:
    """Audit cibuildwheel configuration for security issues.

    Scans pyproject.toml with [tool.cibuildwheel] for hardcoded secrets in
    CIBW_* environment variables, shell injection in test/build hooks,
    curl-pipe-to-shell in before-all scripts, insecure HTTP URLs, unpinned
    manylinux images, and disabled wheel repair.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CibuildwheelFinding] | None = None
        self._stats: CibuildwheelStats | None = None
        self._infos: list[CibuildwheelInfo] | None = None

    def configs(self) -> list[Path]:
        """Return cibuildwheel configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_cibuildwheel_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[CibuildwheelFinding], CibuildwheelInfo]:
        findings: list[CibuildwheelFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, CibuildwheelInfo(path=rel)

        raw_lines = text.splitlines()
        info = CibuildwheelInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            platform_match = re.match(
                r"^\[tool\.cibuildwheel\.([^\]]+)\]",
                stripped,
                re.IGNORECASE,
            )
            if platform_match:
                info.platforms.append(platform_match.group(1))

            env_match = re.search(
                r"(?:CIBW_[A-Z0-9_]+|environment)\s*=\s*[\"']([^\"']+)[\"']",
                stripped,
                re.IGNORECASE,
            )
            if env_match:
                info.env_vars.append(env_match.group(1)[:80])

            checks: list[tuple[str, str, str, re.Pattern[str]]] = [
                ("hardcoded_secret", "high", "hardcoded secret in cibuildwheel config — use CI secret stores", HARDCODED_SECRET_PATTERN),
                ("pypi_token", "high", "PyPI token in cibuildwheel config — use CI secrets", PYPI_TOKEN_PATTERN),
                ("aws_access_key", "high", "AWS access key in cibuildwheel config — use credential helpers", AWS_ACCESS_KEY_PATTERN),
                ("cibw_env_secret", "high", "secret embedded in CIBW_* environment — use GitHub/GitLab secrets", CIBW_ENV_SECRET_PATTERN),
                ("scm_credentials", "high", "credentials embedded in repository URL — use token env vars", SCM_CREDENTIALS_PATTERN),
                ("curl_pipe_shell", "high", "curl/wget piped to shell in cibuildwheel hook — vendor scripts with checksums", CURL_PIPE_SHELL_PATTERN),
                ("insecure_ssl", "high", "SSL/TLS verification disabled in cibuildwheel config", INSECURE_SSL_PATTERN),
                ("sensitive_path", "high", "sensitive host path reference in cibuildwheel config", SENSITIVE_PATH_PATTERN),
                ("insecure_http", "medium", "insecure HTTP URL — use HTTPS for package indexes and downloads", INSECURE_HTTP_PATTERN),
                ("shell_injection", "high", "shell metacharacters in cibuildwheel command — avoid injection risks", SHELL_INJECTION_PATTERN),
                ("unpinned_image", "medium", "manylinux image pinned to :latest — pin to a specific digest or tag", UNPINNED_IMAGE_PATTERN),
                ("skip_repair", "low", "wheel repair disabled — auditwheel/audit may be skipped on Linux wheels", SKIP_REPAIR_PATTERN),
            ]
            for kind, severity, message, pattern in checks:
                if pattern.search(line):
                    findings.append(
                        CibuildwheelFinding(
                            kind=kind,
                            severity=severity,
                            message=message,
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

        return findings, info

    def analyze(self) -> list[CibuildwheelFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CibuildwheelFinding] = []
        infos: list[CibuildwheelInfo] = []
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
        self._stats = CibuildwheelStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CibuildwheelStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CibuildwheelInfo]:
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
        """Scaffold a hardened [tool.cibuildwheel] snippet with secure defaults."""
        return """\
# pyproject.toml — hardened cibuildwheel defaults
[tool.cibuildwheel]
# Pin manylinux images; avoid :latest tags
# manylinux-x86_64-image = "quay.io/pypa/manylinux2014_x86_64:2024.01.01-1"

# Store secrets via CI (CIBW_ENVIRONMENT in workflow secrets), never in pyproject.toml
# test-command = "pytest {project}/tests"
# before-all = ""  # avoid curl | sh; vendor scripts with checksum verification
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "cibuildwheel configs: none found"
        return (
            f"cibuildwheel configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "cibuildwheel analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            platforms = ", ".join(info.platforms[:8]) if info.platforms else "default"
            lines.append(f"  - {info.path} ({info.file_kind}): platforms={platforms}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
