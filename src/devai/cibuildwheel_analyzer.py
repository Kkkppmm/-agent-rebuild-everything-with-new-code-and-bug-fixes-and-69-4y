"""CibuildwheelAnalyzer — audit cibuildwheel pyproject.toml config for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CIBW_PYPROJECT_NAMES = ("pyproject.toml",)
CIBW_CONFIG_NAMES = ("cibuildwheel.toml",)
CIBW_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.cibuildwheel\]|^\[tool\.cibuildwheel\.|cibuildwheel|"
    r"CIBW_|before-build|after-build|repair-command|test-command)",
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
    r"trusted-host\s*=|allow-insecure-host)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
DANGEROUS_SCRIPT_PATTERN = re.compile(
    r"(before-build|after-build|repair-command|test-command|"
    r"before-all|after-all|build-frontend)\s*=\s*",
    re.IGNORECASE,
)
INSECURE_ENV_VAR_PATTERN = re.compile(
    r"(?:CIBW_ENVIRONMENT|CIBW_BEFORE_BUILD|CIBW_AFTER_BUILD|"
    r"CIBW_TEST_COMMAND|TWINE_PASSWORD|TWINE_USERNAME)\s*[=:]\s*"
    r"[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
UNPINNED_GIT_PATTERN = re.compile(
    r"(?:git|rev|branch|tag)\s*=\s*[\"'](?:main|master|HEAD|develop)[\"']|"
    r"@(?:main|master|HEAD|develop)\b",
    re.IGNORECASE,
)
SKIP_TESTS_PATTERN = re.compile(
    r"(?:test-skip|CIBW_TEST_SKIP)\s*[=:]\s*[\"']?\*[\"']?",
    re.IGNORECASE,
)
DISABLED_AUDITWHEEL_PATTERN = re.compile(
    r"(?:repair-command|CIBW_REPAIR_WHEEL_COMMAND)\s*[=:]\s*[\"']?\s*[\"']?",
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
    hooks: list[str] = field(default_factory=list)


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
    name = path.name
    if name in CIBW_CONFIG_NAMES:
        return True
    if name in CIBW_PYPROJECT_NAMES:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            if CIBW_MARKER_PATTERN.search(head):
                return True
        except OSError:
            pass
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "pyproject.toml":
        return "pyproject"
    if name == "cibuildwheel.toml":
        return "cibuildwheel_config"
    return "unknown"


class CibuildwheelAnalyzer:
    """Audit cibuildwheel configuration for security issues.

    Scans pyproject.toml (with [tool.cibuildwheel]) and cibuildwheel.toml for
    hardcoded PyPI tokens, insecure HTTP URLs, credentials in git/source URLs,
    curl-pipe-to-shell in build hooks, disabled auditwheel repair, skipped
    tests, and secrets in CIBW_* environment variables.
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
                r"^\[tool\.cibuildwheel\.([^\]]+)\]", stripped, re.IGNORECASE
            )
            if platform_match:
                info.platforms.append(platform_match.group(1))

            hook_match = DANGEROUS_SCRIPT_PATTERN.search(stripped)
            if hook_match:
                info.hooks.append(hook_match.group(1).lower().replace("-", "_"))

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in cibuildwheel config — use CI secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PYPI_TOKEN_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="pypi_token",
                        severity="high",
                        message="PyPI token in cibuildwheel config — use TWINE_* env vars or CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in cibuildwheel config — use credential helpers",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_ENV_VAR_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="build_env_secret",
                        severity="high",
                        message="secrets in CIBW_* environment — inject via CI secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL — use HTTPS for wheel indexes and downloads",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SCM_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="scm_credentials",
                        severity="high",
                        message="credentials embedded in repository URL — use token env vars or SSH keys",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in cibuildwheel hook — vendor scripts with checksum verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_SSL_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="insecure_ssl",
                        severity="high",
                        message="SSL/TLS verification disabled — keep certificate validation enabled",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SENSITIVE_PATH_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="sensitive_path",
                        severity="high",
                        message="sensitive host path reference — avoid bundling credentials in wheel builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNPINNED_GIT_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="unpinned_git_dep",
                        severity="medium",
                        message="git dependency pinned to moving branch — pin to tag or commit SHA",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SKIP_TESTS_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="skip_all_tests",
                        severity="medium",
                        message="all wheel tests skipped — run platform-specific tests before publishing",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DISABLED_AUDITWHEEL_PATTERN.search(line) and "auditwheel" not in line.lower():
                findings.append(
                    CibuildwheelFinding(
                        kind="disabled_repair",
                        severity="medium",
                        message="auditwheel repair disabled — keep repair-command for manylinux compliance",
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
        """Scaffold a hardened cibuildwheel pyproject.toml snippet."""
        return """\
# pyproject.toml — hardened cibuildwheel defaults
[tool.cibuildwheel]
# Pin build/test dependencies; never curl-pipe-to-shell in hooks
test-command = "pytest {project}/tests"
# Keep auditwheel repair enabled for manylinux wheels
# repair-command = "auditwheel repair -w {dest_dir} {wheel}"

[tool.cibuildwheel.linux]
# Use manylinux images from PyPA; store secrets via CI, not CIBW_ENVIRONMENT

[tool.cibuildwheel.macos]
# Sign wheels with notary credentials from CI secret stores
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
            hooks = ", ".join(info.hooks[:8]) if info.hooks else "none"
            lines.append(f"  - {info.path} ({info.file_kind}): platforms={platforms}, hooks={hooks}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
