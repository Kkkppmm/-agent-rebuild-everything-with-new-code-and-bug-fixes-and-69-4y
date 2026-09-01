"""CibuildwheelAnalyzer — audit cibuildwheel pyproject.toml and cibuildwheel.toml configs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CIBUILDWHEEL_PYPROJECT_NAMES = ("pyproject.toml",)
CIBUILDWHEEL_CONFIG_NAMES = ("cibuildwheel.toml",)
CIBUILDWHEEL_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.cibuildwheel\]|^\[tool\.cibuildwheel\.|"
    r"^\[\[tool\.cibuildwheel\.|cibuildwheel|CIBW_)",
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
    r"(?:>=|<=|>|<)\s*[\"']?\d|"
    r"[a-zA-Z0-9_.-]+\s*=\s*\*",
    re.IGNORECASE,
)
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:git|rev|branch|tag|ref)\s*=\s*[\"'](?:main|master|HEAD|develop)[\"']|"
    r"@(?:main|master|HEAD|develop)\b",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:cert\s*=\s*false|disable[_-]?ssl|ssl[_-]?verify\s*=\s*false|"
    r"trusted-host\s*=|allow-insecure-host|PIP_TRUSTED_HOST)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
INDEX_URL_PATTERN = re.compile(
    r"(?:index-url|extra-index-url|url|repo)\s*=\s*[\"']?(\S+)[\"']?",
    re.IGNORECASE,
)
TRUSTED_HOST_PATTERN = re.compile(
    r"(?:--trusted-host|trusted-host|PIP_TRUSTED_HOST)\s*[= ]?\s*([^\s#]+)",
    re.IGNORECASE,
)
DANGEROUS_SCRIPT_PATTERN = re.compile(
    r"(before-all|before-build|before-test|test-command|repair-wheel-command|"
    r"build-frontend|environment-pass)\s*[=:]",
    re.IGNORECASE,
)
INSECURE_ENV_VAR_PATTERN = re.compile(
    r"(?:CIBW_ENVIRONMENT|CIBW_BEFORE_BUILD|CIBW_BEFORE_ALL|CIBW_TEST_COMMAND|"
    r"CIBW_REPAIR_WHEEL_COMMAND|TWINE_PASSWORD|TWINE_USERNAME|PYPI_TOKEN|"
    r"CIBW_PYPI_TOKEN)\s*=\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
SENSITIVE_ENV_PASS_PATTERN = re.compile(
    r"(?:environment-pass|CIBW_ENVIRONMENT_PASS)\s*=\s*\[.*"
    r"(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)",
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
    index_urls: list[str] = field(default_factory=list)
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
    if name in CIBUILDWHEEL_CONFIG_NAMES:
        return True
    if name in CIBUILDWHEEL_PYPROJECT_NAMES:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            if CIBUILDWHEEL_MARKER_PATTERN.search(head):
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

    Scans pyproject.toml (with [tool.cibuildwheel]), cibuildwheel.toml, and
  related files for hardcoded PyPI tokens, insecure HTTP repository URLs,
    credentials in git/source URLs, unpinned git dependencies, dynamic version
    constraints, curl-pipe-to-shell in build hooks, disabled SSL verification,
    and sensitive environment variables passed into wheel builds.
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

            hook_match = DANGEROUS_SCRIPT_PATTERN.search(stripped)
            if hook_match:
                info.hooks.append(hook_match.group(1).lower())

            index_match = INDEX_URL_PATTERN.search(stripped)
            if index_match:
                info.index_urls.append(index_match.group(1))

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
                        message="PyPI token in cibuildwheel config — use CIBW_PYPI_TOKEN env var",
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
                        kind="publish_credential",
                        severity="high",
                        message="publish/build credentials in config — use CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SENSITIVE_ENV_PASS_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="sensitive_env_pass",
                        severity="high",
                        message="sensitive env var passed into wheel build — avoid leaking secrets to wheels",
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
                        message="insecure HTTP URL — use HTTPS for PyPI indexes and custom sources",
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

            if (
                DYNAMIC_VERSION_PATTERN.search(stripped)
                and not re.match(r"python\s*=", stripped, re.IGNORECASE)
                and (
                    re.search(
                        r"(?:dependency-versions|requirements|pip-args|before-build|before-all)",
                        stripped,
                        re.IGNORECASE,
                    )
                    or ("=" in stripped and not stripped.startswith("["))
                )
            ):
                findings.append(
                    CibuildwheelFinding(
                        kind="dynamic_version",
                        severity="medium",
                        message="loose version constraint — pin dependencies for reproducible wheel builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if GIT_DEP_UNPINNED_PATTERN.search(line):
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

            if TRUSTED_HOST_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="trusted_host",
                        severity="medium",
                        message="trusted-host bypass — avoid disabling TLS hostname verification",
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
                        message="curl/wget piped to shell in build hook — vendor scripts with checksum verification",
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
        """Scaffold a hardened cibuildwheel.toml snippet with secure defaults."""
        return """\
# cibuildwheel.toml — hardened defaults for wheel builds
[tool.cibuildwheel]
# Pin build dependencies in pyproject.toml [build-system] requires
test-command = "pytest {project}/tests"
# Store PyPI credentials via CI secrets:
#   CIBW_PYPI_TOKEN (never commit tokens in config files)

[tool.cibuildwheel.linux]
# Avoid curl-pipe-to-shell in before-build/before-all hooks
# Pin dependency-versions for reproducible wheels
# Do not pass secrets via environment-pass
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
            platforms = ", ".join(info.platforms[:8]) if info.platforms else "none"
            indexes = ", ".join(info.index_urls[:8]) if info.index_urls else "none"
            hooks = ", ".join(info.hooks[:8]) if info.hooks else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.platforms)} platform(s), {len(info.hooks)} hook(s)"
            )
            lines.append(f"    platforms: {platforms}")
            lines.append(f"    index URLs: {indexes}")
            lines.append(f"    hooks: {hooks}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
