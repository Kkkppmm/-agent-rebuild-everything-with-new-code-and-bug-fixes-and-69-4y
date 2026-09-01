"""CibuildwheelAnalyzer — audit cibuildwheel configs for security and release hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CIBW_PYPROJECT_NAMES = ("pyproject.toml",)
CIBW_CONFIG_NAMES = ("cibuildwheel.toml", ".cibuildwheel.toml")
CIBW_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.cibuildwheel\]|^\[tool\.cibuildwheel\.|cibuildwheel\s*=\s*\{|"
    r"CIBW_|test-command\s*=|before-build\s*=|before-all\s*=|"
    r"manylinux-x86_64-image|build-frontend)",
    re.IGNORECASE | re.MULTILINE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|pypi[_-]?token|twine[_-]?password)\s*[=:]\s*"
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
TEST_SKIP_ALL_PATTERN = re.compile(
    r"(?:test-skip|skip)\s*=\s*[\"']?\*[\"']?",
    re.IGNORECASE,
)
LATEST_IMAGE_PATTERN = re.compile(
    r"(?:manylinux|musllinux|alpine)[^\n\"']*:latest\b",
    re.IGNORECASE,
)
CIBW_ENV_SECRET_PATTERN = re.compile(
    r"(?:CIBW_|TWINE_|PYPI_)(?:PASSWORD|TOKEN|AUTH|SECRET|USERNAME)\s*=\s*"
    r"[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
DANGEROUS_COMMAND_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|exec\s*\()",
    re.IGNORECASE,
)
DISABLED_TESTS_PATTERN = re.compile(
    r"test-command\s*=\s*(?:\"\"|''|\[\s*\])",
    re.IGNORECASE,
)
BUILD_FRONTEND_HTTP_PATTERN = re.compile(
    r"build-frontend\s*=\s*[\"']?http://",
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
    test_commands: list[str] = field(default_factory=list)
    build_hooks: list[str] = field(default_factory=list)


@dataclass
class CibuildwheelStats:
    """Aggregate cibuildwheel analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_cibuildwheel_pyproject(path: Path) -> bool:
    if path.name not in CIBW_PYPROJECT_NAMES:
        return False
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:16384]
        return bool(CIBW_MARKER_PATTERN.search(head))
    except OSError:
        return False


def _is_cibuildwheel_file(path: Path) -> bool:
    if path.name in CIBW_CONFIG_NAMES:
        return True
    return _is_cibuildwheel_pyproject(path)


def _file_kind(path: Path) -> str:
    if path.name == "pyproject.toml":
        return "pyproject"
    if path.name in CIBW_CONFIG_NAMES:
        return "cibuildwheel"
    return "unknown"


class CibuildwheelAnalyzer:
    """Audit cibuildwheel configuration for security issues.

    Scans pyproject.toml ([tool.cibuildwheel]), cibuildwheel.toml, and
    .cibuildwheel.toml for hardcoded PyPI tokens, insecure HTTP indexes,
    credentials in repository URLs, curl-pipe-to-shell in build/test hooks,
    disabled test commands, test-skip wildcards, :latest container images,
    hardcoded CIBW_* secrets, and dangerous shell commands.
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

            platform_match = re.search(
                r"^\[tool\.cibuildwheel\.([^\]]+)\]",
                stripped,
                re.IGNORECASE,
            )
            if platform_match:
                info.platforms.append(platform_match.group(1))

            for hook in (
                "test-command",
                "before-build",
                "before-all",
                "before-test",
                "after-test",
                "repair-wheel-command",
            ):
                if re.search(rf"^{re.escape(hook)}\s*=", stripped, re.IGNORECASE):
                    info.build_hooks.append(hook)
                    if hook == "test-command":
                        value = stripped.split("=", 1)[-1].strip().strip("\"'")
                        if value:
                            info.test_commands.append(value[:120])

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
                        message="PyPI token in config — use CIBW_* env vars or CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CIBW_ENV_SECRET_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="cibw_env_secret",
                        severity="high",
                        message="hardcoded CIBW/TWINE credential — inject via CI secrets",
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
                        message="AWS access key in config — use credential helpers or secret stores",
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
                        message="insecure HTTP URL — use HTTPS for PyPI indexes and registries",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if BUILD_FRONTEND_HTTP_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="insecure_build_frontend",
                        severity="medium",
                        message="build-frontend uses HTTP — prefer pip/uv with HTTPS indexes",
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

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
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
                    CibuildwheelFinding(
                        kind="sensitive_path",
                        severity="high",
                        message="sensitive host path reference — avoid bundling credentials in wheel builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if TEST_SKIP_ALL_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="test_skip_all",
                        severity="medium",
                        message="test-skip=* disables all wheel tests — verify platform coverage",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DISABLED_TESTS_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="disabled_tests",
                        severity="medium",
                        message="empty test-command — wheels may ship without verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if LATEST_IMAGE_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="latest_image",
                        severity="low",
                        message="container image uses :latest — pin to a digest or version tag",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DANGEROUS_COMMAND_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="dangerous_command",
                        severity="high",
                        message="dangerous shell command in build/test hook — review for supply-chain risk",
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
        """Scaffold a hardened pyproject.toml snippet with secure cibuildwheel defaults."""
        return """\
# pyproject.toml — hardened cibuildwheel defaults
[tool.cibuildwheel]
build-frontend = "pip"
test-command = "pytest {project}/tests"
# Pin manylinux images — avoid :latest tags
# manylinux-x86_64-image = "manylinux2014"
# Store publish tokens via CI secrets — never commit TWINE_PASSWORD or CIBW_* tokens
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Cibuildwheel configs: none found"
        return (
            f"Cibuildwheel configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Cibuildwheel analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            platforms = ", ".join(info.platforms[:8]) if info.platforms else "default"
            hooks = ", ".join(info.build_hooks[:8]) if info.build_hooks else "none"
            tests = ", ".join(info.test_commands[:4]) if info.test_commands else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.platforms)} platform section(s), {len(info.build_hooks)} hook(s)"
            )
            lines.append(f"    platforms: {platforms}")
            lines.append(f"    hooks: {hooks}")
            lines.append(f"    test commands: {tests}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
