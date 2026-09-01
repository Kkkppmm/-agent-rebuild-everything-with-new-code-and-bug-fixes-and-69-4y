"""CibuildwheelAnalyzer — audit cibuildwheel configs for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CIBW_PYPROJECT_NAMES = ("pyproject.toml",)
CIBW_CONFIG_NAMES = ("cibuildwheel.toml",)
CIBW_SETUP_CFG_NAMES = ("setup.cfg",)
CIBW_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.cibuildwheel\]|^\[tool\.cibuildwheel\.|^\[cibuildwheel\]|"
    r"cibuildwheel\s*=\s*\{)",
    re.IGNORECASE | re.MULTILINE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|pypi[_-]?token)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
PYPI_TOKEN_PATTERN = re.compile(r"[\"']?pypi-[A-Za-z0-9_-]{20,}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
PRIVILEGED_DOCKER_PATTERN = re.compile(
    r"(?:--privileged|privileged\s*=\s*true|security_opt\s*=\s*\[)",
    re.IGNORECASE,
)
UNPINNED_IMAGE_PATTERN = re.compile(
    r"(?:manylinux|musllinux|image)\s*=\s*[\"'][^\"':]+:latest[\"']",
    re.IGNORECASE,
)
SKIP_TESTS_PATTERN = re.compile(
    r"(?:test-command|test-skip)\s*=\s*[\"']?\s*[\"']?",
    re.IGNORECASE,
)
ENV_INJECTION_PATTERN = re.compile(
    r"(?:CIBW_|before-all|before-build|test-command)\s*=\s*.*\$\{",
    re.IGNORECASE,
)
DANGEROUS_TEST_CMD_PATTERN = re.compile(
    r"test-command\s*=\s*[\"'].*(?:curl|wget|bash|sh\s+-c|eval|exec)",
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
    if name in CIBW_PYPROJECT_NAMES or name in CIBW_SETUP_CFG_NAMES:
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
    if name == "setup.cfg":
        return "setup_cfg"
    return "unknown"


class CibuildwheelAnalyzer:
    """Audit cibuildwheel configuration for security issues.

    Scans pyproject.toml [tool.cibuildwheel], cibuildwheel.toml, and setup.cfg
    for hardcoded secrets, insecure HTTP URLs, privileged Docker settings,
    unpinned manylinux images, skipped tests, and dangerous test commands.
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
                r"(?:build|skip|test-skip)\s*=\s*[\"']([^\"']+)[\"']",
                stripped,
                re.IGNORECASE,
            )
            if platform_match:
                info.platforms.append(platform_match.group(1))

            test_match = re.search(
                r"test-command\s*=\s*[\"']([^\"']+)[\"']",
                stripped,
                re.IGNORECASE,
            )
            if test_match:
                info.test_commands.append(test_match.group(1))

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
                        message="PyPI token in cibuildwheel config — use CIBW_* env vars from CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="insecure_http",
                        severity="high",
                        message="insecure HTTP URL in cibuildwheel config — use HTTPS",
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
                        message="curl-pipe-to-shell in cibuildwheel script — supply-chain risk",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PRIVILEGED_DOCKER_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="privileged_docker",
                        severity="high",
                        message="privileged Docker mode in cibuildwheel — avoid in CI builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNPINNED_IMAGE_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="unpinned_image",
                        severity="medium",
                        message="unpinned :latest manylinux/musllinux image — pin to a specific tag",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SKIP_TESTS_PATTERN.search(line) and "test-skip" in stripped.lower():
                findings.append(
                    CibuildwheelFinding(
                        kind="skipped_tests",
                        severity="medium",
                        message="test-skip configured — wheels may ship without verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DANGEROUS_TEST_CMD_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="dangerous_test_command",
                        severity="high",
                        message="dangerous test-command in cibuildwheel — review for injection risks",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ENV_INJECTION_PATTERN.search(line):
                findings.append(
                    CibuildwheelFinding(
                        kind="env_injection",
                        severity="low",
                        message="environment variable interpolation in cibuildwheel — verify trusted sources",
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
        """Scaffold a hardened cibuildwheel config snippet with secure defaults."""
        return """\
# pyproject.toml — hardened cibuildwheel defaults
[tool.cibuildwheel]
build = "cp39-* cp310-* cp311-* cp312-*"
test-command = "pytest {project}/tests"
# Pin manylinux images; never use :latest
# manylinux-x86_64-image = "manylinux2014"
# Store secrets via CI env vars (CIBW_*), never in config files
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
            platforms = ", ".join(info.platforms[:8]) if info.platforms else "none"
            tests = ", ".join(info.test_commands[:4]) if info.test_commands else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.platforms)} platform(s), {len(info.test_commands)} test command(s)"
            )
            lines.append(f"    platforms: {platforms}")
            lines.append(f"    test commands: {tests}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
