"""HardcodedConfigAnalyzer — detect hardcoded configuration values."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_CONFIG_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    (
        "hardcoded_database_url",
        re.compile(
            r"""(?:DATABASE_URL|DB_URL|SQLALCHEMY_DATABASE_URI)\s*=\s*['"][^'"]+['"]""",
            re.IGNORECASE,
        ),
        "high",
        "Hardcoded database URL — use environment variables",
    ),
    (
        "hardcoded_admin_password",
        re.compile(
            r"""(?:ADMIN_PASSWORD|DEFAULT_PASSWORD|ROOT_PASSWORD)\s*=\s*['"][^'"]+['"]""",
            re.IGNORECASE,
        ),
        "critical",
        "Hardcoded admin password — use secrets management",
    ),
    (
        "hardcoded_host_port",
        re.compile(
            r"""(?:HOST|BIND|LISTEN)\s*=\s*['"](?:0\.0\.0\.0|127\.0\.0\.1)[^'"]*['"]""",
            re.IGNORECASE,
        ),
        "low",
        "Hardcoded host binding — consider environment-based configuration",
    ),
    (
        "hardcoded_debug_true",
        re.compile(
            r"""(?:DEBUG|DEVELOPMENT)\s*=\s*True""",
            re.IGNORECASE,
        ),
        "medium",
        "Debug mode enabled in source — ensure this is disabled in production",
    ),
    (
        "hardcoded_api_endpoint",
        re.compile(
            r"""(?:API_URL|BASE_URL|ENDPOINT|SERVICE_URL)\s*=\s*['"]https?://[^'"]+['"]""",
            re.IGNORECASE,
        ),
        "medium",
        "Hardcoded API endpoint — use environment variables for deployment flexibility",
    ),
    (
        "hardcoded_smtp",
        re.compile(
            r"""(?:SMTP_HOST|MAIL_SERVER|EMAIL_HOST)\s*=\s*['"][^'"]+['"]""",
            re.IGNORECASE,
        ),
        "medium",
        "Hardcoded SMTP/mail server — use environment configuration",
    ),
]


@dataclass
class HardcodedConfigFinding:
    """A hardcoded configuration value in source code."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        snippet = f" — {self.line.strip()[:60]}" if self.line else ""
        return (
            f"{self.path}:{self.lineno} [{self.severity}] {self.pattern}: "
            f"{self.message}{snippet}"
        )


@dataclass
class HardcodedConfigStats:
    """Aggregate hardcoded-config analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


class HardcodedConfigAnalyzer:
    """Detect hardcoded configuration values in Python source.

    Flags database URLs, admin passwords, API endpoints, SMTP settings, and
    debug flags that should be loaded from environment variables or config files.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[HardcodedConfigFinding] = []
        self._stats: HardcodedConfigStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        if path.suffix != ".py":
            return True
        # Skip test files for debug=True patterns
        return False

    def analyze(self) -> list[HardcodedConfigFinding]:
        """Analyze the project and return hardcoded-config findings."""
        if self._findings:
            return self._findings

        findings: list[HardcodedConfigFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))
            lines = source.splitlines()

            for lineno, line in enumerate(lines, start=1):
                for pattern_name, compiled, severity, message in _CONFIG_PATTERNS:
                    if compiled.search(line):
                        findings.append(
                            HardcodedConfigFinding(
                                path=rel,
                                lineno=lineno,
                                pattern=pattern_name,
                                severity=severity,
                                message=message,
                                line=line,
                            )
                        )
                        files_with_findings.add(rel)

        self._findings = findings
        self._files_scanned = files_scanned

        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = HardcodedConfigStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> HardcodedConfigStats:
        """Return aggregate hardcoded-config statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[HardcodedConfigFinding]:
        """Return high and critical severity findings."""
        return [f for f in self.analyze() if f.severity in ("high", "critical")]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no hardcoded config)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        critical = sum(1 for f in self._findings if f.severity == "critical")
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = critical * 40.0 + high * 25.0 + medium * 10.0 + low * 3.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        critical = stats.by_severity.get("critical", 0)
        high = stats.by_severity.get("high", 0)
        lines = [
            f"Hardcoded config: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Critical: {critical}, High: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing hardcoded-config findings."""
        self.analyze()
        lines = ["Hardcoded config analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No hardcoded configuration found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
