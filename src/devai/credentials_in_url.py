"""CredentialsInURLAnalyzer — detect hardcoded credentials embedded in URLs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SCHEMES = r"(?:https?|ftp|mongodb(?:\+srv)?|redis|amqp|postgres(?:ql)?)"
_CREDENTIALS_IN_URL = re.compile(
    rf"""['"]{_SCHEMES}://[^:/'"@]+:[^@'"]+@[^'"]+['"]""",
    re.IGNORECASE,
)
_QUERY_SECRET = re.compile(
    r"""['"][^'"]*[?&](?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|password)=([^&'"]+)['"]""",
    re.IGNORECASE,
)
_BEARER_TOKEN = re.compile(r"""['"]Bearer\s+([A-Za-z0-9._\-]{12,})['"]""")
_PLACEHOLDER = re.compile(r"^[\$\{%]|^\{.*\}$|^\$\{.*\}$|^<.*>$|^%s$|^None$|^null$", re.IGNORECASE)


@dataclass
class CredentialsInURLFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    detail: str = ""

    def format(self) -> str:
        suffix = f" ({self.detail})" if self.detail else ""
        return f"{self.path}:{self.lineno} [{self.severity}] {self.pattern}{suffix}: {self.message}"


@dataclass
class CredentialsInURLStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


class CredentialsInURLAnalyzer:
    """Detect hardcoded usernames, passwords, tokens, and API keys embedded in URLs."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[CredentialsInURLFinding] = []
        self._stats: CredentialsInURLStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _is_placeholder(self, value: str) -> bool:
        value = value.strip()
        if not value or len(value) < 4:
            return True
        return bool(_PLACEHOLDER.match(value))

    def _scan_source(self, rel: str, source: str) -> list[CredentialsInURLFinding]:
        findings: list[CredentialsInURLFinding] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if "environ" in line or "getenv" in line or "os.getenv" in line:
                continue

            for match in _CREDENTIALS_IN_URL.finditer(line):
                url = match.group(0).strip("'\"")
                if "@" in url and not self._is_placeholder(url.split("@", 1)[0].split("://", 1)[-1]):
                    findings.append(
                        CredentialsInURLFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="url_embedded_credentials",
                            severity="high",
                            message="Remove credentials from URLs — use environment variables or a secrets manager",
                            detail=url.split("@", 1)[0].split("://", 1)[-1][:20] + "@...",
                        )
                    )

            for match in _QUERY_SECRET.finditer(line):
                secret_value = match.group(1)
                if not self._is_placeholder(secret_value):
                    findings.append(
                        CredentialsInURLFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="query_string_secret",
                            severity="high",
                            message="Hardcoded secrets in URL query strings leak via logs, referrers, and browser history",
                            detail=secret_value[:12] + "..." if len(secret_value) > 12 else secret_value,
                        )
                    )

            for match in _BEARER_TOKEN.finditer(line):
                token = match.group(1)
                if not self._is_placeholder(token):
                    findings.append(
                        CredentialsInURLFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="hardcoded_bearer_token",
                            severity="high",
                            message="Store bearer tokens in environment variables, not hardcoded strings",
                            detail=token[:8] + "...",
                        )
                    )

        return findings

    def analyze(self) -> list[CredentialsInURLFinding]:
        if self._findings:
            return self._findings

        findings: list[CredentialsInURLFinding] = []
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
            file_findings = self._scan_source(rel, source)
            if file_findings:
                files_with_findings.add(rel)
            findings.extend(file_findings)

        self._findings = findings
        self._files_scanned = files_scanned
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = CredentialsInURLStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> CredentialsInURLStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = high * 25.0 + medium * 12.0 + low * 5.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Credentials in URL risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Credentials in URL analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No hardcoded credentials in URLs found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
