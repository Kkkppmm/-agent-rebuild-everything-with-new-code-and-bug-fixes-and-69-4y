"""InsecureHTTPAnalyzer — detect hardcoded insecure HTTP URLs in production code."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_HTTP_URL = re.compile(r"""['"]http://(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?:[:/]|['"]))[^'"]+['"]""")
_LOCALHOST_HTTP = re.compile(r"""['"]http://(?:localhost|127\.0\.0\.1)(?:[:/][^'"]*)?['"]""")
_VERIFY_FALSE = re.compile(r"verify\s*=\s*False")
_SSL_DISABLED = re.compile(r"(?:ssl|tls)\s*=\s*False", re.IGNORECASE)


@dataclass
class InsecureHTTPFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    url: str = ""

    def format(self) -> str:
        detail = f" ({self.url})" if self.url else ""
        return f"{self.path}:{self.lineno} [{self.severity}] {self.pattern}{detail}: {self.message}"


@dataclass
class InsecureHTTPStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


class InsecureHTTPAnalyzer:
    """Detect hardcoded http:// URLs and disabled TLS verification in Python code."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureHTTPFinding] = []
        self._stats: InsecureHTTPStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(self, rel: str, source: str) -> list[InsecureHTTPFinding]:
        findings: list[InsecureHTTPFinding] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            for match in _HTTP_URL.finditer(line):
                url = match.group(0).strip("'\"")
                findings.append(
                    InsecureHTTPFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="insecure_http_url",
                        severity="medium",
                        message="Use https:// for external URLs to prevent credential and data interception",
                        url=url,
                    )
                )

            if _LOCALHOST_HTTP.search(line) and "test" not in rel.lower():
                match = _LOCALHOST_HTTP.search(line)
                if match:
                    url = match.group(0).strip("'\"")
                    findings.append(
                        InsecureHTTPFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="localhost_http",
                            severity="low",
                            message="Consider https:// even for local services when TLS is available",
                            url=url,
                        )
                    )

            if _VERIFY_FALSE.search(line) and ("requests." in line or "httpx." in line or "urllib" in line):
                findings.append(
                    InsecureHTTPFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="tls_verify_disabled",
                        severity="high",
                        message="Disabling TLS certificate verification exposes connections to MITM attacks",
                    )
                )

            if _SSL_DISABLED.search(line):
                findings.append(
                    InsecureHTTPFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="ssl_disabled",
                        severity="high",
                        message="Explicitly disabling SSL/TLS weakens transport security",
                    )
                )

        return findings

    def analyze(self) -> list[InsecureHTTPFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureHTTPFinding] = []
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
        self._stats = InsecureHTTPStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureHTTPStats:
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
            f"Insecure HTTP risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure HTTP analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure HTTP patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
