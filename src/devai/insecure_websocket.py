"""InsecureWebSocketAnalyzer — detect hardcoded insecure ws:// WebSocket URLs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_WS_URL = re.compile(
    r"""['"]ws://(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?:[:/]|['"]))[^'"]+['"]"""
)
_LOCALHOST_WS = re.compile(r"""['"]ws://(?:localhost|127\.0\.0\.1)(?:[:/][^'"]*)?['"]""")
_SSL_DISABLED = re.compile(
    r"(?:ssl\s*=\s*False|ssl_cert_reqs\s*=\s*(?:ssl\.)?CERT_NONE|cert_reqs\s*=\s*(?:ssl\.)?CERT_NONE)"
)


@dataclass
class InsecureWebSocketFinding:
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
class InsecureWebSocketStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


class InsecureWebSocketAnalyzer:
    """Detect hardcoded ws:// URLs and disabled WebSocket TLS in Python code."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureWebSocketFinding] = []
        self._stats: InsecureWebSocketStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(self, rel: str, source: str) -> list[InsecureWebSocketFinding]:
        findings: list[InsecureWebSocketFinding] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            for match in _WS_URL.finditer(line):
                url = match.group(0).strip("'\"")
                findings.append(
                    InsecureWebSocketFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="insecure_ws_url",
                        severity="medium",
                        message="Use wss:// for WebSocket connections to prevent credential and data interception",
                        url=url,
                    )
                )

            if _LOCALHOST_WS.search(line) and "test" not in rel.lower():
                match = _LOCALHOST_WS.search(line)
                if match:
                    url = match.group(0).strip("'\"")
                    findings.append(
                        InsecureWebSocketFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="localhost_ws",
                            severity="low",
                            message="Consider wss:// even for local WebSocket services when TLS is available",
                            url=url,
                        )
                    )

            if _SSL_DISABLED.search(line) and (
                "websocket" in line.lower() or "websockets" in line.lower() or "ws://" in line
            ):
                findings.append(
                    InsecureWebSocketFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="ws_tls_disabled",
                        severity="high",
                        message="Disabling WebSocket TLS exposes real-time data to interception",
                    )
                )

        return findings

    def analyze(self) -> list[InsecureWebSocketFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureWebSocketFinding] = []
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
        self._stats = InsecureWebSocketStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureWebSocketStats:
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
            f"Insecure WebSocket risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure WebSocket analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure WebSocket patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
